"""Locally pinned, static-validator wallet checkpoints and native payment outbox.

No RPC, broadcast, external payments, consensus or production light-client claim.
Quorum certificates authenticate state AS OF a height, not current network state.
The local journal prevents this workspace from signing competing commitments;
other workspaces, restored backups and keys used elsewhere are outside that claim.
"""
from __future__ import annotations

from contextlib import contextmanager
import hashlib
import hmac
import json
import os
from pathlib import Path
import sqlite3
import stat
import time

from commit_verifier import (encode, load_json, pinned_genesis, verify_state_witness,
    verify_signed_header, block_id, timestamp, MAX_PACKET_BYTES)
from native_core import (NativeLedger, canonical, digest, integer, require, DOMAIN)
from offline_signer import review_intent, approve_intent
from block_application import restore, tables_for

REVIEW_DOMAIN = b'1soft/certified-payment-review/v1\x00'
COLUMNS = {
    'meta': ('k','v'),
    'accounts': ('id','public_key','nonce','epoch','balance'),
    'grants': ('id','owner','public_key','epoch','nonce','cap','spent','expires','recipients','revoked'),
    'receipts': ('txid','sequence','previous','record','hash'),
}


def restore_verified_state(state: dict) -> NativeLedger:
    """Semantically check the already-attested full witness; never mutate a node."""
    require(type(state) is dict and type(state.get('native')) is dict,
            'invalid wallet state snapshot')
    tables = tables_for(state['genesis'])
    require(set(state['native']) == set(tables), 'invalid wallet state tables')
    for table, columns in tables.items():
        rows = state['native'][table]
        require(type(rows) is list and len(rows) <= 10000,
                'wallet state table bound exceeded')
        require(all(type(row) is list and len(row) == len(columns) for row in rows),
                'invalid state row')
    ledger = restore(state['genesis'], state['native'])
    try:
        meta = dict(ledger.db.execute('SELECT k,v FROM meta'))
        require(set(meta) == {'genesis','height','supply'} and meta['genesis'] == digest(state['genesis']), 'invalid state metadata')
        require(meta['supply'] == str(sum(item['units'] for item in state['genesis']['allocations'])), 'state supply differs from genesis')
        require(str(int(meta['height'])) == meta['height'] and 0 <= int(meta['height']) <= state['height'], 'invalid ledger height')
        for row in ledger.db.execute('SELECT nonce,epoch,balance FROM accounts'):
            for value in row: integer(value)
        for row in ledger.db.execute('SELECT epoch,nonce,cap,spent,expires,revoked FROM grants'):
            for value in row: integer(value)
            require(row[-1] in (0,1), 'invalid revocation flag')
        ledger.verify_receipts()
        return ledger
    except BaseException:
        ledger.close()
        raise


class WalletState:
    """One trusted local workspace; atomic reservations across its processes."""
    def __init__(self, path: Path, genesis_bytes: bytes, expected_genesis_sha256: str,
                 *, clock=time.time_ns, max_age_seconds: int = 300, max_future_seconds: int = 30):
        self.trust = pinned_genesis(genesis_bytes, expected_genesis_sha256)
        # This outbox predates protocol-3 shared budgets. Its local holds cover
        # balances and individual grants but do not coordinate a shared budget
        # across grants, so it must not sign for a v3 genesis.
        native_genesis = load_json(genesis_bytes, max_bytes=1024 * 1024)['app_state']
        require(native_genesis.get('protocol_version', 1) in (1, 2),
                'protocol 3 budgets require a shared-reservation outbox integration')
        self.genesis_sha256 = hashlib.sha256(genesis_bytes).hexdigest()
        self.clock = clock
        require(type(max_age_seconds) is int and 1 <= max_age_seconds <= 3600, 'invalid age policy')
        require(type(max_future_seconds) is int and 0 <= max_future_seconds <= 60, 'invalid future policy')
        self.max_age_ns = max_age_seconds * 10**9
        self.max_future_ns = max_future_seconds * 10**9
        path = Path(path).absolute()
        # Trusted, stable, same-user filesystem. Not hostile-OS or race-safe custody.
        require(os.name == 'posix', 'wallet workspace requires POSIX/Linux/WSL')
        require(not any(p.is_symlink() for p in (path, *path.parents)), 'workspace symlinks are refused')
        parent = path.parent.stat()
        require(parent.st_uid == os.geteuid() and stat.S_IMODE(parent.st_mode) & 0o077 == 0,
                'workspace parent must be private and owned (0700)')
        if path.exists():
            info = path.stat()
            require(stat.S_ISREG(info.st_mode) and info.st_uid == os.geteuid() and info.st_nlink == 1
                    and stat.S_IMODE(info.st_mode) & 0o077 == 0, 'workspace must be a private regular file')
        else:
            fd = os.open(path, os.O_CREAT | os.O_EXCL | os.O_WRONLY | os.O_NOFOLLOW, 0o600)
            os.close(fd)
        self.db = sqlite3.connect(str(path), isolation_level=None, timeout=10)
        self.db.row_factory = sqlite3.Row
        try:
            self.db.execute('PRAGMA journal_mode=WAL')
            self.db.execute('PRAGMA synchronous=FULL')
            self.db.executescript('''
              CREATE TABLE IF NOT EXISTS anchor(id INTEGER PRIMARY KEY CHECK(id=1), schema INTEGER NOT NULL,
                genesis_sha256 TEXT NOT NULL);
              CREATE TABLE IF NOT EXISTS checkpoint(id INTEGER PRIMARY KEY CHECK(id=1), witness TEXT NOT NULL,
                certificate TEXT NOT NULL);
              CREATE TABLE IF NOT EXISTS outbox(txid TEXT PRIMARY KEY, account TEXT NOT NULL, grant_id TEXT NOT NULL,
                nonce INTEGER NOT NULL, signer TEXT NOT NULL, debit INTEGER NOT NULL, valid_until INTEGER NOT NULL,
                envelope TEXT NOT NULL, review_digest TEXT NOT NULL, state_height INTEGER NOT NULL,
                status TEXT NOT NULL CHECK(status IN ('signed','recorded','expired')));
              CREATE UNIQUE INDEX IF NOT EXISTS pending_lane ON outbox(account,grant_id,nonce) WHERE status='signed';
            ''')
            with self._atomic():
                row = self.db.execute('SELECT * FROM anchor WHERE id=1').fetchone()
                if row is None:
                    require(not self.db.execute('SELECT 1 FROM checkpoint UNION ALL SELECT 1 FROM outbox').fetchone(),
                            'unanchored workspace data')
                    self.db.execute('INSERT INTO anchor VALUES (1,1,?)', (self.genesis_sha256,))
                else:
                    require(row['schema'] == 1 and row['genesis_sha256'] == self.genesis_sha256, 'workspace trust anchor mismatch')
        except BaseException:
            self.db.close()
            raise

    def close(self): self.db.close()
    def __enter__(self): return self
    def __exit__(self, *args): self.close()

    @contextmanager
    def _atomic(self):
        self.db.execute('BEGIN IMMEDIATE')
        try:
            yield
            self.db.execute('COMMIT')
        except BaseException:
            self.db.execute('ROLLBACK')
            raise

    def _time(self, certificate: dict) -> None:
        now = self.clock()
        require(type(now) is int and now >= 0, 'invalid trusted local clock')
        stamp = timestamp(certificate['header']['time'])
        signed_time = stamp.seconds*10**9 + stamp.nanos
        require(now - self.max_age_ns <= signed_time <= now + self.max_future_ns,
                'certificate outside local age policy; obtain newer evidence or correct the clock')

    def _stored(self, *, age: bool = True):
        row = self.db.execute('SELECT witness,certificate FROM checkpoint WHERE id=1').fetchone()
        require(row is not None, 'no verified account state; import a certificate first')
        state = load_json(row['witness'].encode())
        certificate = load_json(row['certificate'].encode())
        info = verify_state_witness(state, certificate, self.trust)
        if age: self._time(certificate)
        return state, certificate, info

    def import_state(self, packet: dict, *, continuation: list | None = None) -> dict:
        """Verify before updating. Never learn trusted validators from a reply.

        After bootstrap, updates must extend the stored header by exact block-ID
        links. `continuation` holds intermediate signed headers only (max 64).
        Wall-clock age is a local plausibility policy, NOT proof of latestness.
        """
        packet = load_json(encode(packet))
        require(type(packet) is dict and set(packet) == {'state','state_commit'}, 'invalid account-state packet')
        state, cert = packet['state'], packet['state_commit']
        info = verify_state_witness(state, cert, self.trust)
        self._time(cert)
        ledger = restore_verified_state(state)
        ledger.close()
        links = [] if continuation is None else load_json(encode(continuation))
        require(type(links) is list and len(links) <= 64, 'continuation bound exceeded')
        with self._atomic():
            existing = self.db.execute('SELECT 1 FROM checkpoint').fetchone()
            if existing:
                _, old, old_info = self._stored(age=False)
                if info['height'] == old_info['height']:
                    require(not links and info['block_hash'] == old_info['block_hash'], 'conflicting same-height checkpoint')
                else:
                    require(info['height'] > old_info['height'], 'checkpoint rollback refused')
                    previous = old
                    for following in [*links, cert]:
                        verify_signed_header(following, self.trust,
                                             expected_height=int(previous['header']['height'])+1)
                        require(block_id(following['header']['last_block_id']).SerializeToString() ==
                                block_id(previous['commit']['block_id']).SerializeToString(), 'checkpoint fork or missing link')
                        a, b = timestamp(previous['header']['time']), timestamp(following['header']['time'])
                        require((b.seconds,b.nanos) >= (a.seconds,a.nanos), 'header time regressed')
                        previous = following
            else:
                require(not links, 'bootstrap takes one independently pinned static-set certificate')
            self._reconcile(state)
            self.db.execute('INSERT OR REPLACE INTO checkpoint VALUES (1,?,?)', (encode(state).decode(),encode(cert).decode()))
        return {'status':'imported','state_height':info['state_height'],'certificate_height':info['height'],
                'state_app_hash':info['state_app_hash'],'header_hash':info['block_hash'],
                'latest_network_state_established':False,'scope':'static-set attested state, local continuity checks'}

    def _reconcile(self, state):
        receipts = {row[0]: load_json(row[3].encode()) for row in state['native']['receipts']}
        for row in self.db.execute("SELECT * FROM outbox WHERE status='signed'").fetchall():
            record = receipts.get(row['txid'])
            if record is not None:
                require(canonical(record['envelope']) == row['envelope'].encode() and
                        record['signer_public_key'] == row['signer'], 'receipt conflicts with original signed intention')
                status = 'recorded'
            elif state['height'] > row['valid_until']:
                status = 'expired'
            else:
                continue  # silence, timeout or revocation alone is not a refund
            self.db.execute('UPDATE outbox SET status=? WHERE txid=?', (status,row['txid']))

    def build_transfer(self, account: str, recipient: str, units: int, *, valid_until: int,
                       grant_id: str = '') -> dict:
        with self._atomic():
            state, _, _ = self._stored()
            ledger = restore_verified_state(state)
            try:
                owner = ledger._account(account)
                signer = owner
                if grant_id:
                    signer = ledger.db.execute('SELECT * FROM grants WHERE id=?',
                        (ledger.grant_storage_id(account,grant_id),)).fetchone()
                    require(signer is not None, 'grant absent from verified state')
                body = ledger.body(account, signer['nonce'], {'type':'transfer','to':recipient,'units':units},
                                   grant_id=grant_id, valid_until=valid_until)
                return self._review(body,signer['public_key'])
            finally:
                ledger.close()

    def review(self, body: dict, signer_public_key: str) -> dict:
        with self._atomic(): return self._review(body, signer_public_key)

    def _review(self, body: dict, signer_public_key: str) -> dict:
        state, cert, info = self._stored()
        base = review_intent(state['genesis'],body,signer_public_key)
        body = base['body']
        require(body['op']['type'] == 'transfer', 'certified outbox currently supports native transfers only')
        require(body['valid_until'] >= info['height']+1, 'transaction would expire before the next possible block')
        ledger = restore_verified_state(state)
        try:
            account = ledger._account(body['sender'])
            signer = account
            if body['grant_id']:
                signer = ledger.db.execute('SELECT * FROM grants WHERE id=?',
                    (ledger.grant_storage_id(body['sender'],body['grant_id']),)).fetchone()
                require(signer is not None and not signer['revoked'] and signer['epoch'] == account['epoch']
                        and signer['expires'] >= info['height']+1, 'grant inactive in attested state')
                require(body['op']['to'] in json.loads(signer['recipients']), 'recipient outside agent grant')
            require(signer['public_key'] == signer_public_key and signer['nonce'] == body['nonce'],
                    'signer or nonce differs from attested authority')
            ledger._account(body['op']['to'])
            txid = hashlib.sha256(DOMAIN + canonical(body)).hexdigest()
            prior = self.db.execute('SELECT * FROM outbox WHERE txid=?',(txid,)).fetchone()
            require(prior is None or prior['status'] == 'signed', 'intention already recorded or expired')
            lane = self.db.execute("SELECT txid FROM outbox WHERE account=? AND grant_id=? AND nonce=? AND status='signed'",
                                   (body['sender'],body['grant_id'],body['nonce'])).fetchone()
            require(lane is None or lane['txid'] == txid, 'another signed intention occupies this nonce; reconcile first')
            pending = list(self.db.execute("SELECT * FROM outbox WHERE account=? AND status='signed' AND txid<>?",
                                           (body['sender'],txid)))
            reserved = sum(row['debit'] for row in pending)
            debit = base['proposed_account_debit_units']
            require(reserved+debit <= account['balance'], 'balance insufficient after local outstanding intentions')
            if body['grant_id']:
                grant_reserved = sum(row['debit'] for row in pending if row['grant_id'] == body['grant_id'])
                require(signer['spent']+grant_reserved+debit <= signer['cap'], 'agent allowance insufficient including fees')
            context = {'domain':'certified-native-transfer-v1','genesis_sha256':self.genesis_sha256,
                'header_hash':info['block_hash'],'state_app_hash':info['state_app_hash'],
                'body':body,'signer_public_key':signer_public_key,'local_reserved_units':reserved}
            confirmation = hashlib.sha256(REVIEW_DOMAIN+encode(context)).hexdigest()
            return {'schema':1,'body':body,'signer_public_key':signer_public_key,
                'confirmation':confirmation,'state_height':state['height'],'certificate_height':info['height'],
                'state_app_hash':info['state_app_hash'],'header_hash':info['block_hash'],
                'attested_balance_units':account['balance'],'other_local_reserved_units':reserved,
                'proposed_debit_units':debit,'native_txid':txid,'authority_verified_as_of_height':state['height'],
                'latest_network_state_established':False,'broadcast':False,
                'warning':'Attested historical state; not a live balance guarantee. Same-workspace reservations only. Development.'}
        finally:
            ledger.close()

    def approve(self, body: dict, signer_public_key: str, confirmation: str, *, vault: Path, password: bytes) -> dict:
        with self._atomic():
            view = self._review(body,signer_public_key)
            require(type(confirmation) is str and confirmation.isascii() and
                    hmac.compare_digest(view['confirmation'], confirmation), 'review context changed; review again')
            prior = self.db.execute('SELECT envelope FROM outbox WHERE txid=?',(view['native_txid'],)).fetchone()
            if prior:
                return load_json(prior['envelope'].encode()) # retrieve the already-approved signature, never resign
            state, _, info = self._stored()
            base = review_intent(state['genesis'], view['body'], signer_public_key)
            envelope = approve_intent(vault,password,state['genesis'],view['body'],signer_public_key,base['confirmation'])
            # Validate the actual generated signature against an isolated, verified
            # snapshot before exposing or recording it. Never changes node state.
            ledger = restore_verified_state(state)
            try: ledger.apply(envelope,height=info['height']+1)
            finally: ledger.close()
            self.db.execute('INSERT INTO outbox VALUES (?,?,?,?,?,?,?,?,?,?,?)',
                (view['native_txid'],view['body']['sender'],view['body']['grant_id'],view['body']['nonce'],
                 signer_public_key,view['proposed_debit_units'],view['body']['valid_until'],
                 canonical(envelope).decode(),confirmation,view['state_height'],'signed'))
            return envelope  # context manager commits before the caller receives this

    def export(self, txid: str) -> dict:
        row = self.db.execute('SELECT envelope FROM outbox WHERE txid=?',(txid,)).fetchone()
        require(row is not None, 'unknown signed intention')
        return load_json(row['envelope'].encode())

    def outbox(self) -> list[dict]:
        return [dict(row) for row in self.db.execute('SELECT txid,account,grant_id,nonce,debit,valid_until,state_height,status FROM outbox ORDER BY rowid')]
