"""Offline certificate-backed review and durable signing decisions (development).

Static genesis validators only. Recent authenticated state is NOT guaranteed to
be the latest state. Trusted local clock, filesystem, policy and genesis remain
assumptions. No network requests, broadcasting, or production custody claim.
"""
from __future__ import annotations

import hashlib
import hmac
import json
import os
from pathlib import Path
import re
import sqlite3
import stat
import time
from typing import Callable

from block_application import restore
from commit_verifier import (encode, load_json, pinned_genesis, timestamp,
                             verify_state_witness, verify_signed_header, block_id)
from native_core import Reject, address, canonical, public, require, sign, accept_account_key
from offline_signer import _load_vault, review_intent
from wallet_obligations import inventory, constrain, checked_decision

DOMAIN = b'1soft/certified-review/v1\x00'
MAX_EVIDENCE = 16 * 1024 * 1024
MAX_ROWS = 10000
POLICY_FIELDS = {'schema', 'genesis_sha256', 'trust_expires_utc',
                 'minimum_header_height', 'maximum_age_seconds', 'future_skew_seconds'}


def nanos(value: str) -> int:
    stamp = timestamp(value)
    return stamp.seconds * 1_000_000_000 + stamp.nanos


def _int(value, lo, hi, name):
    require(type(value) is int and lo <= value <= hi, 'invalid ' + name)
    return value


def _hash(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def _bounded_copy(value):
    raw = encode(value)
    require(len(raw) <= MAX_EVIDENCE, 'certificate exceeds development limit')
    return load_json(raw)


class CertifiedWallet:
    """One locally pinned trust policy and one durable signing journal.

    Review never unlocks a key. Approve rechecks the certificate, local checkpoint,
    and nonce before key access, then rechecks time after decryption. A committed
    signature is recoverable if the process dies before the caller receives it.
    The journal must be shared by all local signers using this protection.
    """
    def __init__(self, journal: Path, genesis_bytes: bytes, policy: dict,
                 *, clock: Callable[[], int] = time.time_ns):
        require(type(policy) is dict and set(policy) == POLICY_FIELDS,
                'invalid trust policy fields')
        require(type(policy['schema']) is int and policy['schema'] == 1,
                'unsupported trust policy')
        require(type(policy['genesis_sha256']) is str and
                re.fullmatch('[0-9a-f]{64}', policy['genesis_sha256']) is not None,
                'invalid trusted genesis digest')
        _int(policy['minimum_header_height'], 1, 2**53-1, 'minimum height')
        _int(policy['maximum_age_seconds'], 1, 86400, 'maximum age')
        _int(policy['future_skew_seconds'], 0, 30, 'future skew')
        self.trust = pinned_genesis(genesis_bytes, policy['genesis_sha256'])
        self.engine_genesis = load_json(genesis_bytes, max_bytes=1024*1024)
        self.policy = json.loads(encode(policy))
        self.policy_id = _hash(encode(self.policy))
        self.trust_expires = nanos(policy['trust_expires_utc'])
        self.clock = clock
        journal = Path(os.path.abspath(journal))
        require(os.name == 'posix', 'journal requires Linux/WSL or POSIX')
        # SQLite reopens its files: this is not hostile-filesystem/race protection.
        # A private, trusted, same-user directory is an explicit local assumption.
        for path in (journal.parent, *journal.parent.parents):
            require(not path.is_symlink(), 'journal parent may not be a symbolic link')
        parent = journal.parent.stat()
        require(stat.S_ISDIR(parent.st_mode) and parent.st_uid == os.geteuid() and
                stat.S_IMODE(parent.st_mode) & 0o077 == 0,
                'journal parent must be private and owned (0700)')
        try:
            fd = os.open(journal, os.O_CREAT | os.O_EXCL | os.O_WRONLY | os.O_NOFOLLOW, 0o600)
        except FileExistsError:
            info = journal.lstat()
            require(stat.S_ISREG(info.st_mode) and info.st_uid == os.geteuid() and
                    info.st_nlink == 1 and stat.S_IMODE(info.st_mode) & 0o077 == 0,
                    'journal must be an owned private regular file with no links')
        else:
            os.close(fd)
        for suffix in ('-wal', '-shm', '-journal'):
            sidecar = Path(str(journal) + suffix)
            if sidecar.exists() or sidecar.is_symlink():
                info = sidecar.lstat()
                require(stat.S_ISREG(info.st_mode) and info.st_nlink == 1 and
                        info.st_uid == os.geteuid() and stat.S_IMODE(info.st_mode) & 0o077 == 0,
                        'unsafe journal sidecar')
        self.db = sqlite3.connect(journal, isolation_level=None, timeout=10)
        try:
            tables = {row[0] for row in self.db.execute("SELECT name FROM sqlite_master WHERE type='table'")}
            require(not tables.intersection({'anchor','outbox','configuration','payments','policy'}),
                    'different wallet or dispatcher journal; export/reconcile it explicitly, never overwrite')
            self.db.execute('PRAGMA journal_mode=WAL')
            self.db.execute('PRAGMA synchronous=FULL')
            self.db.executescript('''
                CREATE TABLE IF NOT EXISTS checkpoint (
                    id INTEGER PRIMARY KEY CHECK(id=1), policy_id TEXT NOT NULL,
                    height INTEGER NOT NULL, block_hash TEXT NOT NULL,
                    header_ns INTEGER NOT NULL, clock_ns INTEGER NOT NULL);
                CREATE TABLE IF NOT EXISTS decisions (
                    id TEXT PRIMARY KEY, slot TEXT UNIQUE NOT NULL, review TEXT NOT NULL,
                    result TEXT NOT NULL, result_hash TEXT NOT NULL);
                CREATE TABLE IF NOT EXISTS wallet_evidence (
                    id INTEGER PRIMARY KEY CHECK(id=1), witness TEXT NOT NULL,
                    witness_hash TEXT NOT NULL);
            ''')
            self.db.execute('BEGIN IMMEDIATE')
            row = self.db.execute('SELECT policy_id FROM checkpoint WHERE id=1').fetchone()
            if row:
                require(row[0] == self.policy_id, 'journal belongs to a different trust policy')
            else:
                self.db.execute('INSERT INTO checkpoint VALUES (1,?,0,\'\',0,?)',
                                (self.policy_id, _int(self.clock(), 0, 2**63-1, 'local clock nanoseconds')))
            self.db.execute('COMMIT')
        except BaseException:
            if self.db.in_transaction:
                self.db.execute('ROLLBACK')
            self.db.close()
            raise

    def close(self):
        self.db.close()

    def _time_check(self, header_ns: int | None) -> int:
        now = _int(self.clock(), 0, 2**63-1, 'local clock nanoseconds')
        require(now < self.trust_expires, 'local trust policy expired')
        if header_ns is not None:
            require(header_ns <= now + self.policy['future_skew_seconds'] * 1_000_000_000,
                    'header is too far in the future')
            require(now - header_ns <= self.policy['maximum_age_seconds'] * 1_000_000_000,
                    'authenticated snapshot is too old')
        return now

    def _checkpoint_check(self, cert: dict, header_ns: int, now: int, signed_header: dict,
                          continuation: list | None = None):
        row = self.db.execute('SELECT height,block_hash,header_ns,clock_ns FROM checkpoint WHERE id=1').fetchone()
        require(now >= row[3], 'local clock moved backwards')
        require(cert['height'] >= row[0], 'certificate rolls back the local checkpoint')
        links = [] if continuation is None else _bounded_copy(continuation)
        require(type(links) is list and len(links) <= 64, 'invalid bounded header continuation')
        if cert['height'] == row[0]:
            require(not links and cert['block_hash'] == row[1], 'conflicting certificate at observed height')
        elif row[0]:
            require(len(links) == cert['height'] - row[0] - 1,
                    'missing signed header continuation; cannot release holds across an unlinked checkpoint')
            previous_hash, previous_height, previous_ns = row[1], row[0], row[2]
            previous_id = None
            stored = self.db.execute('SELECT witness,witness_hash FROM wallet_evidence WHERE id=1').fetchone()
            if stored:
                require(_hash(stored[0].encode()) == stored[1], 'stored witness integrity mismatch')
                previous_id = load_json(stored[0].encode())['state_commit']['commit']['block_id']
            for following in [*links, signed_header]:
                next_info = verify_signed_header(following, self.trust, expected_height=previous_height+1)
                require(following['header']['last_block_id']['hash'].upper() == previous_hash,
                        'adjacent certificate does not extend observed header')
                if previous_id is not None:
                    require(block_id(following['header']['last_block_id']).SerializeToString() ==
                            block_id(previous_id).SerializeToString(), 'header block-ID continuation differs')
                next_ns = nanos(following['header']['time'])
                require(next_ns >= previous_ns, 'certificate timestamp moved backwards')
                previous_hash, previous_height, previous_ns = next_info['block_hash'], next_info['height'], next_ns
                previous_id = following['commit']['block_id']
        else:
            require(not links, 'initial checkpoint does not take a continuation')
        require(header_ns >= row[2], 'certificate timestamp moved backwards')

    def _verified_snapshot(self, witness: dict, continuation: list | None = None):
        witness = _bounded_copy(witness)
        require(type(witness) is dict and set(witness) == {'schema','state','state_commit'}
                and type(witness['schema']) is int and witness['schema'] == 1,
                'invalid account witness')
        state = witness['state']
        cert = verify_state_witness(state, witness['state_commit'], self.trust)
        require(cert['height'] >= self.policy['minimum_header_height'], 'below locally required height')
        header_ns = nanos(witness['state_commit']['header']['time'])
        now = self._time_check(header_ns)
        self._checkpoint_check(cert, header_ns, now, witness['state_commit'], continuation)
        for rows in state['native'].values():
            require(type(rows) is list and len(rows) <= MAX_ROWS, 'snapshot row limit exceeded')
        ledger = restore(state['genesis'], state['native'])
        try:
            native_height = int(dict(ledger.db.execute('SELECT k,v FROM meta'))['height'])
            require(native_height <= state['height'], 'native height exceeds certified application height')
            return witness, ledger, cert, header_ns, now
        except BaseException:
            ledger.close()
            raise

    def _prepare(self, witness: dict, body: dict, signer_pk: str, mode: str,
                 continuation: list | None = None):
        witness, ledger, cert, header_ns, now = self._verified_snapshot(witness, continuation)
        state = witness['state']
        try:
            base = review_intent(state['genesis'], body, signer_pk, mode=mode)
            body = base['body']
            # ABCI empty blocks advance the application height, not necessarily
            # the native ledger's last-transaction height.
            native_height = int(dict(ledger.db.execute('SELECT k,v FROM meta'))['height'])
            require(native_height <= state['height'], 'native height exceeds certified application height')
            owner = ledger._account(body['sender'])
            at_height = state['height'] + 1
            require(body['valid_until'] >= at_height, 'intention already expired at certified state')
            required = base['proposed_account_debit_units']
            require(owner['balance'] >= required, 'certified balance is insufficient')
            grant = None
            budget = None
            if body['grant_id']:
                grant_id = ledger.grant_storage_id(owner['id'], body['grant_id'])
                grant = ledger.db.execute('SELECT * FROM grants WHERE id=?', (grant_id,)).fetchone()
                require(grant is not None and grant['owner'] == owner['id'], 'unknown certified grant')
                require(not grant['revoked'] and grant['epoch'] == owner['epoch'] and
                        grant['expires'] >= at_height, 'certified grant is inactive')
                require(body['op']['to'] in json.loads(grant['recipients']), 'recipient outside certified grant')
                require(grant['spent'] + required <= grant['cap'], 'certified grant budget exceeded')
                if ledger.budgets is not None:
                    budget = ledger.budgets.for_grant(owner, grant, at_height, body['op']['to'], required)
            authority = grant if grant is not None else owner
            require(body['nonce'] == authority['nonce'], 'certified nonce does not match')
            if mode == 'sign':
                require(signer_pk == authority['public_key'], 'signer is not the certified controlling key')
            if ledger.budgets is not None:
                ledger.db.execute('SAVEPOINT budget_review')
            op = body['op']
            if op['type'] == 'transfer':
                ledger._account(op['to'])
            elif op['type'] == 'grant':
                key = ledger.grant_storage_id(owner['id'], op['id'])
                require(ledger.db.execute('SELECT 1 FROM grants WHERE id=?', (key,)).fetchone() is None,
                        'certified grant label already exists')
                require(op['expires'] >= at_height, 'new grant already expired')
                for recipient in op['recipients']:
                    ledger._account(recipient)
                if ledger.budgets is not None:
                    # Mutates only this isolated, disposable validation copy.
                    ledger.budgets.bind(owner, key, op, at_height)
            elif op['type'] == 'budget_create' and ledger.budgets is not None:
                ledger.budgets.create(owner, op, at_height)
            elif op['type'] == 'budget_revoke' and ledger.budgets is not None:
                ledger.budgets.revoke(owner, op)
            elif op['type'] == 'revoke':
                key = ledger.grant_storage_id(owner['id'], op['id'])
                target = ledger.db.execute('SELECT owner FROM grants WHERE id=?', (key,)).fetchone()
                require(target is not None and target[0] == owner['id'], 'not the certified grant owner')
            elif op['type'] in ('open_account','rotate_key'):
                require(ledger.db.execute('SELECT 1 FROM accounts WHERE public_key=?',
                                         (op['public_key'],)).fetchone() is None,
                        'incoming key already controls an account')
                if op['type'] == 'open_account':
                    require(ledger.db.execute('SELECT 1 FROM accounts WHERE id=?',
                                             (address(op['public_key']),)).fetchone() is None,
                            'certified account already exists')
            if ledger.budgets is not None:
                ledger.db.execute('ROLLBACK TO budget_review')
                ledger.db.execute('RELEASE budget_review')
            slot = [body['sender'], 'owner', body['nonce']]
            if grant is not None:
                slot = [body['sender'], 'grant', body['grant_id'], grant['epoch'], body['nonce']]
            if mode == 'accept':
                slot = [body['sender'], 'incoming-consent', signer_pk, body['nonce']]
            review = {'schema':1, 'development_only':True, 'mode':mode, 'body':body,
                'signer_public_key':signer_pk, 'asset':state['genesis']['asset'],
                'native_fee_units':base['native_fee_units'], 'proposed_account_debit_units':required,
                'authority_at_snapshot_verified':True, 'latest_state_guaranteed':False,
                'state_height':state['height'], 'header_height':cert['height'],
                'header_hash':cert['block_hash'], 'state_app_hash':cert['state_app_hash'],
                'header_time_utc':witness['state_commit']['header']['time'],
                'trust_policy_sha256':self.policy_id, 'signed_power':cert['signed_power'],
                'total_power':cert['total_power'], 'account_balance_units':owner['balance'],
                'grant_remaining_units':None if grant is None else grant['cap']-grant['spent'],
                'warning':'Authenticated historical snapshot, not proof of latest state, broadcast or settlement.'}
            if ledger.protocol_version == 3:
                review['shared_budget_id'] = None if budget is None else budget['id']
                review['shared_budget_remaining_units'] = None if budget is None else budget['cap']-budget['spent']
            summary = inventory(self.db, self.policy_id, ledger, state['height'])
            review.update(constrain(review, summary, ledger, body, mode, signer_pk))
            decision_id = _hash(DOMAIN + encode(review))
            review['confirmation'] = decision_id
            # Preserve old decisions; new uniqueness is per exact intention. Pending
            # logical-nonce exclusivity is enforced from the verified inventory.
            slot_key = _hash(encode([self.policy_id, slot, _hash(canonical(body))]))
            return review, slot_key, ledger, witness, header_ns, now
        except BaseException:
            ledger.close()
            raise

    def review(self, witness: dict, body: dict, signer_pk: str, *, mode: str = 'sign',
               continuation: list | None = None) -> dict:
        self.db.execute('BEGIN IMMEDIATE')
        ledger = None
        try:
            review, slot, ledger, frozen, header_ns, now = self._prepare(witness, body, signer_pk, mode, continuation)
            require(self.db.execute('SELECT 1 FROM decisions WHERE slot=?', (slot,)).fetchone() is None,
                    'this authority nonce already has a local signing decision; export it instead')
            self._observe(review, header_ns, now, frozen)
            self.db.execute('COMMIT')
            return review
        except BaseException:
            if self.db.in_transaction: self.db.execute('ROLLBACK')
            raise
        finally:
            if ledger is not None: ledger.close()

    def _observe(self, review: dict, header_ns: int, now: int, witness: dict):
        data = encode(witness)
        self.db.execute('INSERT OR REPLACE INTO wallet_evidence VALUES (1,?,?)',
                        (data.decode(), _hash(data)))
        self.db.execute('UPDATE checkpoint SET height=?,block_hash=?,header_ns=?,clock_ns=? WHERE id=1',
            (review['header_height'], review['header_hash'], header_ns, now))

    def approve(self, witness: dict, body: dict, signer_pk: str, confirmation: str,
                vault: Path, password: bytes, *, mode: str = 'sign',
                continuation: list | None = None) -> dict:
        self.db.execute('BEGIN IMMEDIATE')
        ledger = None
        try:
            review, slot, ledger, frozen, header_ns, now = self._prepare(witness, body, signer_pk, mode, continuation)
            require(type(confirmation) is str and re.fullmatch('[0-9a-f]{64}', confirmation) is not None
                    and hmac.compare_digest(confirmation, review['confirmation']), 'certified review changed')
            require(self.db.execute('SELECT 1 FROM decisions WHERE slot=?', (slot,)).fetchone() is None,
                    'this authority nonce already has a local signing decision; export it instead')
            key = _load_vault(vault, password)
            require(public(key) == signer_pk, 'vault is not the certified signer')
            # An expensive unlock must not turn an expired review into a signature.
            now_after = self._time_check(header_ns)
            require(now_after >= now, 'local clock moved backwards while unlocking')
            result = (accept_account_key(key, review['body']) if mode == 'accept'
                      else sign(key, review['body']))
            if mode == 'sign':
                ledger.apply(result, height=review['state_height'] + 1)
            result_wire = canonical(result)
            self.db.execute('INSERT INTO decisions VALUES (?,?,?,?,?)',
                (review['confirmation'], slot, encode(review).decode(), result_wire.decode(), _hash(result_wire)))
            self._observe(review, header_ns, now_after, frozen)
            self.db.execute('COMMIT')
            return {'decision_id':review['confirmation'], 'status':'signed-locally-not-broadcast',
                    'result':result}
        except BaseException:
            if self.db.in_transaction: self.db.execute('ROLLBACK')
            raise
        finally:
            if ledger is not None: ledger.close()

    def sync(self, witness: dict, *, continuation: list | None = None) -> dict:
        """Verify a full checkpoint and reconcile every existing signature.

        No receipt/hold status is accepted from an RPC success flag. Decisions
        remain immutable. Reconciliation and checkpoint advancement are atomic.
        """
        self.db.execute('BEGIN IMMEDIATE')
        ledger = None
        try:
            frozen, ledger, cert, header_ns, now = self._verified_snapshot(witness, continuation)
            summary = inventory(self.db, self.policy_id, ledger, frozen['state']['height'])
            observation = {'header_height': cert['height'], 'header_hash': cert['block_hash']}
            self._observe(observation, header_ns, now, frozen)
            self.db.execute('COMMIT')
            return self._inventory_view(summary, frozen['state']['height'])
        except BaseException:
            if self.db.in_transaction: self.db.execute('ROLLBACK')
            raise
        finally:
            if ledger is not None: ledger.close()

    @staticmethod
    def _inventory_view(summary: dict, height: int) -> dict:
        return {'schema': 1, 'state_height': height, 'decision_count': summary['decisions'],
                'decisions': summary['entries'], 'pending_account_units': summary['accounts'],
                'pending_grant_units': summary['grants'], 'pending_budget_units': summary['budgets'],
                'inventory_digest': summary['digest'], 'broadcast': False,
                'latest_state_guaranteed': False, 'scope': 'this local journal and the stated historical full snapshot'}

    def pending(self) -> dict:
        """Reverify saved historical evidence without requiring a live clock.

        This is recoverable inspection, not fresh signing authority or permission
        to broadcast. A trust expiry never prevents exporting a saved signature.
        """
        self.db.execute('BEGIN IMMEDIATE')
        ledger = None
        try:
            row = self.db.execute('SELECT witness,witness_hash FROM wallet_evidence WHERE id=1').fetchone()
            require(row is not None and _hash(row[0].encode()) == row[1], 'no intact saved account witness; sync first')
            frozen = load_json(row[0].encode())
            cert = verify_state_witness(frozen['state'], frozen['state_commit'], self.trust)
            checkpoint = self.db.execute('SELECT height,block_hash FROM checkpoint WHERE id=1').fetchone()
            require((cert['height'], cert['block_hash']) == tuple(checkpoint), 'saved witness differs from checkpoint')
            ledger = restore(frozen['state']['genesis'], frozen['state']['native'])
            summary = inventory(self.db, self.policy_id, ledger, frozen['state']['height'])
            self.db.execute('COMMIT')
            return {**self._inventory_view(summary, frozen['state']['height']), 'freshness_checked': False}
        except BaseException:
            if self.db.in_transaction: self.db.execute('ROLLBACK')
            raise
        finally:
            if ledger is not None: ledger.close()

    def export(self, decision_id: str) -> dict:
        require(type(decision_id) is str and re.fullmatch('[0-9a-f]{64}', decision_id) is not None,
                'invalid signing decision identifier')
        row = self.db.execute('SELECT id,slot,review,result,result_hash FROM decisions WHERE id=?', (decision_id,)).fetchone()
        require(row is not None, 'signing decision not found')
        checked = checked_decision(row, self.engine_genesis['app_state'], self.policy_id)
        return {'decision_id':decision_id, 'status':'previously-signed-not-settlement-proof',
                'result':checked['result']}
