"""Durable, explicit native-transfer dispatch to a loopback development node.

Consumes existing signed envelopes from either wallet; never unlocks or signs.
Records a dispatch attempt BEFORE opening a socket. Endpoint responses do not
release obligations or establish execution. Only an independently verified native
receipt can record execution. Fixed-validator trust and a trusted local filesystem
remain assumptions. This is not a public wallet, consensus engine or card adapter.
"""
from __future__ import annotations
import base64
from contextlib import contextmanager
import fcntl
import hashlib
import json
import os
from pathlib import Path
import re
import sqlite3
import stat
import subprocess
import sys
import time

from commit_verifier import (MAX_PACKET_BYTES, encode, load_json, pinned_genesis,
                             timestamp, verify_native_signatures, verify_packet)
from native_core import NativeLedger, BODY_FIELDS, DOMAIN, canonical, fields, integer, identifier, require
from payment_rpc import endpoint_port

MAX_INTENTIONS = 1000
MAX_ATTEMPTS = 100
WORKER_TIMEOUT = 4.0
CONFIRM_DOMAIN = b'1soft/native-dispatch/v1\x00'


def _digest(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def _private_file(path: Path):
    info = path.lstat()
    require(stat.S_ISREG(info.st_mode) and info.st_uid == os.geteuid() and
            info.st_nlink == 1 and stat.S_IMODE(info.st_mode) & 0o077 == 0,
            'journal and sidecars must be private owned regular files without links')


def _create_private(path: Path):
    try:
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600)
    except FileExistsError:
        _private_file(path)
    else:
        os.close(fd)


def _worker(endpoint: str, raw: bytes, request_id: int) -> dict:
    request = encode({'endpoint': endpoint, 'transaction': base64.b64encode(raw).decode(),
                      'request_id': request_id})
    try:
        result = subprocess.run([sys.executable, str(Path(__file__).with_name('payment_rpc.py'))],
            input=request, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
            timeout=WORKER_TIMEOUT, check=False)
        require(result.returncode == 0 and len(result.stdout) <= 4096, 'invalid worker result')
        observed = load_json(result.stdout, max_bytes=4096)
        require(type(observed) is dict, 'invalid worker observation')
        kind = observed.get('observation')
        if kind in ('endpoint_admitted', 'endpoint_declined'):
            fields(observed, {'observation', 'check_tx_code', 'response_sha256'})
            integer(observed['check_tx_code'])
            require((observed['check_tx_code'] == 0) == (kind == 'endpoint_admitted'), 'inconsistent observation')
            require(type(observed['response_sha256']) is str and
                    re.fullmatch('[0-9a-f]{64}', observed['response_sha256']) is not None, 'invalid response digest')
        else:
            fields(observed, {'observation', 'reason'})
            require(kind == 'unresolved' and type(observed['reason']) is str and
                    len(observed['reason']) <= 128, 'invalid unresolved observation')
        return observed
    except (OSError, ValueError, subprocess.TimeoutExpired):
        return {'observation': 'unresolved', 'reason': 'worker unavailable, invalid, or deadline exceeded'}


class DispatchJournal:
    """Single active local dispatcher per journal, including during network waits.

    SQLite provides durable commits; a POSIX file lock prevents overlapping
    dispatcher processes. Restoring an old workspace, other journals, direct key
    use and hostile same-user filesystem changes are outside this protection.
    """
    def __init__(self, path: Path, genesis_bytes: bytes, genesis_sha256: str,
                 endpoint: str, trust_expires_utc: str, *, clock=time.time_ns):
        endpoint_port(endpoint)
        self.trust = pinned_genesis(genesis_bytes, genesis_sha256)
        self.genesis = load_json(genesis_bytes, max_bytes=1024*1024)['app_state']
        validation = NativeLedger(':memory:', self.genesis)
        validation.close()
        stamp = timestamp(trust_expires_utc)
        self.deadline = stamp.seconds*1_000_000_000 + stamp.nanos
        self.clock = clock
        self.endpoint = endpoint
        self.config = encode({'schema': 1, 'genesis_sha256': genesis_sha256,
                              'endpoint': endpoint, 'trust_expires_utc': trust_expires_utc}).decode()
        self.db = None
        self.lock = None
        path = Path(os.path.abspath(path))
        for parent in (path.parent, *path.parent.parents):
            require(not parent.is_symlink(), 'journal parents may not be symlinks')
        info = path.parent.stat()
        require(stat.S_ISDIR(info.st_mode) and info.st_uid == os.geteuid() and
                stat.S_IMODE(info.st_mode) & 0o077 == 0, 'journal directory must be private and owned (0700)')
        lock_path = Path(str(path)+'.dispatch-lock')
        _create_private(lock_path)
        self.lock = os.open(lock_path, os.O_RDWR | os.O_NOFOLLOW | os.O_CLOEXEC)
        try:
            fcntl.flock(self.lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
            _create_private(path)
            for suffix in ('-wal', '-shm', '-journal'):
                candidate = Path(str(path)+suffix)
                if candidate.exists() or candidate.is_symlink():
                    _private_file(candidate)
            self.db = sqlite3.connect(path, isolation_level=None, timeout=3)
            self.db.row_factory = sqlite3.Row
            self.db.execute('PRAGMA journal_mode=WAL')
            self.db.execute('PRAGMA synchronous=FULL')
            self.db.executescript('''
                CREATE TABLE IF NOT EXISTS configuration(id INTEGER PRIMARY KEY CHECK(id=1), value TEXT NOT NULL, clock_ns INTEGER NOT NULL);
                CREATE TABLE IF NOT EXISTS payments(txid TEXT PRIMARY KEY, slot TEXT UNIQUE NOT NULL, raw BLOB NOT NULL,
                    signer TEXT NOT NULL, wire_hash TEXT NOT NULL, confirmation TEXT NOT NULL, status TEXT NOT NULL,
                    attempts INTEGER NOT NULL DEFAULT 0, proof BLOB, proof_hash TEXT);
                CREATE TABLE IF NOT EXISTS events(id INTEGER PRIMARY KEY, txid TEXT NOT NULL, event TEXT NOT NULL, detail TEXT NOT NULL);
            ''')
            with self._atomic():
                row = self.db.execute('SELECT value FROM configuration WHERE id=1').fetchone()
                if row is None:
                    self.db.execute('INSERT INTO configuration VALUES (1,?,0)', (self.config,))
                else:
                    require(row[0] == self.config, 'journal endpoint, genesis or trust policy differs')
        except BaseException:
            self.close()
            raise

    def close(self):
        if self.db is not None:
            self.db.close(); self.db = None
        if self.lock is not None:
            os.close(self.lock); self.lock = None

    def __enter__(self): return self
    def __exit__(self, *_): self.close()

    @contextmanager
    def _atomic(self):
        self.db.execute('BEGIN IMMEDIATE')
        try:
            yield
            self.db.execute('COMMIT')
        except BaseException:
            self.db.execute('ROLLBACK')
            raise

    def _time(self):
        now = self.clock()
        require(type(now) is int and 0 <= now <= 2**63-1, 'invalid local clock')
        old = self.db.execute('SELECT clock_ns FROM configuration WHERE id=1').fetchone()[0]
        require(now >= old, 'local clock moved backwards')
        require(now < self.deadline, 'dispatch trust policy expired')
        self.db.execute('UPDATE configuration SET clock_ns=? WHERE id=1', (now,))
        return now

    def _intention(self, raw: bytes, signer: str) -> dict:
        require(type(raw) is bytes and 1 <= len(raw) <= 16_384, 'invalid native transaction size')
        env = load_json(raw, max_bytes=16_384)
        fields(env, {'body', 'signature'}); fields(env['body'], BODY_FIELDS)
        require(canonical(env) == raw, 'export must contain canonical native transaction bytes')
        body = env['body']; op = body['op']
        require(body['chain_id'] == self.trust.chain_id and
                body['genesis_hash'] == self.trust.native_genesis_hash, 'wrong chain or native genesis')
        identifier(body['sender']); integer(body['nonce']); integer(body['valid_until']); integer(body['max_fee'])
        require(type(body['grant_id']) is str, 'invalid grant label')
        if body['grant_id']: identifier(body['grant_id'])
        fields(op, {'type', 'to', 'units'})
        require(op['type'] == 'transfer', 'this dispatch boundary supports native transfers only')
        identifier(op['to']); integer(op['units'], minimum=1)
        require(op['to'] not in (body['sender'], 'system:fees') and body['sender'] != 'system:fees', 'invalid transfer party')
        require(self.genesis['fee'] <= body['max_fee'], 'fee outside signed consent')
        integer(op['units'] + self.genesis['fee'])
        verify_native_signatures(env, signer, protocol_version=self.genesis.get('protocol_version', 1))
        txid = _digest(DOMAIN+canonical(body))
        slot = _digest(encode([self.trust.native_genesis_hash, body['sender'], body['grant_id'], body['nonce']]))
        confirmation = _digest(CONFIRM_DOMAIN+encode({'config': self.config, 'raw': base64.b64encode(raw).decode(), 'signer': signer}))
        return {'txid': txid, 'slot': slot, 'wire_hash': _digest(raw), 'confirmation': confirmation}

    def _row(self, txid: str):
        require(type(txid) is str and re.fullmatch('[0-9a-f]{64}', txid) is not None, 'invalid transaction ID')
        row = self.db.execute('SELECT * FROM payments WHERE txid=?', (txid,)).fetchone()
        require(row is not None, 'transaction not queued')
        expected = self._intention(bytes(row['raw']), row['signer'])
        require(all(row[k] == v for k, v in expected.items()), 'stored payment failed integrity check')
        require(row['status'] in ('queued','dispatching','endpoint_admitted','endpoint_declined','unresolved','receipt_verified'), 'invalid dispatch status')
        require(type(row['attempts']) is int and 0 <= row['attempts'] <= MAX_ATTEMPTS, 'invalid attempt counter')
        if row['status'] == 'receipt_verified':
            require(type(row['proof']) is bytes and row['proof_hash'] == _digest(row['proof']),
                    'saved receipt proof is missing or corrupted')
            packet = load_json(row['proof'], max_bytes=MAX_PACKET_BYTES)
            verify_packet(packet, self.trust, expected_txids=[txid])
            require(base64.b64decode(packet['transactions'][0]['tx'], validate=True) == bytes(row['raw']),
                    'saved proof is for different transaction bytes')
        else:
            require(row['proof'] is None and row['proof_hash'] is None, 'unexpected stored proof')
        return row

    def _event(self, txid, kind, detail):
        self.db.execute('INSERT INTO events(txid,event,detail) VALUES (?,?,?)', (txid, kind, encode(detail).decode()))

    def queue(self, raw: bytes, signer_public_key: str) -> dict:
        item = self._intention(raw, signer_public_key)
        with self._atomic():
            self._time()
            row = self.db.execute('SELECT * FROM payments WHERE txid=?', (item['txid'],)).fetchone()
            if row is not None:
                require(bytes(row['raw']) == raw and row['signer'] == signer_public_key, 'same intention has different signature or signer')
            else:
                require(self.db.execute('SELECT count(*) FROM payments').fetchone()[0] < MAX_INTENTIONS, 'development journal limit reached')
                require(self.db.execute('SELECT 1 FROM payments WHERE slot=?', (item['slot'],)).fetchone() is None,
                        'different signed transaction already occupies this authority nonce')
                self.db.execute('INSERT INTO payments(txid,slot,raw,signer,wire_hash,confirmation,status) VALUES (?,?,?,?,?,?,?)',
                    (item['txid'],item['slot'],raw,signer_public_key,item['wire_hash'],item['confirmation'],'queued'))
                self._event(item['txid'],'queued',{'signature_verified': True, 'current_authority_verified': False})
        return self.status(item['txid'])

    def status(self, txid: str) -> dict:
        row = self._row(txid)
        return {'native_txid': txid, 'wire_sha256': row['wire_hash'], 'endpoint': self.endpoint,
                'status': row['status'], 'attempts': row['attempts'], 'dispatch_confirmation': row['confirmation'],
                'receipt_verified': row['status'] == 'receipt_verified',
                'live_network_provenance_established': False, 'current_authority_verified': False,
                'not_established': ['latest account state','public-network operation','external card or cash settlement']}

    def export(self, txid: str) -> bytes:
        return bytes(self._row(txid)['raw'])

    def events(self, txid: str) -> list[dict]:
        self._row(txid)
        return [{'id': r['id'], 'event': r['event'], 'detail': json.loads(r['detail'])}
                for r in self.db.execute('SELECT * FROM events WHERE txid=? ORDER BY id', (txid,))]

    def dispatch(self, txid: str, confirmation: str, *, replay: bool = False) -> dict:
        require(type(replay) is bool, 'replay must be explicit boolean')
        with self._atomic():
            self._time(); row = self._row(txid)
            require(type(confirmation) is str and confirmation == row['confirmation'], 'exact dispatch confirmation required')
            require(row['status'] != 'receipt_verified', 'verified payment must not be dispatched again')
            require((row['status'] == 'queued') != replay,
                    'first send and explicit exact-byte replay are different operations')
            require(row['attempts'] < MAX_ATTEMPTS, 'development retry limit reached')
            attempt = row['attempts']+1; raw = bytes(row['raw'])
            self.db.execute("UPDATE payments SET status='dispatching',attempts=? WHERE txid=?", (attempt, txid))
            self._event(txid, 'dispatch_committed_before_io', {'attempt': attempt, 'exact_byte_replay': replay,
                        'endpoint': self.endpoint, 'wire_sha256': row['wire_hash']})
        # A crash or interruption from here leaves a durable unresolved attempt.
        observed = _worker(self.endpoint, raw, attempt)
        with self._atomic():
            self.db.execute('UPDATE payments SET status=? WHERE txid=?', (observed['observation'], txid))
            self._event(txid, 'endpoint_observation_not_settlement', observed)
        return self.status(txid)

    def export_receipt(self, txid: str) -> bytes:
        """Return the existing reverified proof, never a new signature or query."""
        row = self._row(txid)
        require(row['status'] == 'receipt_verified', 'verified receipt is not available')
        return bytes(row['proof'])

    def refresh_receipt(self, txid: str, *, read_attempts: int = 1) -> dict:
        """Read evidence only; never send, sign, replay, or clear a payment slot."""
        from receipt_collector import attempts, fetch_packet
        attempts(read_attempts)
        with self._atomic():
            self._time()
            row = self._row(txid)
            if row['status'] == 'receipt_verified':
                return {**self.status(txid), 'collection_status':'already_verified', 'read_requests':0}
            raw = bytes(row['raw'])
            self._event(txid, 'receipt_collection_requested', {'read_attempts':read_attempts})
        collected = fetch_packet(self.endpoint, raw, read_attempts=read_attempts)
        outcome = collected['status']
        if outcome == 'evidence_collected':
            try:
                # Recheck signatures, exact bytes, pinned trust and time in this
                # process. A child claiming success cannot mark a payment paid.
                self.prove(txid, encode(collected['packet']))
                outcome = 'receipt_verified'
            except ValueError:
                outcome = 'evidence_rejected'
        with self._atomic():
            self._event(txid, 'receipt_collection_result',
                        {'status':outcome, 'read_requests':collected['requests']})
        return {**self.status(txid), 'collection_status':outcome,
                'read_requests':collected['requests']}

    def prove(self, txid: str, certificate_bytes: bytes) -> dict:
        row = self._row(txid)
        packet = load_json(certificate_bytes, max_bytes=MAX_PACKET_BYTES)
        verified = verify_packet(packet, self.trust, expected_txids=[txid])
        # The native ID hashes the body; also bind the exact signature/wire bytes.
        require(base64.b64decode(packet['transactions'][0]['tx'], validate=True) == bytes(row['raw']),
                'receipt does not prove the exact exported transaction')
        stamp = timestamp(packet['state_commit']['header']['time'])
        with self._atomic():
            now = self._time()
            require(stamp.seconds*1_000_000_000+stamp.nanos <= now+5_000_000_000, 'future-dated certificate')
            current = self._row(txid)
            if current['status'] != 'receipt_verified':
                raw_proof = encode(packet)
                require(len(raw_proof) <= MAX_PACKET_BYTES, 'normalized certificate exceeds limit')
                self.db.execute("UPDATE payments SET status='receipt_verified',proof=?,proof_hash=? WHERE txid=?",
                                (raw_proof,_digest(raw_proof),txid))
                self._event(txid,'native_receipt_verified',{'certificate_sha256':_digest(raw_proof),
                    'state_height':verified['state']['state_height'], 'scope': verified['scope'],
                    'live_network_provenance_established': False})
        return self.status(txid)
