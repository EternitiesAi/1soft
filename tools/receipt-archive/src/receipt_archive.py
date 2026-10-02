"""Append-only local receipt evidence, separate from all monetary journals.

No archive miss is a proof of nonexecution. Contradictory verified receipts are
retained and reported as conflict, never resolved by arrival time. A local host
can delete or rewrite an entire archive; hashes do not prove availability or
resistance to a malicious operator. No SQL/database file comes from a capsule.
"""
from __future__ import annotations

from contextlib import contextmanager
import os
from pathlib import Path
import sqlite3
import stat

from commit_verifier import b64, encode, load_json, pinned_genesis
from receipt_capsule import (MAX_BYTES, ArchiveError, hash_text, need, sha,
                             transaction_identity, verify_capsule, frozen)

APP_ID = 0x31534152
SCHEMA = 1
DEFAULT_ENTRIES = 4096
DEFAULT_BYTES = 128 * 1024 * 1024
POLICY_COLUMNS = ('id', 'schema', 'genesis_sha256', 'max_entries', 'max_bytes')
CAPSULE_COLUMNS = ('id', 'txid', 'receipt_hash', 'wire_hash', 'header_height',
                   'header_hash', 'payload', 'bytes')


def private_path(path):
    need(os.name == 'posix', 'archive requires POSIX local storage')
    p = Path(os.path.abspath(path))
    for ancestor in (p.parent, *p.parent.parents):
        need(not ancestor.is_symlink(), 'archive ancestor symlink refused')
    info = p.parent.stat()
    need(stat.S_ISDIR(info.st_mode) and info.st_uid == os.geteuid() and
         stat.S_IMODE(info.st_mode) & 0o077 == 0, 'private owned archive directory required')
    for f in [p, *(Path(str(p) + s) for s in ('-wal', '-shm', '-journal'))]:
        if f.exists() or f.is_symlink():
            m = f.lstat()
            need(stat.S_ISREG(m.st_mode) and m.st_nlink == 1 and m.st_uid == os.geteuid() and
                 stat.S_IMODE(m.st_mode) & 0o077 == 0, 'unsafe archive database or sidecar')
    return p


def write_new(path, raw):
    """Exclusive export. Failed output never changes the archive or a payment."""
    need(type(raw) is bytes and len(raw) <= MAX_BYTES, 'export exceeds limit')
    p = private_path(path)
    fd = os.open(p, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, 'wb') as f:
        f.write(raw); f.flush(); os.fsync(f.fileno())
    d = os.open(p.parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        os.fsync(d)
    finally:
        os.close(d)


class ReceiptArchive:
    def __init__(self, path, genesis_bytes, genesis_sha256, *, create=False,
                 read_only=False, max_entries=DEFAULT_ENTRIES, max_bytes=DEFAULT_BYTES):
        hash_text(genesis_sha256)
        pinned_genesis(genesis_bytes, genesis_sha256)
        need(type(create) is bool and type(read_only) is bool and not (create and read_only),
             'invalid archive mode')
        need(type(max_entries) is int and 1 <= max_entries <= 100000 and
             type(max_bytes) is int and 1 <= max_bytes <= 1024*1024*1024, 'invalid archive capacity')
        self.genesis = bytes(genesis_bytes)
        self.genesis_sha256 = genesis_sha256
        self.read_only = read_only
        self.db = None
        self.path = private_path(path)
        if create:
            # Never initializes or repairs an existing wallet/dispatcher/empty file.
            fd = os.open(self.path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
            os.close(fd)
        else:
            need(self.path.is_file(), 'archive is not initialized')
        try:
            mode = 'ro' if read_only else 'rw'
            self.db = sqlite3.connect(self.path.as_uri() + '?mode=' + mode,
                                      uri=True, isolation_level=None, timeout=5)
            if create:
                self.db.execute('PRAGMA journal_mode=WAL')
                self.db.execute('PRAGMA synchronous=FULL')
                with self.atomic():
                    self.db.execute(f'PRAGMA application_id={APP_ID}')
                    self.db.execute('CREATE TABLE archive_policy(id INTEGER PRIMARY KEY CHECK(id=1), schema INTEGER NOT NULL, genesis_sha256 TEXT NOT NULL, max_entries INTEGER NOT NULL, max_bytes INTEGER NOT NULL)')
                    self.db.execute('CREATE TABLE capsules(id TEXT PRIMARY KEY, txid TEXT NOT NULL, receipt_hash TEXT NOT NULL, wire_hash TEXT NOT NULL, header_height INTEGER NOT NULL, header_hash TEXT NOT NULL, payload BLOB NOT NULL, bytes INTEGER NOT NULL)')
                    self.db.execute('CREATE INDEX by_transaction ON capsules(txid)')
                    self.db.execute('CREATE INDEX by_header ON capsules(header_height)')
                    self.db.execute('INSERT INTO archive_policy VALUES (1,?,?,?,?)',
                                    (SCHEMA, genesis_sha256, max_entries, max_bytes))
                directory = os.open(self.path.parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
                try: os.fsync(directory)
                finally: os.close(directory)
            self._policy()
            if not read_only:
                self.db.execute('PRAGMA synchronous=FULL')
                need(self.db.execute('PRAGMA journal_mode').fetchone()[0] == 'wal',
                     'archive journal mode differs; no automatic repair')
        except BaseException:
            self.close()
            raise

    def close(self):
        if self.db is not None:
            self.db.close(); self.db = None

    def __enter__(self): return self
    def __exit__(self, *_): self.close()

    @contextmanager
    def atomic(self, write=True):
        need(not self.db.in_transaction, 'archive transaction already active')
        need(not (write and self.read_only), 'archive is read-only')
        self.db.execute('BEGIN IMMEDIATE' if write else 'BEGIN')
        try:
            yield
            self.db.execute('COMMIT')
        except BaseException:
            if self.db.in_transaction: self.db.execute('ROLLBACK')
            raise

    def _policy(self):
        need(self.db.execute('PRAGMA application_id').fetchone()[0] == APP_ID,
             'not a receipt archive; existing database untouched')
        objects = self.db.execute("SELECT type,name FROM sqlite_master WHERE name NOT LIKE 'sqlite_%'").fetchall()
        need(set(objects) == {('table','archive_policy'), ('table','capsules'),
                             ('index','by_transaction'), ('index','by_header')}, 'archive schema differs')
        for table, expected in (('archive_policy', POLICY_COLUMNS), ('capsules', CAPSULE_COLUMNS)):
            need(tuple(x[1] for x in self.db.execute(f'PRAGMA table_info({table})')) == expected,
                 'archive columns differ')
        rows = self.db.execute('SELECT * FROM archive_policy').fetchall()
        need(len(rows) == 1 and rows[0][:3] == (1, SCHEMA, self.genesis_sha256),
             'archive policy or genesis differs')
        maximum_entries, maximum_bytes = rows[0][3:]
        need(type(maximum_entries) is int and 1 <= maximum_entries <= 100000 and
             type(maximum_bytes) is int and 1 <= maximum_bytes <= 1024*1024*1024,
             'archive stored capacity invalid')
        count, size = self.db.execute('SELECT count(*),coalesce(sum(bytes),0) FROM capsules').fetchone()
        need(count <= maximum_entries and 0 <= size <= maximum_bytes, 'archive exceeds configured capacity')
        need(self.db.execute('SELECT 1 FROM capsules WHERE bytes!=length(payload) OR bytes<=0 OR bytes>? LIMIT 1',
                             (MAX_BYTES,)).fetchone() is None, 'archive stored sizes differ')
        return maximum_entries, maximum_bytes, count, size

    @staticmethod
    def _metadata(report):
        return (report['evidence_id'], report['native_txid'], report['receipt_sha256'],
                report['wire_sha256'], report['state_header_height'], report['state_header_hash'])

    def _check_row(self, row):
        need(type(row[6]) is bytes and row[7] == len(row[6]), 'archive payload type/length differs')
        c = load_json(row[6], max_bytes=MAX_BYTES)
        need(encode(c) == row[6] and sha(row[6]) == row[0], 'archive payload hash differs')
        r = verify_capsule(c, self.genesis, self.genesis_sha256,
                          expected_transaction=b64(c['transaction']), expected_header_hash=row[5])
        need(self._metadata(r) == tuple(row[:6]), 'archive index differs from reverified evidence')
        return c, r

    def put(self, capsule, *, expected_transaction, expected_header_hash):
        # Freeze caller-owned data once; verification and insertion use the same bytes.
        c = frozen(capsule)
        raw = encode(c)
        r = verify_capsule(c, self.genesis, self.genesis_sha256,
                          expected_transaction=expected_transaction, expected_header_hash=expected_header_hash)
        with self.atomic():
            max_entries, max_bytes, count, size = self._policy()
            old = self.db.execute('SELECT * FROM capsules WHERE id=?', (r['evidence_id'],)).fetchone()
            if old:
                self._check_row(old)
                need(old[6] == raw, 'same evidence ID has different bytes')
                stored = False
            else:
                need(count < max_entries and size + len(raw) <= max_bytes, 'archive capacity reached; no eviction')
                self.db.execute('INSERT INTO capsules VALUES (?,?,?,?,?,?,?,?)',
                                (*self._metadata(r), raw, len(raw)))
                stored = True
        return {'status': 'stored' if stored else 'already_stored',
                'evidence_id': r['evidence_id'], 'wallet_reservations_changed': False}

    def lookup(self, expected_transaction):
        txid, wire_hash, _ = transaction_identity(expected_transaction)
        with self.atomic(write=False):
            self._policy()
            rows = self.db.execute('SELECT * FROM capsules WHERE txid=? ORDER BY id', (txid,)).fetchall()
            reports = [self._check_row(row)[1] for row in rows]
            receipt_conflict = len({r['receipt_sha256'] for r in reports}) > 1
            wire_conflict = any(r['wire_sha256'] != wire_hash for r in reports)
            anchor_conflict = False
            for height in {r['state_header_height'] for r in reports}:
                # Reverify all observed competing anchors at the selected height,
                # including evidence for other payments. An SQL index is not proof.
                anchored = self.db.execute('SELECT * FROM capsules WHERE header_height=?', (height,)).fetchall()
                anchor_conflict |= len({self._check_row(row)[1]['state_header_hash'] for row in anchored}) > 1
            status = ('unavailable' if not reports else
                      'conflict' if receipt_conflict or wire_conflict or anchor_conflict else 'available')
            return {'schema': 1, 'status': status, 'native_txid': txid,
                    'evidence_ids': [r['evidence_id'] for r in reports],
                    'receipt_sha256': reports[0]['receipt_sha256'] if status == 'available' else None,
                    'competing_receipts': receipt_conflict, 'competing_signed_headers': anchor_conflict,
                    'selected_winner': None, 'historical_absence_proven': False,
                    'wallet_reservations_changed': False, 'latest_state_guaranteed': False}

    def export(self, evidence_id):
        """Export one explicitly selected proof, not a conflict-resolution decision."""
        hash_text(evidence_id)
        with self.atomic(write=False):
            self._policy()
            row = self.db.execute('SELECT * FROM capsules WHERE id=?', (evidence_id,)).fetchone()
            need(row is not None, 'receipt evidence unavailable; payment outcome unknown')
            capsule, _ = self._check_row(row)
            return capsule
