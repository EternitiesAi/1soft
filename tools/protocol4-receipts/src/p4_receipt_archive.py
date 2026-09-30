"""Private content-addressed P4 capsules with an atomic SQLite catalogue.

This is a distinct evidence archive, never a wallet, dispatcher or retry journal.
Filesystem protections assume a trusted same-user POSIX host, not a hostile OS.
"""
from __future__ import annotations

from contextlib import contextmanager
import os
from pathlib import Path
import sqlite3
import stat

from commit_verifier import encode
from p4_evidence import (check_clock, content_id, hash_text, integer, need,
                         p4_genesis, policy_checked)
from p4_receipt_capsule import (MAX_CAPSULE_BYTES, encode_capsule, parse_capsule,
                                sha256, verify_capsule)

APPLICATION_ID = 0x31503443
FORMAT = '1soft/protocol4-receipt-archive/v1'
MAX_RECORDS = 32
MAX_STORED_BYTES = 64 * 1024 * 1024
MAX_DB_BYTES = 80 * 1024 * 1024
CONFIG_COLUMNS = ('id', 'schema', 'format', 'genesis_sha256', 'policy_id',
                  'max_records', 'max_bytes', 'last_ns')
CAPSULE_COLUMNS = ('capsule_id', 'wire_sha256', 'native_txid', 'receipt_sha256',
                   'height', 'header_hash', 'payload', 'bytes')


def private_path(path):
    need(os.name == 'posix', 'P4 archive requires a trusted POSIX host')
    p = Path(os.path.abspath(path))
    for parent in (p.parent, *p.parent.parents):
        need(not parent.is_symlink(), 'archive ancestor symlink refused')
    info = p.parent.stat()
    need(stat.S_ISDIR(info.st_mode) and info.st_uid == os.geteuid() and
         not info.st_mode & 0o077, 'private owned archive directory required')
    for file in (p, *(Path(str(p) + suffix) for suffix in ('-wal', '-shm', '-journal'))):
        if file.exists() or file.is_symlink():
            info = file.lstat()
            need(stat.S_ISREG(info.st_mode) and info.st_uid == os.geteuid() and
                 info.st_nlink == 1 and not info.st_mode & 0o077,
                 'unsafe archive file or database sidecar')
            need(info.st_size <= MAX_DB_BYTES, 'archive file exceeds physical read bound')
    return p


def _sync_directory(path):
    fd = os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def write_new(path, raw):
    """Exclusive private export. Failure is never a wallet rollback claim."""
    need(type(raw) is bytes and 0 < len(raw) <= MAX_CAPSULE_BYTES,
         'bounded capsule output bytes required')
    p = private_path(path)
    fd = os.open(p, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, 'wb') as out:
        out.write(raw); out.flush(); os.fsync(out.fileno())
    _sync_directory(p.parent)


class P4ReceiptArchive:
    def __init__(self, path, genesis_bytes, policy, *, now_ns, create=False,
                 read_only=False, max_records=MAX_RECORDS, max_bytes=MAX_STORED_BYTES):
        need(type(create) is bool and type(read_only) is bool and
             not (create and read_only), 'invalid archive mode')
        integer(max_records, 1, MAX_RECORDS); integer(max_bytes, 1, MAX_STORED_BYTES)
        self.policy = policy_checked(policy)
        need(type(genesis_bytes) is bytes, 'external genesis bytes required')
        self.genesis = bytes(genesis_bytes)
        p4_genesis(self.genesis, self.policy['genesis_sha256'])
        check_clock(self.policy, now_ns)
        self.policy_id = content_id(self.policy)
        self.read_only = read_only; self.db = None
        self.path = private_path(path)
        if create:
            fd = os.open(self.path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
            os.close(fd)
        else:
            need(self.path.is_file(), 'archive not initialized')
        try:
            self.db = sqlite3.connect(self.path.as_uri() +
                ('?mode=ro' if read_only else '?mode=rw'), uri=True,
                isolation_level=None, timeout=5)
            self.db.execute('PRAGMA trusted_schema=OFF')
            if create:
                self.db.execute('PRAGMA journal_mode=WAL')
                self.db.execute('PRAGMA synchronous=FULL')
                with self.atomic():
                    self.db.execute(f'PRAGMA application_id={APPLICATION_ID}')
                    self.db.execute('CREATE TABLE config(id INTEGER PRIMARY KEY CHECK(id=1), schema INTEGER NOT NULL, format TEXT NOT NULL, genesis_sha256 TEXT NOT NULL, policy_id TEXT NOT NULL, max_records INTEGER NOT NULL, max_bytes INTEGER NOT NULL, last_ns INTEGER NOT NULL)')
                    self.db.execute('CREATE TABLE capsules(capsule_id TEXT PRIMARY KEY, wire_sha256 TEXT NOT NULL, native_txid TEXT NOT NULL, receipt_sha256 TEXT NOT NULL, height INTEGER NOT NULL, header_hash TEXT NOT NULL, payload BLOB NOT NULL, bytes INTEGER NOT NULL)')
                    self.db.execute('CREATE INDEX by_wire ON capsules(wire_sha256)')
                    self.db.execute('INSERT INTO config VALUES (1,1,?,?,?,?,?,?)',
                        (FORMAT, self.policy['genesis_sha256'], self.policy_id,
                         max_records, max_bytes, now_ns))
                _sync_directory(self.path.parent)
            self._catalog(now_ns)
            need(self.db.execute('PRAGMA journal_mode').fetchone()[0] == 'wal',
                 'archive journal mode differs; no repair')
            if not read_only:
                self.db.execute('PRAGMA synchronous=FULL')
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
        need(self.db is not None and not self.db.in_transaction and
             not (write and self.read_only), 'archive transaction or mode conflict')
        self.db.execute('BEGIN IMMEDIATE' if write else 'BEGIN')
        try:
            yield
            self.db.execute('COMMIT')
        except BaseException:
            if self.db.in_transaction:
                self.db.execute('ROLLBACK')
            raise

    def _catalog(self, now_ns):
        private_path(self.path)
        need(self.db.execute('PRAGMA application_id').fetchone()[0] == APPLICATION_ID,
             'not a P4 receipt archive; unknown database untouched')
        objects = self.db.execute("SELECT type,name FROM sqlite_master WHERE name NOT LIKE 'sqlite_%'").fetchall()
        need(set(objects) == {('table', 'config'), ('table', 'capsules'), ('index', 'by_wire')},
             'archive schema differs')
        for table, columns in (('config', CONFIG_COLUMNS), ('capsules', CAPSULE_COLUMNS)):
            need(tuple(r[1] for r in self.db.execute(f'PRAGMA table_info({table})')) == columns,
                 'archive columns differ')
        rows = self.db.execute('SELECT * FROM config').fetchall()
        need(len(rows) == 1 and rows[0][:5] == (1, 1, FORMAT,
             self.policy['genesis_sha256'], self.policy_id), 'archive external pins differ')
        maximum_records, maximum_bytes, last = rows[0][5:]
        integer(maximum_records, 1, MAX_RECORDS); integer(maximum_bytes, 1, MAX_STORED_BYTES)
        check_clock(self.policy, now_ns, last)
        count, size = self.db.execute('SELECT count(*),coalesce(sum(bytes),0) FROM capsules').fetchone()
        need(count <= maximum_records and 0 <= size <= maximum_bytes,
             'archive exceeds retained capacity')
        need(self.db.execute('SELECT 1 FROM capsules WHERE bytes!=length(payload) OR bytes<=0 OR bytes>? OR typeof(payload)!=? LIMIT 1',
             (MAX_CAPSULE_BYTES, 'blob')).fetchone() is None, 'archive payload sizes differ')
        return maximum_records, maximum_bytes, count, size

    @staticmethod
    def _metadata(report):
        binding = report['binding']
        return (report['capsule_id'], binding['wire_sha256'], binding['native_txid'],
                binding['receipt_sha256'], report['state_height'], report['header_hash'])

    def _check_row(self, row, now_ns, expected_payer=None, expected_wire_sha256=None):
        need(type(row[6]) is bytes and row[7] == len(row[6]) and
             sha256(row[6]) == row[0], 'stored capsule hash or length differs')
        c = parse_capsule(row[6])
        r = verify_capsule(c, self.genesis, self.policy, now_ns=now_ns,
            expected_payer=expected_payer, expected_wire_sha256=expected_wire_sha256)
        need(self._metadata(r) == tuple(row[:6]), 'archive index differs from verified capsule')
        return c, r

    def put(self, capsule, *, now_ns, expected_payer=None, expected_wire_sha256=None):
        c = parse_capsule(capsule); raw = encode_capsule(c)
        r = verify_capsule(c, self.genesis, self.policy, now_ns=now_ns,
            expected_payer=expected_payer, expected_wire_sha256=expected_wire_sha256)
        with self.atomic():
            maximum_records, maximum_bytes, count, size = self._catalog(now_ns)
            old = self.db.execute('SELECT * FROM capsules WHERE capsule_id=?',
                                  (r['capsule_id'],)).fetchone()
            if old is not None:
                self._check_row(old, now_ns, expected_payer, expected_wire_sha256)
                need(old[6] == raw, 'same capsule ID has different bytes')
                stored = False
            else:
                need(count < maximum_records and size + len(raw) <= maximum_bytes,
                     'archive capacity reached; no eviction')
                # Conflicting receipt identities are retained as separate verified
                # capsules. There is no latest-wins payment or nonpayment decision.
                self.db.execute('INSERT INTO capsules VALUES (?,?,?,?,?,?,?,?)',
                    (*self._metadata(r), raw, len(raw)))
                stored = True
            check_clock(self.policy, now_ns)
            self.db.execute('UPDATE config SET last_ns=? WHERE id=1', (now_ns,))
        return {'status': 'stored' if stored else 'already_stored',
                'capsule_id': r['capsule_id'], 'wallet_reservations_changed': False,
                'spending_authority': False, 'automatic_resend': False}

    def _get(self, capsule_id, now_ns, expected_payer, expected_wire_sha256):
        hash_text(capsule_id)
        with self.atomic(write=False):
            self._catalog(now_ns)
            row = self.db.execute('SELECT * FROM capsules WHERE capsule_id=?',
                                  (capsule_id,)).fetchone()
            need(row is not None, 'capsule unavailable; payment outcome unknown')
            return self._check_row(row, now_ns, expected_payer, expected_wire_sha256)

    def get(self, capsule_id, *, now_ns, expected_payer=None, expected_wire_sha256=None):
        return self._get(capsule_id, now_ns, expected_payer, expected_wire_sha256)[0]

    def inspect(self, capsule_id, *, now_ns, expected_payer=None, expected_wire_sha256=None):
        return self._get(capsule_id, now_ns, expected_payer, expected_wire_sha256)[1]
