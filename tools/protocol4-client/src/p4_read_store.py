"""Separate P4 read checkpoint store. No funds, keys, wallet holds or submissions.

Each accepted view retains its complete source evidence. Compare-and-swap prevents
parallel readers from silently replacing a reviewed tip. History may not roll back;
trust may not auto-renew. A trusted local filesystem/clock is assumed. These are
not defences against deletion or rollback of an entire user workspace.
"""
from __future__ import annotations

from contextlib import contextmanager
import hashlib
import os
from pathlib import Path
import sqlite3
import stat
import time

from block_application import encode
from commit_verifier import load_json
from p4_evidence import (MAX_EVIDENCE_BYTES, _account_from_verified_report, check_clock, content_id,
                         extends, freeze, hash_text, integer, need, p4_genesis,
                         policy_checked, _receipt_from_verified_report, verify_evidence)

from p4_storage_codec import FRAME_BYTES, decode_payload, encode_payload

APPLICATION_ID = 0x31503452
MAX_RECORDS = 32
MAX_STORED_BYTES = 64 * 1024 * 1024
ZERO = '0' * 64


def private_path(path):
    need(os.name == 'posix', 'P4 read storage requires a trusted POSIX host')
    p = Path(os.path.abspath(path))
    for parent in (p.parent, *p.parent.parents):
        need(not parent.is_symlink(), 'symlink parent refused')
    info = p.parent.stat()
    need(stat.S_ISDIR(info.st_mode) and info.st_uid == os.geteuid() and not info.st_mode & 0o077,
         'private owned output directory required')
    for file in (p, *(Path(str(p)+suffix) for suffix in ('-wal', '-shm', '-journal'))):
        if file.exists() or file.is_symlink():
            info = file.lstat()
            need(stat.S_ISREG(info.st_mode) and info.st_uid == os.geteuid() and
                 info.st_nlink == 1 and not info.st_mode & 0o077, 'unsafe read-store file or sidecar')
    return p


def write_new(path, data):
    need(type(data) is bytes and len(data) <= MAX_EVIDENCE_BYTES, 'bounded output bytes required')
    p = private_path(path)
    fd = os.open(p, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, 'wb') as out:
        out.write(data); out.flush(); os.fsync(out.fileno())
    parent = os.open(p.parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try: os.fsync(parent)
    finally: os.close(parent)


class P4ReadStore:
    """Append-only verified observations, distinct from every monetary journal."""
    def __init__(self, path, genesis_bytes, policy, *, create=False, read_only=False,
                 clock=time.time_ns, storage_version=None):
        self.policy = policy_checked(policy)
        self.genesis = bytes(genesis_bytes)
        p4_genesis(self.genesis, self.policy['genesis_sha256'])
        need(type(create) is bool and type(read_only) is bool and not (create and read_only), 'invalid store mode')
        need(storage_version is None or (create and type(storage_version) is int and
             storage_version in (1, 2)), 'storage version is an explicit supported creation option only')
        self.storage_version = (1 if storage_version is None else storage_version) if create else None
        self.policy_id = content_id(self.policy)
        self.clock = clock; self.read_only = read_only; self.db = None
        self.path = private_path(path)
        if create:
            check_clock(self.policy, self.clock())
            fd = os.open(self.path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
            os.close(fd)
        else:
            need(self.path.is_file(), 'read store is not initialized')
        try:
            self.db = sqlite3.connect(self.path.as_uri()+('?mode=ro' if read_only else '?mode=rw'),
                                      uri=True, isolation_level=None, timeout=5)
            if create:
                self.db.execute('PRAGMA journal_mode=WAL')
                self.db.execute('PRAGMA synchronous=FULL')
                with self.atomic():
                    self.db.execute(f'PRAGMA application_id={APPLICATION_ID}')
                    self.db.execute('CREATE TABLE config(id INTEGER PRIMARY KEY CHECK(id=1), version INTEGER NOT NULL, policy BLOB NOT NULL, policy_id TEXT NOT NULL)')
                    suffix = ', logical_bytes INTEGER NOT NULL' if self.storage_version == 2 else ''
                    self.db.execute('CREATE TABLE observations(seq INTEGER PRIMARY KEY, evidence_id TEXT UNIQUE NOT NULL, parent_id TEXT NOT NULL, checked_ns INTEGER NOT NULL, height INTEGER NOT NULL, payload BLOB NOT NULL'+suffix+')')
                    self.db.execute(f'INSERT INTO config VALUES (1,{self.storage_version},?,?)', (encode(self.policy), self.policy_id))
                parent = os.open(self.path.parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
                try: os.fsync(parent)
                finally: os.close(parent)
            self._catalog()
            if not read_only:
                need(self.db.execute('PRAGMA journal_mode').fetchone()[0] == 'wal', 'unexpected journal mode; no repair')
                self.db.execute('PRAGMA synchronous=FULL')
        except BaseException:
            self.close(); raise

    def close(self):
        if self.db is not None: self.db.close(); self.db = None
    def __enter__(self): return self
    def __exit__(self, *_): self.close()

    @contextmanager
    def atomic(self, write=True):
        need(not self.db.in_transaction and not (write and self.read_only), 'read-store transaction or mode conflict')
        self.db.execute('BEGIN IMMEDIATE' if write else 'BEGIN')
        try:
            yield
            self.db.execute('COMMIT')
        except BaseException:
            if self.db.in_transaction: self.db.execute('ROLLBACK')
            raise

    def _catalog(self):
        need(self.db.execute('PRAGMA application_id').fetchone()[0] == APPLICATION_ID,
             'not a P4 read store; existing file not repaired')
        objects = set(self.db.execute("SELECT type,name FROM sqlite_master WHERE name NOT LIKE 'sqlite_%'"))
        need(objects == {('table','config'), ('table','observations')}, 'unsupported read-store schema')
        need(tuple(row[1] for row in self.db.execute('PRAGMA table_info(config)')) ==
             ('id','version','policy','policy_id'), 'read-store columns differ')
        config = self.db.execute('SELECT * FROM config').fetchall()
        need(len(config) == 1 and type(config[0][1]) is int and config[0][1] in (1, 2) and
             config[0] == (1,config[0][1],encode(self.policy),self.policy_id),
             'read-store external policy differs')
        version = config[0][1]
        need(self.storage_version is None or self.storage_version == version,
             'read-store version changed')
        columns = ('seq','evidence_id','parent_id','checked_ns','height','payload')
        if version == 2: columns += ('logical_bytes',)
        need(tuple(row[1] for row in self.db.execute('PRAGMA table_info(observations)')) == columns,
             'read-store columns differ')
        self.storage_version = version
        count = self.db.execute('SELECT count(*) FROM observations').fetchone()[0]
        need(count <= MAX_RECORDS, 'read-store capacity exceeded')
        # Inspect all typed descriptors and both byte totals BEFORE fetching any
        # proof BLOB. Physical savings never enlarge logical admission limits.
        extra = ',logical_bytes,typeof(logical_bytes)' if version == 2 else ''
        descriptors = self.db.execute('SELECT seq,evidence_id,parent_id,checked_ns,height,'
            'typeof(payload),length(payload)'+extra+' FROM observations ORDER BY seq').fetchall()
        need(len(descriptors) == count, 'read-store catalog changed')
        prior_id, prior_height, prior_clock = ZERO, -1, nanos_anchor(self.policy)
        logical_total = physical_total = 0
        for expected_seq, descriptor in enumerate(descriptors, 1):
            seq, evidence_id, parent, checked_ns, height, payload_type, physical = descriptor[:7]
            integer(seq, expected_seq, expected_seq); integer(height, 0, 512)
            integer(checked_ns, prior_clock); hash_text(evidence_id)
            need(parent == prior_id and height > prior_height, 'read-store lineage or content changed')
            need(payload_type == 'blob', 'read-store payload descriptor changed')
            logical = descriptor[7] if version == 2 else physical
            if version == 2: need(descriptor[8] == 'integer', 'invalid logical proof length type')
            integer(logical, 1, MAX_EVIDENCE_BYTES)
            integer(physical, FRAME_BYTES+1 if version == 2 else 1,
                    logical+FRAME_BYTES if version == 2 else MAX_EVIDENCE_BYTES)
            logical_total += logical; physical_total += physical
            need(logical_total <= MAX_STORED_BYTES and
                 physical_total <= MAX_STORED_BYTES+(count*FRAME_BYTES if version == 2 else 0),
                 'read-store capacity exceeded')
            prior_id, prior_height, prior_clock = evidence_id, height, checked_ns
        payloads = self.db.execute('SELECT seq,payload FROM observations ORDER BY seq').fetchall()
        need(len(payloads) == count, 'read-store catalog changed')
        rows = []
        for descriptor, (seq, payload) in zip(descriptors, payloads):
            need(seq == descriptor[0] and type(payload) is bytes and len(payload) == descriptor[6],
                 'read-store payload descriptor changed')
            raw = decode_payload(payload) if version == 2 else payload
            need(len(raw) == (descriptor[7] if version == 2 else descriptor[6]) and
                 hashlib.sha256(raw).hexdigest() == descriptor[1],
                 'read-store lineage or content changed')
            rows.append((*descriptor[:5], raw))
        return rows

    def storage_stats(self):
        """Read-only physical/logical accounting; does not qualify current trust."""
        with self.atomic(write=False):
            rows = self._catalog()
            physical = self.db.execute('SELECT coalesce(sum(length(payload)),0) FROM observations').fetchone()[0]
            return {'format_version':self.storage_version, 'observations':len(rows),
                    'logical_evidence_bytes':sum(len(row[5]) for row in rows),
                    'stored_payload_bytes':physical, 'spending_authority':False}

    def _verified(self, row, now_ns):
        _, evidence_id, _, checked_ns, height, raw = row
        check_clock(self.policy, now_ns, checked_ns)
        evidence = load_json(raw, max_bytes=MAX_EVIDENCE_BYTES)
        need(encode(evidence) == raw, 'noncanonical saved evidence')
        report = verify_evidence(evidence, self.genesis, self.policy, now_ns=now_ns)
        need(report['evidence_id'] == evidence_id and report['state_height'] == height,
             'stored metadata differs from verified checkpoint')
        return evidence, report

    def import_evidence(self, value, *, expected_tip):
        frozen = freeze(value)
        begin = self.clock(); report = verify_evidence(frozen, self.genesis, self.policy, now_ns=begin)
        if expected_tip is not None: hash_text(expected_tip)
        with self.atomic():
            rows = self._catalog(); actual_tip = rows[-1][1] if rows else None
            need(expected_tip == actual_tip, 'reviewed read tip changed; re-read before importing')
            checked = self.clock(); check_clock(self.policy, checked, begin)
            if rows:
                old, _ = self._verified(rows[-1], checked)
                extends(old, frozen)
                if report['state_height'] == rows[-1][4]:
                    # Both independently verified. Alternate quorum subsets on the
                    # same exact block path do not invent a fork or replace history.
                    check_clock(self.policy, self.clock(), checked)
                    return {'status': 'already_recorded', 'evidence_id': actual_tip,
                            'state_height': report['state_height'], 'wallet_reservations_changed': False}
            raw = encode(frozen)
            need(len(rows) < MAX_RECORDS and sum(len(row[5]) for row in rows)+len(raw) <= MAX_STORED_BYTES,
                 'read-store capacity reached; evidence not evicted')
            payload = encode_payload(raw) if self.storage_version == 2 else raw
            # Expiry is checked again AFTER old evidence replay/compression and immediately
            # before the database write. Only this derived read store changes.
            checked = self.clock(); check_clock(self.policy, checked, begin)
            if rows: check_clock(self.policy, checked, rows[-1][3])
            record = (len(rows)+1, report['evidence_id'], actual_tip or ZERO, checked,
                      report['state_height'], payload)
            if self.storage_version == 2:
                self.db.execute('INSERT INTO observations VALUES (?,?,?,?,?,?,?)', (*record, len(raw)))
            else:
                self.db.execute('INSERT INTO observations VALUES (?,?,?,?,?,?)', record)
        return {'status': 'recorded', 'evidence_id': report['evidence_id'],
                'state_height': report['state_height'], 'wallet_reservations_changed': False}

    def current(self):
        with self.atomic(write=False):
            rows = self._catalog()
            if not rows: return None
            start = self.clock(); _, report = self._verified(rows[-1], start)
            end = self.clock(); check_clock(self.policy, end, start)
            report['checked_at_ns'] = end
            return report

    def export(self, evidence_id):
        hash_text(evidence_id)
        with self.atomic(write=False):
            rows = self._catalog(); selected = [row for row in rows if row[1] == evidence_id]
            need(len(selected) == 1, 'requested evidence unavailable; no payment outcome inferred')
            start = self.clock(); evidence, _ = self._verified(selected[0], start)
            check_clock(self.policy, self.clock(), start)
            return evidence

    def account(self, account_id):
        report = self.current()
        need(report is not None, 'no authenticated P4 checkpoint')
        return _account_from_verified_report(report, account_id)

    def receipt(self, exact_transaction, *, payer):
        report = self.current()
        need(report is not None, 'no authenticated P4 checkpoint')
        return _receipt_from_verified_report(report, exact_transaction, payer)


def nanos_anchor(policy):
    from validator_witness import nanos
    return nanos(policy['anchor_time'])
