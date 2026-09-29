"""Durable bounded validator continuity; separate from wallets and node stores.

Only explicit local imports. No network, keys, broadcasts, upgrades or governance.
Saved accepted-at times are local diagnostics, not independent time attestations.
A malicious local host, full-workspace rollback or compromised quorum is outside
this trust model. Expired history remains inspectable but cannot bootstrap a jump.
"""
from __future__ import annotations

from contextlib import contextmanager
import os
from pathlib import Path
import sqlite3
import stat
import time

from commit_verifier import encode, load_json, sha
from validator_transition import (MAX_BATCH, MAX_BATCH_BYTES, MAX_STEP_BYTES, check_time,
    freeze, hex32, integer, need, validate_policy, verify_anchor, verify_link, verify_step)

APP_ID = 0x31535643
MAX_RECORDS = 512
MAX_STORE_BYTES = 32 * 1024 * 1024


def private_path(path):
    need(os.name == 'posix', 'continuity store requires POSIX')
    p = Path(os.path.abspath(path))
    for ancestor in (p.parent, *p.parent.parents):
        need(not ancestor.is_symlink(), 'symlink ancestor refused')
    parent = p.parent.stat()
    need(stat.S_ISDIR(parent.st_mode) and parent.st_uid == os.geteuid() and
         not stat.S_IMODE(parent.st_mode) & 0o077, 'private owned directory required')
    for item in (p, *(Path(str(p)+s) for s in ('-wal','-shm','-journal'))):
        if item.exists() or item.is_symlink():
            st = item.lstat()
            need(stat.S_ISREG(st.st_mode) and st.st_uid == os.geteuid() and st.st_nlink == 1 and
                 not stat.S_IMODE(st.st_mode) & 0o077, 'unsafe continuity file or sidecar')
    return p


def fsync_directory(path):
    fd = os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try: os.fsync(fd)
    finally: os.close(fd)


def write_new(path, raw):
    p = private_path(path)
    need(type(raw) is bytes and len(raw) <= MAX_STORE_BYTES, 'output too large')
    fd = os.open(p, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, 'wb') as f:
        f.write(raw); f.flush(); os.fsync(f.fileno())
    fsync_directory(p.parent)


class ValidatorStore:
    def __init__(self, path, genesis_bytes, policy, *, anchor=None, read_only=False, clock=time.time_ns):
        self.policy = freeze(policy); validate_policy(self.policy, genesis_bytes)
        self.genesis = bytes(genesis_bytes); self.clock = clock; self.db = None
        need(type(read_only) is bool and not (read_only and anchor is not None), 'invalid open mode')
        self.read_only = read_only
        selected = freeze(anchor) if anchor is not None else None
        accepted = None
        if selected is not None:
            accepted = integer(clock())
            verify_anchor(selected, self.policy, self.genesis, accepted)
        self.path = private_path(path)
        if selected is not None:
            fd = os.open(self.path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600); os.close(fd)
        else:
            need(self.path.is_file(), 'continuity store not initialized')
        try:
            mode = 'ro' if read_only else 'rw'
            self.db = sqlite3.connect(self.path.as_uri()+'?mode='+mode, uri=True,
                                      isolation_level=None, timeout=5)
            if selected is not None:
                self.db.execute('PRAGMA journal_mode=WAL'); self.db.execute('PRAGMA synchronous=FULL')
                with self.atomic():
                    self.db.execute(f'PRAGMA application_id={APP_ID}')
                    self.db.execute('CREATE TABLE policy (id INTEGER PRIMARY KEY CHECK(id=1), body BLOB NOT NULL)')
                    self.db.execute('CREATE TABLE headers (height INTEGER PRIMARY KEY, header_hash TEXT NOT NULL, body BLOB NOT NULL, accepted_ns INTEGER NOT NULL)')
                    self.db.execute('INSERT INTO policy VALUES (1,?)', (encode(self.policy),))
                    final_clock = integer(clock()); need(final_clock >= accepted, 'local clock moved backwards')
                    info = verify_anchor(selected, self.policy, self.genesis, final_clock)
                    self.db.execute('INSERT INTO headers VALUES (?,?,?,?)',
                        (info['height'], info['header_hash'], encode(selected), final_clock))
                fsync_directory(self.path.parent)
            with self.atomic(write=False): self._read()
            if not read_only:
                need(self.db.execute('PRAGMA journal_mode').fetchone()[0] == 'wal', 'unexpected journal mode')
                self.db.execute('PRAGMA synchronous=FULL')
        except BaseException:
            self.close(); raise

    def close(self):
        if self.db is not None: self.db.close(); self.db = None
    def __enter__(self): return self
    def __exit__(self, *_): self.close()

    @contextmanager
    def atomic(self, write=True):
        need(not self.db.in_transaction and not (write and self.read_only), 'invalid continuity transaction')
        self.db.execute('BEGIN IMMEDIATE' if write else 'BEGIN')
        try:
            yield
            self.db.execute('COMMIT')
        except BaseException:
            if self.db.in_transaction: self.db.execute('ROLLBACK')
            raise

    def _read(self):
        need(self.db.execute('PRAGMA application_id').fetchone()[0] == APP_ID, 'not a validator continuity store')
        objects = set(self.db.execute("SELECT type,name FROM sqlite_master WHERE name NOT LIKE 'sqlite_%'"))
        need(objects == {('table','policy'),('table','headers')}, 'unexpected continuity schema')
        for name, columns in [('policy',('id','body')),('headers',('height','header_hash','body','accepted_ns'))]:
            need(tuple(r[1] for r in self.db.execute(f'PRAGMA table_info({name})')) == columns, 'wrong columns')
        config = self.db.execute('SELECT * FROM policy').fetchall()
        need(len(config) == 1 and config[0] == (1, encode(self.policy)), 'persisted trust policy differs')
        size = self.db.execute('SELECT count(*),coalesce(sum(length(body)),0) FROM headers').fetchone()
        need(0 < size[0] <= MAX_RECORDS and size[1] <= MAX_STORE_BYTES, 'store empty or over capacity')
        rows = self.db.execute('SELECT height,header_hash,body,accepted_ns FROM headers ORDER BY height').fetchall()
        checked = []; previous = None; last_clock = None
        for h, digest, raw, accepted in rows:
            need(type(raw) is bytes and len(raw) <= MAX_STEP_BYTES, 'invalid stored header bytes')
            value = load_json(raw, max_bytes=MAX_STEP_BYTES)
            need(encode(value) == raw, 'noncanonical stored evidence')
            integer(accepted)
            if previous is None:
                info = verify_anchor(value, self.policy, self.genesis, accepted)
            else:
                need(accepted >= last_clock, 'stored acceptance clock regressed')
                check_time(checked[-1][1], self.policy, accepted)
                info = verify_link(previous, value, self.policy)
                check_time(info, self.policy, accepted)
            need(type(h) is int and h == info['height'] and digest == info['header_hash'], 'header index differs from signed evidence')
            checked.append((value, info, accepted)); previous = value; last_clock = accepted
        return checked

    def inspect(self):
        with self.atomic(write=False):
            records = self._read(); _, last, accepted = records[-1]
            now = integer(self.clock())
            can_continue = now >= accepted
            try: check_time(last, self.policy, now)
            except ValueError: can_continue = False
            return {'schema':1,'status':'verified-historical-headers',
                'initial_height':records[0][1]['height'], 'height':last['height'],
                'header_hash':last['header_hash'], 'validators_hash':last['validators_hash'],
                'next_validators_hash':last['next_validators_hash'],
                'validator_count':last['validator_count'], 'records':len(records),
                'observed_set_changes':sum(a[1]['validators_hash'] != b[1]['validators_hash'] for a,b in zip(records,records[1:])),
                'continuation_within_local_time_policy':can_continue,
                'financial_authority':False,'governance_authorization_checked':False,
                'consensus_executed':False,'latest_state_guaranteed':False}

    def export(self):
        with self.atomic(write=False):
            return [r[0] for r in self._read()]

    def advance(self, values, *, expected_tip_hash):
        hex32(expected_tip_hash)
        selected = freeze(values, MAX_BATCH_BYTES)
        need(type(selected) is list and 1 <= len(selected) <= MAX_BATCH, 'invalid header batch length')
        with self.atomic():
            records = self._read(); previous, last, accepted = records[-1]
            need(last['header_hash'] == expected_tip_hash, 'saved frontier changed; inspect before retry')
            now = integer(self.clock()); need(now >= accepted, 'local clock moved backwards')
            check_time(last, self.policy, now)
            need(len(records)+len(selected) <= MAX_RECORDS, 'history capacity reached; no automatic eviction')
            size = sum(len(encode(r[0])) for r in records)
            pending = []
            for value in selected:
                info = verify_link(previous, value, self.policy)
                check_time(info, self.policy, now)
                raw = encode(value); size += len(raw)
                need(size <= MAX_STORE_BYTES, 'history bytes exceed capacity')
                pending.append((value, info, raw)); previous = value
            end = integer(self.clock()); need(end >= now, 'local clock regressed during verification')
            # The old tip must remain unexpired until commit: a batch cannot
            # resurrect expired trust by supplying many convenient new signatures.
            check_time(last, self.policy, end)
            for _, info, raw in pending:
                check_time(info, self.policy, end)
                self.db.execute('INSERT INTO headers VALUES (?,?,?,?)',
                    (info['height'],info['header_hash'],raw,end))
            result = {'status':'headers-advanced','height':pending[-1][1]['height'],
                      'header_hash':pending[-1][1]['header_hash'],'accepted_headers':len(pending),
                      'financial_authority':False,'chain_mutated':False}
        return result
