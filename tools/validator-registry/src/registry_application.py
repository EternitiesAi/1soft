"""Durable isolated registry experiment. Not the native coin's node or wallet.

Finalize computes without persistence. Commit uses an exact optimistic base guard
and one SQLite transaction. No engine launch or network receiver is exposed.
"""
from __future__ import annotations
from contextlib import contextmanager
import os
from pathlib import Path
import sqlite3
import stat

from commit_verifier import encode, exact, load_json
from registry_rules import (PROFILE, MAX_STATE_BYTES, validate_genesis, genesis_id,
    initial_state, restore_state, state_hash, block_transition, need, canonical_copy, sha)
from validator_wire import encode_update_response

APP_ID = 0x31565247


def private_path(path):
    need(os.name == 'posix', 'registry store requires a trusted POSIX workspace')
    path = Path(os.path.abspath(path))
    for parent in (path.parent, *path.parent.parents):
        need(not parent.is_symlink(), 'aliased registry ancestor')
    m = path.parent.stat()
    need(stat.S_ISDIR(m.st_mode) and m.st_uid == os.geteuid() and not stat.S_IMODE(m.st_mode) & 0o077,
         'private owned registry directory required')
    for p in (path, *(Path(str(path) + s) for s in ('-wal', '-shm', '-journal'))):
        if p.exists() or p.is_symlink():
            m = p.lstat()
            need(stat.S_ISREG(m.st_mode) and m.st_uid == os.geteuid() and m.st_nlink == 1
                 and not stat.S_IMODE(m.st_mode) & 0o077, 'unsafe registry database or sidecar')
    return path


class RegistryApplication:
    def __init__(self, path, genesis, *, create=False, read_only=False):
        need(type(create) is bool and type(read_only) is bool and not (create and read_only), 'invalid store mode')
        self.genesis = validate_genesis(genesis); self.db = None; self.pending = None
        self.read_only = read_only; self.path = private_path(path)
        if create:
            fd = os.open(self.path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
            os.close(fd)
        else:
            need(self.path.is_file(), 'registry has not been explicitly initialized')
        try:
            self.db = sqlite3.connect(self.path.as_uri() + ('?mode=ro' if read_only else '?mode=rw'),
                                     uri=True, isolation_level=None, timeout=5)
            if create:
                self.db.execute('PRAGMA journal_mode=WAL'); self.db.execute('PRAGMA synchronous=FULL')
                with self.atomic():
                    self.db.execute(f'PRAGMA application_id={APP_ID}')
                    self.db.execute('CREATE TABLE bootstrap(id INTEGER PRIMARY KEY CHECK(id=1), height INTEGER NOT NULL, app_hash TEXT NOT NULL)')
                    self.db.execute('CREATE TABLE configuration(id INTEGER PRIMARY KEY CHECK(id=1), genesis BLOB NOT NULL)')
                    self.db.execute('CREATE TABLE checkpoint(id INTEGER PRIMARY KEY CHECK(id=1), state BLOB NOT NULL, app_hash TEXT NOT NULL, last_block BLOB NOT NULL)')
                    self.db.execute('INSERT INTO configuration VALUES (1,?)', (encode(self.genesis),))
                    s = initial_state(self.genesis)
                    self.db.execute('INSERT INTO checkpoint VALUES (1,?,?,?)', (encode(s), state_hash(s), b'null'))
                fd = os.open(self.path.parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
                try: os.fsync(fd)
                finally: os.close(fd)
            with self.atomic(False): self._read()
            if not read_only:
                need(self.db.execute('PRAGMA journal_mode').fetchone()[0] == 'wal', 'unexpected registry journal mode')
                self.db.execute('PRAGMA synchronous=FULL')
        except BaseException:
            self.close(); raise

    def __enter__(self): return self
    def __exit__(self, *_): self.close()
    def close(self):
        if self.db is not None: self.db.close(); self.db = None
        self.pending = None

    @contextmanager
    def atomic(self, write=True):
        need(not self.db.in_transaction and not (write and self.read_only), 'registry transaction/mode conflict')
        self.db.execute('BEGIN IMMEDIATE' if write else 'BEGIN')
        try:
            yield
            self.db.execute('COMMIT')
        except BaseException:
            if self.db.in_transaction: self.db.execute('ROLLBACK')
            raise

    def _read(self):
        need(self.db.execute('PRAGMA application_id').fetchone()[0] == APP_ID, 'not a registry database')
        need(set(self.db.execute("SELECT type,name FROM sqlite_master WHERE name NOT LIKE 'sqlite_%'")) ==
             {('table', 'configuration'), ('table', 'checkpoint'), ('table', 'bootstrap')}, 'unknown registry schema')
        for table, fields in (('configuration', ('id','genesis')), ('checkpoint', ('id','state','app_hash','last_block')), ('bootstrap', ('id','height','app_hash'))):
            need(tuple(r[1] for r in self.db.execute(f'PRAGMA table_info({table})')) == fields, 'registry columns differ')
        config = self.db.execute('SELECT * FROM configuration').fetchall()
        need(config == [(1, encode(self.genesis))], 'pinned registry genesis differs')
        rows = self.db.execute('SELECT * FROM checkpoint').fetchall()
        need(len(rows) == 1 and rows[0][0] == 1, 'registry checkpoint missing')
        _, raw, h, last_raw = rows[0]
        need(type(raw) is bytes and type(last_raw) is bytes and len(last_raw) <= MAX_STATE_BYTES,
             'checkpoint byte type or size differs')
        state = load_json(raw, max_bytes=MAX_STATE_BYTES)
        need(encode(state) == raw, 'noncanonical checkpoint')
        state = restore_state(self.genesis, state, h)
        last = load_json(last_raw, max_bytes=MAX_STATE_BYTES)
        markers = self.db.execute('SELECT * FROM bootstrap').fetchall()
        need(len(markers) <= 1, 'duplicate registry bootstrap marker')
        if markers:
            from validator_sets import hex_text, integer
            from registry_rules import advance_clock, decode_command, accept
            need(markers[0][0] == 1, 'invalid registry bootstrap marker')
            integer(markers[0][1], 1, state['height']); hex_text(markers[0][2])
            historical = initial_state(self.genesis)
            for receipt in state['receipts']:
                if receipt['height'] <= markers[0][1]:
                    advance_clock(historical, receipt['height'])
                    accept(historical, decode_command(encode(receipt['envelope']), self.genesis), self.genesis)
            advance_clock(historical, markers[0][1])
            need(state_hash(historical) == markers[0][2], 'bootstrap marker differs from authorized history')
        if state['height'] == 0:
            need(last is None and not markers, 'unexpected genesis block record')
        elif last is None:
            need(markers == [(1, state['height'], h)], 'missing executed block without bootstrap marker')
        else:
            exact(last, {'height', 'block_hash', 'transactions', 'result'}, 'last registry block')
            need(type(last['height']) is int and last['height'] == state['height'], 'last registry height differs')
            # Reproduce the preceding state from immutable signed receipts, then
            # re-execute the complete last block, including its rejected commands.
            previous = initial_state(self.genesis)
            from registry_rules import advance_clock, decode_command, accept
            for r in state['receipts']:
                if r['height'] < state['height']:
                    advance_clock(previous, r['height'])
                    accept(previous, decode_command(encode(r['envelope']), self.genesis), self.genesis)
            advance_clock(previous, state['height'] - 1)
            need(type(last['transactions']) is list, 'invalid retained registry block')
            wires = []
            for raw_hex in last['transactions']:
                need(type(raw_hex) is str and len(raw_hex) <= 2 * 65536, 'retained transaction bound')
                wire = bytes.fromhex(raw_hex)
                need(wire.hex() == raw_hex, 'noncanonical retained transaction')
                wires.append(wire)
            replay, result = block_transition(self.genesis, previous, state['height'], last['block_hash'], wires)
            need(encode(replay) == raw and encode(result) == encode(last['result']),
                 'last block differs from deterministic replay')
        need(encode(last) == last_raw, 'noncanonical last registry block')
        return state, last

    def state(self):
        with self.atomic(False): return self._read()[0]

    def finalize_block(self, transactions, height, block_hash):
        need(not self.read_only, 'read-only registry cannot finalize')
        with self.atomic(False): current, last = self._read()
        need(type(transactions) is list and all(type(x) is bytes for x in transactions), 'exact registry wires required')
        identity = {'height': height, 'block_hash': block_hash, 'transactions': [x.hex() for x in transactions]}
        if type(height) is int and height == current['height'] and last is not None:
            need(encode(identity) == encode({k:last[k] for k in identity}), 'conflicting committed block retry')
            return canonical_copy(last['result'])
        if self.pending is not None:
            need(encode(identity) == encode(self.pending['identity']), 'conflicting uncommitted block')
            return canonical_copy(self.pending['result'])
        next_state, result = block_transition(self.genesis, current, height, block_hash, transactions)
        self.pending = {'base_hash': state_hash(current), 'identity': identity,
                        'state': next_state, 'result': result}
        return canonical_copy(result)

    def commit(self):
        need(not self.read_only, 'read-only registry cannot commit')
        if self.pending is None: return {'status': 'no-pending-block', 'app_hash': state_hash(self.state())}
        p = self.pending; last = {**p['identity'], 'result': p['result']}
        with self.atomic():
            current, old_last = self._read()
            if encode(current) == encode(p['state']) and encode(old_last) == encode(last):
                status = 'already-committed'
            else:
                need(state_hash(current) == p['base_hash'], 'registry advanced; stale finalization refused')
                self.db.execute('UPDATE checkpoint SET state=?,app_hash=?,last_block=? WHERE id=1',
                                (encode(p['state']), state_hash(p['state']), encode(last)))
                status = 'committed'
        self.pending = None
        return {'status': status, 'height': p['state']['height'], 'app_hash': state_hash(p['state'])}

    def update_wire(self):
        """Field-3 probe bytes for the pending result; NOT a usable ABCI response."""
        need(self.pending is not None, 'no pending registry block')
        rows = self.pending['result']['validator_updates']
        return encode_update_response(rows) if rows else b''

    def install_snapshot(self, snapshot, *, expected_app_hash):
        """Restore only into an untouched experiment, with an external exact hash.

        This is not CometBFT state sync. The caller's trust in that hash is external
        to this library; no validator/network source of it is inferred here.
        """
        state = restore_state(self.genesis, snapshot, expected_app_hash)
        need(state['height'] > 0 and self.pending is None, 'snapshot must be above genesis with no pending block')
        with self.atomic():
            current, last = self._read()
            need(current['height'] == 0 and not current['receipts'] and last is None,
                 'snapshot installation requires an untouched registry')
            need(self.db.execute('SELECT 1 FROM bootstrap').fetchone() is None, 'registry already bootstrapped')
            self.db.execute('UPDATE checkpoint SET state=?,app_hash=?,last_block=? WHERE id=1',
                            (encode(state), state_hash(state), b'null'))
            self.db.execute('INSERT INTO bootstrap VALUES (1,?,?)', (state['height'], state_hash(state)))
        return {'status': 'restored', 'height': state['height'], 'app_hash': state_hash(state),
                'consensus_verified_by_this_operation': False}
