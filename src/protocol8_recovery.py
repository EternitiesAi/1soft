"""Separate P8 recovery store; inherited lifecycle retains the frozen P8 rules.

Snapshot state contains the replay history, never historical engine responses.
The local origin records a replayable base; real response rows cover its suffix.
This schema deliberately refuses ordinary P8 stores rather than migrating them.
"""
from __future__ import annotations
import os, re, sqlite3, threading
from pathlib import Path
from block_application import StoreLock
from protocol5_encoding import decode_canonical_json, comet_validator_set
from protocol8_application import (Application, SCHEMA, _safe, _votes,
                                   finalization_identity, encode_finalization)
from protocol8_consensus import (need, canonical, digest, genesis_document,
    initial_state, replay, _execute, application_hash, MAX_STATE_BYTES)

RECOVERY_SCHEMA = {**SCHEMA,
    'p8_snapshot_origin': 'CREATE TABLE p8_snapshot_origin (id INTEGER PRIMARY KEY CHECK(id=1), height INTEGER NOT NULL, app_hash TEXT NOT NULL, payload_sha256 TEXT NOT NULL, payload BLOB NOT NULL)'}

def schema(db, empty=False):
    rows = db.execute("SELECT type,name,sql FROM sqlite_master WHERE name NOT LIKE 'sqlite_%' ORDER BY name").fetchall()
    if empty and not rows: return False
    need(len(rows) == len(RECOVERY_SCHEMA) and all(
        t == 'table' and n in RECOVERY_SCHEMA and
        ' '.join(sql.split()) == ' '.join(RECOVERY_SCHEMA[n].split())
        for t, n, sql in rows), 'P8 recovery schema differs; no silent migration')
    return True

class RecoveryApplication(Application):
    def __init__(self, path, worker, *, expected_genesis):
        need(type(expected_genesis) is bytes, 'P8 external genesis pin required')
        self.expected = expected_genesis
        self.g = genesis_document(expected_genesis, worker); self.worker = worker
        self.validators = comet_validator_set(self.g['validators'])
        self.lock = threading.RLock(); self.pending = None; self.state = None
        self.height = 0; self.app_hash = ''; self.closed = False
        path = Path(path).absolute(); _safe(path)
        for p in (path, Path(str(path)+'.lock')):
            fd = os.open(p, os.O_CREAT|os.O_RDWR|os.O_NOFOLLOW, 0o600); os.close(fd)
        self.store_lock = StoreLock(Path(str(path)+'.lock'))
        try:
            self.db = sqlite3.connect(path, isolation_level=None, timeout=10, check_same_thread=False)
            if not schema(self.db, empty=True):
                for sql in RECOVERY_SCHEMA.values(): self.db.execute(sql)
            self.db.execute('PRAGMA journal_mode=WAL'); self.db.execute('PRAGMA synchronous=FULL')
            for p in (path, Path(str(path)+'-wal'), Path(str(path)+'-shm')):
                if p.exists(): os.chmod(p, 0o600)
            _safe(path); schema(self.db)
            row = self.db.execute('SELECT genesis,height,app_hash,state FROM p8_checkpoint WHERE id=1').fetchone()
            if row:
                need(bytes(row[0]) == self.expected, 'P8 durable genesis differs')
                s = decode_canonical_json(bytes(row[3]), max_bytes=MAX_STATE_BYTES)
                replay(self.g, s, row[1], self.worker)
                need(application_hash(self.g, row[1], s) == row[2], 'P8 durable AppHash differs')
                self.state = s; self.height = row[1]; self.app_hash = row[2]
                self._audit_blocks()
            else:
                need(self.db.execute('SELECT count(*) FROM p8_blocks').fetchone()[0] == 0 and
                     self.db.execute('SELECT count(*) FROM p8_snapshot_origin').fetchone()[0] == 0,
                     'P8 recovery rows without checkpoint')
            from protocol8_state_sync import StateSync
            self.state_sync = StateSync(self)
        except BaseException:
            if hasattr(self, 'db'): self.db.close()
            self.store_lock.close(); raise

    def _audit_blocks(self):
        from protocol8_state_sync import validate_payload, payload_hash
        origin = self.db.execute('SELECT height,app_hash,payload_sha256,payload FROM p8_snapshot_origin WHERE id=1').fetchone()
        base = 0; s = initial_state(self.g, self.worker)
        if origin:
            raw = bytes(origin[3]); need(payload_hash(raw).hex() == origin[2], 'P8 origin payload hash differs')
            p = validate_payload(raw, self, origin[0], origin[1])
            base = origin[0]; s = p['state']
            need(base <= self.height, 'P8 origin beyond checkpoint')
        rows = self.db.execute('SELECT height,block_hash,request_sha256,result,response,request_wire FROM p8_blocks ORDER BY height').fetchall()
        need(len(rows) == self.height-base, 'P8 real local response suffix differs')
        for h in range(base+1, self.height+1):
            b = self.state['blocks'][h-1]
            txs = [bytes.fromhex(v) for v in b['transactions']]
            s, results = _execute(self.g, s, txs, h, self.worker)
            row = rows[h-base-1]; value = decode_canonical_json(bytes(row[3]))
            need(row[0] == h and re.fullmatch('[0-9a-f]{64}', row[1]) is not None and
                 re.fullmatch('[0-9a-f]{64}', row[2]) is not None, 'P8 retained block identity')
            need(type(value) is dict and set(value) == {'height','app_hash','tx_results','last_commit_votes','validator_updates'} and
                 value['height'] == h and value['app_hash'] == application_hash(self.g,h,s) and
                 value['tx_results'] == results and value['validator_updates'] == [], 'P8 retained result differs')
            votes = _votes(value['last_commit_votes'], self.validators, h)
            wire = bytes(row[5]); need(len(wire) <= 32768, 'P8 retained request bound')
            wanted = finalization_identity(txs,h,bytes.fromhex(row[1]),bytes.fromhex(self.validators.hash),votes,wire)
            need(row[2] == wanted and bytes(row[4]) == encode_finalization(value), 'P8 exact retained response differs')
        need(canonical(s) == canonical(self.state), 'P8 origin/suffix checkpoint differs')

    def info(self):
        need(not self.closed, 'P8 recovery application closed; reopen required')
        return {**super().info(), 'name':'1soft-protocol8-recipient-recovery-development',
                'recovery_store_version':1}

    def _after_snapshot_commit(self):
        """No production fault control. Test-only subclass observes/crashes here."""

    def list_snapshots(self): return self.state_sync.list()
    def load_snapshot_chunk(self, height, format_, index): return self.state_sync.load(height, format_, index)
    def offer_snapshot(self, snapshot, app_hash): return self.state_sync.offer(snapshot, app_hash)
    def apply_snapshot_chunk(self, index, chunk, sender): return self.state_sync.apply(index, chunk, sender)
