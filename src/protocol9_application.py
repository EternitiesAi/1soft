"""Segmented recipient ABCI lifecycle with streamed native restart audit."""
import copy
import hashlib
import os
import re
import sqlite3
import stat
import tempfile
import threading
from pathlib import Path
import protocol8_transfer as n
from block_application import StoreLock, transaction_data_size
from protocol5_encoding import comet_validator_set
from protocol5_abci_wire import Request, Response
from protocol8_application import _votes
from protocol9_consensus import (genesis_document, closed, application_hash, result,
    MAX_HEIGHT, MAX_TX_BYTES, MAX_REQUEST_BYTES, MAX_CHECKPOINT_BYTES)
from protocol9_store import Store, schema, compare_indexes, INDEX_TABLES

def safe(path):
    for parent in path.parents:
        n.need(not parent.is_symlink(), 'P9 symlink storage ancestry refused')
    s = path.parent.lstat()
    n.need(stat.S_ISDIR(s.st_mode) and s.st_uid == os.getuid() and stat.S_IMODE(s.st_mode) == 0o700,
           'P9 private owner storage directory required')
    for candidate in (path,Path(str(path)+'-wal'),Path(str(path)+'-shm'),Path(str(path)+'.lock')):
        if not candidate.exists() and not candidate.is_symlink(): continue
        s = candidate.lstat()
        n.need(stat.S_ISREG(s.st_mode) and s.st_uid == os.getuid() and s.st_nlink == 1 and
               stat.S_IMODE(s.st_mode) == 0o600, 'P9 private single-link storage required')

def request_identity(txs, height, block_hash, validators_hash, votes, raw):
    n.need(type(raw) is bytes and len(raw) <= MAX_REQUEST_BYTES, 'P9 finalize wire bound')
    try: q = type(Request().finalize_block).FromString(raw)
    except Exception as e: raise n.Invalid('P9 malformed finalization request') from e
    actual_votes = [{'address':bytes(v.validator.address).hex(),'power':v.validator.power,
                     'block_id_flag':v.block_id_flag} for v in q.decided_last_commit.votes]
    n.need(q.SerializeToString(deterministic=True) == raw and list(q.txs) == txs and
           q.height == height and bytes(q.hash) == block_hash and
           bytes(q.next_validators_hash) == validators_hash and actual_votes == votes,
           'P9 retained request projection differs')
    return n.sha(b'1soft/segmented-recipient-consensus/finalize/v1\0' + raw)

def encode_finalization(value):
    out = Response().finalize_block; out.SetInParent(); out.app_hash = bytes.fromhex(value['app_hash'])
    for r in value['tx_results']:
        t = out.tx_results.add(code=r['code'],log=r['log'],data=r['data'].encode('ascii'))
        if t.code: t.codespace = 'one-segmented-recipient-development'
    return out.SerializeToString(deterministic=True)

class Application:
    def __init__(self, path, worker, *, expected_genesis):
        self.g = genesis_document(expected_genesis,worker); self.expected = expected_genesis
        self.worker = worker; self.validators = comet_validator_set(self.g['validators'])
        self.lock = threading.RLock(); self.closed = False; self.pending = None
        self.height = 0; self.app_hash = ''; self.checkpoint = None
        path = Path(path).absolute(); safe(path)
        for target in (path,Path(str(path)+'.lock')):
            fd = os.open(target,os.O_CREAT|os.O_RDWR|os.O_NOFOLLOW,0o600); os.close(fd)
        self.store_lock = StoreLock(Path(str(path)+'.lock'))
        try:
            self.db = sqlite3.connect(path,isolation_level=None,timeout=10,check_same_thread=False)
            schema(self.db,create=True)
            self.db.execute('PRAGMA journal_mode=WAL'); self.db.execute('PRAGMA synchronous=FULL')
            for target in (path,Path(str(path)+'-wal'),Path(str(path)+'-shm')):
                if target.exists(): os.chmod(target,0o600)
            safe(path); self.store = Store(self.db,self.g,worker)
            sizes = self.db.execute('SELECT length(genesis),length(checkpoint),length(app_hash) FROM p9_checkpoint WHERE id=1').fetchone()
            if sizes:
                n.need(sizes[0] <= 16384 and sizes[1] <= MAX_CHECKPOINT_BYTES and sizes[2] == 64,
                       'P9 durable checkpoint bounds')
                raw,c,a = self.db.execute('SELECT genesis,checkpoint,app_hash FROM p9_checkpoint WHERE id=1').fetchone()
                n.need(bytes(raw) == expected_genesis, 'P9 durable external genesis differs')
                checkpoint = closed(bytes(c),MAX_CHECKPOINT_BYTES)
                self._audit(checkpoint,a)
                self._publish(checkpoint,a)
            else:
                n.need(all(self.db.execute('SELECT COUNT(*) FROM '+table).fetchone()[0] == 0
                           for table in (*INDEX_TABLES,'p9_blocks')), 'P9 records without checkpoint')
        except BaseException:
            if hasattr(self,'db'): self.db.close()
            self.store_lock.close(); self.closed = True; raise

    def _publish(self, checkpoint, app_hash):
        self.checkpoint = checkpoint; self.height = checkpoint['height']; self.app_hash = app_hash
        self.pending = None

    def _audit(self, checkpoint, app_hash):
        # Disk-backed replay keeps memory bounded by one block and one segment.
        with tempfile.TemporaryDirectory(prefix='one-p9-replay-') as tmp:
            replayed = sqlite3.connect(str(Path(tmp)/'audit.sqlite'),isolation_level=None)
            try:
                schema(replayed,create=True); store = Store(replayed,self.g,self.worker)
                c = store.initial(); a = application_hash(self.g,c)
                count = 0
                lengths = self.db.execute('SELECT height,length(block_hash),length(identity),length(txs),length(value),length(response),length(request_wire) FROM p9_blocks ORDER BY height')
                for h,b,i,t,v,r,w in lengths:
                    n.need(h == count+1 and b == i == 64 and t <= 2*MAX_TX_BYTES*2+16 and
                           v <= 16384 and r <= 16384 and w <= MAX_REQUEST_BYTES, 'P9 retained block bounds/order')
                    row = self.db.execute('SELECT block_hash,identity,txs,value,response,request_wire FROM p9_blocks WHERE height=?',(h,)).fetchone()
                    txhex = closed(bytes(row[2]),2*MAX_TX_BYTES*2+16)
                    n.need(type(txhex) is list and len(txhex) <= 2 and all(type(x) is str and
                           len(x) <= 2*MAX_TX_BYTES and len(x)%2 == 0 and re.fullmatch('[0-9a-f]*',x) is not None for x in txhex),
                           'P9 retained transactions')
                    txs = [bytes.fromhex(x) for x in txhex]; value = closed(bytes(row[3]),16384)
                    n.need(type(value) is dict and set(value) == {'height','app_hash','tx_results','last_commit_votes','validator_updates'},
                           'P9 closed retained result')
                    votes = _votes(value['last_commit_votes'],self.validators,h)
                    n.need(re.fullmatch('[0-9a-f]{64}',row[0]) is not None and
                           request_identity(txs,h,bytes.fromhex(row[0]),bytes.fromhex(self.validators.hash),votes,bytes(row[5])) == row[1],
                           'P9 retained finalization identity differs')
                    c,results,a = store.advance(c,txs,h)
                    expected = {'height':h,'app_hash':a,'tx_results':results,'last_commit_votes':votes,'validator_updates':[]}
                    n.need(n.canonical(value) == n.canonical(expected) and bytes(row[4]) == encode_finalization(expected),
                           'P9 replayed block result/response differs')
                    count += 1
                n.need(n.canonical(c) == n.canonical(checkpoint) and a == app_hash and count == c['height'],
                       'P9 replayed checkpoint differs')
                compare_indexes(self.db,replayed)
            finally: replayed.close()

    def close(self):
        with self.lock:
            if not self.closed:
                self.db.close(); self.store_lock.close(); self.closed = True; self.pending = None
    def __enter__(self): return self
    def __exit__(self,*_): self.close()
    def _ready(self): n.need(not self.closed and self.checkpoint is not None, 'P9 not initialized')
    def info(self):
        return {'name':'1soft-segmented-recipient-development','version':9,'height':self.height,
                'app_hash':self.app_hash,'initialized':self.checkpoint is not None,'worker_startup':self.worker.startup}

    def init_chain(self, chain_id, raw, validators, initial_height=1):
        with self.lock:
            n.need(type(initial_height) is int and initial_height == 1 and chain_id == self.g['chain_id'] and
                   raw == self.expected and type(validators) is list and
                   n.canonical(sorted(validators,key=lambda v:v['public_key'])) == n.canonical(self.g['validators']),
                   'P9 engine genesis/roster differs')
            if self.checkpoint is not None:
                n.need(self.height == 0, 'P9 already progressed'); return self.app_hash
            self.db.execute('BEGIN IMMEDIATE')
            try:
                c = self.store.initial(); a = application_hash(self.g,c)
                self.db.execute('INSERT INTO p9_checkpoint VALUES (1,?,?,?)',(raw,n.canonical(c),a))
                self.db.execute('COMMIT'); self._publish(c,a)
            except BaseException:
                if self.db.in_transaction: self.db.execute('ROLLBACK')
                else: self.close()
                raise
            return a

    def _simulate(self, txs, height):
        self.db.execute('SAVEPOINT p9_simulation')
        try: return self.store.advance(self.checkpoint,txs,height)
        finally:
            self.db.execute('ROLLBACK TO p9_simulation'); self.db.execute('RELEASE p9_simulation')

    def check_tx(self, raw):
        with self.lock:
            self._ready()
            if self.height == MAX_HEIGHT: return result(7)
            if type(raw) is not bytes or len(raw) > MAX_TX_BYTES: return result(1)
            return self._simulate([raw],self.height+1)[1][0]

    def prepare_proposal(self, candidates, height, max_bytes):
        with self.lock:
            self._ready(); n.need(type(candidates) is list and type(height) is int and height == self.height+1 and
                                 type(max_bytes) is int and max_bytes >= 0, 'P9 proposal context')
            accepted = []
            for raw in candidates[:8]:
                if len(accepted) == 2: break
                if type(raw) is not bytes or len(raw) > MAX_TX_BYTES or transaction_data_size(accepted+[raw]) > min(max_bytes,8208): continue
                if all(r['code'] == 0 for r in self._simulate(accepted+[raw],height)[1]): accepted.append(raw)
            return accepted

    def process_proposal(self, txs, height, next_validators_hash):
        with self.lock:
            self._ready()
            if type(next_validators_hash) is not bytes or next_validators_hash.hex() != self.validators.hash: return False
            try: return all(r['code'] == 0 for r in self._simulate(txs,height)[1])
            except n.Invalid: return False

    def finalize_block(self, txs, height, block_hash, next_validators_hash, last_commit_votes, request_wire):
        with self.lock:
            self._ready()
            n.need(type(height) is int and type(block_hash) is bytes and len(block_hash) == 32 and
                   type(next_validators_hash) is bytes and next_validators_hash.hex() == self.validators.hash,
                   'P9 finalization context')
            votes = _votes(last_commit_votes,self.validators,height)
            ident = request_identity(txs,height,block_hash,next_validators_hash,votes,request_wire)
            if height == self.height and height > 0:
                row = self.db.execute('SELECT identity,value,response FROM p9_blocks WHERE height=?',(height,)).fetchone()
                n.need(row is not None and row[0] == ident, 'P9 conflicting committed finalize')
                return closed(bytes(row[1]),16384),bytes(row[2])
            n.need(height == self.height+1, 'P9 finalize height differs')
            if self.pending:
                n.need(self.pending['identity'] == ident, 'P9 conflicting pending finalize')
                return copy.deepcopy(self.pending['value']),self.pending['response']
            c,results,a = self._simulate(txs,height)
            value = {'height':height,'app_hash':a,'tx_results':results,'last_commit_votes':votes,'validator_updates':[]}
            response = encode_finalization(value)
            self.pending = {'identity':ident,'txs':list(txs),'block_hash':block_hash.hex(),'request_wire':request_wire,
                            'value':value,'response':response,'checkpoint':c}
            return copy.deepcopy(value),response

    def commit(self):
        with self.lock:
            self._ready()
            if not self.pending: return self.info()
            p = self.pending; h = p['value']['height']; self.db.execute('BEGIN IMMEDIATE')
            try:
                c,results,a = self.store.advance(self.checkpoint,p['txs'],h)
                n.need(c == p['checkpoint'] and results == p['value']['tx_results'] and a == p['value']['app_hash'],
                       'P9 commit transition differs from staged result')
                self.db.execute('UPDATE p9_checkpoint SET checkpoint=?,app_hash=? WHERE id=1',(n.canonical(c),a))
                self.db.execute('INSERT INTO p9_blocks VALUES (?,?,?,?,?,?,?)',
                    (h,p['block_hash'],p['identity'],n.canonical([raw.hex() for raw in p['txs']]),
                     n.canonical(p['value']),p['response'],p['request_wire']))
                self.db.execute('COMMIT'); self._publish(c,a)
            except BaseException:
                if self.db.in_transaction: self.db.execute('ROLLBACK')
                else: self.close()  # Unknown/post-commit outcome cannot serve stale memory.
                raise
            return self.info()

    def query(self, path, height=0, prove=False):
        with self.lock:
            try:
                self._ready(); n.need(type(path) is str and type(height) is int and height in (0,self.height) and
                                     prove is False, 'P9 query context')
                if path == '/info': value = self.info()
                elif path == '/worker-receipts': value = self.worker.audit()
                elif path == '/state':
                    value = {'genesis':self.g,'height':self.height,'app_hash':self.app_hash,'checkpoint':self.checkpoint}
                elif re.fullmatch('/segment/(0|[1-9][0-9]{0,18})',path):
                    segment = int(path.split('/')[-1])
                    n.need(segment <= MAX_HEIGHT, 'P9 segment integer bound')
                    rows = self.db.execute('SELECT commitment FROM p9_notes WHERE segment=? ORDER BY position LIMIT 17',(segment,)).fetchall()
                    n.need(1 <= len(rows) <= 16, 'P9 segment absent')
                    value = {'segment':segment,'notes':[r[0] for r in rows]}
                elif re.fullmatch('/tx/[0-9a-f]{64}',path):
                    row = self.db.execute('SELECT height,wire FROM p9_receipts WHERE txid=?',(path[4:],)).fetchone()
                    n.need(row is not None, 'P9 receipt absent'); value = {'height':row[0],'wire':bytes(row[1]).hex()}
                else: raise n.Invalid('unsupported P9 query')
                return {'code':0,'height':self.height,'value':n.canonical(value),'log':''}
            except n.Invalid:
                return {'code':1,'height':self.height,'value':b'','log':'unsupported P9 query'}
