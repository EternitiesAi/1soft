"""Pinned P6 ABCI lifecycle: isolate proposals, stage finalization, commit atomically."""
from __future__ import annotations
import hashlib, os, re, sqlite3, stat, threading
from pathlib import Path
from block_application import StoreLock,transaction_data_size
from protocol5_encoding import decode_canonical_json,comet_validator_set
from protocol5_abci_wire import Response
from protocol6_treasury import (canonical,need,genesis_document,initial_state,execute_block,replay,application_hash,result,StateError,CapacityError)

SCHEMA={
'checkpoint':'CREATE TABLE checkpoint (id INTEGER PRIMARY KEY CHECK(id=1), genesis BLOB NOT NULL, height INTEGER NOT NULL, app_hash TEXT NOT NULL, state BLOB NOT NULL)',
'blocks':'CREATE TABLE blocks (height INTEGER PRIMARY KEY, block_hash TEXT NOT NULL, request_sha256 TEXT NOT NULL, result BLOB NOT NULL, response BLOB NOT NULL, request_wire BLOB NOT NULL)'}
def _schema(db,empty=False):
    rows=db.execute("SELECT type,name,sql FROM sqlite_master WHERE name NOT LIKE 'sqlite_%' ORDER BY name").fetchall()
    if empty and not rows:return False
    need(len(rows)==2 and all(t=='table' and n in SCHEMA and ' '.join(sql.split())==' '.join(SCHEMA[n].split()) for t,n,sql in rows),'P6 schema differs')
    return True
def _safe(path):
    parent=path.parent.lstat();need(stat.S_ISDIR(parent.st_mode) and parent.st_uid==os.getuid() and stat.S_IMODE(parent.st_mode)==0o700,'P6 private storage directory required')
    for p in [path,Path(str(path)+'-wal'),Path(str(path)+'-shm'),Path(str(path)+'.lock')]:
        if not p.exists() and not p.is_symlink():continue
        st=p.lstat();need(stat.S_ISREG(st.st_mode) and st.st_uid==os.getuid() and stat.S_IMODE(st.st_mode)==0o600,'P6 private regular storage required')
def encode_finalization(value):
    out=Response().finalize_block;out.SetInParent();out.app_hash=bytes.fromhex(value['app_hash'])
    for r in value['tx_results']:
        t=out.tx_results.add(code=r['code'],log=r['log'],data=r['data'].encode('ascii'))
        if t.code:t.codespace='one-protocol6-treasury-development'
    return out.SerializeToString(deterministic=True)
def _votes(rows,validators,h):
    if h==1:need(rows==[],'P6 first last-commit must be empty');return []
    need(type(rows) is list,'P6 votes required');wanted={v.address.hex():v.power for v in validators.validators};seen={}
    for r in rows:
        need(type(r) is dict and set(r)=={'address','power','block_id_flag'} and type(r['address']) is str and r['address'] in wanted and r['address'] not in seen and type(r['power']) is int and type(r['block_id_flag']) is int and r['block_id_flag'] in (1,2,3),'P6 vote entry')
        seen[r['address']]=r['power']
    need(seen==wanted and sum(r['power'] for r in rows if r['block_id_flag']==2)*3>validators.total_power*2,'P6 last-commit roster or quorum differs')
    return rows
def finalization_identity(txs,height,block_hash,validators_hash,votes,request_wire):
    return hashlib.sha256(b'1soft/protocol6-static-treasury/finalize/v1\0'+canonical({'txs':[r.hex() for r in txs],'height':height,'block':block_hash.hex(),'validators':validators_hash.hex(),'votes':votes,'wire_sha256':hashlib.sha256(request_wire).hexdigest()})).hexdigest()
class Application:
    def __init__(self,path,worker,*,expected_genesis):
        need(type(expected_genesis) is bytes,'P6 external genesis pin required')
        self.expected=expected_genesis;self.g=genesis_document(expected_genesis);self.worker=worker
        self.validators=comet_validator_set(self.g['validators']);self.lock=threading.RLock();self.pending=None;self.state=None;self.height=0;self.app_hash='';self.closed=False
        path=Path(path).absolute();_safe(path)
        for p in (path,Path(str(path)+'.lock')):
            fd=os.open(p,os.O_CREAT|os.O_RDWR|os.O_NOFOLLOW,0o600);os.close(fd)
        self.store_lock=StoreLock(Path(str(path)+'.lock'))
        try:
            self.db=sqlite3.connect(path,isolation_level=None,timeout=10,check_same_thread=False)
            if not _schema(self.db,empty=True):
                for sql in SCHEMA.values():self.db.execute(sql)
            self.db.execute('PRAGMA journal_mode=WAL');self.db.execute('PRAGMA synchronous=FULL')
            for p in (path,Path(str(path)+'-wal'),Path(str(path)+'-shm')):
                if p.exists():os.chmod(p,0o600)
            _safe(path);_schema(self.db)
            row=self.db.execute('SELECT genesis,height,app_hash,state FROM checkpoint WHERE id=1').fetchone()
            if row:
                need(bytes(row[0])==self.expected,'P6 durable genesis differs')
                s=decode_canonical_json(bytes(row[3]),max_bytes=262144);replay(self.g,s,row[1],self.worker)
                need(application_hash(self.g,row[1],s)==row[2],'P6 durable AppHash differs')
                self.state=s;self.height=row[1];self.app_hash=row[2];self._audit_blocks()
            else:need(self.db.execute('SELECT COUNT(*) FROM blocks').fetchone()[0]==0,'P6 blocks without checkpoint')
        except BaseException:
            if hasattr(self,'db'):self.db.close()
            self.store_lock.close();raise
    def _audit_blocks(self):
        rows=self.db.execute('SELECT height,block_hash,request_sha256,result,response,request_wire FROM blocks ORDER BY height').fetchall()
        need(len(rows)==self.height,'P6 retained block count differs')
        s=initial_state(self.g,self.worker)
        for h,b in enumerate(self.state['blocks'],1):
            s,results=execute_block(self.g,s,[bytes.fromhex(v) for v in b['transactions']],h,self.worker)
            row=rows[h-1];value=decode_canonical_json(bytes(row[3]))
            need(row[0]==h and re.fullmatch('[0-9a-f]{64}',row[1]) is not None and re.fullmatch('[0-9a-f]{64}',row[2]) is not None,'P6 retained block identity')
            need(type(value) is dict and set(value)=={'height','app_hash','tx_results','last_commit_votes','validator_updates'} and value['height']==h and value['app_hash']==application_hash(self.g,h,s) and value['tx_results']==results and value['validator_updates']==[],'P6 retained block result differs')
            votes=_votes(value['last_commit_votes'],self.validators,h)
            wire=bytes(row[5]);need(len(wire)<=16384,'P6 retained request bound')
            wanted=finalization_identity([bytes.fromhex(v) for v in b['transactions']],h,bytes.fromhex(row[1]),bytes.fromhex(self.validators.hash),votes,wire)
            need(row[2]==wanted,'P6 retained finalization identity differs')
            need(bytes(row[4])==encode_finalization(value),'P6 exact retained response differs')
    def close(self):
        with self.lock:
            if not self.closed:self.db.close();self.store_lock.close();self.closed=True;self.pending=None
    def __enter__(self):return self
    def __exit__(self,*_):self.close()
    def info(self):return {'name':'1soft-protocol6-static-treasury-development','version':6,'height':self.height,'app_hash':self.app_hash,'initialized':self.state is not None,'worker_startup':self.worker.startup}
    def init_chain(self,chain_id,raw,validators,initial_height=1):
        with self.lock:
            need(type(initial_height) is int and initial_height==1 and chain_id==self.g['chain_id'] and raw==self.expected,'P6 engine genesis differs')
            need(type(validators) is list and canonical(sorted(validators,key=lambda v:v['public_key']))==canonical(self.g['validators']),'P6 engine validators differ')
            if self.state is not None:need(self.height==0,'P6 already initialized');return self.app_hash
            s=initial_state(self.g,self.worker);a=application_hash(self.g,0,s)
            self.db.execute('BEGIN IMMEDIATE')
            try:self.db.execute('INSERT INTO checkpoint VALUES (1,?,?,?,?)',(raw,0,a,canonical(s)));self.db.execute('COMMIT')
            except BaseException:
                if self.db.in_transaction:self.db.execute('ROLLBACK')
                raise
            self.state=s;self.app_hash=a;return a
    def _ready(self):need(self.state is not None and not self.closed,'P6 not initialized')
    def check_tx(self,raw):
        with self.lock:
            self._ready()
            if type(raw) is not bytes or len(raw)>4096:return result(1)
            try:return execute_block(self.g,self.state,[raw],self.height+1,self.worker)[1][0]
            except CapacityError:return result(7)
    def prepare_proposal(self,candidates,height,max_bytes):
        with self.lock:
            self._ready();need(type(candidates) is list and type(height) is int and height==self.height+1 and type(max_bytes) is int and max_bytes>=0,'P6 proposal context')
            accepted=[]
            for r in candidates[:8]:
                if len(accepted)==2:break
                if type(r) is not bytes or len(r)>4096 or transaction_data_size(accepted+[r])>min(max_bytes,8200):continue
                try:_,results=execute_block(self.g,self.state,accepted+[r],height,self.worker)
                except CapacityError:break
                if all(x['code']==0 for x in results):accepted.append(r)
            return accepted
    def process_proposal(self,txs,height,next_validators_hash):
        with self.lock:
            self._ready()
            if type(next_validators_hash) is not bytes or next_validators_hash.hex()!=self.validators.hash:return False
            try:return all(r['code']==0 for r in execute_block(self.g,self.state,txs,height,self.worker)[1])
            except StateError:return False
    def finalize_block(self,txs,height,block_hash,next_validators_hash,last_commit_votes,request_wire):
        with self.lock:
            self._ready();need(type(height) is int and type(block_hash) is bytes and len(block_hash)==32 and type(request_wire) is bytes and len(request_wire)<=16384,'P6 finalization identity')
            need(type(next_validators_hash) is bytes and next_validators_hash.hex()==self.validators.hash,'P6 immutable validators differ')
            votes=_votes(last_commit_votes,self.validators,height)
            need(type(txs) is list and len(txs)<=2 and all(type(t) is bytes and len(t)<=4096 for t in txs),'P6 finalization container')
            ident=finalization_identity(txs,height,block_hash,next_validators_hash,votes,request_wire)
            if height==self.height and height>0:
                row=self.db.execute('SELECT block_hash,request_sha256,result,response FROM blocks WHERE height=?',(height,)).fetchone()
                need(row is not None and row[0]==block_hash.hex() and row[1]==ident,'P6 conflicting committed finalize')
                return decode_canonical_json(bytes(row[2])),bytes(row[3])
            need(height==self.height+1,'P6 finalize height differs')
            if self.pending:
                need(self.pending['identity']==ident,'P6 conflicting pending finalize')
                return decode_canonical_json(canonical(self.pending['result'])),self.pending['response']
            s,results=execute_block(self.g,self.state,txs,height,self.worker)
            value={'height':height,'app_hash':application_hash(self.g,height,s),'tx_results':results,'last_commit_votes':votes,'validator_updates':[]}
            response=encode_finalization(value);self.pending={'identity':ident,'block':block_hash.hex(),'state':s,'result':value,'response':response,'request_wire':request_wire}
            return decode_canonical_json(canonical(value)),response
    def commit(self):
        with self.lock:
            self._ready()
            if not self.pending:return self.info()
            p=self.pending;value=p['result'];replay(self.g,p['state'],value['height'],self.worker)
            self.db.execute('BEGIN IMMEDIATE')
            try:
                self.db.execute('UPDATE checkpoint SET height=?,app_hash=?,state=? WHERE id=1',(value['height'],value['app_hash'],canonical(p['state'])))
                self.db.execute('INSERT INTO blocks VALUES (?,?,?,?,?,?)',(value['height'],p['block'],p['identity'],canonical(value),p['response'],p['request_wire']))
                self.db.execute('COMMIT')
            except BaseException:
                if self.db.in_transaction:self.db.execute('ROLLBACK')
                raise
            self.state=p['state'];self.height=value['height'];self.app_hash=value['app_hash'];self.pending=None
            return self.info()
    def query(self,path,height=0,prove=False):
        with self.lock:
            try:
                self._ready();need(type(path) is str and type(height) is int and height in (0,self.height) and prove is False,'P6 query context')
                if path=='/info':value=self.info()
                elif path=='/state':value={'genesis':self.g,'height':self.height,'app_hash':self.app_hash,'state':self.state}
                elif path.startswith('/tx/'):
                    ident=path[4:];need(re.fullmatch('[0-9a-f]{64}',ident) is not None,'P6 tx identity')
                    rows=[r for r in self.state['receipts'] if r['txid']==ident];need(len(rows)==1,'P6 receipt absent');value=rows[0]
                else:raise StateError('unsupported P6 query')
                return {'code':0,'height':self.height,'value':canonical(value),'log':''}
            except StateError:return {'code':1,'height':self.height,'value':b'','log':'unsupported P6 query'}
