"""Finite exact P6 obligations on one trusted POSIX host; no signing or retry."""
from __future__ import annotations
import contextlib,os,sqlite3,stat,threading
from pathlib import Path
from protocol5_encoding import decode_canonical_json
from protocol6_treasury import canonical,genesis_document,initial_state,execute_block,replay,parse,txid,digest,integer
from protocol6_certificate import verify_state
from protocol6_worker import Worker

FORMAT='1soft/protocol6-certified-treasury-journal/v1'
MAX_OBLIGATIONS=8
MAX_OBSERVATIONS=65
MAX_OBSERVATION_BYTES=1048576
SCHEMA={
'identity':'CREATE TABLE identity (id INTEGER PRIMARY KEY CHECK(id=1), format TEXT NOT NULL, genesis BLOB NOT NULL)',
'observations':'CREATE TABLE observations (height INTEGER PRIMARY KEY, payload BLOB NOT NULL)',
'obligations':'CREATE TABLE obligations (txid TEXT PRIMARY KEY, raw BLOB NOT NULL, nf TEXT NOT NULL, parent_old TEXT NOT NULL, grant_old TEXT NOT NULL, request TEXT NOT NULL, completed_at INTEGER REFERENCES observations(height))',
'attempts':'CREATE TABLE attempts (txid TEXT PRIMARY KEY REFERENCES obligations(txid), raw_sha256 TEXT NOT NULL)',
**{'live_'+name:f'CREATE UNIQUE INDEX live_{name} ON obligations ({key}) WHERE completed_at IS NULL' for name,key in [('input','nf'),('parent','parent_old'),('grant','grant_old'),('request','request')]}}

class WalletError(ValueError):pass
def need(condition,message):
    if not condition:raise WalletError(message)
def _private(path):
    need(os.name=='posix','P6 journal requires trusted POSIX host')
    parent=path.parent.lstat()
    need(stat.S_ISDIR(parent.st_mode) and parent.st_uid==os.getuid() and stat.S_IMODE(parent.st_mode)==0o700,'P6 journal private owner directory required')
    for p in (path,Path(str(path)+'-wal'),Path(str(path)+'-shm')):
        if not p.exists() and not p.is_symlink():continue
        s=p.lstat();need(stat.S_ISREG(s.st_mode) and s.st_uid==os.getuid() and stat.S_IMODE(s.st_mode)==0o600,'P6 journal private regular owner file required')
def _schema(db,empty=False):
    rows=db.execute("SELECT type,name,sql FROM sqlite_master WHERE name NOT LIKE 'sqlite_%' ORDER BY name").fetchall()
    if not rows and empty:return False
    need(len(rows)==len(SCHEMA) and all(n in SCHEMA and t==('index' if n.startswith('live_') else 'table') and ' '.join(sql.split())==' '.join(SCHEMA[n].split()) for t,n,sql in rows),'P6 journal schema differs')
    return True

def checked_observation(witness,signed_header,raw_genesis,worker):
    """Authenticate and independently replay this finite history; no freshness claim."""
    raw=canonical({'witness':witness,'signed_header':signed_header})
    need(len(raw)<=MAX_OBSERVATION_BYTES,'P6 observation byte bound')
    o=decode_canonical_json(raw,max_bytes=MAX_OBSERVATION_BYTES)
    cert=verify_state(o['witness'],o['signed_header'],raw_genesis)
    g=genesis_document(raw_genesis)
    need(isinstance(worker,Worker) and worker.sha256==g['worker_sha256'] and worker.kat_sha256==g['kat_sha256'],'P6 journal verifier/genesis pins differ')
    replay(g,o['witness']['state'],o['witness']['height'],worker)
    return o,cert

def _continuation(prior,current):
    a,b=prior['witness'],current['witness']
    need(b['height']>=a['height'],'P6 observation rollback refused')
    if b['height']==a['height']:
        need(b['app_hash']==a['app_hash'] and canonical(b['state'])==canonical(a['state']),'P6 same-height conflicting state refused')
    else:
        old,new=a['state'],b['state']
        need(new['blocks'][:len(old['blocks'])]==old['blocks'] and new['receipts'][:len(old['receipts'])]==old['receipts'],'P6 certified history fork refused')

def _resolve(raw,o):
    if o is None:return 'unknown',None
    p=parse(raw);ident=txid(raw);w=o['witness'];s=w['state']
    for r in s['receipts']:
        if r['txid']==ident:
            need(r['raw']==raw.hex() and r['raw_sha256']==digest(raw) and r['statement']==p and integer(p[15])<=r['height']<integer(p[16]) and r['fee']==integer(p[17]),'P6 exact certified receipt differs')
            return 'executed-exact',r
    for r in s['receipts']:
        q=r['statement']
        if q[21]==p[21] or q[18]==p[18] or set(q[11:13])&set(p[11:13]) or set(q[22:24])&set(p[22:24]):return 'conflict',None
    t=s['treasury']
    if p[7]!=t['parent'] or [p[6],p[8]] not in t['grants'] or integer(p[14])!=t['epoch']:return 'stale-authority',None
    return 'unknown',None

class CertifiedTreasuryJournal:
    """One canonical local journal; cloned/deleted history is not rollback protected."""
    def __init__(self,path,*,expected_genesis,worker):
        need(type(expected_genesis) is bytes,'P6 external genesis bytes required')
        self.raw_genesis=expected_genesis;self.g=genesis_document(expected_genesis);self.worker=worker
        need(isinstance(worker,Worker) and worker.sha256==self.g['worker_sha256'] and worker.kat_sha256==self.g['kat_sha256'],'P6 journal worker pins differ')
        self.path=Path(path).absolute();_private(self.path);self.lock=threading.RLock();self.closed=False
        fd=os.open(self.path,os.O_CREAT|os.O_RDWR|os.O_NOFOLLOW,0o600)
        try:
            s=os.fstat(fd);need(stat.S_ISREG(s.st_mode) and s.st_uid==os.getuid() and stat.S_IMODE(s.st_mode)==0o600,'P6 journal opened file differs')
        finally:os.close(fd)
        self.db=sqlite3.connect(self.path,isolation_level=None,timeout=60,check_same_thread=False)
        try:
            self.db.execute('PRAGMA journal_mode=WAL');self.db.execute('PRAGMA synchronous=FULL');self.db.execute('PRAGMA foreign_keys=ON')
            for p in (self.path,Path(str(self.path)+'-wal'),Path(str(self.path)+'-shm')):
                if p.exists():os.chmod(p,0o600)
            _private(self.path)
            with self.atomic():
                if not _schema(self.db,empty=True):
                    for sql in SCHEMA.values():self.db.execute(sql)
                    self.db.execute('INSERT INTO identity VALUES (1,?,?)',(FORMAT,self.raw_genesis))
                self._audit()
        except BaseException:self.db.close();self.closed=True;raise
    @contextlib.contextmanager
    def atomic(self,write=True):
        with self.lock:
            need(not self.closed,'P6 journal closed')
            self.db.execute('BEGIN IMMEDIATE' if write else 'BEGIN')
            try:yield;self.db.execute('COMMIT')
            except BaseException:
                if self.db.in_transaction:self.db.execute('ROLLBACK')
                raise
    def close(self):
        with self.lock:
            if not self.closed:self.db.close();self.closed=True
    def __enter__(self):return self
    def __exit__(self,*_):self.close()
    def _audit(self):
        _private(self.path);_schema(self.db)
        need(self.db.execute('SELECT id,format,genesis FROM identity').fetchall()==[(1,FORMAT,self.raw_genesis)],'P6 journal identity differs')
        obs=[]
        rows=self.db.execute('SELECT height,payload FROM observations ORDER BY height').fetchall()
        need(len(rows)<=MAX_OBSERVATIONS,'P6 observation capacity')
        for height,payload in rows:
            o=decode_canonical_json(bytes(payload),max_bytes=MAX_OBSERVATION_BYTES)
            need(type(o) is dict and set(o)=={'witness','signed_header'},'P6 retained observation shape')
            o,_=checked_observation(o['witness'],o['signed_header'],self.raw_genesis,self.worker)
            need(height==o['witness']['height'],'P6 retained observation height differs')
            if obs:_continuation(obs[-1],o)
            obs.append(o)
        obligations={}
        rows=self.db.execute('SELECT txid,raw,nf,parent_old,grant_old,request,completed_at FROM obligations ORDER BY txid').fetchall()
        need(len(rows)<=MAX_OBLIGATIONS,'P6 obligation capacity')
        for ident,wire,nf,parent,grant,request,completed in rows:
            raw=bytes(wire);p=parse(raw)
            need(txid(raw)==ident and (nf,parent,grant,request)==(p[21],p[7],p[8],p[18]),'P6 retained wire/resource identity differs')
            self._domain(p);need(self.worker.verify(raw),'P6 retained invalid proof')
            first=next((o for o in obs if _resolve(raw,o)[0]=='executed-exact'),None)
            need(completed==(first['witness']['height'] if first else None),'P6 saved completion differs from exact certified inclusion')
            obligations[ident]={'raw':raw,'completed_at':completed,'attempts':0}
        for ident,rawsha in self.db.execute('SELECT txid,raw_sha256 FROM attempts'):
            need(ident in obligations and rawsha==digest(obligations[ident]['raw']),'P6 retained attempt identity differs')
            obligations[ident]['attempts']=1
        need(self.db.execute('PRAGMA foreign_key_check').fetchall()==[],'P6 journal foreign reference differs')
        return obs,obligations
    def _domain(self,p):
        t=self.g['treasury']
        need(all(p[i]==t[k] for i,k in [(1,'genesis'),(2,'asset'),(3,'mission'),(5,'parent_id')]) and p[6] in [x[0] for x in t['grants']] and integer(p[14])==t['epoch'] and integer(p[17])==t['fee'],'P6 retained transaction domain differs')
    def retain(self,raw):
        p=parse(raw);self._domain(p);need(self.worker.verify(raw),'P6 invalid prepared proof');ident=txid(raw)
        try:
            with self.atomic():
                obs,rows=self._audit();need(len(rows)<MAX_OBLIGATIONS,'P6 obligation capacity')
                need(ident not in rows,'P6 exact obligation already retained')
                if obs:
                    o=obs[-1]['witness'];state=o['state'];height=o['height']+1
                else:state=initial_state(self.g,self.worker);height=1
                _,results=execute_block(self.g,state,[raw],height,self.worker)
                need(results[0]['code']==0,'P6 prepared transaction not valid at known checkpoint')
                self.db.execute('INSERT INTO obligations VALUES (?,?,?,?,?,?,NULL)',(ident,raw,p[21],p[7],p[8],p[18]))
            return ident
        except sqlite3.IntegrityError:raise WalletError('P6 input, authority or request is held by an existing obligation') from None
    def claim(self,ident):
        with self.atomic():
            obs,rows=self._audit();need(ident in rows,'P6 exact obligation missing');row=rows[ident]
            need(row['attempts']==0 and row['completed_at'] is None,'P6 one delivery attempt already claimed or completed')
            if obs:
                reason,_=_resolve(row['raw'],obs[-1]);p=parse(row['raw']);next_height=obs[-1]['witness']['height']+1
                need(reason=='unknown' and next_height<=64 and integer(p[15])<=next_height<integer(p[16]),'P6 known conflict, stale authority or elapsed window refuses delivery')
            self.db.execute('INSERT INTO attempts VALUES (?,?)',(ident,digest(row['raw'])))
            return row['raw']
    def deliver_once(self,ident,transport):
        need(callable(transport),'P6 delivery transport required');raw=self.claim(ident)
        try:transport(raw)
        except Exception:return {'txid':ident,'outcome':'unknown','attempts':1}
        return {'txid':ident,'outcome':'returned-untrusted','attempts':1}
    def observe(self,witness,signed_header):
        o,cert=checked_observation(witness,signed_header,self.raw_genesis,self.worker)
        with self.atomic():
            obs,rows=self._audit();h=o['witness']['height']
            if obs:_continuation(obs[-1],o)
            same=bool(obs and h==obs[-1]['witness']['height'])
            if not same:
                need(len(obs)<MAX_OBSERVATIONS,'P6 observation capacity')
                self.db.execute('INSERT INTO observations VALUES (?,?)',(h,canonical(o)))
            for ident,row in rows.items():
                reason,_=_resolve(row['raw'],o)
                if reason=='executed-exact' and row['completed_at'] is None:self.db.execute('UPDATE obligations SET completed_at=? WHERE txid=?',(h,ident))
        return {'state_height':h,'app_hash':o['witness']['app_hash'],'idempotent':same,'certificate':cert}
    def _row(self,ident):
        obs,rows=self._audit();need(ident in rows,'P6 exact obligation missing');return obs,rows[ident]
    def status(self,ident):
        with self.atomic(False):
            obs,row=self._row(ident);reason,_=_resolve(row['raw'],obs[-1] if obs else None)
            status='recorded-certified' if row['completed_at'] is not None else ('observed-held' if obs else ('attempted-held' if row['attempts'] else 'retained'))
            return {'txid':ident,'status':status,'attempts':row['attempts'],'hold_reason':None if status=='recorded-certified' else reason,'certified_height':obs[-1]['witness']['height'] if obs else None}
    def export(self,ident):
        with self.atomic(False):return self._row(ident)[1]['raw']
    def recorded_receipt(self,ident):
        with self.atomic(False):
            obs,row=self._row(ident);need(row['completed_at'] is not None,'P6 exact certified execution absent')
            o=next(o for o in obs if o['witness']['height']==row['completed_at']);reason,r=_resolve(row['raw'],o)
            need(reason=='executed-exact','P6 exact recorded receipt absent')
            return {'format':'1soft/protocol6-exact-execution-record/v1','genesis':self.raw_genesis.hex(),'txid':ident,'raw':row['raw'].hex(),'raw_sha256':digest(row['raw']),
                    'state_height':o['witness']['height'],'receipt':r,'witness':o['witness'],'signed_header':o['signed_header']}
