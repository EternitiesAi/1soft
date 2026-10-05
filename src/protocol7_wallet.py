"""Finite exact P7 obligations on one trusted POSIX host; no signing or retry."""
from __future__ import annotations
import contextlib,os,sqlite3,stat,threading
from pathlib import Path
from protocol5_encoding import decode_canonical_json
from protocol7_treasury import canonical,genesis_document,initial_state,replay,parse,packet,txid,digest,integer,COMMAND_MAGIC,COMMAND_DOMAIN,hexbytes,bootstrap_digest,ZERO
from protocol7_certificate import verify_state
from protocol7_worker import Worker
from protocol7_admission import preflight
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

FORMAT='1soft/protocol7-certified-treasury-journal/v1'
MAX_OBLIGATIONS=8
MAX_OBSERVATIONS=65
MAX_OBSERVATION_BYTES=1048576
SCHEMA={
'identity':'CREATE TABLE identity (id INTEGER PRIMARY KEY CHECK(id=1), format TEXT NOT NULL, genesis BLOB NOT NULL)',
'observations':'CREATE TABLE observations (height INTEGER PRIMARY KEY, payload BLOB NOT NULL)',
'obligations':"CREATE TABLE obligations (txid TEXT PRIMARY KEY, raw BLOB NOT NULL, kind TEXT NOT NULL CHECK(kind IN ('payment','owner')), context_root TEXT NOT NULL, owner_lane TEXT, nf TEXT, parent_old TEXT, grant_old TEXT, request TEXT, completed_at INTEGER REFERENCES observations(height))",
'attempts':'CREATE TABLE attempts (txid TEXT PRIMARY KEY REFERENCES obligations(txid), raw_sha256 TEXT NOT NULL)',
**{'live_'+name:f'CREATE UNIQUE INDEX live_{name} ON obligations ({key}) WHERE completed_at IS NULL' for name,key in [('context','context_root'),('owner','owner_lane'),('input','nf'),('parent','parent_old'),('grant','grant_old'),('request','request')]}}

class WalletError(ValueError):pass
def need(condition,message):
    if not condition:raise WalletError(message)
def _private(path):
    need(os.name=='posix','P7 journal requires trusted POSIX host')
    parent=path.parent.lstat()
    need(stat.S_ISDIR(parent.st_mode) and parent.st_uid==os.getuid() and stat.S_IMODE(parent.st_mode)==0o700,'P7 journal private owner directory required')
    for p in (path,Path(str(path)+'-wal'),Path(str(path)+'-shm')):
        if not p.exists() and not p.is_symlink():continue
        s=p.lstat();need(stat.S_ISREG(s.st_mode) and s.st_uid==os.getuid() and stat.S_IMODE(s.st_mode)==0o600,'P7 journal private regular owner file required')
def _schema(db,empty=False):
    rows=db.execute("SELECT type,name,sql FROM sqlite_master WHERE name NOT LIKE 'sqlite_%' ORDER BY name").fetchall()
    if not rows and empty:return False
    need(len(rows)==len(SCHEMA) and all(n in SCHEMA and t==('index' if n.startswith('live_') else 'table') and ' '.join(sql.split())==' '.join(SCHEMA[n].split()) for t,n,sql in rows),'P7 journal schema differs')
    return True

def checked_observation(witness,signed_header,raw_genesis,worker):
    """Authenticate and independently replay this finite history; no freshness claim."""
    raw=canonical({'witness':witness,'signed_header':signed_header})
    need(len(raw)<=MAX_OBSERVATION_BYTES,'P7 observation byte bound')
    o=decode_canonical_json(raw,max_bytes=MAX_OBSERVATION_BYTES)
    cert=verify_state(o['witness'],o['signed_header'],raw_genesis,worker)
    g=genesis_document(raw_genesis,worker)
    need(isinstance(worker,Worker) and worker.sha256==g['worker_sha256'] and worker.kat_sha256==g['kat_sha256'],'P7 journal verifier/genesis pins differ')
    return o,cert

def _continuation(prior,current):
    a,b=prior['witness'],current['witness']
    need(b['height']>=a['height'],'P7 observation rollback refused')
    if b['height']==a['height']:
        need(b['app_hash']==a['app_hash'] and canonical(b['state'])==canonical(a['state']),'P7 same-height conflicting state refused')
    else:
        old,new=a['state'],b['state']
        need(new['blocks'][:len(old['blocks'])]==old['blocks'] and new['receipts'][:len(old['receipts'])]==old['receipts'],'P7 certified history fork refused')

def _resolve(raw,o,worker):
    if o is None:return 'unknown',None
    kind='owner' if raw[:8]==COMMAND_MAGIC else 'payment';p=packet(raw)['body'] if kind=='owner' else parse(raw)
    ident=txid(raw);w=o['witness'];s=w['state'];t=s['treasury'];earliest=w['height']+2
    for r in s['receipts']:
        if r['txid']==ident:
            need(r['kind']==kind and r['raw']==raw.hex() and r['raw_sha256']==digest(raw),'P7 exact certified typed receipt differs')
            if kind=='owner':need(r['body']==p and r['height']==p['height'],'P7 exact owner receipt differs')
            else:need(r['statement']==p and integer(p[15])<=r['height']<integer(p[16]) and r['fee']==integer(p[17]),'P7 exact payment receipt differs')
            return 'executed-exact',r
    if kind=='owner':
        if t['owner_sequence']>=p['next_sequence']:return 'consumed-owner-sequence',None
        old=next(r for r in t['grants'] if r['id']==p['grant_id'])
        if old['generation']!=p['generation']:return 'rotated-grant',None
        if old['commitment']!=p['old_commitment'] or p['context_root']!=worker.context_root(t):return 'stale-authority',None
        if p['height']<=w['height']:return 'elapsed-owner-height',None
        if p['height']<earliest:return 'committed-range-unknown',None
        return 'unknown',None
    slot=next(r for r in t['grants'] if r['id']==p[6])
    if slot['generation']!=integer(p[26]):return 'rotated-grant',None
    if slot['commitment']==ZERO:return 'revoked-grant',None
    for r in s['receipts']:
        if r['kind']!='payment':continue
        q=r['statement']
        if q[21]==p[21] or q[18]==p[18] or set(q[11:13])&set(p[11:13]) or set(q[22:24])&set(p[22:24]):return 'conflict',None
    if p[7]!=t['parent'] or p[8]!=slot['commitment'] or p[29]!=slot['agent_key'] or integer(p[25])!=t['owner_sequence'] or p[4]!=worker.context_root(t):return 'stale-authority',None
    if earliest>=integer(p[16]):return 'elapsed-payment-window',None
    if earliest<integer(p[15]):return 'not-yet-payment-window',None
    if earliest>64:return 'capacity-frontier',None
    return 'unknown',None

class CertifiedTreasuryJournal:
    """One canonical local journal; cloned/deleted history is not rollback protected."""
    def __init__(self,path,*,expected_genesis,worker):
        need(type(expected_genesis) is bytes,'P7 external genesis bytes required')
        self.raw_genesis=expected_genesis;self.g=genesis_document(expected_genesis,worker);self.worker=worker
        need(isinstance(worker,Worker) and worker.sha256==self.g['worker_sha256'] and worker.kat_sha256==self.g['kat_sha256'],'P7 journal worker pins differ')
        self.path=Path(path).absolute();_private(self.path);self.lock=threading.RLock();self.closed=False
        fd=os.open(self.path,os.O_CREAT|os.O_RDWR|os.O_NOFOLLOW,0o600)
        try:
            s=os.fstat(fd);need(stat.S_ISREG(s.st_mode) and s.st_uid==os.getuid() and stat.S_IMODE(s.st_mode)==0o600,'P7 journal opened file differs')
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
            need(not self.closed,'P7 journal closed')
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
        need(self.db.execute('SELECT id,format,genesis FROM identity').fetchall()==[(1,FORMAT,self.raw_genesis)],'P7 journal identity differs')
        obs=[]
        rows=self.db.execute('SELECT height,payload FROM observations ORDER BY height').fetchall()
        need(len(rows)<=MAX_OBSERVATIONS,'P7 observation capacity')
        for height,payload in rows:
            o=decode_canonical_json(bytes(payload),max_bytes=MAX_OBSERVATION_BYTES)
            need(type(o) is dict and set(o)=={'witness','signed_header'},'P7 retained observation shape')
            o,_=checked_observation(o['witness'],o['signed_header'],self.raw_genesis,self.worker)
            need(height==o['witness']['height'],'P7 retained observation height differs')
            if obs:_continuation(obs[-1],o)
            obs.append(o)
        obligations={}
        rows=self.db.execute('SELECT txid,raw,kind,context_root,owner_lane,nf,parent_old,grant_old,request,completed_at FROM obligations ORDER BY txid').fetchall()
        need(len(rows)<=MAX_OBLIGATIONS,'P7 obligation capacity')
        for ident,wire,kind,context,lane,nf,parent,grant,request,completed in rows:
            raw=bytes(wire);projection=self._checked(raw)
            need(txid(raw)==ident and (kind,context,lane,nf,parent,grant,request)==projection,'P7 retained typed wire/resource identity differs')
            first=next((o for o in obs if _resolve(raw,o,self.worker)[0]=='executed-exact'),None)
            need(completed==(first['witness']['height'] if first else None),'P7 saved completion differs from exact certified inclusion')
            obligations[ident]={'raw':raw,'kind':kind,'completed_at':completed,'attempts':0}
        for ident,rawsha in self.db.execute('SELECT txid,raw_sha256 FROM attempts'):
            need(ident in obligations and rawsha==digest(obligations[ident]['raw']),'P7 retained attempt identity differs')
            obligations[ident]['attempts']=1
        need(self.db.execute('PRAGMA foreign_key_check').fetchall()==[],'P7 journal foreign reference differs')
        return obs,obligations
    def _checked(self,raw):
        t=self.g['treasury']
        if type(raw) is bytes and raw[:8]==COMMAND_MAGIC:
            p=packet(raw)['body']
            need(p['profile_sha256']==self.g['profile_sha256'] and p['genesis_sha256']==digest(self.raw_genesis) and p['chain_id']==self.g['chain_id'] and p['owner_key']==t['owner_key'] and p['owner_epoch']==t['owner_epoch'] and p['grant_id'] in [r['id'] for r in t['grants']],'P7 retained owner command domain differs')
            v=packet(raw)
            try:Ed25519PublicKey.from_public_bytes(hexbytes(t['owner_key'],32)).verify(hexbytes(v['signature'],64),COMMAND_DOMAIN+canonical(p))
            except InvalidSignature:raise WalletError('P7 retained owner signature refused') from None
            lane=t['owner_key']+':'+str(t['owner_epoch'])+':'+str(p['next_sequence'])
            return ('owner',p['context_root'],lane,None,None,p['old_commitment'] if p['old_commitment']!=ZERO else None,None)
        p=parse(raw)
        need(all(p[i]==t[k] for i,k in [(1,'genesis'),(2,'asset'),(3,'mission'),(5,'parent_id')]) and p[6] in [r['id'] for r in t['grants']] and integer(p[14])==t['epoch'] and integer(p[17])==t['fee'] and integer(p[28])==t['owner_epoch'] and p[27]==self.worker.owner_key(t['owner_key']),'P7 retained payment domain differs')
        need(self.worker.verify(raw),'P7 retained invalid prepared proof')
        return ('payment',p[4],None,p[21],p[7],p[8],p[18])
    def _checkpoint(self,obs):
        if obs:return obs[-1]['witness']['state'],obs[-1]['witness']['height']+2
        return initial_state(self.g,self.worker),1
    def retain(self,raw):
        projection=self._checked(raw);ident=txid(raw)
        try:
            with self.atomic():
                obs,rows=self._audit();need(len(rows)<MAX_OBLIGATIONS,'P7 obligation capacity');need(ident not in rows,'P7 exact obligation already retained')
                state,earliest=self._checkpoint(obs)
                need(preflight(self.g,state,raw,earliest,self.worker)['code']==0,'P7 prepared transaction not valid at AS-OF context/future frontier')
                self.db.execute('INSERT INTO obligations VALUES (?,?,?,?,?,?,?,?,?,NULL)',(ident,raw,*projection))
            return ident
        except sqlite3.IntegrityError:raise WalletError('P7 context, sequence, input, authority or request is held by an existing obligation') from None
    def prepare(self,prover,public,witness):
        """Prove and retain under one write transaction; never claim or submit.

        Supplied openings are developer inputs, not encrypted custody or discovery.
        Certified AS-OF state and the existing full preflight remain authoritative.
        """
        from protocol7_prover import Prover,canonical_inputs
        p,w=canonical_inputs(public,witness)
        need(isinstance(prover,Prover) and prover.raw_genesis==self.raw_genesis
             and prover.worker is self.worker,'P7 prover/journal pins differ')
        try:
            with self.atomic():
                obs,rows=self._audit()
                need(len(rows)<MAX_OBLIGATIONS,'P7 obligation capacity')
                state,earliest=self._checkpoint(obs);t=state['treasury']
                need(all(p[i]==t[k] for i,k in [(1,'genesis'),(2,'asset'),(3,'mission'),(5,'parent_id'),(7,'parent')])
                     and integer(p[14])==t['epoch'] and integer(p[17])==t['fee']
                     and integer(p[25])==t['owner_sequence'] and integer(p[28])==t['owner_epoch']
                     and p[27]==self.worker.owner_key(t['owner_key']) and p[4]==self.worker.context_root(t),
                     'P7 proving current authority differs')
                need(any(g['id']==p[6] and g['generation']==integer(p[26])
                         and g['commitment']==p[8]!=ZERO and g['agent_key']==p[29] for g in t['grants']),
                     'P7 proving grant differs')
                need(p[20] in t['anchors'] and integer(p[15])<=earliest<integer(p[16]),
                     'P7 proving anchor/window differs')
                need(p[21] not in t['nullifiers'] and p[11]!=p[12]
                     and not any(v in t['authority_nullifiers'] for v in p[11:13])
                     and not any(v in t['notes'] for v in p[22:24])
                     and not any(r['kind']=='payment' and r['statement'][18]==p[18] for r in state['receipts']),
                     'P7 proving replay differs')
                # Refuse all live reservation conflicts before sending any witness to a child.
                resources=(('context_root',p[4]),('nf',p[21]),('parent_old',p[7]),
                           ('grant_old',p[8]),('request',p[18]))
                for column,value in resources:
                    need(not self.db.execute('SELECT 1 FROM obligations WHERE completed_at IS NULL AND '+column+'=?',(value,)).fetchone(),
                         'P7 proving resource already held')
                raw=prover.produce(p,w)
                need(tuple(parse(raw))==p,'P7 produced statement differs from requested payment')
                projection=self._checked(raw);ident=txid(raw)
                need(ident not in rows,'P7 exact obligation already retained')
                need(preflight(self.g,state,raw,earliest,self.worker)['code']==0,
                     'P7 produced transaction not valid at AS-OF context/future frontier')
                self.db.execute('INSERT INTO obligations VALUES (?,?,?,?,?,?,?,?,?,NULL)',(ident,raw,*projection))
            return ident
        except sqlite3.IntegrityError:
            raise WalletError('P7 proving resource conflicts with an existing obligation') from None
    def claim(self,ident):
        with self.atomic():
            obs,rows=self._audit();need(ident in rows,'P7 exact obligation missing');row=rows[ident]
            need(row['attempts']==0 and row['completed_at'] is None,'P7 one delivery attempt already claimed or completed')
            reason,_=_resolve(row['raw'],obs[-1] if obs else None,self.worker)
            need(reason=='unknown','P7 known conflict, stale authority or committed/elapsed frontier refuses delivery')
            state,earliest=self._checkpoint(obs)
            need(preflight(self.g,state,row['raw'],earliest,self.worker)['code']==0,'P7 first claim failed AS-OF context/frontier preflight')
            self.db.execute('INSERT INTO attempts VALUES (?,?)',(ident,digest(row['raw'])))
            return row['raw']
    def deliver_once(self,ident,transport):
        need(callable(transport),'P7 delivery transport required');raw=self.claim(ident)
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
                need(len(obs)<MAX_OBSERVATIONS,'P7 observation capacity')
                self.db.execute('INSERT INTO observations VALUES (?,?)',(h,canonical(o)))
            for ident,row in rows.items():
                reason,_=_resolve(row['raw'],o,self.worker)
                if reason=='executed-exact' and row['completed_at'] is None:self.db.execute('UPDATE obligations SET completed_at=? WHERE txid=?',(h,ident))
        return {'state_height':h,'app_hash':o['witness']['app_hash'],'idempotent':same,'certificate':cert}
    def _row(self,ident):
        obs,rows=self._audit();need(ident in rows,'P7 exact obligation missing');return obs,rows[ident]
    def status(self,ident):
        with self.atomic(False):
            obs,row=self._row(ident);reason,_=_resolve(row['raw'],obs[-1] if obs else None,self.worker)
            status='recorded-certified' if row['completed_at'] is not None else ('observed-held' if obs else ('attempted-held' if row['attempts'] else 'retained'))
            return {'txid':ident,'kind':row['kind'],'status':status,'attempts':row['attempts'],'hold_reason':None if status=='recorded-certified' else reason,'certified_height':obs[-1]['witness']['height'] if obs else None}
    def export(self,ident):
        with self.atomic(False):return self._row(ident)[1]['raw']
    def recorded_receipt(self,ident):
        with self.atomic(False):
            obs,row=self._row(ident);need(row['completed_at'] is not None,'P7 exact certified execution absent')
            o=next(o for o in obs if o['witness']['height']==row['completed_at']);reason,r=_resolve(row['raw'],o,self.worker)
            need(reason=='executed-exact','P7 exact recorded receipt absent')
            return {'format':'1soft/protocol7-exact-execution-record/v1','genesis':self.raw_genesis.hex(),'genesis_sha256':digest(self.raw_genesis),'profile_sha256':self.g['profile_sha256'],'worker_sha256':self.g['worker_sha256'],'kat_sha256':self.g['kat_sha256'],'bootstrap_sha256':bootstrap_digest(self.g),'kind':row['kind'],'txid':ident,'raw':row['raw'].hex(),'raw_sha256':digest(row['raw']),
                    'state_height':o['witness']['height'],'receipt':r,'witness':o['witness'],'signed_header':o['signed_header'],'certificate':verify_state(o['witness'],o['signed_header'],self.raw_genesis,self.worker)}
