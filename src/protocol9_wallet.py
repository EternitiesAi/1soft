"""Bounded encrypted P9 recipient wallet on one trusted POSIX host.

One authenticated blob holds private openings, signed AS-OF observations and
original payment obligations. No network dispatcher, retry, discovery or key
recovery. Local rollback and a hostile host remain outside this qualification.
"""
from __future__ import annotations
import contextlib, copy, fcntl, hmac, os, stat, threading
from pathlib import Path
from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
import protocol8_transfer as n
from protocol9_certificate import verify_history, MAX_BLOCKS, MAX_ATTEMPTS
from protocol8_consensus import canonical, closed_json, hex32
from protocol9_consensus import bootstrap_digest, MAX_HEIGHT, genesis_document
from protocol8_notes import opening, num
from protocol9_notes import NoteController, statement, Prover

FORMAT='1soft/protocol9-recipient-wallet/v1'
ENVELOPE='1soft/protocol9-recipient-wallet-envelope/v1'
AAD=b'1soft/protocol9-recipient-wallet/aad/v1\0'
MAX_PLAIN=16*1024**2
MAX_FILE=2*MAX_PLAIN+8192
MAX_NOTES=32
MAX_OBLIGATIONS=16
MAX_OBSERVATIONS=8
MAX_REVISIONS=256
REVIEW_FORMAT='1soft/protocol9-private-intent-review/v2'
REVIEW_SCHEME='sha256-private-review-v2-with-keyed-blind'
REVIEW_KEY_DOMAIN=b'1soft/protocol9-private-intent-review/key/v2\0'

def review_blind(key,*,wallet_id,genesis_sha256,txid,wire_sha256):
    """Private deterministic blind; never disclose it with the public file hash."""
    n.need(type(key) is bytes and len(key)==32 and any(key),'P9 review key required')
    context={'format':'1soft/protocol9-private-intent-review/blind/v2','wallet_id':wallet_id,
        'genesis_sha256':genesis_sha256,'txid':txid,'wire_sha256':wire_sha256}
    for value in (wallet_id,genesis_sha256,txid,wire_sha256):hex32(value)
    derived=hmac.digest(key,REVIEW_KEY_DOMAIN,'sha256')
    return hmac.digest(derived,canonical(context),'sha256').hex()

def random_field():
    for _ in range(128):
        raw=os.urandom(32)
        if 0<int.from_bytes(raw,'little')<n.MODULUS:return raw.hex()
    raise n.Unavailable('P9 random field source refused')

class RecipientWallet:
    def __init__(self,path,*,key,wallet_id,recipient_secret,controller,create=False):
        n.need(os.name=='posix' and type(create) is bool,'P9 explicit POSIX wallet creation')
        n.need(type(key) is bytes and len(key)==32 and any(key),'P9 external AES256 key required')
        hex32(wallet_id);n.need(wallet_id!=n.ZERO,'P9 opaque wallet ID required')
        n.need(isinstance(controller,NoteController),'P9 actual private controller required')
        self.path=Path(os.path.abspath(path));self.lock_path=Path(str(self.path)+'.lock')
        self.key=key;self.secret=recipient_secret;self.controller=controller;self.worker=controller.worker
        self.g=genesis_document(canonical(controller.g),self.worker);self.raw_genesis=canonical(self.g);self.wallet_id=wallet_id
        self._verified_views={}
        self.recipient_key=controller.key(recipient_secret);self.thread_lock=threading.RLock()
        self.pins={'format':ENVELOPE,'wallet_id':wallet_id,'recipient_key':self.recipient_key,
            'genesis_sha256':n.sha(self.raw_genesis),'bootstrap_sha256':bootstrap_digest(self.g),
            'profile_sha256':n.PROFILE_SHA256,'parameter_sha256':n.PROFILE['parameter_sha256'],
            'verifying_key_sha256':n.PROFILE['verifying_key_sha256'],'worker_sha256':self.worker.sha256,
            'kat_sha256':self.worker.kat_sha256,'controller_sha256':controller.sha256}
        self._private()
        with self._locked():
            if create:
                n.need(not self.path.exists(),'P9 wallet already exists')
                self._write({'format':FORMAT,'revision':0,'nonces':[],'observations':[], 'notes':[],'obligations':[]},initial=True)
            self._read()
    def _file(self,path,required=False):
        try:s=path.lstat()
        except FileNotFoundError:n.need(not required,'P9 wallet file missing');return
        n.need(stat.S_ISREG(s.st_mode) and s.st_uid==os.geteuid() and s.st_nlink==1 and
               stat.S_IMODE(s.st_mode)==0o600 and s.st_size<=MAX_FILE,'P9 private owner regular file required')
    def _private(self):
        for p in (self.path.parent,*self.path.parent.parents):n.need(not p.is_symlink(),'P9 symlink parent refused')
        s=self.path.parent.lstat()
        n.need(stat.S_ISDIR(s.st_mode) and s.st_uid==os.geteuid() and stat.S_IMODE(s.st_mode)==0o700,'P9 private owner directory required')
        self._file(self.path);self._file(self.lock_path)
        for suffix in ('-wal','-shm','-journal'):
            p=Path(str(self.path)+suffix);n.need(not p.exists() and not p.is_symlink(),'P9 plaintext sidecar refused')
    @contextlib.contextmanager
    def _locked(self):
        with self.thread_lock:
            self._private();fd=os.open(self.lock_path,os.O_CREAT|os.O_RDWR|os.O_NOFOLLOW,0o600)
            try:
                self._file(self.lock_path,True);s=os.fstat(fd);live=self.lock_path.lstat()
                n.need((s.st_dev,s.st_ino)==(live.st_dev,live.st_ino) and stat.S_ISREG(s.st_mode) and s.st_nlink==1 and
                       s.st_uid==os.geteuid() and stat.S_IMODE(s.st_mode)==0o600,'P9 opened lock differs')
                fcntl.flock(fd,fcntl.LOCK_EX);self._private();yield
            finally:fcntl.flock(fd,fcntl.LOCK_UN);os.close(fd)
    def _write(self,payload,initial=False):
        self._private();p=copy.deepcopy(payload)
        n.need(type(p['revision']) is int and p['revision']<=MAX_REVISIONS,'P9 revision capacity')
        for _ in range(8):
            nonce=os.urandom(12).hex()
            if nonce not in p['nonces']:break
        else:raise n.Unavailable('P9 nonce reuse refused')
        p['nonces'].append(nonce);plain=canonical(p);n.need(len(plain)<=MAX_PLAIN,'P9 private payload bound')
        h={**self.pins,'revision':p['revision'],'nonce':nonce}
        raw=canonical({'header':h,'ciphertext':AESGCM(self.key).encrypt(bytes.fromhex(nonce),plain,AAD+canonical(h)).hex()})
        n.need(len(raw)<=MAX_FILE,'P9 encrypted envelope bound')
        stage=self.path.with_name('.'+self.path.name+'.stage-'+os.urandom(16).hex());fd=None
        try:
            fd=os.open(stage,os.O_CREAT|os.O_EXCL|os.O_WRONLY|os.O_NOFOLLOW,0o600)
            with os.fdopen(fd,'wb') as f:fd=None;f.write(raw);f.flush();os.fsync(f.fileno())
            self._file(stage,True)
            if initial:os.link(stage,self.path)
            else:self._file(self.path,True);os.replace(stage,self.path)
            d=os.open(self.path.parent,os.O_RDONLY|os.O_DIRECTORY)
            try:os.fsync(d)
            finally:os.close(d)
        finally:
            if fd is not None:os.close(fd)
            if stage.exists():stage.unlink()
    def _view(self,witness,signed):
        ident=n.sha(canonical({'witness':witness,'signed_header':signed}))
        if ident not in self._verified_views:
            verified=verify_history(witness,signed,self.raw_genesis,self.worker)
            if len(self._verified_views)>=MAX_OBSERVATIONS+1:self._verified_views.clear()
            self._verified_views[ident]=verified
        return self._verified_views[ident]
    def _cert(self,witness,signed):return copy.deepcopy(self._view(witness,signed)[0])
    def _ledger(self,obs):return copy.deepcopy(self._view(obs['witness'],obs['signed_header'])[1])
    def _segment(self,ledger,commitment):
        found=[r for r in ledger['notes'] if r['commitment']==commitment]
        n.need(len(found)==1,'P9 authenticated input absent')
        segment=found[0]['segment'];rows=[r for r in ledger['notes'] if r['segment']==segment]
        n.need(1<=len(rows)<=16 and [r['position'] for r in rows]==list(range(len(rows))),'P9 authenticated segment differs')
        return [r['commitment'] for r in rows]
    def _extend(self,previous,current):
        old,new=previous['witness'],current['witness']
        n.need(new['height']>old['height'] and new['blocks'][:len(old['blocks'])]==old['blocks'],
               'P9 observation rollback or divergent history refused')
    def _receipt(self,obs,raw):
        ident=n.txid(raw);rows=[r for r in self._ledger(obs)['receipts'] if r['txid']==ident]
        n.need(len(rows)==1 and rows[0]['raw']==raw.hex() and rows[0]['statement']==n.parse(raw),'P9 exact certified execution required')
        return rows[0]
    def _origin(self,record,obs):
        n.need(type(record) is dict and set(record)=={'commitment','opening','origin'},'P9 closed note record')
        opening(record['opening']);n.field(record['commitment'])
        o=record['origin'];n.need(type(o) is dict and set(o)=={'kind','raw','txid','height','output'},'P9 closed note origin')
        if o['kind']=='genesis':
            n.need(o=={'kind':'genesis','raw':None,'txid':None,'height':0,'output':None} and
                   record['commitment'] in [r['commitment'] for r in self.g['notes']],'P9 genesis note pin differs')
        else:
            n.need(o['kind']=='payment' and o['output'] in (10,11) and type(o['output']) is int,'P9 exact typed output required')
            n.need(type(o['raw']) is str and len(o['raw'])==7120 and all(c in '0123456789abcdef' for c in o['raw']), 'P9 origin wire shape')
            hex32(o['txid']);n.need(type(o['height']) is int and 1<=o['height']<=MAX_HEIGHT,'P9 origin height')
            raw=bytes.fromhex(o['raw']);r=self._receipt(obs,raw)
            n.need(o['txid']==r['txid'] and o['height']==r['height'] and record['commitment']==r['statement'][o['output']],
                   'P9 certified output origin differs')
        notes=self._segment(self._ledger(obs),record['commitment'])
        d=self.controller.inspect(record['opening'],self.secret,notes)
        n.need(d['commitment']==record['commitment'] and d['recipient_key']==self.recipient_key,'P9 received opening differs')
        return d
    def _read(self):
        self._private();self._file(self.path,True);fd=os.open(self.path,os.O_RDONLY|os.O_NOFOLLOW)
        try:
            s=os.fstat(fd);n.need(stat.S_ISREG(s.st_mode) and s.st_uid==os.geteuid() and s.st_nlink==1 and stat.S_IMODE(s.st_mode)==0o600,'P9 opened wallet differs')
            with os.fdopen(os.dup(fd),'rb') as f:raw=f.read(MAX_FILE+1)
        finally:os.close(fd)
        v=closed_json(raw,MAX_FILE);n.need(type(v) is dict and set(v)=={'header','ciphertext'},'P9 closed encrypted envelope')
        h=v['header'];n.need(type(h) is dict and set(h)==set(self.pins)|{'revision','nonce'} and all(h[k]==x for k,x in self.pins.items()),'P9 encrypted wallet pins differ')
        n.need(type(h['revision']) is int and 0<=h['revision']<=MAX_REVISIONS,'P9 revision bound')
        nonce=h['nonce'];ct=v['ciphertext']
        n.need(type(nonce) is str and len(nonce)==24 and all(c in '0123456789abcdef' for c in nonce),'P9 nonce shape')
        n.need(type(ct) is str and len(ct)%2==0 and 32<=len(ct)<=2*(MAX_PLAIN+16) and all(c in '0123456789abcdef' for c in ct),'P9 ciphertext shape')
        try:plain=AESGCM(self.key).decrypt(bytes.fromhex(nonce),bytes.fromhex(ct),AAD+canonical(h))
        except InvalidTag:raise n.Invalid('P9 encrypted wallet authentication refused') from None
        p=closed_json(plain,MAX_PLAIN)
        n.need(type(p) is dict and set(p)=={'format','revision','nonces','observations','notes','obligations'} and p['format']==FORMAT and p['revision']==h['revision'],'P9 closed wallet payload')
        ns=p['nonces'];n.need(type(ns) is list and len(ns)==h['revision']+1 and len(set(ns))==len(ns) and ns[-1]==nonce,'P9 nonce history differs')
        for x in ns:n.need(type(x) is str and len(x)==24 and all(c in '0123456789abcdef' for c in x),'P9 nonce history shape')
        obs=p['observations'];records=p['notes'];obligations=p['obligations']
        n.need(type(obs) is list and len(obs)<=MAX_OBSERVATIONS and type(records) is list and len(records)<=MAX_NOTES and
               type(obligations) is list and len(obligations)<=MAX_OBLIGATIONS,'P9 finite wallet capacity')
        for i,o in enumerate(obs):
            n.need(type(o) is dict and set(o)=={'witness','signed_header','certificate'},'P9 closed observation')
            n.need(o['certificate']==self._cert(o['witness'],o['signed_header']),'P9 retained certificate differs')
            if i:self._extend(obs[i-1],o)
        n.need(bool(obs) or (not records and not obligations),'P9 authenticated observation required')
        commitments=[]
        for r in records:self._origin(r,obs[-1]);commitments.append(r['commitment'])
        n.need(len(set(commitments))==len(commitments),'P9 duplicate imported note')
        inputs=set();requests=set()
        for item in obligations:
            n.need(type(item) is dict and set(item)=={'input','request','observation','private_request','successor_origin','raw','attempts','result'},'P9 closed obligation')
            n.need(item['input'] in commitments and item['input'] not in inputs and item['request'] not in requests,'P9 duplicate held input/intent')
            inputs.add(item['input']);requests.add(item['request'])
            n.need(type(item['observation']) is int and 0<=item['observation']<len(obs),'P9 preparation observation')
            n.need(type(item['private_request']) is str and len(item['private_request'])==2320 and
                   all(c in '0123456789abcdef' for c in item['private_request']),'P9 retained request bound')
            req=bytes.fromhex(item['private_request']);public,w=statement(req,self.g)
            r=next(r for r in records if r['commitment']==item['input']);o=obs[item['observation']]
            d=self._origin(r,o);t=self._ledger(o)
            n.need(public[5] not in t['nullifiers'] and public[6] not in t['requests'] and public[6]==item['request'] and
                   n.integer(public[7])==o['witness']['height']+2 and n.integer(public[9])==self.g['fee'],'P9 retained preparation authority differs')
            rebuilt,origin=self.controller.construct(r['opening'],self.secret,self._segment(t,r['commitment']),
                request=public[6],valid_from=n.integer(public[7]),valid_until=n.integer(public[8]),
                destination=w[11],payment=n.integer(w[12]),payment_expiry=n.integer(w[13]),payment_secret=w[14],
                payment_blind=w[15],change_secret=w[17],change_blind=w[18])
            n.need(rebuilt==req and origin==item['successor_origin'] and public[5]==d['nullifier'],'P9 retained private request differs')
            n.need(type(item['attempts']) is int and item['attempts'] in (0,1),'P9 attempt bound')
            if item['raw'] is None:n.need(item['attempts']==0 and item['result'] is None,'P9 unproven obligation state')
            else:
                n.need(type(item['raw']) is str and len(item['raw'])==7120 and all(c in '0123456789abcdef' for c in item['raw']),'P9 retained wire bound')
                wire=bytes.fromhex(item['raw']);n.need(n.parse(wire)==public and self.worker.verify(wire,self.g['network']),'P9 retained proof differs')
                if item['result'] is not None:
                    result=item['result']
                    n.need(type(result) is dict and set(result)=={'status','txid','raw_sha256','receipt','observation','state_height','app_hash','genesis_sha256','claim'} and
                           type(result['observation']) is int and item['observation']<=result['observation']<len(obs),'P9 closed completion/index')
                    n.need(result==self._result(wire,obs[result['observation']],result['observation']), 'P9 retained completion differs')
        return p
    def observe(self,witness,signed_header):
        cert=self._cert(witness,signed_header);o={'witness':copy.deepcopy(witness),'signed_header':copy.deepcopy(signed_header),'certificate':cert}
        with self._locked():
            p=self._read()
            if p['observations']:
                last=p['observations'][-1]
                if witness['height']==last['witness']['height']:
                    n.need(canonical(witness)==canonical(last['witness']),'P9 same-height observation conflict')
                    return copy.deepcopy(last['certificate'])
                self._extend(last,o)
            n.need(len(p['observations'])<MAX_OBSERVATIONS,'P9 observation capacity')
            p['observations'].append(o);p['revision']+=1;self._write(p)
        return cert
    def import_note(self,commitment,o,*,raw=None,output=10,genesis=False):
        n.field(commitment);opening(o);n.need(type(genesis) is bool,'P9 explicit genesis import')
        with self._locked():
            p=self._read();n.need(bool(p['observations']),'P9 signed observation required before import')
            obs=p['observations'][-1];notes=self._segment(self._ledger(obs),commitment)
            d=self.controller.inspect(o,self.secret,notes)
            if genesis:
                n.need(raw is None and output==10,'P9 explicit genesis source')
                origin={'kind':'genesis','raw':None,'txid':None,'height':0,'output':None}
            else:
                n.need(type(raw) is bytes and type(output) is int and output in (10,11),'P9 exact received output')
                r=self._receipt(obs,raw);origin={'kind':'payment','raw':raw.hex(),'txid':r['txid'],'height':r['height'],'output':output}
            record={'commitment':d['commitment'],'opening':copy.deepcopy(o),'origin':origin};self._origin(record,obs)
            existing=next((r for r in p['notes'] if r['commitment']==d['commitment']),None)
            if existing is not None:
                n.need(existing==record,'P9 immutable import conflict');return d['commitment']
            n.need(len(p['notes'])<MAX_NOTES,'P9 note capacity');p['notes'].append(record);p['revision']+=1;self._write(p)
            return d['commitment']
    def prepare(self,prover,commitment,*,request,destination,payment,valid_until,payment_expiry):
        n.need(isinstance(prover,Prover) and prover.worker is self.worker and prover.g==self.g,'P9 actual pinned prover required')
        n.field(commitment);n.field(request);n.field(destination)
        n.need(request!=n.ZERO and destination!=n.ZERO,'P9 explicit nonzero intent/destination')
        for v in (payment,valid_until,payment_expiry):n.u64(v)
        with self._locked():
            p=self._read();n.need(bool(p['observations']),'P9 signed preparation observation required')
            r=next((r for r in p['notes'] if r['commitment']==commitment),None);n.need(r is not None,'P9 imported input required')
            n.need(len(p['obligations'])<MAX_OBLIGATIONS and not any(x['input']==commitment or x['request']==request for x in p['obligations']),
                   'P9 original input/intent held; reconcile original')
            obs=p['observations'][-1];d=self._origin(r,obs);t=self._ledger(obs);earliest=obs['witness']['height']+2
            n.need(d['nullifier'] not in t['nullifiers'] and request not in t['requests'] and d['root'] in t['anchors'],'P9 AS-OF note spent/intent/root refused')
            n.need(0<payment and payment+self.g['fee']<r['opening']['value'] and earliest<valid_until<=payment_expiry<=r['opening']['expiry'] and
                   valid_until<=MAX_HEIGHT and earliest<MAX_BLOCKS and obs['witness']['checkpoint']['attempt_count']<MAX_ATTEMPTS,'P9 finite conservation/window/capacity')
            req,origin=self.controller.construct(r['opening'],self.secret,self._segment(t,r['commitment']),
                request=request,valid_from=earliest,valid_until=valid_until,destination=destination,
                payment=payment,payment_expiry=payment_expiry,payment_secret=random_field(),payment_blind=random_field(),
                change_secret=random_field(),change_blind=random_field())
            item={'input':commitment,'request':request,'observation':len(p['observations'])-1,'private_request':req.hex(),
                  'successor_origin':origin,'raw':None,'attempts':0,'result':None}
            p['obligations'].append(item);p['revision']+=1;self._write(p)
        # Persist the hold before native proving. Failure/unknown never regenerates.
        wire=prover.produce(req)
        with self._locked():
            p=self._read();held=next(x for x in p['obligations'] if x['request']==request)
            n.need(held==item,'P9 original obligation changed while proving')
            held['raw']=wire.hex();p['revision']+=1;self._write(p)
        return n.txid(wire)
    def _find(self,p,ident):
        hex32(ident);row=next((x for x in p['obligations'] if x['raw'] is not None and n.txid(bytes.fromhex(x['raw']))==ident),None)
        n.need(row is not None,'P9 original retained wire absent');return row
    def export(self,ident):
        with self._locked():return bytes.fromhex(self._find(self._read(),ident)['raw'])
    def review_intent(self,ident):
        """Explicit minimal private operator view; no keys, openings or dispatch."""
        with self._locked():
            payload=self._read();row=self._find(payload,ident)
            raw=bytes.fromhex(row['raw']);public,witness=statement(bytes.fromhex(row['private_request']),self.g)
            n.need(public==n.parse(raw) and n.txid(raw)==ident,'P9 review original wire differs')
            return {'format':REVIEW_FORMAT,'wallet_id':self.wallet_id,
                'private_review_blind':review_blind(self.key,wallet_id=self.wallet_id,
                    genesis_sha256=self.pins['genesis_sha256'],txid=ident,wire_sha256=n.sha(raw)),
                'txid':ident,'wire_sha256':n.sha(raw),'wire_bytes':len(raw),
                'destination':witness[11],'payment':n.integer(witness[12]),
                'payment_expiry':n.integer(witness[13]),'fee':n.integer(public[9]),
                'valid_from':n.integer(public[7]),'valid_until':n.integer(public[8]),
                'attempts':row['attempts'],'completed':row['result'] is not None,
                'as_of_height':payload['observations'][-1]['witness']['height'],
                'wallet_genesis_sha256':self.pins['genesis_sha256']}
    def mark_attempt(self,ident):
        """One local caller attempt marker; never a retry authorization or dispatch."""
        with self._locked():
            p=self._read();row=self._find(p,ident)
            n.need(row['attempts']==0 and row['result'] is None,'P9 original attempt already held')
            row['attempts']=1;p['revision']+=1;self._write(p)
    def _result(self,wire,obs,index):
        receipt=self._receipt(obs,wire)
        return {'status':'executed-exact','txid':n.txid(wire),'raw_sha256':n.sha(wire),'receipt':copy.deepcopy(receipt),
                'observation':index,'state_height':obs['witness']['height'],'app_hash':obs['witness']['app_hash'],
                'genesis_sha256':self.pins['genesis_sha256'],'claim':'AS-OF exact certified execution; no freshness or retry authority'}
    def reconcile(self,ident):
        with self._locked():
            p=self._read();row=self._find(p,ident)
            if row['result'] is not None:return copy.deepcopy(row['result'])
            obs=p['observations'][-1];wire=bytes.fromhex(row['raw']);public=n.parse(wire);t=self._ledger(obs)
            if any(r['txid']==ident for r in t['receipts']):
                row['result']=self._result(wire,obs,len(p['observations'])-1);p['revision']+=1;self._write(p);return copy.deepcopy(row['result'])
            return {'status':'conflict-held' if public[5] in t['nullifiers'] or public[6] in t['requests'] else 'unresolved-held',
                    'txid':ident,'attempts':row['attempts'],'as_of_height':obs['witness']['height'],'automatic_retry':False,'freshness_established':False}
    def output_opening(self,ident,output=10):
        """Explicit private disclosure for recipient delivery; never log this result."""
        n.need(type(output) is int and output in (10,11),'P9 selected output')
        with self._locked():
            p=self._read();row=self._find(p,ident);n.need(row['result'] is not None,'P9 certified execution required for private delivery')
            _,w=statement(bytes.fromhex(row['private_request']),self.g)
            return {'origin':row['successor_origin'],'value':n.integer(w[12 if output==10 else 16]),
                    'expiry':n.integer(w[13 if output==10 else 3]),'note_secret':w[14 if output==10 else 17],
                    'blind':w[15 if output==10 else 18]}
    def inventory(self):
        with self._locked():
            p=self._read();return {'format':FORMAT,'wallet_id':self.wallet_id,'recipient_key':self.recipient_key,
                'revision':p['revision'],'as_of_height':p['observations'][-1]['witness']['height'] if p['observations'] else None,
                'notes':[r['commitment'] for r in p['notes']],
                'obligations':[{'input':x['input'],'request':x['request'],'txid':n.txid(bytes.fromhex(x['raw'])) if x['raw'] else None,
                    'attempts':x['attempts'],'completed':x['result'] is not None} for x in p['obligations']],
                'freshness_established':False,'automatic_retry':False}
