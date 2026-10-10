"""Separately versioned encrypted P9 wallet with one stored history.

Full bounded signed native replay authenticates every retained observation.
Payment preparation, origins, proof verification, holds and exact results use
the frozen v1 implementation. No v1 migration or incremental proof claim.
"""
from __future__ import annotations
import copy, os, stat, threading
from pathlib import Path
from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
import protocol8_transfer as n
from protocol8_consensus import canonical, closed_json, hex32
from protocol9_consensus import bootstrap_digest, MAX_HEIGHT, genesis_document
from protocol9_notes import NoteController, statement
from protocol9_wallet import RecipientWallet as LegacyWallet
from protocol9_history_codec import pack, unpack, retain
FORMAT='1soft/protocol9-recipient-wallet/v2'
ENVELOPE='1soft/protocol9-recipient-wallet-envelope/v2'
AAD=b'1soft/protocol9-recipient-wallet/aad/v2\0'
MAX_PLAIN=16*1024**2
MAX_FILE=2*MAX_PLAIN+8192
MAX_NOTES=32
MAX_OBLIGATIONS=16
MAX_OBSERVATIONS=8
MAX_REVISIONS=256

class RecipientWallet(LegacyWallet):
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

    def _write(self,payload,initial=False):
        self._private();p=copy.deepcopy(payload)
        n.need(type(p['revision']) is int and p['revision']<=MAX_REVISIONS,'P9 revision capacity')
        for _ in range(8):
            nonce=os.urandom(12).hex()
            if nonce not in p['nonces']:break
        else:raise n.Unavailable('P9 nonce reuse refused')
        p['nonces'].append(nonce)
        p['history'],p['observations']=pack(p['observations'],self.g)
        plain=canonical(p);n.need(len(plain)<=MAX_PLAIN,'P9 private payload bound')
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
        n.need(type(p) is dict and set(p)=={'format','revision','nonces','history','observations','notes','obligations'} and p['format']==FORMAT and p['revision']==h['revision'],'P9 closed wallet payload')
        ns=p['nonces'];n.need(type(ns) is list and len(ns)==h['revision']+1 and len(set(ns))==len(ns) and ns[-1]==nonce,'P9 nonce history differs')
        for x in ns:n.need(type(x) is str and len(x)==24 and all(c in '0123456789abcdef' for c in x),'P9 nonce history shape')
        p['observations']=unpack(p.pop('history'),p['observations'])
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
            p['observations']=retain(p['observations'],p['obligations'],o);p['revision']+=1;self._write(p)
        return cert

    def inventory(self):
        with self._locked():
            p=self._read();return {'format':FORMAT,'wallet_id':self.wallet_id,'recipient_key':self.recipient_key,
                'revision':p['revision'],'as_of_height':p['observations'][-1]['witness']['height'] if p['observations'] else None,
                'notes':[r['commitment'] for r in p['notes']],
                'obligations':[{'input':x['input'],'request':x['request'],'txid':n.txid(bytes.fromhex(x['raw'])) if x['raw'] else None,
                    'attempts':x['attempts'],'completed':x['result'] is not None} for x in p['obligations']],
                'freshness_established':False,'automatic_retry':False}
