"""Bounded encrypted P7 CHANGE-note custody on one trusted POSIX host.

External AES key and vault ID are required on every open. The canonical certified
journal is the sole authority. No scan, key recovery, retry, or hostile-host claim.
"""
from __future__ import annotations
import contextlib,copy,fcntl,os,stat,threading
from pathlib import Path
from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from protocol7_treasury import (PROFILE,PROFILE_SHA256,FIELD_MODULUS,ZERO,MAX_U64,
    bootstrap_digest,canonical,closed_json,digest,field,hexbytes,integer,numfield,parse,txid)
from protocol7_wallet import checked_observation,_resolve
from protocol7_notes import NoteController

FORMAT='1soft/protocol7-change-vault/v1'
ENVELOPE='1soft/protocol7-change-vault-envelope/v1'
AAD=b'1soft/protocol7-change-vault/aad/v1\0'
MAX_PLAIN=2*1024*1024
MAX_FILE=MAX_PLAIN*2+8192
MAX_NOTES=16
MAX_PENDING=8
MAX_REVISIONS=MAX_NOTES+MAX_PENDING
ORIGIN_KEYS={'format','genesis','genesis_sha256','profile_sha256','worker_sha256','kat_sha256','bootstrap_sha256',
             'kind','txid','raw','raw_sha256','state_height','receipt','witness','signed_header','certificate'}

class VaultError(ValueError):pass
def need(condition,message):
    if not condition:raise VaultError(message)
def _random_field():
    for _ in range(128):
        raw=os.urandom(32);value=int.from_bytes(raw,'little')
        if 0<value<FIELD_MODULUS:return raw.hex()
    raise VaultError('P7 random field source refused')

class ChangeVault:
    """Encrypted immutable origins and staged openings; no independent spend state."""
    def __init__(self,path,*,key,expected_vault_id,controller,create=False):
        need(os.name=='posix','P7 vault requires trusted POSIX host')
        need(type(key) is bytes and len(key)==32 and any(key),'P7 external256-bit vault key required')
        hexbytes(expected_vault_id,32);need(expected_vault_id!=ZERO,'P7 opaque vault ID required')
        need(isinstance(controller,NoteController),'P7 actual note controller required')
        need(type(create) is bool,'P7 explicit vault creation required')
        self.path=Path(os.path.abspath(path));self.lock_path=Path(str(self.path)+'.lock')
        self.key=key;self.controller=controller;self.worker=controller.worker;self.g=controller.g
        self.raw_genesis=controller.raw_genesis;self.vault_id=expected_vault_id;self.thread_lock=threading.RLock()
        self.pins={'format':ENVELOPE,'vault_id':expected_vault_id,'genesis_sha256':digest(self.raw_genesis),
                   'bootstrap_sha256':bootstrap_digest(self.g),'profile_sha256':PROFILE_SHA256,
                   'parameter_sha256':PROFILE['parameter_sha256'],'verifying_key_sha256':PROFILE['verifying_key_sha256'],
                   'worker_sha256':self.worker.sha256,'kat_sha256':self.worker.kat_sha256,'controller_sha256':controller.sha256}
        self._private()
        with self._locked():
            if create:
                need(not self.path.exists(),'P7 vault already exists')
                self._write({'format':FORMAT,'revision':0,'nonce_history':[],'records':[],'pending':[]},initial=True)
            self._read()
    def _file(self,path,required=False):
        try:s=path.lstat()
        except FileNotFoundError:
            need(not required,'P7 vault missing');return
        need(stat.S_ISREG(s.st_mode) and s.st_uid==os.geteuid() and s.st_nlink==1 and stat.S_IMODE(s.st_mode)==0o600,
             'P7 private regular owner file required')
        need(s.st_size<=MAX_FILE,'P7 vault file bound')
    def _private(self):
        for p in (self.path.parent,*self.path.parent.parents):need(not p.is_symlink(),'P7 symlink parent refused')
        s=self.path.parent.lstat()
        need(stat.S_ISDIR(s.st_mode) and s.st_uid==os.geteuid() and stat.S_IMODE(s.st_mode)==0o700,
             'P7 private owner vault directory required')
        self._file(self.path);self._file(self.lock_path)
        for suffix in ('-wal','-shm','-journal'):
            p=Path(str(self.path)+suffix)
            need(not p.exists() and not p.is_symlink(),'P7 unexpected plaintext sidecar refused')
    @contextlib.contextmanager
    def _locked(self):
        with self.thread_lock:
            self._private();fd=os.open(self.lock_path,os.O_CREAT|os.O_RDWR|os.O_NOFOLLOW,0o600)
            try:
                s=os.fstat(fd);self._file(self.lock_path,True)
                need(s.st_uid==os.geteuid() and s.st_nlink==1 and stat.S_ISREG(s.st_mode) and stat.S_IMODE(s.st_mode)==0o600,
                     'P7 opened lock differs')
                need((s.st_dev,s.st_ino)==(self.lock_path.lstat().st_dev,self.lock_path.lstat().st_ino),'P7 lock replaced')
                fcntl.flock(fd,fcntl.LOCK_EX);self._private();yield
            finally:fcntl.flock(fd,fcntl.LOCK_UN);os.close(fd)
    def _read(self):
        self._private();self._file(self.path,True)
        fd=os.open(self.path,os.O_RDONLY|os.O_NOFOLLOW)
        try:
            s=os.fstat(fd)
            need(s.st_uid==os.geteuid() and s.st_nlink==1 and stat.S_ISREG(s.st_mode) and stat.S_IMODE(s.st_mode)==0o600,
                 'P7 opened vault differs')
            with os.fdopen(os.dup(fd),'rb') as f:raw=f.read(MAX_FILE+1)
        finally:os.close(fd)
        v=closed_json(raw,MAX_FILE)
        need(type(v) is dict and set(v)=={'header','ciphertext'},'P7 closed encrypted envelope required')
        h=v['header'];need(type(h) is dict and set(h)==set(self.pins)|{'revision','nonce'}
                          and all(h[k]==value for k,value in self.pins.items()),'P7 vault pins differ')
        need(type(h['revision']) is int and 0<=h['revision']<=MAX_REVISIONS,'P7 vault revision bound')
        nonce=hexbytes(h['nonce'],12);ct=v['ciphertext']
        need(type(ct) is str and len(ct)%2==0 and 32<=len(ct)<=2*(MAX_PLAIN+16),'P7 ciphertext bound')
        ciphertext=hexbytes(ct,len(ct)//2)
        try:plain=AESGCM(self.key).decrypt(nonce,ciphertext,AAD+canonical(h))
        except InvalidTag:raise VaultError('P7 encrypted vault authentication refused') from None
        payload=closed_json(plain,MAX_PLAIN)
        need(type(payload) is dict and set(payload)=={'format','revision','nonce_history','records','pending'}
             and payload['format']==FORMAT and payload['revision']==h['revision'],'P7 closed vault payload required')
        history=payload['nonce_history'];records=payload['records'];pending=payload['pending']
        need(type(history) is list and len(history)==h['revision']+1 and len(set(history))==len(history)
             and history[-1]==h['nonce'],'P7 nonce history differs')
        for n in history:hexbytes(n,12)
        need(type(records) is list and len(records)<=MAX_NOTES and type(pending) is list and len(pending)<=MAX_PENDING
             and len(records)+len(pending)==h['revision'],'P7 encrypted record capacity/revision')
        commitments=set()
        for record in records:
            need(type(record) is dict and set(record)=={'commitment','origin','opening','import_provenance'},'P7 change record shape')
            commitment=record['commitment'];field(commitment)
            need(commitment not in commitments,'P7 duplicate change note');commitments.add(commitment)
            p,o=self._origin(record['origin'])
            notes=o['witness']['state']['treasury']['notes']
            need(commitment==p[23] and commitment in notes,'P7 restricted CHANGE origin differs')
            self.controller.derive(p,record['opening'],notes,notes.index(commitment))
            provenance=record['import_provenance']
            need(type(provenance) is dict and set(provenance)=={'height','owner_sequence','context_root'}
                 and type(provenance['height']) is int and o['witness']['height']<=provenance['height']<=64
                 and type(provenance['owner_sequence']) is int and 0<=provenance['owner_sequence']<=MAX_U64,
                 'P7 import provenance differs')
            field(provenance['context_root'])
        inputs=set();requests=set()
        from protocol7_prover import canonical_inputs
        for item in pending:
            need(type(item) is dict and set(item)=={'input','origin_txid','origin_record_sha256','public','witness'},'P7 staged opening shape')
            p,w=canonical_inputs(item['public'],item['witness'])
            need(item['input'] in commitments and item['input'] not in inputs and p[18] not in requests,
                 'P7 duplicate/missing staged input/request')
            inputs.add(item['input']);requests.add(p[18])
            record=next(r for r in records if r['commitment']==item['input'])
            need(item['origin_txid']==record['origin']['txid']
                 and item['origin_record_sha256']==digest(canonical(record['origin'])),'P7 staged public origin binding differs')
            original=parse(bytes.fromhex(record['origin']['raw']));opening=record['opening']
            need(all(p[i]==original[i] for i in (1,2,3,5,6,14,26,28,29))
                 and w[11]==opening['agent_secret'] and integer(w[16])==opening['value']
                 and integer(w[17])==opening['expiry'] and w[18]==opening['note_secret'] and w[19]==opening['blind']
                 and integer(w[15])==record['origin']['witness']['state']['treasury']['notes'].index(item['input']),
                 'P7 staged input differs from imported restricted note')
            # Reconstruct and validate the relation without generating a second proof.
            partial=list(p)
            for i in (9,10,11,12,13,19,21,22,23,24):partial[i]=ZERO
            got=self.controller.construct(partial,w)
            need(got==(p,w),'P7 staged canonical request differs')
        return payload
    def _write(self,payload,initial=False):
        self._private();payload=copy.deepcopy(payload)
        for _ in range(8):
            nonce=os.urandom(12).hex()
            if nonce not in payload['nonce_history']:break
        else:raise VaultError('P7 nonce source reused')
        payload['nonce_history'].append(nonce)
        plain=canonical(payload);need(len(plain)<=MAX_PLAIN,'P7 encrypted payload byte bound')
        header={**self.pins,'revision':payload['revision'],'nonce':nonce}
        raw=canonical({'header':header,'ciphertext':AESGCM(self.key).encrypt(bytes.fromhex(nonce),plain,AAD+canonical(header)).hex()})
        need(len(raw)<=MAX_FILE,'P7 envelope byte bound')
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
            if stage.exists():
                stage.unlink()
                d=os.open(self.path.parent,os.O_RDONLY|os.O_DIRECTORY)
                try:os.fsync(d)
                finally:os.close(d)
    def _origin(self,r):
        need(type(r) is dict and set(r)==ORIGIN_KEYS and r['format']=='1soft/protocol7-exact-execution-record/v1'
             and r['kind']=='payment','P7 exact payment origin required')
        pins={'genesis':self.raw_genesis.hex(),'genesis_sha256':digest(self.raw_genesis),
              'bootstrap_sha256':bootstrap_digest(self.g),**{k:self.g[k] for k in ('profile_sha256','worker_sha256','kat_sha256')}}
        need(all(r[k]==v for k,v in pins.items()),'P7 origin pins differ')
        wire=hexbytes(r['raw'],4168);p=parse(wire)
        need(r['txid']==txid(wire) and r['raw_sha256']==digest(wire) and self.worker.verify(wire),'P7 origin wire differs')
        o,cert=checked_observation(r['witness'],r['signed_header'],self.raw_genesis,self.worker)
        reason,receipt=_resolve(wire,o,self.worker)
        need(reason=='executed-exact' and r['receipt']==receipt and r['certificate']==cert
             and r['state_height']==o['witness']['height'],'P7 origin execution differs')
        return p,o
    def _journal(self,journal):
        from protocol7_wallet import CertifiedTreasuryJournal
        need(isinstance(journal,CertifiedTreasuryJournal) and journal.raw_genesis==self.raw_genesis
             and journal.worker is self.worker,'P7 vault/journal pins differ')
    def _live(self,journal,record):
        self._journal(journal);obs,rows=journal._audit()
        need(bool(obs),'P7 authenticated current journal required')
        o=obs[-1];t=o['witness']['state']['treasury'];p=parse(bytes.fromhex(record['origin']['raw']))
        commitment=record['commitment'];earliest=o['witness']['height']+2
        need(any(r['txid']==record['origin']['txid'] and r['raw']==record['origin']['raw'] for r in o['witness']['state']['receipts']),
             'P7 current certified origin absent')
        need(t['owner_epoch']==integer(p[28]) and t['epoch']==integer(p[14])
             and any(g['id']==p[6] and g['generation']==integer(p[26]) and g['agent_key']==p[29] and g['commitment']!=ZERO for g in t['grants']),
             'P7 change generation/epoch/grant refused')
        need(commitment in t['notes'],'P7 change note absent')
        d=self.controller.derive(p,record['opening'],t['notes'],t['notes'].index(commitment))
        need(d['root'] in t['anchors'] and d['nullifier'] not in t['nullifiers'],'P7 change spent/anchor refused')
        need(earliest<=record['opening']['expiry'] and earliest<=64,'P7 change expired/frontier refused')
        need(not any(row['kind']=='payment' and row['completed_at'] is None and parse(row['raw'])[21]==d['nullifier'] for row in rows.values()),
             'P7 change input already journal-held')
        return p,t,earliest,d,o
    def import_change(self,journal,ident,opening):
        self._journal(journal);origin=journal.recorded_receipt(ident);p,_=self._origin(origin)
        record={'commitment':p[23],'origin':origin,'opening':copy.deepcopy(opening),'import_provenance':{}}
        with self._locked():
            payload=self._read();need(len(payload['records'])<MAX_NOTES,'P7 change capacity')
            need(not any(r['commitment']==p[23] for r in payload['records']),'P7 change already imported')
            with journal.atomic(False):
                _,t,_,_,o=self._live(journal,record)
                record['import_provenance']={'height':o['witness']['height'],'owner_sequence':t['owner_sequence'],
                                              'context_root':self.worker.context_root(t)}
            payload['records'].append(record);payload['revision']+=1;self._write(payload)
        return p[23]
    def _record(self,payload,commitment):
        field(commitment);record=next((r for r in payload['records'] if r['commitment']==commitment),None)
        need(record is not None,'P7 imported change missing');return record
    def prepare_payment(self,journal,prover,commitment,*,authority,amount,valid_until,request):
        self._journal(journal)
        from protocol7_prover import Prover
        need(isinstance(prover,Prover) and prover.raw_genesis==self.raw_genesis and prover.worker is self.worker,
             'P7 vault/prover pins differ')
        need(type(authority) is dict and set(authority)=={'parent','grant'} and type(authority['parent']) in (list,tuple)
             and len(authority['parent'])==4 and type(authority['grant']) in (list,tuple) and len(authority['grant'])==6,
             'P7 closed current authority openings required')
        need(type(amount) is int and 0<amount<=MAX_U64 and type(valid_until) is int,'P7 payment integers')
        field(request);need(request!=ZERO,'P7 explicit nonzero payment request required')
        with self._locked():
            payload=self._read();record=self._record(payload,commitment)
            need(len(payload['pending'])<MAX_PENDING and not any(x['input']==commitment or x['public'][18]==request for x in payload['pending']),
                 'P7 input/request already staged; reconcile original')
            with journal.atomic(False):
                old,t,earliest,d,_=self._live(journal,record)
                slot=next(g for g in t['grants'] if g['id']==old[6]);p=[ZERO]*30
                for i,key in ((1,'genesis'),(2,'asset'),(3,'mission'),(5,'parent_id'),(7,'parent')):p[i]=t[key]
                p[0]=numfield(2);p[4]=self.worker.context_root(t);p[6]=slot['id'];p[8]=slot['commitment'];p[14]=numfield(t['epoch'])
                p[15]=numfield(earliest);p[16]=numfield(valid_until);p[17]=numfield(t['fee']);p[18]=request;p[20]=d['root']
                p[25]=numfield(t['owner_sequence']);p[26]=numfield(slot['generation']);p[27]=self.worker.owner_key(t['owner_key'])
                p[28]=numfield(t['owner_epoch']);p[29]=slot['agent_key']
                for column,value in (('context_root',p[4]),('parent_old',p[7]),('grant_old',p[8]),('request',request),('nf',d['nullifier'])):
                    need(not journal.db.execute('SELECT 1 FROM obligations WHERE completed_at IS NULL AND '+column+'=?',(value,)).fetchone(),
                         'P7 existing journal reservation refuses staging')
                opening=record['opening'];change=opening['value']-amount-t['fee']
                need(change>0 and earliest<valid_until<=opening['expiry'],'P7 change conservation/window')
                w=[ZERO]*31;w[0:4]=authority['parent'];w[4]=_random_field()
                w[5:9]=authority['grant'][:4];w[9]=_random_field();w[10]=authority['grant'][4]
                w[11]=opening['agent_secret'];w[12]=authority['grant'][5];w[13]=numfield(amount);w[14]=_random_field()
                w[15]=numfield(t['notes'].index(commitment));w[16]=numfield(opening['value']);w[17]=numfield(opening['expiry'])
                w[18]=opening['note_secret'];w[19]=opening['blind'];w[20:24]=d['path'];w[24]=numfield(change);w[25]=d['agent_key']
                w[26]=numfield(opening['expiry']);w[27]=_random_field();w[28]=_random_field();w[29]=numfield(opening['expiry']);w[30]=_random_field()
                public,witness=self.controller.construct(p,w)
            payload['pending'].append({'input':commitment,'origin_txid':record['origin']['txid'],
                                       'origin_record_sha256':digest(canonical(record['origin'])),
                                       'public':list(public),'witness':list(witness)})
            payload['revision']+=1;self._write(payload)
        # Durable encrypted output openings precede journal proving/commit. On
        # any unknown result recover the exact journal wire; do not regenerate.
        return journal.prepare(prover,public,witness)
    def recover_prepared(self,journal,commitment):
        self._journal(journal)
        with self._locked():
            payload=self._read();item=next((x for x in payload['pending'] if x['input']==commitment),None)
            need(item is not None,'P7 staged request absent')
        with journal.atomic(False):
            _,rows=journal._audit()
            matches=[ident for ident,row in rows.items() if row['kind']=='payment' and parse(row['raw'])==item['public']]
            need(len(matches)==1,'P7 exact staged journal wire absent or ambiguous')
            return matches[0]
    def import_prepared_change(self,journal,ident):
        self._journal(journal);wire=journal.export(ident);public=parse(wire)
        with self._locked():
            payload=self._read();item=next((x for x in payload['pending'] if x['public']==public),None)
            need(item is not None,'P7 encrypted prepared opening absent');w=item['witness']
            opening={'agent_secret':w[11],'value':integer(w[24]),'expiry':integer(w[26]),'note_secret':w[27],'blind':w[28]}
        return self.import_change(journal,ident,opening)
    def inventory(self):
        with self._locked():
            p=self._read()
            return {'vault_id':self.vault_id,'revision':p['revision'],
                    'notes':[r['commitment'] for r in p['records']],
                    'retained_preparations':[x['public'][18] for x in p['pending']]}
