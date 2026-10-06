"""Finite local P7 quotes, explicit encrypted disclosures and durable fulfillment.

One trusted POSIX host with an external AES key. No HTTP routing, wallet dispatch,
merchant-note redemption, latest-state assertion or external delivery side effect.
"""
from __future__ import annotations
import contextlib,copy,os,re,sqlite3,stat,threading
from pathlib import Path
from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from protocol7_treasury import (canonical,closed_json,digest,hexbytes,field,integer,
    number,ZERO,parse,txid,bootstrap_digest,genesis_document,PROFILE)
from protocol7_wallet import checked_observation,_resolve
from protocol7_notes import NoteController

FORMAT='1soft/protocol7-merchant-book/v1'
QUOTE='1soft/protocol7-merchant-quote/v1'
RESULT='1soft/protocol7-local-fulfillment/v1'
QUOTE_DOMAIN=b'1soft/P7-merchant-quote/v1\0'
DISCLOSURE_DOMAIN=b'1soft/protocol7-merchant-disclosure/v1\0'
KEY_CHECK=b'1soft/P7-merchant-key-check/v1'
MAX_QUOTES=8
MAX_RESOURCE=8192
MAX_ORIGIN=1048576
QUOTE_KEYS={'format','book_id','merchant_namespace','recipient','amount','payment_expiry',
    'chain_id','genesis_sha256','profile_sha256','asset','mission','grant_id',
    'generation','owner_epoch','valid_from','valid_until','resource','resource_sha256','nonce'}
SCHEMA={
 'identity':'CREATE TABLE identity (id INTEGER PRIMARY KEY CHECK(id=1), pins BLOB NOT NULL, key_nonce BLOB NOT NULL, key_check BLOB NOT NULL)',
 'quotes':'CREATE TABLE quotes (request TEXT PRIMARY KEY, core BLOB NOT NULL, quote_sha256 TEXT NOT NULL UNIQUE, nonce TEXT NOT NULL UNIQUE)',
 'payments':'CREATE TABLE payments (request TEXT PRIMARY KEY REFERENCES quotes(request), txid TEXT NOT NULL UNIQUE, commitment TEXT NOT NULL UNIQUE, origin BLOB NOT NULL, nonce BLOB NOT NULL UNIQUE, disclosure BLOB NOT NULL)',
 'fulfillments':'CREATE TABLE fulfillments (request TEXT PRIMARY KEY REFERENCES payments(request), result BLOB NOT NULL)'}

class MerchantError(ValueError):pass
def need(ok,message):
    if not ok:raise MerchantError(message)

def quote_request(core):
    raw=canonical(core)
    return (bytes.fromhex(digest(QUOTE_DOMAIN+raw))[:31]+b'\0').hex()

class MerchantBook:
    """Immutable local purchase agreement and one retained public resource result."""
    def __init__(self,path,*,expected_genesis,controller,key,book_id,merchant_namespace,recipient,create=False):
        need(os.name=='posix','P7 merchant requires trusted POSIX host')
        need(isinstance(controller,NoteController),'P7 actual merchant controller required')
        need(type(key) is bytes and len(key)==32 and any(key),'P7 external merchant256-bit key required')
        need(type(create) is bool,'P7 explicit merchant creation required')
        hexbytes(book_id,32);field(recipient)
        need(book_id!=ZERO and recipient!=ZERO,'P7 nonzero merchant identity required')
        need(type(merchant_namespace) is str and re.fullmatch('[a-zA-Z0-9._-]{1,64}',merchant_namespace) is not None,
             'P7 bounded merchant namespace required')
        self.raw_genesis=expected_genesis;self.controller=controller;self.worker=controller.worker
        self.g=genesis_document(expected_genesis,self.worker)
        need(controller.raw_genesis==expected_genesis,'P7 merchant/controller pins differ')
        self.key=key;self.book_id=book_id;self.namespace=merchant_namespace;self.recipient=recipient
        self.pins={'format':FORMAT,'book_id':book_id,'merchant_namespace':merchant_namespace,'recipient':recipient,
            'genesis_sha256':digest(expected_genesis),'bootstrap_sha256':bootstrap_digest(self.g),
            'profile_sha256':self.g['profile_sha256'],'worker_sha256':self.worker.sha256,
            'kat_sha256':self.worker.kat_sha256,'controller_sha256':controller.sha256,
            'parameter_sha256':PROFILE['parameter_sha256'],'verifying_key_sha256':PROFILE['verifying_key_sha256']}
        self.path=Path(os.path.abspath(path));self.lock=threading.RLock();self.closed=False
        self._private()
        need(not create or not self.path.exists(),'P7 merchant book already exists')
        fd=os.open(self.path,os.O_RDWR|os.O_NOFOLLOW|(os.O_CREAT|os.O_EXCL if create else 0),0o600)
        try:
            s=os.fstat(fd);need(self._safe_file(s),'P7 opened merchant file differs')
            self.file_identity=(s.st_dev,s.st_ino)
        finally:os.close(fd)
        self.db=sqlite3.connect(self.path,isolation_level=None,timeout=60,check_same_thread=False)
        try:
            self.db.execute('PRAGMA journal_mode=WAL');self.db.execute('PRAGMA synchronous=FULL')
            self.db.execute('PRAGMA foreign_keys=ON')
            for suffix in ('','-wal','-shm'):
                p=Path(str(self.path)+suffix)
                if p.exists():os.chmod(p,0o600)
            with self.atomic():
                if not self.db.execute("SELECT name FROM sqlite_master WHERE name NOT LIKE 'sqlite_%'").fetchall():
                    need(create,'P7 existing merchant schema required')
                    for sql in SCHEMA.values():self.db.execute(sql)
                    nonce=os.urandom(12)
                    need(type(nonce) is bytes and len(nonce)==12,'P7 merchant nonce source refused')
                    check=AESGCM(self.key).encrypt(nonce,KEY_CHECK,DISCLOSURE_DOMAIN+canonical(self.pins))
                    self.db.execute('INSERT INTO identity VALUES (1,?,?,?)',(canonical(self.pins),nonce,check))
                self._audit()
        except BaseException:self.db.close();self.closed=True;raise
    def _safe_file(self,s):
        return stat.S_ISREG(s.st_mode) and s.st_uid==os.getuid() and s.st_nlink==1 and stat.S_IMODE(s.st_mode)==0o600 and s.st_size<=24*1024*1024
    def _private(self):
        for parent in (self.path.parent,*self.path.parent.parents):need(not parent.is_symlink(),'P7 merchant symlink parent refused')
        s=self.path.parent.lstat()
        need(stat.S_ISDIR(s.st_mode) and s.st_uid==os.getuid() and stat.S_IMODE(s.st_mode)==0o700,
             'P7 merchant private owner directory required')
        for suffix in ('','-wal','-shm','-journal'):
            p=Path(str(self.path)+suffix)
            if p.exists() or p.is_symlink():
                need(self._safe_file(p.lstat()),'P7 merchant private regular owner file required')
        if hasattr(self,'file_identity'):
            s=self.path.lstat();need((s.st_dev,s.st_ino)==self.file_identity,'P7 merchant database replaced')
    @contextlib.contextmanager
    def atomic(self,write=True):
        with self.lock:
            need(not self.closed,'P7 merchant book closed');self._private()
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
    def _quote(self,core):
        need(type(core) is dict and set(core)==QUOTE_KEYS and core['format']==QUOTE,'P7 closed merchant quote required')
        t=self.g['treasury']
        pins={'book_id':self.book_id,'merchant_namespace':self.namespace,'recipient':self.recipient,
              'genesis_sha256':digest(self.raw_genesis),'profile_sha256':self.g['profile_sha256'],
              'chain_id':self.g['chain_id'],'asset':t['asset'],'mission':t['mission'],'owner_epoch':t['owner_epoch']}
        need(all(core[k]==v for k,v in pins.items()),'P7 quote trust pins differ')
        for k in ('amount','payment_expiry','generation','owner_epoch','valid_from','valid_until'):number(core[k])
        field(core['grant_id']);field(core['recipient']);hexbytes(core['nonce'],32)
        need(core['nonce']!=ZERO and core['amount']>0 and core['generation']>0 and
             1<=core['valid_from']<core['valid_until']<=64 and core['payment_expiry']>=core['valid_until'],
             'P7 quote amount/generation/interval refused')
        need(core['grant_id'] in [v['id'] for v in t['grants']],'P7 quote grant lane differs')
        r=core['resource'];need(type(r) is str and len(r)%2==0 and 2<=len(r)<=2*MAX_RESOURCE,'P7 resource byte bound')
        resource=hexbytes(r,len(r)//2);need(core['resource_sha256']==digest(resource),'P7 quoted resource differs')
        request=quote_request(core);field(request);need(request!=ZERO,'P7 nonzero quote request required')
        return request,resource
    def _origin(self,origin):
        from protocol7_vault import ORIGIN_KEYS
        need(type(origin) is dict and set(origin)==ORIGIN_KEYS and
             origin['format']=='1soft/protocol7-exact-execution-record/v1' and origin['kind']=='payment',
             'P7 exact certified merchant payment required')
        pins={'genesis':self.raw_genesis.hex(),'genesis_sha256':digest(self.raw_genesis),
              'bootstrap_sha256':bootstrap_digest(self.g),**{k:self.g[k] for k in ('profile_sha256','worker_sha256','kat_sha256')}}
        need(all(origin[k]==v for k,v in pins.items()),'P7 merchant origin pins differ')
        wire=hexbytes(origin['raw'],4168);p=parse(wire)
        need(origin['txid']==txid(wire) and origin['raw_sha256']==digest(wire) and self.worker.verify(wire),
             'P7 merchant exact wire/proof differs')
        o,cert=checked_observation(origin['witness'],origin['signed_header'],self.raw_genesis,self.worker)
        reason,receipt=_resolve(wire,o,self.worker)
        need(reason=='executed-exact' and canonical(origin['receipt'])==canonical(receipt) and canonical(origin['certificate'])==canonical(cert) and
             type(origin['state_height']) is int and origin['state_height']==o['witness']['height'],
             'P7 merchant certified exact execution required')
        return p,cert
    def _verify(self,core,origin,opening):
        request,_=self._quote(core);p,cert=self._origin(origin)
        need(p[1]==self.g['treasury']['genesis'] and p[18]==request and p[6]==core['grant_id'] and integer(p[26])==core['generation'] and
             integer(p[28])==core['owner_epoch'] and integer(p[15])==core['valid_from'] and
             integer(p[16])==core['valid_until'] and p[2]==core['asset'] and p[3]==core['mission'],
             'P7 certified payment differs from retained quote')
        # Closed/type checks happen in the measured native-controller wrapper.
        commitment=self.controller.merchant_commitment(p,opening)
        need(commitment==p[22],'P7 merchant opening commitment mismatch')
        need(opening['recipient']==core['recipient'] and opening['payment']==core['amount'] and
             opening['payment_expiry']==core['payment_expiry'],'P7 disclosed payment differs from quote')
        return p,cert
    def _aad(self,request,origin):
        return DISCLOSURE_DOMAIN+canonical({'pins':self.pins,'request':request,'origin_sha256':digest(canonical(origin))})
    def _decrypt(self,request,origin,nonce,ciphertext):
        need(type(nonce) is bytes and len(nonce)==12 and type(ciphertext) is bytes and 16<len(ciphertext)<=1024,
             'P7 encrypted merchant disclosure bound')
        try:plain=AESGCM(self.key).decrypt(nonce,ciphertext,self._aad(request,origin))
        except InvalidTag:raise MerchantError('P7 merchant disclosure authentication refused') from None
        return closed_json(plain,1024)
    def _result(self,core,origin):
        return {'format':RESULT,'book_id':self.book_id,'merchant_namespace':self.namespace,
            'request':quote_request(core),'quote_sha256':digest(canonical(core)),
            'txid':origin['txid'],'raw_sha256':origin['raw_sha256'],'commitment':parse(hexbytes(origin['raw'],4168))[22],
            'recipient':core['recipient'],'amount':core['amount'],'payment_expiry':core['payment_expiry'],
            'state_height':origin['state_height'],'app_hash':origin['witness']['app_hash'],
            'certificate_sha256':digest(canonical(origin['certificate'])),
            'resource':core['resource'],'resource_sha256':core['resource_sha256'],
            'latest_state_established':False,'retry_authorized':False,'external_delivery_established':False,
            'merchant_note_redemption_established':False}
    def _audit(self):
        self._private()
        rows=self.db.execute("SELECT type,name,sql FROM sqlite_master WHERE name NOT LIKE 'sqlite_%' ORDER BY name").fetchall()
        need(len(rows)==len(SCHEMA) and all(t=='table' and n in SCHEMA and
             ' '.join(sql.split())==' '.join(SCHEMA[n].split()) for t,n,sql in rows),'P7 merchant schema differs')
        identity=self.db.execute('SELECT id,pins,key_nonce,key_check FROM identity').fetchall()
        need(len(identity)==1 and identity[0][:2]==(1,canonical(self.pins)),'P7 merchant identity differs')
        key_nonce,key_check=identity[0][2:]
        need(type(key_nonce) is bytes and len(key_nonce)==12 and type(key_check) is bytes and len(key_check)==len(KEY_CHECK)+16,
             'P7 merchant key-check bound')
        try:check=AESGCM(self.key).decrypt(key_nonce,key_check,DISCLOSURE_DOMAIN+canonical(self.pins))
        except InvalidTag:raise MerchantError('P7 merchant key authentication refused') from None
        need(check==KEY_CHECK,'P7 merchant key check differs')
        quotes={};payments={};results={}
        rows=self.db.execute('SELECT request,core,quote_sha256,nonce FROM quotes ORDER BY request').fetchall()
        need(len(rows)<=MAX_QUOTES,'P7 merchant quote capacity')
        for request,raw,sha,nonce in rows:
            need(type(raw) is bytes,'P7 retained quote bytes required')
            core=closed_json(raw,32768);derived,_=self._quote(core)
            need(request==derived and sha==digest(raw) and nonce==core['nonce'],'P7 retained quote identity differs');quotes[request]=core
        for request,ident,commitment,raw,nonce,ciphertext in self.db.execute('SELECT request,txid,commitment,origin,nonce,disclosure FROM payments'):
            need(request in quotes,'P7 payment quote absent')
            need(type(raw) is bytes,'P7 retained merchant origin bytes required')
            origin=closed_json(raw,MAX_ORIGIN)
            need(nonce!=key_nonce,'P7 disclosure/key-check nonce reuse')
            opening=self._decrypt(request,origin,nonce,ciphertext);p,_=self._verify(quotes[request],origin,opening)
            need(ident==origin['txid'] and commitment==p[22],'P7 retained merchant wire differs');payments[request]=origin
        for request,raw in self.db.execute('SELECT request,result FROM fulfillments'):
            need(type(raw) is bytes and request in payments and raw==canonical(self._result(quotes[request],payments[request])),
                 'P7 retained fulfillment differs');results[request]=raw
        need(self.db.execute('PRAGMA foreign_key_check').fetchall()==[],'P7 merchant foreign reference differs')
        return quotes,payments,results
    def create_quote(self,*,resource,amount,payment_expiry,grant_id,generation,valid_from,valid_until):
        need(type(resource) is bytes and 1<=len(resource)<=MAX_RESOURCE,'P7 exact resource bytes required')
        t=self.g['treasury']
        core={'format':QUOTE,'book_id':self.book_id,'merchant_namespace':self.namespace,'recipient':self.recipient,
            'amount':amount,'payment_expiry':payment_expiry,'chain_id':self.g['chain_id'],
            'genesis_sha256':digest(self.raw_genesis),'profile_sha256':self.g['profile_sha256'],
            'asset':t['asset'],'mission':t['mission'],'grant_id':grant_id,'generation':generation,
            'owner_epoch':t['owner_epoch'],'valid_from':valid_from,'valid_until':valid_until,
            'resource':resource.hex(),'resource_sha256':digest(resource),'nonce':os.urandom(32).hex()}
        request,_=self._quote(core)
        try:
            with self.atomic():
                quotes,_,_=self._audit();need(len(quotes)<MAX_QUOTES,'P7 merchant quote capacity')
                self.db.execute('INSERT INTO quotes VALUES (?,?,?,?)',(request,canonical(core),digest(canonical(core)),core['nonce']))
        except sqlite3.IntegrityError:raise MerchantError('P7 quote request/nonce conflict') from None
        return {'core':copy.deepcopy(core),'request':request,'quote_sha256':digest(canonical(core))}
    def enroll(self,request,origin,opening):
        field(request);need(len(canonical(origin))<=MAX_ORIGIN,'P7 merchant origin byte bound')
        try:
            with self.atomic():
                quotes,payments,_=self._audit();need(request in quotes,'P7 original retained quote required')
                self._verify(quotes[request],origin,opening)
                if request in payments:
                    need(canonical(payments[request])==canonical(origin),'P7 immutable merchant origin conflict')
                    row=self.db.execute('SELECT nonce,disclosure FROM payments WHERE request=?',(request,)).fetchone()
                    need(canonical(self._decrypt(request,origin,row[0],row[1]))==canonical(opening),
                         'P7 immutable merchant disclosure conflict')
                else:
                    nonce=os.urandom(12)
                    need(type(nonce) is bytes and len(nonce)==12,'P7 merchant nonce source refused')
                    need(nonce!=self.db.execute('SELECT key_nonce FROM identity').fetchone()[0],'P7 disclosure/key-check nonce reuse')
                    ciphertext=AESGCM(self.key).encrypt(nonce,canonical(opening),self._aad(request,origin))
                    self.db.execute('INSERT INTO payments VALUES (?,?,?,?,?,?)',
                        (request,origin['txid'],parse(hexbytes(origin['raw'],4168))[22],canonical(origin),nonce,ciphertext))
                return {'request':request,'txid':origin['txid'],'quote_sha256':digest(canonical(quotes[request]))}
        except sqlite3.IntegrityError:raise MerchantError('P7 merchant payment/nonce conflict') from None
    def fulfill(self,request):
        field(request)
        with self.atomic():
            quotes,payments,results=self._audit();need(request in payments,'P7 certified enrolled payment required')
            if request in results:return results[request]
            raw=canonical(self._result(quotes[request],payments[request]))
            self.db.execute('INSERT INTO fulfillments VALUES (?,?)',(request,raw));return raw
    def inspect(self,request):
        """Read transaction only. Re-verifies retained disclosures, never fulfills."""
        field(request)
        with self.atomic(write=False):
            quotes,payments,results=self._audit();need(request in quotes,'P7 retained quote absent')
            return {'request':request,'quote_sha256':digest(canonical(quotes[request])),
                'status':'fulfilled' if request in results else ('certified-enrolled' if request in payments else 'quoted'),
                'txid':payments[request]['txid'] if request in payments else None,
                'result_sha256':digest(results[request]) if request in results else None,
                'latest_state_established':False,'retry_authorized':False,'external_delivery_established':False,
                'merchant_note_redemption_established':False}
