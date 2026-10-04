"""Explicit durable-alpha paid resource adapter. Historical proof is not authority.

Original public packet bytes are stored once. No keys, wallet edits, enrollment
endpoint, callback, migration, trust renewal or external settlement is provided.
"""
import base64
from contextlib import contextmanager
from dataclasses import asdict
import hashlib
import os
from pathlib import Path
import sqlite3

from block_application import encode
from commit_verifier import b64, exact, load_json
from native_core import canonical, digest, DOMAIN
from p4_evidence import content_id, hash_text, integer, need, nanos, p4_genesis
from p4_incremental_evidence import policy_v2_checked
from p4_alpha_custody import MAX_RECEIPT_BYTES, RECEIPT_FORMAT, verify_receipt
from p4_read_store import private_path
from merchant_book import MAX_QUOTES, MAX_RESOURCE_BYTES, EXPECTATION_FIELDS, _resource, _stored_quote
from payment_x402 import (MAX_SIGNATURE_HEADER, MAX_RESPONSE_HEADER, MAX_REQUIRED_HEADER,
    TrustedMerchantAssignment, _sha, _wire, _header, _depth, invoice_binding,
    parse_payment_required, parse_payment_response, SCHEME)

FORMAT='1soft/alpha-merchant-book/v1'
PAYLOAD_FORMAT='1soft/alpha-native-payment/v1'
PROOF_FORMAT='1soft/alpha-merchant-proof/v1'
APPLICATION_ID=0x3150414D
MAX_STORED_BYTES=80*1024*1024
MAX_PHYSICAL_BYTES=240*1024*1024
MAX_PROOF_BYTES=4*((MAX_RECEIPT_BYTES+16384+MAX_RESOURCE_BYTES+8192+8)//3)+65536
SCHEMA={
 'config':'id INTEGER PRIMARY KEY CHECK(id=1),format TEXT NOT NULL,genesis_sha256 TEXT NOT NULL,policy BLOB NOT NULL,last_ns INTEGER NOT NULL',
 'quotes':'quote_id TEXT PRIMARY KEY,request_id TEXT UNIQUE NOT NULL,required BLOB NOT NULL,expectation BLOB NOT NULL,resource BLOB NOT NULL,retained_ns INTEGER NOT NULL',
 'payments':'quote_id TEXT PRIMARY KEY REFERENCES quotes(quote_id),payer TEXT NOT NULL,wire BLOB NOT NULL,wire_sha256 TEXT UNIQUE NOT NULL,native_txid TEXT UNIQUE NOT NULL,capsule BLOB NOT NULL,capsule_sha256 TEXT NOT NULL,reference_id TEXT NOT NULL,signer_public_key TEXT NOT NULL,enrolled_ns INTEGER NOT NULL,fulfilled_ns INTEGER,response_header TEXT'}


def parse_packet(raw):
    need(type(raw) is bytes and 0<len(raw)<=MAX_RECEIPT_BYTES,'bounded original alpha packet required')
    v=load_json(raw,max_bytes=MAX_RECEIPT_BYTES)
    exact(v,{'schema','format','reference','capsule_id','wire_hex','history'},'alpha packet')
    integer(v['schema'],1,1)
    need(v['format']==RECEIPT_FORMAT and encode(v)==raw,'canonical alpha packet required')
    return v


def _quote(required,expectation,now):
    q=parse_payment_required(required,expectation,now_ns=now)
    need(type(q.get('invoice_terms')) is dict,'alpha merchant requires committed v2 invoice')
    return q


def make_signature(*,required_header,expectation,exact_wire,capsule,payer,now_ns):
    q=_quote(required_header,expectation,now_ns);v=parse_packet(capsule)
    invoice_binding(_wire(exact_wire,expectation,payer),q['invoice_terms'])
    need(v['wire_hex']==exact_wire.hex() and v['reference']['payer']==payer and
         v['reference']['wire_sha256']==_sha(exact_wire) and
         v['reference']['genesis_sha256']==expectation.genesis_sha256,'alpha packet changes exact payment')
    return _header({'x402Version':2,'resource':q['offer']['resource'],'accepted':q['offer']['accepts'][0],
        'payload':{'format':PAYLOAD_FORMAT,'quoteSha256':q['quote_sha256'],'requestId':q['request_id'],
        'payer':payer,'wire':base64.b64encode(exact_wire).decode('ascii'),
        'wireSha256':_sha(exact_wire),'capsuleSha256':_sha(capsule)}},MAX_SIGNATURE_HEADER)


def verify_payment(*,signature_header,required_header,expectation,assignment,exact_wire,capsule,genesis_bytes,policy,payer,now_ns):
    p=policy_v2_checked(policy);now=integer(now_ns,nanos(p['anchor_time']))
    need(now<p['absolute_not_after_ns'],'new alpha payment interpretation exceeds original fixed horizon')
    g,_=p4_genesis(genesis_bytes,p['genesis_sha256'])
    need(g.get('development_profile')=='durable-private-alpha-v1' and g.get('invoice_commitment_version')==1 and
         g['asset']=='DEV' and expectation.asset=='1soft:DEV' and expectation.genesis_sha256==p['genesis_sha256'],
         'independent committed DEV alpha genesis required')
    q=_quote(required_header,expectation,now)
    need(type(assignment) is TrustedMerchantAssignment,'independent immutable assignment required')
    assignment.__post_init__()
    need(asdict(assignment)==dict(quote_sha256=q['quote_sha256'],request_id=q['request_id'],
        recipient=expectation.recipient,payer=payer,wire_sha256=_sha(exact_wire)),'independent assignment differs')
    packet=_wire(exact_wire,expectation,payer)
    need(packet['body']['chain_id']==g['chain_id'] and packet['body']['genesis_hash']==digest(g),'native chain/genesis differs')
    expected=make_signature(required_header=required_header,expectation=expectation,exact_wire=exact_wire,
                            capsule=capsule,payer=payer,now_ns=now)
    need(signature_header==expected,'exact alpha signature payload differs')
    proof=verify_receipt(capsule,genesis_bytes,p,payer=payer,wire_sha256=_sha(exact_wire))
    value=parse_packet(capsule)
    tip=value['history']['checkpoints'][-1]
    need(tip['lookahead_time_ns']<=now+p['max_clock_drift_seconds']*10**9,
         'caller interpretation time precedes signed receipt checkpoint')
    receipt=proof['receipt']
    need(canonical(receipt['record']['envelope'])==exact_wire and
         receipt['native_txid']==_sha(DOMAIN+canonical(packet['body'])),'positive original receipt differs')
    response=_header({'success':True,'transaction':receipt['native_txid'],'network':expectation.network,
        'payer':payer,'amount':expectation.amount_units,'extensions':{SCHEME:{'quoteSha256':q['quote_sha256'],
        'wireSha256':_sha(exact_wire),'capsuleSha256':_sha(capsule),'genesisSha256':expectation.genesis_sha256,
        'resourceUrl':expectation.resource_url}}},MAX_RESPONSE_HEADER)
    return dict(native_txid=receipt['native_txid'],wire_sha256=_sha(exact_wire),capsule_sha256=_sha(capsule),
        reference_id=proof['capsule_id'],signer_public_key=receipt['record']['signer_public_key'],
        payment_response_header=response,receipt_report=proof,native_signature_authenticates_resource=True,
        current_spending_authority=False,wallet_reservations_changed=False)


class AlphaMerchantBook:
    def __init__(self,path,genesis_bytes,policy,*,clock,create=False,read_only=False):
        need(type(create) is bool and type(read_only) is bool and not(create and read_only) and callable(clock),
             'explicit alpha merchant modes and trusted clock required')
        self.path=private_path(path);self.genesis=bytes(genesis_bytes);self.policy=policy_v2_checked(policy)
        self.policy_id=content_id(self.policy);self.clock=clock;self.read_only=read_only;self.db=None
        self._observed_ns=nanos(self.policy['anchor_time']);self._commit_row=None
        g,_=p4_genesis(self.genesis,self.policy['genesis_sha256'])
        need(g.get('development_profile')=='durable-private-alpha-v1' and g.get('invoice_commitment_version')==1 and g['asset']=='DEV',
             'fresh committed DEV alpha genesis required')
        self.native_genesis=g;now=self._now()
        if create:
            need(now<self.policy['absolute_not_after_ns'],'original fixed horizon expired')
            need(not any(os.path.lexists(str(self.path)+suffix) for suffix in ('','-wal','-shm','-journal')),
                 'new alpha merchant path and sidecars required; no repair')
            fd=os.open(self.path,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600);os.close(fd)
        else:need(self.path.is_file(),'original alpha merchant book unavailable')
        try:
            self.db=sqlite3.connect(self.path.as_uri()+('?mode=ro' if read_only else '?mode=rw'),uri=True,isolation_level=None)
            self.db.row_factory=sqlite3.Row
            self.db.execute('PRAGMA trusted_schema=OFF');self.db.execute('PRAGMA foreign_keys=ON')
            if not read_only:self.db.execute('PRAGMA synchronous=FULL')
            if create:
                self.db.execute('PRAGMA journal_mode=WAL')
                with self.atomic():
                    self.db.execute(f'PRAGMA application_id={APPLICATION_ID}')
                    for name,ddl in SCHEMA.items():self.db.execute(f'CREATE TABLE {name}({ddl})')
                    self.db.execute('INSERT INTO config VALUES(1,?,?,?,?)',(FORMAT,self.policy['genesis_sha256'],encode(self.policy),now))
                fd=os.open(self.path.parent,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
                try:os.fsync(fd)
                finally:os.close(fd)
            self._catalog(now)
        except BaseException:self.close();raise
    def close(self):
        if self.db is not None:self.db.close();self.db=None
    def __enter__(self):return self
    def __exit__(self,*_):self.close()
    @contextmanager
    def atomic(self,write=True):
        need(not(write and self.read_only),'read-only alpha book cannot mutate')
        self.db.execute('BEGIN IMMEDIATE' if write else 'BEGIN')
        try:
            yield
            if write and self._commit_row is not None:
                end=self._live(self._commit_row,self._observed_ns)
                self._advance(end)
                self._live(self._commit_row,end)
                self._advance(self._observed_ns)
            self.db.execute('COMMIT')
        except BaseException:
            if self.db.in_transaction:self.db.execute('ROLLBACK')
            raise
        finally:self._commit_row=None
    def _now(self):
        now=integer(self.clock(),self._observed_ns);self._observed_ns=now;return now
    def _catalog(self,now):
        private_path(self.path);total=0
        for suffix in ('','-wal','-shm'):
            file=Path(str(self.path)+suffix)
            if file.exists():private_path(file);total+=file.stat().st_size
        need(total<=MAX_PHYSICAL_BYTES,'alpha merchant physical quota exceeded')
        need(self.db.execute('PRAGMA application_id').fetchone()[0]==APPLICATION_ID and
             self.db.execute('PRAGMA journal_mode').fetchone()[0]=='wal','original alpha book identity differs')
        schema={r['name']:r['sql'] for r in self.db.execute("SELECT name,sql FROM sqlite_master WHERE name NOT LIKE 'sqlite_%'")}
        need(schema=={n:f'CREATE TABLE {n}({d})' for n,d in SCHEMA.items()},'original alpha book schema differs')
        cfg=self.db.execute('SELECT * FROM config').fetchall()
        need(len(cfg)==1 and tuple(cfg[0])[:4]==(1,FORMAT,self.policy['genesis_sha256'],encode(self.policy)),
             'independent original alpha merchant context differs')
        now=integer(now,nanos(self.policy['anchor_time']));need(integer(cfg[0]['last_ns'])<=now,'merchant local clock regressed')
        count,size=self.db.execute('SELECT count(*),coalesce(sum(length(required)+length(expectation)+length(resource)),0) FROM quotes').fetchone()
        pc,ps=self.db.execute('SELECT count(*),coalesce(sum(length(wire)+length(capsule)),0) FROM payments').fetchone()
        need(count<=MAX_QUOTES and pc<=count and size+ps<=MAX_STORED_BYTES,'alpha merchant logical quota exceeded; no eviction')
        rows={}
        for r in self.db.execute('SELECT * FROM quotes ORDER BY quote_id'):
            header,e,q=_stored_quote(r['required'],r['expectation']);resource=_resource(r['resource'])
            q=dict(q,created_ns=q['invoice_terms']['created_ns'],expires_ns=q['invoice_terms']['expires_ns'])
            need(q['quote_sha256']==r['quote_id'] and q['request_id']==r['request_id'] and type(q.get('invoice_terms')) is dict and
                 e.genesis_sha256==self.policy['genesis_sha256'] and e.asset=='1soft:DEV' and
                 _sha(resource)==q['invoice_terms']['resource_sha256'],'retained committed resource differs')
            integer(r['retained_ns'],q['created_ns'],q['expires_ns']-1)
            need(r['retained_ns']<=now and r['retained_ns']<self.policy['absolute_not_after_ns'],'quote retention time differs')
            rows[r['quote_id']]=dict(r)|dict(expectation=e,quote=q,resource=resource,payment=None)
        for p in self.db.execute('SELECT * FROM payments ORDER BY quote_id'):
            need(p['quote_id'] in rows,'orphan retained payment')
            r=rows[p['quote_id']];packet=_wire(p['wire'],r['expectation'],p['payer']);invoice_binding(packet,r['quote']['invoice_terms'])
            v=parse_packet(p['capsule'])
            need(p['wire_sha256']==_sha(p['wire']) and p['capsule_sha256']==_sha(p['capsule']) and
                 p['native_txid']==_sha(DOMAIN+canonical(packet['body'])) and v['wire_hex']==p['wire'].hex() and
                 v['capsule_id']==p['reference_id']==content_id(v['reference']) and
                 v['reference']['policy_id']==self.policy_id and v['reference']['payer']==p['payer'] and
                 v['reference']['wire_sha256']==p['wire_sha256'],'retained original alpha payment identity differs')
            hash_text(p['signer_public_key'])
            integer(p['enrolled_ns'],r['retained_ns'],now);need(p['enrolled_ns']<min(r['quote']['expires_ns'],self.policy['absolute_not_after_ns']),
                 'enrollment after quote/horizon')
            need((p['fulfilled_ns'] is None)==(p['response_header'] is None),'partial retained fulfillment')
            if p['fulfilled_ns'] is not None:
                integer(p['fulfilled_ns'],p['enrolled_ns'],now)
                need(p['fulfilled_ns']<min(r['quote']['expires_ns'],self.policy['absolute_not_after_ns']),'consumption after quote/horizon')
                response=parse_payment_response(p['response_header'],r['expectation'],payer=p['payer'],quote_sha256=r['quote_id'],
                    wire_sha256=p['wire_sha256'],capsule_sha256=p['capsule_sha256'])
                need(response['response']['transaction']==p['native_txid'],'retained response transaction differs')
            rows[p['quote_id']]['payment']=dict(p)
        return cfg[0],rows
    def _advance(self,previous):
        now=integer(max(previous,self._observed_ns));self.db.execute('UPDATE config SET last_ns=? WHERE id=1',(now,));return now
    def _live(self,row,previous):
        now=integer(self._now(),previous)
        need(now<self.policy['absolute_not_after_ns'],'original alpha merchant fixed horizon expired')
        _quote(row['required'].decode('ascii'),row['expectation'],now)
        return now
    def add_quote(self,required_header,expectation,*,resource):
        resource=_resource(resource);now=integer(self._now());q=_quote(required_header,expectation,now)
        need(expectation.genesis_sha256==self.policy['genesis_sha256'] and expectation.asset=='1soft:DEV' and
             q['invoice_terms']['resource_sha256']==_sha(resource),'pinned resource/genesis differs')
        with self.atomic():
            _,rows=self._catalog(now);row=dict(required=required_header.encode('ascii'),expectation=expectation)
            now=self._live(row,now);self._commit_row=row
            if q['quote_sha256'] in rows:
                old=rows[q['quote_sha256']];need(old['required']==row['required'] and old['expectation']==expectation and old['resource']==resource,
                    'original quote immutable');status='already_retained'
            else:
                need(len(rows)<MAX_QUOTES and not any(r['expectation'].resource_url==expectation.resource_url for r in rows.values()),
                     'quote capacity or exact route already assigned')
                self.db.execute('INSERT INTO quotes VALUES(?,?,?,?,?,?)',(q['quote_sha256'],q['request_id'],row['required'],encode(asdict(expectation)),resource,now))
                status='quote_retained'
            end=self._live(row,now);self._advance(end);self._catalog(end)
            end=self._live(row,end);self._advance(end);self._live(row,end)
        return dict(status=status,quote_sha256=q['quote_sha256'],request_id=q['request_id'],resource_sha256=_sha(resource))
    def _assignment(self,row,p):
        return TrustedMerchantAssignment(row['quote_id'],row['request_id'],row['expectation'].recipient,p['payer'],p['wire_sha256'])
    def assignment(self,qid):
        with self.atomic(write=False):
            _,rows=self._catalog(self._now());r=rows[hash_text(qid)];need(r['payment'] is not None,'explicit paid enrollment required')
            return self._assignment(r,r['payment'])
    def _verify(self,row,p,now,signature=None):
        h=make_signature(required_header=row['required'].decode('ascii'),expectation=row['expectation'],exact_wire=p['wire'],
            capsule=p['capsule'],payer=p['payer'],now_ns=now) if signature is None else signature
        return verify_payment(signature_header=h,required_header=row['required'].decode('ascii'),expectation=row['expectation'],
            assignment=self._assignment(row,p),exact_wire=p['wire'],capsule=p['capsule'],genesis_bytes=self.genesis,
            policy=self.policy,payer=p['payer'],now_ns=now)
    def enroll_wire(self,qid,payer,wire,*,evidence):
        hash_text(qid);now=integer(self._now())
        with self.atomic():
            _,rows=self._catalog(now);need(qid in rows,'merchant quote unavailable');r=rows[qid]
            now=self._live(r,now);self._commit_row=r;p=dict(payer=payer,wire=wire,wire_sha256=_sha(wire),capsule=evidence)
            proof=self._verify(r,p,now);now=self._live(r,now)
            old=r['payment']
            if old is not None:
                need(old['payer']==payer and old['wire']==wire and old['capsule']==evidence and old['signer_public_key']==proof['signer_public_key'],
                     'paid enrollment immutable');status='already_enrolled'
            else:
                self.db.execute('INSERT INTO payments VALUES(?,?,?,?,?,?,?,?,?,?,NULL,NULL)',(qid,payer,wire,_sha(wire),proof['native_txid'],
                    evidence,_sha(evidence),proof['reference_id'],proof['signer_public_key'],now));status='paid_wire_enrolled'
            end=self._live(r,now);self._advance(end);self._catalog(end)
            end=self._live(r,end);self._advance(end);self._live(r,end)
        return dict(status=status,quote_sha256=qid,wire_sha256=_sha(wire),execution_proven=True,current_spending_authority=False,wallet_reservations_changed=False)
    def fulfill(self,qid,signature_header,capsule):
        hash_text(qid);now=integer(self._now())
        with self.atomic():
            _,rows=self._catalog(now);need(qid in rows,'merchant quote unavailable');r=rows[qid];p=r['payment']
            need(p is not None,'explicit independently paid enrollment required')
            need(type(capsule) is bytes and capsule==p['capsule'],'original paid packet differs; no cache shortcut')
            historical=p['fulfilled_ns'] is not None
            checked=p['fulfilled_ns'] if historical else self._live(r,now)
            proof=self._verify(r,p,checked,signature_header)
            need((proof['native_txid'],proof['reference_id'],proof['signer_public_key'])==
                 (p['native_txid'],p['reference_id'],p['signer_public_key']),'retained historical signer/payment differs')
            if historical:
                need(proof['payment_response_header']==p['response_header'],'original response differs')
                self._advance(now);status='original_local_fulfillment_retained';saved=p['fulfilled_ns']
            else:
                self._commit_row=r
                saved=self._live(r,now)
                self.db.execute('UPDATE payments SET fulfilled_ns=?,response_header=? WHERE quote_id=?',
                    (saved,proof['payment_response_header'],qid))
                end=self._live(r,saved);self._advance(end);status='local_fulfillment_retained'
            self._catalog(self._now())
            if not historical:
                end=self._live(r,saved);self._advance(end);self._live(r,end)
        return dict(status=status,quote_sha256=qid,native_txid=p['native_txid'],wire_sha256=p['wire_sha256'],
            resource=r['resource'],resource_sha256=_sha(r['resource']),payment_response_header=proof['payment_response_header'],fulfilled_ns=saved,
            native_execution_reverified=True,merchant_consumption_retained=True,wallet_reservations_changed=False,
            external_service_delivery_verified=False,globally_exactly_once_service_delivery=False)
    def _display(self,r):
        p=r['payment']
        return dict(quote_sha256=r['quote_id'],required_header=r['required'].decode('ascii'),expectation=r['expectation'],
            resource_sha256=_sha(r['resource']),retained_ns=r['retained_ns'],created_ns=r['quote']['created_ns'],expires_ns=r['quote']['expires_ns'],
            enrollment=None if p is None else {k:p[k] for k in ('payer','wire_sha256','signer_public_key','reference_id','enrolled_ns')},
            fulfillment=None if p is None or p['fulfilled_ns'] is None else {k:p[k] for k in ('native_txid','wire_sha256','capsule_sha256','fulfilled_ns')},
            execution_proven=False,resource_delivery_authorized=False,wallet_reservations_changed=False)
    def selected(self,qid):
        with self.atomic(write=False):
            _,rows=self._catalog(self._now());need(qid in rows,'merchant quote unavailable');return self._display(rows[qid])
    def entries(self):
        with self.atomic(write=False):
            _,rows=self._catalog(self._now());return [self._display(r) for r in rows.values()]
    def export_proof(self,qid):
        with self.atomic(write=False):
            _,rows=self._catalog(self._now());need(qid in rows,'merchant quote unavailable');r=rows[qid];p=r['payment']
            need(p is not None and p['fulfilled_ns'] is not None,'original completed local fulfillment required')
            signature=make_signature(required_header=r['required'].decode('ascii'),expectation=r['expectation'],exact_wire=p['wire'],
                capsule=p['capsule'],payer=p['payer'],now_ns=p['fulfilled_ns'])
            value=dict(schema=1,format=PROOF_FORMAT,required_header=r['required'].decode('ascii'),signature_header=signature,response_header=p['response_header'])
            for n,raw in (('invoice_terms',canonical(r['quote']['invoice_terms'])),('wire',p['wire']),('capsule',p['capsule']),('resource',r['resource'])):
                value[n+'_b64']=base64.b64encode(raw).decode('ascii')
            raw=encode(value)
            verify_proof(raw,genesis_bytes=self.genesis,policy=self.policy,expectation=r['expectation'],assignment=self._assignment(r,p),now_ns=p['fulfilled_ns'])
            return raw


def verify_proof(raw,*,genesis_bytes,policy,expectation,assignment,now_ns):
    need(type(raw) is bytes and 0<len(raw)<=MAX_PROOF_BYTES,'bounded alpha merchant proof required');_depth(raw)
    v=load_json(raw,max_bytes=MAX_PROOF_BYTES)
    exact(v,{'schema','format','required_header','signature_header','response_header','invoice_terms_b64','wire_b64','capsule_b64','resource_b64'},'alpha merchant proof')
    integer(v['schema'],1,1);need(v['format']==PROOF_FORMAT and encode(v)==raw,'canonical alpha merchant proof required')
    for name,bound in (('required_header',MAX_REQUIRED_HEADER),('signature_header',MAX_SIGNATURE_HEADER),('response_header',MAX_RESPONSE_HEADER)):
        need(type(v[name]) is str and 0<len(v[name])<=bound and v[name].isascii(),'bounded original header required')
    parts={n:b64(v[n+'_b64'],max_size=b) for n,b in [('invoice_terms',8192),('wire',16384),('capsule',MAX_RECEIPT_BYTES),('resource',MAX_RESOURCE_BYTES)]}
    q=_quote(v['required_header'],expectation,now_ns)
    need(parts['invoice_terms']==canonical(q['invoice_terms']) and 0<len(parts['resource']) and
         _sha(parts['resource'])==q['invoice_terms']['resource_sha256'],'original committed resource differs')
    proof=verify_payment(signature_header=v['signature_header'],required_header=v['required_header'],expectation=expectation,
        assignment=assignment,exact_wire=parts['wire'],capsule=parts['capsule'],genesis_bytes=genesis_bytes,policy=policy,payer=assignment.payer,now_ns=now_ns)
    need(v['response_header']==proof['payment_response_header'],'original response declaration differs')
    return dict(status='verified-historical-alpha-merchant-payment',proof_sha256=_sha(raw),quote_sha256=q['quote_sha256'],request_id=q['request_id'],
        native_txid=proof['native_txid'],wire_sha256=proof['wire_sha256'],capsule_sha256=proof['capsule_sha256'],reference_id=proof['reference_id'],
        resource_sha256=_sha(parts['resource']),checked_at_ns=now_ns,native_execution_replayed=True,native_signature_authenticates_resource=True,
        resource_bytes_match_commitment=True,merchant_consumption_proven=False,merchant_identity_authenticated=False,
        external_service_delivery_verified=False,delivery_time_verified=False,spending_authority=False,wallet_reservations_changed=False,
        source_host_admission_times_authenticated=False,onchain_privacy=False,full_public_ledger_disclosed=True)
