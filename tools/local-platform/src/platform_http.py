"""Bounded loopback browser interface. The trusted local host remains the custody boundary."""
import hmac
import hashlib
from http.server import HTTPServer, BaseHTTPRequestHandler
from pathlib import Path
import re
import secrets
import sqlite3

from block_application import encode
from commit_verifier import load_json
from p4_evidence import hash_text, integer, need
from payment_requests import new_request, encode_request

MAX_BODY=65536
MAX_MERCHANT_RESOURCE=65536
MAX_MERCHANT_PROOF=90*1024*1024
WEB=Path(__file__).resolve().parents[1]/'web'
HASH=r'[0-9a-f]{64}'
POST_FIELDS={
    '/api/create-request':{'recipient','units','note','lifetime_seconds'},
    '/api/import-request':{'request_json'},
    '/api/prepare':{'request_id','role','valid_until'},
    '/api/sign':{'request_id','role','review_json','confirmation','password'},
    '/api/sign-invoice':{'request_id','role','review_json','confirmation','terms_json','terms_confirmation','password'},
    '/api/submission-review':{'request_id'},
    '/api/submit':{'request_id','review_json','confirmation'},
    '/api/collect':{'request_id'},'/api/retain':{'request_id'},
    '/api/reconcile':{'request_id','expected_revision'},
    '/api/refresh':{'expected_tip'},'/api/sync':{'expected_revision'},
    '/api/backup-history':{'passphrase','repeat_passphrase','scope_confirmed'},
    '/api/merchant-review':{'request_id'},
    '/api/merchant-retrieve':{'request_id','review_json','confirmation'},
}
CSP="default-src 'none'; script-src 'self'; style-src 'self'; connect-src 'self'; img-src 'self'; form-action 'none'; base-uri 'none'; frame-ancestors 'none'"


def backup_password(q):
    """Validate and remove secrets before opening a service or making artifacts."""
    first=q.pop('passphrase');repeat=q.pop('repeat_passphrase')
    password=confirmation=b''
    try:
        need(type(first) is str and type(repeat) is str,'backup passphrase text required')
        password=first.encode('utf-8');confirmation=repeat.encode('utf-8')
        need(16<=len(password)<=1024 and 16<=len(confirmation)<=1024,'backup passphrase byte bound differs')
        need(q['scope_confirmed'] is True,'complete shared history scope confirmation required')
        need(hmac.compare_digest(password,confirmation),'backup passphrases differ')
        return password
    finally:first=repeat='';confirmation=b'';password=b''


def canonical_review(value):
    need(type(value) is str,'canonical review text required')
    raw=value.encode('utf-8');need(len(raw)<=32768,'review exceeds bound')
    parsed=load_json(raw,max_bytes=32768)
    need(type(parsed) is dict and encode(parsed)==raw,'review text changed')
    return parsed


def public_review(prepared):
    review=prepared['review'];body=review.get('body')
    if body is not None:
        summary={'payer':body['sender'],'recipient':body['op']['to'],
                 'units':str(body['op']['units']),'fee_units':str(body['max_fee']),
                 'debit_units':review['debit_units'],'grant_id':body['grant_id'],
                 'valid_until':str(body['valid_until']),'nonce':str(body['nonce']),
                 'state_height':str(review['state_height'])}
    else:
        summary={k:str(review[k]) for k in ('decision_id','payer','grant_id','wire_sha256',
                 'endpoint','valid_until','debit_units','state_height','registry_epoch')}
    # Opaque canonical text avoids loss of 64-bit amounts in JavaScript JSON numbers.
    result = {k:v for k,v in prepared.items() if k not in ('review','terms')}|{
        'review_json':encode(review).decode('utf-8'),'summary':summary}
    if 'terms' in prepared:
        terms=prepared['terms']
        result.update(terms_json=encode(terms).decode('utf-8'),
            terms_summary={k:str(terms[k]) for k in ('request_id','quote_sha256','merchant_origin',
                'resource_url','network','asset','recipient','amount_units','genesis_sha256','role',
                'native_confirmation','resource_sha256','invoice_commitment','created_ns','expires_ns')})
    return result


def server(service_factory,*,port=0):
    integer(port,0,65535);token=secrets.token_hex(32)
    class Handler(BaseHTTPRequestHandler):
        protocol_version='HTTP/1.0'
        def log_message(self,*_):pass
        def setup(self):
            super().setup();self.connection.settimeout(10)
        def reply_headers(self,code,size,mime='application/json',filename=None,*,backup_format=None,purchase=None,proof_sha256=None):
            self.send_response(code);self.send_header('Content-Type',mime)
            self.send_header('Content-Length',str(size));self.send_header('Cache-Control','no-store')
            self.send_header('Content-Security-Policy',CSP)
            self.send_header('X-Content-Type-Options','nosniff');self.send_header('Referrer-Policy','no-referrer')
            self.send_header('X-Frame-Options','DENY');self.send_header('Cross-Origin-Resource-Policy','same-origin')
            self.send_header('Permissions-Policy','camera=(), microphone=(), geolocation=()')
            if filename:self.send_header('Content-Disposition','attachment; filename="'+filename+'"')
            if backup_format:self.send_header('X-1Soft-Backup-Format',backup_format)
            if purchase:
                for key in ('request_id','quote_sha256','resource_sha256','wire_sha256','capsule_sha256','native_txid'):
                    hash_text(purchase[key]);self.send_header('X-1soft-'+key.replace('_','-'),purchase[key])
                integer(purchase['fulfilled_ns'],1,2**63-1)
                self.send_header('X-1soft-Fulfilled-Ns',str(purchase['fulfilled_ns']))
            if proof_sha256:
                hash_text(proof_sha256);self.send_header('X-1soft-Proof-Sha256',proof_sha256)
                self.send_header('X-1soft-Proof-Format','alpha-v1')
            self.end_headers()
        def reply(self,code,raw,mime='application/json',filename=None):
            self.reply_headers(code,len(raw),mime,filename);self.wfile.write(raw)
        def history_reply(self,item):
            from platform_service import HISTORY_BACKUP_BYTES,HISTORY_BLOCK_BYTES
            alpha='format' in item
            if alpha:need(type(item['format']) is str and item['format']=='alpha-v1','unknown history backup format')
            limit=180*1024*1024 if alpha else HISTORY_BACKUP_BYTES
            magic=b'1SOFTP4A1\n' if alpha else b'1SOFTP4B3\n'
            filename='1soft-recovery-history.p4alpha' if alpha else '1soft-recovery-history.p4b3'
            size=item['size'];need(type(size) is int and 10<=size<=limit,'history response bound differs')
            prefix=item['source'].read(10)
            need(type(prefix) is bytes and prefix==magic,'history backup magic differs')
            self.binary_started=True
            self.reply_headers(200,size,'application/octet-stream',filename,backup_format='alpha-v1' if alpha else None)
            self.wfile.write(prefix)
            remaining=size-len(prefix)
            while remaining:
                raw=item['source'].read(min(remaining,HISTORY_BLOCK_BYTES))
                need(type(raw) is bytes and 0<len(raw)<=remaining,'history output truncated')
                self.wfile.write(raw);remaining-=len(raw)
            self.wfile.flush()
        def merchant_reply(self,item,rid,*,proof=False):
            hash_text(rid)
            if proof:
                raw=item['raw'];pins={**item['report'],'fulfilled_ns':item['fulfilled_ns']}
                bound=MAX_MERCHANT_PROOF;filename=f'1soft-merchant-proof-{rid}.json'
            else:
                raw=item['resource'];pins=item;bound=MAX_MERCHANT_RESOURCE;filename=f'1soft-purchase-{rid}.bin'
                need(hashlib.sha256(raw).hexdigest()==pins['resource_sha256'],'merchant resource digest differs')
            need(type(raw) is bytes and 0<len(raw)<=bound and pins['request_id']==rid,'bounded correlated merchant output required')
            for key in ('request_id','quote_sha256','resource_sha256','wire_sha256','capsule_sha256','native_txid'):hash_text(pins[key])
            integer(pins['fulfilled_ns'],1,2**63-1)
            self.binary_started=True
            self.reply_headers(200,len(raw),'application/octet-stream',filename,purchase=pins,
                proof_sha256=hashlib.sha256(raw).hexdigest() if proof else None)
            for start in range(0,len(raw),65536):self.wfile.write(raw[start:start+65536])
            self.wfile.flush()
        def error(self,code,message):
            self.reply(code,encode({'error':message,'message':
                'Action refused or unavailable. Inspect the saved request before repeating an action; original signatures, attempts and obligations are retained.'}))
        def guard(self,post=False):
            expected=f'127.0.0.1:{self.server.server_port}';origin='http://'+expected
            need(self.headers.get_all('Host',[])==[expected],'host refused')
            values=self.headers.get_all('Origin',[])
            need((not values and not post) or values==[origin],'origin refused')
            fetch=self.headers.get_all('Sec-Fetch-Site',[])
            need(not fetch or fetch in (['none'],['same-origin']),'cross-site request refused')
            if post:
                values=self.headers.get_all('X-1soft-CSRF',[])
                need(len(values)==1 and hmac.compare_digest(values[0],token),'CSRF confirmation refused')
        def do_GET(self):
            self.binary_started=False
            try:self.guard()
            except (ValueError,TypeError):self.error(403,'origin_or_session_refused');return
            path=self.path
            try:
                if path in ('/','/wallet.css','/wallet.js'):
                    name='index.html' if path=='/' else path[1:]
                    mime={'index.html':'text/html; charset=utf-8','wallet.css':'text/css; charset=utf-8',
                          'wallet.js':'text/javascript; charset=utf-8'}[name]
                    self.reply(200,(WEB/name).read_bytes(),mime);return
                if path=='/api/session':self.reply(200,encode({'csrf':token,'development_only':True}));return
                if path=='/api/state':
                    with service_factory() as svc:raw=encode(svc.state())
                    self.reply(200,raw);return
                m=re.fullmatch('/api/(request|original)/('+HASH+')',path)
                if m:
                    kind,rid=m.groups()
                    with service_factory() as svc:
                        raw=encode_request(svc.book.selected(rid)['request']) if kind=='request' else svc.recover(rid)
                    self.reply(200,raw,filename=f'1soft-{kind}-{rid}.json');return
                m=re.fullmatch('/api/capsule/('+HASH+')/('+HASH+')',path)
                if m:
                    rid,cid=m.groups()
                    with service_factory() as svc:raw=svc.capsule(rid,cid)
                    self.reply(200,raw,filename=f'1soft-capsule-{cid}.json');return
                m=re.fullmatch('/api/merchant-proof/('+HASH+')',path)
                if m:
                    rid=m.group(1)
                    with service_factory() as svc:
                        need(callable(getattr(svc,'merchant_proof',None)),'merchant fulfillment context required')
                        item=svc.merchant_proof(rid)
                    self.merchant_reply(item,rid,proof=True);return
                self.error(404,'route_unavailable')
            except (ValueError,KeyError,TypeError,OSError,sqlite3.DatabaseError):
                if self.binary_started:self.close_connection=True
                else:self.error(400,'request_refused')
            except Exception:
                if self.binary_started:self.close_connection=True
                else:self.error(500,'operation_unresolved')
        def do_POST(self):
            self.binary_started=False
            try:self.guard(post=True)
            except (ValueError,TypeError):self.error(403,'origin_or_session_refused');return
            fields=POST_FIELDS.get(self.path)
            if fields is None:self.error(404,'route_unavailable');return
            if (self.headers.get_all('Content-Type',[])!=['application/json'] or
                self.headers.get('Content-Encoding') is not None or
                self.headers.get('Transfer-Encoding') is not None):
                self.error(415,'encoding_refused');return
            lengths=self.headers.get_all('Content-Length',[])
            if len(lengths)!=1 or len(lengths[0])>8 or not lengths[0].isascii() or not lengths[0].isdecimal():
                self.error(400,'body_length_refused');return
            length=int(lengths[0])
            if not 0<length<=MAX_BODY:self.error(413,'body_bound_exceeded');return
            try:
                raw=self.rfile.read(length);need(len(raw)==length,'incomplete body')
                q=load_json(raw,max_bytes=MAX_BODY)
                need(type(q) is dict and set(q)==fields,'request fields differ')
                if self.path=='/api/backup-history':
                    raw=b'';password=backup_password(q)
                    try:
                        with service_factory() as svc:
                            with svc.backup_history(password) as item:self.history_reply(item)
                    finally:password=b''
                    return
                with service_factory() as svc:
                    if self.path in ('/api/create-request','/api/import-request'):
                        need(getattr(svc,'allow_unsigned_requests',True),'retained merchant invoices required')
                    if self.path=='/api/create-request':
                        life=integer(q['lifetime_seconds'],1,86400);now=svc.clock()
                        result=svc.add_request(new_request(svc.policy['genesis_sha256'],q['recipient'],q['units'],
                            created_ns=now,expires_ns=now+life*10**9,note=q['note']))
                    elif self.path=='/api/import-request':
                        need(type(q['request_json']) is str,'request text required')
                        result=svc.add_request(q['request_json'].encode('utf-8'))
                    elif self.path=='/api/prepare':
                        result=public_review(svc.prepare(q['request_id'],q['role'],valid_until=q['valid_until']))
                    elif self.path=='/api/sign':
                        need(type(q['password']) is str,'vault password text required')
                        password=q.pop('password').encode('utf-8')
                        try:result=svc.approve(q['request_id'],q['role'],canonical_review(q['review_json']),
                                               q['confirmation'],password=password)
                        finally:password=b''
                    elif self.path=='/api/sign-invoice':
                        need(callable(getattr(svc,'approve_invoice',None)),'merchant browser context required')
                        need(type(q['password']) is str,'vault password text required')
                        password=q.pop('password').encode('utf-8')
                        try:result=svc.approve_invoice(q['request_id'],q['role'],canonical_review(q['review_json']),
                            q['confirmation'],canonical_review(q['terms_json']),q['terms_confirmation'],password=password)
                        finally:password=b''
                    elif self.path=='/api/submission-review':result=public_review(svc.submission_review(q['request_id']))
                    elif self.path=='/api/submit':
                        result=svc.submit(q['request_id'],canonical_review(q['review_json']),q['confirmation'])
                    elif self.path=='/api/collect':result=svc.collect(q['request_id'])
                    elif self.path=='/api/retain':result=svc.retain_receipt(q['request_id'])
                    elif self.path=='/api/reconcile':result=svc.reconcile(q['request_id'],expected_revision=q['expected_revision'])
                    elif self.path=='/api/refresh':result=svc.refresh(expected_tip=q['expected_tip'])
                    elif self.path=='/api/sync':result=svc.sync(expected_revision=q['expected_revision'])
                    elif self.path=='/api/merchant-review':
                        need(callable(getattr(svc,'resource_review',None)),'merchant fulfillment context required')
                        item=svc.resource_review(q['request_id'])
                        result=dict(request_id=q['request_id'],review_json=encode(item['review']).decode('utf-8'),
                                    confirmation=item['confirmation'],summary=item['summary'])
                    elif self.path=='/api/merchant-retrieve':
                        need(callable(getattr(svc,'retrieve_purchase',None)),'merchant fulfillment context required')
                        result=svc.retrieve_purchase(q['request_id'],canonical_review(q['review_json']),q['confirmation'])
                        self.merchant_reply(result,q['request_id']);return
                self.reply(200,encode(result))
            except (ValueError,KeyError,TypeError,OSError,sqlite3.DatabaseError):
                if self.binary_started:self.close_connection=True
                else:self.error(400,'request_refused')
            except Exception:
                if self.binary_started:self.close_connection=True
                else:self.error(500,'operation_unresolved')
        def do_PUT(self):self.error(405,'method_refused')
        do_DELETE=do_PUT;do_PATCH=do_PUT;do_OPTIONS=do_PUT
    class LocalServer(HTTPServer):
        allow_reuse_address=False
        def handle_error(self,*_):pass  # No raw request, password or exception logging.
    return LocalServer(('127.0.0.1',port),Handler)
