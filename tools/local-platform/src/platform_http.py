"""Bounded loopback browser interface. The trusted local host remains the custody boundary."""
import hmac
from http.server import HTTPServer, BaseHTTPRequestHandler
from pathlib import Path
import re
import secrets
import sqlite3

from block_application import encode
from commit_verifier import load_json
from p4_evidence import integer, need
from payment_requests import new_request, encode_request

MAX_BODY=65536
WEB=Path(__file__).resolve().parents[1]/'web'
HASH=r'[0-9a-f]{64}'
POST_FIELDS={
    '/api/create-request':{'recipient','units','note','lifetime_seconds'},
    '/api/import-request':{'request_json'},
    '/api/prepare':{'request_id','role','valid_until'},
    '/api/sign':{'request_id','role','review_json','confirmation','password'},
    '/api/submission-review':{'request_id'},
    '/api/submit':{'request_id','review_json','confirmation'},
    '/api/collect':{'request_id'},'/api/retain':{'request_id'},
    '/api/reconcile':{'request_id','expected_revision'},
    '/api/refresh':{'expected_tip'},'/api/sync':{'expected_revision'},
}
CSP="default-src 'none'; script-src 'self'; style-src 'self'; connect-src 'self'; img-src 'self'; form-action 'none'; base-uri 'none'; frame-ancestors 'none'"


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
    return {k:v for k,v in prepared.items() if k!='review'}|{
        'review_json':encode(review).decode('utf-8'),'summary':summary}


def server(service_factory,*,port=0):
    integer(port,0,65535);token=secrets.token_hex(32)
    class Handler(BaseHTTPRequestHandler):
        protocol_version='HTTP/1.0'
        def log_message(self,*_):pass
        def setup(self):
            super().setup();self.connection.settimeout(10)
        def reply(self,code,raw,mime='application/json',filename=None):
            self.send_response(code);self.send_header('Content-Type',mime)
            self.send_header('Content-Length',str(len(raw)));self.send_header('Cache-Control','no-store')
            self.send_header('Content-Security-Policy',CSP)
            self.send_header('X-Content-Type-Options','nosniff');self.send_header('Referrer-Policy','no-referrer')
            self.send_header('X-Frame-Options','DENY');self.send_header('Cross-Origin-Resource-Policy','same-origin')
            self.send_header('Permissions-Policy','camera=(), microphone=(), geolocation=()')
            if filename:self.send_header('Content-Disposition','attachment; filename="'+filename+'"')
            self.end_headers();self.wfile.write(raw)
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
                self.error(404,'route_unavailable')
            except (ValueError,KeyError,TypeError,OSError,sqlite3.DatabaseError):self.error(400,'request_refused')
            except Exception:self.error(500,'operation_unresolved')
        def do_POST(self):
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
                with service_factory() as svc:
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
                    elif self.path=='/api/submission-review':result=public_review(svc.submission_review(q['request_id']))
                    elif self.path=='/api/submit':
                        result=svc.submit(q['request_id'],canonical_review(q['review_json']),q['confirmation'])
                    elif self.path=='/api/collect':result=svc.collect(q['request_id'])
                    elif self.path=='/api/retain':result=svc.retain_receipt(q['request_id'])
                    elif self.path=='/api/reconcile':result=svc.reconcile(q['request_id'],expected_revision=q['expected_revision'])
                    elif self.path=='/api/refresh':result=svc.refresh(expected_tip=q['expected_tip'])
                    elif self.path=='/api/sync':result=svc.sync(expected_revision=q['expected_revision'])
                self.reply(200,encode(result))
            except (ValueError,KeyError,TypeError,OSError,sqlite3.DatabaseError):self.error(400,'request_refused')
            except Exception:self.error(500,'operation_unresolved')
        def do_PUT(self):self.error(405,'method_refused')
        do_DELETE=do_PUT;do_PATCH=do_PUT;do_OPTIONS=do_PUT
    class LocalServer(HTTPServer):
        allow_reuse_address=False
        def handle_error(self,*_):pass  # No raw request, password or exception logging.
    return LocalServer(('127.0.0.1',port),Handler)
