"""Literal-loopback, read-only P4 explorer. Every data request re-verifies original proof."""
import re,time,sqlite3
from pathlib import Path
from http.server import HTTPServer,BaseHTTPRequestHandler
from block_application import encode
from native_core import canonical
from p4_evidence import need
from p4_read_store import P4ReadStore
from p4_explorer import current_view

WEB=Path(__file__).resolve().parents[1]/'web'
CSP="default-src 'none'; script-src 'self'; style-src 'self'; connect-src 'self'; img-src 'self'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'"


class QuietHTTPServer(HTTPServer):
    def handle_error(self,request,client_address):
        # No request/proof details or traceback leak on a broken browser socket.
        pass


def server(store_path,genesis_bytes,policy,*,port=0,clock=time.time_ns,label='Local development ledger'):
    need(type(port) is int and 0<=port<=65535,'invalid loopback port')
    need(type(label) is str and len(label)<=160,'invalid display label')
    class Handler(BaseHTTPRequestHandler):
        protocol_version='HTTP/1.0'
        def setup(self):
            super().setup();self.connection.settimeout(3)
        def log_message(self,*args):pass
        def reply(self,code,raw=b'',kind='application/json',filename=None):
            self.send_response(code)
            for k,v in [('Content-Type',kind),('Content-Length',str(len(raw))),('Cache-Control','no-store'),
                ('X-Content-Type-Options','nosniff'),('Content-Security-Policy',CSP),
                ('X-Frame-Options','DENY'),('Referrer-Policy','no-referrer'),('Connection','close')]:self.send_header(k,v)
            if filename:self.send_header('Content-Disposition','attachment; filename="'+filename+'"')
            self.end_headers();self.wfile.write(raw)
        def guard(self):
            origin='http://127.0.0.1:'+str(self.server.server_port)
            return (self.headers.get_all('Host')==[origin[7:]] and
                self.headers.get_all('Origin') in (None,[origin]) and
                self.headers.get_all('Sec-Fetch-Site') in (None,['same-origin'],['none']))
        def do_GET(self):
            if not self.guard():return self.reply(403,encode({'status':'forbidden'}))
            static={'/':('index.html','text/html; charset=utf-8'),'/assets/explorer.css':('explorer.css','text/css; charset=utf-8'),
                    '/assets/explorer.js':('explorer.js','text/javascript; charset=utf-8')}
            if self.path in static:
                name,kind=static[self.path]
                try:return self.reply(200,(WEB/name).read_bytes(),kind)
                except OSError:return self.reply(503,encode({'status':'unavailable'}))
            if self.path=='/api/view':
                try:
                    view=current_view(store_path,genesis_bytes,policy,clock=clock);view['label']=label
                    raw=encode(view);need(len(raw)<=16*1024*1024,'display response exceeds bounded size')
                    return self.reply(200,raw)
                except (ValueError,OSError,sqlite3.Error,TypeError,KeyError,OverflowError):return self.reply(503,encode({'status':'unavailable','message':'Verified checkpoint unavailable. No payment outcome or spending authority established.'}))
            match=re.fullmatch(r'/api/capsule/([0-9a-f]{64})',self.path)
            if match:
                try:
                    from p4_receipt_capsule import make_capsule,encode_capsule
                    with P4ReadStore(store_path,genesis_bytes,policy,read_only=True,clock=clock) as store:
                        report=store.current();need(report is not None,'checkpoint unavailable')
                        row=next((r for r in report['receipts'] if r['native_txid']==match[1] and r['record']['envelope']['body']['op']['type']=='transfer'),None)
                        if row is None:return self.reply(404,encode({'status':'unavailable'}))
                        evidence=store.export(report['evidence_id']);wire=canonical(row['record']['envelope'])
                        capsule=make_capsule(evidence,genesis_bytes,policy,wire,payer=row['record']['envelope']['body']['sender'],now_ns=clock())
                    return self.reply(200,encode_capsule(capsule),'application/json','1soft-receipt-'+match[1]+'.json')
                except (ValueError,OSError,sqlite3.Error,TypeError,KeyError,OverflowError):return self.reply(503,encode({'status':'unavailable'}))
            self.reply(404,encode({'status':'unavailable'}))
        def refuse(self):self.reply(405,encode({'status':'read-only'}))
        do_POST=do_PUT=do_PATCH=do_DELETE=do_OPTIONS=do_HEAD=do_TRACE=do_CONNECT=refuse
    http=QuietHTTPServer(('127.0.0.1',port),Handler);http.timeout=3
    return http
