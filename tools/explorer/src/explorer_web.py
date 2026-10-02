"""Self-contained historical explorer renderer and loopback-only read server."""
import base64
import hashlib
from http.server import HTTPServer, BaseHTTPRequestHandler
import json
from pathlib import Path
from urllib.parse import urlsplit

from commit_verifier import encode
from explorer_index import ExplorerIndex, ExplorerError, need

ROOT=Path(__file__).resolve().parents[1]


def policy():
    js=(ROOT/'web/explorer.js').read_bytes()
    digest=base64.b64encode(hashlib.sha256(js).digest()).decode()
    return "default-src 'none'; script-src 'sha256-"+digest+"'; style-src 'unsafe-inline'; connect-src 'self'; base-uri 'none'; form-action 'none'; img-src data:"


def render(view):
    need(type(view) is dict and view.get('schema')==1,'no verified explorer view')
    data=encode(view).decode().replace('&','\\u0026').replace('<','\\u003c').replace('>','\\u003e')
    template=(ROOT/'web/index.html').read_text()
    # Replace script/data last, once; untrusted values never become markup/code.
    return template.replace('@@CSP@@',policy()).replace('@@CSS@@',(ROOT/'web/explorer.css').read_text()).replace(
        '@@JS@@',(ROOT/'web/explorer.js').read_text()).replace('@@DATA@@',data).encode()


def server(index_path, genesis, genesis_sha256, *, port=0):
    need(type(port) is int and (port==0 or 1024<=port<=65535),'invalid local viewer port')
    class Handler(BaseHTTPRequestHandler):
        def setup(self):
            super().setup();self.connection.settimeout(3)
        def log_message(self,*_):pass
        def respond(self,code,data,content_type):
            self.send_response(code)
            self.send_header('Content-Type',content_type);self.send_header('Content-Length',str(len(data)))
            self.send_header('Cache-Control','no-store');self.send_header('X-Content-Type-Options','nosniff')
            self.send_header('Content-Security-Policy',policy()+"; frame-ancestors 'none'")
            self.send_header('X-Frame-Options','DENY');self.send_header('Referrer-Policy','no-referrer')
            self.send_header('Connection','close');self.end_headers();self.wfile.write(data)
        def do_GET(self):
            host=f'127.0.0.1:{self.server.server_port}'
            if (self.headers.get_all('Host')!=[host] or
                self.headers.get('Origin') not in (None,'http://'+host) or
                self.headers.get('Sec-Fetch-Site')=='cross-site'):
                return self.respond(403,b'Forbidden','text/plain; charset=utf-8')
            if self.path not in ('/','/api/view','/api/evidence'):
                return self.respond(404,b'Not found','text/plain; charset=utf-8')
            try:
                with ExplorerIndex(index_path,genesis,genesis_sha256,read_only=True) as index:
                    if self.path=='/api/evidence':data=encode(index.evidence())
                    else:
                        view=index.current();need(view is not None,'index is empty')
                        data=render(view) if self.path=='/' else encode(view)
                self.respond(200,data,'text/html; charset=utf-8' if self.path=='/' else 'application/json')
            except (OSError,ValueError,KeyError,TypeError,OverflowError):
                self.respond(503,b'{"status":"unavailable","payment_outcome_inferred":false}', 'application/json')
            except __import__('sqlite3').Error:
                self.respond(503,b'{"status":"unavailable","payment_outcome_inferred":false}', 'application/json')
        def do_POST(self):self.respond(405,b'Read-only explorer','text/plain')
        do_PUT=do_POST;do_DELETE=do_POST;do_PATCH=do_POST;do_OPTIONS=do_POST
    http=HTTPServer(('127.0.0.1',port),Handler)
    return http
