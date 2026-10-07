"""Local P8 presentation adapter. Protected console children retain authority."""
from __future__ import annotations
import argparse,html,json,os,re,secrets,subprocess,sys,tempfile,threading,time
from http.server import BaseHTTPRequestHandler,ThreadingHTTPServer
from pathlib import Path
ROOT=Path(__file__).resolve().parents[3]
sys.path[:0]=[str(ROOT/'src'),str(ROOT/'scripts'),str(ROOT/'tools/payment-console/src')]
import protocol8_wallet_cli as c
import protocol8_transfer as n
from protocol8_payment import endpoint_port
from run_protocol8_wallet_cli import process_identity,abort_owned_tree

WEB=ROOT/'tools/p8-wallet/web'
FIELDS={
    'guide':set(),'observe':{'packet'},
    'import-note':{'opening','source','wire','output_index'},
    'prepare':{'commitment','destination','payment','valid_until','payment_expiry'},
    'review':{'txid'},'submit':{'txid'},'status':{'txid'},'reconcile':{'txid','packet'},
    'export':{'txid','output'},'deliver':{'txid','output','output_index'}}
MAX_REQUEST=16384;MAX_DISPLAY=16384

def field(v):
    c.require(type(v) is str and 0<len(v)<=4096 and '\x00' not in v,'bounded text field required')
    return v
def integer(v):
    c.require(type(v) is str and re.fullmatch(r'[1-9][0-9]{0,19}',v) is not None,'positive integer text required')
    value=int(v);c.require(value<2**64,'bounded integer required');return str(value)
def object_pairs(pairs):
    c.require(len(pairs)==len(dict(pairs)),'duplicate JSON field');return dict(pairs)

class Busy(Exception):pass
class Duplicate(Exception):pass

class Service:
    def __init__(self,workspace,credentials,genesis,endpoint,journal,*,demo_inputs=None):
        c.pin(genesis);endpoint_port(endpoint)
        self.workspace=c.absolute(workspace);self.credentials=c.absolute(credentials)
        self.genesis=genesis;self.endpoint=endpoint;self.journal=c.absolute(journal)
        self.token=secrets.token_hex(32);self.lock=threading.Lock();self.claimed=set();self.events=[]
        self.demo_inputs=demo_inputs
    def arguments(self,command,fields):
        c.require(command in FIELDS and type(fields) is dict and set(fields)==FIELDS[command],'closed action fields required')
        extra=[]
        if command=='observe':extra=['--packet',field(fields['packet'])]
        elif command=='import-note':
            c.require(fields['source'] in ('genesis','received') and fields['output_index'] in ('10','11'),'explicit note source/output required')
            extra=['--opening',field(fields['opening']),'--output-index',fields['output_index']]
            if fields['source']=='genesis':
                c.require(fields['wire']=='','genesis import has no origin wire');extra+=['--genesis-note']
            else:extra+=['--wire',field(fields['wire'])]
        elif command=='prepare':
            for name in ('commitment','destination'):c.pin(fields[name]);extra+=['--'+name,fields[name]]
            for name in ('payment','valid_until','payment_expiry'):extra+=['--'+name.replace('_','-'),integer(fields[name])]
            # The intent is a nonzero canonical protocol field, not a digest.
            extra+=['--request',(secrets.randbelow(n.MODULUS-1)+1).to_bytes(32,'little').hex()]
        elif command in ('review','submit','status','reconcile'):
            c.pin(fields['txid']);extra=['--txid',fields['txid'],'--endpoint',self.endpoint,'--journal',str(self.journal)]
            if command=='reconcile' and fields['packet']!='':extra+=['--packet',field(fields['packet'])]
        elif command in ('export','deliver'):
            c.pin(fields['txid']);extra=['--txid',fields['txid'],'--output',field(fields['output'])]
            if command=='deliver':
                c.require(fields['output_index'] in ('10','11'),'explicit output required');extra+=['--output-index',fields['output_index']]
        return extra
    def invoke(self,command,extra,confirmation):
        # Private stdout is displayed only to this local operator. Never record
        # it, argv, request fields, credential contents or local file contents.
        proc=None;identity=None;forced=[];started=time.monotonic()
        with tempfile.TemporaryDirectory(prefix='1soft-wallet-view-') as name:
            path=Path(name);c.directory(path,private=True);receipt=path/'public-receipt.json'
            argv=[sys.executable,'-B',str(ROOT/'scripts/protocol8_console.py'),
                '--workspace',str(self.workspace),'--credentials',str(self.credentials),
                '--genesis-sha256',self.genesis,'--receipt',str(receipt),command,*extra]
            with tempfile.TemporaryFile() as out,tempfile.TemporaryFile() as err:
                try:
                    proc=subprocess.Popen(argv,stdin=subprocess.PIPE,stdout=out,stderr=err,start_new_session=True)
                    identity=process_identity(proc.pid);c.require(identity is not None,'console birth unavailable')
                    proc.communicate((confirmation+'\n').encode(),timeout=1200)
                finally:
                    if proc is not None and proc.poll() is None:forced=abort_owned_tree(proc)
                out.seek(0);err.seek(0);display=out.read(MAX_DISPLAY+1);diagnostic=err.read(257)
            c.require(not diagnostic and len(display)<=MAX_DISPLAY and not forced,'protected console output/lifecycle refused')
            raw=c.read_file(receipt,2*1024**2,private=True);value=json.loads(raw,object_pairs_hook=object_pairs)
            c.require(raw==c.canonical(value)+b'\n' and (value['pid'],value['start_ticks'])==(proc.pid,identity[0]),'console response identity differs')
            c.require(value['command']==command and value['genesis_sha256']==self.genesis and
                proc.returncode==(1 if value['status']=='refused' else 0),'console command/exit differs')
            from payment_console import runtime_sha
            c.require(value['runtime_sha256']==runtime_sha() and value['private_review_values_retained'] is False and
                all(value[k] is False for k in ('automatic_retry','freshness_established','production_ready')),'console runtime/claims differ')
            return {'format':'1soft/local-wallet-action/v1','command':command,'status':value['status'],
                'console_receipt':value,'private_display':display.decode(),
                'process':{'pid':proc.pid,'start_ticks':identity[0],'process_reaped':True,
                    'exit_code':proc.returncode,'elapsed_seconds':round(time.monotonic()-started,6)},
                'private_display_local_only':True,'private_display_logged':False,'automatic_retry':False}
    def perform(self,body):
        c.require(type(body) is dict and set(body)=={'command','fields','confirmation','nonce'},'closed action required')
        command=body['command'];c.require(type(command) is str and command in FIELDS,'known action required')
        c.require(type(body['nonce']) is str and re.fullmatch('[0-9a-f]{48}',body['nonce']) is not None,'action identity required')
        confirmation=body['confirmation'];c.require(type(confirmation) is str and len(confirmation)<=220 and '\n' not in confirmation and '\r' not in confirmation,'one confirmation line required')
        c.require(command in ('prepare','submit') or confirmation=='','confirmation only for prepare/send')
        extra=self.arguments(command,body['fields'])
        if not self.lock.acquire(blocking=False):raise Busy
        try:
            if body['nonce'] in self.claimed:raise Duplicate
            c.require(len(self.claimed)<256,'session action limit reached; reopen explicitly')
            self.claimed.add(body['nonce']) # Claim before starting a child. Never retry an uncertain action.
            result=self.invoke(command,extra,confirmation)
            self.events.append({'command':command,'status':result['status'],'pid':result['process']['pid'],
                'process_reaped':result['process']['process_reaped']})
            return result
        finally:self.lock.release()

class Server(ThreadingHTTPServer):
    # Closing the local server waits for an in-flight protected child; browser
    # disconnect or server stop cannot strand a detached financial action.
    daemon_threads=False
    def __init__(self,service,port=0):
        self.service=service;super().__init__(('127.0.0.1',port),Handler)
        self.origin='http://127.0.0.1:'+str(self.server_address[1])

class Handler(BaseHTTPRequestHandler):
    server_version='1soft-local';sys_version=''
    def log_message(self,*args):pass
    def setup(self):super().setup();self.connection.settimeout(5)
    def trusted(self,api=False):
        host=self.headers.get_all('Host',[]);origin=self.headers.get_all('Origin',[])
        if host!=[self.server.origin.removeprefix('http://')]:return False
        if origin and origin!=[self.server.origin]:return False
        if self.headers.get('Sec-Fetch-Site') not in (None,'none','same-origin'):return False
        if api:
            return origin==[self.server.origin] and self.headers.get_all('X-1soft-Session',[])==[self.server.service.token]
        return True
    def send(self,code,raw,mime='application/json; charset=utf-8'):
        self.send_response(code)
        for k,v in {'Content-Type':mime,'Content-Length':str(len(raw)),'Cache-Control':'no-store',
            'Pragma':'no-cache','X-Content-Type-Options':'nosniff','X-Frame-Options':'DENY','Referrer-Policy':'no-referrer',
            'Content-Security-Policy':"default-src 'none'; script-src 'self'; style-src 'self'; connect-src 'self'; img-src 'self'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'"}.items():self.send_header(k,v)
        self.end_headers()
        try:self.wfile.write(raw)
        except (BrokenPipeError,ConnectionResetError):pass # A lost HTTP reply never retries the protected action.
    def failure(self,code,message):self.send(code,c.canonical({'status':'refused','message':message,'automatic_retry':False})+b'\n')
    def do_GET(self):
        if not self.trusted():return self.failure(403,'Open the wallet from its local address.')
        if self.path=='/':
            raw=(WEB/'index.html').read_text().replace('SESSION_TOKEN',html.escape(self.server.service.token,quote=True))
            raw=raw.replace('DEMO_CONTROL','<button id="demo-inputs" class="quiet">Load synthetic demo inputs</button>' if self.server.service.demo_inputs else '')
            raw=raw.encode()
            return self.send(200,raw,'text/html; charset=utf-8')
        for path,mime in (('/wallet.js','text/javascript; charset=utf-8'),('/wallet.css','text/css; charset=utf-8')):
            if self.path==path:return self.send(200,(WEB/path[1:]).read_bytes(),mime)
        return self.failure(404,'Page unavailable.')
    def do_POST(self):
        if self.path not in ('/api/action','/api/context'):return self.failure(404,'Action unavailable.')
        if not self.trusted(api=True):return self.failure(403,'Session or origin differs. Reopen this local wallet.')
        if self.headers.get_all('Content-Type',[])!=['application/json'] or self.headers.get('Transfer-Encoding'):
            return self.failure(400,'Bounded JSON request required.')
        try:
            lengths=self.headers.get_all('Content-Length',[])
            c.require(len(lengths)==1 and lengths[0].isascii() and lengths[0].isdecimal(),'one body length required')
            size=int(lengths[0]);c.require(0<size<=MAX_REQUEST,'bounded request required')
            raw=self.rfile.read(size);c.require(len(raw)==size,'complete request required')
            body=json.loads(raw,object_pairs_hook=object_pairs)
            if self.path=='/api/context':
                c.require(body=={} and self.server.service.demo_inputs is not None,'demo inputs unavailable')
                return self.send(200,c.canonical(self.server.service.demo_inputs())+b'\n')
            value=self.server.service.perform(body)
        except Busy:return self.failure(409,'Another wallet action is running. Wait, then choose the next action explicitly.')
        except Duplicate:return self.failure(409,'This action was already claimed. Check status; do not resend it.')
        except Exception:return self.failure(400,'Action refused. Preserve the original payment and use status or signed recovery.')
        self.send(200,c.canonical(value)+b'\n')

def main():
    p=argparse.ArgumentParser(description=__doc__)
    for name in ('workspace','credentials','journal'):p.add_argument('--'+name,type=Path,required=True)
    for name in ('genesis-sha256','endpoint'):p.add_argument('--'+name,required=True)
    p.add_argument('--port',type=int,default=0);a=p.parse_args()
    c.require(0<=a.port<=65535,'local port required')
    service=Service(a.workspace,a.credentials,a.genesis_sha256,a.endpoint,a.journal)
    server=Server(service,a.port);print('1soft local wallet: '+server.origin,flush=True)
    try:server.serve_forever(poll_interval=0.1)
    except KeyboardInterrupt:pass
    finally:server.server_close()
if __name__=='__main__':main()
