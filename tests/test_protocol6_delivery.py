"""Run the HTTP boundary against a real local server; RPC success never means settlement."""
import base64,json,threading,unittest,tempfile,subprocess,sys,urllib.error,socket
from unittest.mock import patch
from http.server import BaseHTTPRequestHandler,HTTPServer
from pathlib import Path
try:from protocol6_delivery import LoopbackSubmit
except ModuleNotFoundError:LoopbackSubmit=None

class DeliveryTests(unittest.TestCase):
    def setUp(self):self.assertIsNotNone(LoopbackSubmit,'Bounded loopback-only treasury transport is missing')
    def test_wrong_bootstrap_pin_refuses_before_journal_or_worker_io(self):
        root=Path(__file__).resolve().parents[1]
        report=json.loads((root/'evidence/protocol6-treasury/20261004/engine-qualified-01.json').read_bytes())
        raw=json.dumps(report['genesis'],sort_keys=True,separators=(',',':')).encode()
        with tempfile.TemporaryDirectory() as d:
            directory=Path(d);genesis=directory/'genesis.json';genesis.write_bytes(raw)
            journal=directory/'journal.sqlite'
            command=[sys.executable,str(root/'scripts/treasury_wallet.py'),'--journal',str(journal),'--genesis',str(genesis),'--genesis-sha256','ab'*32,'--worker','/missing/unassessed-worker','--worker-sha256',report['genesis']['worker_sha256'],'--kat','/missing/kat','inspect','--txid','ab'*32]
            done=subprocess.run(command,capture_output=True,timeout=10)
            self.assertEqual(done.returncode,1,done.stderr.decode())
            value=json.loads(done.stdout);self.assertEqual(value['status'],'failed')
            self.assertIn('bootstrap genesis pin',value['error']);self.assertFalse(journal.exists())
            self.assertEqual(sorted(p.name for p in directory.iterdir()),['genesis.json'])
    def test_external_addresses_credentials_paths_and_queries_refused(self):
        for url in ['https://example.com:443','http://192.168.1.2:26657','http://user:pw@127.0.0.1:26657','http://127.0.0.1:26657/private','http://127.0.0.1:26657/?secret=x','file:///tmp/socket','http://127.0.0.1:0','http://127.0.0.1:26657/#x']:
            with self.subTest(url=url),self.assertRaises(ValueError):LoopbackSubmit(url)
    def test_exact_raw_is_submitted_once_and_response_is_only_a_hint(self):
        received=[];raw=(Path(__file__).resolve().parents[1]/'evidence/protocol6-treasury/20261004/engine-qualified-01.json.artifacts/fixture-a.tx').read_bytes()
        class Handler(BaseHTTPRequestHandler):
            def do_POST(self):
                received.append(json.loads(self.rfile.read(int(self.headers['Content-Length']))))
                response=json.dumps({'jsonrpc':'2.0','id':1,'result':{'code':0,'hash':'untrusted'}}).encode()
                self.send_response(200);self.send_header('Content-Length',str(len(response)));self.end_headers();self.wfile.write(response)
            def log_message(self,*_):pass
        with HTTPServer(('127.0.0.1',0),Handler) as server:
            thread=threading.Thread(target=server.serve_forever);thread.start()
            try:reply=LoopbackSubmit('http://127.0.0.1:'+str(server.server_port))(raw)
            finally:server.shutdown();thread.join(5)
        self.assertEqual(reply['code'],0);self.assertEqual(len(received),1)
        self.assertEqual(received[0]['method'],'broadcast_tx_sync');self.assertEqual(base64.b64decode(received[0]['params']['tx'],validate=True),raw)
    def test_rpc_failure_does_not_retry(self):
        received=[];raw=(Path(__file__).resolve().parents[1]/'evidence/protocol6-treasury/20261004/engine-qualified-01.json.artifacts/fixture-a.tx').read_bytes()
        class Handler(BaseHTTPRequestHandler):
            def do_POST(self):
                received.append(1);self.rfile.read(int(self.headers['Content-Length']));self.send_response(503);self.end_headers()
            def log_message(self,*_):pass
        with HTTPServer(('127.0.0.1',0),Handler) as server:
            thread=threading.Thread(target=server.serve_forever);thread.start()
            try:
                with self.assertRaises(Exception):LoopbackSubmit('http://127.0.0.1:'+str(server.server_port))(raw)
            finally:server.shutdown();thread.join(5)
        self.assertEqual(received,[1])
    def test_redirect_refused_before_any_second_request(self):
        raw=(Path(__file__).resolve().parents[1]/'evidence/protocol6-treasury/20261004/engine-qualified-01.json.artifacts/fixture-a.tx').read_bytes()
        posts=[];gets=[];destination=[None]
        class Handler(BaseHTTPRequestHandler):
            def do_POST(self):
                posts.append(1);self.rfile.read(int(self.headers['Content-Length']))
                self.send_response(302);self.send_header('Location',destination[0]);self.end_headers()
            def do_GET(self):
                gets.append(self.path)
                response=json.dumps({'jsonrpc':'2.0','id':1,'result':{'code':0}}).encode()
                self.send_response(200);self.send_header('Content-Length',str(len(response)));self.end_headers();self.wfile.write(response)
            def log_message(self,*_):pass
        original=socket.getaddrinfo
        def local_only(host,*args,**kwargs):
            if host not in ('127.0.0.1','::1'):raise AssertionError('test refuses all external DNS/network')
            return original(host,*args,**kwargs)
        with HTTPServer(('127.0.0.1',0),Handler) as server:
            local='http://127.0.0.1:'+str(server.server_port)
            destinations=[local+'/',local+'/path?query=x','http://user:pw@127.0.0.1:'+str(server.server_port)+'/',
                          'http://127.0.0.1:1/','http://[::1]:1/','https://must-not-resolve.invalid:443/']
            thread=threading.Thread(target=server.serve_forever);thread.start()
            try:
                with patch('socket.getaddrinfo',side_effect=local_only):
                    for target in destinations:
                        destination[0]=target
                        with self.subTest(target=target):
                            with self.assertRaises(urllib.error.HTTPError) as error:LoopbackSubmit(local)(raw)
                            self.assertEqual(error.exception.code,302)
            finally:server.shutdown();thread.join(5)
        self.assertEqual(gets,[]);self.assertEqual(len(posts),len(destinations))
if __name__=='__main__':unittest.main()
