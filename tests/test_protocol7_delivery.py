"""Real HTTP boundary for both P7 prepared wire kinds; no RPC settlement claim."""
import base64,json,os,socket,threading,unittest,urllib.error
from pathlib import Path
from http.server import BaseHTTPRequestHandler,HTTPServer
from unittest.mock import patch
from protocol7_delivery import LoopbackSubmit
@unittest.skipUnless(os.environ.get('P7_REPORT'),'unassessed: actual P7 owner/payment bytes not supplied')
class DeliveryTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        p=Path(os.environ['P7_REPORT']);v=json.loads(p.read_bytes());cls.owner=bytes.fromhex(v['commands'][0]);cls.payment=(p.with_name(p.name+'.artifacts')/'fixture-a.tx').read_bytes()
    def exchange(self,raw,mode):
        posts=[];gets=[]
        class Handler(BaseHTTPRequestHandler):
            def do_POST(self):
                posts.append(json.loads(self.rfile.read(int(self.headers['Content-Length']))))
                if mode=='lost':self.connection.shutdown(socket.SHUT_RDWR);self.connection.close();return
                if mode=='redirect':self.send_response(302);self.send_header('Location','http://must-not-resolve.invalid:1/');self.end_headers();return
                if mode=='503':self.send_response(503);self.end_headers();return
                if mode=='bad':reply=b'{}'
                elif mode=='rpc-error':reply=json.dumps({'jsonrpc':'2.0','id':1,'error':{'code':-1}}).encode()
                else:reply=json.dumps({'jsonrpc':'2.0','id':1,'result':{'code':0,'hash':'untrusted'}}).encode()
                self.send_response(200);self.send_header('Content-Length',str(len(reply)));self.end_headers();self.wfile.write(reply)
            def do_GET(self):gets.append(self.path);self.send_response(500);self.end_headers()
            def log_message(self,*_):pass
        original=socket.getaddrinfo
        def local_only(host,*a,**kw):
            if host not in ('127.0.0.1','::1'):raise AssertionError('external DNS/network forbidden')
            return original(host,*a,**kw)
        with HTTPServer(('127.0.0.1',0),Handler) as server:
            t=threading.Thread(target=server.serve_forever);t.start()
            try:
                with patch('socket.getaddrinfo',side_effect=local_only):
                    if mode=='ok':self.assertEqual(LoopbackSubmit('http://127.0.0.1:'+str(server.server_port))(raw)['code'],0)
                    else:
                        with self.assertRaises(Exception):LoopbackSubmit('http://127.0.0.1:'+str(server.server_port))(raw)
            finally:server.shutdown();t.join(5)
        self.assertEqual(gets,[]);self.assertEqual(len(posts),1)
        self.assertEqual(posts[0]['method'],'broadcast_tx_sync');self.assertEqual(base64.b64decode(posts[0]['params']['tx'],validate=True),raw)
    def test_owner_exact_wire_is_delivered(self):self.exchange(self.owner,'ok')
    def test_payment_exact_wire_is_delivered(self):self.exchange(self.payment,'ok')
    def test_owner_lost_reply_http_rpc_failure_malformed_and_redirect_do_not_retry(self):
        for mode in ('lost','503','rpc-error','bad','redirect'):
            with self.subTest(mode=mode):self.exchange(self.owner,mode)
    def test_malformed_unknown_and_wrong_type_wire_refuse_before_network(self):
        with patch('urllib.request.OpenerDirector.open',side_effect=AssertionError('invalid wire must not reach HTTP')):
            for raw in (b'',b'1SOWNR01{}',b'bad',bytearray(self.owner),self.owner.decode('ascii')):
                with self.subTest(kind=type(raw).__name__),self.assertRaises((ValueError,TypeError)):LoopbackSubmit('http://127.0.0.1:1')(raw)
    def test_external_endpoints_and_credentials_refused(self):
        for url in ('http://192.168.1.1:1','https://example.com:443','http://user:pw@127.0.0.1:1','http://127.0.0.1:1/private','http://127.0.0.1:1/?a=b'):
            with self.assertRaises(ValueError):LoopbackSubmit(url)
if __name__=='__main__':unittest.main()
