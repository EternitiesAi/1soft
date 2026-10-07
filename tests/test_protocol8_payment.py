"""Fake-wallet coordinator tests plus actual disposable loopback HTTP transport.

Wallet/crypto/consensus are not qualified here; the native gate covers those.
"""
import copy, hashlib, json, threading, unittest
from http.server import BaseHTTPRequestHandler, HTTPServer
from unittest.mock import patch
import test_protocol8_wallet_cli as wallet_fixture
import protocol8_payment as p
import protocol8_wallet_cli as c
import protocol8_transfer as n

class FakeWallet:
    def __init__(self, wire):
        self.wire=wire;self.ident=n.txid(wire);self.attempts=0;self.completed=False
    def export(self,ident):
        if ident!=self.ident:raise ValueError('unknown')
        return self.wire
    def inventory(self):return {'obligations':[{'txid':self.ident,'attempts':self.attempts,'completed':self.completed}]}
    def mark_attempt(self,ident):
        self.export(ident)
        if self.attempts or self.completed:raise ValueError('held')
        self.attempts=1
    def reconcile(self,ident):
        self.export(ident)
        return {'status':'executed-exact' if self.completed else 'unresolved-held','txid':ident}
    def observe(self,witness,header):raise ValueError('fake refuses certificate')

class PaymentTests(unittest.TestCase):
    def setUp(self):
        self.fixture=wallet_fixture.WalletCommandTests();self.fixture.setUp();self.fixture.init()
        self.wallet=FakeWallet(self.fixture.tx);self.endpoint='http://127.0.0.1:12345'
        self.wallet.pins=json.loads((self.fixture.workspace/'wallet-cli.json').read_bytes())['wallet_pins']
        self.journal=self.fixture.data/'payment'
        self.native=patch.object(c,'native',return_value=(self.wallet,None));self.native.start()
    def tearDown(self):self.native.stop();self.fixture.tearDown()
    def args(self,command='submit',**kw):
        return self.fixture.args(command,txid=self.wallet.ident,endpoint=self.endpoint,journal=self.journal,packet=None,**kw)
    def call(self,command='submit'):return p.execute(self.args(command))
    def dispatch(self,outcome='admission-accepted',code=0):
        return patch.object(p,'dispatch',return_value={'outcome':outcome,'admission_code':code})
    def test_marker_and_authenticated_journal_precede_transport(self):
        def send(endpoint,wire):
            self.assertEqual(self.wallet.attempts,1);self.assertEqual(wire,self.wallet.wire)
            envelope=json.loads(self.journal.read_bytes());self.assertEqual(envelope['record']['phase'],'attempt-marked')
            self.assertEqual(self.journal.stat().st_mode&0o777,0o600)
            return {'outcome':'admission-accepted','admission_code':0}
        with patch.object(p,'dispatch',side_effect=send):r,code=self.call()
        self.assertEqual(code,0,r);self.assertEqual(r['transport']['outcome'],'admission-accepted')
        self.assertFalse(r['execution_confirmed']);self.assertEqual(r['transport_attempts'],1)
        self.assertEqual(self.call('status')[0]['submission_state'],'admission-accepted')
    def test_lost_response_and_repeated_submit_never_retry(self):
        with self.dispatch('unknown',None):r,code=self.call()
        self.assertEqual((code,r['submission_state']),(0,'attempted-outcome-unknown'))
        with patch.object(p,'dispatch',side_effect=AssertionError('second send')):
            self.assertEqual(self.call()[1],1)
            self.journal=self.fixture.data/'different';self.assertEqual(self.call()[1],1)
        self.assertEqual(self.wallet.attempts,1)
    def test_decline_is_not_release_or_execution(self):
        with self.dispatch('admission-refused',9):r,code=self.call()
        self.assertEqual((code,r['submission_state']),(0,'admission-refused'));self.assertFalse(r['execution_confirmed'])
        r,code=self.call('reconcile');self.assertEqual(r['result']['status'],'unresolved-held');self.assertEqual(self.wallet.attempts,1)
    def test_crash_before_marker_is_distinct_and_not_resumed(self):
        with patch.object(self.wallet,'mark_attempt',side_effect=RuntimeError('crash')):r,code=self.call()
        self.assertEqual(code,1);self.assertEqual(self.wallet.attempts,0)
        self.assertEqual(self.call('status')[0]['submission_state'],'prepared-not-attempted')
        with patch.object(p,'dispatch',side_effect=AssertionError('resume')):self.assertEqual(self.call()[1],1)
    def test_crash_after_marker_before_journal_update_does_not_send(self):
        write=p.save
        def fail(path,record,key,*,initial=False):
            if not initial:raise RuntimeError('after durable marker')
            return write(path,record,key,initial=True)
        with patch.object(p,'save',side_effect=fail),patch.object(p,'dispatch',side_effect=AssertionError('send')):r,code=self.call()
        self.assertEqual(code,1);self.assertEqual(self.wallet.attempts,1)
        self.assertEqual(self.call('status')[0]['submission_state'],'attempt-record-incomplete')
        self.assertEqual(self.call()[1],1)
    def test_journal_mac_path_endpoint_and_wallet_wire_binding(self):
        with self.dispatch():self.assertEqual(self.call()[1],0)
        old=self.journal.read_bytes();v=json.loads(old);v['record']['phase']='unknown';self.journal.write_bytes(c.canonical(v))
        self.assertEqual(self.call('status')[1],1);self.journal.write_bytes(old)
        self.endpoint='http://127.0.0.1:12346';self.assertEqual(self.call('status')[1],1);self.endpoint='http://127.0.0.1:12345'
        other=self.fixture.data/'copied';other.write_bytes(old);other.chmod(0o600)
        original=self.journal;self.journal=other;self.assertEqual(self.call('status')[1],1);self.journal=original
        self.wallet.wire=self.wallet.wire[:-1]+bytes([self.wallet.wire[-1]^1]);self.assertEqual(self.call('reconcile')[1],1)
    def test_native_pins_refuse_before_network_and_secret_errors_are_suppressed(self):
        a=self.args();a.genesis_sha256='ef'*32
        with patch.object(p,'dispatch',side_effect=AssertionError('send')):r,code=p.execute(a)
        self.assertEqual(code,1);self.assertFalse(self.journal.exists())
        with patch.object(p,'operate',side_effect=RuntimeError('private-key-never-echo')):r,code=self.call()
        self.assertNotIn(b'private-key-never-echo',c.canonical(r));self.assertTrue(r['reconciliation_required'])
    def test_public_dns_alias_redirect_and_path_endpoints_refuse(self):
        for value in ('https://127.0.0.1:12345','http://localhost:12345','http://192.168.1.2:12345','http://127.0.0.1:01234',
                      'http://127.0.0.1:0','http://127.0.0.1:65536','http://127.0.0.1:12345/','http://u:p@127.0.0.1:12345'):
            with self.subTest(endpoint=value),self.assertRaises(ValueError):p.endpoint_port(value)
    def test_reconcile_requires_wallet_signed_result(self):
        with self.dispatch('unknown',None):self.assertEqual(self.call()[1],0)
        self.wallet.completed=True;r,code=self.call('reconcile')
        self.assertEqual((code,r['result']['status']),(0,'executed-exact'));self.assertTrue(r['execution_confirmed'])
        self.assertEqual(r['transport_attempts'],0)

class LoopbackTransportTests(unittest.TestCase):
    def test_actual_http_deadline_includes_waiting_for_headers(self):
        import time
        seen=[]
        class Slow(BaseHTTPRequestHandler):
            def log_message(self,*args):pass
            def do_POST(self):
                seen.append(self.rfile.read(int(self.headers['Content-Length'])))
                time.sleep(0.6);self.close_connection=True
        server=HTTPServer(('127.0.0.1',0),Slow);thread=threading.Thread(target=server.serve_forever);thread.start()
        started=time.monotonic()
        try:
            with patch.object(p,'TOTAL_RPC_SECONDS',0.1):result=p.dispatch('http://127.0.0.1:'+str(server.server_port),b'wire')
            self.assertLess(time.monotonic()-started,0.5)
        finally:server.shutdown();thread.join();server.server_close()
        self.assertEqual(result,{'outcome':'unknown','admission_code':None});self.assertEqual(len(seen),1)

    def invoke(self,response,status=200):
        seen=[]
        class Handler(BaseHTTPRequestHandler):
            def log_message(self,*args):pass
            def do_POST(self):
                seen.append(self.rfile.read(int(self.headers['Content-Length'])))
                self.send_response(status);self.send_header('Content-Length',str(len(response)));self.end_headers();self.wfile.write(response)
        server=HTTPServer(('127.0.0.1',0),Handler);thread=threading.Thread(target=server.serve_forever);thread.start()
        try:result=p.dispatch('http://127.0.0.1:'+str(server.server_port),b'exact-public-wire')
        finally:server.shutdown();thread.join();server.server_close()
        self.assertEqual(len(seen),1);self.assertEqual(json.loads(seen[0])['method'],'broadcast_tx_sync')
        import base64
        self.assertEqual(base64.b64decode(json.loads(seen[0])['params']['tx']),b'exact-public-wire')
        return result
    def reply(self,**changes):
        result={'code':0,'data':'','log':'','codespace':'','hash':hashlib.sha256(b'exact-public-wire').hexdigest().upper()};result.update(changes)
        return json.dumps({'jsonrpc':'2.0','id':1,'result':result}).encode()
    def test_actual_http_admission_and_decline(self):
        self.assertEqual(self.invoke(self.reply()),{'outcome':'admission-accepted','admission_code':0})
        self.assertEqual(self.invoke(self.reply(code=13)),{'outcome':'admission-refused','admission_code':13})
    def test_actual_http_ambiguous_wrong_hash_redirect_and_oversized_replies(self):
        for response,status in ((b'not-json',200),(self.reply(hash='00'*32),200),(self.reply(code=True),200),
                                (self.reply(),302),(b'x'*9000,200),(b'{"jsonrpc":"2.0","id":1,"id":2,"result":{}}',200)):
            with self.subTest(status=status,bytes=len(response)):self.assertEqual(self.invoke(response,status),{'outcome':'unknown','admission_code':None})

if __name__=='__main__':unittest.main()
