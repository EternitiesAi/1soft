import base64
from contextlib import contextmanager
import http.client
from http.server import HTTPServer,BaseHTTPRequestHandler
import json
from pathlib import Path
import tempfile
import threading
import unittest
from unittest.mock import patch

from commit_verifier import encode
from explorer_index import ExplorerIndex,ns
from explorer_rpc import collect,refresh
from explorer_web import server
from fixture_explorer import scenario,bundle,pin

@contextmanager
def rpc(c,height=12,fail_commits=0,fail_blocks=False):
    requests=[];fail=[fail_commits]
    class Handler(BaseHTTPRequestHandler):
        def log_message(self,*_):pass
        def do_POST(self):
            q=json.loads(self.rfile.read(int(self.headers['Content-Length'])));requests.append(q)
            if q['method']=='abci_query':
                state=c['states'][height];result={'response':{'code':0,'height':str(height),'value':base64.b64encode(encode(state)).decode()}}
            elif q['method']=='commit':
                h=int(q['params']['height'])
                if h==height+1 and fail[0]>0:
                    fail[0]-=1;self._reply({'jsonrpc':'2.0','id':q['id'],'error':{'code':-1}});return
                result={'signed_header':c['headers'][h]}
            elif q['method']=='block':
                if fail_blocks:self._reply({'jsonrpc':'2.0','id':q['id'],'error':{'code':-1}});return
                result=c['blocks'][int(q['params']['height'])]
            else:raise AssertionError('Unexpected non-read RPC')
            self._reply({'jsonrpc':'2.0','id':q['id'],'result':result})
        def _reply(self,value):
            raw=encode(value);self.send_response(200);self.send_header('Content-Type','application/json')
            self.send_header('Content-Length',str(len(raw)));self.end_headers();self.wfile.write(raw)
    http=HTTPServer(('127.0.0.1',0),Handler);thread=threading.Thread(target=http.serve_forever,daemon=True);thread.start()
    try:yield f'http://127.0.0.1:{http.server_port}/',requests
    finally:http.shutdown();http.server_close();thread.join(2)

class NetworkTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):cls.c=scenario()
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory();self.root=Path(self.tmp.name);self.path=self.root/'index.sqlite'
        self.x=ExplorerIndex(self.path,self.c['genesis'],self.c['genesis_sha256'],create=True)
    def tearDown(self):self.x.close();self.tmp.cleanup()
    def clock(self,h=12):return ns(self.c['headers'][h+1]['header']['time'])+1000000000
    def test_real_loopback_collection_and_index_update(self):
        with rpc(self.c) as (endpoint,reads):r=refresh(self.x,endpoint,initial_header_hash=pin(self.c,12),clock=self.clock)
        self.assertEqual(r['state_height'],12);self.assertFalse(r['broadcast'])
        self.assertTrue(all(q['method'] in ('abci_query','commit','block') for q in reads))
    def test_fixed_height_commit_retry_captures_state_once(self):
        with rpc(self.c,fail_commits=2) as (endpoint,reads):r=refresh(self.x,endpoint,initial_header_hash=pin(self.c,12),clock=self.clock)
        self.assertEqual(sum(r['method']=='abci_query' for r in reads),1)
        self.assertEqual([q['params']['height'] for q in reads[1:4]],['13']*3)
        self.assertEqual(r['rpc_requests'],len(reads))
    def test_missing_fixed_commit_leaves_no_partial_index(self):
        with rpc(self.c,fail_commits=4) as (endpoint,reads):
            with self.assertRaises(ValueError):refresh(self.x,endpoint,initial_header_hash=pin(self.c,12),clock=self.clock)
        self.assertEqual(len(reads),5);self.assertIsNone(self.x.current())
    def test_block_read_failure_leaves_existing_index_unchanged(self):
        self.x.ingest(bundle(self.c,6),initial_header_hash=pin(self.c,6))
        with rpc(self.c,fail_blocks=True) as (endpoint,reads):
            with self.assertRaises(ValueError):refresh(self.x,endpoint,clock=self.clock)
        self.assertEqual(self.x.current()['state_height'],6)
    def test_refresh_continues_old_header_without_reset(self):
        self.x.ingest(bundle(self.c,12),initial_header_hash=pin(self.c,12))
        with rpc(self.c,height=24) as (endpoint,reads):r=refresh(self.x,endpoint,clock=lambda:self.clock(24))
        self.assertEqual(r['state_height'],24);self.assertEqual(self.x.current()['indexed_block_count'],24)
    def test_public_or_hostname_endpoint_refused_before_io(self):
        for endpoint in ('http://example.com:26657/','http://localhost:26657/','https://127.0.0.1:26657/'):
            with self.assertRaises(ValueError):refresh(self.x,endpoint,initial_header_hash=pin(self.c,12))
        self.assertIsNone(self.x.current())
    def test_no_initial_pin_means_no_rpc_reads(self):
        with rpc(self.c) as (endpoint,reads):
            with self.assertRaises(ValueError):refresh(self.x,endpoint)
        self.assertEqual(reads,[])
    def test_stale_refresh_is_not_accepted_as_current(self):
        with rpc(self.c) as (endpoint,reads):
            with self.assertRaises(ValueError):refresh(self.x,endpoint,initial_header_hash=pin(self.c,12),clock=lambda:self.clock()+301*10**9)
        self.assertIsNone(self.x.current())
    def test_commit_published_half_second_after_state_is_retrieved_at_fixed_height(self):
        # Deterministic model of the existing 500 ms block interval, not a
        # validator run or a wall-clock timing assertion. State is read once.
        from receipt_collector import Unavailable
        elapsed=[0.0]; requests=[]
        c=self.c
        class DelayedReader:
            def __init__(self,endpoint):pass
            def call(self,method,height=None):
                requests.append((method,height))
                if method=='abci_query':
                    return {'response':{'code':0,'height':'12',
                        'value':base64.b64encode(encode(c['states'][12])).decode()}}
                if method=='commit':
                    if height==13 and elapsed[0]<0.5:
                        raise Unavailable('fixture_next_commit_not_yet_published')
                    return {'signed_header':c['headers'][height]}
                if method=='block':return c['blocks'][height]
                raise AssertionError('unexpected method')
        def sleep(seconds):elapsed[0]+=seconds
        with patch('explorer_rpc.Reader',DelayedReader),patch('explorer_rpc.time.sleep',side_effect=sleep):
            result=collect('http://127.0.0.1:26657/',0)
        self.assertEqual(result['status'],'collected')
        self.assertEqual([r for r in requests if r[0]=='abci_query'],[('abci_query',None)])
        target_reads=[r for r in requests if r==('commit',13)]
        self.assertLessEqual(len(target_reads),4)
        self.assertGreaterEqual(elapsed[0],0.5)
        self.assertLessEqual(elapsed[0],0.75)
        self.assertEqual(result['evidence']['state']['height'],12)
        self.assertEqual(result['rpc_requests'],len(requests))

    def test_preview_data_uses_real_native_execution(self):
        self.x.ingest(bundle(self.c,24),initial_header_hash=pin(self.c,24));v=self.x.current()
        self.assertEqual(v['transaction_count'],len(self.c['states'][24]['native']['receipts']))
        self.assertEqual(self.c['old_block_status'],2)
        self.assertTrue(all(t['block_inclusion_verified'] for t in v['transactions']))

class ViewerTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):cls.c=scenario(blocks=8)
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory();self.path=Path(self.tmp.name)/'index.sqlite'
        self.x=ExplorerIndex(self.path,self.c['genesis'],self.c['genesis_sha256'],create=True)
        self.x.ingest(bundle(self.c),initial_header_hash=pin(self.c))
        self.http=server(self.path,self.c['genesis'],self.c['genesis_sha256'])
        self.thread=threading.Thread(target=self.http.serve_forever,daemon=True);self.thread.start()
    def tearDown(self):self.http.shutdown();self.http.server_close();self.thread.join(2);self.x.close();self.tmp.cleanup()
    def ask(self,path,method='GET',headers=None):
        c=http.client.HTTPConnection('127.0.0.1',self.http.server_port,timeout=5)
        try:
            c.request(method,path,headers=headers or {});r=c.getresponse();return r.status,r.read(),dict(r.getheaders())
        finally:c.close()
    def test_http_view_matches_reverified_state(self):
        status,data,h=self.ask('/api/view');self.assertEqual(status,200)
        self.assertEqual(json.loads(data),self.x.current());self.assertEqual(h['Cache-Control'],'no-store')
    def test_html_served_with_content_security_policy(self):
        status,data,h=self.ask('/');self.assertEqual(status,200)
        self.assertIn('1soft',data.decode());self.assertIn("default-src 'none'",h['Content-Security-Policy'])
        self.assertEqual(h['X-Frame-Options'],'DENY')
    def test_cross_origin_and_wrong_host_refused(self):
        self.assertEqual(self.ask('/api/view',headers={'Host':'evil.example'})[0],403)
        self.assertEqual(self.ask('/api/view',headers={'Origin':'https://evil.example'})[0],403)
    def test_post_and_wallet_or_path_routes_unavailable(self):
        self.assertEqual(self.ask('/api/view',method='POST')[0],405)
        self.assertEqual(self.ask('/broadcast_tx_sync',method='POST')[0],405)
        self.assertEqual(self.ask('/../../etc/passwd')[0],404)
    def test_bad_index_returns_unavailable_not_empty_balances(self):
        self.x.db.execute("UPDATE current SET view=x'7b7d'")
        status,data,_=self.ask('/api/view');self.assertEqual(status,503)
        self.assertFalse(json.loads(data)['payment_outcome_inferred'])
    def test_evidence_export_has_no_wallet_or_private_key(self):
        status,data,_=self.ask('/api/evidence');self.assertEqual(status,200)
        self.assertEqual(json.loads(data),self.x.evidence())
        self.assertNotIn(b'private_key',data);self.assertNotIn(b'password',data)

if __name__=='__main__':unittest.main()
