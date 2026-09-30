"""Actual loopback HTTP to synthetic signed-fixture server; not CometBFT."""
import base64
from contextlib import contextmanager
from http.server import BaseHTTPRequestHandler, HTTPServer
import json
from pathlib import Path
import tempfile
import threading
import unittest
from unittest.mock import patch

from block_application import encode
from p4_evidence import nanos
from p4_read_store import P4ReadStore
from p4_rpc import collect, sync_read_store
from p4_fixture import build,bundle


@contextmanager
def rpc(c, height=16, failures=0, fail_block=False, mutate_state=False):
    requests=[];remaining=[failures]
    class Handler(BaseHTTPRequestHandler):
        def log_message(self,*_):pass
        def do_POST(self):
            q=json.loads(self.rfile.read(int(self.headers['Content-Length'])));requests.append(q)
            method=q['method'];error=False
            if method=='abci_query':
                state=json.loads(encode(c['states'][height]))
                if mutate_state:state['native']['accounts'][0][4]+=10000
                result={'response':{'code':0,'height':str(height),'value':base64.b64encode(encode(state)).decode()}}
            elif method=='commit':
                h=int(q['params']['height'])
                if h==height+1 and remaining[0]>0:
                    remaining[0]-=1;error=True;result={'code':-32603,'message':'not yet available'}
                else:result={'signed_header':c['headers'][h-1]['signed_header']}
            elif method=='block':
                h=int(q['params']['height'])
                if fail_block:error=True;result={'code':-1,'message':'missing body'}
                else:
                    sh=c['headers'][h-1]['signed_header']
                    result={'block_id':sh['commit']['block_id'],
                            'block':{'header':sh['header'],'data':{'txs':c['history'][h-1]['txs'] or None}}}
            else:raise AssertionError('Only read requests permitted')
            raw=encode({'jsonrpc':'2.0','id':q['id'],'error' if error else 'result':result})
            self.send_response(200);self.send_header('Content-Type','application/json')
            self.send_header('Content-Length',str(len(raw)));self.end_headers();self.wfile.write(raw)
    server=HTTPServer(('127.0.0.1',0),Handler)
    thread=threading.Thread(target=lambda:server.serve_forever(poll_interval=.03),daemon=True);thread.start()
    try:yield f'http://127.0.0.1:{server.server_port}/',requests
    finally:server.shutdown();server.server_close();thread.join(2)


class RPCTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):cls.c=build()
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory();self.root=Path(self.temp.name)
        self.now=nanos(self.c['headers'][-1]['signed_header']['header']['time'])+2*10**9
        self.s=P4ReadStore(self.root/'read.sqlite',self.c['genesis'],self.c['policy'],create=True,clock=lambda:self.now)
    def tearDown(self):self.s.close();self.temp.cleanup()
    def test_real_read_worker_resolves_pinned_native_with_cleared_pythonpath(self):
        with rpc(self.c) as (url,requests):
            r=sync_read_store(self.s,url,expected_tip=None)
        self.assertEqual(r['state_height'],16);self.assertEqual(r['rpc_requests'],34)
        self.assertFalse(r['broadcast']);self.assertFalse(r['signed'])
        self.assertEqual(self.s.account(self.c['payer'])['account']['recorded_balance'],'874')
        self.assertTrue(all(q['method'] in ('abci_query','commit','block') for q in requests))
    def test_fixed_next_commit_retries_without_recapturing_state(self):
        with rpc(self.c,failures=2) as (url,requests):
            r=sync_read_store(self.s,url,expected_tip=None)
        self.assertEqual(sum(q['method']=='abci_query' for q in requests),1)
        self.assertEqual([q['params']['height'] for q in requests[1:4]],['17']*3)
        self.assertEqual(r['rpc_requests'],36)
    def test_missing_fixed_commit_is_unavailable_not_new_state(self):
        with rpc(self.c,failures=100) as (url,requests),patch('p4_rpc.NEXT_COMMIT_WAIT',0):
            with self.assertRaises(ValueError):collect(url,self.c['genesis'],self.c['policy'],self.now)
        self.assertEqual(len(requests),2);self.assertIsNone(self.s.current())
    def test_node_state_tampering_leaves_old_checkpoint_intact(self):
        first=self.s.import_evidence(bundle(self.c,3),expected_tip=None)
        with rpc(self.c,mutate_state=True) as (url,requests):
            with self.assertRaises(ValueError):sync_read_store(self.s,url,expected_tip=first['evidence_id'])
        self.assertEqual(self.s.current()['state_height'],3)
    def test_unavailable_block_body_refuses_without_partial_import(self):
        with rpc(self.c,fail_block=True) as (url,requests):
            with self.assertRaises(ValueError):sync_read_store(self.s,url,expected_tip=None)
        self.assertIsNone(self.s.current())
    def test_stale_expected_tip_stops_before_network(self):
        self.s.import_evidence(bundle(self.c,3),expected_tip=None)
        with rpc(self.c) as (url,requests):
            with self.assertRaisesRegex(ValueError,'tip changed'):sync_read_store(self.s,url,expected_tip=None)
        self.assertEqual(requests,[])
    def test_expired_policy_stops_before_network(self):
        self.now=nanos(self.c['policy']['anchor_time'])+3600*10**9
        with rpc(self.c) as (url,requests):
            with self.assertRaises(ValueError):sync_read_store(self.s,url,expected_tip=None)
        self.assertEqual(requests,[])
    def test_stale_rpc_checkpoint_cannot_claim_fresh_update(self):
        self.now+=301*10**9
        with rpc(self.c) as (url,requests):
            with self.assertRaisesRegex(ValueError,'freshness'):sync_read_store(self.s,url,expected_tip=None)
        self.assertIsNone(self.s.current())
    def test_public_hostname_tls_and_noncanonical_endpoints_refused(self):
        for url in ('https://127.0.0.1:26657/','http://localhost:26657/','http://example.invalid:26657/',
                    'http://127.0.0.1:26657/submit'):
            with self.subTest(url=url),patch('socket.socket',side_effect=AssertionError('no network')):
                with self.assertRaises(ValueError):sync_read_store(self.s,url,expected_tip=None)
    def test_collection_height_limit_refuses_before_historical_reads(self):
        with rpc(self.c) as (url,requests),patch('p4_rpc.MAX_RPC_HEIGHT',8):
            with self.assertRaises(ValueError):collect(url,self.c['genesis'],self.c['policy'],self.now)
        self.assertEqual(len(requests),1)
    def test_reopened_store_syncs_handover_and_retains_old_evidence(self):
        with rpc(self.c,height=3) as (url,_):first=sync_read_store(self.s,url,expected_tip=None)
        self.s.close();self.s=P4ReadStore(self.root/'read.sqlite',self.c['genesis'],self.c['policy'],clock=lambda:self.now)
        with rpc(self.c) as (url,_):sync_read_store(self.s,url,expected_tip=first['evidence_id'])
        self.assertEqual(self.s.current()['registry_epoch'],2)
        self.assertEqual(self.s.export(first['evidence_id'])['state']['height'],3)


if __name__=='__main__':unittest.main()
