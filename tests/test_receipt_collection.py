"""Real HTTP collection over synthetic committee fixtures, NOT real consensus."""
from contextlib import contextmanager
import base64
import copy
import hashlib
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
import os
from pathlib import Path
import socket
import subprocess
import sys
import tempfile
import threading
import time
import unittest
from unittest.mock import patch

from commit_verifier import encode, sha
from native_core import NativeLedger, public
from payment_transport import DispatchJournal
from receipt_collector import Reader, _request, fetch_packet, attempts
from transport_fixture import fixture, packet, NOW_NS, DEADLINE

ROOT = Path(__file__).resolve().parents[1]


@contextmanager
def rpc_fixture(*, proof=None, mode='', delayed_commit=0, ledger_path=None):
    proof = copy.deepcopy(packet() if proof is None else proof)
    seen = []; missing_commits = [delayed_commit]; executed = [False]
    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *args): pass
        def do_POST(self):
            req = json.loads(self.rfile.read(int(self.headers['Content-Length'])))
            seen.append(req)
            method = req['method']; params = req['params']
            if mode == 'stall': time.sleep(2); return
            if method == 'broadcast_tx_sync':
                raw = base64.b64decode(params['tx'], validate=True)
                ledger = NativeLedger(ledger_path, fixture()[2])
                ledger.apply(json.loads(raw),height=1); ledger.close(); executed[0]=True
                self.connection.shutdown(socket.SHUT_RDWR); self.connection.close(); return
            result = None; error = False
            if method == 'abci_query':
                if mode == 'wait_for_actual_payment' and not executed[0]:
                    state = copy.deepcopy(proof['state']); state['native']['receipts']=[]
                else:
                    state = proof['state']
                result = {'response':{'code':0,'height':str(state['height']),
                          'value':base64.b64encode(encode(state)).decode(),'log':''}}
                if mode == 'height_mismatch': result['response']['height']='2'
                if mode == 'boolean_code': result['response']['code']=False
                if mode == 'nonzero_query_code': result['response']['code']=1
                if mode == 'duplicate_receipt':
                    state=copy.deepcopy(state);state['native']['receipts']*=2
                    result['response']['value']=base64.b64encode(encode(state)).decode()
            elif method == 'block':
                result = copy.deepcopy(proof['transactions'][0]['block'])
                if mode == 'wrong_block_data': result['block']['data']['txs']=[]
            elif method == 'commit':
                height=int(params['height'])
                if height == 1:
                    signed = proof['transactions'][0]['commit']
                else:
                    signed = proof['state_commit']
                    if missing_commits[0] > 0:
                        missing_commits[0]-=1; error=True
                    if mode == 'same_height_commit': signed=proof['transactions'][0]['commit']
                result={'signed_header':signed,'canonical':False}
            else:
                error=True
            if mode == 'rpc_error': error=True
            message={'jsonrpc':'2.0','id':req['id']}
            message.update({'error':{'code':-32603,'message':'fixture has no evidence yet'}} if error else {'result':result})
            if mode=='wrong_id':message['id']+=1
            if mode=='boolean_id':message['id']=True
            if mode=='wrong_jsonrpc':message['jsonrpc']='1.0'
            data=encode(message)
            if mode=='duplicate_json':data=b'{"jsonrpc":"2.0","id":1,"id":1,"result":{}}'
            if mode=='invalid_json':data=b'not-json'
            if mode=='redirect':
                self.send_response(302);self.send_header('Location','http://example.invalid/never');self.end_headers();return
            self.send_response(200)
            self.send_header('Content-Type','text/html' if mode=='wrong_type' else 'application/json')
            size=len(data)+(10 if mode=='truncated' else 0)
            if mode=='oversize_header':size=8*1024*1024+1
            self.send_header('Content-Length',str(size))
            if mode=='duplicate_length':self.send_header('Content-Length',str(size))
            if mode=='ambiguous_framing':self.send_header('Transfer-Encoding','chunked')
            if mode=='compressed':self.send_header('Content-Encoding','gzip')
            self.end_headers()
            try:self.wfile.write(data)
            except OSError:pass
    server=ThreadingHTTPServer(('127.0.0.1',0),Handler)
    server.daemon_threads=True;server.block_on_close=False
    thread=threading.Thread(target=lambda:server.serve_forever(poll_interval=.01),daemon=True);thread.start()
    try:yield f'http://127.0.0.1:{server.server_port}/',seen
    finally:server.shutdown();server.server_close();thread.join(timeout=2)


class CollectionTests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory();self.root=Path(self.tmp.name)
        self.owner,_,self.native,self.engine,_,_,self.raw=fixture()
        self.genesis=encode(self.engine);self.digest=sha(self.genesis).hex();self.now=NOW_NS
        self.j=None
    def tearDown(self):
        if self.j:self.j.close()
        self.tmp.cleanup()
    def open(self,url):
        if self.j:self.j.close()
        self.j=DispatchJournal(self.root/'j.sqlite',self.genesis,self.digest,url,DEADLINE,clock=lambda:self.now)
        return self.j.queue(self.raw,public(self.owner))
    def test_reads_exact_rpc_methods_then_verifies_specific_payment(self):
        with rpc_fixture() as (url,seen):
            row=self.open(url);out=self.j.refresh_receipt(row['native_txid'])
            self.assertTrue(out['receipt_verified']);self.assertEqual(out['read_requests'],4)
            self.assertEqual([r['method'] for r in seen],['abci_query','block','commit','commit'])
            self.assertEqual(seen[0]['params'],{'path':'/state','prove':False})
            self.assertEqual([r['params']['height'] for r in seen[1:]],['1','1','2'])
            self.assertFalse(out['live_network_provenance_established'])
    def test_refresh_never_broadcasts_or_replays(self):
        with rpc_fixture() as (url,seen),patch('payment_transport._worker',side_effect=AssertionError('no broadcast')):
            row=self.open(url);out=self.j.refresh_receipt(row['native_txid'])
            self.assertEqual(out['attempts'],0)
            self.assertNotIn('broadcast_tx_sync',[r['method'] for r in seen])
    def test_untrusted_worker_success_must_be_reverified(self):
        with rpc_fixture() as (url,seen):
            row=self.open(url)
            with patch('receipt_collector.fetch_packet',return_value={'status':'evidence_collected','packet':{},'requests':4}):
                out=self.j.refresh_receipt(row['native_txid'])
            self.assertEqual(out['collection_status'],'evidence_rejected');self.assertFalse(out['receipt_verified'])
            self.assertEqual(out['status'],'queued');self.assertEqual(seen,[])
    def test_missing_receipt_is_not_failure_or_nonpayment_proof(self):
        proof=packet();proof['state']['native']['receipts']=[]
        with rpc_fixture(proof=proof) as (url,seen):
            row=self.open(url);out=self.j.refresh_receipt(row['native_txid'])
            self.assertEqual(out['collection_status'],'evidence_unavailable')
            self.assertEqual(out['status'],'queued');self.assertEqual(len(seen),1)
            self.assertEqual(self.j.export(row['native_txid']),self.raw)
    def test_lost_broadcast_response_then_read_only_receipt_recovery(self):
        with rpc_fixture(mode='wait_for_actual_payment',ledger_path=self.root/'executed.sqlite') as (url,seen):
            row=self.open(url)
            self.assertFalse(self.j.refresh_receipt(row['native_txid'])['receipt_verified'])
            out=self.j.dispatch(row['native_txid'],row['dispatch_confirmation'])
            self.assertEqual(out['status'],'unresolved')
            out=self.j.refresh_receipt(row['native_txid'])
            self.assertEqual(out['status'],'receipt_verified')
            self.assertEqual(sum(r['method']=='broadcast_tx_sync' for r in seen),1)
            ledger=NativeLedger(self.root/'executed.sqlite',self.native)
            self.assertEqual(ledger.verify_receipts(),True);ledger.close()
    def test_success_survives_restart_without_more_reads(self):
        with rpc_fixture() as (url,seen):
            row=self.open(url);self.j.refresh_receipt(row['native_txid']);count=len(seen)
            self.open(url);out=self.j.refresh_receipt(row['native_txid'])
            self.assertEqual(out['collection_status'],'already_verified');self.assertEqual(len(seen),count)
    def test_refresh_of_verified_payment_never_contacts_dead_server(self):
        with rpc_fixture() as (url,seen):
            row=self.open(url);self.j.refresh_receipt(row['native_txid'])
        out=self.j.refresh_receipt(row['native_txid']);self.assertEqual(out['read_requests'],0)
    def test_forged_validator_signature_does_not_mark_paid(self):
        proof=packet();proof['state_commit']['commit']['signatures'][0]['signature']=base64.b64encode(bytes(64)).decode()
        with rpc_fixture(proof=proof) as (url,seen):
            row=self.open(url);out=self.j.refresh_receipt(row['native_txid'])
            self.assertEqual(out['collection_status'],'evidence_rejected');self.assertEqual(out['status'],'queued')
    def test_altered_account_snapshot_does_not_mark_paid(self):
        proof=packet();proof['state']['native']['accounts'][0][4]+=1
        with rpc_fixture(proof=proof) as (url,_):
            row=self.open(url);out=self.j.refresh_receipt(row['native_txid'])
            self.assertFalse(out['receipt_verified']);self.assertEqual(out['collection_status'],'evidence_rejected')
    def test_same_height_state_certificate_refused(self):
        with rpc_fixture(mode='same_height_commit') as (url,_):
            row=self.open(url);self.assertFalse(self.j.refresh_receipt(row['native_txid'])['receipt_verified'])
    def test_wrong_block_transaction_list_refused(self):
        with rpc_fixture(mode='wrong_block_data') as (url,_):
            row=self.open(url);self.assertEqual(self.j.refresh_receipt(row['native_txid'])['collection_status'],'evidence_rejected')
    def test_other_chain_certificate_refused(self):
        proof=packet();proof['state_commit']['header']['chain_id']='other'
        with rpc_fixture(proof=proof) as (url,_):
            row=self.open(url);self.assertFalse(self.j.refresh_receipt(row['native_txid'])['receipt_verified'])
    def test_inconsistent_query_height_refused(self):
        with rpc_fixture(mode='height_mismatch') as (url,seen):
            row=self.open(url);out=self.j.refresh_receipt(row['native_txid'])
            self.assertEqual(out['collection_status'],'evidence_rejected');self.assertEqual(len(seen),1)
    def test_duplicate_receipt_hint_refused(self):
        with rpc_fixture(mode='duplicate_receipt') as (url,seen):
            row=self.open(url);out=self.j.refresh_receipt(row['native_txid'])
            self.assertEqual(out['collection_status'],'evidence_rejected');self.assertEqual(len(seen),1)
    def test_nonzero_query_code_does_not_assert_nonexecution(self):
        with rpc_fixture(mode='nonzero_query_code') as (url,_):
            row=self.open(url);out=self.j.refresh_receipt(row['native_txid'])
            self.assertEqual(out['status'],'queued');self.assertEqual(out['collection_status'],'evidence_unavailable')
    def test_default_has_no_read_retries(self):
        with rpc_fixture(delayed_commit=2) as (url,seen):
            row=self.open(url);out=self.j.refresh_receipt(row['native_txid'])
            self.assertEqual(out['collection_status'],'evidence_unavailable');self.assertEqual(len(seen),4)
    def test_explicit_read_wait_keeps_same_state_checkpoint(self):
        with rpc_fixture(delayed_commit=2) as (url,seen):
            row=self.open(url);out=self.j.refresh_receipt(row['native_txid'],read_attempts=3)
            self.assertTrue(out['receipt_verified']);self.assertEqual(len(seen),6)
            self.assertEqual(sum(r['method']=='abci_query' for r in seen),1)
            self.assertEqual([r['params']['height'] for r in seen[-3:]],['2']*3)
    def test_read_wait_has_hard_attempt_bound(self):
        with rpc_fixture(delayed_commit=100) as (url,seen):
            row=self.open(url);out=self.j.refresh_receipt(row['native_txid'],read_attempts=4)
            self.assertFalse(out['receipt_verified']);self.assertEqual(len(seen),7)
    def test_invalid_attempt_values_do_not_contact_endpoint(self):
        with rpc_fixture() as (url,seen):
            row=self.open(url)
            for value in [True,False,0,5,-1,1.0,'2']:
                with self.subTest(value=value),self.assertRaises(ValueError):self.j.refresh_receipt(row['native_txid'],read_attempts=value)
            self.assertEqual(seen,[])
    def test_expired_trust_stops_reads_before_io(self):
        with rpc_fixture() as (url,seen):
            row=self.open(url);self.now+=2*86400*10**9
            with self.assertRaises(ValueError):self.j.refresh_receipt(row['native_txid'])
            self.assertEqual(seen,[])
    def test_clock_rollback_stops_reads_before_io(self):
        with rpc_fixture() as (url,seen):
            row=self.open(url);self.now-=1
            with self.assertRaises(ValueError):self.j.refresh_receipt(row['native_txid'])
            self.assertEqual(seen,[])
    def test_expiry_during_collection_still_prevents_proof_acceptance(self):
        with rpc_fixture() as (url,seen):
            row=self.open(url)
            def delayed(*args,**kwargs):
                self.now+=2*86400*10**9
                return {'status':'evidence_collected','packet':packet(),'requests':4}
            with patch('receipt_collector.fetch_packet',side_effect=delayed):out=self.j.refresh_receipt(row['native_txid'])
            self.assertEqual(out['collection_status'],'evidence_rejected');self.assertFalse(out['receipt_verified'])
    def test_wrong_body_in_receipt_hint_refused_before_block_reads(self):
        proof=packet();row=proof['state']['native']['receipts'][0];record=json.loads(row[3]);record['envelope']['body']['op']['units']+=1;row[3]=encode(record).decode()
        with rpc_fixture(proof=proof) as (url,seen):
            row=self.open(url);out=self.j.refresh_receipt(row['native_txid'])
            self.assertEqual(out['collection_status'],'evidence_rejected');self.assertEqual(len(seen),1)
    def test_negative_receipt_height_cannot_control_request(self):
        proof=packet();row=proof['state']['native']['receipts'][0];record=json.loads(row[3]);record['height']=-1;row[3]=encode(record).decode()
        with rpc_fixture(proof=proof) as (url,seen):
            row=self.open(url);out=self.j.refresh_receipt(row['native_txid'])
            self.assertFalse(out['receipt_verified']);self.assertEqual(len(seen),1)
    def test_invalid_http_or_rpc_responses_never_verify(self):
        for mode in ['wrong_id','boolean_id','wrong_jsonrpc','boolean_code','duplicate_json','invalid_json',
                     'oversize_header','wrong_type','duplicate_length','ambiguous_framing','compressed','truncated','redirect']:
            with self.subTest(mode=mode),rpc_fixture(mode=mode) as (url,seen):
                out=fetch_packet(url,self.raw)
                self.assertNotEqual(out['status'],'evidence_collected');self.assertEqual(len(seen),1)
    def test_endpoint_rpc_errors_do_not_trigger_unbounded_retries(self):
        with rpc_fixture(mode='rpc_error') as (url,seen):
            out=fetch_packet(url,self.raw,read_attempts=4)
            self.assertEqual(out['status'],'evidence_unavailable');self.assertEqual(len(seen),1)
    def test_no_hostname_redirect_or_public_endpoint_allowed(self):
        for url in ['http://localhost:26657/','https://127.0.0.1:26657/','http://example.com:26657/','http://127.0.0.1:26657/?query=1']:
            with self.subTest(url=url),self.assertRaises(ValueError):fetch_packet(url,self.raw)
    def test_method_allowlist_cannot_broadcast_or_query_arbitrary_path(self):
        for method,height in [('broadcast_tx_sync',None),('genesis',None),('abci_query',1),('status',None),('block','1'),('commit',True)]:
            with self.subTest(method=method,height=height),self.assertRaises(ValueError):_request(method,height)
    def test_hostile_proxy_environment_is_ignored(self):
        with rpc_fixture() as (url,seen),patch.dict(os.environ,{'HTTP_PROXY':'http://example.invalid:1','HTTPS_PROXY':'http://example.invalid:1','ALL_PROXY':'http://example.invalid:1','NO_PROXY':''}):
            row=self.open(url);self.assertTrue(self.j.refresh_receipt(row['native_txid'])['receipt_verified'])
    def test_worker_has_total_deadline(self):
        with rpc_fixture(mode='stall') as (url,seen),patch('receipt_collector.WORKER_TIMEOUT',.3):
            start=time.monotonic();out=fetch_packet(url,self.raw)
            self.assertLess(time.monotonic()-start,1.5);self.assertEqual(out['reason'],'worker_deadline_or_failure')
    def test_crash_after_read_before_verification_leaves_payment_unresolved(self):
        with rpc_fixture() as (url,seen):
            row=self.open(url);self.j.close();self.j=None
            (self.root/'genesis.json').write_bytes(self.genesis)
            code='''from pathlib import Path
import os,sys
from payment_transport import DispatchJournal
import receipt_collector as r
original=r.fetch_packet
def crash(*args,**kwargs):
 original(*args,**kwargs)
 os._exit(31)
r.fetch_packet=crash
with DispatchJournal(Path(sys.argv[1]),Path(sys.argv[2]).read_bytes(),sys.argv[3],sys.argv[4],sys.argv[5],clock=lambda:int(sys.argv[7])) as j:
 j.refresh_receipt(sys.argv[6])
'''
            out=subprocess.run([sys.executable,'-c',code,str(self.root/'j.sqlite'),str(self.root/'genesis.json'),self.digest,url,DEADLINE,row['native_txid'],str(self.now)],env=dict(os.environ,PYTHONPATH=str(ROOT/'src')),capture_output=True,timeout=8)
            self.assertEqual(out.returncode,31,out.stderr);self.open(url)
            self.assertEqual(self.j.status(row['native_txid'])['status'],'queued')
            self.assertEqual(self.j.status(row['native_txid'])['attempts'],0)
            self.assertTrue(self.j.refresh_receipt(row['native_txid'])['receipt_verified'])
    def test_refresh_events_distinguish_read_from_dispatch(self):
        with rpc_fixture() as (url,_):
            row=self.open(url);self.j.refresh_receipt(row['native_txid'])
            names=[e['event'] for e in self.j.events(row['native_txid'])]
            self.assertIn('receipt_collection_requested',names);self.assertIn('native_receipt_verified',names)
            self.assertNotIn('dispatch_committed_before_io',names)
    def test_export_collected_proof_verifies_independently(self):
        from commit_verifier import verify_packet, pinned_genesis
        with rpc_fixture() as (url,seen):
            row=self.open(url);self.j.refresh_receipt(row['native_txid']);count=len(seen)
            proof=self.j.export_receipt(row['native_txid'])
            result=verify_packet(json.loads(proof),pinned_genesis(self.genesis,self.digest),expected_txids=[row['native_txid']])
            self.assertEqual(result['status'],'verified');self.assertEqual(len(seen),count)
    def test_cannot_export_a_receipt_that_was_never_verified(self):
        with rpc_fixture() as (url,seen):
            row=self.open(url)
            with self.assertRaises(ValueError):self.j.export_receipt(row['native_txid'])
            self.assertEqual(seen,[])
    def test_historical_proof_export_remains_available_after_trust_expiry(self):
        with rpc_fixture() as (url,seen):
            row=self.open(url);self.j.refresh_receipt(row['native_txid']);proof=self.j.export_receipt(row['native_txid'])
            self.now+=2*86400*10**9
            self.assertEqual(self.j.export_receipt(row['native_txid']),proof)
    def test_export_rejects_corrupted_stored_proof(self):
        with rpc_fixture() as (url,seen):
            row=self.open(url);self.j.refresh_receipt(row['native_txid'])
            self.j.db.execute('UPDATE payments SET proof=?',(b'{}',))
            with self.assertRaises(ValueError):self.j.export_receipt(row['native_txid'])

    def test_cli_refresh_collects_without_certificate_argument(self):
        # The CLI uses the real clock, unlike the other historical fixture
        # tests. Give this test a fresh policy while keeping expiry enforced.
        deadline=time.strftime('%Y-%m-%dT%H:%M:%SZ',time.gmtime(max(time.time(),self.now/1_000_000_000)+86400))
        with patch(f'{__name__}.DEADLINE',deadline),rpc_fixture() as (url,seen):
            row=self.open(url);self.j.close();self.j=None;(self.root/'genesis.json').write_bytes(self.genesis)
            # Reopen under the same pinned policy; no live-network provenance claim.
            out=subprocess.run([sys.executable,str(ROOT/'scripts/payment_dispatch.py'),'--genesis',str(self.root/'genesis.json'),
                '--genesis-sha256',self.digest,'--journal',str(self.root/'j.sqlite'),'--endpoint',url,
                '--trust-expires-utc',DEADLINE,'refresh','--txid',row['native_txid']],capture_output=True,text=True,timeout=8)
            self.assertEqual(out.returncode,0,out.stderr);self.assertTrue(json.loads(out.stdout)['receipt_verified'])
            self.assertEqual([r['method'] for r in seen],['abci_query','block','commit','commit'])


if __name__=='__main__':unittest.main()
