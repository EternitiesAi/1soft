"""Diagnostic observations, not payment evidence. Disposable local fixtures only."""
import copy
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

from refresh_trace import (RefreshTrace, TraceError, recorded_refresh, read_trace,
                           public_result, validate_event, wire)
from wallet_refresh import refresh_wallet, RefreshObserverError
import test_client as fixture_module
from test_client import rpc
from commit_verifier import encode

ROOT = Path(__file__).resolve().parents[1]


def start(trace):
    trace.record('started', {'started_ns': 100, 'max_batches': 2, 'headers_per_batch': 64})


def outcome(status='unavailable'):
    return {'status': status, 'state_synced': status == 'synced', 'headers_accepted': 0,
            'batches_committed': 0, 'rpc_attempts': None, 'request_bound': 133,
            'target_header_height': 5 if status == 'synced' else None,
            'state_header_height': 5 if status == 'synced' else None,
            'verified_header_height': None}


class TraceStorageTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(); self.root = Path(self.tmp.name); self.path = self.root/'run'
    def tearDown(self): self.tmp.cleanup()
    def test_completed_diagnostic_is_not_financial_evidence(self):
        with RefreshTrace(self.path) as t:
            start(t); t.record('completed', outcome())
        r=read_trace(self.path)
        self.assertEqual(r['recording_status'],'completed');self.assertEqual(r['outcome']['status'],'unavailable')
        self.assertIs(r['financial_authority'],False);self.assertIs(r['wallet_state_inferred'],False)
    def test_private_file_and_directory(self):
        with RefreshTrace(self.path) as t: start(t)
        self.assertEqual(self.path.stat().st_mode&0o777,0o700)
        self.assertEqual((self.path/'events.jsonl').stat().st_mode&0o777,0o600)
    def test_no_terminal_record_means_unknown(self):
        with RefreshTrace(self.path) as t: start(t)
        r=read_trace(self.path);self.assertEqual(r['recording_status'],'incomplete');self.assertIsNone(r['outcome'])
    def test_partial_last_record_is_not_an_outcome(self):
        with RefreshTrace(self.path) as t: start(t)
        with (self.path/'events.jsonl').open('ab') as f: f.write(b'{"event":"completed"')
        r=read_trace(self.path);self.assertTrue(r['partial_tail']);self.assertIsNone(r['outcome'])
    def test_existing_directory_is_never_overwritten(self):
        with RefreshTrace(self.path) as t: start(t)
        before=(self.path/'events.jsonl').read_bytes()
        with self.assertRaises(FileExistsError):RefreshTrace(self.path)
        self.assertEqual((self.path/'events.jsonl').read_bytes(),before)
    def test_cannot_append_after_completion(self):
        with RefreshTrace(self.path) as t:
            start(t);t.record('completed',outcome())
            with self.assertRaises(TraceError):t.record('state_synced',{'height':1})
    def test_data_after_terminal_record_is_invalid(self):
        with RefreshTrace(self.path) as t: start(t);t.record('completed',outcome())
        with (self.path/'events.jsonl').open('ab') as f:f.write(b'x')
        with self.assertRaises(TraceError):read_trace(self.path)
    def test_corrupted_hash_is_rejected(self):
        with RefreshTrace(self.path) as t: start(t)
        p=self.path/'events.jsonl';p.write_bytes(p.read_bytes().replace(b'"started_ns":100',b'"started_ns":101'))
        with self.assertRaises(TraceError):read_trace(self.path)
    def test_reordered_records_are_rejected(self):
        with RefreshTrace(self.path) as t:start(t);t.record('local_ready',{'height':1})
        p=self.path/'events.jsonl';lines=p.read_bytes().splitlines(keepends=True);p.write_bytes(b''.join(reversed(lines)))
        with self.assertRaises(TraceError):read_trace(self.path)
    def test_symlink_file_is_refused(self):
        with RefreshTrace(self.path) as t:start(t)
        p=self.path/'events.jsonl';p.rename(self.path/'saved');p.symlink_to('saved')
        with self.assertRaises(OSError):read_trace(self.path)
    def test_hardlink_file_is_refused(self):
        with RefreshTrace(self.path) as t:start(t)
        os.link(self.path/'events.jsonl',self.root/'link')
        with self.assertRaises(TraceError):read_trace(self.path)
    def test_group_readable_file_is_refused(self):
        with RefreshTrace(self.path) as t:start(t)
        (self.path/'events.jsonl').chmod(0o640)
        with self.assertRaises(TraceError):read_trace(self.path)
    def test_symlink_parent_is_refused(self):
        (self.root/'alias').symlink_to(self.root,target_is_directory=True)
        with self.assertRaises(TraceError):RefreshTrace(self.root/'alias'/'new')
    def test_payloads_paths_and_keys_are_not_valid_diagnostic_fields(self):
        for data in ({'height':1,'password':'sensitive'}, {'height':1,'packet':{}}, {'height':1,'endpoint':'private'}):
            with self.subTest(data=data),self.assertRaises(TraceError):validate_event('target_verified',data)
    def test_outcome_sanitizes_private_wallet_data(self):
        r=outcome();r.update(pending_account_units={'secret-account':60},inventory_digest='secret',password='secret')
        self.assertNotIn('secret',json.dumps(public_result(r)))
    def test_inconsistent_or_nonboolean_success_is_refused(self):
        for r in ({**outcome(),'state_synced':True},{**outcome(),'state_synced':1},{**outcome(),'status':{}}):
            with self.assertRaises(TraceError):public_result(r)
    def test_terminal_fsync_failure_cannot_return_success(self):
        t=RefreshTrace(self.path);start(t)
        with patch('refresh_trace.os.fsync',side_effect=OSError('disk')):
            with self.assertRaises(OSError):t.record('completed',outcome())
        self.assertTrue(t.failed);t.close()
    def test_maximum_event_count_is_enforced(self):
        with RefreshTrace(self.path) as t:
            start(t)
            with patch('refresh_trace.MAX_EVENTS',1):
                with self.assertRaises(TraceError):t.record('local_ready',{'height':1})
    def test_standalone_inspection_requires_no_native_dependency(self):
        with RefreshTrace(self.path) as t:start(t);t.record('completed',outcome())
        env={**os.environ,'PYTHONPATH':''}
        p=subprocess.run([sys.executable,str(ROOT/'scripts/inspect_refresh.py'),str(self.path)],env=env,capture_output=True,text=True,timeout=5)
        self.assertEqual(p.returncode,0,p.stderr);self.assertIsNone(json.loads(p.stdout)['outcome']['rpc_attempts'])
    def test_empty_created_trace_is_unknown(self):
        with RefreshTrace(self.path):pass
        self.assertEqual(read_trace(self.path)['recording_status'],'incomplete')


class TraceIntegrationTests(unittest.TestCase):
    def setUp(self):
        self.f=fixture_module.ClientTests();self.f.setUp();self.c=self.f.c;self.path=self.c.root/'run-record'
    def tearDown(self):self.f.tearDown()
    def held(self):return self.f.held()
    def test_success_saved_before_callers_assertion(self):
        with rpc(self.c.witness,self.f.headers) as (url,reads):
            r=recorded_refresh(self.c.wallet,url,self.path)
            # The caller can fail immediately afterwards without losing the return.
            with self.assertRaises(AssertionError):self.assertFalse(r['state_synced'])
        saved=read_trace(self.path)
        self.assertEqual(saved['outcome'],public_result(r));self.assertEqual(self.held(),0)
        self.assertEqual(saved['last_event'],'completed')
    def test_no_financial_data_or_endpoint_in_record(self):
        with rpc(self.c.witness,self.f.headers) as (url,reads):
            recorded_refresh(self.c.wallet,url,self.path)
        raw=(self.path/'events.jsonl').read_text()
        self.assertNotIn(url,raw);self.assertNotIn('pending_account',raw);self.assertNotIn('signature',raw)
        self.assertNotIn(self.signed_body_account(),raw)
    def signed_body_account(self):return self.f.signed['result']['body']['sender']
    def test_missing_commit_records_unavailable_not_paid(self):
        with rpc(self.c.witness,self.f.headers,target_commit_failures=4) as (url,reads):
            r=recorded_refresh(self.c.wallet,url,self.path)
        s=read_trace(self.path)
        self.assertEqual(s['outcome']['status'],'unavailable');self.assertEqual(s['outcome']['rpc_attempts'],5)
        self.assertEqual(self.held(),60);self.assertEqual(len(reads),5)
    def test_fixed_commit_retry_stays_exact(self):
        with rpc(self.c.witness,self.f.headers,target_commit_failures=2) as (url,reads):
            r=recorded_refresh(self.c.wallet,url,self.path)
        self.assertEqual(sum(x['method']=='abci_query' for x in reads),1)
        self.assertEqual([x['params']['height'] for x in reads[1:4]],[str(self.c.witness['state']['height']+1)]*3)
        self.assertEqual(read_trace(self.path)['outcome']['rpc_attempts'],r['rpc_attempts'])
    def test_tampered_target_records_validation_stage(self):
        bad=copy.deepcopy(self.c.witness);bad['state']['native']['accounts'][0][4]+=1
        with rpc(bad,self.f.headers) as (url,_):r=recorded_refresh(self.c.wallet,url,self.path)
        s=read_trace(self.path);self.assertEqual(r['status'],'rejected');self.assertEqual(self.held(),60)
        self.assertIn({'stage':'target_validation'},[e['data'] for e in s['events'] if e['event']=='rejected'])
    def test_expired_policy_records_preflight_no_rpc(self):
        self.c.clock=self.c.wallet.trust_expires
        with rpc(self.c.witness,self.f.headers) as (url,reads):recorded_refresh(self.c.wallet,url,self.path)
        self.assertEqual(reads,[]);self.assertEqual(self.held(),60)
        rejected=[e for e in read_trace(self.path)['events'] if e['event']=='rejected']
        self.assertEqual(rejected[0]['data']['stage'],'preflight')
    def test_partial_record_and_restart_keep_reservations(self):
        with rpc(self.c.witness,self.f.headers) as (url,reads):
            first=recorded_refresh(self.c.wallet,url,self.path,max_batches=1,headers_per_batch=2)
            self.assertEqual(first['status'],'headers_only');self.assertEqual(self.held(),60)
            self.c.wallet.close();self.c.wallet=self.c.open()
            second=recorded_refresh(self.c.wallet,url,self.c.root/'second')
        self.assertEqual(second['headers_accepted'],2);self.assertEqual(self.held(),0)
        self.assertEqual(read_trace(self.path)['outcome']['status'],'headers_only')
        self.assertNotEqual(read_trace(self.path)['run_id'],read_trace(self.c.root/'second')['run_id'])
    def test_old_report_directory_refused_before_io(self):
        with RefreshTrace(self.path) as t:start(t)
        with rpc(self.c.witness,self.f.headers) as (url,reads):
            with self.assertRaises(FileExistsError):recorded_refresh(self.c.wallet,url,self.path)
        self.assertEqual(reads,[]);self.assertEqual(self.held(),60)
    def test_failed_diagnostic_before_io_stops_refresh(self):
        original=RefreshTrace.record
        def fail(t,event,data):
            if event=='collection_started':raise OSError('private path and secret must not appear')
            return original(t,event,data)
        with rpc(self.c.witness,self.f.headers) as (url,reads),patch.object(RefreshTrace,'record',fail):
            with self.assertRaises(RefreshObserverError):recorded_refresh(self.c.wallet,url,self.path)
        self.assertEqual(reads,[]);self.assertEqual(self.held(),60)
        self.assertEqual(read_trace(self.path)['recording_status'],'aborted')
        self.assertNotIn('private path',(self.path/'events.jsonl').read_text())
    def test_failure_after_real_state_commit_does_not_claim_rollback(self):
        original=RefreshTrace.record
        def fail(t,event,data):
            if event=='state_synced':raise OSError('write failed')
            return original(t,event,data)
        with rpc(self.c.witness,self.f.headers) as (url,reads),patch.object(RefreshTrace,'record',fail):
            with self.assertRaises(RefreshObserverError):recorded_refresh(self.c.wallet,url,self.path)
        self.assertEqual(self.held(),0)
        s=read_trace(self.path);self.assertEqual(s['recording_status'],'aborted');self.assertIsNone(s['outcome'])
        self.assertFalse(s['wallet_state_inferred'])
    def test_no_key_unlock_or_broadcast(self):
        with rpc(self.c.witness,self.f.headers) as (url,reads),patch('certified_wallet._load_vault',side_effect=AssertionError('no keys')):
            recorded_refresh(self.c.wallet,url,self.path)
        self.assertTrue(all(x['method'] in ('abci_query','commit') for x in reads))
        self.assertEqual(self.c.wallet.export(self.f.signed['decision_id'])['result'],self.f.signed['result'])
    def test_unknown_worker_count_remains_null(self):
        with patch('wallet_refresh.fetch',return_value={'status':'unavailable','rpc_attempts':None}):
            r=recorded_refresh(self.c.wallet,'http://127.0.0.1:26657/',self.path)
        self.assertIsNone(read_trace(self.path)['outcome']['rpc_attempts']);self.assertEqual(r['status'],'unavailable')
    def test_bad_input_aborts_record_without_rpc(self):
        with self.assertRaises(ValueError):recorded_refresh(self.c.wallet,'https://example.invalid/',self.path)
        self.assertEqual(read_trace(self.path)['recording_status'],'aborted');self.assertEqual(self.held(),60)
    def crash(self,event):
        # Input includes only synthetic public fixture state/policy, never a key.
        for name,obj in [('genesis',self.c.engine),('policy',self.c.policy)]:
            (self.c.root/f'{name}.json').write_bytes(encode(obj))
        code='''from pathlib import Path
import json,os,sys
from certified_wallet import CertifiedWallet
from refresh_trace import recorded_refresh,RefreshTrace
p=Path(sys.argv[1]);original=RefreshTrace.record
def crash(self,event,data):
 original(self,event,data)
 if event==sys.argv[5]:os._exit(27)
RefreshTrace.record=crash
w=CertifiedWallet(p/'wallet.sqlite',(p/'genesis.json').read_bytes(),json.loads((p/'policy.json').read_bytes()),clock=lambda:int(sys.argv[2]))
recorded_refresh(w,sys.argv[3],p/'run-record',max_batches=1,headers_per_batch=2)
'''
        with rpc(self.c.witness,self.f.headers) as (url,reads):
            p=subprocess.run([sys.executable,'-c',code,str(self.c.root),str(self.c.clock),url,'unused',event],capture_output=True,timeout=12)
            self.assertEqual(p.returncode,27,p.stderr)
            return url,reads
    def test_actual_process_exit_after_header_commit_retains_unknown_outcome(self):
        self.crash('batch_committed')
        r=read_trace(self.path);self.assertEqual(r['recording_status'],'incomplete');self.assertEqual(r['last_event'],'batch_committed')
        self.assertIsNone(r['outcome']);self.assertEqual(self.held(),60)
        self.c.wallet.close();self.c.wallet=self.c.open()
        with rpc(self.c.witness,self.f.headers) as (url,reads):out=recorded_refresh(self.c.wallet,url,self.c.root/'resume')
        self.assertEqual(out['headers_accepted'],2);self.assertEqual(self.held(),0)
    def test_caller_killed_after_final_record_keeps_exact_return(self):
        self.crash('completed')
        r=read_trace(self.path);self.assertEqual(r['recording_status'],'completed')
        self.assertEqual(r['outcome']['status'],'headers_only');self.assertEqual(self.held(),60)
    def test_trace_inspector_does_not_require_unexpired_policy(self):
        with rpc(self.c.witness,self.f.headers) as (url,reads):recorded_refresh(self.c.wallet,url,self.path)
        self.c.clock=self.c.wallet.trust_expires
        with patch('certified_wallet.CertifiedWallet',side_effect=AssertionError('must not open wallet')):
            self.assertEqual(read_trace(self.path)['outcome']['status'],'synced')


if __name__=='__main__':unittest.main()
