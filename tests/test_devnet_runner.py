import builtins
import hashlib
import http.client
import importlib.util
import json
from pathlib import Path
import sys
import tempfile
import unittest
from datetime import datetime
from unittest.mock import patch

path=Path(__file__).resolve().parents[1]/'scripts/run_devnet.py'
spec=importlib.util.spec_from_file_location('devnet_runner',path)
runner=importlib.util.module_from_spec(spec);spec.loader.exec_module(runner)

class RunnerTests(unittest.TestCase):
    def test_toml_scope_is_preserved(self):
        text='proxy_app = "old"\n[rpc]\nladdr = "old-rpc"\n[p2p]\nladdr = "old-p2p"\n'
        changed=runner.patch_toml(text,{'rpc.laddr':'tcp://127.0.0.1:1234'})
        self.assertIn('laddr = "old-p2p"',changed)
        self.assertIn('laddr = "tcp://127.0.0.1:1234"',changed)

    def test_unknown_configuration_key_fails_closed(self):
        with self.assertRaises(ValueError):runner.patch_toml('[rpc]\na=1\n',{'rpc.missing':1})

    def test_toml_boolean_encoding(self):
        self.assertIn('unsafe = false',runner.patch_toml('[rpc]\nunsafe=true\n',{'rpc.unsafe':False}))

    def test_no_binary_is_unassessed_not_passed_and_records_source_provenance(self):
        with tempfile.TemporaryDirectory() as d:
            out=Path(d)/'out.json'
            result=runner.run(str(Path(d)/'does-not-exist'),out)
            self.assertEqual(result['status'],'unassessed')
            self.assertEqual(result['checks'],[])
            self.assertEqual(json.loads(out.read_text())['status'],'unassessed')
            provenance=result['run_provenance']
            self.assertEqual(provenance['runner_relative_path'],'scripts/run_devnet.py')
            self.assertEqual(provenance['runner_sha256'],
                hashlib.sha256(path.read_bytes()).hexdigest())
            self.assertEqual(provenance['source_manifest_sha256'],
                hashlib.sha256((path.parents[1]/'SOURCE_MANIFEST.json').read_bytes()).hexdigest())
            started=datetime.fromisoformat(provenance['started_at_utc'].replace('Z','+00:00'))
            self.assertIsNotNone(started.tzinfo)
            self.assertIn(provenance['tracked_worktree_dirty'],(True,False,None))
            for field in ('source_commit','source_tree','tracked_diff_sha256'):
                value=provenance[field]
                self.assertTrue(value is None or (len(value)==40 if field!='tracked_diff_sha256'
                    else len(value)==64))

    def test_wrong_engine_version_is_rejected(self):
        with tempfile.TemporaryDirectory() as d:
            with patch.object(runner.subprocess,'check_output',return_value='0.0.1\n'):
                result=runner.run(sys.executable,Path(d)/'out.json')
            self.assertEqual(result['status'],'failed')
            self.assertIn('version',result['reason'])

    def test_ephemeral_ports_distinct(self):
        ports=runner.free_ports(8)
        self.assertEqual(len(set(ports)),8)
        self.assertTrue(all(0<p<65536 for p in ports))

    def test_default_runner_import_and_run_do_not_require_wallet_delivery(self):
        delivery_path=str(path.parents[1]/'tools/wallet-delivery/src')
        original_sys_path=list(sys.path)
        sys.path[:]=[entry for entry in sys.path if entry!=delivery_path]
        original_import=builtins.__import__
        def forbid_delivery(name,*args,**kwargs):
            if name=='decision_delivery':
                raise AssertionError('default runner imported DecisionDelivery')
            return original_import(name,*args,**kwargs)
        isolated_spec=importlib.util.spec_from_file_location('devnet_runner_default_isolated',path)
        isolated=importlib.util.module_from_spec(isolated_spec)
        try:
            with patch('builtins.__import__',side_effect=forbid_delivery):
                isolated_spec.loader.exec_module(isolated)
                with tempfile.TemporaryDirectory() as d:
                    result=isolated.run(str(Path(d)/'missing-engine'),Path(d)/'out.json',3)
            self.assertEqual(result['status'],'unassessed')
            self.assertNotIn(delivery_path,sys.path)
        finally:
            sys.path[:]=original_sys_path

    def test_decision_delivery_import_is_available_only_when_opted_in(self):
        with tempfile.TemporaryDirectory() as d:
            result=runner.run(str(Path(d)/'missing-engine'),Path(d)/'out.json',3,
                decision_delivery=True)
        self.assertEqual(result['status'],'unassessed')
        self.assertTrue(result['decision_delivery']['enabled'])
        self.assertIn('decision_delivery',sys.modules)

    def test_rpc_proxy_tracks_non_post_http_methods(self):
        proxy=runner.DecisionDeliveryRpcProxy(runner.free_ports(1)[0],[
            ('first',b'expected-first'),('second',b'expected-second')])
        try:
            connection=http.client.HTTPConnection('127.0.0.1',proxy.port,timeout=3)
            connection.request('GET','/')
            response=connection.getresponse()
            response.read()
            self.assertEqual(response.status,501)
            connection.close()

            payload=json.dumps({'jsonrpc':'2.0','id':1,'method':'broadcast_tx_sync',
                'params':{'tx':'bm90LXRoZS1leHBlY3RlZC1ieXRlcw=='}}).encode()
            connection=http.client.HTTPConnection('127.0.0.1',proxy.port,timeout=3)
            connection.request('POST','/',payload,{'Content-Type':'application/json'})
            response=connection.getresponse()
            response.read()
            self.assertEqual(response.status,403)
            connection.close()

            snapshot=proxy.snapshot()
            self.assertEqual(snapshot['http_methods_seen'],['GET','POST'])
            self.assertEqual(snapshot['unexpected_http_methods'],['GET'])
            self.assertEqual(snapshot['unexpected_requests'],['different_signed_bytes'])
            self.assertEqual(snapshot['forwarded_payment_submissions'],0)
        finally:
            proxy.close()

class NativeCaseTests(unittest.TestCase):
    """Test transaction plans. These are NOT network tests."""
    def check_case(self,version):
        from native_core import NativeLedger, parse_wire, Reject
        case=runner.build_native_case('eternities-network-plan-tests',version)
        ledger=NativeLedger(':memory:',case['genesis'])
        try:
            for _,raw in case['accepted']:ledger.apply(parse_wire(raw),height=1)
            before=ledger.state_hash()
            for name,raw in case['rejected']:
                with self.subTest(name=name):
                    with self.assertRaises(Reject):ledger.apply(parse_wire(raw),height=2)
                    self.assertEqual(ledger.state_hash(),before)
            self.assertTrue(ledger.verify_receipts())
            self.assertEqual(len(list(ledger.db.execute('SELECT * FROM receipts'))),len(case['accepted']))
            if version==2:
                account=ledger._account(case['new_account'])
                self.assertEqual(account['public_key'],case['new_public_key'])
                self.assertEqual(account['balance'],case['expected_new_balance'])
                self.assertEqual((account['nonce'],account['epoch']),(3,1))
        finally:ledger.close()
        return case

    def test_v1_plan_still_executes_original_four_operations(self):
        case=self.check_case(1);self.assertEqual(len(case['accepted']),4)
        self.assertNotIn('protocol_version',case['genesis'])

    def test_v2_plan_includes_ten_operations_and_four_rejections(self):
        case=self.check_case(2);self.assertEqual(len(case['accepted']),10)
        self.assertEqual(len(case['rejected']),4)

    def test_unsupported_plan_version_rejected(self):
        for value in [True,0,4,'2']:
            with self.assertRaises(ValueError):runner.build_native_case('dev',value)

    def test_missing_engine_does_not_pass_v2(self):
        with tempfile.TemporaryDirectory() as d:
            out=Path(d)/'nested/out.json'
            result=runner.run(str(Path(d)/'missing-engine'),out,2)
            self.assertEqual(result['native_protocol_version'],2)
            self.assertEqual(result['status'],'unassessed');self.assertEqual(result['checks'],[])

    def test_no_private_keys_in_case_exports(self):
        case=runner.build_native_case('dev',2)
        self.assertEqual(set(case),{'genesis','accepted','rejected','protocol_version',
                                  'new_account','new_public_key','expected_new_balance'})
        self.assertTrue(all(type(raw) is bytes for _,raw in case['accepted']+case['rejected']))
