"""Local component and acceptance-driver tests, never fake validator qualification."""
import copy
import hashlib
import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

from block_application import BlockApplication
from certified_wallet import CertifiedWallet
from decision_delivery import DecisionDelivery
from delivery_fixture import Scenario, IDS
from native_core import canonical
from product_observer import ProductObserver, validate_history
import run_product_network as runner


class ProductTests(unittest.TestCase):
    def setUp(self):
        self.c = Scenario(compact=self._testMethodName.endswith('_smt'))
        c = self.c
        c.app.close(); c.app = BlockApplication(c.root/'app.sqlite', expected_genesis=c.genesis, block_history_keep=2)
        self.decisions = [c.sign(), c.sign(who=3, units=38)]
        for p in c.root.glob('*.pem'): p.unlink()
        self.rpc_context = c.rpc(); self.url = self.rpc_context.__enter__()
        self.d = DecisionDelivery(c.wallet_path, c.delivery_path, c.raw, c.policy, self.url,
                                   create=True, clock=lambda: c.clock)
        self.observer = ProductObserver(c.root/'product', c.root/'reports', c.raw, c.policy, self.url,
                                        IDS[0]+'::project', clock=lambda: c.clock)
    def tearDown(self):
        self.observer.close(); self.d.close()
        if self.rpc_context is not None: self.rpc_context.__exit__(None,None,None)
        self.c.close()
    def begin(self): self.observer.begin(self.c.exposed, self.c.wallet, self.d)
    def payment(self, n):
        c = self.c; decision = self.decisions[n]; role = ('raven','atlas')[n]
        selection = {'account': IDS[0], 'grant_id': role}
        q = self.d.queue(decision['decision_id'], **selection)
        sent = self.d.send(decision['decision_id'], q['delivery_confirmation'], **selection)
        self.assertEqual(sent['transport_status'], 'unresolved')
        self.d.close(); c.wallet.close()
        c.wallet = CertifiedWallet(c.wallet_path, c.raw, c.policy, clock=lambda: c.clock)
        self.d = DecisionDelivery(c.wallet_path, c.delivery_path, c.raw, c.policy, self.url, clock=lambda: c.clock)
        collected = self.d.refresh(decision['decision_id'], **selection)
        self.assertTrue(collected['exact_transport_receipt_verified'])
        packet = json.loads(self.d.export_receipt(decision['decision_id'], **selection))
        return role, packet, canonical(decision['result']), selection
    def step(self, n):
        role, packet, raw, selection = self.payment(n)
        pending = (100,40)[n]; spent = (60,100)[n]
        self.observer.before_reconcile(role, packet, raw, self.c.wallet, self.d,
                                        expected_pending=pending, expected_spent=spent)
        answer = self.d.reconcile(self.decisions[n]['decision_id'], continuation=self.c.continuation(), **selection)
        self.assertEqual(answer['wallet_obligation_status'], 'recorded')
        self.observer.after_reconcile(role, self.c.wallet, expected_pending=(40,0)[n], expected_spent=spent)
    def complete(self):
        self.begin(); self.step(0); self.step(1)
        self.rpc_context.__exit__(None,None,None); self.rpc_context = None
        self.c.app.close()
        with patch('socket.socket', side_effect=AssertionError('offline verification must not contact node')):
            result = self.observer.finish(self.c.wallet, self.d, expected_receipt_count=6)
        self.assertEqual(result['status'], 'passed')
        self.assertEqual(len(self.c.seen), 2)
        self.assertFalse(result['independent_operators_established'])
        self.assertFalse(result['wallet_authority'])
        self.assertEqual(self.c.holds(), 0)
        self.assertTrue((self.c.root/'reports/explorer.html').is_file())
        return result
    def test_complete_local_observer_flat(self): self.complete()
    def test_complete_local_observer_smt(self):
        self.complete()
        c = json.loads((self.c.root/'reports/raven-capsule.json').read_bytes())
        self.assertEqual(c['proof_kind'], 'smt-v1')
    def test_initial_observation_does_not_mutate_wallet_or_dispatch(self):
        before = self.observer.journals(self.c.wallet,self.d); self.begin()
        self.assertEqual(self.observer.journals(self.c.wallet,self.d),before)
        self.assertEqual(self.c.holds(),100)
    def test_valid_same_height_alternate_anchor_is_not_wallet_checkpoint(self):
        from certificate_fixture import make_commit
        witness=copy.deepcopy(self.c.exposed)
        head=witness['state_commit']['header'];head['consensus_hash']='ab'*32
        witness['state_commit']=make_commit(head,self.c.trust,self.c.committee)
        with patch('socket.socket',side_effect=AssertionError('must check before RPC')):
            with self.assertRaisesRegex(AssertionError,'exact wallet checkpoint'):
                self.observer.begin(witness,self.c.wallet,self.d)
        self.assertIsNone(self.observer.index.current())

    def test_before_reconcile_leaves_obligation_intact(self):
        self.begin();role,packet,raw,_ = self.payment(0)
        before = self.observer.journals(self.c.wallet,self.d)
        self.observer.before_reconcile(role,packet,raw,self.c.wallet,self.d,expected_pending=100,expected_spent=60)
        self.assertEqual(self.observer.journals(self.c.wallet,self.d),before)
        self.assertEqual(self.c.holds(),100)
        self.assertEqual(self.observer.index.current()['budgets'][0]['spent'],'60')
    def test_assertion_failure_preserves_observed_accounting(self):
        self.begin()
        with self.assertRaises(AssertionError):
            self.observer.record('bad_expectation', self.c.wallet, expected_pending=99, expected_spent=0)
        saved = json.loads((self.c.root/'reports/observer.json').read_bytes())
        self.assertEqual(saved['stages'][-1]['pending_units'],100)
        self.assertEqual(saved['stages'][-1]['expected_pending'],99)
        self.assertNotEqual(saved['status'],'passed')
    def test_explorer_failure_does_not_undo_archived_receipt_or_release_hold(self):
        self.begin();role,packet,raw,_ = self.payment(0)
        before = self.observer.journals(self.c.wallet,self.d)
        with patch('product_observer.refresh_explorer',side_effect=ValueError('fixture read unavailable')):
            with self.assertRaises(ValueError):
                self.observer.before_reconcile(role,packet,raw,self.c.wallet,self.d,expected_pending=100,expected_spent=60)
        self.assertEqual(self.observer.archive.lookup(raw)['status'],'available')
        self.assertEqual(self.observer.journals(self.c.wallet,self.d),before)
        self.assertEqual(self.c.holds(),100)
        saved = json.loads((self.c.root/'reports/observer.json').read_bytes())
        self.assertEqual(saved['active_operation'],'raven_receipt_and_index')
        self.assertNotEqual(saved['status'],'passed')
    def test_wrong_exact_payment_refused(self):
        self.begin();role,packet,_,_ = self.payment(0)
        with self.assertRaises(ValueError):
            self.observer.before_reconcile(role,packet,canonical(self.decisions[1]['result']),self.c.wallet,self.d,
                                             expected_pending=100,expected_spent=60)
        self.assertEqual(self.observer.archive.lookup(canonical(self.decisions[0]['result']))['status'],'unavailable')
        self.assertEqual(self.c.holds(),100)
    def test_final_anchor_must_match_separately_fetched_header(self):
        self.begin();role,packet,raw,_ = self.payment(0)
        packet['state_commit']['header']['consensus_hash']='ab'*32
        with self.assertRaisesRegex(AssertionError,'anchor conflicts'):
            self.observer.before_reconcile(role,packet,raw,self.c.wallet,self.d,expected_pending=100,expected_spent=60)
        self.assertEqual(self.c.holds(),100)
    def test_duplicate_named_product_step_refused(self):
        self.begin();self.step(0)
        role, packet = 'raven', json.loads((self.c.root/'reports/raven-capsule.json').read_bytes())
        with self.assertRaisesRegex(AssertionError,'duplicate'):
            self.observer.before_reconcile(role,packet,canonical(self.decisions[0]['result']),self.c.wallet,self.d,
                                           expected_pending=40,expected_spent=60)
    def test_finish_refuses_incomplete_journey(self):
        self.begin();self.step(0)
        with self.assertRaises(AssertionError): self.observer.finish(self.c.wallet,self.d,expected_receipt_count=6)
        self.assertNotEqual(json.loads((self.c.root/'reports/observer.json').read_bytes())['status'],'passed')
    def test_observer_never_unlocks_keys(self):
        with patch('certified_wallet._load_vault',side_effect=AssertionError('must not unlock')):
            self.complete()
    def test_existing_report_directory_not_overwritten(self):
        p=self.c.root/'reports/keep';p.write_text('preserve')
        with self.assertRaises(FileExistsError):
            ProductObserver(self.c.root/'another-product',self.c.root/'reports',self.c.raw,self.c.policy,self.url,
                            IDS[0]+'::project')
        self.assertEqual(p.read_text(),'preserve')
    def test_history_matches_actual_retention_metadata(self):
        for _ in range(6): self.c.block([])
        data=json.loads(self.c.app.query('/history')['value'])
        r=validate_history(data,2,minimum_height=6)
        self.assertEqual(r['retained_count'],2)
        self.assertEqual(r['pruned_through'],self.c.app.height-2)
    def test_wrong_history_window_or_false_authority_refused(self):
        for _ in range(6): self.c.block([])
        original=json.loads(self.c.app.query('/history')['value'])
        for field in ('native_receipts_pruned','engine_history_pruning_requested',
                      'historical_transaction_absence_proven','total_storage_bounded'):
            changed=copy.deepcopy(original);changed[field]=True
            with self.subTest(field=field),self.assertRaises(AssertionError):validate_history(changed,2)
        changed=copy.deepcopy(original);changed['availability']['pruned_through']-=1
        with self.assertRaises(AssertionError):validate_history(changed,2)
    def test_retention_not_exercised_is_not_passing(self):
        data=json.loads(self.c.app.query('/history')['value'])
        with self.assertRaises(AssertionError):validate_history(data,2)
    def test_history_boolean_is_not_height_or_count(self):
        for _ in range(6):self.c.block([])
        data=json.loads(self.c.app.query('/history')['value']);data['availability']['retained_count']=True
        with self.assertRaises(AssertionError):validate_history(data,2)


class EngineDriverTests(unittest.TestCase):
    def test_initial_application_command_enables_retention(self):
        args=runner.application_command('db','sock','genesis',3)
        self.assertEqual(args[-2:],['--block-history-keep','3'])
    def test_restart_command_relies_on_existing_policy(self):
        args=runner.application_command('db','sock','genesis',3,restart=True)
        self.assertNotIn('--block-history-keep',args)
        self.assertIn('db',args)
    def test_test_window_bounds_are_explicit(self):
        for value in (None,True,1,17,'3'):
            with self.subTest(value=value),self.assertRaises(AssertionError):
                runner.application_command('db','sock','genesis',value)
    def test_missing_binary_is_unassessed(self):
        with tempfile.TemporaryDirectory() as d:
            r=runner.engine_preflight(str(Path(d)/'missing'),None)
            self.assertEqual(r['status'],'unassessed')
    def test_missing_engine_digest_does_not_execute_binary(self):
        with patch.object(runner.subprocess,'check_output',side_effect=AssertionError('must not execute')):
            r=runner.engine_preflight(sys.executable,None)
        self.assertEqual(r['status'],'unassessed')
    def test_wrong_digest_refused_before_version_command(self):
        with patch.object(runner.subprocess,'check_output',side_effect=AssertionError('must not execute')):
            with self.assertRaisesRegex(AssertionError,'bytes differ'):
                runner.engine_preflight(sys.executable,'0'*64)
    def test_matching_digest_with_wrong_version_is_refused(self):
        pin=hashlib.sha256(Path(sys.executable).read_bytes()).hexdigest()
        with patch.object(runner.subprocess,'check_output',return_value='0.0.1'):
            with self.assertRaisesRegex(AssertionError,'version differs'):runner.engine_preflight(sys.executable,pin)
    def test_missing_engine_full_gate_retains_zero_executed_checks(self):
        with tempfile.TemporaryDirectory() as d:
            output=Path(d)/'evidence'
            r=runner.run(str(Path(d)/'missing'),output,compact=True)
            saved=json.loads((output/'result.json').read_bytes())
            self.assertEqual(saved,r);self.assertEqual(r['status'],'unassessed')
            self.assertEqual(r['checks'],[]);self.assertEqual(r['engine_processes_started'],0)
            self.assertFalse(r['consensus_executed']);self.assertFalse(r['real_funds'])
            self.assertEqual(r['release_status'],'blocked')
    def test_existing_evidence_directory_is_refused(self):
        with tempfile.TemporaryDirectory() as d:
            p=Path(d)/'keep';p.write_text('old result')
            with self.assertRaises(FileExistsError):runner.output_directory(Path(d))
            self.assertEqual(p.read_text(),'old result')
    def test_state_capture_reads_only_fixed_next_header(self):
        captured={'height':4};seen=[]
        def rpc(port, method, params=None):
            seen.append((method,params))
            return {'signed_header':{'header':{'height':'5'}}}
        with patch.object(runner,'query_value',return_value=captured) as q, \
             patch.object(runner,'wait_until',return_value=True), \
             patch.object(runner,'verify_state_witness'),patch.object(runner,'rpc',side_effect=rpc):
            r=runner.live_witness(1234,None)
        self.assertEqual(q.call_count,1)
        self.assertEqual(seen,[('commit',{'height':'5'})]);self.assertIs(r['state'],captured)
    def test_continuation_is_exact_and_bounded(self):
        calls=[]
        def rpc(port,method,params):
            calls.append(params['height']);return {'signed_header':{'height':params['height']}}
        with patch.object(runner,'rpc',side_effect=rpc):r=runner.continuation(1234,3,6)
        self.assertEqual(calls,['4','5']);self.assertEqual(len(r),2)
        with self.assertRaises(AssertionError):runner.continuation(1234,3,100)


if __name__=='__main__':unittest.main()
