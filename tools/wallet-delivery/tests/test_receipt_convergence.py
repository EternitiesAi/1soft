"""Out-of-order receipt reconciliation; real local state, synthetic committees."""
import copy
import hashlib
import json
from pathlib import Path
import sqlite3
import subprocess
import sys
import unittest
from unittest.mock import patch

from decision_delivery import DecisionDelivery
from delivery_fixture import Scenario, IDS
from native_core import Reject, canonical
from certified_wallet import CertifiedWallet
from commit_verifier import encode, verify_packet


class ConvergenceTests(unittest.TestCase):
    def setUp(self):
        self.c = Scenario()
        self.first = self.c.sign()
        self.d = None
        self.rpc = self.c.rpc()
        self.url = self.rpc.__enter__()
        self.open()
        self.q = self.d.queue(self.first['decision_id'], **self.selection())

    def tearDown(self):
        if self.d: self.d.close()
        self.rpc.__exit__(None,None,None)
        self.c.close()

    def selection(self, role='raven'):
        return {'account':IDS[0], 'grant_id':role}

    def open(self):
        if self.d: self.d.close()
        self.d = DecisionDelivery(self.c.wallet_path,self.c.delivery_path,self.c.raw,
            self.c.policy,self.url,create=not self.c.delivery_path.exists(),clock=lambda:self.c.clock)

    def collect_first(self):
        reviewed=self.d.review(self.first['decision_id'],**self.selection())
        sent=self.d.send(self.first['decision_id'],reviewed['delivery_confirmation'],**self.selection())
        self.assertEqual(sent['transport_status'],'unresolved')
        found=self.d.refresh(self.first['decision_id'],**self.selection())
        self.assertTrue(found['exact_transport_receipt_verified'])
        return json.loads(self.d.export_receipt(self.first['decision_id'],**self.selection()))

    def reconcile_first(self):
        return self.d.reconcile(self.first['decision_id'],continuation=self.c.continuation(),**self.selection())

    def newer(self):
        self.c.block([])
        self.c.exposed=self.c.witness(self.c.app.height-1)
        return self.c.exposed

    def dump(self):
        return list(self.c.wallet.db.iterdump()), list(self.d.dispatch.db.iterdump())

    def test_repeat_at_same_checkpoint_is_verified_noop(self):
        self.collect_first(); first=self.reconcile_first(); before=self.dump()
        repeated=self.d.reconcile(self.first['decision_id'],**self.selection())
        self.assertTrue(first['wallet_sync_performed'])
        self.assertFalse(repeated['wallet_sync_performed'])
        self.assertEqual(repeated['reconciliation_outcome'],'already_recorded')
        self.assertEqual(self.dump(),before)

    def test_older_receipt_after_newer_wallet_state_is_verified_noop(self):
        self.collect_first();self.reconcile_first();self.newer()
        self.c.wallet.sync(self.c.exposed,continuation=self.c.continuation())
        before=self.dump();height=self.c.wallet.pending()['state_height']
        result=self.d.reconcile(self.first['decision_id'],**self.selection())
        self.assertFalse(result['wallet_sync_performed'])
        self.assertEqual(result['reconciliation_outcome'],'already_recorded')
        self.assertEqual(result['wallet_state_height'],height)
        self.assertEqual(self.dump(),before)

    def test_later_payment_can_reconcile_both_then_older_receipt_is_noop(self):
        second=self.c.sign(who=3,units=38)
        q2=self.d.queue(second['decision_id'],**self.selection('atlas'))
        self.collect_first();self.assertEqual(self.c.holds(),100)
        self.d.send(second['decision_id'],q2['delivery_confirmation'],**self.selection('atlas'))
        self.d.refresh(second['decision_id'],**self.selection('atlas'))
        self.assertEqual(self.c.holds(),100)
        self.d.reconcile(second['decision_id'],continuation=self.c.continuation(),**self.selection('atlas'))
        self.assertEqual(self.c.holds(),0)
        before=self.dump();self.open()
        result=self.d.reconcile(self.first['decision_id'],**self.selection())
        self.assertEqual(result['reconciliation_outcome'],'already_recorded')
        self.assertEqual(self.dump(),before);self.assertEqual(len(self.c.seen),2)
        self.assertEqual(sum(r[4] for r in self.c.exposed['state']['native']['budgets']),100)

    def test_collected_receipt_alone_never_claims_noop(self):
        self.collect_first();before=self.dump()
        with self.assertRaises(Reject): self.d.reconcile(self.first['decision_id'],**self.selection())
        self.assertEqual(self.c.holds(),60);self.assertEqual(self.dump(),before)

    def test_recorded_in_current_wallet_still_requires_collected_exact_proof(self):
        self.c.latest_after(canonical(self.first['result']))
        self.c.wallet.sync(self.c.exposed,continuation=self.c.continuation())
        before=self.dump()
        with self.assertRaises(ValueError): self.d.reconcile(self.first['decision_id'],**self.selection())
        self.assertEqual(self.dump(),before)

    def test_current_recording_never_bypasses_corrupt_stored_proof(self):
        self.collect_first();self.reconcile_first()
        self.d.dispatch.db.execute('UPDATE payments SET proof=?,proof_hash=?',(b'{}',hashlib.sha256(b'{}').hexdigest()))
        before=list(self.c.wallet.db.iterdump())
        with self.assertRaises(ValueError):self.d.reconcile(self.first['decision_id'],**self.selection())
        self.assertEqual(list(self.c.wallet.db.iterdump()),before)

    def test_current_recording_never_bypasses_corrupt_wallet_evidence(self):
        self.collect_first();self.reconcile_first()
        self.c.wallet.db.execute("UPDATE wallet_evidence SET witness='{}'")
        with self.assertRaises(ValueError):self.d.reconcile(self.first['decision_id'],**self.selection())

    def test_current_recording_never_bypasses_corrupt_wallet_signature(self):
        self.collect_first();self.reconcile_first()
        self.c.wallet.db.execute("UPDATE decisions SET result='{}'")
        with self.assertRaises(ValueError):self.d.reconcile(self.first['decision_id'],**self.selection())

    def test_wrong_account_or_role_remains_refused_after_recording(self):
        self.collect_first();self.reconcile_first()
        for account,role in [(IDS[1],'raven'),(IDS[0],'atlas'),(IDS[0],'')]:
            with self.subTest(account=account,role=role),self.assertRaises(ValueError):
                self.d.reconcile(self.first['decision_id'],account=account,grant_id=role)

    def test_expired_policy_allows_only_historical_recorded_noop(self):
        self.collect_first();self.reconcile_first();self.c.clock=self.d.dispatch.deadline
        before=self.dump()
        result=self.d.reconcile(self.first['decision_id'],**self.selection())
        self.assertEqual(result['reconciliation_outcome'],'already_recorded')
        self.assertFalse(result['wallet_sync_performed']);self.assertFalse(result['latest_state_guaranteed'])
        self.assertIn('policy_expired',result['wallet_time_frontier_blockers'])
        self.assertEqual(self.dump(),before)

    def test_expired_policy_does_not_reconcile_still_pending_payment(self):
        self.collect_first();self.c.clock=self.d.dispatch.deadline;before=self.dump()
        with self.assertRaises(ValueError):self.reconcile_first()
        self.assertEqual(self.c.holds(),60);self.assertEqual(self.dump(),before)

    def test_noop_does_not_open_writer_unlock_or_request_network(self):
        self.collect_first();self.reconcile_first();before=len(self.c.requests)
        with patch('decision_delivery.CertifiedWallet',side_effect=AssertionError('no wallet writer')), \
             patch('certified_wallet._load_vault',side_effect=AssertionError('no key')), \
             patch('payment_transport._worker',side_effect=AssertionError('no submit')):
            result=self.d.reconcile(self.first['decision_id'],**self.selection())
        self.assertFalse(result['network_requested']);self.assertEqual(len(self.c.requests),before)

    def test_newer_proof_for_recorded_payment_does_not_renew_wallet_state(self):
        self.collect_first();self.reconcile_first();old_height=self.c.wallet.pending()['state_height']
        self.newer()
        txid=self.q['native_txid'];old=json.loads(self.d.export_receipt(self.first['decision_id'],**self.selection()))
        old['state']=self.c.exposed['state'];old['state_commit']=self.c.exposed['state_commit']
        verify_packet(old,self.c.trust,expected_txids=[txid]);proof=encode(old)
        self.d.dispatch.db.execute('UPDATE payments SET proof=?,proof_hash=?',(proof,hashlib.sha256(proof).hexdigest()))
        before=self.dump();result=self.d.reconcile(self.first['decision_id'],**self.selection())
        self.assertFalse(result['wallet_sync_performed']);self.assertEqual(result['wallet_state_height'],old_height)
        self.assertEqual(self.dump(),before)

    def test_same_transaction_at_different_execution_height_is_not_same_receipt(self):
        self.collect_first();self.reconcile_first()
        other=Scenario()
        try:
            other.block([]);other.latest_after(canonical(self.first['result']))
            height=other.exposed['state']['height']
            packet={'schema':1,'state':other.exposed['state'],'state_commit':other.exposed['state_commit'],
                'transactions':[{'tx':__import__('base64').b64encode(canonical(self.first['result'])).decode(),
                    'block':other.blocks[height],'commit':other.headers[height]}]}
            verify_packet(packet,self.c.trust,expected_txids=[self.q['native_txid']])
            raw=encode(packet)
            self.d.dispatch.db.execute('UPDATE payments SET proof=?,proof_hash=?',(raw,hashlib.sha256(raw).hexdigest()))
            before=self.dump()
            with self.assertRaisesRegex(ValueError,'receipt conflicts'):self.d.reconcile(self.first['decision_id'],**self.selection())
            self.assertEqual(self.dump(),before)
        finally:other.close()

    def test_competing_sync_to_newer_recorded_state_becomes_verified_noop(self):
        self.collect_first();links=self.c.continuation();self.newer();newlinks=self.c.continuation()
        original=CertifiedWallet.sync
        def concurrent(wallet,witness,**kwargs):
            original(self.c.wallet,self.c.exposed,continuation=newlinks)
            return original(wallet,witness,**kwargs)
        with patch('decision_delivery.CertifiedWallet.sync',concurrent):
            result=self.d.reconcile(self.first['decision_id'],continuation=links,**self.selection())
        self.assertEqual(result['reconciliation_outcome'],'already_recorded')
        self.assertFalse(result['wallet_sync_performed']);self.assertEqual(self.c.holds(),0)
        self.assertEqual(result['wallet_state_height'],self.c.exposed['state']['height'])

    def test_competing_sync_without_payment_does_not_clear_hold(self):
        self.collect_first();links=self.c.continuation();other=Scenario()
        try:
            other.block([]);other.block([]);other.block([]);other.exposed=other.witness(4)
            origin=self.c.wallet.db.execute('SELECT height FROM checkpoint').fetchone()[0]
            nextlinks=[other.headers[h] for h in range(origin+1,5)]
            original=CertifiedWallet.sync
            def concurrent(wallet,witness,**kwargs):
                original(self.c.wallet,other.exposed,continuation=nextlinks)
                return original(wallet,witness,**kwargs)
            with patch('decision_delivery.CertifiedWallet.sync',concurrent),self.assertRaises(Reject):
                self.d.reconcile(self.first['decision_id'],continuation=links,**self.selection())
            self.assertEqual(self.c.holds(),60)
        finally:other.close()

    def test_unrelated_sqlite_failure_is_not_relabelled_as_recorded(self):
        self.collect_first()
        with patch('decision_delivery.CertifiedWallet.sync',side_effect=sqlite3.OperationalError('fixture fault')):
            with self.assertRaises(sqlite3.OperationalError):self.reconcile_first()
        self.assertEqual(self.c.holds(),60)

    def test_original_signature_and_attempt_count_unchanged_after_repeats(self):
        self.collect_first();self.reconcile_first()
        for _ in range(3):self.d.reconcile(self.first['decision_id'],**self.selection())
        self.assertEqual(self.c.wallet.export(self.first['decision_id'])['result'],self.first['result'])
        self.assertEqual(self.d.status(self.first['decision_id'],**self.selection())['submission_attempts'],1)
        self.assertEqual(len(self.c.seen),1)

    def test_cli_reopens_old_receipt_without_writing_wallet(self):
        self.collect_first();self.reconcile_first();self.newer()
        self.c.wallet.sync(self.c.exposed,continuation=self.c.continuation())
        before=self.dump();self.d.close();self.d=None
        for name,value in [('genesis',self.c.engine),('policy',self.c.policy)]:
            (self.c.root/(name+'.json')).write_bytes(encode(value))
        cli=Path(__file__).resolve().parents[1]/'scripts/deliver.py'
        result=subprocess.run([sys.executable,str(cli),'--genesis',str(self.c.root/'genesis.json'),
            '--policy',str(self.c.root/'policy.json'),'--wallet',str(self.c.wallet_path),
            '--delivery-journal',str(self.c.delivery_path),'--endpoint',self.url,
            '--account',IDS[0],'--grant-id','raven','--decision-id',self.first['decision_id'],
            'reconcile'],capture_output=True,text=True,timeout=10)
        self.assertEqual(result.returncode,0,result.stderr)
        report=json.loads(result.stdout)
        self.assertEqual(report['reconciliation_outcome'],'already_recorded')
        self.assertFalse(report['wallet_sync_performed']);self.open()
        self.assertEqual(self.dump(),before)

    def test_process_exit_after_sync_resumes_without_reimport(self):
        self.collect_first()
        for name,value in [('genesis',self.c.engine),('policy',self.c.policy),('links',self.c.continuation())]:
            (self.c.root/(name+'.json')).write_bytes(encode(value))
        self.d.close();self.d=None
        code="""import json,os,sys
from pathlib import Path
from decision_delivery import DecisionDelivery
p=Path(sys.argv[1])
d=DecisionDelivery(p/'wallet.sqlite',p/'delivery.sqlite',(p/'genesis.json').read_bytes(),json.loads((p/'policy.json').read_bytes()),sys.argv[2],clock=lambda:int(sys.argv[5]))
d.reconcile(sys.argv[3],account=sys.argv[4],grant_id='raven',continuation=json.loads((p/'links.json').read_bytes()))
os._exit(29)
"""
        result=subprocess.run([sys.executable,'-c',code,str(self.c.root),self.url,
            self.first['decision_id'],IDS[0],str(self.c.clock)],capture_output=True,timeout=10)
        self.assertEqual(result.returncode,29,result.stderr)
        self.open();before=self.dump();report=self.d.reconcile(self.first['decision_id'],**self.selection())
        self.assertFalse(report['wallet_sync_performed']);self.assertEqual(self.dump(),before)
        self.assertEqual(self.c.holds(),0);self.assertEqual(len(self.c.seen),1)


if __name__=='__main__':unittest.main()
