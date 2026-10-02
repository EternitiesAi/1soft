"""Attempt-scoped delivery approvals over disposable native state; no live funds."""
import copy
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import unittest
from unittest.mock import patch

from decision_delivery import DecisionDelivery
from delivery_fixture import Scenario, IDS, KEYS, PASSWORD
from native_core import canonical, public, sign
from commit_verifier import encode


class AttemptConsentTests(unittest.TestCase):
    def setUp(self):
        self.c=Scenario(); self.signed=self.c.sign(); self.decision=self.signed['decision_id']; self.d=None
        self.selection={'account':IDS[0],'grant_id':'raven'}
    def tearDown(self):
        if self.d: self.d.close()
        self.c.close()
    def open(self,url='http://127.0.0.1:26657/',create=True):
        if self.d: self.d.close()
        self.d=DecisionDelivery(self.c.wallet_path,self.c.delivery_path,self.c.raw,self.c.policy,url,
            create=create,clock=lambda:self.c.clock)
        return self.d
    def call(self,method,*args,**kw):
        return getattr(self.d,method)(self.decision,*args,**self.selection,**kw)
    def sync_empty(self):
        self.c.block([]); self.c.exposed=self.c.witness(self.c.app.height-1)
        self.c.wallet.sync(self.c.exposed,continuation=self.c.continuation())
    def test_original_send_confirmation_cannot_approve_replay(self):
        self.c.mode='decline'
        with self.c.rpc() as url:
            self.open(url); q=self.call('queue'); self.call('send',q['delivery_confirmation'])
            with self.assertRaises(ValueError): self.call('send',q['delivery_confirmation'],replay=True)
            self.assertEqual(len(self.c.seen),1)
    def test_changed_signing_inventory_invalidates_queued_approval(self):
        with self.c.rpc() as url:
            self.open(url); q=self.call('queue'); self.c.sign(who=3,units=38)
            with self.assertRaises(ValueError): self.call('send',q['delivery_confirmation'])
            self.assertEqual(self.c.seen,[]); self.assertEqual(self.c.holds(),100)
    def test_new_checkpoint_invalidates_initial_confirmation(self):
        with self.c.rpc() as url:
            self.open(url); q=self.call('queue'); self.sync_empty()
            with self.assertRaises(ValueError): self.call('send',q['delivery_confirmation'])
            self.assertEqual(self.c.seen,[])
    def test_review_is_read_only_and_reproducible(self):
        self.open();q=self.call('queue')
        financial=list(self.c.wallet.db.iterdump()); transport=list(self.d.dispatch.db.iterdump())
        with patch('payment_transport._worker',side_effect=AssertionError('no I/O')),patch('certified_wallet._load_vault',side_effect=AssertionError('no key')):
            a=self.call('review');b=self.call('review')
        self.assertEqual(a,b);self.assertEqual(a['delivery_confirmation'],q['delivery_confirmation'])
        self.assertEqual(financial,list(self.c.wallet.db.iterdump()));self.assertEqual(transport,list(self.d.dispatch.db.iterdump()))
        self.assertEqual(self.c.holds(),60)
    def test_review_exposes_exact_payment_and_attempt(self):
        self.open();q=self.call('queue');r=q['submission_review']
        self.assertEqual((r['operation'],r['next_attempt'],r['schema']),('send',1,2))
        self.assertEqual((r['amount_units'],r['fee_units'],r['total_debit_units']),(58,2,60))
        self.assertEqual(r['recipient'],IDS[1]);self.assertEqual(r['account'],IDS[0]);self.assertEqual(r['grant_id'],'raven')
        self.assertEqual(r['wire_sha256'],hashlib.sha256(canonical(self.signed['result'])).hexdigest())
        self.assertEqual(r['nonce'],self.signed['result']['body']['nonce'])
        self.assertEqual(r['wallet_app_hash'],self.c.exposed['state']['app_hash'])
    def test_status_never_supplies_a_fresh_approval(self):
        self.open();q=self.call('queue');s=self.call('status')
        self.assertIsNotNone(q['delivery_confirmation']);self.assertIsNone(s['delivery_confirmation']);self.assertIsNone(s['submission_review'])
    def test_review_requires_existing_queue(self):
        self.open()
        with self.assertRaisesRegex(ValueError,'queue'):self.call('review')
        self.assertEqual(self.d.dispatch.db.execute('SELECT count(*) FROM payments').fetchone()[0],0)
    def test_replay_review_cannot_be_first_send(self):
        self.open();self.call('queue')
        with self.assertRaisesRegex(ValueError,'different'):self.call('review',replay=True)
    def test_wrong_role_cannot_obtain_review(self):
        self.open();self.call('queue')
        for grant in ('','atlas','missing'):
            with self.subTest(grant=grant),self.assertRaises(ValueError):self.d.review(self.decision,account=IDS[0],grant_id=grant)
    def test_non_boolean_replay_refused_before_attempt(self):
        self.open();q=self.call('queue')
        for value in (0,1,'true',None,[],{}):
            with self.subTest(value=value),self.assertRaises(ValueError):self.call('review',replay=value)
            with self.subTest(value=value),self.assertRaises(ValueError):self.call('send',q['delivery_confirmation'],replay=value)
        self.assertEqual(self.call('status')['submission_attempts'],0)
    def test_fresh_review_after_inventory_change_keeps_original_signature(self):
        with self.c.rpc() as url:
            self.open(url);q=self.call('queue');self.c.sign(who=3,units=38)
            r=self.call('review');self.assertNotEqual(q['delivery_confirmation'],r['delivery_confirmation'])
            self.call('send',r['delivery_confirmation'])
            self.assertEqual(self.c.seen,[canonical(self.signed['result'])]);self.assertEqual(self.c.holds(),100)
    def test_fresh_review_after_checkpoint_does_not_resign(self):
        with self.c.rpc() as url:
            self.open(url);q=self.call('queue');self.sync_empty();r=self.call('review')
            self.assertNotEqual(q['delivery_confirmation'],r['delivery_confirmation'])
            with patch('certified_wallet._load_vault',side_effect=AssertionError('no key')):self.call('send',r['delivery_confirmation'])
            self.assertEqual(self.c.seen,[canonical(self.signed['result'])])
    def test_first_send_review_after_attempt_is_refused(self):
        self.c.mode='decline'
        with self.c.rpc() as url:
            self.open(url);q=self.call('queue');self.call('send',q['delivery_confirmation'])
            with self.assertRaisesRegex(ValueError,'different'):self.call('review')
    def test_requeue_after_attempt_is_not_replay_consent(self):
        self.c.mode='decline'
        with self.c.rpc() as url:
            self.open(url);q=self.call('queue');self.call('send',q['delivery_confirmation']);again=self.call('queue')
            self.assertIsNone(again['delivery_confirmation']);self.assertIsNone(again['submission_review'])
            self.assertEqual(again['submission_attempts'],1)
    def test_each_replay_requires_its_own_attempt_confirmation(self):
        self.c.mode='decline'
        with self.c.rpc() as url:
            self.open(url);q=self.call('queue');self.call('send',q['delivery_confirmation'])
            r2=self.call('review',replay=True)
            self.assertEqual((r2['submission_review']['operation'],r2['submission_review']['next_attempt']),('replay',2))
            self.call('send',r2['delivery_confirmation'],replay=True)
            with self.assertRaises(ValueError):self.call('send',r2['delivery_confirmation'],replay=True)
            r3=self.call('review',replay=True);self.assertNotEqual(r3['delivery_confirmation'],r2['delivery_confirmation'])
            self.call('send',r3['delivery_confirmation'],replay=True)
            self.assertEqual(self.c.seen,[canonical(self.signed['result'])]*3);self.assertEqual(self.c.holds(),60)
    def test_replay_review_cannot_be_used_as_send(self):
        self.c.mode='decline'
        with self.c.rpc() as url:
            self.open(url);q=self.call('queue');self.call('send',q['delivery_confirmation']);r=self.call('review',replay=True)
            with self.assertRaises(ValueError):self.call('send',r['delivery_confirmation'],replay=False)
            self.assertEqual(len(self.c.seen),1)
    def test_intervening_send_invalidates_review_across_reopen(self):
        self.c.mode='decline'
        with self.c.rpc() as url:
            self.open(url);q=self.call('queue');self.open(url,False)
            self.call('send',q['delivery_confirmation']);self.open(url,False)
            with self.assertRaises(ValueError):self.call('send',q['delivery_confirmation'],replay=True)
            self.assertEqual(len(self.c.seen),1)
    def test_failed_confirmation_changes_neither_journal(self):
        self.open();self.call('queue');before=list(self.c.wallet.db.iterdump());transport=list(self.d.dispatch.db.iterdump())
        for confirmation in ('0'*64,'','A'*64,None,False):
            with self.assertRaises(ValueError):self.call('send',confirmation)
        self.assertEqual(before,list(self.c.wallet.db.iterdump()));self.assertEqual(transport,list(self.d.dispatch.db.iterdump()))
    def test_legacy_v1_confirmation_is_not_accepted(self):
        self.open();q=self.call('queue');transport=self.d.dispatch.status(q['native_txid'])
        old=hashlib.sha256(b'1soft/decision-delivery/v1\x00'+encode({'route':self.d.route,
            'decision_id':self.decision,'account':IDS[0],'grant_id':'raven','native_txid':q['native_txid'],
            'wire_sha256':q['wire_sha256'],'dispatch_confirmation':transport['dispatch_confirmation']})).hexdigest()
        with self.assertRaises(ValueError):self.call('send',old)
        self.assertEqual(self.call('status')['submission_attempts'],0)
    def test_verified_receipt_refuses_replay_review_without_clearing_hold(self):
        with self.c.rpc() as url:
            self.open(url);q=self.call('queue');self.call('send',q['delivery_confirmation']);self.call('refresh')
            with self.assertRaises(ValueError):self.call('review',replay=True)
            self.assertEqual(self.c.holds(),60);self.assertEqual(len(self.c.seen),1)
    def test_stale_state_refuses_new_review(self):
        self.open();self.call('queue');self.c.clock+=400*10**9
        with self.assertRaises(ValueError):self.call('review')
        self.assertIsNone(self.call('status')['delivery_confirmation']);self.assertEqual(self.c.holds(),60)
    def test_policy_expiry_invalidates_previously_reviewed_attempt(self):
        self.open();r=self.call('queue');self.c.clock=self.d.dispatch.deadline
        with self.assertRaises(ValueError):self.call('send',r['delivery_confirmation'])
        self.assertEqual(self.call('status')['submission_attempts'],0)
    def test_failed_dispatch_commit_does_not_consume_confirmation(self):
        self.open();q=self.call('queue')
        self.d.dispatch.db.execute("CREATE TRIGGER stop_attempt BEFORE UPDATE ON payments BEGIN SELECT RAISE(ABORT,'test stop'); END")
        import sqlite3
        with patch('payment_transport._worker',side_effect=AssertionError('no I/O')):
            with self.assertRaises(sqlite3.IntegrityError):self.call('send',q['delivery_confirmation'])
        self.d.dispatch.db.execute('DROP TRIGGER stop_attempt')
        self.assertEqual(self.call('status')['submission_attempts'],0)
        self.assertEqual(q['delivery_confirmation'],self.call('review')['delivery_confirmation'])
    def test_actual_process_exit_before_socket_consumes_attempt_scope(self):
        self.c.mode='decline'
        with self.c.rpc() as url:
            self.open(url);q=self.call('queue');self.d.close();self.d=None
            for name,value in [('genesis',self.c.engine),('policy',self.c.policy)]:
                (self.c.root/(name+'.json')).write_bytes(encode(value))
            code='''from pathlib import Path
import os,json,sys
from decision_delivery import DecisionDelivery
import payment_transport
p=Path(sys.argv[1]);payment_transport._worker=lambda *a:os._exit(29)
with DecisionDelivery(p/'wallet.sqlite',p/'delivery.sqlite',(p/'genesis.json').read_bytes(),json.loads((p/'policy.json').read_bytes()),sys.argv[2],clock=lambda:int(sys.argv[5])) as d:
 d.send(sys.argv[3],sys.argv[4],account=sys.argv[6],grant_id='raven')
'''
            child=subprocess.run([sys.executable,'-c',code,str(self.c.root),url,self.decision,q['delivery_confirmation'],str(self.c.clock),IDS[0]],capture_output=True,timeout=8)
            self.assertEqual(child.returncode,29,child.stderr);self.assertEqual(self.c.requests,[])
            self.open(url,False);self.assertEqual(self.call('status')['transport_status'],'dispatching')
            with self.assertRaises(ValueError):self.call('send',q['delivery_confirmation'],replay=True)
            r=self.call('review',replay=True);self.assertEqual(r['submission_review']['next_attempt'],2)
            self.call('send',r['delivery_confirmation'],replay=True)
            self.assertEqual(len(self.c.seen),1);self.assertEqual(self.c.holds(),60)
    def test_retry_limit_checked_during_review(self):
        self.c.mode='decline'
        with self.c.rpc() as url:
            self.open(url);q=self.call('queue');self.call('send',q['delivery_confirmation'])
            with patch('decision_delivery.MAX_ATTEMPTS',1),self.assertRaises(ValueError):self.call('review',replay=True)
    def test_wallet_change_after_capture_remains_outside_atomic_boundary(self):
        """Negative control: no claim of a wallet/network global transaction."""
        with self.c.rpc() as url:
            self.open(url);q=self.call('queue');dispatch=self.d.dispatch.dispatch
            def later(*args,**kwargs):
                self.c.sign(who=3,units=38)
                return dispatch(*args,**kwargs)
            with patch.object(self.d.dispatch,'dispatch',side_effect=later):
                self.call('send',q['delivery_confirmation'])
            self.assertEqual(len(self.c.seen),1);self.assertEqual(self.c.holds(),100)
    def test_same_signature_in_second_journal_still_not_globally_deduplicated(self):
        with self.c.rpc() as url:
            self.open(url);q=self.call('queue');self.call('send',q['delivery_confirmation']);self.d.close();self.d=None
            with DecisionDelivery(self.c.wallet_path,self.c.root/'second.sqlite',self.c.raw,self.c.policy,url,create=True,clock=lambda:self.c.clock) as other:
                r=other.queue(self.decision,**self.selection);other.send(self.decision,r['delivery_confirmation'],**self.selection)
            self.assertEqual(self.c.seen,[canonical(self.signed['result'])]*2)
            self.assertEqual(self.c.native_results,[0,1])
            self.assertEqual(self.c.exposed['state']['native']['budgets'][0][4],60)
    def test_two_payments_reconcile_then_explicitly_rereview_remaining(self):
        atlas=self.c.sign(who=3,units=38);a={'account':IDS[0],'grant_id':'atlas'}
        with self.c.rpc() as url:
            self.open(url);r=self.call('queue');old_atlas=self.d.queue(atlas['decision_id'],**a)
            self.call('send',r['delivery_confirmation']);self.call('refresh')
            self.assertEqual(self.c.holds(),100);self.call('reconcile',continuation=self.c.continuation())
            self.assertEqual(self.c.holds(),40)
            with self.assertRaises(ValueError):self.d.send(atlas['decision_id'],old_atlas['delivery_confirmation'],**a)
            self.assertEqual(len(self.c.seen),1)
            fresh=self.d.review(atlas['decision_id'],**a)
            self.assertEqual(fresh['submission_review']['next_attempt'],1)
            self.d.send(atlas['decision_id'],fresh['delivery_confirmation'],**a)
            self.d.refresh(atlas['decision_id'],**a);self.assertEqual(self.c.holds(),40)
            self.d.reconcile(atlas['decision_id'],continuation=self.c.continuation(),**a)
            self.assertEqual(self.c.holds(),0);self.assertEqual(len(self.c.seen),2)
            self.assertEqual(self.c.exposed['state']['native']['budgets'][0][4],100)
