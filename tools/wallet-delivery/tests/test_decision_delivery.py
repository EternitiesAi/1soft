"""Decision-bound delivery using actual local I/O; no consensus-engine claim."""
import copy
import hashlib
import json
import os
from pathlib import Path
import shutil
import sqlite3
import subprocess
import sys
import unittest
from unittest.mock import patch

from decision_delivery import DecisionDelivery
from delivery_fixture import Scenario, IDS, KEYS, PASSWORD
from native_core import canonical, public, sign
from commit_verifier import encode, verify_packet
from certified_wallet import CertifiedWallet

ROOT=Path(__file__).resolve().parents[1]


class DeliveryTests(unittest.TestCase):
    def setUp(self):
        self.c=Scenario();self.signed=self.c.sign();self.decision=self.signed['decision_id'];self.d=None
    def tearDown(self):
        if self.d:self.d.close()
        self.c.close()
    def open(self,url='http://127.0.0.1:26657/',create=True,**kw):
        if self.d:self.d.close()
        args=dict(wallet_journal=self.c.wallet_path,delivery_journal=self.c.delivery_path,
                  genesis_bytes=self.c.raw,policy=self.c.policy,endpoint=url,create=create,clock=lambda:self.c.clock)
        args.update(kw);self.d=DecisionDelivery(**args);return self.d
    def call(self,method,*args,**kw):
        return getattr(self.d,method)(self.decision,*args,account=IDS[0],grant_id='raven',**kw)
    def queue(self):return self.call('queue')
    def sent(self,url):
        self.open(url);q=self.queue();return self.call('send',q['delivery_confirmation'])
    def test_queue_selects_exact_existing_signed_decision(self):
        self.open();before='\n'.join(self.c.wallet.db.iterdump())
        with patch('payment_transport._worker',side_effect=AssertionError('no I/O')),patch('certified_wallet._load_vault',side_effect=AssertionError('no keys')):
            q=self.queue()
        self.assertEqual(q['transport_status'],'queued');self.assertEqual(q['wallet_obligation_status'],'pending')
        self.assertEqual(self.d.dispatch.export(q['native_txid']),canonical(self.signed['result']))
        self.assertEqual('\n'.join(self.c.wallet.db.iterdump()),before);self.assertEqual(self.c.holds(),60)
    def test_unknown_decision_refuses_before_network(self):
        self.open()
        with patch('payment_transport._worker',side_effect=AssertionError('no I/O')):
            with self.assertRaises(ValueError):self.d.queue('0'*64,account=IDS[0],grant_id='raven')
    def test_wrong_account_cannot_select_payment(self):
        self.open()
        with self.assertRaises(ValueError):self.d.queue(self.decision,account=IDS[1],grant_id='raven')
    def test_wrong_role_and_owner_fallback_refused(self):
        self.open()
        for role in ('','atlas','missing'):
            with self.subTest(role=role),self.assertRaises(ValueError):self.d.queue(self.decision,account=IDS[0],grant_id=role)
    def test_no_file_import_interface(self):
        self.open()
        with self.assertRaises(TypeError):self.d.queue(envelope=self.signed['result'],account=IDS[0])
    def test_distinct_store_required_before_any_schema_write(self):
        before='\n'.join(self.c.wallet.db.iterdump())
        with self.assertRaises(ValueError):self.open(delivery_journal=self.c.wallet_path)
        self.assertEqual('\n'.join(self.c.wallet.db.iterdump()),before)
    def test_other_wallet_file_not_repurposed_as_dispatcher(self):
        other=self.c.root/'other.sqlite'
        w=CertifiedWallet(other,self.c.raw,self.c.policy,clock=lambda:self.c.clock);w.close()
        db=sqlite3.connect(other);before='\n'.join(db.iterdump());db.close()
        with self.assertRaises(ValueError):self.open(delivery_journal=other)
        db=sqlite3.connect(other);self.assertEqual('\n'.join(db.iterdump()),before);db.close()
    def test_missing_wallet_never_created(self):
        target=self.c.root/'no-wallet.sqlite'
        with self.assertRaises((OSError,ValueError)):self.open(wallet_journal=target)
        self.assertFalse(target.exists());self.assertFalse(self.c.delivery_path.exists())
    def test_status_cannot_create_missing_delivery_journal(self):
        with self.assertRaises(ValueError):self.open(create=False)
        self.assertFalse(self.c.delivery_path.exists())
    def test_nonloopback_refused(self):
        with self.assertRaises(ValueError):self.open(url='https://example.com/')
        self.assertFalse(self.c.delivery_path.exists())
    def test_queue_repeated_is_same_no_duplicate_event(self):
        self.open();a=self.queue();b=self.queue();self.assertEqual(a,b)
        self.assertEqual(len(self.d.dispatch.events(a['native_txid'])),1)
    def test_unknown_result_is_not_a_new_send(self):
        with self.c.rpc() as url:
            result=self.sent(url);self.assertEqual(result['transport_status'],'unresolved')
            self.assertEqual(result['wallet_obligation_status'],'pending');self.assertEqual(len(self.c.seen),1)
            q=self.queue();self.assertEqual(q['submission_attempts'],1)
            with self.assertRaises(ValueError):self.call('send',q['delivery_confirmation'])
            self.assertEqual(len(self.c.seen),1);self.assertEqual(self.c.holds(),60)
    def test_route_confirmation_is_not_original_signing_confirmation(self):
        self.open();q=self.queue()
        with self.assertRaises(ValueError):self.call('send',self.decision)
        self.assertNotEqual(q['delivery_confirmation'],self.decision)
        self.assertEqual(self.call('status')['submission_attempts'],0)
    def test_confirmation_bound_to_explicit_delivery_location(self):
        self.open();q=self.queue();self.d.close();self.d=None
        self.open(delivery_journal=self.c.root/'another.sqlite');other=self.queue()
        self.assertNotEqual(q['delivery_confirmation'],other['delivery_confirmation'])
        with self.assertRaises(ValueError):self.call('send',q['delivery_confirmation'])
    def test_signature_mutation_rejected_before_socket(self):
        self.open();q=self.queue();row=self.c.wallet.db.execute('SELECT result FROM decisions').fetchone()
        r=json.loads(row[0]);r['signature']='0'*128;data=canonical(r)
        self.c.wallet.db.execute('UPDATE decisions SET result=?,result_hash=?',(data.decode(),hashlib.sha256(data).hexdigest()))
        with patch('payment_transport._worker',side_effect=AssertionError('no I/O')):
            with self.assertRaises(ValueError):self.call('send',q['delivery_confirmation'])
    def test_expired_policy_stops_send_but_not_historical_status(self):
        self.open();q=self.queue();self.c.clock=self.d.dispatch.deadline
        with self.assertRaises(ValueError):self.call('send',q['delivery_confirmation'])
        s=self.call('status');self.assertIn('policy_expired',s['wallet_time_frontier_blockers']);self.assertEqual(s['wallet_obligation_status'],'pending')
    def test_stale_saved_state_cannot_send(self):
        self.open();q=self.queue();self.c.clock+=400*10**9
        with self.assertRaises(ValueError):self.call('send',q['delivery_confirmation'])
        self.assertEqual(self.c.holds(),60)
    def test_revoked_grant_prevents_send_without_releasing_hold(self):
        self.open();q=self.queue()
        from block_application import restore
        l=restore(self.c.genesis,self.c.exposed['state']['native'])
        raw=canonical(sign(KEYS[0],l.body(IDS[0],4,{'type':'revoke','id':'raven'})));l.close()
        self.c.latest_after(raw);self.c.wallet.sync(self.c.exposed,continuation=self.c.continuation())
        with self.assertRaises(ValueError):self.call('send',q['delivery_confirmation'])
        self.assertEqual(self.c.holds(),60)
    def test_recorded_decision_not_sent_again(self):
        with self.c.rpc() as url:
            q=self.sent(url);self.call('refresh');self.call('reconcile',continuation=self.c.continuation())
            with self.assertRaises(ValueError):self.call('send',q['delivery_confirmation'],replay=True)
            self.assertEqual(len(self.c.seen),1)
    def test_receipt_collection_does_not_modify_signing_journal(self):
        with self.c.rpc() as url:
            self.sent(url);before='\n'.join(self.c.wallet.db.iterdump())
            r=self.call('refresh');self.assertTrue(r['exact_transport_receipt_verified'])
            self.assertEqual(r['wallet_obligation_status'],'pending');self.assertTrue(r['wallet_reconciliation_needed'])
            self.assertEqual('\n'.join(self.c.wallet.db.iterdump()),before);self.assertEqual(self.c.holds(),60)
    def test_end_to_end_lost_response_reopen_collect_sync(self):
        with self.c.rpc() as url:
            self.sent(url);original=canonical(self.signed['result']);self.open(url,create=False)
            with patch('certified_wallet._load_vault',side_effect=AssertionError('no keys')):
                collected=self.call('refresh');self.assertEqual(self.c.holds(),60)
                result=self.call('reconcile',continuation=self.c.continuation())
            self.assertTrue(result['wallet_sync_performed']);self.assertEqual(result['wallet_obligation_status'],'recorded')
            self.assertFalse(result['wallet_reconciliation_needed']);self.assertEqual(self.c.holds(),0)
            self.assertEqual(self.c.wallet.export(self.decision)['result'],self.signed['result'])
            self.assertEqual(self.c.seen,[original])
            self.assertEqual(self.c.exposed['state']['native']['budgets'][0][4],60)
    def test_missing_header_continuation_does_not_release_hold(self):
        with self.c.rpc() as url:
            self.sent(url);self.call('refresh');before='\n'.join(self.c.wallet.db.iterdump())
            with self.assertRaises(ValueError):self.call('reconcile')
            self.assertEqual(self.c.holds(),60);self.assertEqual('\n'.join(self.c.wallet.db.iterdump()),before)
            self.assertTrue(self.call('status')['exact_transport_receipt_verified'])
    def test_corrupt_transport_proof_rejected_on_status_and_sync(self):
        with self.c.rpc() as url:
            self.sent(url);self.call('refresh');self.d.dispatch.db.execute('UPDATE payments SET proof=?',(b'{}',))
            for method in ('status','reconcile','export_receipt'):
                with self.subTest(method=method),self.assertRaises(ValueError):self.call(method)
            self.assertEqual(self.c.holds(),60)
    def test_expiry_after_collection_preserves_receipt_and_hold(self):
        with self.c.rpc() as url:
            self.sent(url);self.call('refresh');self.c.clock=self.d.dispatch.deadline
            with self.assertRaises(ValueError):self.call('reconcile',continuation=self.c.continuation())
            proof=self.call('export_receipt');self.assertIsInstance(proof,bytes);self.assertEqual(self.c.holds(),60)
    def test_proof_export_independent_verification_no_network(self):
        with self.c.rpc() as url:
            self.sent(url);self.call('refresh');before=len(self.c.requests)
            raw=self.call('export_receipt')
            result=verify_packet(json.loads(raw),self.c.trust,expected_txids=[self.call('status')['native_txid']])
            self.assertEqual(result['status'],'verified');self.assertEqual(len(self.c.requests),before)
    def test_replay_explicit_same_bytes_only(self):
        self.c.mode='decline'
        with self.c.rpc() as url:
            first=self.sent(url);self.assertEqual(first['transport_status'],'endpoint_declined')
            second=self.call('send',first['delivery_confirmation'],replay=True)
            self.assertEqual(second['submission_attempts'],2);self.assertEqual(self.c.seen,[canonical(self.signed['result'])]*2)
            self.assertEqual(self.c.holds(),60)
    def test_admission_reply_does_not_mark_wallet_paid(self):
        self.c.mode='admit'
        with self.c.rpc() as url:
            r=self.sent(url);self.assertEqual(r['transport_status'],'endpoint_admitted')
            self.assertFalse(r['exact_transport_receipt_verified']);self.assertEqual(self.c.holds(),60)
    def test_two_agents_share_one_signing_reservation_and_reconcile(self):
        with self.assertRaises(ValueError):self.c.sign(who=3,units=39)
        atlas=self.c.sign(who=3,units=38);self.assertEqual(self.c.holds(),100)
        with self.c.rpc() as url:
            self.sent(url);self.call('refresh');self.call('reconcile',continuation=self.c.continuation())
            self.assertEqual(self.c.holds(),40)
            kw={'account':IDS[0],'grant_id':'atlas'};q=self.d.queue(atlas['decision_id'],**kw)
            self.d.send(atlas['decision_id'],q['delivery_confirmation'],**kw)
            self.d.refresh(atlas['decision_id'],**kw)
            self.d.reconcile(atlas['decision_id'],continuation=self.c.continuation(),**kw)
            self.assertEqual(self.c.holds(),0);self.assertEqual(len(self.c.seen),2)
            self.assertEqual(self.c.exposed['state']['native']['budgets'][0][4],100)
    def test_reconcile_interrupted_after_wallet_commit_is_idempotent(self):
        with self.c.rpc() as url:
            self.sent(url);self.call('refresh');links=self.c.continuation()
            original=CertifiedWallet.sync
            def after_commit(w,*args,**kwargs):
                original(w,*args,**kwargs);raise RuntimeError('simulated interrupted caller')
            with patch.object(CertifiedWallet,'sync',after_commit),self.assertRaises(RuntimeError):self.call('reconcile',continuation=links)
            self.assertEqual(self.c.holds(),0)
            self.assertEqual(self.call('reconcile')['wallet_obligation_status'],'recorded')
            self.assertEqual(len(self.c.seen),1)
    def test_expired_absent_decision_not_submitted(self):
        # Existing signature remains valid through 100. Advance verified state beyond it.
        self.open();q=self.queue()
        for _ in range(100):self.c.block([])
        self.c.exposed=self.c.witness(101)
        # Direct sync supports only 64 intermediate headers: feed two actual signed checkpoints.
        self.c.wallet.sync(self.c.witness(60),continuation=[self.c.headers[h] for h in range(3,61)])
        self.c.wallet.sync(self.c.exposed,continuation=self.c.continuation())
        with self.assertRaises(ValueError):self.call('send',q['delivery_confirmation'])
        self.assertEqual(self.call('status')['wallet_obligation_status'],'expired_absent')
    def test_actual_process_death_after_dispatch_leaves_original_recoverable(self):
        with self.c.rpc() as url:
            self.open(url);q=self.queue();self.d.close();self.d=None
            for name,val in [('genesis',self.c.engine),('policy',self.c.policy)]:
                (self.c.root/(name+'.json')).write_bytes(encode(val))
            code='''from pathlib import Path
import json,os,sys
from decision_delivery import DecisionDelivery
import payment_transport
p=Path(sys.argv[1]);original=payment_transport._worker
def drop(*a): original(*a);os._exit(31)
payment_transport._worker=drop
with DecisionDelivery(p/'wallet.sqlite',p/'delivery.sqlite',(p/'genesis.json').read_bytes(),json.loads((p/'policy.json').read_bytes()),sys.argv[2],clock=lambda:int(sys.argv[6])) as d:
 d.send(sys.argv[3],sys.argv[4],account=sys.argv[5],grant_id='raven')
'''
            p=subprocess.run([sys.executable,'-c',code,str(self.c.root),url,self.decision,q['delivery_confirmation'],IDS[0],str(self.c.clock)],capture_output=True,timeout=12)
            self.assertEqual(p.returncode,31,p.stderr);self.open(url,create=False)
            self.assertEqual(self.call('status')['transport_status'],'dispatching');self.assertEqual(self.c.holds(),60)
            self.call('refresh');self.call('reconcile',continuation=self.c.continuation())
            self.assertEqual(self.c.holds(),0);self.assertEqual(len(self.c.seen),1)
    def test_unsupported_dispatch_schema_rejected_without_altering_it(self):
        db=sqlite3.connect(self.c.delivery_path);db.execute('CREATE TABLE arbitrary(payload TEXT)');db.commit();db.close()
        self.c.delivery_path.chmod(0o600)
        with self.assertRaises(ValueError):self.open()
        db=sqlite3.connect(self.c.delivery_path)
        self.assertEqual(db.execute("SELECT name FROM sqlite_master WHERE type='table'").fetchall(),[('arbitrary',)]);db.close()
    def test_changed_endpoint_requires_another_explicit_route(self):
        self.open();self.queue();self.d.close();self.d=None
        with self.assertRaises(ValueError):self.open(url='http://127.0.0.1:26658/')
    def test_full_native_receipt_absence_not_truncated_view_controls_selection(self):
        second=self.c.sign(who=3,units=38);self.open()
        for result,role in [(self.signed,'raven'),(second,'atlas')]:
            q=self.d.queue(result['decision_id'],account=IDS[0],grant_id=role)
            self.assertEqual(q['wallet_obligation_status'],'pending')
        self.assertEqual(self.c.holds(),100)

    def test_evidence_ages_out_during_preflight_without_submission(self):
        self.open();q=self.queue()
        from native_core import NativeLedger
        apply=NativeLedger.apply
        def slow(l,*args,**kwargs):
            r=apply(l,*args,**kwargs);self.c.clock+=400*10**9;return r
        with patch.object(NativeLedger,'apply',slow),patch('payment_transport._worker',side_effect=AssertionError('no I/O')):
            with self.assertRaisesRegex(ValueError,'expired during'):self.call('send',q['delivery_confirmation'])
        self.assertEqual(self.call('status')['submission_attempts'],0)
    def test_admin_and_incoming_consent_decisions_cannot_be_delivered(self):
        self.open()
        op={'type':'fence'}
        b=self.c.body(who=0,units=1);b['op']=op
        r=self.c.wallet.review(self.c.exposed,b,public(KEYS[0]))
        result=self.c.wallet.approve(self.c.exposed,b,public(KEYS[0]),r['confirmation'],self.c.root/'key0.pem',PASSWORD)
        with self.assertRaises(ValueError):self.d.queue(result['decision_id'],account=IDS[0])
    def test_read_only_status_does_not_demand_signing_clock(self):
        self.open();self.queue();self.c.clock+=500*10**9
        with patch('certified_wallet._load_vault',side_effect=AssertionError('no keys')):
            s=self.call('status')
        self.assertIn('snapshot_too_old',s['wallet_time_frontier_blockers'])
        self.assertEqual(s['wallet_obligation_status'],'pending')
    def test_competing_dispatcher_is_excluded(self):
        self.open();self.queue()
        with self.assertRaises(BlockingIOError):
            DecisionDelivery(self.c.wallet_path,self.c.delivery_path,self.c.raw,self.c.policy,
                             'http://127.0.0.1:26657/',clock=lambda:self.c.clock)
    def test_no_pending_release_on_endpoint_decline(self):
        self.c.mode='decline'
        with self.c.rpc() as url:
            self.sent(url);r=self.call('refresh')
            self.assertEqual(r['collection_status'],'evidence_unavailable')
            self.assertFalse(r['exact_transport_receipt_verified']);self.assertEqual(self.c.holds(),60)
    def test_protocol_variants_run_same_delivery_path(self):
        for version,compact in [(1,False),(2,False),(3,False),(3,True)]:
            with self.subTest(version=version,compact=compact):
                c=Scenario(version=version,compact=compact)
                try:
                    result=c.sign()
                    with c.rpc() as url,DecisionDelivery(c.wallet_path,c.delivery_path,c.raw,c.policy,url,
                                                          create=True,clock=lambda:c.clock) as d:
                        kw={'account':IDS[0],'grant_id':'raven'}
                        q=d.queue(result['decision_id'],**kw)
                        d.send(result['decision_id'],q['delivery_confirmation'],**kw)
                        d.refresh(result['decision_id'],**kw)
                        r=d.reconcile(result['decision_id'],continuation=c.continuation(),**kw)
                        self.assertEqual(r['wallet_obligation_status'],'recorded')
                        self.assertEqual(c.holds(),0);self.assertEqual(len(c.seen),1)
                finally:c.close()

    def test_incoming_key_consent_is_not_a_payment(self):
        self.open()
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
        k=Ed25519PrivateKey.from_private_bytes(bytes([85])*32)
        from cryptography.hazmat.primitives import serialization as ser
        path=self.c.root/'incoming.pem'
        path.write_bytes(k.private_bytes(ser.Encoding.PEM,ser.PrivateFormat.PKCS8,ser.BestAvailableEncryption(PASSWORD)));path.chmod(0o600)
        b=self.c.body(who=0,units=1)
        b['op']={'type':'open_account','public_key':public(k),'units':20,'acceptance':''}
        r=self.c.wallet.review(self.c.exposed,b,public(k),mode='accept')
        result=self.c.wallet.approve(self.c.exposed,b,public(k),r['confirmation'],path,PASSWORD,mode='accept')
        with self.assertRaises(ValueError):self.d.queue(result['decision_id'],account=IDS[0])
    def test_other_delivery_store_is_not_claimed_globally_deduplicated(self):
        with self.c.rpc() as url:
            self.sent(url)
            self.open(url,delivery_journal=self.c.root/'other-delivery.sqlite')
            q=self.queue();self.call('send',q['delivery_confirmation'])
            self.assertEqual(len(self.c.seen),2)
            self.assertEqual(self.c.seen[0],self.c.seen[1])
            self.assertEqual(self.c.exposed['state']['native']['budgets'][0][4],60)
    def test_actual_process_exit_after_reconcile_recovers_completed_wallet(self):
        with self.c.rpc() as url:
            self.sent(url);self.call('refresh');self.d.close();self.d=None
            for name,value in [('genesis',self.c.engine),('policy',self.c.policy),('links',self.c.continuation())]:
                (self.c.root/(name+'.json')).write_bytes(encode(value))
            code="""from pathlib import Path
import json,os,sys
from decision_delivery import DecisionDelivery
from certified_wallet import CertifiedWallet
p=Path(sys.argv[1]);old=CertifiedWallet.sync
def stop(w,*args,**kwargs):old(w,*args,**kwargs);os._exit(33)
CertifiedWallet.sync=stop
with DecisionDelivery(p/'wallet.sqlite',p/'delivery.sqlite',(p/'genesis.json').read_bytes(),json.loads((p/'policy.json').read_bytes()),sys.argv[2],clock=lambda:int(sys.argv[5])) as d:
 d.reconcile(sys.argv[3],account=sys.argv[4],grant_id='raven',continuation=json.loads((p/'links.json').read_bytes()))
"""
            p=subprocess.run([sys.executable,'-c',code,str(self.c.root),url,self.decision,IDS[0],str(self.c.clock)],capture_output=True,timeout=12)
            self.assertEqual(p.returncode,33,p.stderr);self.assertEqual(self.c.holds(),0)
            self.open(url,create=False)
            self.assertEqual(self.call('reconcile')['wallet_obligation_status'],'recorded')
            self.assertEqual(len(self.c.seen),1)


if __name__=='__main__':unittest.main()
