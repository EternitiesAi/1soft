import copy
from concurrent.futures import ThreadPoolExecutor
import hashlib
import json
import os
from pathlib import Path
import sqlite3
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

from block_application import encode
from commit_verifier import load_json
from p4_delivery import P4Delivery, disjoint_paths, observation
from p4_evidence import content_id
from p4_wallet import P4Wallet
from delivery_fixture import Fixture


class DeliveryTests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory();self.root=Path(self.tmp.name)
        self.f=Fixture(self.root);self.d=self.f.delivery;self.did=self.f.sign()
    def tearDown(self):self.f.close();self.tmp.cleanup()
    def select(self,grant='raven'):return self.f.selection(grant)
    def collect(self):return self.d.collect(self.did,**self.select())
    def reconcile(self):return self.d.reconcile(self.did,**self.select(),expected_revision=self.f.wallet.status()['revision'])
    def test_preparation_does_not_submit_or_change_wallet(self):
        before=list(self.f.wallet.db.iterdump());p=self.f.review(self.did)
        self.assertFalse(p['submission_performed']);self.assertEqual(self.f.submissions,[])
        self.assertEqual(list(self.f.wallet.db.iterdump()),before)
    def test_dropped_reply_collects_exact_receipt_without_resend_or_hold_release(self):
        raw=self.f.wallet.recover(self.did,**self.select());r=self.f.send(self.did)
        self.assertEqual(r['transport_observation'],'unresolved');self.assertEqual(self.f.submissions,[raw])
        self.assertEqual(self.f.held(),60)
        self.d.close();self.f.delivery=self.d=self.f.open_delivery()
        r=self.collect();self.assertEqual(r['status'],'receipt_collected')
        self.assertEqual(self.f.submissions,[raw]);self.assertEqual(self.f.held(),60)
        self.assertEqual(self.reconcile()['status'],'wallet_reconciled');self.assertEqual(self.f.held(),0)
        self.assertEqual(self.reconcile()['status'],'already_recorded')
    def test_endpoint_admission_is_not_execution_proof(self):
        self.f.mode='admit_only';r=self.f.send(self.did)
        self.assertEqual(r['transport_observation'],'endpoint_admitted');self.assertFalse(r['execution_proven'])
        self.assertEqual(self.collect()['status'],'unavailable');self.assertEqual(self.f.held(),60)
    def test_endpoint_decline_does_not_retire_or_allow_retry(self):
        self.f.mode='reject';r=self.f.send(self.did)
        self.assertEqual(r['transport_observation'],'endpoint_declined');self.assertEqual(self.f.held(),60)
        with self.assertRaises(ValueError):self.f.review(self.did)
        self.assertEqual(self.collect()['status'],'unavailable');self.assertEqual(len(self.f.submissions),1)
    def test_wrong_hash_response_remains_unresolved(self):
        self.f.mode='wrong_hash';r=self.f.send(self.did)
        self.assertEqual(r['transport_observation'],'unresolved');self.assertEqual(self.f.held(),60)
        self.assertEqual(self.collect()['status'],'receipt_collected')
    def test_boolean_checktx_code_is_not_zero(self):
        self.f.mode='boolean_code';self.assertEqual(self.f.send(self.did)['transport_observation'],'unresolved')
    def test_repeated_send_cannot_open_second_socket(self):
        p=self.f.review(self.did);self.d.send(p['review'],p['confirmation'])
        with self.assertRaises(ValueError):self.d.send(p['review'],p['confirmation'])
        self.assertEqual(len(self.f.submissions),1)
    def test_two_writers_share_one_claim(self):
        p=self.f.review(self.did)
        def send(_):
            with self.f.open_delivery() as d:
                try:d.send(p['review'],p['confirmation']);return 'sent'
                except ValueError:return 'refused'
        with ThreadPoolExecutor(max_workers=2) as pool:r=list(pool.map(send,range(2)))
        self.assertEqual(sorted(r),['refused','sent']);self.assertEqual(len(self.f.submissions),1)
    def test_wrong_payer_refused_before_rpc(self):
        with self.assertRaises(ValueError):self.d.collect(self.did,payer=self.f.chain.merchant,grant_id='raven')
        self.assertEqual(self.f.reads,[])
    def test_wrong_role_has_no_owner_fallback(self):
        with self.assertRaises(ValueError):self.d.prepare(self.did,payer=self.f.chain.payer,grant_id='')
        self.assertEqual(self.f.reads,[])
    def test_unknown_decision_is_not_arbitrary_transaction_input(self):
        with self.assertRaises(ValueError):self.d.prepare('0'*64,**self.select())
        self.assertEqual(self.f.reads,[])
    def test_mismatched_confirmation_refused(self):
        p=self.f.review(self.did)
        with self.assertRaises(ValueError):self.d.send(p['review'],'0'*64)
        self.assertEqual(self.f.reads,[])
    def test_rehashed_changed_review_refused(self):
        p=self.f.review(self.did);v=p['review'];v['endpoint']='http://127.0.0.1:65534/'
        with self.assertRaises(ValueError):self.d.send(v,content_id(v))
        self.assertEqual(self.f.reads,[])
    def test_new_signature_invalidates_previous_delivery_review(self):
        p=self.f.review(self.did);self.f.sign('atlas',38)
        with self.assertRaises(ValueError):self.d.send(p['review'],p['confirmation'])
        self.assertEqual(self.f.reads,[])
    def test_new_checkpoint_invalidates_delivery_review(self):
        p=self.f.review(self.did);self.f.publish();self.f.sync()
        with self.assertRaises(ValueError):self.d.send(p['review'],p['confirmation'])
        self.assertEqual(self.f.reads,[])
    def test_after_turnover_original_wire_can_be_re_reviewed_and_sent(self):
        raw=self.f.wallet.recover(self.did,**self.select());self.f.turnover();self.f.sync()
        self.assertEqual(self.f.held(),60);self.f.send(self.did)
        self.assertEqual(self.f.submissions,[raw]);self.collect();self.reconcile()
        self.assertEqual(self.f.held(),0)
    def test_old_receipt_reconcile_after_newer_wallet_checkpoint_is_noop(self):
        atlas=self.f.sign('atlas',38);self.f.send(self.did);self.collect()
        self.f.send(atlas,'atlas');self.d.collect(atlas,**self.select('atlas'))
        self.d.reconcile(atlas,**self.select('atlas'),expected_revision=self.f.wallet.status()['revision'])
        before=list(self.f.wallet.db.iterdump());self.assertEqual(self.reconcile()['status'],'already_recorded')
        self.assertEqual(list(self.f.wallet.db.iterdump()),before);self.assertEqual(self.f.held(),0)
    def test_receipt_collection_does_not_change_either_signature_or_reservation(self):
        self.f.send(self.did);before=list(self.f.wallet.db.iterdump());self.collect()
        self.assertEqual(list(self.f.wallet.db.iterdump()),before)
    def test_exact_receipt_must_exist_before_reconciliation(self):
        self.f.send(self.did)
        with self.assertRaises(ValueError):self.reconcile()
        self.assertEqual(self.f.held(),60)
    def test_stale_expected_wallet_revision_refuses(self):
        old=self.f.wallet.status()['revision'];self.f.send(self.did);self.collect();self.f.sync()
        with self.assertRaises(ValueError):self.d.reconcile(self.did,**self.select(),expected_revision=old)
    def test_invalid_evidence_leaves_transport_and_wallet_unchanged(self):
        self.f.send(self.did);before=list(self.d.db.iterdump());wallet=list(self.f.wallet.db.iterdump())
        e=copy.deepcopy(self.f.proof);e['state']['native']['accounts'][0][4]+=1
        with self.assertRaises(ValueError):self.d.import_receipt(self.did,e,**self.select())
        self.assertEqual(list(self.d.db.iterdump()),before);self.assertEqual(list(self.f.wallet.db.iterdump()),wallet)
    def test_foreign_receipt_does_not_establish_this_payment(self):
        atlas=self.f.sign('atlas',38);self.f.send(atlas,'atlas')
        self.assertEqual(self.collect()['status'],'unavailable');self.assertEqual(self.f.held(),100)
    def test_included_but_rejected_replay_does_not_create_second_receipt(self):
        self.f.send(self.did);self.collect();first=self.d.export_receipt(self.did,**self.select())
        raw=self.f.submissions[0];out=self.f.chain.block([raw]);self.assertNotEqual(out['tx_results'][0]['code'],0)
        self.f.publish();self.assertEqual(self.collect()['status'],'already_collected')
        self.assertEqual(self.d.export_receipt(self.did,**self.select()),first)
    def test_receipt_import_before_attempt_blocks_submission(self):
        raw=self.f.wallet.recover(self.did,**self.select());self.f.chain.block([raw]);self.f.publish()
        self.collect()
        with self.assertRaises(ValueError):self.f.review(self.did)
        self.assertEqual(self.f.submissions,[])
    def test_failed_collection_preserves_existing_state(self):
        self.f.mode='read_error';before=list(self.d.db.iterdump())
        with self.assertRaises(ValueError):self.collect()
        self.assertEqual(list(self.d.db.iterdump()),before);self.assertEqual(self.f.held(),60)
    def test_expired_policy_refuses_new_send_and_collect(self):
        p=self.f.review(self.did);self.f.chain.now+=4000*10**9
        with self.assertRaises(ValueError):self.d.send(p['review'],p['confirmation'])
        with self.assertRaises(ValueError):self.collect()
        self.assertEqual(self.f.reads,[])
    def test_historical_status_and_receipt_export_survive_policy_expiry(self):
        self.f.send(self.did);self.collect();e=self.d.export_receipt(self.did,**self.select())
        self.f.chain.now+=4000*10**9
        self.assertEqual(self.d.inspect(self.did,**self.select())['receipt_status'],'verified_historical_receipt')
        self.assertEqual(self.d.export_receipt(self.did,**self.select()),e)
        with self.assertRaises(ValueError):self.reconcile()
    def test_revoked_original_grant_is_refused_before_network(self):
        self.f.chain.block([self.f.chain.owner_wire({'type':'revoke','id':'raven'})]);self.f.publish();self.f.sync()
        with self.assertRaises(ValueError):self.f.review(self.did)
        self.assertEqual(self.f.held(),60);self.assertEqual(self.f.reads,[])
    def test_expired_original_transfer_is_refused_before_network(self):
        for _ in range(34):self.f.chain.block([])
        self.f.chain.now+=60*10**9;self.f.publish();self.f.sync()
        with self.assertRaises(ValueError):self.f.review(self.did)
        self.assertEqual(self.f.held(),60)
    def test_no_key_unlock_during_delivery_collection_or_reconciliation(self):
        for p in self.root.glob('*.pem'):p.unlink()
        with patch('p4_wallet._load_vault',side_effect=AssertionError('no vault')),patch('p4_wallet.sign',side_effect=AssertionError('no signing')):
            self.f.send(self.did);self.collect();self.reconcile()
            self.assertEqual(self.f.held(),0)
    def test_constructor_rejects_wrong_endpoint_binding(self):
        with self.assertRaises(ValueError):P4Delivery(self.f.wp,self.f.dp,self.f.chain.genesis,self.f.chain.policy,'http://127.0.0.1:65534/',clock=self.f.chain.clock)
    def test_public_hostname_or_https_refused_before_creation(self):
        for endpoint in ('https://127.0.0.1:26657/','http://localhost:26657/','http://example.com:26657/'):
            with self.assertRaises(ValueError):P4Delivery(self.f.wp,self.root/'new.sqlite',self.f.chain.genesis,self.f.chain.policy,endpoint,create=True,clock=self.f.chain.clock)
        self.assertFalse((self.root/'new.sqlite').exists())
    def test_wallet_sidecar_alias_refused_before_creation(self):
        for suffix in ('','-wal','-shm','-journal'):
            with self.assertRaises(ValueError):P4Delivery(self.f.wp,Path(str(self.f.wp)+suffix),self.f.chain.genesis,self.f.chain.policy,self.f.url,create=True,clock=self.f.chain.clock)
        self.assertEqual(self.f.held(),60)
    def test_reverse_sidecar_alias_refused(self):
        with self.assertRaises(ValueError):disjoint_paths(self.root/'x.sqlite-wal',self.root/'x.sqlite')
    def test_wrong_database_not_repaired(self):
        p=self.root/'node.sqlite';db=sqlite3.connect(p);db.execute('CREATE TABLE committed(id INTEGER)');db.close();p.chmod(0o600)
        old=p.read_bytes()
        with self.assertRaises(ValueError):P4Delivery(self.f.wp,p,self.f.chain.genesis,self.f.chain.policy,self.f.url,clock=self.f.chain.clock)
        self.assertEqual(p.read_bytes(),old)
    def test_empty_existing_database_not_initialized(self):
        p=self.root/'empty.sqlite';p.touch(mode=0o600)
        with self.assertRaises(ValueError):P4Delivery(self.f.wp,p,self.f.chain.genesis,self.f.chain.policy,self.f.url,clock=self.f.chain.clock)
        self.assertEqual(p.read_bytes(),b'')
    def test_existing_journal_not_overwritten(self):
        before=list(self.d.db.iterdump())
        with self.assertRaises(FileExistsError):self.f.open_delivery(create=True)
        self.assertEqual(list(self.d.db.iterdump()),before)
    def test_missing_configuration_refused(self):
        self.d.db.execute('DELETE FROM config')
        with self.assertRaises(ValueError):self.f.review(self.did)
    def test_symlink_or_hardlink_journal_refused(self):
        p=self.root/'alias.sqlite';p.symlink_to(self.f.dp)
        with self.assertRaises(ValueError):P4Delivery(self.f.wp,p,self.f.chain.genesis,self.f.chain.policy,self.f.url,clock=self.f.chain.clock)
        p.unlink();os.link(self.f.dp,p)
        with self.assertRaises(ValueError):self.f.open_delivery()
        p.unlink()
    def test_failed_attempt_commit_never_submits(self):
        p=self.f.review(self.did)
        def deny(action,arg,*_):
            return sqlite3.SQLITE_DENY if action==sqlite3.SQLITE_TRANSACTION and arg=='COMMIT' else sqlite3.SQLITE_OK
        self.d.db.set_authorizer(deny)
        with self.assertRaises(sqlite3.DatabaseError):self.d.send(p['review'],p['confirmation'])
        self.d.db.set_authorizer(None);self.assertEqual(self.f.submissions,[])
        self.assertFalse(self.d.inspect(self.did,**self.select())['attempt_recorded'])
    def test_missing_response_after_worker_exception_is_unknown_and_no_retry(self):
        p=self.f.review(self.did)
        with patch('p4_delivery.submit_once',side_effect=RuntimeError('interrupted caller')):
            with self.assertRaises(RuntimeError):self.d.send(p['review'],p['confirmation'])
        self.assertTrue(self.d.inspect(self.did,**self.select())['attempt_recorded'])
        with self.assertRaises(ValueError):self.d.send(p['review'],p['confirmation'])
        self.assertEqual(self.f.submissions,[])
    def test_altered_stored_review_refused(self):
        self.f.send(self.did);row=self.d.db.execute('SELECT review FROM attempts').fetchone();v=json.loads(row[0]);v['wire_sha256']='0'*64
        self.d.db.execute('UPDATE attempts SET review=?',(encode(v),))
        with self.assertRaises(ValueError):self.d.inspect(self.did,**self.select())
    def test_altered_collected_proof_refused(self):
        self.f.send(self.did);self.collect();v=json.loads(self.d.db.execute('SELECT payload FROM receipts').fetchone()[0])
        v['evidence']['state']['native']['accounts'][0][4]+=1
        self.d.db.execute('UPDATE receipts SET payload=?',(encode(v),))
        with self.assertRaises(ValueError):self.d.export_receipt(self.did,**self.select())
    def test_boolean_endpoint_observation_refused(self):
        with self.assertRaises(ValueError):observation({'observation':'endpoint_admitted','check_tx_code':False,'response_sha256':'0'*64})
    def test_attempt_capacity_refuses_without_socket(self):
        with patch('p4_delivery.MAX_ATTEMPTS',0):
            p=self.f.review(self.did)
            with self.assertRaises(ValueError):self.d.send(p['review'],p['confirmation'])
        self.assertEqual(self.f.reads,[])
    def test_receipt_capacity_refuses_without_releasing_hold(self):
        self.f.send(self.did)
        with patch('p4_delivery.MAX_RECEIPTS',0):
            with self.assertRaises(ValueError):self.collect()
        self.assertEqual(self.f.held(),60)
    def test_receipt_export_requires_exact_payer_and_grant(self):
        self.f.send(self.did);self.collect()
        with self.assertRaises(ValueError):self.d.export_receipt(self.did,payer=self.f.chain.payer,grant_id='atlas')
    def test_delayed_endpoint_response_after_expiry_is_recorded_but_non_authorizing(self):
        actual=__import__('p4_delivery').submit_once
        def late(*args):
            r=actual(*args);self.f.chain.now+=4000*10**9;return r
        self.f.mode='admit_only';p=self.f.review(self.did)
        with patch('p4_delivery.submit_once',late):result=self.d.send(p['review'],p['confirmation'])
        self.assertEqual(result['transport_observation'],'endpoint_admitted')
        self.assertFalse(self.d.inspect(self.did,**self.select())['current_spending_authority'])
    def test_response_storage_failure_does_not_erase_attempt_or_resend(self):
        p=self.f.review(self.did)
        def deny(action,name,*_):
            return sqlite3.SQLITE_DENY if action==sqlite3.SQLITE_INSERT and name=='responses' else sqlite3.SQLITE_OK
        self.d.db.set_authorizer(deny)
        with self.assertRaises(sqlite3.DatabaseError):self.d.send(p['review'],p['confirmation'])
        self.d.db.set_authorizer(None)
        self.assertEqual(len(self.f.submissions),1)
        self.assertEqual(self.d.inspect(self.did,**self.select())['transport_observation'],'unresolved')
        with self.assertRaises(ValueError):self.d.send(p['review'],p['confirmation'])
        self.collect();self.reconcile();self.assertEqual(self.f.held(),0)
    def test_external_spending_deficit_refuses_dispatch_without_releasing_hold(self):
        raw=self.f.chain.owner_wire({'type':'transfer','to':self.f.chain.merchant,'units':935})
        self.f.chain.block([raw]);self.f.publish();self.f.sync()
        with self.assertRaises(ValueError):self.f.review(self.did)
        self.assertEqual(self.f.held(),60);self.assertEqual(self.f.reads,[])
    def test_expiry_after_no_receipt_verification_is_still_refused(self):
        import p4_delivery
        actual=p4_delivery.verify_evidence
        def elapsed(*args,**kwargs):
            result=actual(*args,**kwargs);self.f.chain.now+=4000*10**9;return result
        with patch('p4_delivery.verify_evidence',side_effect=elapsed):
            with self.assertRaises(ValueError):self.d.import_receipt(self.did,self.f.proof,**self.select())
        self.assertEqual(self.d.db.execute('SELECT count(*) FROM receipts').fetchone()[0],0)
    def test_mutating_caller_proof_does_not_change_verified_saved_bytes(self):
        import p4_delivery
        self.f.send(self.did);external=copy.deepcopy(self.f.proof);saved=copy.deepcopy(external)
        actual=p4_delivery.verify_evidence
        def mutate(*args,**kwargs):
            result=actual(*args,**kwargs);external['state']['native']['accounts'][0][4]+=1;return result
        with patch('p4_delivery.verify_evidence',side_effect=mutate):
            self.d.import_receipt(self.did,external,**self.select())
        self.assertEqual(self.d.export_receipt(self.did,**self.select()),saved)
    def test_attempt_exists_before_submit_worker_is_called(self):
        p=self.f.review(self.did);observed=[]
        def worker(*args):
            db=sqlite3.connect(self.f.dp)
            try:observed.append(db.execute('SELECT decision_id FROM attempts').fetchone()[0])
            finally:db.close()
            return {'observation':'unresolved','reason':'test interrupted before transport'}
        with patch('p4_delivery.submit_once',worker):self.d.send(p['review'],p['confirmation'])
        self.assertEqual(observed,[self.did]);self.assertEqual(self.f.submissions,[])
    def test_submission_does_not_hold_wallet_database_lock_during_io(self):
        p=self.f.review(self.did);actual=__import__('p4_delivery').submit_once
        def worker(*args):
            db=sqlite3.connect(self.f.wp,timeout=.05,isolation_level=None)
            try:db.execute('BEGIN IMMEDIATE');db.execute('ROLLBACK')
            finally:db.close()
            return actual(*args)
        with patch('p4_delivery.submit_once',worker):self.d.send(p['review'],p['confirmation'])
        self.assertEqual(len(self.f.submissions),1)

    def test_second_delivery_journal_is_not_claimed_globally_coordinated(self):
        raw=self.f.wallet.recover(self.did,**self.select());self.f.send(self.did)
        with P4Delivery(self.f.wp,self.root/'other.sqlite',self.f.chain.genesis,self.f.chain.policy,self.f.url,create=True,clock=self.f.chain.clock) as d:
            r=d.prepare(self.did,**self.select());d.send(r['review'],r['confirmation'])
        self.assertEqual(self.f.submissions,[raw,raw])
        # Native replay rejects the second request: exact receipt count stays one.
        receipts=self.f.chain.app.state['native']['receipts']
        self.assertEqual(sum(json.loads(r[3])['envelope']==json.loads(raw) for r in receipts),1)


if __name__=='__main__':unittest.main()
