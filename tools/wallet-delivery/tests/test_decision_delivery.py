"""Real loopback delivery and wallet journals; synthetic committees, no funds."""
from contextlib import contextmanager
import copy
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

from decision_delivery import DecisionDelivery
from delivery_fixture import Node, server, fixtures
from commit_verifier import encode, verify_packet
from native_core import canonical

ROOT = Path(__file__).resolve().parents[1]


class DeliveryTests(unittest.TestCase):
    def setUp(self):
        self.c = fixtures.ObligationTests(); self.c.setUp(); self.c.sync()
        self.signed = self.c.approve()
        self.node = Node(self.c)
        self.dispatch_path = self.c.root/'dispatch.sqlite'
    def tearDown(self): self.c.tearDown()
    def service(self, url='http://127.0.0.1:26657/', **change):
        options = dict(dispatch_journal=self.dispatch_path, endpoint=url, account=fixtures.IDS[0],
                       grant_id='raven', decision_id=self.signed['decision_id'], clock=lambda:self.c.clock)
        options.update(change)
        return DecisionDelivery(self.c.path,self.c.raw,self.c.policy,**options)
    def logical_wallet(self): return '\n'.join(self.c.wallet.db.iterdump())
    def broadcasts(self): return [r for r in self.node.requests if r['method']=='broadcast_tx_sync']
    def held(self): return self.c.wallet.pending()['pending_account_units'].get(fixtures.IDS[0],0)
    def run_send(self, service):
        plan = service.review()
        return service.send(plan['confirmation'])
    def test_status_of_unstaged_decision_creates_no_dispatcher(self):
        before=self.logical_wallet(); out=self.service().status()
        self.assertEqual(out['delivery_status'],'not_staged');self.assertFalse(self.dispatch_path.exists())
        self.assertEqual(before,self.logical_wallet());self.assertEqual(self.held(),60)
    def test_review_stages_exact_bytes_without_signing_or_network(self):
        before=self.logical_wallet()
        with patch('payment_transport._worker',side_effect=AssertionError('no network')), \
             patch('certified_wallet._load_vault',side_effect=AssertionError('no key')):
            plan=self.service().review()
        db=sqlite3.connect(self.dispatch_path)
        self.assertEqual(db.execute('SELECT raw FROM payments').fetchone()[0],canonical(self.signed['result']));db.close()
        self.assertEqual(plan['total_debit_units'],60);self.assertEqual(plan['next_attempt'],1)
        self.assertEqual(self.held(),60);self.assertEqual(before,self.logical_wallet())
    def test_repeated_review_reuses_staged_payment(self):
        service=self.service();self.assertEqual(service.review(),service.review())
        self.assertEqual(service.status()['attempts'],0)
    def test_wrong_explicit_account_refused_before_dispatch_creation(self):
        with self.assertRaisesRegex(ValueError,'explicitly selected'): self.service(account=fixtures.IDS[5]).review()
        self.assertFalse(self.dispatch_path.exists())
    def test_wrong_grant_never_falls_back_to_owner(self):
        for grant in ('', 'atlas', 'missing'):
            with self.subTest(grant=grant),self.assertRaisesRegex(ValueError,'explicitly selected'):
                self.service(grant_id=grant).review()
        self.assertFalse(self.dispatch_path.exists())
    def test_unsigned_draft_id_cannot_be_delivered(self):
        with self.assertRaisesRegex(ValueError,'signed decision not found'):
            self.service(decision_id='0'*64).review()
        self.assertFalse(self.dispatch_path.exists())
    def test_bad_decision_id_and_public_endpoint_refused(self):
        for value in ('x',True,None):
            with self.assertRaises(ValueError):self.service(decision_id=value)
        for url in ('https://127.0.0.1:26657/','http://localhost:26657/','http://example.com:26657/'):
            with self.assertRaises(ValueError):self.service(url)
    def test_wallet_or_its_sidecar_cannot_be_dispatch_journal(self):
        before=self.logical_wallet()
        for path in (self.c.path, Path(str(self.c.path)+'-wal')):
            with self.assertRaisesRegex(ValueError,'separate'):
                self.service(dispatch_journal=path)
        self.assertEqual(before,self.logical_wallet())
    def test_unknown_existing_database_not_migrated(self):
        db=sqlite3.connect(self.dispatch_path);db.execute('CREATE TABLE private_data(v TEXT)');db.commit();db.close()
        self.dispatch_path.chmod(0o600)
        before=self.dispatch_path.read_bytes()
        with self.assertRaisesRegex(ValueError,'supported dispatch journal'):self.service().review()
        self.assertEqual(before,self.dispatch_path.read_bytes())
    def test_same_endpoint_policy_required_on_reopen(self):
        self.service().review()
        with self.assertRaisesRegex(ValueError,'differs'):self.service('http://127.0.0.1:26658/').status()
    def test_changed_pending_inventory_invalidates_confirmation(self):
        with server(self.node) as url:
            service=self.service(url);plan=service.review();self.c.approve(3,38)
            with self.assertRaisesRegex(ValueError,'context changed'):service.send(plan['confirmation'])
        self.assertEqual(self.node.requests,[]);self.assertEqual(self.held(),100)
    def test_wrong_confirmation_no_io(self):
        with server(self.node) as url:
            service=self.service(url);service.review()
            with self.assertRaisesRegex(ValueError,'confirmation'):service.send('0'*64)
        self.assertEqual(self.node.requests,[])
    def test_send_without_staging_never_creates_dispatch(self):
        with self.assertRaisesRegex(ValueError,'not staged'):self.service().send('0'*64)
        self.assertFalse(self.dispatch_path.exists())
    def test_expired_or_stale_evidence_refuses_sending(self):
        with server(self.node) as url:
            service=self.service(url);plan=service.review();self.c.clock+=301*10**9
            with self.assertRaisesRegex(ValueError,'not current'):service.send(plan['confirmation'])
        self.assertEqual(self.node.requests,[]);self.assertEqual(self.held(),60)
    def test_policy_expiry_permits_historical_status_not_network(self):
        with server(self.node) as url:
            service=self.service(url);service.review();self.c.clock=self.c.wallet.trust_expires
            self.assertEqual(service.status()['wallet_obligation_status'],'pending')
            with self.assertRaisesRegex(ValueError,'trust expired'):service.refresh()
        self.assertEqual(self.node.requests,[])
    def test_revoked_grant_rechecked_without_releasing_reservation(self):
        self.c.advance([self.c.owner_operation({'type':'revoke','id':'raven'})]);self.c.sync()
        with self.assertRaisesRegex(ValueError,'inactive'):self.service().review()
        self.assertEqual(self.held(),60)
    def test_already_recorded_decision_refuses_new_send(self):
        self.c.advance([canonical(self.signed['result'])]);self.c.sync()
        with self.assertRaisesRegex(ValueError,'already recorded'):self.service().review()
        self.assertFalse(self.dispatch_path.exists())
    def test_corrupt_rehashed_wallet_signature_refused(self):
        row=self.c.wallet.db.execute('SELECT result FROM decisions').fetchone()
        result=json.loads(row[0]);result['signature']='0'*128;wire=canonical(result)
        self.c.wallet.db.execute('UPDATE decisions SET result=?,result_hash=?',(wire.decode(),hashlib.sha256(wire).hexdigest()))
        with self.assertRaises(ValueError):self.service().review()
        self.assertFalse(self.dispatch_path.exists())
    def test_admission_never_releases_hold(self):
        before=self.logical_wallet()
        with server(self.node) as url:out=self.run_send(self.service(url))
        self.assertEqual(out['delivery_status'],'endpoint_admitted');self.assertFalse(out['wallet_reconciled'])
        self.assertEqual(self.held(),60);self.assertEqual(before,self.logical_wallet())
        self.assertEqual(len(self.broadcasts()),1)
    def test_real_socket_loss_after_execution_read_only_recovery(self):
        self.node.drop_reply=True
        with server(self.node) as url:
            service=self.service(url);out=self.run_send(service)
            self.assertEqual(out['delivery_status'],'unresolved');self.assertEqual(self.held(),60)
            self.c.wallet.close();self.c.wallet=self.c.open()
            service=self.service(url);receipt=service.refresh()
            self.assertTrue(receipt['receipt_verified']);self.assertFalse(receipt['wallet_sync_performed'])
            self.assertEqual(self.held(),60)
            out=service.reconcile();self.assertTrue(out['wallet_reconciled']);self.assertEqual(self.held(),0)
            proof=json.loads(service.export_receipt())
            self.assertEqual(verify_packet(proof,self.c.trust,expected_txids=[out['native_txid']])['status'],'verified')
            self.assertEqual(self.c.wallet.export(self.signed['decision_id'])['result'],self.signed['result'])
        self.assertEqual(len(self.broadcasts()),1)
    def test_declined_response_is_not_nonpayment_or_refund(self):
        self.node.decline=True
        with server(self.node) as url:
            service=self.service(url);out=self.run_send(service)
            self.assertEqual(out['delivery_status'],'endpoint_declined')
            self.assertFalse(service.refresh()['receipt_verified'])
        self.assertEqual(self.held(),60)
    def test_first_send_cannot_be_repeated_implicitly(self):
        self.node.do_execute=False
        with server(self.node) as url:
            service=self.service(url);plan=service.review();service.send(plan['confirmation'])
            with self.assertRaisesRegex(ValueError,'distinct'):service.send(plan['confirmation'])
            with self.assertRaisesRegex(ValueError,'distinct'):service.review()
        self.assertEqual(len(self.broadcasts()),1)
    def test_explicit_replay_needs_new_action_and_attempt_confirmation(self):
        self.node.do_execute=False
        with server(self.node) as url:
            service=self.service(url);plan=service.review();service.send(plan['confirmation'])
            replay=service.review(replay=True)
            self.assertNotEqual(replay['confirmation'],plan['confirmation'])
            self.assertEqual(replay['next_attempt'],2)
            with self.assertRaisesRegex(ValueError,'context changed'):service.send(plan['confirmation'],replay=True)
            out=service.send(replay['confirmation'],replay=True)
            self.assertEqual(out['attempts'],2)
        self.assertEqual([r['params']['tx'] for r in self.broadcasts()][0],self.broadcasts()[1]['params']['tx'])
        self.assertEqual(self.held(),60)
    def test_replay_cannot_be_first_attempt(self):
        service=self.service();service.review()
        with self.assertRaisesRegex(ValueError,'distinct'):service.review(replay=True)
    def test_verified_receipt_refuses_even_explicit_replay(self):
        with server(self.node) as url:
            service=self.service(url);self.run_send(service);service.refresh()
            with self.assertRaisesRegex(ValueError,'receipt already verified'):service.review(replay=True)
        self.assertEqual(len(self.broadcasts()),1)
    def test_refresh_never_signs_or_broadcasts(self):
        with server(self.node) as url:
            service=self.service(url);self.run_send(service)
            with patch('payment_transport._worker',side_effect=AssertionError('no send')), \
                 patch('certified_wallet._load_vault',side_effect=AssertionError('no key')):
                self.assertTrue(service.refresh()['receipt_verified'])
            self.assertEqual(self.held(),60)
        self.assertEqual(len(self.broadcasts()),1)
    def test_fixed_commit_read_retry_is_bounded_and_does_not_resend(self):
        self.node.delay_target_reads=2
        with server(self.node) as url:
            service=self.service(url);self.run_send(service)
            out=service.refresh(read_attempts=3);self.assertTrue(out['receipt_verified'])
            self.assertEqual(out['read_requests'],6)
        self.assertEqual(len(self.broadcasts()),1)
    def test_forged_receipt_does_not_reconcile(self):
        self.node.forge=True
        with server(self.node) as url:
            service=self.service(url);self.run_send(service)
            out=service.refresh();self.assertFalse(out['receipt_verified'])
            with self.assertRaisesRegex(ValueError,'no verified receipt'):service.reconcile()
        self.assertEqual(self.held(),60)
    def test_valid_receipt_is_distinct_from_wallet_sync(self):
        with server(self.node) as url:
            service=self.service(url);self.run_send(service);service.refresh()
            before=self.logical_wallet();status=service.status()
            self.assertTrue(status['receipt_verified']);self.assertFalse(status['wallet_reconciled'])
            self.assertEqual(before,self.logical_wallet());self.assertEqual(self.held(),60)
    def test_reconciliation_uses_existing_sync_without_network_or_unlock(self):
        with server(self.node) as url:
            service=self.service(url);self.run_send(service);service.refresh();count=len(self.node.requests)
            with patch('payment_transport._worker',side_effect=AssertionError('no send')), \
                 patch('receipt_collector.fetch_packet',side_effect=AssertionError('no reads')), \
                 patch('certified_wallet._load_vault',side_effect=AssertionError('no key')):
                out=service.reconcile()
            self.assertEqual(out['reconciliation'],'recorded');self.assertEqual(len(self.node.requests),count)
            again=service.reconcile();self.assertEqual(again['reconciliation'],'already_recorded')
        self.assertEqual(self.held(),0)
    def test_missing_ancestry_keeps_receipt_and_hold(self):
        with server(self.node) as url:
            service=self.service(url);self.run_send(service)
            original=list(self.node.packets.values())[-1]
            self.c.advance([])
            original['state']=self.c.witness['state'];original['state_commit']=self.c.witness['state_commit']
            self.assertTrue(service.refresh()['receipt_verified'])
            out=service.reconcile();self.assertEqual(out['reconciliation'],'wallet_sync_required')
            self.assertTrue(out['receipt_verified']);self.assertEqual(self.held(),60)
            links=[w['state_commit'] for w in self.c.witnesses if 2<int(w['state_commit']['header']['height'])<5]
            self.assertEqual(service.reconcile(continuation=links)['reconciliation'],'recorded')
        self.assertEqual(self.held(),0)
    def test_bad_continuation_cannot_release_wallet_hold(self):
        with server(self.node) as url:
            service=self.service(url);self.run_send(service);service.refresh()
            out=service.reconcile(continuation=[])
            self.assertEqual(out['reconciliation'],'wallet_sync_required');self.assertEqual(self.held(),60)
    def test_two_agents_finish_without_changing_reserved_total_twice(self):
        atlas=self.c.approve(3,38)
        with server(self.node) as url:
            raven_service=self.service(url);atlas_service=self.service(url,decision_id=atlas['decision_id'],grant_id='atlas')
            raven_service.review();atlas_service.review();self.assertEqual(self.held(),100)
            self.run_send(raven_service);raven_service.refresh();raven_service.reconcile()
            self.assertEqual(self.held(),40)
            self.run_send(atlas_service);atlas_service.refresh();atlas_service.reconcile()
            self.assertEqual(self.held(),0)
            spent=json.loads(self.c.app.query('/state')['value'])['native']['budgets'][0][4]
            self.assertEqual(spent,100)
        self.assertEqual(len(self.broadcasts()),2)
    def test_stored_proof_export_works_after_expiry_but_cannot_trigger_sync(self):
        with server(self.node) as url:
            service=self.service(url);self.run_send(service);service.refresh()
            self.c.clock=self.c.wallet.trust_expires
            self.assertTrue(json.loads(service.export_receipt())['transactions'])
            with self.assertRaisesRegex(ValueError,'trust expired'):service.reconcile()
        self.assertEqual(self.held(),60)
    def test_injected_dispatch_database_failure_before_io_keeps_signature(self):
        with server(self.node) as url:
            service=self.service(url);plan=service.review()
            db=sqlite3.connect(self.dispatch_path)
            db.execute("CREATE TRIGGER disallow BEFORE UPDATE ON payments BEGIN SELECT RAISE(ABORT,'test'); END");db.close()
            # Unsupported stored schema is rejected before constructor/network.
            with self.assertRaisesRegex(ValueError,'supported dispatch journal'):service.send(plan['confirmation'])
        self.assertEqual(self.node.requests,[]);self.assertEqual(self.held(),60)
    def test_process_exit_after_attempt_commit_requires_explicit_replay(self):
        self.node.do_execute=False
        with server(self.node) as url:
            service=self.service(url);plan=service.review()
            for name,obj in [('genesis',self.c.engine),('policy',self.c.policy)]:
                (self.c.root/(name+'.json')).write_bytes(encode(obj))
            code='''import os,sys,json
from pathlib import Path
from decision_delivery import DecisionDelivery
import payment_transport
payment_transport._worker=lambda *a:os._exit(29)
p=Path(sys.argv[1])
d=DecisionDelivery(p/'wallet.sqlite',(p/'genesis.json').read_bytes(),json.loads((p/'policy.json').read_text()),dispatch_journal=p/'dispatch.sqlite',endpoint=sys.argv[2],account=sys.argv[3],grant_id='raven',decision_id=sys.argv[4],clock=lambda:int(sys.argv[6]))
d.send(sys.argv[5])
'''
            run=subprocess.run([sys.executable,'-c',code,str(self.c.root),url,fixtures.IDS[0],self.signed['decision_id'],plan['confirmation'],str(self.c.clock)],capture_output=True,timeout=10)
            self.assertEqual(run.returncode,29,run.stderr);self.assertEqual(self.node.requests,[])
            self.assertEqual(service.status()['delivery_status'],'dispatching')
            with self.assertRaisesRegex(ValueError,'distinct'):service.send(plan['confirmation'])
            replay=service.review(replay=True);service.send(replay['confirmation'],replay=True)
        self.assertEqual(len(self.broadcasts()),1);self.assertEqual(self.held(),60)

    def test_two_concurrent_senders_make_one_attempt(self):
        from concurrent.futures import ThreadPoolExecutor
        import threading
        self.node.do_execute=False
        with server(self.node) as url:
            service=self.service(url);plan=service.review();gate=threading.Barrier(2)
            def run(_):
                gate.wait(timeout=5)
                try: self.service(url).send(plan['confirmation']);return 'sent'
                except (OSError,ValueError,sqlite3.Error):return 'refused'
            with ThreadPoolExecutor(max_workers=2) as pool:result=list(pool.map(run,range(2)))
        self.assertEqual(sorted(result),['refused','sent']);self.assertEqual(len(self.broadcasts()),1)
        self.assertEqual(self.held(),60)
    def test_expiry_between_source_check_and_io_refuses_attempt(self):
        with server(self.node) as url:
            service=self.service(url);plan=service.review();original=service._review
            def delayed(*a,**kw):
                result=original(*a,**kw);self.c.clock+=301*10**9;return result
            with patch.object(service,'_review',side_effect=delayed):
                with self.assertRaisesRegex(ValueError,'aged out'):service.send(plan['confirmation'])
        self.assertEqual(self.node.requests,[]);self.assertEqual(self.held(),60)
    def test_fresh_checkpoint_changes_delivery_confirmation(self):
        with server(self.node) as url:
            service=self.service(url);plan=service.review();self.c.advance([]);self.c.sync()
            with self.assertRaisesRegex(ValueError,'context changed'):service.send(plan['confirmation'])
        self.assertEqual(self.node.requests,[])

    def test_newer_optional_header_frontier_is_not_bypassed_by_older_sync(self):
        with server(self.node) as url:
            service=self.service(url);self.run_send(service);service.refresh()
            # Only a synthetic test journal receives this known optional schema;
            # the adapter never creates or migrates it in operation.
            cp=self.c.wallet.db.execute('SELECT policy_id,height,block_hash,clock_ns FROM checkpoint').fetchone()
            signed=self.node.continuations[-1];raw=encode(signed)
            self.c.wallet.db.execute('CREATE TABLE wallet_header_progress(id INTEGER PRIMARY KEY,policy_id TEXT,origin_height INTEGER,origin_hash TEXT,signed_header TEXT,header_digest TEXT,clock_ns INTEGER)')
            self.c.wallet.db.execute('INSERT INTO wallet_header_progress VALUES(1,?,?,?,?,?,?)',
                (cp[0],cp[1],cp[2],raw.decode(),hashlib.sha256(raw).hexdigest(),cp[3]))
            before=self.logical_wallet()
            result=service.reconcile()
            self.assertEqual(result['reconciliation'],'wallet_sync_required')
            self.assertEqual(before,self.logical_wallet());self.assertEqual(self.held(),60)
            with self.assertRaisesRegex(ValueError,'not current'):service.review(replay=True)

    def test_missing_dispatch_configuration_is_not_silently_recreated(self):
        self.service().review()
        db=sqlite3.connect(self.dispatch_path);db.execute('DELETE FROM configuration');db.commit();db.close()
        with self.assertRaisesRegex(ValueError,'configuration missing'):self.service().status()
        db=sqlite3.connect(self.dispatch_path);self.assertEqual(db.execute('SELECT count(*) FROM configuration').fetchone()[0],0);db.close()
    def test_other_dispatch_database_requires_its_own_confirmation(self):
        with server(self.node) as url:
            first=self.service(url);plan=first.review()
            second=self.service(url,dispatch_journal=self.c.root/'second.sqlite');other=second.review()
            self.assertNotEqual(plan['confirmation'],other['confirmation'])
            with self.assertRaisesRegex(ValueError,'context changed'):second.send(plan['confirmation'])
        self.assertEqual(self.node.requests,[])


if __name__ == '__main__': unittest.main()
