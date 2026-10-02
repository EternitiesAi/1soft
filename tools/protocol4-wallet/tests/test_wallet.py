import copy
import json
import os
from pathlib import Path
import sqlite3
import subprocess
import sys
import tempfile
from concurrent.futures import ThreadPoolExecutor
import unittest
from unittest.mock import patch

from block_application import encode
from native_core import canonical
from p4_evidence import content_id
from p4_wallet import P4Wallet
from wallet_fixture import Chain,PASSWORD

class WalletTests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory();self.root=Path(self.tmp.name)
        self.c=Chain(self.root);self.path=self.root/'wallet.sqlite'
        self.w=self.open(create=True)
        self.initial=self.c.evidence();self.w.sync(self.initial,expected_revision=None)
    def tearDown(self):self.w.close();self.c.close();self.tmp.cleanup()
    def open(self,**kw):return P4Wallet(self.path,self.c.genesis,self.c.policy,clock=self.c.clock,**kw)
    def prepare(self,units=58,role='raven',**kw):
        return self.w.prepare(**{'payer':self.c.payer,'recipient':self.c.merchant,'units':units,
            'grant_id':role,'valid_until':30,**kw})
    def approve(self,review=None,role='raven'):
        q=review or self.prepare(role=role)
        return self.w.approve(q['review'],q['confirmation'],vault=self.root/(role+'.pem'),password=PASSWORD)
    def held(self):return self.w.status()['pending_debit_units']
    def sync(self):return self.w.sync(self.c.evidence(),expected_revision=self.w.status()['revision'])
    def dump(self):return list(self.w.db.iterdump())

    def test_prepare_is_no_reservation_or_signature(self):
        before=self.dump();q=self.prepare()
        self.assertFalse(q['reserved']);self.assertFalse(q['signed']);self.assertEqual(self.held(),'0')
        self.assertEqual(self.dump(),before)
    def test_approve_records_fee_in_hold(self):
        signed=self.approve();self.assertEqual(self.held(),'60');self.assertFalse(signed['broadcast'])
        self.assertEqual(signed['transaction']['body']['version'],4)
    def test_agent_overcommit_refused_before_key_unlock(self):
        self.approve()
        with patch('p4_wallet._load_vault',side_effect=AssertionError('must not unlock')):
            with self.assertRaisesRegex(ValueError,'budget funds already committed'):self.prepare(39,'atlas')
        self.assertEqual(self.held(),'60')
    def test_boundary_second_agent_fits(self):
        self.approve();self.approve(self.prepare(38,'atlas'),'atlas');self.assertEqual(self.held(),'100')
    def test_two_reviews_do_not_reserve_and_later_review_goes_stale(self):
        a=self.prepare();b=self.prepare(38,'atlas');self.approve(a)
        with patch('p4_wallet._load_vault',side_effect=AssertionError('must not unlock')):
            with self.assertRaisesRegex(ValueError,'reviewed wallet state'):self.approve(b,'atlas')
        self.assertEqual(self.held(),'60')
    def test_stale_review_after_new_checkpoint_refused_before_key(self):
        q=self.prepare();self.c.block();self.sync()
        with patch('p4_wallet._load_vault',side_effect=AssertionError('must not unlock')):
            with self.assertRaisesRegex(ValueError,'reviewed wallet state'):self.approve(q)
    def test_one_unresolved_per_agent_lane(self):
        self.approve()
        with self.assertRaisesRegex(ValueError,'unresolved'):self.prepare(1)
    def test_owner_transfer_respects_agent_pending_account_debits(self):
        self.approve()
        with self.assertRaisesRegex(ValueError,'account funds already committed'):self.prepare(935,'')
    def test_owner_uses_current_key_not_grant_key(self):
        q=self.prepare(10,'');self.assertEqual(q['review']['body']['nonce'],3)
        r=self.w.approve(q['review'],q['confirmation'],vault=self.root/'owner.pem',password=PASSWORD)
        self.assertEqual(r['transaction']['body']['grant_id'],'');self.assertEqual(self.held(),'12')
    def test_unknown_grant_never_falls_back_to_owner(self):
        with self.assertRaisesRegex(ValueError,'unknown agent grant'):self.prepare(1,'missing')
    def test_bad_amount_types_and_overflow_refused(self):
        for units in (True,False,0,-1,1.0,'1',2**53):
            with self.subTest(units=units),self.assertRaises(ValueError):self.prepare(units)
    def test_self_and_system_or_unknown_recipient_refused(self):
        from native_core import FEE_ACCOUNT
        for recipient in (self.c.payer,FEE_ACCOUNT,'unknown'):
            with self.subTest(recipient=recipient),self.assertRaises(ValueError):self.prepare(recipient=recipient)
    def test_unsupported_horizon_refused(self):
        for h in (1,True,34,513):
            with self.subTest(h=h),self.assertRaises(ValueError):self.prepare(valid_until=h)
    def test_wrong_confirmation_refused_before_key(self):
        q=self.prepare()
        with patch('p4_wallet._load_vault',side_effect=AssertionError('must not unlock')):
            with self.assertRaises(ValueError):self.w.approve(q['review'],'0'*64,vault=self.root/'raven.pem',password=PASSWORD)
    def test_changed_recipient_cannot_reuse_confirmation(self):
        q=self.prepare();q['review']['body']['op']['to']=self.c.payer
        with self.assertRaises(ValueError):self.approve(q)
    def test_rehashed_nontransfer_is_not_supported(self):
        q=self.prepare();q['review']['body']['op']={'type':'fence'};q['confirmation']=content_id(q['review'])
        with self.assertRaises(ValueError):self.approve(q)
    def test_extra_authority_field_refused(self):
        q=self.prepare();q['review']['approved']=True;q['confirmation']=content_id(q['review'])
        with self.assertRaises(ValueError):self.approve(q)
    def test_wrong_vault_cannot_sign_selected_grant(self):
        q=self.prepare();before=self.dump()
        with self.assertRaisesRegex(ValueError,'vault does not control'):
            self.w.approve(q['review'],q['confirmation'],vault=self.root/'atlas.pem',password=PASSWORD)
        self.assertEqual(self.dump(),before)
    def test_wrong_password_leaves_no_decision(self):
        q=self.prepare();before=self.dump()
        with self.assertRaises(ValueError):self.w.approve(q['review'],q['confirmation'],vault=self.root/'raven.pem',password=b'wrong password long enough')
        self.assertEqual(self.dump(),before)
    def test_expiry_before_unlock_rejected(self):
        q=self.prepare();self.c.now+=3600*10**9
        with patch('p4_wallet._load_vault',side_effect=AssertionError('must not unlock')):
            with self.assertRaises(ValueError):self.approve(q)
    def test_expiry_during_unlock_rejected_no_decision(self):
        q=self.prepare();before=self.dump()
        def unlock(*args):self.c.now+=3600*10**9;return self.c.raven
        with patch('p4_wallet._load_vault',side_effect=unlock):
            with self.assertRaises(ValueError):self.approve(q)
        self.assertEqual(self.dump(),before)
    def test_stale_authenticated_state_is_not_signable(self):
        self.c.now+=301*10**9
        with self.assertRaisesRegex(ValueError,'recent authenticated'):self.prepare()
        self.assertFalse(self.w.status()['spending_authorized'])
    def test_staleness_during_unlock_rejected(self):
        q=self.prepare();before=self.dump()
        def unlock(*args):self.c.now+=301*10**9;return self.c.raven
        with patch('p4_wallet._load_vault',side_effect=unlock):
            with self.assertRaises(ValueError):self.approve(q)
        self.assertEqual(self.dump(),before)
    def test_clock_rollback_refused(self):
        self.approve();self.c.now-=1
        with self.assertRaises(ValueError):self.w.status()
    def test_native_execution_receipt_reconciles_hold(self):
        s=self.approve();self.c.block([canonical(s['transaction'])]);self.assertEqual(self.held(),'60')
        self.sync();self.assertEqual(self.held(),'0')
        self.assertEqual(self.w.status()['budgets'][0]['spent'],'60')
    def test_verified_read_alone_does_not_reconcile_wallet(self):
        from p4_evidence import verify_evidence
        s=self.approve();self.c.block([canonical(s['transaction'])]);e=self.c.evidence()
        verify_evidence(e,self.c.genesis,self.c.policy,now_ns=self.c.now)
        self.assertEqual(self.held(),'60')
    def test_signed_hold_survives_roster_turnover(self):
        s=self.approve();self.c.block([self.c.admin()])
        while self.c.app.height<8:self.c.block()
        self.sync();self.assertEqual(self.held(),'60');self.assertEqual(self.w.status()['registry_epoch'],1)
        self.c.block([canonical(s['transaction'])]);self.sync();self.assertEqual(self.held(),'0')
    def test_expired_transaction_without_receipt_stays_reserved(self):
        self.approve(self.prepare(valid_until=3))
        for _ in range(6):self.c.block()
        self.sync();self.assertEqual(self.held(),'60')
        with self.assertRaisesRegex(ValueError,'unresolved'):self.prepare()
    def test_revoked_grant_does_not_release_signed_hold(self):
        self.approve();self.c.block([self.c.owner_wire({'type':'revoke','id':'raven'})]);self.sync()
        self.assertEqual(self.held(),'60')
    def test_revoked_grant_cannot_sign_new_transfer(self):
        self.c.block([self.c.owner_wire({'type':'revoke','id':'raven'})]);self.sync()
        with self.assertRaisesRegex(ValueError,'inactive'):self.prepare()
    def test_revoked_budget_cannot_sign_new_transfer(self):
        self.c.block([self.c.owner_wire({'type':'budget_revoke','id':'studio'})]);self.sync()
        with self.assertRaises(ValueError):self.prepare()
    def test_replay_does_not_release_twice(self):
        s=self.approve();raw=canonical(s['transaction']);self.c.block([raw]);self.sync()
        r=self.c.block([raw]);self.assertEqual(r['tx_results'][0]['code'],1)
        self.sync();self.assertEqual(self.held(),'0');self.assertEqual(self.w.status()['budgets'][0]['spent'],'60')
    def test_reopen_preserves_hold_and_exact_bytes(self):
        s=self.approve();self.w.close();self.w=self.open()
        self.assertEqual(self.held(),'60')
        self.assertEqual(self.w.recover(s['decision_id'],payer=self.c.payer,grant_id='raven'),canonical(s['transaction']))
    def test_recover_after_policy_expiry_uses_no_key(self):
        s=self.approve();self.c.now+=7200*10**9
        with patch('p4_wallet._load_vault',side_effect=AssertionError('no keys')):
            self.assertEqual(self.w.recover(s['decision_id'],payer=self.c.payer,grant_id='raven'),canonical(s['transaction']))
        with self.assertRaises(ValueError):self.prepare()
    def test_recover_wrong_payer_or_role_refused(self):
        s=self.approve()
        for payer,role in [(self.c.merchant,'raven'),(self.c.payer,''),(self.c.payer,'atlas')]:
            with self.subTest(role=role),self.assertRaises(ValueError):self.w.recover(s['decision_id'],payer=payer,grant_id=role)
    def test_unknown_decision_not_signed_again(self):
        before=self.dump()
        with self.assertRaises(ValueError):self.w.recover('0'*64,payer=self.c.payer,grant_id='raven')
        self.assertEqual(self.dump(),before)
    def test_two_writers_one_review_only_one_signature_record(self):
        q=self.prepare()
        def go(_):
            try:
                with self.open() as w:return w.approve(q['review'],q['confirmation'],vault=self.root/'raven.pem',password=PASSWORD)['status']
            except ValueError:return 'stale'
        with ThreadPoolExecutor(max_workers=2) as pool:results=list(pool.map(go,range(2)))
        self.assertEqual(sorted(results),['signed_and_reserved','stale']);self.assertEqual(self.held(),'60')
    def test_prepare_from_other_journal_cannot_be_approved_here(self):
        otherpath=self.root/'other.sqlite'
        with P4Wallet(otherpath,self.c.genesis,self.c.policy,create=True,clock=self.c.clock) as other:
            other.sync(self.initial,expected_revision=None)
            q=other.prepare(payer=self.c.payer,recipient=self.c.merchant,units=58,valid_until=30,grant_id='raven')
        with self.assertRaises(ValueError):self.approve(q)
    def test_caller_mutation_during_key_load_cannot_change_signed_bytes(self):
        q=self.prepare();original=copy.deepcopy(q)
        def key(*args):q['review']['body']['op']['units']=1;return self.c.raven
        with patch('p4_wallet._load_vault',side_effect=key):s=self.approve(q)
        self.assertEqual(s['transaction']['body'],original['review']['body'])
    def test_database_write_failure_returns_no_signature_or_hold(self):
        q=self.prepare();before=self.dump()
        def deny(code,*_):return sqlite3.SQLITE_DENY if code==sqlite3.SQLITE_INSERT else sqlite3.SQLITE_OK
        self.w.db.set_authorizer(deny)
        with self.assertRaises(sqlite3.DatabaseError):self.approve(q)
        self.w.db.set_authorizer(None);self.assertEqual(self.dump(),before)
    def test_stale_sync_revision_cannot_override_a_new_signature(self):
        revision=self.w.status()['revision'];self.approve();e=self.c.evidence();before=self.dump()
        with self.assertRaisesRegex(ValueError,'revision changed'):self.w.sync(e,expected_revision=revision)
        self.assertEqual(self.dump(),before)
    def test_bad_evidence_import_does_not_release_hold(self):
        self.approve();e=self.c.evidence();e['state']['native']['accounts'][0][4]+=1;before=self.dump()
        with self.assertRaises(ValueError):self.w.sync(e,expected_revision=self.w.status()['revision'])
        self.assertEqual(self.dump(),before)
    def test_rollback_checkpoint_refused(self):
        self.sync();before=self.dump()
        with self.assertRaises(ValueError):self.w.sync(self.initial,expected_revision=self.w.status()['revision'])
        self.assertEqual(self.dump(),before)
    def test_same_checkpoint_is_noop_not_duplicate_observation(self):
        before=self.dump();r=self.w.sync(self.initial,expected_revision=self.w.status()['revision'])
        self.assertEqual(r['status'],'already_recorded');self.assertEqual(self.dump(),before)
    def test_same_checkpoint_import_rechecks_expiry(self):
        revision=self.w.status()['revision'];self.c.now+=3600*10**9
        with self.assertRaises(ValueError):self.w.sync(self.initial,expected_revision=revision)
    def test_tampered_stored_signature_is_refused(self):
        self.approve();row=self.w.db.execute('SELECT payload FROM decisions').fetchone();d=json.loads(row[0])
        wire=json.loads(bytes.fromhex(d['wire_hex']));wire['signature']='0'*128;d['wire_hex']=canonical(wire).hex()
        self.w.db.execute('UPDATE decisions SET payload=?',(encode(d),))
        with self.assertRaises(ValueError):self.w.status()
    def test_rehashed_stored_review_cannot_erase_hold(self):
        self.approve();d=json.loads(self.w.db.execute('SELECT payload FROM decisions').fetchone()[0])
        d['review']['debit_units']='0';d['id']=content_id(d['review'])
        self.w.db.execute('UPDATE decisions SET decision_id=?,payload=?',(d['id'],encode(d)))
        with self.assertRaises(ValueError):self.w.status()
    def test_missing_observation_breaks_recovery_instead_of_new_signing(self):
        self.approve();self.w.db.execute('DELETE FROM observations')
        with self.assertRaises(ValueError):self.w.status()
    def test_missing_config_not_repaired(self):
        self.w.db.execute('DELETE FROM config');self.w.close()
        with self.assertRaises(ValueError):self.open()
    def test_existing_wallet_cannot_be_reinitialized(self):
        self.approve();before=self.dump()
        with self.assertRaises(FileExistsError):self.open(create=True)
        self.assertEqual(self.dump(),before)
    def test_read_store_is_not_a_signing_wallet(self):
        from p4_read_store import P4ReadStore
        path=self.root/'read.sqlite'
        with P4ReadStore(path,self.c.genesis,self.c.policy,create=True,clock=self.c.clock):pass
        before=path.read_bytes()
        with self.assertRaises(ValueError):P4Wallet(path,self.c.genesis,self.c.policy,clock=self.c.clock)
        self.assertEqual(path.read_bytes(),before)
    def test_node_store_is_not_a_signing_wallet(self):
        path=self.root/'node.sqlite';db=sqlite3.connect(path);db.execute('CREATE TABLE committed(x)');db.close();path.chmod(0o600)
        before=path.read_bytes()
        with self.assertRaises(ValueError):P4Wallet(path,self.c.genesis,self.c.policy,clock=self.c.clock)
        self.assertEqual(path.read_bytes(),before)
    def test_wrong_policy_cannot_reopen_wallet(self):
        p=copy.deepcopy(self.c.policy);p['trust_period_seconds']+=1
        with self.assertRaises(ValueError):P4Wallet(self.path,self.c.genesis,p,clock=self.c.clock)
    def test_symlink_sidecar_refused(self):
        self.w.close();p=Path(str(self.path)+'-wal');p.unlink(missing_ok=True);p.symlink_to(self.root/'raven.pem')
        with self.assertRaises(ValueError):self.open()
    def test_group_readable_wallet_refused(self):
        self.w.close();self.path.chmod(0o640)
        with self.assertRaises(ValueError):self.open()
    def test_no_network_for_any_wallet_operation(self):
        with patch('socket.socket',side_effect=AssertionError('no network')):
            s=self.approve();self.w.status();self.w.recover(s['decision_id'],payer=self.c.payer,grant_id='raven')
    def test_legacy_signer_still_refuses_p4(self):
        from offline_signer import review_intent
        q=self.prepare()
        with self.assertRaisesRegex(ValueError,'legacy offline signer refuses'):
            review_intent(self.c.g,q['review']['body'],q['review']['signer_public_key'])
    def test_new_signature_after_complete_roster_replacement(self):
        self.c.block([self.c.admin()])
        while self.c.app.state['registry']['epoch']==0:self.c.block()
        self.sync();q=self.prepare(10)
        self.assertEqual(q['review']['registry_epoch'],1)
        signed=self.approve(q);self.assertEqual(self.held(),'12')
        result=self.c.block([canonical(signed['transaction'])])
        self.assertEqual(result['tx_results'][0]['code'],0)
        self.sync();self.assertEqual(self.held(),'0')
    def test_external_spend_deficit_is_visible_and_cannot_free_own_hold(self):
        self.approve()
        wire=self.c.owner_wire({'type':'transfer','to':self.c.merchant,'units':950})
        self.c.block([wire]);self.sync()
        owner=next(a for a in self.w.status()['accounts'] if a['id']==self.c.payer)
        self.assertEqual(owner['recorded_balance'],'42')
        self.assertEqual(owner['pending_debit_units'],'60')
        self.assertEqual(owner['uncommitted_units'],'0')
        self.assertEqual(owner['reservation_deficit_units'],'18')
        with self.assertRaisesRegex(ValueError,'account funds already committed'):self.prepare(1,'atlas')
    def test_observation_capacity_refuses_without_eviction_or_hold_release(self):
        self.approve();before=self.dump();e=self.c.evidence()
        with patch('p4_wallet.MAX_OBSERVATIONS',1):
            with self.assertRaisesRegex(ValueError,'capacity reached'):
                self.w.sync(e,expected_revision=self.w.status()['revision'])
        self.assertEqual(self.dump(),before);self.assertEqual(self.held(),'60')
    def test_decision_capacity_refuses_before_key_unlock(self):
        self.approve();q=self.prepare(38,'atlas');before=self.dump()
        with patch('p4_wallet.MAX_DECISIONS',1),patch('p4_wallet._load_vault',side_effect=AssertionError('no unlock')):
            with self.assertRaisesRegex(ValueError,'capacity reached'):self.approve(q,'atlas')
        self.assertEqual(self.dump(),before)
    def test_receipt_id_without_exact_wire_cannot_reconcile(self):
        signed=self.approve();self.c.block([canonical(signed['transaction'])]);self.sync()
        # Exercise the defensive receipt matcher independently of cryptographic replay.
        # Full imported evidence containing this mismatch is refused even earlier.
        from p4_wallet import matched_receipt
        decision=json.loads(self.w.db.execute('SELECT payload FROM decisions').fetchone()[0])
        _,_,report,_,_=self.w._load();changed=copy.deepcopy(report)
        txid=__import__('hashlib').sha256(__import__('native_core').DOMAIN+canonical(signed['transaction']['body'])).hexdigest()
        target=next(r for r in changed['receipts'] if r['native_txid']==txid)
        target['record']['envelope']['signature']='0'*128
        with self.assertRaisesRegex(ValueError,'conflicts'):matched_receipt(changed,decision)

    def test_external_budget_spend_preserves_our_hold_and_reports_deficit(self):
        self.approve()
        from block_application import restore
        from native_core import sign
        ledger=restore(self.c.g,self.c.app.state['native'])
        try:
            body=ledger.body(self.c.payer,0,{'type':'transfer','to':self.c.merchant,'units':88},
                             grant_id='atlas',valid_until=30)
            outside=canonical(sign(self.c.atlas,body))
        finally:ledger.close()
        self.c.block([outside]);self.sync();budget=self.w.status()['budgets'][0]
        self.assertEqual(budget['spent'],'90');self.assertEqual(budget['pending_debit_units'],'60')
        self.assertEqual(budget['uncommitted_units'],'0');self.assertEqual(budget['reservation_deficit_units'],'50')
        with self.assertRaises(ValueError):self.prepare(10,'atlas')

    def crash(self,after):
        q=self.prepare()
        (self.root/'genesis.json').write_bytes(self.c.genesis)
        (self.root/'policy.json').write_bytes(encode(self.c.policy));(self.root/'review.json').write_bytes(encode(q))
        code='''import json,os,sys
from pathlib import Path
from p4_wallet import P4Wallet
from wallet_fixture import PASSWORD
r=Path(sys.argv[1]);q=json.loads((r/'review.json').read_bytes())
w=P4Wallet(r/'wallet.sqlite',(r/'genesis.json').read_bytes(),json.loads((r/'policy.json').read_bytes()),clock=lambda:int(sys.argv[3]))
if sys.argv[2]=='before':
 def kill(sql):
  if sql=='COMMIT':os._exit(81)
 w.db.set_trace_callback(kill)
w.approve(q['review'],q['confirmation'],vault=r/'raven.pem',password=PASSWORD)
os._exit(82)
'''
        p=subprocess.run([sys.executable,'-c',code,str(self.root),'after' if after else 'before',str(self.c.now)],capture_output=True,timeout=15)
        self.assertEqual(p.returncode,82 if after else 81,p.stderr)
        return q
    def test_actual_process_exit_before_commit_leaves_no_hold(self):
        self.crash(False);self.assertEqual(self.held(),'0')
    def test_actual_process_exit_after_commit_recovers_exact_signed_payment(self):
        q=self.crash(True);self.assertEqual(self.held(),'60')
        wire=self.w.recover(q['confirmation'],payer=self.c.payer,grant_id='raven')
        self.assertEqual(json.loads(wire)['body'],q['review']['body'])
        self.c.block([wire]);self.sync();self.assertEqual(self.held(),'0')

if __name__=='__main__':unittest.main()
