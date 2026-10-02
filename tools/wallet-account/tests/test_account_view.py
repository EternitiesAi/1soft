"""New disposable wallet fixtures only. Synthetic validators, no live funds."""
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

import test_wallet_obligations as fixture
from native_core import canonical, sign, public, address, accept_account_key
from account_view import read_account, open_readonly
from account_report import render_html
from commit_verifier import encode

ROOT=Path(__file__).resolve().parents[1]


class AccountTests(unittest.TestCase):
    def setUp(self):
        self.c=fixture.ObligationTests();self.c.setUp();self.c.wallet.sync(self.c.witness)
    def tearDown(self):self.c.tearDown()
    def read(self,account=None,**kw):
        return read_account(self.c.path,self.c.raw,self.c.policy,account or fixture.IDS[0],
                            observed_at_ns=kw.pop('observed_at_ns',self.c.clock),**kw)
    def logical(self):return '\n'.join(self.c.wallet.db.iterdump())
    def test_initial_account_reconciles_genesis_and_admin_fees(self):
        r=self.read();self.assertEqual(r['funds']['recorded_balance_units'],992)
        self.assertEqual(r['funds']['genesis_allocation_units'],1000)
        self.assertEqual(r['funds']['net_recorded_change_units'],-8)
        self.assertTrue(r['funds']['complete_receipt_history_reconciles'])
    def test_zero_is_a_verified_balance_not_missing_evidence(self):
        self.assertEqual(self.read(fixture.IDS[1])['funds']['recorded_balance_units'],0)
        with self.assertRaises(ValueError):self.read('unseen-account')
    def test_pending_fee_counts_without_changing_chain_balance(self):
        self.c.approve();r=self.read()
        self.assertEqual(r['funds']['recorded_balance_units'],992)
        self.assertEqual(r['funds']['pending_debit_units'],60)
        self.assertEqual(r['funds']['uncommitted_headroom_units'],932)
        self.assertEqual(r['budgets'][0]['uncommitted_allowance_units'],40)
    def test_shared_limits_are_not_added_across_grants(self):
        self.c.approve();r=self.read()
        self.assertEqual([g['shared_budget_headroom_units'] for g in r['grants']],[40,40,40])
        self.assertEqual([g['effective_next_debit_ceiling_units'] for g in r['grants']],[40,40,40])
    def test_two_pending_signatures_consume_budget_once_each(self):
        self.c.approve();self.c.approve(3,38);r=self.read()
        self.assertEqual(r['budgets'][0]['pending_debit_units'],100)
        self.assertEqual(r['budgets'][0]['uncommitted_allowance_units'],0)
        self.assertEqual(r['funds']['pending_debit_units'],100)
    def test_read_never_changes_wallet_tables_or_checkpoint(self):
        self.c.approve();before=self.logical();self.read();self.read()
        self.assertEqual(before,self.logical())
    def test_readonly_connection_refuses_writes(self):
        db=open_readonly(self.c.path)
        try:
            with self.assertRaises(sqlite3.OperationalError):db.execute('DELETE FROM decisions')
        finally:db.close()
    def test_existing_pending_survives_stale_observation(self):
        self.c.approve();r=self.read(observed_at_ns=self.c.clock+301*10**9)
        self.assertEqual(r['funds']['pending_debit_units'],60)
        self.assertIn('snapshot_too_old',r['observation']['blockers'])
        self.assertTrue(all(g['effective_next_debit_ceiling_units'] is None for g in r['grants']))
    def test_policy_expiry_does_not_hide_history_or_create_authority(self):
        self.c.approve();r=self.read(observed_at_ns=self.c.wallet.trust_expires)
        self.assertIn('policy_expired',r['observation']['blockers'])
        self.assertEqual(r['funds']['pending_debit_units'],60)
        self.assertFalse(r['authority']['fresh_payment_authorization'])
    def test_clock_rollback_is_visible_not_reset(self):
        before=self.logical();r=self.read(observed_at_ns=self.c.clock-1)
        self.assertIn('local_clock_rollback',r['observation']['blockers']);self.assertEqual(before,self.logical())
    def test_future_header_is_not_shown_as_current(self):
        r=self.read(observed_at_ns=self.c.clock-10*10**9)
        self.assertIn('snapshot_from_future',r['observation']['blockers'])
    def test_full_state_reconciliation_moves_pending_to_recorded_spend(self):
        first=self.c.approve();self.c.advance([canonical(first['result'])]);self.c.sync();r=self.read()
        self.assertEqual(r['funds']['recorded_balance_units'],932)
        self.assertEqual(r['funds']['pending_debit_units'],0)
        self.assertEqual(r['budgets'][0]['recorded_spent_units'],60)
        self.assertEqual(r['decisions'][0]['status'],'recorded')
        self.assertEqual(r['history'][0]['delta_units'],-60)
    def test_recipient_view_has_incoming_credit_not_senders_reservations(self):
        first=self.c.approve();self.c.advance([canonical(first['result'])]);self.c.sync()
        r=self.read(fixture.IDS[1]);self.assertEqual(r['funds']['recorded_balance_units'],58)
        self.assertEqual(r['history'][0]['delta_units'],58)
        self.assertEqual(r['history'][0]['fee_charged_to_account_units'],0)
        self.assertEqual(r['decisions'],[]);self.assertEqual(r['budgets'],[])
    def test_other_account_signatures_never_charge_selected_account(self):
        self.c.approve(5,450);r=self.read()
        self.assertEqual(r['funds']['pending_debit_units'],0);self.assertEqual(r['decisions'],[])
    def test_revoked_grant_has_zero_effective_ceiling_but_preserves_pending(self):
        self.c.approve();self.c.advance([self.c.owner_operation({'type':'revoke','id':'raven'})]);self.c.sync()
        r=self.read();g=next(x for x in r['grants'] if x['id'].endswith('::raven'))
        self.assertFalse(g['active_at_next_height']);self.assertEqual(g['effective_next_debit_ceiling_units'],0)
        self.assertEqual(r['funds']['pending_debit_units'],60)
    def test_parent_budget_revocation_disables_child_ceiling(self):
        self.c.advance([self.c.owner_operation({'type':'budget_revoke','id':'project'})]);self.c.sync()
        r=self.read();self.assertTrue(all(g['effective_next_debit_ceiling_units']==0 for g in r['grants']))
        self.assertTrue(all('parent_budget_inactive' in g['inactive_reasons'] for g in r['grants']))
    def test_authority_fence_keeps_history_and_disables_permissions(self):
        self.c.advance([self.c.owner_operation({'type':'fence'})]);self.c.sync();r=self.read()
        self.assertEqual(r['account_epoch'],1)
        self.assertTrue(all(not g['active_at_next_height'] for g in r['grants']))
        self.assertTrue(r['funds']['complete_receipt_history_reconciles'])
    def test_signed_expiry_not_wall_time_controls_hold(self):
        self.c.approve(until=2);self.c.advance();self.c.sync()
        self.assertEqual(self.read()['funds']['pending_debit_units'],60)
        self.c.advance();self.c.sync();r=self.read()
        self.assertEqual(r['funds']['pending_debit_units'],0)
        self.assertEqual(r['decisions'][0]['status'],'expired_absent')
    def test_external_spend_can_leave_overcommitted_hold_visible(self):
        self.c.approve();self.c.advance([self.c.owner_operation({'type':'transfer','to':fixture.IDS[5],'units':950})]);self.c.sync()
        r=self.read();self.assertEqual(r['funds']['recorded_balance_units'],40)
        self.assertEqual(r['funds']['pending_debit_units'],60)
        self.assertEqual(r['funds']['overcommitted_units'],20)
        self.assertEqual(r['funds']['uncommitted_headroom_units'],0)
    def test_truncation_is_disclosed_and_totals_are_untruncated(self):
        self.c.approve();self.c.approve(3,38);r=self.read(limit=1)
        self.assertEqual(len(r['decisions']),1);self.assertEqual(r['coverage']['total_items']['decisions'],2)
        self.assertIn('decisions',r['coverage']['truncated_lists']);self.assertEqual(r['funds']['pending_debit_units'],100)
        self.assertEqual(r['coverage']['total_items']['history'],4)
    def test_invalid_limits_rejected(self):
        for val in (True,0,201,1.0,'1'):
            with self.subTest(val=val),self.assertRaises(ValueError):self.read(limit=val)
    def test_unchanged_input_produces_identical_view_digest(self):
        self.c.approve();self.assertEqual(self.read(),self.read())
    def test_tampered_witness_even_with_rehashed_document_is_refused(self):
        row=self.c.wallet.db.execute('SELECT witness FROM wallet_evidence').fetchone()
        w=json.loads(row[0]);w['state']['native']['accounts'][0][4]+=1;raw=encode(w)
        self.c.wallet.db.execute('UPDATE wallet_evidence SET witness=?,witness_hash=?',(raw.decode(),hashlib.sha256(raw).hexdigest()))
        with self.assertRaises(ValueError):self.read()
    def test_tampered_signed_decision_refused_even_with_new_storage_hash(self):
        self.c.approve();row=self.c.wallet.db.execute('SELECT result FROM decisions').fetchone()
        obj=json.loads(row[0]);obj['signature']='0'*128;raw=canonical(obj)
        self.c.wallet.db.execute('UPDATE decisions SET result=?,result_hash=?',(raw.decode(),hashlib.sha256(raw).hexdigest()))
        with self.assertRaises(ValueError):self.read()
    def test_wrong_policy_is_not_silently_accepted(self):
        wrong={**self.c.policy,'maximum_age_seconds':301}
        with self.assertRaises(ValueError):read_account(self.c.path,self.c.raw,wrong,fixture.IDS[0],observed_at_ns=self.c.clock)
    def test_wrong_genesis_digest_fails(self):
        with self.assertRaises(ValueError):read_account(self.c.path,self.c.raw,{**self.c.policy,'genesis_sha256':'0'*64},fixture.IDS[0])
    def test_missing_journal_is_not_created(self):
        p=self.c.root/'missing.sqlite'
        with self.assertRaises(OSError):read_account(p,self.c.raw,self.c.policy,fixture.IDS[0])
        self.assertFalse(p.exists())
    def test_new_unsynced_wallet_is_not_a_zero_balance(self):
        p=self.c.root/'unseen.sqlite';w=self.c.open(p);w.close()
        with self.assertRaises(ValueError):read_account(p,self.c.raw,self.c.policy,fixture.IDS[0])
    def test_legacy_journal_refused_without_migration(self):
        p=self.c.root/'legacy.sqlite';db=sqlite3.connect(p);db.execute('CREATE TABLE outbox(secret TEXT)');db.commit();db.close();p.chmod(0o600)
        raw=p.read_bytes()
        with self.assertRaises(ValueError):read_account(p,self.c.raw,self.c.policy,fixture.IDS[0])
        self.assertEqual(raw,p.read_bytes())
    def test_symlink_and_hardlink_journals_refused(self):
        for kind in ('symlink','hardlink'):
            p=self.c.root/kind
            p.symlink_to(self.c.path) if kind=='symlink' else os.link(self.c.path,p)
            with self.assertRaises(ValueError):read_account(p,self.c.raw,self.c.policy,fixture.IDS[0])
            p.unlink()
    def test_world_readable_journal_refused(self):
        self.c.path.chmod(0o644)
        with self.assertRaises(ValueError):self.read()
    def test_journal_query_only_path_never_uses_keys_or_rpc(self):
        self.c.approve()
        with patch('certified_wallet._load_vault',side_effect=AssertionError('no key')),patch('socket.socket',side_effect=AssertionError('no network')):
            self.assertEqual(self.read()['funds']['pending_debit_units'],60)
    def test_uncheckpointed_wal_decision_is_included(self):
        self.c.wallet.db.execute('PRAGMA wal_autocheckpoint=0')
        self.c.approve();wal=Path(str(self.c.path)+'-wal')
        self.assertTrue(wal.is_file());self.assertGreater(wal.stat().st_size,0)
        self.assertEqual(self.read()['funds']['pending_debit_units'],60)
    def test_concurrent_signing_cannot_mix_old_state_with_new_inventory(self):
        import account_view
        original=account_view.inventory
        called=[]
        def during(*args):
            if not called:
                called.append(True);self.c.approve()
            return original(*args)
        with patch('account_view.inventory',side_effect=during):first=self.read()
        self.assertEqual(first['funds']['pending_debit_units'],0)
        self.assertEqual(self.read()['funds']['pending_debit_units'],60)
    def test_published_wallet_without_catchup_table_is_supported(self):
        self.c.wallet.db.execute('DROP TABLE IF EXISTS wallet_header_progress')
        self.assertEqual(self.read()['state']['verified_header_height'],2)
    def test_report_contains_no_signatures_vaults_or_other_account_balances(self):
        self.c.approve();text=json.dumps(self.read())
        self.assertNotIn('"signature"',text);self.assertNotIn(fixture.PASSWORD.decode(),text)
        self.assertNotIn(str(self.c.path),text);self.assertNotIn(fixture.IDS[5],text)
    def test_opened_account_reconciles_sponsor_credit(self):
        body=self.c.model.body(fixture.IDS[0],4,{'type':'open_account','public_key':public(fixture.KEYS[4]),'units':100,'acceptance':''})
        tx=canonical(sign(fixture.KEYS[0],accept_account_key(fixture.KEYS[4],body)))
        self.c.advance([tx]);self.c.sync();r=self.read(address(public(fixture.KEYS[4])))
        self.assertEqual(r['funds']['genesis_allocation_units'],0)
        self.assertEqual(r['funds']['recorded_balance_units'],100)
        self.assertEqual(r['history'][0]['delta_units'],100)
    def test_incoming_consent_creates_no_fictitious_debit(self):
        body=self.c.model.body(fixture.IDS[0],4,{'type':'open_account','public_key':public(fixture.KEYS[4]),'units':100,'acceptance':''})
        r=self.c.wallet.review(self.c.witness,body,public(fixture.KEYS[4]),mode='accept')
        self.c.wallet.approve(self.c.witness,body,public(fixture.KEYS[4]),r['confirmation'],self.c.root/'key4.pem',fixture.PASSWORD,mode='accept')
        report=self.read();self.assertEqual(report['funds']['pending_debit_units'],0)
        self.assertEqual(report['decisions'][0]['status'],'consent_only')
    def test_history_arithmetic_is_rechecked_not_a_display_flag(self):
        with patch('account_view._activity',return_value=[]):
            with self.assertRaisesRegex(ValueError,'does not reconcile'):self.read()


class PresentationTests(unittest.TestCase):
    def setUp(self):
        self.c=fixture.ObligationTests();self.c.setUp();self.c.approve()
        self.view=read_account(self.c.path,self.c.raw,self.c.policy,fixture.IDS[0],observed_at_ns=self.c.clock)
    def tearDown(self):self.c.tearDown()
    def test_html_is_static_and_all_assets_self_contained(self):
        from html.parser import HTMLParser
        seen=[]
        class Parser(HTMLParser):
            def handle_starttag(self,tag,attrs):seen.append((tag,dict(attrs)))
        parser=Parser();parser.feed(render_html(self.view,specimen=True))
        self.assertFalse(any(t in ('script','iframe','form','link','img') for t,a in seen))
        self.assertIn('DEVELOPMENT SPECIMEN',render_html(self.view,specimen=True))
    def test_identifiers_are_escaped_not_executable_markup(self):
        v=copy.deepcopy(self.view);v['account']='<script>alert(1)</script>'
        html=render_html(v);self.assertNotIn('<script>alert',html);self.assertIn('&lt;script&gt;',html)
    def test_cli_produces_historical_json_without_unlock(self):
        for n,obj in [('genesis',self.c.engine),('policy',self.c.policy)]:
            (self.c.root/f'{n}.json').write_bytes(encode(obj))
        args=[sys.executable,str(ROOT/'scripts/account.py'),'--genesis',str(self.c.root/'genesis.json'),'--policy',str(self.c.root/'policy.json'),'--journal',str(self.c.path),'--account',fixture.IDS[0]]
        p=subprocess.run(args,capture_output=True,text=True,timeout=10)
        self.assertEqual(p.returncode,0,p.stderr);r=json.loads(p.stdout)
        self.assertEqual(r['funds']['pending_debit_units'],60);self.assertFalse(r['authority']['signing_enabled'])
    def test_cli_never_overwrites_report(self):
        for n,obj in [('genesis',self.c.engine),('policy',self.c.policy)]:
            (self.c.root/f'{n}.json').write_bytes(encode(obj))
        target=self.c.root/'keep.html';target.write_text('keep')
        p=subprocess.run([sys.executable,str(ROOT/'scripts/account.py'),'--genesis',str(self.c.root/'genesis.json'),'--policy',str(self.c.root/'policy.json'),'--journal',str(self.c.path),'--account',fixture.IDS[0],'--format','html','--output',str(target)],capture_output=True,text=True,timeout=10)
        self.assertEqual(p.returncode,2);self.assertEqual(target.read_text(),'keep')
    def test_cli_refuses_missing_evidence_not_a_balance_of_zero(self):
        for n,obj in [('genesis',self.c.engine),('policy',self.c.policy)]:
            (self.c.root/f'{n}.json').write_bytes(encode(obj))
        p=subprocess.run([sys.executable,str(ROOT/'scripts/account.py'),'--genesis',str(self.c.root/'genesis.json'),'--policy',str(self.c.root/'policy.json'),'--journal',str(self.c.root/'no-wallet.sqlite'),'--account',fixture.IDS[0]],capture_output=True,text=True,timeout=10)
        self.assertEqual(p.returncode,2);self.assertEqual(p.stdout,'');self.assertIn('No wallet data was changed',p.stderr)



class ProtocolViewsTests(unittest.TestCase):
    def test_all_published_native_protocol_and_commitment_variants(self):
        from block_application import BlockApplication
        from certified_wallet import CertifiedWallet, nanos
        from certificate_fixture import validators, make_header, make_commit, STAMP
        for version,smt in [(1,False),(2,False),(3,False),(3,True)]:
            with self.subTest(version=version,smt=smt),tempfile.TemporaryDirectory() as tmp:
                p=Path(tmp)
                g={'chain_id':f'view-protocol-{version}-smt-{int(smt)}','asset':'DEV','fee':2,
                   'protocol_version':version,'allocations':[{'public_key':public(fixture.KEYS[0]),'units':1000}]}
                if smt:g['state_commitment']='smt-v1'
                app=BlockApplication(':memory:');app.init_chain(g['chain_id'],g)
                engine,trust,keys=validators(g)
                state=json.loads(app.query('/state')['value'])
                h=make_header(trust,1,state['app_hash']);h['version']['app']=str(version)
                witness={'schema':1,'state':state,'state_commit':make_commit(h,trust,keys)}
                raw=encode(engine);policy={'schema':1,'genesis_sha256':hashlib.sha256(raw).hexdigest(),
                  'trust_expires_utc':'2030-01-01T00:00:00Z','minimum_header_height':1,
                  'maximum_age_seconds':300,'future_skew_seconds':5}
                w=CertifiedWallet(p/'wallet.sqlite',raw,policy,clock=lambda:nanos(STAMP)+10**9)
                try:
                    w.sync(witness)
                    r=read_account(p/'wallet.sqlite',raw,policy,fixture.IDS[0],observed_at_ns=nanos(STAMP)+10**9)
                    self.assertEqual(r['funds']['recorded_balance_units'],1000)
                    self.assertEqual(r['state']['application_height'],0)
                    self.assertEqual(r['history'],[])
                    self.assertFalse(r['authority']['fresh_payment_authorization'])
                finally:w.close();app.close()

if __name__=='__main__':unittest.main()
