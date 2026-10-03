"""Original monetary obligations with retained authenticated checkpoint references."""
import copy
from pathlib import Path
import tempfile
import unittest
from block_application import encode
from p4_evidence import content_id
from alpha_wallet_fixture import AlphaChain, PASSWORD

class AlphaWalletCase(unittest.TestCase):
    def setUp(self):
        try:
            from p4_incremental_store import P4IncrementalStore
            from p4_alpha_wallet import P4AlphaWallet
        except ImportError as exc: self.fail(f'new authenticated financial profile missing: {exc}')
        self.Wallet=P4AlphaWallet
        self.temp=tempfile.TemporaryDirectory();self.root=Path(self.temp.name);self.c=AlphaChain(self.root)
        self.store=P4IncrementalStore(self.root/'history.sqlite',self.c.genesis,self.c.policy,create=True,clock=self.c.clock)
        self.tip=None;self.height=0
        self.checkpoint=self.append()
        self.w=self.Wallet(self.root/'wallet.sqlite',self.c.genesis,self.c.policy,self.store,create=True,clock=self.c.clock)
        self.w.sync(self.checkpoint['checkpoint']['id'],expected_revision=None)
    def tearDown(self):
        if hasattr(self,'w'):self.w.close()
        if hasattr(self,'store'):self.store.close()
        if hasattr(self,'c'):self.c.close()
        if hasattr(self,'temp'):self.temp.cleanup()
    def append(self):
        e=self.c.evidence();h=e['state']['height']
        segment={'schema':1,'format':'1soft/protocol4-incremental-segment/v1','parent_checkpoint':self.tip,
            'from_height':self.height,'state':e['state'],'history':e['history'][self.height:],
            'headers':e['headers'][self.height:]}
        view=self.store.import_segment(segment,expected_tip=self.tip)
        self.tip=view['checkpoint']['id'];self.height=h;return view
    def prepare(self,units=58,role='raven'):
        return self.w.prepare(payer=self.c.payer,recipient=self.c.merchant,units=units,grant_id=role,valid_until=self.height+30)
    def sign(self,units=58,role='raven'):
        q=self.prepare(units,role);result=self.w.approve(q['review'],q['confirmation'],vault=self.root/(role+'.pem'),password=PASSWORD)
        return result,self.w.recover(q['confirmation'],payer=self.c.payer,grant_id=role)
    def sync(self):
        view=self.append();self.w.sync(view['checkpoint']['id'],expected_revision=self.w.status()['revision']);return view

class AlphaWalletTests(AlphaWalletCase):
    def test_signed_fee_inclusive_hold_survives_64_observations_and_cold_reopen(self):
        result,wire=self.sign()
        for _ in range(65):self.sync()
        self.assertEqual(self.w.status()['pending_debit_units'],'60')
        self.assertEqual(self.w.db.execute('SELECT count(*) FROM observations').fetchone()[0],66)
        self.assertLess(self.w.db.execute('SELECT max(length(payload)) FROM observations').fetchone()[0],2048)
        self.w.close();self.store.close()
        from p4_incremental_store import P4IncrementalStore
        self.store=P4IncrementalStore(self.root/'history.sqlite',self.c.genesis,self.c.policy,clock=self.c.clock)
        self.w=self.Wallet(self.root/'wallet.sqlite',self.c.genesis,self.c.policy,self.store,clock=self.c.clock)
        self.assertEqual(self.w.recover(result['decision_id'],payer=self.c.payer,grant_id='raven'),wire)
        self.assertEqual(self.w.status()['pending_debit_units'],'60')
    def test_shared_budget_holds_include_fees_across_roles(self):
        self.sign()
        with self.assertRaises(ValueError):self.prepare(39,'atlas')
        self.assertEqual(self.w.status()['pending_debit_units'],'60')
    def test_exact_successful_execution_retires_only_original_hold(self):
        result,wire=self.sign();self.c.block([wire]);self.sync()
        self.assertEqual(self.w.status()['pending_debit_units'],'0')
        self.assertEqual(self.w.recover(result['decision_id'],payer=self.c.payer,grant_id='raven'),wire)
        recorded=[d for d in self.w.status()['decisions'] if d['id']==result['decision_id']]
        self.assertEqual(recorded[0]['status'],'recorded')
    def test_expired_authority_retains_inert_original_wire_and_hold(self):
        result,wire=self.sign();rows=self.w.db.execute('SELECT * FROM decisions').fetchall()
        self.c.now=self.checkpoint['checkpoint']['lookahead_time_ns']+3600*10**9
        with self.assertRaises(ValueError):self.w.status()
        with self.assertRaises(ValueError):self.prepare(1,'atlas')
        self.assertEqual(self.w.recover(result['decision_id'],payer=self.c.payer,grant_id='raven'),wire)
        self.assertEqual(self.w.db.execute('SELECT * FROM decisions').fetchall(),rows)
    def test_stale_revision_cannot_import_new_context(self):
        old=self.w.status()['revision'];self.sign();view=self.append()
        count=self.w.db.execute('SELECT count(*) FROM observations').fetchone()[0]
        with self.assertRaises(ValueError):self.w.sync(view['checkpoint']['id'],expected_revision=old)
        self.assertEqual(self.w.db.execute('SELECT count(*) FROM observations').fetchone()[0],count)
    def test_read_tip_progress_refuses_stale_wallet_signing(self):
        from unittest.mock import patch
        q=self.prepare();self.append()
        with patch('p4_wallet._load_vault',side_effect=AssertionError('must refuse before key access')):
            with self.assertRaises(ValueError):self.w.approve(q['review'],q['confirmation'],vault=self.root/'raven.pem',password=PASSWORD)
        self.assertEqual(self.w.db.execute('SELECT count(*) FROM decisions').fetchone()[0],0)

    def test_missing_origin_history_refuses_without_deleting_original_decision(self):
        self.sign();rows=self.w.db.execute('SELECT * FROM decisions').fetchall()
        self.store.db.execute('DELETE FROM blocks WHERE height=1')
        with self.assertRaises(ValueError):self.w.status()
        self.assertEqual(self.w.db.execute('SELECT * FROM decisions').fetchall(),rows)

if __name__=='__main__':unittest.main()
