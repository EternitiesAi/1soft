"""Actual alpha financial composition; synthetic clock is separate from real-duration qualification."""
import hashlib
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
from alpha_wallet_fixture import AlphaChain,PASSWORD
from payment_requests import new_request

class AlphaServiceTests(unittest.TestCase):
    def setUp(self):
        try:from p4_alpha_platform_service import AlphaPlatformService
        except ImportError as exc:self.fail(f'alpha app integration missing: {exc}')
        self.Service=AlphaPlatformService;self.temp=tempfile.TemporaryDirectory();self.root=Path(self.temp.name)
        self.c=AlphaChain(self.root,time_step_seconds=240)
        self.roles={n:{'payer':self.c.payer,'grant_id':'' if n=='owner' else n,'vault':n+'.pem'} for n in ('owner','raven','atlas')}
        self.s=self.open(create=True);self.tip=None;self.height=0;self.append();self.s.sync(expected_revision=None)
    def open(self,**kwargs):return self.Service(self.root,self.c.genesis,self.c.policy,'http://127.0.0.1:26657/',self.roles,clock=self.c.clock,**kwargs)
    def tearDown(self):
        if hasattr(self,'s'):self.s.close()
        if hasattr(self,'c'):self.c.close()
        if hasattr(self,'temp'):self.temp.cleanup()
    def append(self):
        e=self.c.evidence();q={'schema':1,'format':'1soft/protocol4-incremental-segment/v1','parent_checkpoint':self.tip,
           'from_height':self.height,'state':e['state'],'history':e['history'][self.height:],'headers':e['headers'][self.height:]}
        saved=self.s.import_checkpoint(q,expected_tip=self.tip);self.tip=saved['checkpoint']['id'];self.height=e['state']['height'];return saved
    def request(self):
        return self.s.add_request(new_request(hashlib.sha256(self.c.genesis).hexdigest(),self.c.merchant,'58',
            created_ns=self.c.now,expires_ns=self.c.now+86400*10**9,note='Alpha payment'))['request_id']
    def sign(self,rid):
        q=self.s.prepare(rid,'raven',valid_until=self.height+30)
        return self.s.approve(rid,'raven',q['review'],q['confirmation'],password=PASSWORD)
    def test_original_signature_and_hold_survive_expired_wallet_context_then_sync(self):
        rid=self.request();result=self.sign(rid);wire=self.s.recover(rid)
        for _ in range(3):
            for _ in range(5):self.c.block([])
            self.append()
        self.assertGreater(self.c.now, __import__('p4_evidence').nanos(self.c.policy['anchor_time'])+3600*10**9)
        state=self.s.state()
        self.assertTrue(state['current_evidence_available'])
        self.assertFalse(state['wallet_current'])
        self.assertEqual(state['wallet']['pending_debit_units'],'60')
        self.s.sync(expected_revision=state['wallet']['revision'])
        self.assertEqual(self.s.recover(rid),wire)
        self.assertEqual(self.s.state()['wallet']['pending_debit_units'],'60')
        self.s.close();self.s=self.open()
        self.assertEqual(self.s.recover(rid),wire)
    def test_view_and_prepare_do_not_fetch_dispatch_or_sign(self):
        rid=self.request()
        with patch('p4_wallet._load_vault',side_effect=AssertionError('key access')),patch('p4_delivery.submit_once',side_effect=AssertionError('network')):
            state=self.s.state();q=self.s.prepare(rid,'raven',valid_until=30)
        self.assertEqual(state['wallet']['pending_debit_units'],'0')
        self.assertFalse(q['signed']);self.assertIsNone(self.s.book.selected(rid)['decision_id'])
    def test_profile_limits_match_actual_new_callers(self):
        state=self.s.state()
        self.assertEqual(state['limits']['rpc_height'],4096)
        self.assertEqual(state['limits']['rpc_batch_blocks'],64)
        self.assertTrue(state['limits']['checkpoint_progression'])
        self.assertFalse(state['real_funds_supported'])
    def test_same_shared_store_can_serve_sequential_app_connections(self):
        external=self.s.store;self.s.close()
        # Ordinary owned service closes its store; reopen provides its own. Shared construction below borrows it.
        from p4_incremental_store import P4IncrementalStore
        store=P4IncrementalStore(self.root/'ledger.sqlite',self.c.genesis,self.c.policy,clock=self.c.clock)
        try:
            for _ in range(2):
                with self.Service(self.root,self.c.genesis,self.c.policy,'http://127.0.0.1:26657/',self.roles,clock=self.c.clock,store=store) as svc:
                    self.assertEqual(svc.state()['ledger']['checkpoint']['state_height'],'1')
            self.assertEqual(store.current()['report']['state_height'],1)
        finally:store.close()
        self.s=self.open()

    def test_complete_streamed_backup_restores_original_inert_obligation(self):
        with patch('p4_alpha_custody.time.time_ns',self.c.clock):
            from p4_alpha_custody import restore_backup,RecoveryArchive
            rid=self.request();signed=self.sign(rid);wire=self.s.recover(rid)
            output=self.root/'download.p4alpha'
            with self.s.backup_history(PASSWORD) as item:
                self.assertEqual(item['format'],'alpha-v1')
                raw=item['source'].read();self.assertEqual(raw[:10],b'1SOFTP4A1\n')
                self.assertEqual(len(raw),item['size']);self.assertEqual(hashlib.sha256(raw).hexdigest(),item['sha256'])
                output.write_bytes(raw);output.chmod(0o600)
            restore_backup(output,self.root/'inert',self.c.genesis,self.c.policy,PASSWORD)
            with RecoveryArchive(self.root/'inert',self.c.genesis,self.c.policy) as archive:
                self.assertEqual(archive.recover(signed['decision_id'],payer=self.c.payer,grant_id='raven'),wire)
                self.assertEqual(archive.inspect()['pending_debit_units'],'60')
                self.assertFalse(archive.inspect()['signing_enabled'])
    def test_retained_receipt_is_small_and_packet_stays_exact_after_progress(self):
        from p4_alpha_custody import verify_receipt
        rid=self.request();signed=self.sign(rid);wire=self.s.recover(rid)
        self.c.block([wire]);self.append()
        self.s.delivery.import_receipt(signed['decision_id'],self.tip,payer=self.c.payer,grant_id='raven')
        saved=self.s.retain_receipt(rid);before=self.s.capsule(rid,saved['capsule_id'])
        self.assertLess(len(self.s.receipts.db.execute('SELECT payload FROM references_v1').fetchone()[0]),4096)
        self.append();self.assertEqual(self.s.capsule(rid,saved['capsule_id']),before)
        with patch('p4_alpha_custody.time.time_ns',self.c.clock):
            checked=verify_receipt(before,self.c.genesis,self.c.policy,payer=self.c.payer,wire_sha256=hashlib.sha256(wire).hexdigest())
        self.assertEqual(checked['capsule_id'],saved['capsule_id']);self.assertFalse(checked['current_spending_authority'])
    def test_partial_workspace_cannot_be_recreated(self):
        self.s.close()
        with self.assertRaises(ValueError):self.s=self.open(create=True)
        self.s=self.open();self.assertEqual(self.s.state()['wallet']['pending_debit_units'],'0')

if __name__=='__main__':unittest.main()
