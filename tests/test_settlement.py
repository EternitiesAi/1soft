import tempfile
import threading
import unittest
from pathlib import Path
from concurrent.futures import ThreadPoolExecutor
from native_core import Reject
from settlement_journal import SettlementJournal

class SettlementTests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory(); self.path=Path(self.tmp.name)/'journal.sqlite'
        self.j=SettlementJournal(self.path); self.j.register_asset('demo:usd',2); self.j.register_asset('bitcoin:btc',8)
        self.j.fixture_credit('fund','alice','demo:usd',10000)
    def tearDown(self): self.j.close(); self.tmp.cleanup()
    def reserve(self,units=3000,rail='card',intent='purchase'):
        return self.j.reserve(intent,owner='alice',asset='demo:usd',units=units,rail=rail,beneficiary='merchant-a',provider='fixture-processor')
    def sent(self,units=3000): self.reserve(units); self.j.dispatch('purchase')
    def settle(self,actual=3000): return self.j.reconcile('capture','purchase',provider='fixture-processor',outcome='settled',actual=actual)
    def test_fixture_idempotency(self):
        self.j.fixture_credit('fund','alice','demo:usd',10000)
        self.assertEqual(self.j.balance('available:alice','demo:usd'),10000); self.assertTrue(self.j.verify())
    def test_fixture_conflict(self):
        with self.assertRaises(Reject): self.j.fixture_credit('fund','alice','demo:usd',9999)
        self.assertEqual(self.j.balance('available:alice','demo:usd'),10000)
    def test_asset_registry_not_redefinable(self):
        self.j.register_asset('demo:usd',2)
        with self.assertRaises(Reject): self.j.register_asset('demo:usd',8)
    def test_assets_not_interchangeable(self):
        with self.assertRaises(Reject): self.j.reserve('p',owner='alice',asset='bitcoin:btc',units=1,rail='native',beneficiary='b',provider='p')
        self.assertEqual(self.j.balance('available:alice','demo:usd'),10000)
    def test_reservation_atomic_and_idempotent(self):
        self.reserve(); self.reserve()
        self.assertEqual(self.j.balance('available:alice','demo:usd'),7000)
        self.assertEqual(self.j.balance('held:purchase','demo:usd'),3000); self.assertTrue(self.j.verify())
    def test_reservation_insufficient_funds_rolls_back(self):
        with self.assertRaises(Reject): self.reserve(10001)
        with self.assertRaises(Reject): self.j.intent('purchase')
        self.assertEqual(self.j.balance('available:alice','demo:usd'),10000); self.assertTrue(self.j.verify())
    def test_no_silent_reroute(self):
        self.reserve()
        with self.assertRaises(Reject): self.reserve(rail='x402')
        self.assertEqual(self.j.intent('purchase')['body']['rail'],'card')
    def test_dispatch_retry_idempotent(self):
        self.sent(); self.j.dispatch('purchase'); self.assertEqual(self.j.intent('purchase')['status'],'dispatched')
    def test_unknown_keeps_hold_across_restart(self):
        self.sent(); self.j.unknown('purchase'); self.j.close(); self.j=SettlementJournal(self.path)
        self.assertEqual(self.j.intent('purchase')['status'],'unknown')
        self.assertEqual(self.j.balance('held:purchase','demo:usd'),3000)
        with self.assertRaises(Reject): self.j.dispatch('purchase')
    def test_provider_mismatch(self):
        self.sent()
        with self.assertRaises(Reject): self.j.reconcile('c','purchase',provider='wrong-provider',outcome='settled',actual=3000)
        self.assertEqual(self.j.balance('held:purchase','demo:usd'),3000)
    def test_cannot_settle_without_dispatch(self):
        self.reserve()
        with self.assertRaises(Reject): self.settle()
    def test_final_capture_and_idempotent_evidence(self):
        self.sent(); self.settle(); self.settle()
        self.assertEqual(self.j.balance('settled:purchase','demo:usd'),3000)
        self.assertEqual(self.j.balance('held:purchase','demo:usd'),0); self.assertTrue(self.j.verify())
    def test_conflicting_capture_evidence_rejected(self):
        self.sent(); self.settle()
        with self.assertRaises(Reject): self.settle(2999)
    def test_lower_final_capture_releases_difference(self):
        self.sent(); self.settle(2400)
        self.assertEqual(self.j.balance('available:alice','demo:usd'),7600); self.assertTrue(self.j.verify())
    def test_overcapture_records_liability_not_fake_rejection(self):
        self.sent(); result=self.settle(3500)
        self.assertEqual(result['status'],'exception'); self.assertEqual(self.j.balance('liability:alice','demo:usd'),-500)
        self.assertEqual(self.j.balance('available:alice','demo:usd'),7000); self.assertTrue(self.j.verify())
    def test_unresolved_liability_freezes_new_reservations(self):
        self.sent(); self.settle(3500)
        with self.assertRaises(Reject): self.reserve(intent='next-purchase')
        self.assertEqual(self.j.balance('available:alice','demo:usd'),7000)
    def test_confirmed_nonpayment_releases_hold(self):
        self.sent(); self.j.unknown('purchase')
        self.j.reconcile('release','purchase',provider='fixture-processor',outcome='confirmed_not_settled')
        self.assertEqual(self.j.balance('available:alice','demo:usd'),10000)
        self.assertEqual(self.j.intent('purchase')['status'],'released')
    def test_late_capture_after_release_records_liability(self):
        self.test_confirmed_nonpayment_releases_hold(); self.settle()
        self.assertEqual(self.j.intent('purchase')['status'],'exception')
        self.assertEqual(self.j.balance('liability:alice','demo:usd'),-3000); self.assertTrue(self.j.verify())
    def test_refund_same_settlement_asset_idempotent(self):
        self.sent(); self.settle()
        for _ in range(2): self.j.refund('refund','purchase',provider='fixture-processor',units=2000)
        self.assertEqual(self.j.balance('available:alice','demo:usd'),9000)
        self.assertEqual(self.j.balance('available:alice','bitcoin:btc'),0); self.assertTrue(self.j.verify())
    def test_refund_over_capture_rejected(self):
        self.sent(); self.settle(); self.j.refund('r','purchase',provider='fixture-processor',units=2000)
        with self.assertRaises(Reject): self.j.refund('r2','purchase',provider='fixture-processor',units=1001)
        self.assertEqual(self.j.balance('available:alice','demo:usd'),9000)
    def test_refund_exception_requires_explicit_debt_resolution(self):
        self.sent(); self.settle(3500)
        with self.assertRaises(Reject): self.j.refund('r','purchase',provider='fixture-processor',units=100)
    def test_rejects_noninteger_units(self):
        for units in [True,1.5,-1,0,'30']:
            with self.subTest(units=units):
                with self.assertRaises(Reject): self.reserve(units)
    def test_racing_routes_cannot_reserve_same_available_funds(self):
        barrier=threading.Barrier(2)
        def worker(rail):
            j=SettlementJournal(self.path)
            try:
                barrier.wait(timeout=5)
                try:
                    j.reserve(rail,owner='alice',asset='demo:usd',units=7000,rail=rail,beneficiary='merchant',provider='fixture')
                    return 'accepted'
                except Reject: return 'rejected'
            finally: j.close()
        with ThreadPoolExecutor(max_workers=2) as pool: results=list(pool.map(worker,['card','x402']))
        self.assertEqual(sorted(results),['accepted','rejected'])
        self.assertEqual(self.j.balance('available:alice','demo:usd'),3000); self.assertTrue(self.j.verify())

if __name__=='__main__': unittest.main()
