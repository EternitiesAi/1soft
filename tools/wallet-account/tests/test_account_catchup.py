"""Optional integration tests against the separately supplied catch-up core."""
import unittest
import test_wallet_obligations as fixture
from account_view import read_account
from native_core import canonical

class CatchupAccountTests(unittest.TestCase):
    def setUp(self):
        self.c=fixture.ObligationTests();self.c.setUp();self.c.wallet.sync(self.c.witness)
    def tearDown(self):self.c.tearDown()
    def read(self):
        return read_account(self.c.path,self.c.raw,self.c.policy,fixture.IDS[0],observed_at_ns=self.c.clock)
    def test_header_only_progress_cannot_update_balance_or_retire_pending(self):
        first=self.c.approve();self.c.advance([canonical(first['result'])])
        self.c.wallet.advance_headers([self.c.witness['state_commit']])
        r=self.read();self.assertEqual(r['state']['application_height'],1)
        self.assertEqual(r['state']['verified_header_height'],3)
        self.assertEqual(r['funds']['pending_debit_units'],60)
        self.assertIn('newer_headers_need_state_sync',r['observation']['blockers'])

    def test_corrupt_optional_header_progress_is_refused(self):
        self.c.advance();self.c.wallet.advance_headers([self.c.witness['state_commit']])
        self.c.wallet.db.execute("UPDATE wallet_header_progress SET header_digest=?",('0'*64,))
        with self.assertRaises(ValueError):self.read()

