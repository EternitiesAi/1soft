"""No automatic resend and original receipts under the new history-reference profile."""
import unittest
from unittest.mock import patch
from test_alpha_wallet import AlphaWalletCase

class AlphaDeliveryTests(AlphaWalletCase):
    def setUp(self):
        super().setUp()
        try:from p4_alpha_delivery import P4AlphaDelivery
        except ImportError as exc:self.fail(f'alpha delivery missing: {exc}')
        self.delivery=P4AlphaDelivery(self.root/'wallet.sqlite',self.root/'delivery.sqlite',self.c.genesis,
            self.c.policy,'http://127.0.0.1:26657/',self.store,create=True,clock=self.c.clock)
    def tearDown(self):
        if hasattr(self,'delivery'):self.delivery.close()
        super().tearDown()
    def test_committed_attempt_is_not_resent_after_lost_response(self):
        result,wire=self.sign();selection={'payer':self.c.payer,'grant_id':'raven'}
        q=self.delivery.prepare(result['decision_id'],**selection)
        with patch('p4_delivery.submit_once',side_effect=RuntimeError('controlled lost reply')):
            with self.assertRaisesRegex(RuntimeError,'lost reply'):self.delivery.send(q['review'],q['confirmation'])
        self.assertEqual(self.delivery.db.execute('SELECT count(*) FROM attempts').fetchone()[0],1)
        with self.assertRaises(ValueError):self.delivery.prepare(result['decision_id'],**selection)
        self.assertEqual(self.w.status()['pending_debit_units'],'60')
        self.assertEqual(self.w.recover(result['decision_id'],**selection),wire)
    def test_positive_original_receipt_survives_cold_reopen_and_reconciles(self):
        result,wire=self.sign();selection={'payer':self.c.payer,'grant_id':'raven'}
        self.c.block([wire]);view=self.append()
        saved=self.delivery.import_receipt(result['decision_id'],view['checkpoint']['id'],**selection)
        self.assertEqual(saved['status'],'receipt_collected')
        self.assertEqual(self.w.status()['pending_debit_units'],'60')
        ref=self.delivery.export_receipt(result['decision_id'],**selection)
        self.delivery.close()
        from p4_alpha_delivery import P4AlphaDelivery
        self.delivery=P4AlphaDelivery(self.root/'wallet.sqlite',self.root/'delivery.sqlite',self.c.genesis,
            self.c.policy,'http://127.0.0.1:26657/',self.store,clock=self.c.clock)
        self.assertEqual(self.delivery.export_receipt(result['decision_id'],**selection),ref)
        self.delivery.reconcile(result['decision_id'],expected_revision=self.w.status()['revision'],**selection)
        self.assertEqual(self.w.status()['pending_debit_units'],'0')
    def test_missing_receipt_does_not_reset_obligation(self):
        result,wire=self.sign();selection={'payer':self.c.payer,'grant_id':'raven'}
        saved=self.delivery.import_receipt(result['decision_id'],self.tip,**selection)
        self.assertEqual(saved['status'],'unavailable')
        self.assertEqual(self.delivery.db.execute('SELECT count(*) FROM receipts').fetchone()[0],0)
        self.assertEqual(self.w.status()['pending_debit_units'],'60')

if __name__=='__main__':unittest.main()
