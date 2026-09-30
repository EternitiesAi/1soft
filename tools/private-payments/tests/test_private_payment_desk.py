"""Real journals/RPC fixture with synthetic signatures, not consensus evidence."""
from dataclasses import replace
import hashlib
from pathlib import Path
import shutil
import tempfile
import unittest
from unittest.mock import patch
from block_application import encode
from delivery_fixture import Fixture
from wallet_fixture import PASSWORD
from invoice_book import initialize_invoice_storage, open_invoice_storage
from payment_x402 import NativePaymentExpectation, make_payment_required
from platform_service import PlatformService
try:
    from private_payment_desk import PrivatePaymentDesk
except ImportError:
    PrivatePaymentDesk = None

INVOICE_PASSWORD = b'only-invoice-data-vault-passphrase'
PRIVATE_DATA = {'description': 'Secret client brief', 'contact': 'client@example.invalid',
                'content': 'Negotiated scope and contact details.'}


class PrivateDeskTests(unittest.TestCase):
    def setUp(self):
        self.assertIsNotNone(PrivatePaymentDesk, 'private payment caller integration is missing')
        self.tmp = tempfile.TemporaryDirectory(); self.root = Path(self.tmp.name); self.root.chmod(0o700)
        self.addCleanup(self.tmp.cleanup)
        node = self.root / 'fixture'; node.mkdir(mode=0o700)
        self.fx = Fixture(node, mode='normal'); self.addCleanup(self.fx.close)
        self.workspace = self.root / 'platform'; self.workspace.mkdir(mode=0o700)
        for role in ('owner', 'raven', 'atlas'):
            shutil.copyfile(node / (role + '.pem'), self.workspace / (role + '.pem'))
            (self.workspace / (role + '.pem')).chmod(0o600)
        c = self.fx.chain
        self.roles = {name: dict(payer=c.payer, grant_id='' if name == 'owner' else name,
                     vault=name + '.pem') for name in ('owner', 'raven', 'atlas')}
        self.service = self.open_service(create=True); self.addCleanup(lambda: self.service.close())
        self.service.import_checkpoint(self.fx.proof, expected_tip=None)
        self.service.sync(expected_revision=None)
        self.storage = self.root / 'invoices'
        initialize_invoice_storage(self.storage, c.policy['genesis_sha256'], password=INVOICE_PASSWORD, clock=c.clock)
        self.book = open_invoice_storage(self.storage, c.policy['genesis_sha256'], clock=c.clock)
        self.addCleanup(lambda: self.book.close())
        self.desk = PrivatePaymentDesk(self.service, self.book)
        self.expected = NativePaymentExpectation('https://merchant.example', 'https://merchant.example/report',
            '1soft:local-test', '1soft:DEV', c.policy['genesis_sha256'], c.merchant, '12')
        self.header = make_payment_required(self.expected, created_ns=c.now,
            expires_ns=c.now + 600 * 10**9, quote_nonce='d' * 64)

    def open_service(self, **kwargs):
        c = self.fx.chain
        return PlatformService(self.workspace, c.genesis, c.policy, self.fx.url, self.roles, clock=c.clock, **kwargs)

    def imported(self):
        return self.desk.import_invoice(self.header, self.expected, PRIVATE_DATA,
                                        invoice_password=INVOICE_PASSWORD)['request_id']

    def sign(self, rid):
        review = self.desk.prepare(rid, 'raven', valid_until=30)
        return self.desk.approve(rid, 'raven', review['review'], review['confirmation'],
            review['terms_confirmation'], payment_password=PASSWORD)

    def test_import_encrypts_content_and_keeps_financial_journals_untouched(self):
        before = self.service.wallet.db.execute('SELECT * FROM decisions').fetchall()
        with patch('p4_wallet._load_vault', side_effect=AssertionError('payment key accessed')):
            rid = self.imported()
        self.assertEqual(before, self.service.wallet.db.execute('SELECT * FROM decisions').fetchall())
        self.assertEqual([], self.fx.submissions)
        self.assertIsNone(self.service.book.selected(rid)['decision_id'])
        self.assertEqual(PRIVATE_DATA, self.desk.open_invoice(rid, invoice_password=INVOICE_PASSWORD))
        self.assertNotIn(PRIVATE_DATA['description'].encode(), encode(self.service.state()))

    def test_terms_review_binds_resource_and_native_confirmation_before_key_access(self):
        rid = self.imported(); review = self.desk.prepare(rid, 'raven', valid_until=30)
        self.assertEqual('https://merchant.example/report', review['terms']['resource_url'])
        self.assertEqual('12', review['terms']['amount_units'])
        self.assertEqual('14', review['review']['debit_units'])
        with patch('p4_wallet._load_vault', side_effect=AssertionError('payment key accessed')):
            with self.assertRaises(ValueError): self.desk.approve(rid, 'raven', review['review'],
                review['confirmation'], '0' * 64, payment_password=PASSWORD)
        self.assertIsNone(self.service.book.selected(rid)['decision_id'])
        self.assertEqual('0', self.service.state()['wallet']['pending_debit_units'])

    def test_signing_uses_original_shared_journal_and_recovery_uses_no_key(self):
        rid = self.imported(); self.sign(rid); original = self.desk.recover(rid)
        self.assertEqual('14', self.service.state()['wallet']['pending_debit_units'])
        self.service.close(); self.service = self.open_service(); self.book.close()
        self.book = open_invoice_storage(self.storage, self.fx.chain.policy['genesis_sha256'], clock=self.fx.chain.clock)
        self.desk = PrivatePaymentDesk(self.service, self.book)
        with patch('p4_wallet._load_vault', side_effect=AssertionError('resign')):
            self.assertEqual(original, self.desk.recover(rid))
        self.assertEqual('14', self.service.state()['wallet']['pending_debit_units'])

    def test_changed_canonical_request_blocks_review_before_any_signature(self):
        rid = self.imported()
        self.service.book.db.execute('UPDATE requests SET payload=? WHERE id=?', (b'{}', rid))
        with patch('p4_wallet._load_vault', side_effect=AssertionError('payment key accessed')):
            with self.assertRaises(ValueError): self.desk.prepare(rid, 'raven', valid_until=30)

    def test_import_is_recoverable_after_unsigned_request_retention_failure(self):
        with patch.object(self.service, 'add_request', side_effect=OSError('retention interrupted')):
            with self.assertRaises(OSError): self.imported()
        row = self.book.entries()[0]; envelope = self.book.envelope(row['request_id'])
        rid = self.imported()
        self.assertEqual(envelope, self.book.envelope(rid))
        self.assertIsNone(self.service.book.selected(rid)['decision_id'])
        self.assertEqual('0', self.service.state()['wallet']['pending_debit_units'])

    def test_unknown_submission_does_not_pay_or_release_the_hold(self):
        rid = self.imported(); self.sign(rid); self.fx.mode = 'admit_only'
        review = self.desk.submission_review(rid)
        result = self.desk.submit(rid, review['review'], review['confirmation'])
        self.assertFalse(result['execution_proven'])
        self.assertEqual('unavailable', self.desk.collect(rid)['status'])
        self.assertEqual('14', self.service.state()['wallet']['pending_debit_units'])
        with self.assertRaises(ValueError): self.desk.submission_review(rid)
        with self.assertRaises(ValueError): self.desk.payment_header(rid, '0' * 64)
        self.assertEqual(1, len(self.fx.submissions))

    def test_receipt_header_and_archive_never_reconcile_funds(self):
        rid = self.imported(); self.sign(rid)
        review = self.desk.submission_review(rid); self.desk.submit(rid, review['review'], review['confirmation'])
        self.desk.collect(rid); retained = self.desk.retain_receipt(rid)
        result = self.desk.payment_header(rid, retained['capsule_id'])
        self.assertTrue(result['payment_signature_header'])
        self.assertFalse(result['resource_delivery_authorized'])
        self.assertTrue(result['full_public_ledger_disclosed'])
        self.assertEqual('14', self.service.state()['wallet']['pending_debit_units'])
        self.desk.reconcile(rid, expected_revision=self.service.state()['wallet']['revision'])
        self.assertEqual('0', self.service.state()['wallet']['pending_debit_units'])

    def test_quote_expiry_prevents_new_submit_but_preserves_original_and_invoice(self):
        rid = self.imported(); self.sign(rid); original = self.desk.recover(rid)
        self.fx.chain.now += 601 * 10**9
        with self.assertRaises(ValueError): self.desk.submission_review(rid)
        self.assertEqual(original, self.desk.recover(rid))
        self.assertEqual(PRIVATE_DATA, self.desk.open_invoice(rid, invoice_password=INVOICE_PASSWORD))
        self.assertEqual('14', self.service.state()['wallet']['pending_debit_units'])


if __name__ == '__main__': unittest.main()
