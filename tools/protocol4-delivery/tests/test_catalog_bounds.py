"""Local damaged journals must not erase ambiguity through dictionary overwrite."""
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from delivery_fixture import Fixture
from p4_delivery import MAX_ATTEMPTS, MAX_RECEIPTS


class CatalogBoundsTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.f = Fixture(Path(self.tmp.name))
        self.addCleanup(self.f.close)
        self.did = self.f.sign()

    def loosen_and_copy(self, table, count):
        # Alter only this disposable fixture. Preserve valid original BLOBs and
        # sequence order so the test detects ambiguity, not a bad signature.
        columns = {
            'attempts': 'seq INTEGER, decision_id TEXT, claimed_ns INTEGER, review BLOB',
            'responses': 'decision_id TEXT, observed_ns INTEGER, payload BLOB',
            'receipts': 'seq INTEGER, decision_id TEXT, evidence_id TEXT, checked_ns INTEGER, payload BLOB',
        }
        db = self.f.delivery.db
        original = db.execute('SELECT * FROM ' + table).fetchone()
        self.assertIsNotNone(original)
        with self.f.delivery.atomic():
            db.execute('DROP TABLE ' + table)
            db.execute('CREATE TABLE ' + table + '(' + columns[table] + ')')
            for n in range(count):
                row = list(original)
                if table != 'responses':
                    row[0] = n + 1
                db.execute('INSERT INTO ' + table + ' VALUES (' +
                           ','.join('?' for _ in row) + ')', row)

    def refused_without_side_effects(self, reason):
        wallet = list(self.f.wallet.db.iterdump())
        delivery = list(self.f.delivery.db.iterdump())
        sent = list(self.f.submissions)
        reads = list(self.f.reads)
        with self.assertRaisesRegex(ValueError, reason):
            self.f.delivery.inspect(self.did, **self.f.selection())
        self.assertEqual(list(self.f.wallet.db.iterdump()), wallet)
        self.assertEqual(list(self.f.delivery.db.iterdump()), delivery)
        self.assertEqual(self.f.submissions, sent)
        self.assertEqual(self.f.reads, reads)
        self.assertEqual(self.f.held(), 60)

    def test_duplicate_attempt_cannot_overwrite_first_claim(self):
        self.f.mode = 'admit_only'
        self.f.send(self.did)
        self.loosen_and_copy('attempts', 2)
        self.refused_without_side_effects('duplicate delivery attempt')

    def test_duplicate_response_cannot_overwrite_first_observation(self):
        self.f.mode = 'admit_only'
        self.f.send(self.did)
        self.loosen_and_copy('responses', 2)
        self.refused_without_side_effects('duplicate endpoint response')

    def test_duplicate_receipt_cannot_overwrite_first_proof(self):
        self.f.send(self.did)
        self.f.delivery.collect(self.did, **self.f.selection())
        self.loosen_and_copy('receipts', 2)
        self.refused_without_side_effects('duplicate delivery receipt')

    def test_response_capacity_refused_before_parsing_any_response(self):
        self.f.mode = 'admit_only'
        self.f.send(self.did)
        self.loosen_and_copy('responses', MAX_ATTEMPTS + 1)
        # Wallet auditing imports its own decoder; this guards the delivery
        # decoder specifically, after the unchanged wallet checks.
        with patch('p4_delivery.observation', side_effect=AssertionError('parsed over-cap response')):
            self.refused_without_side_effects('endpoint response capacity exceeded')

    def test_attempt_capacity_refused_before_replaying_any_attempt(self):
        self.f.mode = 'admit_only'
        self.f.send(self.did)
        self.loosen_and_copy('attempts', MAX_ATTEMPTS + 1)
        with patch('p4_delivery.verify_evidence', side_effect=AssertionError('replayed over-cap attempt')):
            self.refused_without_side_effects('delivery attempt capacity exceeded')

    def test_receipt_capacity_refused_before_replaying_any_receipt(self):
        self.f.send(self.did)
        self.f.delivery.collect(self.did, **self.f.selection())
        self.loosen_and_copy('receipts', MAX_RECEIPTS + 1)
        # The valid attempt is checked first; the receipt decoder must never
        # reach the duplicated over-cap receipts.
        with patch('p4_delivery.extends', side_effect=AssertionError('replayed over-cap receipt')):
            self.refused_without_side_effects('receipt storage limit exceeded')


if __name__ == '__main__':
    unittest.main()
