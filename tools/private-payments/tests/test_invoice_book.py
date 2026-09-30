"""Encrypted invoice persistence and trusted caller boundaries, no consensus."""
from dataclasses import asdict
import hashlib
import json
from pathlib import Path
import sqlite3
import tempfile
import unittest

from native_core import address
from offline_signer import create_vault
from payment_x402 import NativePaymentExpectation, make_payment_required, parse_payment_required
try:
    from invoice_book import InvoiceBook, initialize_invoice_storage, open_invoice_storage
except ImportError:
    InvoiceBook = initialize_invoice_storage = open_invoice_storage = None

PASSWORD = b'private-invoice-only-test-passphrase'
CONTENT = {'description': 'Confidential client project', 'contact': 'private@example.invalid',
           'content': 'A privately negotiated creative brief.'}


class InvoiceBookTests(unittest.TestCase):
    def setUp(self):
        self.assertIsNotNone(InvoiceBook, 'encrypted invoice persistence is missing')
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name); self.root.chmod(0o700)
        self.genesis = 'a' * 64; self.now = 1_900_000_000 * 10**9
        self.expectation = NativePaymentExpectation('https://merchant.example',
            'https://merchant.example/report', '1soft:local-test', '1soft:DEV', self.genesis,
            'lab_' + 'b' * 64, '12')
        self.header = make_payment_required(self.expectation, created_ns=self.now,
            expires_ns=self.now + 600 * 10**9, quote_nonce='c' * 64)
        self.storage = self.root / 'private-invoices'
        initialize_invoice_storage(self.storage, self.genesis, password=PASSWORD, clock=self.clock)
        self.book = self.open(); self.addCleanup(lambda: self.book.close())

    def clock(self): return self.now
    def open(self): return open_invoice_storage(self.storage, self.genesis, clock=self.clock)
    def retain(self, **overrides):
        args = dict(required_header=self.header, expectation=self.expectation,
                    content=dict(CONTENT), password=PASSWORD)
        args.update(overrides); return self.book.retain(**args)

    def test_storage_uses_a_separate_encrypted_vault_not_a_payment_key(self):
        owner = create_vault(self.root / 'owner.pem', PASSWORD)
        self.assertNotEqual(owner, self.book.invoice_key_public)
        self.assertNotEqual(address(owner), address(self.book.invoice_key_public))
        raw = (self.storage / 'invoice-data.pem').read_bytes()
        self.assertTrue(raw.startswith(b'-----BEGIN ENCRYPTED PRIVATE KEY-----'))
        with self.assertRaises(ValueError): self.retain(password=b'an incorrect password')
        self.assertEqual([], self.book.entries())

    def test_encrypted_content_roundtrip_and_no_plaintext_in_persisted_files(self):
        row = self.retain(); rid = row['request_id']
        self.assertEqual(CONTENT, self.book.decrypt(rid, password=PASSWORD))
        self.assertFalse(row['onchain_privacy']); self.assertFalse(row['execution_proven'])
        for file in self.storage.iterdir():
            if file.is_file():
                for value in CONTENT.values(): self.assertNotIn(value.encode(), file.read_bytes())
        self.assertNotIn('content', self.book.selected(rid))
        self.assertEqual('12', self.book.selected(rid)['request']['units'])

    def test_duplicate_import_retains_the_original_ciphertext(self):
        row = self.retain(); original = self.book.envelope(row['request_id'])
        self.assertEqual('already_retained', self.retain()['status'])
        self.assertEqual(original, self.book.envelope(row['request_id']))
        changed = dict(CONTENT); changed['description'] = 'Replacement'
        with self.assertRaises(ValueError): self.retain(content=changed)
        self.assertEqual(original, self.book.envelope(row['request_id']))

    def test_restart_recovers_exact_envelope_and_existing_key(self):
        row = self.retain(); original = self.book.envelope(row['request_id'])
        key_file = (self.storage / 'invoice-data.pem').read_bytes()
        self.book.close(); self.book = self.open()
        self.assertEqual(original, self.book.envelope(row['request_id']))
        self.assertEqual(CONTENT, self.book.decrypt(row['request_id'], password=PASSWORD))
        self.assertEqual(key_file, (self.storage / 'invoice-data.pem').read_bytes())

    def test_initialization_never_overwrites_existing_or_partial_storage(self):
        before = {p.name: p.read_bytes() for p in self.storage.iterdir() if p.is_file()}
        with self.assertRaises(ValueError):
            initialize_invoice_storage(self.storage, self.genesis, password=PASSWORD, clock=self.clock)
        self.assertEqual(before, {p.name: p.read_bytes() for p in self.storage.iterdir() if p.is_file()})
        partial = self.root / 'partial'; partial.mkdir(mode=0o700)
        with self.assertRaises(ValueError):
            initialize_invoice_storage(partial, self.genesis, password=PASSWORD, clock=self.clock)

    def test_wrong_genesis_or_key_identity_cannot_open_existing_storage(self):
        self.retain(); self.book.close()
        with self.assertRaises(ValueError): open_invoice_storage(self.storage, 'd' * 64, clock=self.clock)
        # Owned test fixture replacement: production has no replace/reset API.
        other = self.root / 'different.pem'; create_vault(other, PASSWORD)
        (self.storage / 'invoice-data.pem').write_bytes(other.read_bytes())
        with self.assertRaises(ValueError): self.open()

    def test_expired_quote_cannot_be_imported_but_original_invoice_stays_readable(self):
        row = self.retain(); self.now += 601 * 10**9
        with self.assertRaises(ValueError): self.retain()
        self.assertEqual(CONTENT, self.book.decrypt(row['request_id'], password=PASSWORD))
        self.assertEqual('12', self.book.selected(row['request_id'])['request']['units'])

    def test_clock_rollback_refuses_new_import_without_changing_saved_invoice(self):
        row = self.retain(); original = self.book.envelope(row['request_id'])
        self.now -= 1
        with self.assertRaises(ValueError): self.retain()
        self.assertEqual(original, self.book.envelope(row['request_id']))

    def test_ciphertext_or_request_tampering_never_returns_plaintext(self):
        row = self.retain(); rid = row['request_id']
        packet = json.loads(self.book.envelope(rid)); packet['ciphertext_b64'] = 'A' * len(packet['ciphertext_b64'])
        raw = json.dumps(packet, sort_keys=True, separators=(',', ':')).encode()
        self.book.db.execute('UPDATE invoices SET envelope=? WHERE request_id=?', (raw, rid))
        with self.assertRaises(ValueError): self.book.decrypt(rid, password=PASSWORD)

    def test_file_aliases_and_nonprivate_storage_are_refused(self):
        self.book.close(); database = self.storage / 'invoices.sqlite'
        database.chmod(0o644)
        with self.assertRaises(ValueError): self.open()
        database.chmod(0o600)
        alias = self.root / 'alias'; alias.symlink_to(self.storage, target_is_directory=True)
        with self.assertRaises((ValueError, OSError)):
            open_invoice_storage(alias, self.genesis, clock=self.clock)

    def test_live_offer_pins_are_checked_before_vault_unlock_or_database_write(self):
        different = NativePaymentExpectation(self.expectation.merchant_origin,
            self.expectation.resource_url, self.expectation.network, self.expectation.asset,
            self.genesis, self.expectation.recipient, '13')
        with self.assertRaises(ValueError): self.retain(expectation=different, password=b'ignored')
        self.assertEqual([], self.book.entries())

    def test_rehashed_structurally_incomplete_packet_is_not_presented_as_encrypted(self):
        row = self.retain(); rid = row['request_id']
        raw = json.dumps({'genesis_sha256': self.genesis, 'request_sha256': rid},
                         sort_keys=True, separators=(',', ':')).encode()
        self.book.db.execute('UPDATE invoices SET envelope=?,envelope_sha256=? WHERE request_id=?',
                             (raw, hashlib.sha256(raw).hexdigest(), rid))
        with self.assertRaises(ValueError): self.book.selected(rid)

    def test_slow_unlock_cannot_retain_a_quote_after_its_expiry(self):
        original_unlock = self.book._key
        def delayed_unlock(password):
            key = original_unlock(password); self.now += 601 * 10**9; return key
        from unittest.mock import patch
        with patch.object(self.book, '_key', side_effect=delayed_unlock):
            with self.assertRaises(ValueError): self.retain()
        self.assertEqual([], self.book.entries())

    def test_invoice_uniqueness_constraints_cannot_be_removed_silently(self):
        self.book.db.execute('DROP TABLE invoices')
        self.book.db.execute('CREATE TABLE invoices(request_id TEXT,quote_id TEXT,required_header TEXT NOT NULL,expectation BLOB NOT NULL,request BLOB NOT NULL,envelope BLOB NOT NULL,envelope_sha256 TEXT NOT NULL)')
        with self.assertRaises(ValueError): self.book.entries()

    def test_extra_database_trigger_is_refused_before_retention(self):
        self.book.db.execute('CREATE TRIGGER changed AFTER INSERT ON invoices BEGIN DELETE FROM invoices; END')
        with self.assertRaises(ValueError): self.book.entries()


if __name__ == '__main__': unittest.main()
