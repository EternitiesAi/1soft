"""Fresh-genesis money and registry authority are separate and exact."""
from __future__ import annotations

import hashlib
from pathlib import Path
import sys
import tempfile
import unittest

from certified_wallet import CertifiedWallet
from commit_verifier import VerificationError, encode, trust_from_genesis
from native_core import NativeLedger, Reject, address, digest, public, sign
from offline_signer import approve_intent, review_intent
from protocol4_fixture import fixture
from registry_rules_core import RegistryRules, RegistryReject


class Protocol4CoreTests(unittest.TestCase):
    def setUp(self):
        self.genesis, self.payers, self.admins, self.validators, self.target = fixture()

    def registry_wire(self, rules, state):
        body = rules.body(state, {'kind': 'schedule', 'emitted_height': 4,
                                  'target_validators': self.target}, valid_from=1, valid_until=3)
        message = rules.signing_bytes(body)
        approvals = sorted(({'public_key': public(k), 'signature': k.sign(message).hex()}
                            for k in self.admins[:3]), key=lambda row: row['public_key'])
        return encode({'body': body, 'approvals': approvals})

    def test_payment_binds_full_fresh_protocol4_genesis(self):
        with tempfile.TemporaryDirectory() as temp:
            ledger = NativeLedger(f'{temp}/one.sqlite', self.genesis)
            try:
                sender, receiver = [address(public(k)) for k in self.payers]
                body = ledger.body(sender, 0, {'type': 'transfer', 'to': receiver, 'units': 7},
                                   valid_until=5)
                receipt = ledger.apply(sign(self.payers[0], body), height=1)
                self.assertEqual(receipt['envelope']['body']['version'], 4)
                self.assertEqual(body['genesis_hash'], digest(self.genesis))
                self.assertEqual(ledger.balance(receiver), 100_007)
                self.assertTrue(ledger.verify_receipts())
                changed = dict(self.genesis, fee=2)
                other = NativeLedger(f'{temp}/other.sqlite', changed)
                try:
                    with self.assertRaisesRegex(Reject, 'wrong chain or genesis'):
                        other.apply(sign(self.payers[0], body), height=1)
                finally:
                    other.close()
            finally:
                ledger.close()

    def test_registry_admin_signatures_bind_full_protocol4_genesis(self):
        rules = RegistryRules(self.genesis['validator_registry'],
                              bound_genesis_sha256=digest(self.genesis))
        state = rules.initial_state()
        wire = self.registry_wire(rules, state)
        advanced, result = rules.transition(state, [wire], 1)
        self.assertEqual(result['tx_results'][0]['code'], 0)
        self.assertEqual(advanced['pending']['emitted_height'], 4)
        different = RegistryRules(self.genesis['validator_registry'],
                                  bound_genesis_sha256='f' * 64)
        with self.assertRaises(RegistryReject):
            different.authorize(wire)

    def test_legacy_static_trust_and_wallet_refuse_protocol4_before_journal(self):
        engine = {'chain_id': self.genesis['chain_id'], 'initial_height': '1',
                  'validators': [{}], 'app_state': self.genesis}
        with self.assertRaisesRegex(VerificationError, 'refuses dynamic protocol'):
            trust_from_genesis(engine)
        raw = encode(engine)
        policy = {'schema': 1, 'genesis_sha256': hashlib.sha256(raw).hexdigest(),
                  'trust_expires_utc': '2030-01-01T00:00:00Z',
                  'minimum_header_height': 1, 'maximum_age_seconds': 60,
                  'future_skew_seconds': 0}
        with tempfile.TemporaryDirectory() as temp:
            journal = Path(temp) / 'wallet.sqlite'
            with self.assertRaisesRegex(VerificationError, 'refuses dynamic protocol'):
                CertifiedWallet(journal, raw, policy)
            self.assertFalse(journal.exists())
        with self.assertRaisesRegex(Reject, 'refuses protocol 4'):
            review_intent(self.genesis, {}, public(self.payers[0]))
        with self.assertRaisesRegex(Reject, 'refuses protocol 4'):
            approve_intent(Path('/nonexistent/vault'), b'wrong', self.genesis,
                           {}, public(self.payers[0]), '0' * 64)

        root = Path(__file__).resolve().parents[1]
        sys.path.insert(0, str(root / 'tools/explorer/src'))
        sys.path.insert(0, str(root / 'tools/receipt-archive/src'))
        try:
            from explorer_index import ExplorerIndex
            from receipt_archive import ReceiptArchive
            with tempfile.TemporaryDirectory() as temp:
                explorer = Path(temp) / 'explorer.sqlite'
                archive = Path(temp) / 'archive.sqlite'
                with self.assertRaisesRegex(VerificationError, 'refuses dynamic protocol'):
                    ExplorerIndex(explorer, raw, policy['genesis_sha256'], create=True)
                with self.assertRaisesRegex(VerificationError, 'refuses dynamic protocol'):
                    ReceiptArchive(archive, raw, policy['genesis_sha256'], create=True)
                self.assertFalse(explorer.exists())
                self.assertFalse(archive.exists())
        finally:
            sys.path.pop(0)
            sys.path.pop(0)


if __name__ == '__main__':
    unittest.main()
