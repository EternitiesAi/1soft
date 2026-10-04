"""Forked-device qualification: local journals do not provide coordination."""
import sqlite3
import tempfile
import unittest
from pathlib import Path
from cryptography.hazmat.primitives import serialization as ser
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from block_application import restore
from native_core import canonical, public
from p4_wallet import P4Wallet
from wallet_fixture import Chain, PASSWORD


class ForkedDeviceSecurityTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.chain = Chain(self.root)
        self.addCleanup(self.chain.close)
        self.source = self.root / 'source.sqlite'
        with P4Wallet(self.source, self.chain.genesis, self.chain.policy,
                      create=True, clock=self.chain.clock) as wallet:
            wallet.sync(self.chain.evidence(), expected_revision=None)

    def clone_wallet(self, name):
        target = self.root / f'{name}.sqlite'
        # Use SQLite's online backup API so the clone is a complete database,
        # independent of WAL sidecar timing. This models an uncoordinated
        # device restore, not a supported live replication mechanism.
        with sqlite3.connect(self.source) as source, sqlite3.connect(target) as copy:
            source.backup(copy)
        target.chmod(0o600)
        return target

    def approve(self, path, role, units):
        with P4Wallet(path, self.chain.genesis, self.chain.policy, clock=self.chain.clock) as wallet:
            review = wallet.prepare(payer=self.chain.payer, recipient=self.chain.merchant,
                                    units=units, grant_id=role, valid_until=30)
            result = wallet.approve(review['review'], review['confirmation'],
                                   vault=self.root / f'{role}.pem', password=PASSWORD)
            status = wallet.status()
            return result, status

    def test_two_cloned_journals_can_sign_different_same_nonce_wires_locally(self):
        device_a = self.clone_wallet('device-a')
        device_b = self.clone_wallet('device-b')
        first, status_a = self.approve(device_a, 'raven', 10)
        second, status_b = self.approve(device_b, 'raven', 11)

        self.assertEqual(first['transaction']['body']['nonce'],
                         second['transaction']['body']['nonce'])
        self.assertNotEqual(canonical(first['transaction']), canonical(second['transaction']))
        self.assertEqual(status_a['pending_debit_units'], '12')
        self.assertEqual(status_b['pending_debit_units'], '13')
        self.assertEqual(status_a['coordination_scope'], 'this local journal only')
        self.assertEqual(status_b['coordination_scope'], 'this local journal only')

        # The native grant nonce is the chain-level collision boundary. One
        # wire can win at the next height; the other cannot be applied there.
        ledger = restore(self.chain.g, self.chain.app.state['native'])
        try:
            recipient_before = ledger.balance(self.chain.merchant)
            ledger.apply(first['transaction'], height=self.chain.app.height + 1)
            self.assertEqual(ledger.balance(self.chain.merchant), recipient_before + 10)
            grant = ledger.db.execute(
                'SELECT nonce,spent FROM grants WHERE id=?',
                (ledger.grant_storage_id(self.chain.payer, 'raven'),),
            ).fetchone()
            self.assertEqual(tuple(grant), (1, 12))
            state_after_winner = ledger.state_hash()
            with self.assertRaises(ValueError):
                ledger.apply(second['transaction'], height=self.chain.app.height + 1)
            self.assertEqual(ledger.state_hash(), state_after_winner)
            self.assertEqual(ledger.balance(self.chain.merchant), recipient_before + 10)
        finally:
            ledger.close()

        # Neither local copy is allowed to infer the losing outcome. It stays
        # reserved until an exact authenticated receipt is imported.
        with P4Wallet(device_b, self.chain.genesis, self.chain.policy,
                      clock=self.chain.clock) as wallet_b:
            self.assertEqual(wallet_b.status()['decisions'][0]['status'], 'pending')
            self.assertEqual(wallet_b.recover(second['decision_id'],
                                               payer=self.chain.payer,
                                               grant_id='raven'),
                             canonical(second['transaction']))

    def test_old_clone_is_not_fenced_by_rotation_until_it_observes_chain_state(self):
        stale = self.clone_wallet('stale-device')
        replacement = Ed25519PrivateKey.from_private_bytes(b'\xa3' * 32)
        replacement_vault = self.root / 'replacement.pem'
        replacement_vault.write_bytes(replacement.private_bytes(
            ser.Encoding.PEM, ser.PrivateFormat.PKCS8,
            ser.BestAvailableEncryption(PASSWORD)))
        replacement_vault.chmod(0o600)
        with P4Wallet(self.source, self.chain.genesis, self.chain.policy,
                      clock=self.chain.clock) as wallet:
            review = wallet.prepare_rotation(payer=self.chain.payer,
                                             new_public_key=public(replacement),
                                             valid_until=30)
            accepted = wallet.accept_rotation(review['review'], review['confirmation'],
                                              incoming_vault=replacement_vault,
                                              password=PASSWORD)
            rotation = wallet.approve_rotation(accepted['review'], accepted['confirmation'],
                                               owner_vault=self.root / 'owner.pem',
                                               password=PASSWORD)

        self.chain.block([canonical(rotation['transaction'])])
        with P4Wallet(stale, self.chain.genesis, self.chain.policy,
                      clock=self.chain.clock) as old:
            # The old clone has no current checkpoint or device epoch. It can
            # still prepare and sign against its historical state; this is the
            # explicit unimplemented fencing boundary, not a security success.
            q = old.prepare(payer=self.chain.payer, recipient=self.chain.merchant,
                            units=1, grant_id='', valid_until=30)
            self.assertFalse(q['broadcast'])
            self.assertFalse(q['signed'])
            stale_wire = old.approve(q['review'], q['confirmation'],
                                     vault=self.root / 'owner.pem', password=PASSWORD)

        ledger = restore(self.chain.g, self.chain.app.state['native'])
        try:
            with self.assertRaises(ValueError):
                ledger.apply(stale_wire['transaction'], height=self.chain.app.height + 1)
        finally:
            ledger.close()


if __name__ == '__main__':
    unittest.main()
