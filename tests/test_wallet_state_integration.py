"""Cross-version state restore checks; synthetic local ledger, not consensus."""
import unittest
import hashlib
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from block_application import snapshot
from native_core import NativeLedger, address, public, sign
from wallet_state import WalletState, restore_verified_state
from wallet_state_fixture import StateFixture


class WalletStateIntegrationTests(unittest.TestCase):
    def setUp(self):
        self.owner = Ed25519PrivateKey.from_private_bytes(b'\x71' * 32)
        self.merchant = Ed25519PrivateKey.from_private_bytes(b'\x72' * 32)
        self.agent = Ed25519PrivateKey.from_private_bytes(b'\x73' * 32)
        self.owner_id = address(public(self.owner))
        self.merchant_id = address(public(self.merchant))
        self.genesis = {
            'chain_id': '1soft-wallet-compat-dev', 'asset': 'DEV', 'fee': 2,
            'protocol_version': 3,
            'allocations': [
                {'public_key': public(self.owner), 'units': 1000},
                {'public_key': public(self.merchant), 'units': 0},
            ],
        }
        self.ledger = NativeLedger(':memory:', self.genesis)
        self._apply({'type': 'budget_create', 'id': 'project', 'cap': 100,
                     'expires': 90, 'recipients': [self.merchant_id]})
        self._apply({'type': 'grant', 'id': 'worker', 'public_key': public(self.agent),
                     'cap': 100, 'expires': 80, 'recipients': [self.merchant_id],
                     'budget_id': 'project'})

    def tearDown(self):
        self.ledger.close()

    def _apply(self, operation):
        nonce = self.ledger._account(self.owner_id)['nonce']
        self.ledger.apply(sign(self.owner, self.ledger.body(
            self.owner_id, nonce, operation)), height=1)

    def _state(self):
        return {'genesis': self.genesis, 'height': 1, 'native': snapshot(self.ledger)}

    def test_protocol_three_budget_and_binding_survive_restore(self):
        state = self._state()
        restored = restore_verified_state(state)
        try:
            self.assertEqual(snapshot(restored), state['native'])
            self.assertEqual(len(restored.state()['budgets']), 1)
            self.assertEqual(len(restored.state()['grant_budgets']), 1)
        finally:
            restored.close()

    def test_missing_budget_table_is_rejected(self):
        state = self._state()
        del state['native']['budgets']
        with self.assertRaises((ValueError, KeyError)):
            restore_verified_state(state)

    def test_v3_outbox_refuses_unsupported_shared_budget_reservations(self):
        fixture = StateFixture(self.genesis)
        try:
            with self.assertRaisesRegex(ValueError, 'protocol 3 budgets'):
                WalletState(Path('unused-wallet.sqlite'), fixture.raw,
                            hashlib.sha256(fixture.raw).hexdigest())
        finally:
            fixture.close()


if __name__ == '__main__':
    unittest.main()
