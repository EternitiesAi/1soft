"""Native commitment rules use real original ledger transitions and signatures."""
from contextlib import closing
import tempfile
import unittest

from block_application import restore, snapshot
from native_core import NativeLedger, Reject, address, public, sign
from protocol4_fixture import fixture, key


class InvoiceCommitmentNativeTests(unittest.TestCase):
    def setUp(self):
        self.genesis, self.keys, *_ = fixture()
        self.capable = dict(self.genesis, invoice_commitment_version=1)
        self.payer, self.recipient = [address(public(k)) for k in self.keys]

    def ledger(self):
        try:
            return NativeLedger(':memory:', self.capable)
        except Reject as exc:
            self.fail('fresh invoice capability must be supported: ' + str(exc))

    def body(self, ledger, *, commitment='a' * 64, grant='', nonce=0):
        op = {'type': 'transfer', 'to': self.recipient, 'units': 7}
        if commitment is not None:
            op['invoice_commitment'] = commitment
        return ledger.body(self.payer, nonce, op, grant_id=grant, valid_until=5)

    def test_fresh_capability_executes_committed_owner_payment(self):
        with closing(self.ledger()) as ledger:
            body = self.body(ledger)
            record = ledger.apply(sign(self.keys[0], body), height=1)
            self.assertEqual(record['envelope']['body']['op']['invoice_commitment'], 'a' * 64)
            self.assertEqual(ledger.balance(self.recipient), 100007)
            self.assertEqual(ledger.balance(self.payer), 99992)
            self.assertTrue(ledger.verify_receipts())

    def test_fresh_capability_keeps_plain_transfer_behavior(self):
        with closing(self.ledger()) as ledger:
            record = ledger.apply(sign(self.keys[0], self.body(ledger, commitment=None)), height=1)
            self.assertNotIn('invoice_commitment', record['envelope']['body']['op'])
            self.assertEqual(ledger.balance(self.payer), 99992)

    def test_old_p4_refuses_commitment_without_spending(self):
        with closing(NativeLedger(':memory:', self.genesis)) as ledger:
            before = snapshot(ledger)
            with self.assertRaises(Reject):
                ledger.apply(sign(self.keys[0], self.body(ledger)), height=1)
            self.assertEqual(snapshot(ledger), before)

    def test_commitment_substitution_invalidates_original_signature(self):
        with closing(self.ledger()) as ledger:
            packet = sign(self.keys[0], self.body(ledger))
            packet['body']['op']['invoice_commitment'] = 'b' * 64
            with self.assertRaisesRegex(Reject, 'bad signature'):
                ledger.apply(packet, height=1)
            self.assertEqual(ledger.balance(self.payer), 100000)

    def test_recovered_receipt_retains_commitment_and_exact_identity(self):
        with closing(self.ledger()) as ledger:
            packet = sign(self.keys[0], self.body(ledger))
            first = ledger.apply(packet, height=1)
            state = snapshot(ledger)
        with closing(restore(self.capable, state)) as recovered:
            self.assertEqual(recovered.apply(packet, height=2), first)
            self.assertEqual(recovered.balance(self.recipient), 100007)

    def test_changed_genesis_cannot_reuse_original_payment(self):
        with closing(self.ledger()) as ledger:
            packet = sign(self.keys[0], self.body(ledger))
        with closing(NativeLedger(':memory:', self.genesis)) as original:
            with self.assertRaisesRegex(Reject, 'wrong chain or genesis'):
                original.apply(packet, height=1)

    def test_flag_rejects_boolean_unknown_and_legacy_protocol(self):
        for version in (True, False, 0, 2, '1', None):
            with self.subTest(version=version), self.assertRaises(Reject):
                NativeLedger(':memory:', dict(self.genesis, invoice_commitment_version=version))
        for version in (1, 2, 3):
            g = {k: v for k, v in self.genesis.items() if k != 'validator_registry'}
            g.update(protocol_version=version, invoice_commitment_version=1)
            with self.subTest(protocol=version), self.assertRaises(Reject):
                NativeLedger(':memory:', g)

    def test_malformed_hash_and_unknown_fields_refuse_atomically(self):
        with closing(self.ledger()) as ledger:
            before = snapshot(ledger)
            for value in ('', 'a' * 63, 'A' * 64, 'g' * 64, None, 1, True):
                body = self.body(ledger)
                body['op']['invoice_commitment'] = value
                with self.subTest(value=value), self.assertRaises(Reject):
                    ledger.apply(sign(self.keys[0], body), height=1)
                self.assertEqual(snapshot(ledger), before)
            body = self.body(ledger); body['op']['extra'] = 'unapproved'
            with self.assertRaises(Reject):
                ledger.apply(sign(self.keys[0], body), height=1)
            self.assertEqual(snapshot(ledger), before)

    def test_delegated_commitment_uses_original_shared_budget(self):
        with closing(self.ledger()) as ledger:
            budget = {'type': 'budget_create', 'id': 'shop', 'cap': 10, 'expires': 5,
                      'recipients': [self.recipient]}
            ledger.apply(sign(self.keys[0], ledger.body(self.payer, 0, budget)), height=1)
            grant = {'type': 'grant', 'id': 'raven', 'public_key': public(key(8)),
                     'cap': 10, 'expires': 5, 'recipients': [self.recipient], 'budget_id': 'shop'}
            ledger.apply(sign(self.keys[0], ledger.body(self.payer, 1, grant)), height=1)
            packet = sign(key(8), self.body(ledger, grant='raven'))
            ledger.apply(packet, height=2)
            row = ledger.db.execute('SELECT spent FROM budgets').fetchone()
            self.assertEqual(row['spent'], 8)
            self.assertEqual(ledger.balance(self.recipient), 100007)
            with self.assertRaises(Reject):
                ledger.apply(sign(key(8), self.body(ledger, grant='raven', nonce=1)), height=3)
            self.assertEqual(ledger.db.execute('SELECT spent FROM budgets').fetchone()['spent'], 8)


if __name__ == '__main__':
    unittest.main()
