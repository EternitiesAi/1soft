"""Authenticated audit evidence with real SMT proofs and disposable signatures.

These are local, synthetic static-validator certificates, not consensus evidence.
"""
import copy
from contextlib import closing
from pathlib import Path
import sqlite3
import tempfile
import unittest

import authenticated_reconciliation as reconciliation
from authenticated_reconciliation import reconcile_obligation
from block_application import transaction_id
from commit_verifier import encode, load_json, sha
from compact_verifier import verify_compact_witness
from native_core import canonical, public, sign
from state_tree import make_witness
from test_budget_integration import payment, setup_transactions
import test_compact_state as compact_state
from test_native_budgets import KEYS


class InsertFailureConnection(sqlite3.Connection):
    """Inject a failure after a real write, before the reconciliation commits."""
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.fail_insert = True

    def execute(self, sql, parameters=()):
        cursor = super().execute(sql, parameters)
        if self.fail_insert and sql.startswith('INSERT INTO authenticated_reconciliations'):
            self.fail_insert = False
            raise sqlite3.OperationalError('injected journal write failure')
        return cursor


class AuthenticatedReconciliationTests(unittest.TestCase):
    # Reuse only the compact fixture, without inheriting its test methods.
    block = compact_state.CompactStateTests.block
    certificate = compact_state.CompactStateTests.certificate
    witness = compact_state.CompactStateTests.witness

    def setUp(self):
        compact_state.CompactStateTests.setUp(self)
        self.journal = sqlite3.connect(':memory:')

    def tearDown(self):
        self.journal.close()
        compact_state.CompactStateTests.tearDown(self)

    def wire(self, valid_until=1000):
        body = load_json(payment(self.g, 0, 58))['body']
        body['valid_until'] = valid_until
        return canonical(sign(KEYS[2], body))

    def included_wire(self, valid_until=1000):
        self.block(setup_transactions(self.g))
        wire = self.wire(valid_until)
        result = self.block([wire])
        self.assertEqual(result['tx_results'][0]['code'], 0)
        return wire

    def reconcile(self, wire, *, witness=None, header=None, signer=None, journal=None):
        if witness is None:
            witness = self.witness([('receipts', transaction_id(wire))])
        return reconcile_obligation(
            witness, self.certificate() if header is None else header, self.trust,
            local_wire=wire, expected_signer=public(KEYS[2]) if signer is None else signer,
            journal=self.journal if journal is None else journal)

    def journal_snapshot(self, journal=None):
        return list((self.journal if journal is None else journal).iterdump())

    def altered_receipt(self, wire, *, record_changes=None, row_changes=None, record_value=None):
        """Attest an altered row so the real proof layer accepts the fixture.

        This models a quorum-attested row with bad receipt semantics; it never
        bypasses proof, header or signature verification with a mock.
        """
        state = load_json(self.app.query('/state')['value'])['native']
        txid = transaction_id(wire)
        row = next(row for row in state['receipts'] if row[0] == txid)
        record = load_json(row[3].encode())
        record.update(record_changes or {})
        if record_value is not None:
            record = record_value
        row[3] = encode(record).decode()
        row[4] = sha(encode(record)).hex()
        for index, value in (row_changes or {}).items():
            row[index] = value
        witness = make_witness(self.g, self.app.height, state, [('receipts', txid)])
        header = self.certificate(root=witness['app_hash'])
        checked = verify_compact_witness(
            witness, header, self.trust, expected_queries=[('receipts', txid)])
        self.assertEqual(checked['records'][0]['row'], row)
        return witness, header

    def test_inclusion_before_expiry_binds_exact_wire_and_replays(self):
        wire = self.included_wire(valid_until=3)
        first = self.reconcile(wire)
        second = self.reconcile(wire)
        self.assertEqual(first['status'], 'included')
        self.assertEqual(first['state_height'], 2)
        self.assertTrue(first['recorded'])
        self.assertFalse(first['replayed'])
        self.assertEqual(second, {**first, 'replayed': True})
        self.assertEqual(self.journal.execute(
            'SELECT count(*) FROM authenticated_reconciliations').fetchone()[0], 1)

    def test_inclusion_at_signed_validity_height_is_accepted(self):
        wire = self.included_wire(valid_until=2)
        self.assertEqual(self.reconcile(wire)['status'], 'included')

    def test_historical_inclusion_remains_included_after_expiry(self):
        wire = self.included_wire(valid_until=2)
        self.block([])
        result = self.reconcile(wire)
        self.assertEqual(result['status'], 'included')
        self.assertEqual(result['state_height'], 3)

    def test_authenticated_absence_strictly_after_expiry(self):
        wire = self.wire(valid_until=1)
        self.block([])
        self.block([])
        result = self.reconcile(wire)
        self.assertEqual(result['status'], 'absent_after_expiry')
        self.assertEqual(result['state_height'], 2)
        self.assertTrue(result['recorded'])
        self.assertFalse(result['replayed'])

    def test_absence_before_and_at_expiry_keeps_hold_without_journal_mutation(self):
        wire = self.wire(valid_until=1)
        for height in (0, 1):
            with self.subTest(height=height):
                before = self.journal_snapshot()
                with self.assertRaisesRegex(ValueError, 'not past validity'):
                    self.reconcile(wire)
                self.assertEqual(self.journal_snapshot(), before)
            self.block([])

    def test_forged_local_signature_rejected_despite_authenticated_absence(self):
        envelope = load_json(self.wire(valid_until=1))
        envelope['signature'] = '00' * 64
        wire = canonical(envelope)
        self.block([])
        self.block([])
        witness = self.witness([('receipts', transaction_id(wire))])
        checked = verify_compact_witness(
            witness, self.certificate(), self.trust,
            expected_queries=[('receipts', transaction_id(wire))])
        self.assertIsNone(checked['records'][0]['row'])
        before = self.journal_snapshot()
        with self.assertRaisesRegex(ValueError, 'invalid native receipt signature'):
            self.reconcile(wire, witness=witness)
        self.assertEqual(self.journal_snapshot(), before)

    def test_wrong_expected_signer_rejected_without_journal_mutation(self):
        wire = self.included_wire()
        before = self.journal_snapshot()
        with self.assertRaisesRegex(ValueError, 'invalid native receipt signature'):
            self.reconcile(wire, signer=public(KEYS[1]))
        self.assertEqual(self.journal_snapshot(), before)

    def test_receipt_proof_for_another_local_wire_rejected(self):
        wire = self.included_wire()
        witness = self.witness([('receipts', transaction_id(wire))])
        before = self.journal_snapshot()
        with self.assertRaisesRegex(ValueError, 'proof set differs'):
            self.reconcile(payment(self.g, 0, 57), witness=witness)
        self.assertEqual(self.journal_snapshot(), before)

    def test_unattested_receipt_digest_mutation_rejected_by_proof(self):
        wire = self.included_wire()
        witness = copy.deepcopy(self.witness([('receipts', transaction_id(wire))]))
        witness['entries'][0]['value'][4] = '00' * 32
        before = self.journal_snapshot()
        with self.assertRaisesRegex(ValueError, 'Merkle proof'):
            self.reconcile(wire, witness=witness)
        self.assertEqual(self.journal_snapshot(), before)

    def test_authenticated_receipt_digest_mismatch_rejected(self):
        wire = self.included_wire()
        witness, header = self.altered_receipt(wire, row_changes={4: '00' * 32})
        before = self.journal_snapshot()
        with self.assertRaisesRegex(ValueError, 'receipt record digest mismatch'):
            self.reconcile(wire, witness=witness, header=header)
        self.assertEqual(self.journal_snapshot(), before)

    def test_authenticated_receipt_signer_mismatch_rejected(self):
        wire = self.included_wire()
        witness, header = self.altered_receipt(
            wire, record_changes={'signer_public_key': public(KEYS[1])})
        with self.assertRaisesRegex(ValueError, 'receipt differs from local wire'):
            self.reconcile(wire, witness=witness, header=header)
        self.assertEqual(self.journal_snapshot(), ['BEGIN TRANSACTION;', 'COMMIT;'])

    def test_authenticated_receipt_txid_mismatch_rejected(self):
        wire = self.included_wire()
        witness, header = self.altered_receipt(wire, record_changes={'txid': '00' * 32})
        with self.assertRaisesRegex(ValueError, 'receipt differs from local wire'):
            self.reconcile(wire, witness=witness, header=header)

    def test_authenticated_receipt_envelope_mismatch_rejected(self):
        wire = self.included_wire()
        witness, header = self.altered_receipt(
            wire, record_changes={'envelope': load_json(payment(self.g, 0, 57))})
        with self.assertRaisesRegex(ValueError, 'receipt differs from local wire'):
            self.reconcile(wire, witness=witness, header=header)

    def test_authenticated_receipt_boolean_integer_alias_does_not_match_exact_wire(self):
        wire = self.included_wire()
        envelope = load_json(wire)
        envelope['body']['nonce'] = False
        witness, header = self.altered_receipt(wire, record_changes={'envelope': envelope})
        with self.assertRaisesRegex(ValueError, 'receipt differs from local wire'):
            self.reconcile(wire, witness=witness, header=header)

    def test_authenticated_receipt_height_after_signed_validity_rejected(self):
        wire = self.included_wire(valid_until=2)
        self.block([])
        witness, header = self.altered_receipt(wire, record_changes={'height': 3})
        with self.assertRaisesRegex(ValueError, 'receipt height'):
            self.reconcile(wire, witness=witness, header=header)

    def test_authenticated_receipt_height_after_checkpoint_rejected(self):
        wire = self.included_wire(valid_until=10)
        witness, header = self.altered_receipt(wire, record_changes={'height': 3})
        with self.assertRaisesRegex(ValueError, 'receipt height'):
            self.reconcile(wire, witness=witness, header=header)

    def test_authenticated_receipt_nonpositive_height_rejected(self):
        wire = self.included_wire()
        for height in (-1, 0):
            with self.subTest(height=height):
                witness, header = self.altered_receipt(wire, record_changes={'height': height})
                with self.assertRaisesRegex(ValueError, 'receipt height'):
                    self.reconcile(wire, witness=witness, header=header)

    def test_authenticated_receipt_noninteger_height_rejected(self):
        wire = self.included_wire()
        for height in (True, '2'):
            with self.subTest(height=height):
                witness, header = self.altered_receipt(wire, record_changes={'height': height})
                with self.assertRaisesRegex(ValueError, 'receipt height'):
                    self.reconcile(wire, witness=witness, header=header)

    def test_authenticated_receipt_record_must_be_an_object(self):
        wire = self.included_wire()
        witness, header = self.altered_receipt(wire, record_value=[])
        with self.assertRaisesRegex(ValueError, 'receipt record'):
            self.reconcile(wire, witness=witness, header=header)

    def test_authenticated_receipt_sequence_must_match_row(self):
        wire = self.included_wire()
        witness, header = self.altered_receipt(wire, record_changes={'sequence': 999})
        with self.assertRaisesRegex(ValueError, 'receipt sequence'):
            self.reconcile(wire, witness=witness, header=header)

    def test_authenticated_receipt_previous_digest_must_match_row(self):
        wire = self.included_wire()
        witness, header = self.altered_receipt(wire, record_changes={'previous': '00' * 32})
        with self.assertRaisesRegex(ValueError, 'receipt previous'):
            self.reconcile(wire, witness=witness, header=header)

    def test_invalid_witness_rejected_before_protocol_version_is_consumed(self):
        wire = self.wire()
        witness = self.witness([('receipts', transaction_id(wire))])
        del witness['genesis']
        with self.assertRaises(ValueError):
            self.reconcile(wire, witness=witness)
        self.assertEqual(self.journal_snapshot(), ['BEGIN TRANSACTION;', 'COMMIT;'])

    def assert_restart_replays(self, wire, **connection_options):
        witness = self.witness([('receipts', transaction_id(wire))])
        header = self.certificate()
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'reconciliation.sqlite'
            with closing(sqlite3.connect(path, **connection_options)) as db:
                first = self.reconcile(wire, witness=witness, header=header, journal=db)
                self.assertFalse(db.in_transaction)
            with closing(sqlite3.connect(path, **connection_options)) as db:
                second = self.reconcile(wire, witness=witness, header=header, journal=db)
                self.assertEqual(second, {**first, 'replayed': True})
                self.assertEqual(db.execute(
                    'SELECT count(*) FROM authenticated_reconciliations').fetchone()[0], 1)

    def test_restart_keeps_inclusion_replay_idempotent(self):
        self.assert_restart_replays(self.included_wire())

    def test_restart_keeps_expired_absence_replay_idempotent(self):
        wire = self.wire(valid_until=1)
        self.block([])
        self.block([])
        self.assert_restart_replays(wire)

    @unittest.skipUnless(hasattr(sqlite3.Connection, 'autocommit'), 'Python 3.12+ sqlite3 required')
    def test_autocommit_success_is_durable_and_replays_after_reopen(self):
        included = self.included_wire()
        absent = self.wire(valid_until=1)
        for wire in (included, absent):
            with self.subTest(txid=transaction_id(wire)):
                self.assert_restart_replays(wire, autocommit=True)

    def test_already_open_transaction_rejected_before_schema_creation(self):
        wire = self.included_wire()
        self.journal.execute('BEGIN IMMEDIATE')
        before = self.journal_snapshot()
        with self.assertRaisesRegex(ValueError, 'already in transaction'):
            self.reconcile(wire)
        self.assertTrue(self.journal.in_transaction)
        self.assertEqual(self.journal_snapshot(), before)

    def test_already_open_transaction_preserves_callers_pending_changes(self):
        wire = self.included_wire()
        self.journal.execute('CREATE TABLE caller_changes (value INTEGER)')
        self.journal.execute('INSERT INTO caller_changes VALUES (7)')
        before = self.journal_snapshot()
        with self.assertRaisesRegex(ValueError, 'already in transaction'):
            self.reconcile(wire)
        self.assertTrue(self.journal.in_transaction)
        self.assertEqual(self.journal_snapshot(), before)
        self.journal.rollback()
        self.assertEqual(self.journal.execute('SELECT count(*) FROM caller_changes').fetchone()[0], 0)

    def assert_sqlite_failure_rollback(self, **connection_options):
        wire = self.included_wire()
        witness = self.witness([('receipts', transaction_id(wire))])
        header = self.certificate()
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'reconciliation.sqlite'
            with closing(sqlite3.connect(path, factory=InsertFailureConnection, **connection_options)) as db:
                before = self.journal_snapshot(db)
                with self.assertRaisesRegex(sqlite3.OperationalError, 'injected journal write failure'):
                    self.reconcile(wire, witness=witness, header=header, journal=db)
                self.assertFalse(db.in_transaction)
                self.assertEqual(self.journal_snapshot(db), before)
            with closing(sqlite3.connect(path, **connection_options)) as db:
                self.assertEqual(self.journal_snapshot(db), before)
                first = self.reconcile(wire, witness=witness, header=header, journal=db)
                self.assertFalse(db.in_transaction)
                self.assertFalse(first['replayed'])
                self.assertTrue(self.reconcile(
                    wire, witness=witness, header=header, journal=db)['replayed'])

    def test_sqlite_failure_rolls_back_and_clean_reopen_retry_succeeds(self):
        self.assert_sqlite_failure_rollback()

    @unittest.skipUnless(hasattr(sqlite3.Connection, 'autocommit'), 'Python 3.12+ sqlite3 required')
    def test_autocommit_failure_rolls_back_and_clean_reopen_retry_succeeds(self):
        self.assert_sqlite_failure_rollback(autocommit=True)

    def test_new_authenticated_checkpoint_conflicts_with_durable_audit_result(self):
        wire = self.included_wire()
        old_witness = self.witness([('receipts', transaction_id(wire))])
        old_header = self.certificate()
        first = self.reconcile(wire, witness=old_witness, header=old_header)
        before = self.journal_snapshot()
        self.block([])
        with self.assertRaisesRegex(ValueError, 'conflicts with durable result'):
            self.reconcile(wire)
        self.assertFalse(self.journal.in_transaction)
        self.assertEqual(self.journal_snapshot(), before)
        self.assertEqual(self.reconcile(
            wire, witness=old_witness, header=old_header), {**first, 'replayed': True})

    def test_incompatible_existing_journal_schema_rejected_without_mutation(self):
        wire = self.included_wire()
        self.journal.execute('CREATE TABLE authenticated_reconciliations '
                             '(txid TEXT, status TEXT, state_height INTEGER, '
                             'checkpoint_hash TEXT, evidence_hash TEXT)')
        before = self.journal_snapshot()
        with self.assertRaisesRegex(ValueError, 'journal schema'):
            self.reconcile(wire)
        self.assertFalse(self.journal.in_transaction)
        self.assertEqual(self.journal_snapshot(), before)

    def test_pure_classifier_keeps_preexpiry_and_boundary_absence_pending(self):
        envelope = load_json(self.wire(valid_until=1))
        for height in (0, 1):
            with self.subTest(height=height):
                self.assertEqual(reconciliation.classify_authenticated_receipt(
                    None, local_envelope=envelope, expected_signer=public(KEYS[2]),
                    state_height=height), 'pending')
        self.assertEqual(reconciliation.classify_authenticated_receipt(
            None, local_envelope=envelope, expected_signer=public(KEYS[2]),
            state_height=2), 'absent_after_expiry')

    def test_pure_classifier_rejects_receipt_before_callers_minimum_height(self):
        wire = self.included_wire()
        witness = self.witness([('receipts', transaction_id(wire))])
        row = witness['entries'][0]['value']
        with self.assertRaisesRegex(ValueError, 'receipt height'):
            reconciliation.classify_authenticated_receipt(
                row, local_envelope=load_json(wire), expected_signer=public(KEYS[2]),
                state_height=2, minimum_receipt_height=3)


if __name__ == '__main__':
    unittest.main()
