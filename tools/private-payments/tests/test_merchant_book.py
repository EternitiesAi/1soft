"""Merchant persistence over real P4 replay; SYNTHETIC signatures, not consensus.

Cases catch recipient reuse, trusted-key substitution, cache proof bypass, lost
consumption and partial durable fulfillment. SQLite faults are real authorizer
denials rather than mock financial or cryptographic behavior.
"""
import base64
import copy
from contextlib import closing
from dataclasses import replace
import hashlib
import json
import os
from pathlib import Path
import sqlite3
import tempfile
import unittest

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from native_core import canonical, sign
from p4_fixture import build, bundle
from p4_receipt_capsule import make_capsule, encode_capsule
from payment_x402 import NativePaymentExpectation, make_payment_required, make_payment_signature

try:
    from merchant_book import MerchantBook
except ImportError:
    MerchantBook = None


def encoded(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'), ensure_ascii=True).encode()


class MerchantBookTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.case = build(rejected=True)
        c = cls.case
        cls.wire = c['wires']['after']
        cls.enrollment_evidence = bundle(c, 6)
        cls.capsule = encode_capsule(make_capsule(bundle(c), c['genesis'], c['policy'],
            cls.wire, payer=c['payer'], now_ns=c['now_ns']))
        cls.next_capsule = encode_capsule(make_capsule(bundle(c, 15), c['genesis'], c['policy'],
            cls.wire, payer=c['payer'], now_ns=c['now_ns']))

    def setUp(self):
        self.assertIsNotNone(MerchantBook, 'durable merchant payment gate is missing')
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name); self.root.chmod(0o700)
        self.path = self.root / 'merchant.sqlite'
        self.now = self.case['now_ns']
        self.expectation = NativePaymentExpectation('https://merchant.example',
            'https://merchant.example/report', '1soft:merchant-fixture', '1soft:DEV',
            self.case['policy']['genesis_sha256'], self.case['merchant'], '38')
        self.resource = b'{"report":"retained public result"}\n'
        self.required = self.offer()
        self.book = self.open(create=True)
        self.quote_id = self.book.add_quote(self.required, self.expectation,
                                           resource=self.resource)['quote_sha256']

    def tearDown(self):
        if hasattr(self, 'book'): self.book.close()
        if hasattr(self, 'tmp'): self.tmp.cleanup()

    def open(self, **kwargs):
        args = dict(clock=lambda: self.now)
        args.update(kwargs)
        return MerchantBook(self.path, self.case['genesis'], self.case['policy'], **args)

    def offer(self, expectation=None, nonce='a' * 64):
        return make_payment_required(self.expectation if expectation is None else expectation,
            created_ns=self.case['now_ns'] - 2 * 10**9,
            expires_ns=self.case['now_ns'] + 58 * 10**9, quote_nonce=nonce,
            description='Public report', mime_type='application/json')

    def enroll(self, **kwargs):
        args = dict(evidence=self.enrollment_evidence)
        args.update(kwargs)
        return self.book.enroll_wire(self.quote_id, self.case['payer'], self.wire, **args)

    def signature(self, capsule=None, required=None, expectation=None):
        return make_payment_signature(required_header=self.required if required is None else required,
            expectation=self.expectation if expectation is None else expectation,
            exact_wire=self.wire, capsule=self.capsule if capsule is None else capsule,
            payer=self.case['payer'], now_ns=self.now)

    def fulfill(self, **kwargs):
        args = dict(quote_id=self.quote_id, signature_header=self.signature(), capsule=self.capsule)
        args.update(kwargs)
        return self.book.fulfill(**args)

    def test_quote_result_is_immutable_and_recipient_cannot_be_reassigned(self):
        same = self.book.add_quote(self.required, self.expectation, resource=self.resource)
        self.assertEqual(same['status'], 'already_retained')
        with self.assertRaises(ValueError):
            self.book.add_quote(self.required, self.expectation, resource=b'changed resource')
        alternate = replace(self.expectation, resource_url='https://merchant.example/other')
        with self.assertRaises(ValueError):
            self.book.add_quote(self.offer(alternate, 'b' * 64), alternate, resource=self.resource)
        self.assertEqual(len(self.book.entries()), 1)

    def test_wire_enrollment_requires_independent_verified_evidence_and_preserves_original(self):
        enrolled = self.enroll()
        self.assertEqual(enrolled['status'], 'wire_enrolled')
        self.assertFalse(enrolled['execution_proven'])
        self.assertFalse(enrolled['wallet_reservations_changed'])
        repeated = self.enroll()
        self.assertEqual(repeated['status'], 'already_enrolled')
        with self.assertRaises(TypeError):
            self.book.enroll_wire(self.quote_id, self.case['payer'], self.wire)
        with self.assertRaises(ValueError):
            self.book.enroll_wire(self.quote_id, self.case['payer'], self.case['wires']['raven'],
                                  evidence=self.enrollment_evidence)
        self.assertEqual(self.book.selected(self.quote_id)['enrollment']['wire_sha256'],
                         hashlib.sha256(self.wire).hexdigest())

    def test_enrollment_rejects_bad_signature_wrong_payer_and_quote_supplied_key(self):
        packet = json.loads(self.wire); packet['signature'] = '0' * 128
        with self.assertRaises(ValueError):
            self.book.enroll_wire(self.quote_id, self.case['payer'], encoded(packet),
                                  evidence=self.enrollment_evidence)
        with self.assertRaises(ValueError):
            self.book.enroll_wire(self.quote_id, self.case['merchant'], self.wire,
                                  evidence=self.enrollment_evidence)
        attacker = Ed25519PrivateKey.from_private_bytes(b'\x96' * 32)
        forged = canonical(sign(attacker, json.loads(self.wire)['body']))
        with self.assertRaises(ValueError):
            self.book.enroll_wire(self.quote_id, self.case['payer'], forged,
                                  evidence=self.enrollment_evidence)
        with self.assertRaises(TypeError):
            self.book.enroll_wire(self.quote_id, self.case['payer'], self.wire,
                                  signer_public_key='0' * 64, evidence=self.enrollment_evidence)

    def test_enrollment_tampered_ledger_key_cannot_supply_signing_authority(self):
        evidence = copy.deepcopy(self.enrollment_evidence)
        evidence['state']['native']['grants'][0][2] = '0' * 64
        with self.assertRaises(ValueError): self.enroll(evidence=evidence)
        self.assertIsNone(self.book.selected(self.quote_id)['enrollment'])

    def test_payload_alone_cannot_enroll_wire_or_fulfill_quote(self):
        with self.assertRaises(ValueError): self.fulfill()
        self.assertIsNone(self.book.selected(self.quote_id)['enrollment'])
        self.assertIsNone(self.book.selected(self.quote_id)['fulfillment'])

    def test_fulfillment_retains_exact_result_before_return_and_repeats_idempotently(self):
        self.enroll()
        result = self.fulfill()
        self.assertEqual(result['status'], 'local_fulfillment_retained')
        self.assertEqual(result['resource'], self.resource)
        self.assertEqual(result['resource_sha256'], hashlib.sha256(self.resource).hexdigest())
        self.assertTrue(result['native_execution_reverified'])
        self.assertFalse(result['external_service_delivery_verified'])
        again = self.fulfill()
        self.assertEqual(again['status'], 'original_local_fulfillment_retained')
        for field in ('resource', 'resource_sha256', 'native_txid', 'wire_sha256',
                      'payment_response_header', 'fulfilled_ns'):
            self.assertEqual(again[field], result[field])
        self.assertEqual(self.book.db.execute('SELECT count(*) FROM fulfillments').fetchone()[0], 1)

    def test_completed_row_never_skips_reverification_of_incoming_evidence(self):
        self.enroll(); self.fulfill()
        capsule = json.loads(self.capsule)
        capsule['evidence']['headers'][6]['signed_header']['commit']['signatures'][0]['signature'] = (
            base64.b64encode(b'\0' * 64).decode())
        raw = encoded(capsule)
        with self.assertRaises(ValueError):
            self.fulfill(capsule=raw, signature_header=self.signature(capsule=raw))
        self.assertEqual(self.book.db.execute('SELECT count(*) FROM fulfillments').fetchone()[0], 1)

    def test_changed_valid_capsule_is_not_accepted_as_cached_fulfillment(self):
        self.enroll(); self.fulfill()
        with self.assertRaises(ValueError):
            self.fulfill(capsule=self.next_capsule, signature_header=self.signature(capsule=self.next_capsule))

    def test_wrong_resource_context_and_cross_quote_replay_are_refused(self):
        self.enroll(); self.fulfill()
        alternate = replace(self.expectation, resource_url='https://merchant.example/other')
        with self.assertRaises(ValueError):
            self.fulfill(signature_header=self.signature(required=self.offer(alternate, 'b' * 64),
                                                         expectation=alternate))
        other = replace(self.expectation, recipient=self.case['payer'],
                        resource_url='https://merchant.example/second')
        other_id = self.book.add_quote(self.offer(other, 'c' * 64), other,
                                      resource=b'second public result')['quote_sha256']
        with self.assertRaises(ValueError):
            self.book.enroll_wire(other_id, self.case['payer'], self.wire,
                                  evidence=self.enrollment_evidence)
        with self.assertRaises(ValueError): self.fulfill(quote_id=other_id)
        self.assertIsNone(self.book.selected(other_id)['fulfillment'])

    def test_restart_preserves_unresolved_wire_and_completed_consumption(self):
        self.enroll(); self.book.close(); self.book = self.open()
        self.assertIsNotNone(self.book.selected(self.quote_id)['enrollment'])
        self.assertIsNone(self.book.selected(self.quote_id)['fulfillment'])
        result = self.fulfill()
        self.book.close(); self.book = self.open()
        duplicate = self.fulfill()
        self.assertEqual(duplicate['status'], 'original_local_fulfillment_retained')
        self.assertEqual(duplicate['resource'], result['resource'])
        with self.assertRaises(ValueError):
            self.book.add_quote(self.offer(nonce='f' * 64), self.expectation, resource=self.resource)

    def test_transaction_commit_failure_leaves_no_partial_claim_or_resource(self):
        self.enroll()
        def deny_commit(action, one, two, database, trigger):
            if action == sqlite3.SQLITE_TRANSACTION and one == 'COMMIT':
                return sqlite3.SQLITE_DENY
            return sqlite3.SQLITE_OK
        self.book.db.set_authorizer(deny_commit)
        try:
            with self.assertRaises(sqlite3.DatabaseError): self.fulfill()
        finally: self.book.db.set_authorizer(None)
        self.assertFalse(self.book.db.in_transaction)
        self.assertIsNone(self.book.selected(self.quote_id)['fulfillment'])
        self.book.close(); self.book = self.open()
        self.assertIsNone(self.book.selected(self.quote_id)['fulfillment'])
        self.assertEqual(self.fulfill()['status'], 'local_fulfillment_retained')

    def test_read_only_open_can_inspect_but_never_enroll_or_consume(self):
        self.enroll(); self.fulfill()
        self.book.close(); self.book = self.open(read_only=True)
        selected = self.book.selected(self.quote_id)
        self.assertFalse(selected['execution_proven'])
        self.assertFalse(selected['resource_delivery_authorized'])
        self.assertIsNotNone(selected['fulfillment'])
        with self.assertRaises(ValueError): self.enroll()
        with self.assertRaises(ValueError): self.fulfill()
        with self.assertRaises(ValueError):
            self.book.add_quote(self.required, self.expectation, resource=self.resource)

    def test_clock_regression_or_changed_external_policy_refuses_current_operation(self):
        self.enroll(); self.fulfill()
        self.now -= 1
        with self.assertRaises(ValueError): self.book.selected(self.quote_id)
        self.now += 1
        self.book.close()
        policy = copy.deepcopy(self.case['policy']); policy['max_clock_drift_seconds'] += 1
        with self.assertRaises(ValueError):
            MerchantBook(self.path, self.case['genesis'], policy, clock=lambda: self.now)
        self.book = self.open()

    def test_private_file_links_modes_unknown_schema_and_no_repair(self):
        self.book.close()
        self.path.chmod(0o644)
        with self.assertRaises(ValueError): self.open()
        self.path.chmod(0o600)
        alias = self.root / 'alias.sqlite'; os.link(self.path, alias)
        with self.assertRaises(ValueError): self.open()
        alias.unlink()
        other = self.root / 'unknown.sqlite'
        with closing(sqlite3.connect(other)) as db: db.execute('CREATE TABLE untrusted(x INTEGER)')
        other.chmod(0o600)
        before = other.read_bytes()
        with self.assertRaises(ValueError):
            MerchantBook(other, self.case['genesis'], self.case['policy'], clock=lambda: self.now)
        self.assertEqual(other.read_bytes(), before)
        self.book = self.open()

    def test_modified_persisted_result_is_refused_on_reopen(self):
        self.enroll(); self.fulfill()
        self.book.db.execute('UPDATE fulfillments SET resource=? WHERE quote_id=?',
                             (b'changed content', self.quote_id))
        self.book.close()
        with self.assertRaises(ValueError): self.open()
        # Failed reopen must not repair or forget the consumed row.
        with closing(sqlite3.connect(self.path)) as db:
            self.assertEqual(db.execute('SELECT count(*) FROM fulfillments').fetchone()[0], 1)

    def test_quote_capacity_and_content_bounds_are_no_eviction(self):
        with self.assertRaises(ValueError):
            self.book.add_quote(self.required, self.expectation, resource=b'x' * (65536 + 1))
        for index in range(1, 64):
            other = replace(self.expectation, recipient='lab_' + format(index, '064x'),
                            resource_url='https://merchant.example/report/' + str(index))
            self.book.add_quote(self.offer(other, format(index, '064x')), other, resource=b'public')
        other = replace(self.expectation, recipient='lab_' + format(65, '064x'),
                        resource_url='https://merchant.example/last')
        with self.assertRaises(ValueError):
            self.book.add_quote(self.offer(other, 'e' * 64), other, resource=b'public')
        self.assertEqual(len(self.book.entries()), 64)


if __name__ == '__main__': unittest.main()
