"""Real native replay with SYNTHETIC committee signatures; never consensus.

Each negative case catches dropping a corresponding input/trust boundary. The
literal transport objects are independently formed, not module-built or mocked.
"""
import base64
import copy
from dataclasses import replace
import hashlib
import json
from pathlib import Path
import tempfile
import unittest

from native_core import MAX_UNITS
from p4_fixture import build, bundle
from p4_receipt_capsule import make_capsule, encode_capsule
from payment_requests import RequestBook

try:
    import payment_x402 as px
except ImportError:
    px = None


def raw_json(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'),
                      ensure_ascii=True, allow_nan=False).encode('ascii')


def header(value):
    return base64.b64encode(raw_json(value)).decode('ascii')


class NativeX402Tests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.case = build(rejected=True)
        cls.wire = cls.case['wires']['after']
        cls.capsule = encode_capsule(make_capsule(bundle(cls.case), cls.case['genesis'],
            cls.case['policy'], cls.wire, payer=cls.case['payer'], now_ns=cls.case['now_ns']))

    def setUp(self):
        self.assertIsNotNone(px, 'bounded native x402 adapter is missing')
        c = self.case
        self.expectation = px.NativePaymentExpectation(
            merchant_origin='https://merchant.example',
            resource_url='https://merchant.example/premium/report?edition=1',
            network='1soft:fixture-local', asset='1soft:DEV',
            genesis_sha256=c['policy']['genesis_sha256'],
            recipient=c['merchant'], amount_units='38')
        self.offer = {'x402Version': 2,
            'resource': {'url': self.expectation.resource_url,
                         'description': 'One local report', 'mimeType': 'application/json'},
            'accepts': [{'scheme': '1soft-p4', 'network': '1soft:fixture-local',
                'asset': '1soft:DEV', 'amount': '38', 'payTo': c['merchant'],
                'maxTimeoutSeconds': 60, 'extra': {
                    'format': '1soft/x402-native-offer/v1',
                    'genesisSha256': c['policy']['genesis_sha256'],
                    'merchantOrigin': 'https://merchant.example', 'nativeAsset': 'DEV',
                    'createdNs': c['now_ns'] - 2 * 10**9,
                    'expiresNs': c['now_ns'] + 58 * 10**9,
                    'quoteNonce': 'a' * 64, 'assetTransferMethod': 'p4-capsule',
                    'paymentFlow': 'upfront'}}]}
        self.required = header(self.offer)

    def quote(self, required=None, expectation=None, now_ns=None):
        return px.parse_payment_required(self.required if required is None else required,
            self.expectation if expectation is None else expectation,
            now_ns=self.case['now_ns'] if now_ns is None else now_ns)

    def signature(self, **overrides):
        args = dict(required_header=self.required, expectation=self.expectation,
                    exact_wire=self.wire, capsule=self.capsule, payer=self.case['payer'],
                    now_ns=self.case['now_ns'])
        args.update(overrides)
        return px.make_payment_signature(**args)

    def assignment(self, **overrides):
        q = self.quote()
        args = dict(quote_sha256=q['quote_sha256'], request_id=q['request_id'],
                    recipient=self.case['merchant'], payer=self.case['payer'],
                    wire_sha256=hashlib.sha256(self.wire).hexdigest())
        args.update(overrides)
        return px.TrustedMerchantAssignment(**args)

    def verify(self, **overrides):
        args = dict(signature_header=self.signature(), required_header=self.required,
                    expectation=self.expectation, assignment=self.assignment(),
                    exact_wire=self.wire, capsule=self.capsule,
                    genesis_bytes=self.case['genesis'], policy=self.case['policy'],
                    payer=self.case['payer'], now_ns=self.case['now_ns'])
        args.update(overrides)
        return px.verify_merchant_payment(**args)

    def test_offer_maps_exact_atomic_units_into_unsigned_canonical_request(self):
        q = self.quote()
        self.assertEqual(q['request']['units'], '38')
        self.assertEqual(q['request']['recipient'], self.case['merchant'])
        self.assertEqual(q['request']['created_ns'], self.case['now_ns'] - 2 * 10**9)
        self.assertEqual(q['request']['expires_ns'], self.case['now_ns'] + 58 * 10**9)
        self.assertEqual(q['quote_sha256'], hashlib.sha256(raw_json(self.offer)).hexdigest())
        self.assertEqual(q['request']['note'], 'x402 quote ' + q['quote_sha256'])
        self.assertFalse(q['spending_authority'])

    def test_offer_builder_emits_independently_expected_v2_header(self):
        actual = px.make_payment_required(self.expectation,
            created_ns=self.case['now_ns'] - 2 * 10**9,
            expires_ns=self.case['now_ns'] + 58 * 10**9, quote_nonce='a' * 64,
            description='One local report', mime_type='application/json')
        self.assertEqual(base64.b64decode(actual), raw_json(self.offer))

    def test_retention_only_adds_unsigned_request_without_decision(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory); root.chmod(0o700)
            with RequestBook(root / 'requests.sqlite', self.expectation.genesis_sha256,
                             create=True, clock=lambda: self.case['now_ns']) as book:
                retained = px.retain_payment_request(book, self.required, self.expectation,
                                                    now_ns=self.case['now_ns'])
                self.assertEqual(retained['status'], 'request_retained')
                entry = book.selected(retained['request_id'])
                self.assertIsNone(entry['decision_id']); self.assertIsNone(entry['review'])
                self.assertFalse(entry['execution_proven'])
                repeated = px.retain_payment_request(book, self.required, self.expectation,
                                                    now_ns=self.case['now_ns'])
                self.assertEqual(repeated['status'], 'already_retained')
            self.assertFalse((root / 'wallet.sqlite').exists())

    def test_each_authentication_pin_is_required_and_compared(self):
        changes = {'merchant_origin': 'https://elsewhere.example',
            'resource_url': 'https://merchant.example/other', 'network': '1soft:other',
            'asset': 'USDC', 'genesis_sha256': '0' * 64,
            'recipient': 'lab_' + '0' * 64, 'amount_units': '39'}
        for key, value in changes.items():
            with self.subTest(key=key), self.assertRaises(ValueError):
                expectation = replace(self.expectation, **{key: value})
                self.quote(expectation=expectation)
        with self.assertRaises(ValueError): self.quote(expectation={})

    def test_unrecognized_scheme_network_asset_extensions_are_never_routed(self):
        for field, value in [('scheme', 'exact'), ('scheme', 'upto'),
                             ('network', 'eip155:8453'), ('asset', 'USDC')]:
            offer = copy.deepcopy(self.offer); offer['accepts'][0][field] = value
            with self.subTest(field=field, value=value), self.assertRaises(ValueError):
                self.quote(header(offer))
        for edit in (lambda o: o.update(extensions={'unexpected': {}}),
                     lambda o: o['accepts'].append(copy.deepcopy(o['accepts'][0])),
                     lambda o: o['accepts'][0]['extra'].update(paymentFlow='authorization'),
                     lambda o: o['accepts'][0]['extra'].update(assetTransferMethod='eip3009')):
            offer = copy.deepcopy(self.offer); edit(offer)
            with self.assertRaises(ValueError): self.quote(header(offer))

    def test_malformed_shapes_versions_and_numeric_coercions_refused(self):
        edits = [lambda o: o.update(x402Version=True), lambda o: o.update(x402Version=1),
            lambda o: o['resource'].update(iconUrl='https://outside.example/track'),
            lambda o: o['accepts'][0].update(maxTimeoutSeconds=True),
            lambda o: o['accepts'][0].update(maxTimeoutSeconds=61),
            lambda o: o['accepts'][0]['extra'].update(createdNs=True),
            lambda o: o['accepts'][0]['extra'].update(quoteNonce='abc')]
        for amount in ('0', '038', '-1', '1.0', '1e2', '９', str(MAX_UNITS + 1), 38, True):
            edits.append(lambda o, amount=amount: o['accepts'][0].update(amount=amount))
        for edit in edits:
            offer = copy.deepcopy(self.offer); edit(offer)
            with self.assertRaises(ValueError): self.quote(header(offer))

    def test_expired_future_oversized_lifetime_and_regressed_clock_refused(self):
        for now in (self.case['now_ns'] - 3 * 10**9, self.case['now_ns'] + 58 * 10**9, True):
            with self.subTest(now=now), self.assertRaises(ValueError): self.quote(now_ns=now)
        offer = copy.deepcopy(self.offer)
        offer['accepts'][0]['extra']['expiresNs'] += 86400 * 10**9
        with self.assertRaises(ValueError): self.quote(header(offer))

    def test_canonical_base64_strict_json_duplicate_depth_and_header_bounds(self):
        bad = ['', '%%%=', self.required + '\n', self.required.rstrip('=') + '=',
            base64.b64encode(b' {"x402Version":2}').decode(),
            base64.b64encode(b'{"x402Version":2,"x402Version":2}').decode(),
            base64.b64encode(b'{"x402Version":2.0}').decode(),
            base64.b64encode(b'[' * 65 + b'0' + b']' * 65).decode(), 'A' * 8193]
        # Explicit noncanonical pad bits for JSON '{}': e30= is canonical.
        bad.append('e31=')
        for value in bad:
            with self.subTest(value=value[:35]), self.assertRaises(ValueError): self.quote(value)

    def test_url_pin_refuses_credentials_fragments_remote_http_and_ambiguity(self):
        for url in ('http://merchant.example/report', 'https://a:b@merchant.example/report',
                    'https://merchant.example/report#section', 'https://merchant.example\\evil/report',
                    'https://merchant.example/%0d%0aevil', 'https://merchant.example/a/../b',
                    'https://merchant.example:443/report', 'https://MERCHANT.example/report',
                    'https://merchant.example/report?x=hello world'):
            with self.subTest(url=url), self.assertRaises(ValueError):
                replace(self.expectation, resource_url=url)
        loopback = replace(self.expectation, merchant_origin='http://127.0.0.1:8800',
                           resource_url='http://127.0.0.1:8800/premium')
        self.assertEqual(loopback.resource_url, 'http://127.0.0.1:8800/premium')

    def test_duplicate_case_insensitive_payment_headers_are_refused(self):
        self.assertEqual(px.payment_header([('Payment-Required', self.required)],
                                           'PAYMENT-REQUIRED'), self.required)
        for rows in ([('PAYMENT-REQUIRED', self.required), ('payment-required', self.required)],
                     [('PAYMENT-REQUIRED', self.required + '\r\nInjected: x')], [],
                     [('PAYMENT-REQUIRED', self.required)] * 65):
            with self.assertRaises(ValueError): px.payment_header(rows, 'PAYMENT-REQUIRED')

    def test_signature_retains_original_wire_and_exact_quote_capsule_digests(self):
        value = json.loads(base64.b64decode(self.signature()))
        self.assertEqual(value['x402Version'], 2)
        self.assertEqual(value['accepted'], self.offer['accepts'][0])
        self.assertEqual(value['resource'], self.offer['resource'])
        self.assertEqual(base64.b64decode(value['payload']['wire']), self.wire)
        self.assertEqual(value['payload']['quoteSha256'], self.quote()['quote_sha256'])
        self.assertEqual(value['payload']['capsuleSha256'], hashlib.sha256(self.capsule).hexdigest())
        self.assertNotIn('evidence', value['payload'])

    def test_signature_builder_refuses_wrong_wire_capsule_terms_and_payer(self):
        for overrides in ({'exact_wire': self.case['wires']['raven']},
                          {'exact_wire': self.wire + b' '}, {'payer': self.case['merchant']},
                          {'capsule': self.capsule + b' '}):
            with self.subTest(overrides=list(overrides)), self.assertRaises(ValueError):
                self.signature(**overrides)

    def test_positive_acceptance_replays_validator_turnover_but_needs_consumption(self):
        report = self.verify()
        self.assertEqual(report['status'], 'verified-native-execution-awaiting-merchant-consumption')
        proof = report['receipt_report']
        self.assertEqual((proof['amount_units'], proof['recipient'], proof['payer']),
                         ('38', self.case['merchant'], self.case['payer']))
        self.assertEqual((proof['receipt_height'], proof['registry_epoch']), (7, 2))
        self.assertTrue(proof['signed_block_inclusion_verified'])
        self.assertTrue(report['merchant_consumption_required'])
        for field in ('resource_delivery_authorized', 'merchant_replay_checked',
                      'wallet_reservations_changed', 'external_settlement_verified',
                      'native_signature_authenticates_resource'):
            self.assertFalse(report[field])
        response = px.parse_payment_response(report['payment_response_header'], self.expectation,
            payer=self.case['payer'], quote_sha256=self.quote()['quote_sha256'],
            wire_sha256=hashlib.sha256(self.wire).hexdigest(),
            capsule_sha256=hashlib.sha256(self.capsule).hexdigest())
        self.assertEqual(response['response']['amount'], '38')
        self.assertFalse(response['execution_proven'])

    def test_original_merchant_assignment_required_for_every_positive_match(self):
        for field, value in [('quote_sha256', '0' * 64), ('request_id', '0' * 64),
                            ('recipient', self.case['payer']), ('payer', self.case['merchant']),
                            ('wire_sha256', '0' * 64)]:
            with self.subTest(field=field), self.assertRaises(ValueError):
                self.verify(assignment=self.assignment(**{field: value}))
        with self.assertRaises(ValueError): self.verify(assignment=None)

    def test_genuine_public_receipt_cannot_be_rebundled_for_another_resource_assignment(self):
        alternate = replace(self.expectation, resource_url='https://merchant.example/other')
        offer = copy.deepcopy(self.offer); offer['resource']['url'] = alternate.resource_url
        offer['accepts'][0]['extra']['quoteNonce'] = 'b' * 64
        required = header(offer)
        signature = self.signature(required_header=required, expectation=alternate)
        with self.assertRaises(ValueError):
            self.verify(required_header=required, signature_header=signature, expectation=alternate)

    def test_signature_wrapper_fields_are_compared_to_quote_and_original_material(self):
        original = json.loads(base64.b64decode(self.signature()))
        for edit in (lambda o: o.update(x402Version=True),
            lambda o: o['resource'].update(url='https://merchant.example/other'),
            lambda o: o['accepted'].update(amount='39'),
            lambda o: o['payload'].update(quoteSha256='0' * 64),
            lambda o: o['payload'].update(wireSha256='0' * 64),
            lambda o: o['payload'].update(capsuleSha256='0' * 64),
            lambda o: o['payload'].update(requestId='0' * 64),
            lambda o: o['payload'].update(payer=self.case['merchant']),
            lambda o: o['payload'].update(settled=True)):
            value = copy.deepcopy(original); edit(value)
            with self.assertRaises(ValueError): self.verify(signature_header=header(value))

    def test_real_verifier_rejects_tampered_evidence_even_with_matching_wrapper_hash(self):
        capsule = json.loads(self.capsule)
        capsule['evidence']['headers'][6]['signed_header']['commit']['signatures'][0]['signature'] = (
            base64.b64encode(b'\0' * 64).decode())
        raw = raw_json(capsule)
        signature = self.signature(capsule=raw)
        with self.assertRaises(ValueError): self.verify(capsule=raw, signature_header=signature)

    def test_caller_genesis_policy_time_and_wire_are_independently_required(self):
        changed_policy = copy.deepcopy(self.case['policy']); changed_policy['anchor_hash'] = '0' * 64
        for overrides in ({'genesis_bytes': self.case['genesis'] + b' '},
            {'policy': changed_policy}, {'payer': self.case['merchant']},
            {'exact_wire': self.case['wires']['raven']},
            {'now_ns': self.case['now_ns'] + 3600 * 10**9}):
            with self.assertRaises(ValueError): self.verify(**overrides)

    def test_http_success_or_a_response_header_is_only_an_unverified_declaration(self):
        response = {'success': True, 'transaction': '0' * 64, 'network': '1soft:fixture-local',
                    'payer': self.case['payer'], 'amount': '38', 'extensions': {'1soft-p4': {
                        'quoteSha256': self.quote()['quote_sha256'],
                        'wireSha256': hashlib.sha256(self.wire).hexdigest(),
                        'capsuleSha256': hashlib.sha256(self.capsule).hexdigest(),
                        'genesisSha256': self.expectation.genesis_sha256,
                        'resourceUrl': self.expectation.resource_url}}}
        parsed = px.parse_payment_response(header(response), self.expectation,
            payer=self.case['payer'], quote_sha256=self.quote()['quote_sha256'],
            wire_sha256=hashlib.sha256(self.wire).hexdigest(),
            capsule_sha256=hashlib.sha256(self.capsule).hexdigest())
        self.assertFalse(parsed['execution_proven'])
        self.assertFalse(parsed['wallet_reservations_changed'])
        response['success'] = 1
        with self.assertRaises(ValueError): px.parse_payment_response(header(response), self.expectation,
            payer=self.case['payer'], quote_sha256=self.quote()['quote_sha256'],
            wire_sha256=hashlib.sha256(self.wire).hexdigest(),
            capsule_sha256=hashlib.sha256(self.capsule).hexdigest())


if __name__ == '__main__': unittest.main()
