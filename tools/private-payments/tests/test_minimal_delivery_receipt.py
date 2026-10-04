import hashlib
import json
import unittest

from minimal_delivery_receipt import FORMAT, create, parse


class MinimalDeliveryReceiptTests(unittest.TestCase):
    def setUp(self):
        self.value = {
            'resource_sha256': hashlib.sha256(b'public resource').hexdigest(),
            'merchant_origin': 'http://127.0.0.1:39080',
            'resource_path': '/premium/item',
            'quote_commitment': 'a' * 64,
            'execution_status': 'fulfilled',
            'verifier_anchor': 'b' * 64,
        }

    def test_create_is_canonical_and_contains_only_minimal_fields(self):
        raw = create(**self.value)
        value = parse(raw)
        self.assertEqual(value['format'], FORMAT)
        self.assertEqual(set(value), {
            'schema', 'format', 'resource_sha256', 'merchant_origin',
            'resource_path', 'quote_commitment', 'execution_status',
            'verifier_anchor',
        })
        self.assertEqual(json.dumps(value, sort_keys=True, separators=(',', ':')).encode(), raw)
        for forbidden in ('payer', 'grant_id', 'budget_id', 'wire_sha256',
                          'capsule_sha256', 'native_txid', 'signer_public_key',
                          'full_history', 'session_token', 'created_ns',
                          'expires_ns', 'resource'):
            self.assertNotIn(forbidden, value)

    def test_parser_rejects_unknown_or_noncanonical_fields(self):
        raw = create(**self.value)
        altered = json.loads(raw)
        altered['native_txid'] = 'c' * 64
        with self.assertRaises(ValueError):
            parse(json.dumps(altered, sort_keys=True, separators=(',', ':')).encode())
        altered = json.loads(raw)
        altered['schema'] = True
        with self.assertRaises(ValueError):
            parse(json.dumps(altered, sort_keys=True, separators=(',', ':')).encode())
        with self.assertRaises(ValueError):
            parse(raw + b' ')

    def test_parser_rejects_bad_anchor_and_route(self):
        for field, value in [('verifier_anchor', 'short'),
                             ('resource_sha256', 'z' * 64),
                             ('merchant_origin', 'https://evil.invalid/x'),
                             ('merchant_origin', 'http://user@127.0.0.1:39080'),
                             ('merchant_origin', 'http://127.0.0.1:039080'),
                             ('resource_path', 'relative'),
                             ('resource_path', '/premium/../admin'),
                             ('resource_path', '/premium%2fadmin'),
                             ('resource_path', '/premium?token=secret')]:
            data = dict(self.value)
            data[field] = value
            with self.assertRaises(ValueError):
                create(**data)


if __name__ == '__main__':
    unittest.main()
