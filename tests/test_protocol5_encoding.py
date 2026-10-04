from __future__ import annotations

import hashlib
import unittest

from protocol5_fixture import (
    DEPLOYMENT_BYTES, DEPLOYMENT_ID, PROFILE_BYTES, PROFILE_ID,
    make_genesis, make_limits, make_tx,
)
from protocol5_encoding import (
    EncodingError, DeploymentBinding, ProfileDescriptor, Transaction,
    canonical_json, comet_validator_set, decode_canonical_json, field_bytes,
    genesis_document, h2f, transaction_id,
)

class Protocol5EncodingTests(unittest.TestCase):
    def test_identity_dag_and_golden_vectors(self):
        self.assertEqual(
            h2f(b"asset", b"1soft").hex(),
            "4b07fced1905ae36bdde8ef3e2a8ffc948e2d28739df96b5c260415ef894f435",
        )
        profile = ProfileDescriptor.decode(PROFILE_BYTES)
        self.assertEqual(profile.identity, PROFILE_ID)
        self.assertEqual(profile.proof_length, 1024)
        deployment = DeploymentBinding.decode(DEPLOYMENT_BYTES)
        self.assertEqual(deployment.identity, DEPLOYMENT_ID)
        self.assertEqual(deployment.profile_id, PROFILE_ID)

        genesis = make_genesis()
        parsed = genesis_document(canonical_json(genesis))
        self.assertEqual(parsed.sha256, hashlib.sha256(canonical_json(genesis)).digest())
        tx_raw = make_tx(genesis)
        tx = Transaction.decode(tx_raw, parsed)
        self.assertEqual(tx.proof, b"P" * 1024)
        self.assertEqual(transaction_id(tx_raw), hashlib.sha256(
            b"1soft/shielded-txid/v1\0" + tx_raw).digest())

    def test_canonical_json_and_field_encoding_reject_alternates(self):
        value = {"a": 1, "b": ["x"]}
        raw = b'{"a":1,"b":["x"]}'
        self.assertEqual(canonical_json(value), raw)
        self.assertEqual(decode_canonical_json(raw), value)
        for bad in (
            b'{"b":["x"],"a":1}', b'{"a":1, "b":["x"]}',
            b'{"a":1,"a":1}', b'{"a":1.0,"b":["x"]}',
            b'{"a":NaN,"b":["x"]}',
        ):
            with self.subTest(bad=bad):
                with self.assertRaises(EncodingError):
                    decode_canonical_json(bad)
        modulus = int(
            "40000000000000000000000000000000224698fc094cf91b992d30ed00000001", 16)
        self.assertEqual(field_bytes((modulus - 1).to_bytes(32, "little").hex()),
                         (modulus - 1).to_bytes(32, "little"))
        with self.assertRaises(EncodingError):
            field_bytes(modulus.to_bytes(32, "little").hex())

    def test_genesis_order_and_comet_order_are_separate(self):
        parsed = genesis_document(canonical_json(make_genesis()))
        genesis_keys = [bytes.fromhex(row["public_key"]) for row in parsed.value["validators"]]
        self.assertEqual(genesis_keys, sorted(genesis_keys))
        comet = comet_validator_set(parsed.value["validators"])
        self.assertEqual(
            [v.address for v in comet.validators],
            sorted(hashlib.sha256(key).digest()[:20] for key in genesis_keys),
        )
        self.assertNotEqual(
            [v.public_key for v in comet.validators],
            genesis_keys,
            "fixture must exercise distinct public-key and Comet address order",
        )

    def test_genesis_cross_limit_arithmetic_is_fail_closed(self):
        cases = (
            {"max_accepted_transactions": 8},
            {"max_accepted_transactions": 7, "max_history_transactions": 6},
            {"max_tx_bytes": 1557},
            {"max_fee_total": 29},
            {"max_worker_frame_bytes": 1024},
            {"snapshot_chunk_bytes": 65 * 1024},
        )
        for changes in cases:
            with self.subTest(changes=changes):
                genesis = make_genesis(limits=make_limits(**changes))
                with self.assertRaises(EncodingError):
                    genesis_document(canonical_json(genesis))

    def test_genesis_field_precedes_commitments_but_final_hash_binds_them(self):
        first = make_genesis()
        second = make_genesis(initial_commitments=list(reversed(
            first["initial_commitments"])))
        parsed_first = genesis_document(canonical_json(first))
        parsed_second = genesis_document(canonical_json(second))
        self.assertEqual(first["genesis_field"], second["genesis_field"])
        self.assertNotEqual(parsed_first.sha256, parsed_second.sha256)
        changed_fee = make_genesis(fee=6)
        self.assertNotEqual(first["genesis_field"], changed_fee["genesis_field"])

    def test_chain_id_matches_pinned_engine_ascii_boundary(self):
        accepted = make_genesis(chain_id="a" * 50)
        accepted["genesis_field"] = __import__("protocol5_encoding").field_hex(
            __import__("protocol5_encoding").h2f(b"genesis", canonical_json(
                {k: v for k, v in accepted.items()
                 if k not in ("genesis_field", "initial_commitments")})))
        genesis_document(canonical_json(accepted))
        for chain_id in ("a" * 51, "chain-\N{SNOWMAN}"):
            with self.subTest(chain_id=chain_id):
                rejected = make_genesis(chain_id=chain_id)
                with self.assertRaises(EncodingError):
                    genesis_document(canonical_json(rejected))

    def test_transaction_complete_consumption_and_identity(self):
        genesis = genesis_document(canonical_json(make_genesis()))
        raw = make_tx(genesis.value)
        for bad in (raw + b"x", raw[:-1], b"X" + raw[1:]):
            with self.subTest(length=len(bad)):
                with self.assertRaises(EncodingError):
                    Transaction.decode(bad, genesis)
        changed = bytearray(raw)
        changed[16] ^= 1
        with self.assertRaises(EncodingError):
            Transaction.decode(bytes(changed), genesis)

if __name__ == "__main__":
    unittest.main()
