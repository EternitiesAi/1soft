from __future__ import annotations

import base64
import hashlib
import unittest

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from certificate_fixture import make_commit, make_header
from commit_verifier import VerificationError, sha, trust_from_genesis
from protocol5_application import Protocol5Application
from protocol5_certificate import (
    trust_from_protocol5_genesis, verify_protocol5_state_certificate,
)
from protocol5_encoding import canonical_json, field_hex, genesis_document, h2f
from protocol5_fixture import make_genesis
from test_protocol5_state import FixtureWorker

class Protocol5CertificateTests(unittest.TestCase):
    def _fixture(self):
        keys = [Ed25519PrivateKey.from_private_bytes(bytes([i + 31]) * 32)
                for i in range(4)]
        rows = []
        engine_rows = []
        for key in keys:
            public = key.public_key().public_bytes_raw()
            address = sha(public)[:20]
            rows.append({"public_key": public.hex(), "power": 10})
            engine_rows.append({
                "address": address.hex().upper(),
                "pub_key": {
                    "type": "tendermint/PubKeyEd25519",
                    "value": base64.b64encode(public).decode("ascii"),
                },
                "power": "10",
                "name": "P5",
            })
        rows.sort(key=lambda row: bytes.fromhex(row["public_key"]))
        value = make_genesis(validators=rows)
        value["genesis_field"] = field_hex(h2f(
            b"genesis",
            canonical_json({k: v for k, v in value.items()
                            if k not in ("genesis_field", "initial_commitments")}),
        ))
        raw = canonical_json(value)
        engine = {
            "chain_id": value["chain_id"],
            "initial_height": "1",
            "validators": engine_rows,
            "app_state": value,
        }
        trust = trust_from_protocol5_genesis(engine, raw)
        keyed = {sha(key.public_key().public_bytes_raw())[:20]: key for key in keys}
        ordered_keys = [keyed[validator.address] for validator in trust.validators]
        return raw, engine, trust, ordered_keys

    def test_protocol5_trust_and_signed_next_header_bind_state(self):
        raw, engine, trust, keys = self._fixture()
        with self.assertRaises(VerificationError):
            trust_from_genesis(engine)
        app = Protocol5Application(
            ":memory:", FixtureWorker(), expected_genesis=raw)
        genesis = genesis_document(raw)
        app.init_chain(
            genesis.value["chain_id"], raw, genesis.value["validators"], 1)
        witness = {
            "genesis": genesis.value,
            "height": 0,
            "app_hash": app.app_hash,
            "state": app.state,
        }
        header = make_header(trust, 1, app.app_hash)
        signed = make_commit(header, trust, keys)
        certificate = verify_protocol5_state_certificate(witness, signed, trust)
        self.assertEqual(certificate["state_height"], 0)
        self.assertEqual(certificate["header_height"], 1)
        self.assertEqual(certificate["app_hash"], app.app_hash)
        app.close()

    def test_wrong_apphash_and_wrong_validator_set_are_refused(self):
        raw, _, trust, keys = self._fixture()
        app = Protocol5Application(
            ":memory:", FixtureWorker(), expected_genesis=raw)
        genesis = genesis_document(raw)
        app.init_chain(genesis.value["chain_id"], raw, genesis.value["validators"], 1)
        witness = {"genesis": genesis.value, "height": 0,
                   "app_hash": app.app_hash, "state": app.state}
        header = make_header(trust, 1, "00" * 32)
        with self.assertRaises(VerificationError):
            verify_protocol5_state_certificate(
                witness, make_commit(header, trust, keys), trust)
        app.close()

if __name__ == "__main__":
    unittest.main()
