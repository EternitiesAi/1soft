from __future__ import annotations

import copy
from pathlib import Path
import sys
import unittest


ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(ROOT / "tools/privacy-proof-benchmark/src"))

from privacy_proof_benchmark import (  # noqa: E402
    EXPECTED_CASES,
    EXPECTED_CLAIMS,
    EXPECTED_PUBLIC_INPUTS,
    EXPECTED_UNASSESSED,
    QualificationError,
    load_unique_json_bytes,
    validate_backend_receipt,
)


COMMIT = "a" * 40
TREE = "b" * 40
CIRCUIT_DIGEST = "c" * 64


def valid_receipt():
    return {
        "format": 1,
        "status": "passed",
        "actual_backend_run": True,
        "backend": {
            "id": "gnark-groth16-bn254",
            "gnark": "v0.16.3",
            "gnark_crypto": "v0.21.0",
            "curve": "BN254",
            "proof_system": "Groth16",
            "hash": "Poseidon2",
            "license": "Apache-2.0",
        },
        "circuit": {
            "id": "1soft/privacy-proof-benchmark/v1",
            "source_digest": CIRCUIT_DIGEST,
            "constraints": 12345,
            "depth": 4,
            "inputs": 1,
            "outputs": 2,
            "value_bits": 64,
            "public_inputs": list(EXPECTED_PUBLIC_INPUTS),
            "private_inputs_retained": False,
        },
        "source": {"commit": COMMIT, "tree": TREE},
        "parameters": {
            "kind": "ephemeral-local-groth16-setup",
            "ceremony": False,
            "reusable": False,
            "production": False,
            "proving_key_sha256": "d" * 64,
            "proving_key_bytes": 400000,
            "verifying_key_sha256": "e" * 64,
            "verifying_key_bytes": 1000,
        },
        "artifacts": {
            "proof_sha256": "f" * 64,
            "proof_bytes": 256,
            "public_witness_sha256": "1" * 64,
            "public_witness_bytes": 384,
        },
        "metrics": {
            "compile_ns": 10,
            "setup_ns": 20,
            "iterations": 2,
            "prove_ns": [30, 31],
            "verify_ns": [4, 5],
        },
        "cases": [
            {"id": case_id, "expected": expected, "observed": expected}
            for case_id, expected in EXPECTED_CASES.items()
        ],
        "claims": dict(EXPECTED_CLAIMS),
        "unassessed": list(EXPECTED_UNASSESSED),
    }


class ReceiptContractTests(unittest.TestCase):
    def validate(self, receipt=None):
        return validate_backend_receipt(
            valid_receipt() if receipt is None else receipt,
            expected_commit=COMMIT,
            expected_tree=TREE,
            expected_circuit_digest=CIRCUIT_DIGEST,
        )

    def test_exact_actual_backend_receipt_passes(self):
        result = self.validate()
        self.assertEqual(result["status"], "passed")
        self.assertTrue(result["actual_backend_run"])
        self.assertEqual(result["circuit"]["constraints"], 12345)
        self.assertEqual([case["id"] for case in result["cases"]], list(EXPECTED_CASES))

    def test_top_level_missing_extra_and_boolean_format_are_refused(self):
        for mode in ("missing", "extra", "boolean-format"):
            with self.subTest(mode=mode):
                receipt = valid_receipt()
                if mode == "missing":
                    del receipt["artifacts"]
                elif mode == "extra":
                    receipt["proof"] = "secret bytes"
                else:
                    receipt["format"] = True
                with self.assertRaises(QualificationError):
                    self.validate(receipt)

    def test_only_a_real_successful_run_can_pass(self):
        for field, value in (("status", "failed"), ("actual_backend_run", False)):
            with self.subTest(field=field):
                receipt = valid_receipt()
                receipt[field] = value
                with self.assertRaises(QualificationError):
                    self.validate(receipt)

    def test_stack_source_and_circuit_identity_are_pinned(self):
        mutations = (
            ("backend", "gnark", "v0.16.2"),
            ("backend", "gnark_crypto", "v0.22.0"),
            ("backend", "hash", "MiMC"),
            ("circuit", "id", "other"),
            ("circuit", "source_digest", "0" * 64),
            ("source", "commit", "0" * 40),
            ("source", "tree", "0" * 40),
        )
        for section, field, value in mutations:
            with self.subTest(section=section, field=field):
                receipt = valid_receipt()
                receipt[section][field] = value
                with self.assertRaises(QualificationError):
                    self.validate(receipt)

    def test_public_statement_and_rejection_case_inventory_are_exact(self):
        receipt = valid_receipt()
        receipt["circuit"]["public_inputs"] = receipt["circuit"]["public_inputs"][:-1]
        with self.assertRaises(QualificationError):
            self.validate(receipt)

        for mode in ("missing", "duplicate", "unexpected", "false-pass"):
            with self.subTest(mode=mode):
                receipt = valid_receipt()
                if mode == "missing":
                    receipt["cases"].pop()
                elif mode == "duplicate":
                    receipt["cases"][-1] = copy.deepcopy(receipt["cases"][0])
                elif mode == "unexpected":
                    receipt["cases"][0]["id"] = "unknown-case"
                else:
                    receipt["cases"][1]["observed"] = "accept"
                with self.assertRaises(QualificationError):
                    self.validate(receipt)

    def test_measurements_and_artifact_bindings_require_positive_integers(self):
        mutations = (
            ("metrics", "compile_ns", 0),
            ("metrics", "setup_ns", -1),
            ("metrics", "iterations", True),
            ("metrics", "prove_ns", [30]),
            ("metrics", "verify_ns", [4, 0]),
            ("artifacts", "proof_bytes", 0),
            ("parameters", "proving_key_bytes", 0),
            ("parameters", "verifying_key_sha256", "not-a-digest"),
        )
        for section, field, value in mutations:
            with self.subTest(section=section, field=field):
                receipt = valid_receipt()
                receipt[section][field] = value
                with self.assertRaises(QualificationError):
                    self.validate(receipt)

    def test_nonclaims_and_ephemeral_setup_cannot_be_promoted(self):
        for field in EXPECTED_CLAIMS:
            with self.subTest(claim=field):
                receipt = valid_receipt()
                receipt["claims"][field] = True
                with self.assertRaises(QualificationError):
                    self.validate(receipt)
        for field in ("ceremony", "reusable", "production"):
            with self.subTest(parameter=field):
                receipt = valid_receipt()
                receipt["parameters"][field] = True
                with self.assertRaises(QualificationError):
                    self.validate(receipt)
        receipt = valid_receipt()
        receipt["circuit"]["private_inputs_retained"] = True
        with self.assertRaises(QualificationError):
            self.validate(receipt)

    def test_unassessed_boundary_is_exact_and_boolean_false_is_not_integer_zero(self):
        receipt = valid_receipt()
        receipt["unassessed"] = receipt["unassessed"][:-1]
        with self.assertRaises(QualificationError):
            self.validate(receipt)
        receipt = valid_receipt()
        receipt["claims"]["real_funds"] = 0
        with self.assertRaises(QualificationError):
            self.validate(receipt)

    def test_unique_json_loader_rejects_duplicate_and_nonfinite_numbers(self):
        with self.assertRaisesRegex(QualificationError, "duplicate JSON key"):
            load_unique_json_bytes(b'{"format":1,"format":1}')
        for value in (b'{"x":NaN}', b'{"x":Infinity}', b'{"x":-Infinity}'):
            with self.subTest(value=value):
                with self.assertRaises(QualificationError):
                    load_unique_json_bytes(value)

    def test_validator_does_not_mutate_caller_receipt(self):
        receipt = valid_receipt()
        before = copy.deepcopy(receipt)
        self.validate(receipt)
        self.assertEqual(receipt, before)


if __name__ == "__main__":
    unittest.main()
