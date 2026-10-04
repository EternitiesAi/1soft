from __future__ import annotations

import copy
import unittest

from check_protocol5 import CONSENSUS_CHECKS, validate_report

def unassessed():
    return {
        "schema": "1soft-protocol5-engine-preflight-v1",
        "status": "unassessed",
        "profile": "consensus",
        "missing_inputs": ["worker"],
        "failures": [],
        "checks": [],
        "processes_started": False,
        "state_sync_observed": False,
        "actual_proof_accepted": False,
        "public_network_ready": False,
        "real_funds_ready": False,
        "cryptographic_review_complete": False,
    }

class Protocol5GateTests(unittest.TestCase):
    def test_truthful_unassessed_report_is_accepted_as_unassessed(self):
        result = validate_report(unassessed())
        self.assertEqual(result["status"], "unassessed")
        self.assertFalse(result["qualified"])

    def test_unassessed_cannot_claim_proof_or_hide_missing_inputs(self):
        for mutation in ("proof", "missing", "leak"):
            value = unassessed()
            if mutation == "proof":
                value["actual_proof_accepted"] = True
            elif mutation == "missing":
                value["missing_inputs"] = []
            else:
                value["witness"] = "secret"
            with self.subTest(mutation=mutation), self.assertRaises(ValueError):
                validate_report(value)

    def test_completed_status_requires_exact_real_gate_checks(self):
        value = unassessed()
        value.update(status="completed-awaiting-external-validation",
                     missing_inputs=[], processes_started=True)
        with self.assertRaises(ValueError):
            validate_report(value)

    def test_completed_status_requires_clean_source_and_process_receipts(self):
        value = unassessed()
        receipts = []
        for node in range(4):
            for role in ("engine", "application", "verifier-worker"):
                receipts.append({
                    "role": role, "node": node, "pid": 100 + len(receipts),
                    "start_ticks": 200 + len(receipts),
                    "executable_sha256": "1" * 64,
                })
        value.update(
            status="completed-awaiting-external-validation", missing_inputs=[],
            processes_started=True, actual_proof_accepted=True,
            source_dirty=False, state_sync_observed=False, processes=receipts,
            checks=[{"id": name, "passed": True} for name in CONSENSUS_CHECKS],
        )
        self.assertTrue(validate_report(value)["qualified"])
        for mutation in ("dirty", "receipts"):
            changed = copy.deepcopy(value)
            if mutation == "dirty":
                changed["source_dirty"] = True
            else:
                changed["processes"] = changed["processes"][:-1]
            with self.subTest(mutation=mutation), self.assertRaises(ValueError):
                validate_report(changed)

if __name__ == "__main__":
    unittest.main()
