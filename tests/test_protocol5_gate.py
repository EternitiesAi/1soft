from __future__ import annotations

import copy
import hashlib
import json
import sqlite3
from pathlib import Path
import tempfile
import unittest

from check_protocol5 import CONSENSUS_CHECKS, ENGINE_SHA256, validate_report


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


def completed(root: Path):
    observed = {
        "engine": ENGINE_SHA256,
        "worker": "2" * 64,
        "client": "3" * 64,
        "prover": "4" * 64,
        "profile": "5" * 64,
        "kat": "6" * 64,
        "toolchain": "7" * 64,
        "policy": "8" * 64,
        "genesis": "9" * 64,
    }
    receipts = []
    for node in range(4):
        for role, digest in (
                ("engine", observed["engine"]),
                ("application", "a" * 64),
                ("verifier-worker", observed["worker"])):
            receipts.append({
                "role": role, "node": node, "pid": 100 + len(receipts),
                "start_ticks": 200 + len(receipts),
                "executable_sha256": digest, "exit_code": 0,
            })
    for role, digest in (
            ("development-client-genesis", observed["client"]),
            ("development-client-spend", observed["client"]),
            ("development-prover", observed["prover"])):
        receipts.append({
            "role": role, "node": None, "pid": 100 + len(receipts),
            "start_ticks": 200 + len(receipts),
            "executable_sha256": digest, "exit_code": 0,
        })

    artifacts = root / "report.json.artifacts"
    artifacts.mkdir()
    rows = []
    for node in range(4):
        name = f"state{node}.sqlite"
        path = artifacts / name
        database = sqlite3.connect(path)
        try:
            database.execute(
                "CREATE TABLE committed("
                "id INTEGER PRIMARY KEY, height INTEGER, app_hash TEXT)")
            database.execute(
                "INSERT INTO committed VALUES(1, ?, ?)",
                (9, "b" * 64))
            database.commit()
        finally:
            database.close()
        raw = path.read_bytes()
        rows.append({
            "name": name, "sha256": hashlib.sha256(raw).hexdigest(),
            "bytes": len(raw), "truncated": False, "height": 9,
            "app_hash": "b" * 64,
        })
    (artifacts / "manifest.json").write_text(
        json.dumps(rows, indent=2, sort_keys=True) + "\n", encoding="utf-8")

    value = unassessed()
    value.update(
        status="completed-awaiting-external-validation", missing_inputs=[],
        processes_started=True, actual_proof_accepted=True,
        source_commit="c" * 40, source_tree="d" * 40,
        source_dirty=False, source_dirty_before=False, source_dirty_after=False,
        engine_version="0.38.25", observed_sha256=observed,
        inputs={name: f"/private/{name}" for name in observed},
        genesis_sha256="e" * 64, profile_id="f" * 64,
        deployment_id="1" * 64, processes=receipts, artifacts=rows,
        state_sync_observed=False,
        checks=[{"id": name, "passed": True} for name in CONSENSUS_CHECKS],
    )
    return value, artifacts


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

    def test_completed_status_binds_source_processes_and_artifacts(self):
        with tempfile.TemporaryDirectory() as td:
            value, artifacts = completed(Path(td))
            self.assertTrue(validate_report(
                value, artifact_directory=artifacts)["qualified"])
            for mutation in ("dirty", "receipts", "source", "artifact"):
                changed = copy.deepcopy(value)
                if mutation == "dirty":
                    changed["source_dirty"] = True
                elif mutation == "receipts":
                    changed["processes"][0]["executable_sha256"] = "0" * 64
                elif mutation == "source":
                    changed["source_tree"] = "not-a-tree"
                else:
                    (artifacts / "state0.sqlite").write_bytes(b"changed")
                with self.subTest(mutation=mutation), self.assertRaises(ValueError):
                    validate_report(changed, artifact_directory=artifacts)
                if mutation == "artifact":
                    raw = b"database-0"
                    (artifacts / "state0.sqlite").write_bytes(raw)

    def test_completed_status_requires_artifact_directory(self):
        with tempfile.TemporaryDirectory() as td:
            value, _ = completed(Path(td))
            with self.assertRaises(ValueError):
                validate_report(value)


if __name__ == "__main__":
    unittest.main()