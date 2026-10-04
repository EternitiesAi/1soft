from __future__ import annotations

import copy
import hashlib
import json
import sqlite3
from pathlib import Path
import tempfile
import unittest

from check_protocol5 import (
    CONSENSUS_CHECKS, ENGINE_SHA256, STATE_SYNC_CHECKS,
    STATE_SYNC_EVENT_NAME, STATE_SYNC_HOSTILE_EVIDENCE, validate_report,
)


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


def completed(root: Path, profile: str = "consensus"):
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
    nodes = 4 if profile == "consensus" else 5
    for node in range(nodes):
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
    crash_identity = None
    restart_identity = None
    if profile == "state-sync":
        restart = next(
            row for row in receipts
            if row["role"] == "application" and row["node"] == 4)
        restart_identity = (restart["pid"], restart["start_ticks"])
        crash = {
            "role": "application", "node": 4,
            "pid": 100 + len(receipts), "start_ticks": 200 + len(receipts),
            "executable_sha256": "a" * 64, "exit_code": 96,
        }
        receipts.append(crash)
        crash_identity = (crash["pid"], crash["start_ticks"])

    artifacts = root / "report.json.artifacts"
    artifacts.mkdir()
    rows = []
    for node in range(nodes):
        name = f"state{node}.sqlite"
        path = artifacts / name
        database = sqlite3.connect(path)
        try:
            database.execute("PRAGMA journal_mode=WAL")
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
    if profile == "state-sync":
        event_path = artifacts / STATE_SYNC_EVENT_NAME
        assert crash_identity is not None and restart_identity is not None
        offer = {
            "kind": "offer_snapshot", "height": 9, "format": 1, "chunks": 2,
            "snapshot_hash": "1" * 64, "trusted_app_hash": "b" * 64,
            "result": 1,
        }
        events = [
            {**offer, "pid": crash_identity[0],
             "start_ticks": crash_identity[1]},
            {"kind": "apply_snapshot_chunk", "pid": crash_identity[0],
             "start_ticks": crash_identity[1], "height": 0,
             "index": 0, "result": 1},
            {"kind": "after_snapshot_commit", "pid": crash_identity[0],
             "start_ticks": crash_identity[1], "height": 9},
            {**offer, "pid": restart_identity[0],
             "start_ticks": restart_identity[1]},
            {"kind": "apply_snapshot_chunk", "pid": restart_identity[0],
             "start_ticks": restart_identity[1], "height": 9,
             "index": 0, "result": 1},
            {"kind": "after_snapshot_commit", "pid": restart_identity[0],
             "start_ticks": restart_identity[1], "height": 9},
            {"kind": "apply_snapshot_chunk", "pid": restart_identity[0],
             "start_ticks": restart_identity[1], "height": 9,
             "index": 1, "result": 1},
        ]
        event_raw = b"".join(
            (json.dumps(row, sort_keys=True, separators=(",", ":")) + "\n")
            .encode("utf-8") for row in events)
        event_path.write_bytes(event_raw)
        rows.append({
            "name": STATE_SYNC_EVENT_NAME,
            "sha256": hashlib.sha256(event_raw).hexdigest(),
            "bytes": len(event_raw), "truncated": False,
        })
    (artifacts / "manifest.json").write_text(
        json.dumps(rows, indent=2, sort_keys=True) + "\n", encoding="utf-8")

    checks = [
        {"id": name, "passed": True, "evidence": {}}
        for name in (CONSENSUS_CHECKS if profile == "consensus"
                     else STATE_SYNC_CHECKS)
    ]
    if profile == "state-sync":
        next(row for row in checks if row["id"] == "duplicate-final-reoffer")[
            "evidence"] = {
                "snapshot_height": 9, "accepted_offers": 2,
                "duplicate_final_result": 1, "crash_exit_code": 96,
            }
        next(row for row in checks if row["id"] == "trusted-apphash-replay")[
            "evidence"] = {"height": 9}
        next(row for row in checks if row["id"] == "hostile-offer-chunk-matrix")[
            "evidence"] = {"subcases": copy.deepcopy(STATE_SYNC_HOSTILE_EVIDENCE)}

    value = unassessed()
    value.update(
        status="completed-awaiting-external-validation", missing_inputs=[],
        processes_started=True, actual_proof_accepted=True,
        profile=profile,
        source_commit="c" * 40, source_tree="d" * 40,
        source_dirty=False, source_dirty_before=False, source_dirty_after=False,
        engine_version="0.38.25", observed_sha256=observed,
        inputs={name: f"/private/{name}" for name in observed},
        genesis_sha256="e" * 64, profile_id="f" * 64,
        deployment_id="1" * 64, processes=receipts, artifacts=rows,
        state_sync_observed=profile == "state-sync", checks=checks,
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
            expected_files = {path.name for path in artifacts.iterdir()}
            self.assertFalse(any(
                name.endswith(("-wal", "-shm")) for name in expected_files))
            self.assertTrue(validate_report(
                value, artifact_directory=artifacts)["qualified"])
            self.assertEqual(
                {path.name for path in artifacts.iterdir()}, expected_files)
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

    def test_state_sync_binds_each_hostile_case_and_final_apply_reoffer(self):
        with tempfile.TemporaryDirectory() as td:
            value, artifacts = completed(Path(td), "state-sync")
            self.assertTrue(validate_report(
                value, artifact_directory=artifacts)["qualified"])

        mutations = [
            "hostile_case", "exit96", "first_commit", "first_reply",
            "reoffer", "completion_height", "completion_index",
        ]
        for mutation in mutations:
            with self.subTest(mutation=mutation), tempfile.TemporaryDirectory() as td:
                value, artifacts = completed(Path(td), "state-sync")
                if mutation == "hostile_case":
                    hostile = next(row for row in value["checks"]
                                   if row["id"] == "hostile-offer-chunk-matrix")
                    hostile["evidence"]["subcases"].pop("altered_proof")
                elif mutation == "exit96":
                    for row in value["processes"]:
                        if row["role"] == "application" and row["node"] == 4:
                            row["exit_code"] = 0
                else:
                    path = artifacts / STATE_SYNC_EVENT_NAME
                    events = [json.loads(line) for line in path.read_text().splitlines()]
                    if mutation == "first_commit":
                        events.pop(2)
                    elif mutation == "first_reply":
                        events.insert(3, {
                            "kind": "apply_snapshot_chunk",
                            "pid": events[0]["pid"],
                            "start_ticks": events[0]["start_ticks"],
                            "height": 9, "index": 1, "result": 1,
                        })
                    elif mutation == "reoffer":
                        events.pop(3)
                    elif mutation == "completion_height":
                        events[-1]["height"] = 10
                    else:
                        events[-1]["index"] = -1
                    raw = b"".join(
                        (json.dumps(row, sort_keys=True, separators=(",", ":")) + "\n")
                        .encode("utf-8") for row in events)
                    path.write_bytes(raw)
                    receipt = next(row for row in value["artifacts"]
                                   if row["name"] == STATE_SYNC_EVENT_NAME)
                    receipt.update(
                        bytes=len(raw), sha256=hashlib.sha256(raw).hexdigest())
                    (artifacts / "manifest.json").write_text(
                        json.dumps(value["artifacts"], indent=2, sort_keys=True) + "\n",
                        encoding="utf-8")
                with self.assertRaises(ValueError):
                    validate_report(value, artifact_directory=artifacts)


if __name__ == "__main__":
    unittest.main()
