#!/usr/bin/env python3
"""Fail-closed checker for Protocol 5 private qualification reports."""
from __future__ import annotations

import argparse
import json
from pathlib import Path

CONSENSUS_CHECKS = (
    "four-validator-init", "actual-proof-commit", "randomized-proof-conflict",
    "post-commit-replay-refusal", "global-nullifier-output-uniqueness",
    "same-root-sequential-appends", "same-block-root-freeze",
    "unknown-root-refusal", "validity-boundaries", "signed-next-header",
    "worker-kill-stall", "atomic-commit-faults", "application-engine-restart",
    "four-equal-power-quorum", "three-validator-continuation",
    "identity-proof-validator-hash-faults", "worker-sandbox-probes",
    "secret-leakage-scan",
)
STATE_SYNC_CHECKS = (
    "four-source-never-started-target", "trusted-apphash-replay",
    "marker-no-historical-responses", "post-sync-continuation",
    "same-store-restart", "duplicate-final-reoffer",
    "rollback-refusal", "hostile-offer-chunk-matrix",
)
FORBIDDEN_KEYS = {
    "witness", "witness_bytes", "spend_secret", "note_secret",
    "input_blinding", "output_blinding", "private_key", "unredacted",
}


def _need(condition: bool, message: str) -> None:
    if not condition:
        raise ValueError(message)


def _scan(value, path="report"):
    if isinstance(value, dict):
        for key, item in value.items():
            _need(type(key) is str and key.lower() not in FORBIDDEN_KEYS,
                  "private Protocol 5 material in public report: " + path)
            _scan(item, path + "." + key)
    elif isinstance(value, list):
        for index, item in enumerate(value):
            _scan(item, path + "." + str(index))


def _process_receipts(value: dict, profile: str) -> None:
    rows = value.get("processes")
    _need(type(rows) is list, "missing Protocol 5 process receipts")
    expected_nodes = range(4 if profile == "consensus" else 5)
    for row in rows:
        _need(type(row) is dict and set(row) >= {
            "role", "node", "pid", "start_ticks", "executable_sha256"
        }, "invalid Protocol 5 process receipt")
        _need(row["role"] in {
            "engine", "application", "verifier-worker",
            "development-client-genesis", "development-client-spend",
            "development-prover",
        }, "unknown Protocol 5 process role")
        _need(type(row["pid"]) is int and row["pid"] > 0
              and type(row["start_ticks"]) is int and row["start_ticks"] > 0,
              "invalid Protocol 5 process identity")
        digest = row["executable_sha256"]
        _need(type(digest) is str and len(digest) == 64
              and all(ch in "0123456789abcdef" for ch in digest),
              "invalid Protocol 5 process binary identity")
    for role in ("engine", "application", "verifier-worker"):
        observed = {row["node"] for row in rows if row["role"] == role}
        _need(observed == set(expected_nodes),
              "Protocol 5 process roster incomplete: " + role)


def validate_report(value: dict) -> dict:
    _need(type(value) is dict, "Protocol 5 report must be an object")
    _scan(value)
    _need(value.get("schema") == "1soft-protocol5-engine-preflight-v1",
          "unknown Protocol 5 report schema")
    status = value.get("status")
    profile = value.get("profile")
    _need(status in {
        "unassessed", "failed", "completed-awaiting-external-validation"
    }, "invalid Protocol 5 report status")
    _need(profile in {"consensus", "state-sync"},
          "invalid Protocol 5 report profile")
    for name in (
        "actual_proof_accepted", "public_network_ready", "real_funds_ready",
        "cryptographic_review_complete", "processes_started", "state_sync_observed",
    ):
        _need(type(value.get(name)) is bool, "missing Protocol 5 evidence boolean")
    _need(value["public_network_ready"] is False
          and value["real_funds_ready"] is False
          and value["cryptographic_review_complete"] is False,
          "unsupported Protocol 5 production claim")
    missing = value.get("missing_inputs")
    failures = value.get("failures")
    checks = value.get("checks")
    _need(type(missing) is list and all(type(item) is str and item for item in missing),
          "invalid Protocol 5 missing-input evidence")
    _need(type(failures) is list and all(type(item) is str and item for item in failures),
          "invalid Protocol 5 failure evidence")
    _need(type(checks) is list, "invalid Protocol 5 check evidence")
    if status == "unassessed":
        _need(bool(missing) and not failures and checks == []
              and value["processes_started"] is False
              and value["actual_proof_accepted"] is False,
              "unassessed Protocol 5 report overclaims or lacks exact missing input")
        return {"status": status, "profile": profile, "qualified": False,
                "missing_inputs": list(missing)}
    if status == "failed":
        _need(bool(failures),
              "failed Protocol 5 report lacks failure evidence")
        return {"status": status, "profile": profile, "qualified": False,
                "failures": list(failures)}
    expected = CONSENSUS_CHECKS if profile == "consensus" else STATE_SYNC_CHECKS
    _need(not missing and not failures and value["processes_started"]
          and value["actual_proof_accepted"]
          and value.get("source_dirty") is False,
          "completed Protocol 5 report lacks real execution")
    _need(value["state_sync_observed"] is (profile == "state-sync"),
          "Protocol 5 state-sync observation claim differs")
    _process_receipts(value, profile)
    _need(len(checks) == len(expected)
          and sorted(item.get("id") for item in checks) == sorted(expected)
          and all(type(item) is dict and set(item) >= {"id", "passed"}
                  and item["passed"] is True and "skipped" not in item
                  for item in checks),
          "completed Protocol 5 checks are missing, skipped, or changed")
    return {"status": status, "profile": profile, "qualified": True,
            "check_ids": list(expected)}


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("report", type=Path)
    args = parser.parse_args()
    value = json.loads(args.report.read_text(encoding="utf-8"))
    checked = validate_report(value)
    print(json.dumps(checked, sort_keys=True))
    return 0 if checked["qualified"] else 2


if __name__ == "__main__":
    raise SystemExit(main())
