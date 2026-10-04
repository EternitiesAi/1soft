#!/usr/bin/env python3
"""Fail-closed checker for Protocol 5 private qualification reports."""
from __future__ import annotations

import argparse
from contextlib import closing
import hashlib
import json
from pathlib import Path
import sqlite3
import stat

ENGINE_SHA256 = "218628da07bed5d27e178d38d0bef9ecf46f21b214c8e9fea402fd215fccc024"
INPUT_NAMES = {
    "engine", "worker", "client", "prover", "profile", "kat",
    "toolchain", "policy", "genesis",
}
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


def _hex(value, size: int, name: str) -> str:
    _need(type(value) is str and len(value) == size
          and all(ch in "0123456789abcdef" for ch in value),
          "invalid Protocol 5 " + name)
    return value


def _scan(value, path="report"):
    if isinstance(value, dict):
        for key, item in value.items():
            _need(type(key) is str and key.lower() not in FORBIDDEN_KEYS,
                  "private Protocol 5 material in public report: " + path)
            _scan(item, path + "." + key)
    elif isinstance(value, list):
        for index, item in enumerate(value):
            _scan(item, path + "." + str(index))


def _process_receipts(value: dict, profile: str, observed: dict) -> None:
    rows = value.get("processes")
    _need(type(rows) is list, "missing Protocol 5 process receipts")
    expected_nodes = range(4 if profile == "consensus" else 5)
    expected_hashes = {
        "engine": observed["engine"],
        "verifier-worker": observed["worker"],
        "development-client-genesis": observed["client"],
        "development-client-spend": observed["client"],
        "development-prover": observed["prover"],
    }
    seen_roles = set()
    for row in rows:
        _need(type(row) is dict and set(row) >= {
            "role", "node", "pid", "start_ticks", "executable_sha256"
        }, "invalid Protocol 5 process receipt")
        role = row["role"]
        _need(role in {
            "engine", "application", "verifier-worker",
            "development-client-genesis", "development-client-spend",
            "development-prover",
        }, "unknown Protocol 5 process role")
        _need(type(row["pid"]) is int and row["pid"] > 0
              and type(row["start_ticks"]) is int and row["start_ticks"] > 0,
              "invalid Protocol 5 process identity")
        digest = _hex(
            row["executable_sha256"], 64, "process binary identity")
        if role in expected_hashes:
            _need(digest == expected_hashes[role],
                  "Protocol 5 process binary differs from observed input")
        if "exit_code" in row:
            _need(type(row["exit_code"]) is int,
                  "invalid Protocol 5 process exit code")
        seen_roles.add(role)
    for role in ("engine", "application", "verifier-worker"):
        observed_nodes = {row["node"] for row in rows if row["role"] == role}
        _need(observed_nodes == set(expected_nodes),
              "Protocol 5 process roster incomplete: " + role)
    _need({
        "development-client-genesis", "development-client-spend",
        "development-prover",
    } <= seen_roles, "Protocol 5 controller process roster incomplete")


def _source_binding(value: dict) -> dict:
    for name in ("source_commit", "source_tree"):
        _hex(value.get(name), 40, name)
    _need(value.get("source_dirty") is False
          and value.get("source_dirty_before") is False
          and value.get("source_dirty_after") is False,
          "completed Protocol 5 report has dirty source")
    _need(value.get("engine_version", "").lstrip("v") == "0.38.25",
          "Protocol 5 engine version differs")
    observed = value.get("observed_sha256")
    _need(type(observed) is dict and set(observed) == INPUT_NAMES,
          "Protocol 5 observed input roster differs")
    for name, digest in observed.items():
        _hex(digest, 64, name + " SHA-256")
    _need(observed["engine"] == ENGINE_SHA256,
          "Protocol 5 engine binary differs")
    inputs = value.get("inputs")
    _need(type(inputs) is dict and set(inputs) == INPUT_NAMES
          and all(type(path) is str and path for path in inputs.values()),
          "Protocol 5 input path roster differs")
    for name in ("genesis_sha256", "profile_id", "deployment_id"):
        _hex(value.get(name), 64, name)
    return observed


def _artifact_receipts(
        value: dict, profile: str, artifact_directory: Path | None) -> None:
    _need(artifact_directory is not None,
          "completed Protocol 5 report lacks artifact directory")
    root = Path(artifact_directory)
    mode = root.lstat()
    _need(stat.S_ISDIR(mode.st_mode) and not stat.S_ISLNK(mode.st_mode),
          "unsafe Protocol 5 artifact directory")
    rows = value.get("artifacts")
    _need(type(rows) is list and rows, "missing Protocol 5 artifacts")
    names = [row.get("name") for row in rows if type(row) is dict]
    _need(len(names) == len(rows) == len(set(names))
          and all(type(name) is str and name == Path(name).name and name
                  not in {".", "..", "manifest.json"} for name in names),
          "invalid Protocol 5 artifact names")
    expected_states = {
        f"state{index}.sqlite"
        for index in range(4 if profile == "consensus" else 5)
    }
    _need(expected_states <= set(names),
          "Protocol 5 retained database roster differs")
    for row in rows:
        _need(set(row) >= {"name", "sha256", "bytes", "truncated"},
              "invalid Protocol 5 artifact receipt")
        path = root / row["name"]
        file_mode = path.lstat()
        _need(stat.S_ISREG(file_mode.st_mode) and not stat.S_ISLNK(file_mode.st_mode),
              "unsafe Protocol 5 artifact")
        raw = path.read_bytes()
        _need(type(row["bytes"]) is int and row["bytes"] == len(raw)
              and _hex(row["sha256"], 64, "artifact SHA-256")
              == hashlib.sha256(raw).hexdigest()
              and type(row["truncated"]) is bool,
              "Protocol 5 artifact identity differs")
        if row["name"] in expected_states:
            _need(set(row) >= {"height", "app_hash"}
                  and type(row["height"]) is int and row["height"] >= 0,
                  "invalid retained Protocol 5 checkpoint")
            expected_hash = _hex(
                row["app_hash"], 64, "artifact AppHash")
            with closing(sqlite3.connect(
                    f"file:{path}?mode=ro&immutable=1", uri=True)) as database:
                _need(database.execute(
                    "PRAGMA integrity_check").fetchone() == ("ok",),
                    "retained Protocol 5 database is corrupt")
                committed = database.execute(
                    "SELECT height, app_hash FROM committed WHERE id=1").fetchone()
            _need(committed == (row["height"], expected_hash),
                  "retained Protocol 5 checkpoint receipt differs")
    manifest = root / "manifest.json"
    manifest_mode = manifest.lstat()
    _need(stat.S_ISREG(manifest_mode.st_mode)
          and not stat.S_ISLNK(manifest_mode.st_mode),
          "missing Protocol 5 artifact manifest")
    _need(json.loads(manifest.read_text(encoding="utf-8")) == rows,
          "Protocol 5 artifact manifest differs")
    expected_files = set(names) | {"manifest.json"}
    _need({path.name for path in root.iterdir()} == expected_files,
          "unexpected Protocol 5 artifact file")


def validate_report(
        value: dict, *, artifact_directory: Path | None = None) -> dict:
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
          and value["actual_proof_accepted"],
          "completed Protocol 5 report lacks real execution")
    _need(value["state_sync_observed"] is (profile == "state-sync"),
          "Protocol 5 state-sync observation claim differs")
    observed = _source_binding(value)
    _process_receipts(value, profile, observed)
    _artifact_receipts(value, profile, artifact_directory)
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
    checked = validate_report(
        value,
        artifact_directory=args.report.with_name(args.report.name + ".artifacts"))
    print(json.dumps(checked, sort_keys=True))
    return 0 if checked["qualified"] else 2


if __name__ == "__main__":
    raise SystemExit(main())
