#!/usr/bin/env python3
"""Complete baseline + private component + real private acceptance qualification.

No downloads, deployments, public listeners or spending authorization. Tests and
source-byte identity do not provide independent security or production custody.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import uuid

sys.dont_write_bytecode = True
ROOT = Path(__file__).resolve().parents[3]
IMPORT_PATHS = [ROOT / "src", ROOT / "scripts", ROOT / "tests",
                ROOT / "tools/private-payments/scripts"] + sorted((ROOT / "tools").glob("*/src"))
sys.path[:0] = [str(path) for path in IMPORT_PATHS]
import release_check as legacy

PARENT = "d14165df5476a617bb3048e61bb80b9767722eac"
PARENT_FILES = 445
PIN_SHA = legacy.PIN_SHA
GROUP = "private_payments"
MAX_REPORT_BYTES = 4 * 1024 * 1024
BASELINE_GATES = ("inherited-components", "client-components", "wallet-components",
    "delivery-components", "recovery-components", "explorer-components", "receipts-components",
    "local-components", "p4-baseline", "p4-delivery", "p4-ledger-receipts",
    "bootstrap-after-turnover", "commit-reply-loss-at-emission", "local-product", "local-cli")
ROW_FIELDS = {"path", "mode", "git_blob", "bytes", "sha256"}


def require(condition, message="private qualification refused"):
    if not condition: raise ValueError(message)


def reduced(source):
    return {key: source[key] for key in ("commit", "tree", "source_id", "tracked_files")}


def _pairs(rows):
    result = {}
    for key, value in rows:
        require(key not in result, "duplicate report field")
        result[key] = value
    return result


def _nonfinite(_):
    raise ValueError("nonfinite report value")


def read_report(path):
    path = Path(path)
    require(path.is_file() and not path.is_symlink() and path.stat().st_size <= MAX_REPORT_BYTES,
            "bounded regular report required")
    with path.open("rb") as file: raw = file.read(MAX_REPORT_BYTES + 1)
    require(0 < len(raw) <= MAX_REPORT_BYTES, "report exceeds bound")
    try:
        value = json.loads(raw, object_pairs_hook=_pairs, parse_constant=_nonfinite)
        require(type(value) is dict, "report object required")
        return value
    except (UnicodeError, RecursionError, OverflowError):
        raise ValueError("malformed report") from None


def _row(row):
    require(type(row) is dict and set(row) == ROW_FIELDS, "invalid parent source row")
    name = row["path"]
    require(type(name) is str and name and not Path(name).is_absolute() and
            ".." not in Path(name).parts and "\\" not in name, "unsafe source path")
    require(row["mode"] in ("100644", "100755") and
            type(row["bytes"]) is int and row["bytes"] >= 0, "source mode/size differs")
    for field, width in (("git_blob", 40), ("sha256", 64)):
        require(type(row[field]) is str and re.fullmatch("[0-9a-f]{%d}" % width, row[field]) is not None,
                "invalid source digest")


def verify_parent_inventory(identity, inventory, parent_rows):
    """Compare ALL d141 parent paths/modes/blobs/bytes/SHA256, never ancestry alone."""
    require(type(inventory) is dict and type(inventory.get("schema")) is int and
            inventory["schema"] == 1 and inventory.get("parent_commit") == PARENT,
            "wrong private parent inventory")
    rows = inventory.get("files")
    require(type(rows) is list and len(rows) == PARENT_FILES and
            type(parent_rows) is dict and len(parent_rows) == PARENT_FILES,
            "complete 445-file parent membership required")
    require(type(identity) is dict and type(identity.get("files")) is list, "source identity required")
    current = {row["path"]: row for row in identity["files"]}
    require(len(current) == len(identity["files"]), "duplicate current source path")
    seen = set()
    for row in rows:
        _row(row); name = row["path"]
        require(name not in seen, "duplicate parent inventory path"); seen.add(name)
        require(current.get(name) == row and parent_rows.get(name) == (row["mode"], row["git_blob"]),
                "inherited source byte/blob/mode changed")
    require(seen == set(parent_rows), "pinned parent membership differs")
    return len(seen)


def source_checked(expected=None):
    # Existing exact source, older parent pins and local-platform manifest stay unchanged.
    identity = legacy.source_checked()
    require(subprocess.run(["git", "-C", str(ROOT), "merge-base", "--is-ancestor",
            PARENT, identity["commit"]], capture_output=True, timeout=15).returncode == 0,
            "private parent is not an ancestor")
    parent_rows = {}
    for record in legacy.base.git(ROOT, "ls-tree", "-rz", "--full-tree", PARENT).split(b"\0"):
        if record:
            metadata, name = record.split(b"\t", 1)
            mode, kind, blob = metadata.decode("ascii").split()
            require(kind == "blob" and mode in ("100644", "100755"), "invalid parent file kind")
            parent_rows[name.decode("utf-8")] = (mode, blob)
    verify_parent_inventory(identity, read_report(ROOT / "tools/private-payments/DEPENDENCIES.json"), parent_rows)
    own = read_report(ROOT / "tools/private-payments/SOURCE_MANIFEST.json")
    require(type(own.get("schema")) is int and own["schema"] == 1 and
            type(own.get("files")) is list and own["files"], "private source inventory required")
    current = {row["path"]: row for row in identity["files"]}; names = set()
    for row in own["files"]:
        require(type(row) is dict and set(row) == {"path", "mode", "bytes", "sha256"},
                "invalid private source inventory row")
        name = row["path"]
        require(type(name) is str and name and not Path(name).is_absolute() and
                ".." not in Path(name).parts and "\\" not in name, "unsafe private source path")
        path = "tools/private-payments/" + name
        require(path not in names and path in current, "duplicate/missing private source"); names.add(path)
        inherited = current[path]
        require(all(row[key] == inherited[key] for key in ("mode", "bytes", "sha256")) and
                type(row["bytes"]) is int, "private source byte/mode changed")
    required = {row["path"] for row in identity["files"]
                if row["path"].startswith("tools/private-payments/") and
                not row["path"].endswith(("/SOURCE_MANIFEST.json", "/DEPENDENCIES.json"))}
    require(names == required, "private source inventory membership differs")
    if expected is not None: require(identity == expected, "source changed during private qualification")
    return identity


def child_report_matches(child, process, source, run_id):
    try:
        return (type(child) is dict and type(process) is dict and
            type(child.get("schema")) is int and child["schema"] == 1 and
            type(process.get("returncode")) is int and process["returncode"] == 0 and
            process.get("timed_out") is False and process.get("log_truncated") is False and
            child.get("group") == GROUP and child.get("source_id") == source["source_id"] and
            child.get("run_id") == run_id and child.get("source") == reduced(source) and
            child.get("source_after") == reduced(source) and child.get("source_unchanged") is True and
            child.get("passed") is True and legacy.base.successful(child))
    except (KeyError, TypeError, ValueError): return False


def _checks_match(checks, expected):
    return (type(checks) is list and type(expected) in (tuple, list) and bool(expected) and
            len(expected) == len(set(expected)) and all(type(name) is str and name for name in expected) and
            len(checks) == len(expected) and
            all(type(row) is dict and type(row.get("name")) is str and row["name"] and
                row.get("passed") is True for row in checks) and
            len({row["name"] for row in checks}) == len(checks) and
            {row["name"] for row in checks} == set(expected))


def baseline_report_matches(report, source):
    try:
        return (type(report) is dict and type(report.get("schema")) is int and report["schema"] == 1 and
            report.get("status") == "passed" and report.get("local_automated_qualification") is True and
            report.get("source_commit") == source["commit"] and report.get("source_tree") == source["tree"] and
            report.get("source_id") == source["source_id"] and
            type(report.get("source_tracked_files")) is int and
            report["source_tracked_files"] == source["tracked_files"] and
            report.get("source_identity_after") == reduced(source) and report.get("source_unchanged") is True and
            report.get("engine_sha256") == PIN_SHA and report.get("engine_unchanged") is True and
            type(report.get("python_tests")) is int and report["python_tests"] == 2069 and
            type(report.get("javascript_tests")) is int and report["javascript_tests"] == 38 and
            type(report.get("go_response_vectors")) is int and report["go_response_vectors"] == 4 and
            _checks_match(report.get("gates"), BASELINE_GATES))
    except (KeyError, TypeError, ValueError): return False


def acceptance_report_matches(report, source, run_id, expected_checks):
    try:
        return (type(report) is dict and type(report.get("schema")) is int and report["schema"] == 1 and
            report.get("status") == "passed" and report.get("run_id") == run_id and
            report.get("source") == reduced(source) and report.get("source_after") == reduced(source) and
            report.get("source_unchanged") is True and report.get("engine_version") == "0.38.25" and
            report.get("engine_sha256") == PIN_SHA and report.get("engine_sha256_after") == PIN_SHA and
            report.get("consensus_executed") is True and report.get("source_qualified") is True and
            type(report.get("validator_count")) is int and report["validator_count"] == 4 and
            all(report.get(field) is False for field in
                ("real_funds", "public_network", "onchain_privacy", "independent_hosts")) and
            type(report.get("owned_processes_after_cleanup")) is int and
            report["owned_processes_after_cleanup"] == 0 and
            type(report.get("owned_threads_after_cleanup")) is int and
            report["owned_threads_after_cleanup"] == 0 and
            type(report.get("cleanup_errors")) is list and not report["cleanup_errors"] and
            _checks_match(report.get("checks"), expected_checks))
    except (KeyError, TypeError, ValueError): return False


def _output_directory(output):
    output = Path(os.path.abspath(output))
    require(not output.is_relative_to(ROOT), "qualification output must be outside source")
    for parent in (output.parent, *output.parent.parents):
        require(not parent.is_symlink(), "aliased output parent refused")
    output.mkdir(mode=0o700, exist_ok=False)
    return output


def qualify(engine, output):
    """Run the unchanged complete release once, then isolated private gates."""
    output = _output_directory(output)
    report = {"schema": 1, "status": "running", "run_id": uuid.uuid4().hex,
        "source": None, "source_after": None, "source_unchanged": False,
        "engine_required_sha256": PIN_SHA, "engine_sha256": None, "engine_sha256_after": None,
        "engine_version": None, "engine_unchanged": False,
        "python_tests": 0, "javascript_tests": 0, "go_response_vectors": 0,
        "gates": [{"name": name, "status": "unassessed", "passed": False}
                  for name in ("baseline", "private-components", "private-consensus")],
        "local_automated_qualification": False, "consensus_executed": False,
        "owned_processes_after_cleanup": None, "owned_threads_after_cleanup": None,
        "cleanup_errors": None, "onchain_privacy": False,
        "independent_security_review": False, "production_custody": False,
        "public_release_ready": False, "real_funds_ready": False,
        "spending_or_deployment_authorized": False,
        "unassessed": ["ledger privacy/proofs and anonymity", "independent security/custody review",
            "independent hosts and public network", "rendered UI/human/mobile acceptance",
            "production key recovery and copied journals", "long history/trust renewal beyond P4 bounds"]}
    legacy.base.store_json(output / "started.json", report)
    stage = None
    def progress():
        legacy.base.store_json(output / "progress.json", report, replace=(output / "progress.json").exists())
    def checked():
        source_checked(source); legacy.verify_engine(binary)
    def retained(name, value, path):
        saved = read_report(path); require(saved == value, "returned/retained gate reports differ")
        gate = next(row for row in report["gates"] if row["name"] == name)
        gate.update(result_path=str(path.relative_to(output)), result_sha256=hashlib.sha256(path.read_bytes()).hexdigest())
        return gate
    try:
        source = source_checked(); report["source"] = reduced(source)
        legacy.base.store_json(output / "source.json", source)
        binary = legacy.verify_engine(engine)
        report.update(engine_sha256=PIN_SHA, engine_version="0.38.25")
        stage = "baseline"; checked()
        baseline = legacy.qualify(binary, output / "baseline")
        gate = retained(stage, baseline, output / "baseline/result.json")
        gate.update(status=baseline.get("status", "failed"),
                    passed=baseline_report_matches(baseline, source))
        progress(); require(gate["passed"], "complete baseline did not qualify"); checked()
        report.update(python_tests=baseline["python_tests"], javascript_tests=baseline["javascript_tests"],
                      go_response_vectors=baseline["go_response_vectors"])
        stage = "private-components"; checked()
        result_path = output / "private-components.json"
        process = legacy.base.run_process([sys.executable, str(ROOT / "tools/private-payments/scripts/private_test_worker.py"),
            "--output", str(result_path), "--source-json", str(output / "source.json"),
            "--source-id", source["source_id"], "--run-id", report["run_id"]],
            ROOT, output / "private-components.log", 600)
        gate = next(row for row in report["gates"] if row["name"] == stage)
        gate["process"] = process
        child = read_report(result_path)
        gate.update(result_path=str(result_path.relative_to(output)),
                    result_sha256=hashlib.sha256(result_path.read_bytes()).hexdigest(),
                    status="passed" if child_report_matches(child, process, source, report["run_id"]) else "failed",
                    passed=child_report_matches(child, process, source, report["run_id"]))
        progress(); require(gate["passed"], "private component tests did not qualify"); checked()
        report["python_tests"] += child["run"]
        stage = "private-consensus"; checked()
        from private_acceptance import PRIVATE_CHECKS, run_private
        private = run_private(binary, output / "private-consensus", source=source, run_id=report["run_id"])
        gate = retained(stage, private, output / "private-consensus/result.json")
        gate.update(status=private.get("status", "failed"),
                    passed=acceptance_report_matches(private, source, report["run_id"], PRIVATE_CHECKS))
        report["owned_processes_after_cleanup"] = private.get("owned_processes_after_cleanup")
        report["owned_threads_after_cleanup"] = private.get("owned_threads_after_cleanup")
        report["cleanup_errors"] = private.get("cleanup_errors")
        report["consensus_executed"] = private.get("consensus_executed") is True
        progress(); require(gate["passed"], "real private acceptance did not qualify"); checked()
        report.update(status="passed", local_automated_qualification=True, source_after=reduced(source),
                      source_unchanged=True, engine_sha256_after=PIN_SHA, engine_unchanged=True)
    except BaseException as exc:
        report.update(status="failed", error_type=type(exc).__name__)
        if stage is None: report["preflight"] = {"passed": False, "error_type": type(exc).__name__}
        else:
            gate = next(row for row in report["gates"] if row["name"] == stage)
            gate.update(status="failed", passed=False, error_type=type(exc).__name__)
    report["unassessed_gates"] = [row["name"] for row in report["gates"] if row["status"] == "unassessed"]
    legacy.base.store_json(output / "result.json", report)
    return report


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--engine", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    try: report = qualify(args.engine, args.output)
    except BaseException as exc:
        print(json.dumps({"schema": 1, "status": "refused", "error_type": type(exc).__name__}), flush=True)
        return 1
    print(json.dumps(report, indent=2, sort_keys=True), flush=True)
    return 0 if report["status"] == "passed" else 1


if __name__ == "__main__": raise SystemExit(main())

