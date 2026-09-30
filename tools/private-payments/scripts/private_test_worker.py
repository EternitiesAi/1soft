#!/usr/bin/env python3
"""Isolated private-payments tests with complete IDs and shared source/run provenance."""
from __future__ import annotations

import argparse
import hashlib
import os
from pathlib import Path
import re
import sys

sys.dont_write_bytecode = True
ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(ROOT / "tools/private-payments/scripts"))
from qualify_private import (GROUP, child_report_matches, legacy, read_report,
                             reduced, require, source_checked)
base = legacy.base


def run(output, source_json, source_id, run_id):
    output = Path(os.path.abspath(output))
    require(not output.is_relative_to(ROOT), "worker output must be outside source")
    for parent in (output.parent, *output.parent.parents):
        require(not parent.is_symlink(), "worker output parent alias refused")
    require(not output.exists() and not output.is_symlink(), "worker output exists")
    child_path = output.with_name(output.stem + ".tests.json")
    require(not child_path.exists() and not child_path.is_symlink(), "test receipt exists")
    report = {"schema": 1, "group": GROUP, "source_id": None, "run_id": None,
        "source": None, "source_after": None, "source_unchanged": False,
        "expected_ids": [], "successful_ids": [], "run": 0,
        "skips": 0, "failures": 0, "errors": 0, "expected_failures": 0,
        "unexpected_successes": 0, "passed": False,
        "child_report_path": child_path.name, "child_report_sha256": None}
    original_groups = base.GROUPS
    try:
        require(type(source_id) is str and re.fullmatch("[0-9a-f]{64}", source_id) is not None and
                type(run_id) is str and re.fullmatch("[0-9a-f]{32}", run_id) is not None,
                "exact source/run identity required")
        report.update(source_id=source_id, run_id=run_id)
        expected = read_report(source_json)
        require(expected.get("source_id") == source_id, "supplied source identity differs")
        before = source_checked(expected)
        require(before == expected, "source identity before tests differs")
        report["source"] = reduced(before)
        paths = [ROOT / "tools/private-payments/src", ROOT / "tools/private-payments/scripts",
                 ROOT / "tools/private-payments/tests", ROOT / "src", ROOT / "scripts", ROOT / "tests"]
        paths += sorted((ROOT / "tools").glob("*/src"))
        paths += sorted((ROOT / "tools").glob("*/tests"))
        names = list(dict.fromkeys(str(path.relative_to(ROOT)) for path in paths))
        base.GROUPS = {GROUP: ("tools/private-payments/tests", "test_*.py", names)}
        code = base.worker(GROUP, child_path, source_id, run_id)
        report["child_report_sha256"] = hashlib.sha256(child_path.read_bytes()).hexdigest()
        child = read_report(child_path)
        # Preserve exact child counters/identities, even if final source attribution fails.
        report.update(child)
        report["passed"] = False
        report.update(source=reduced(before), source_after=None, source_unchanged=False,
                      child_report_path=child_path.name,
                      child_report_sha256=hashlib.sha256(child_path.read_bytes()).hexdigest())
        after = source_checked(expected)
        report["source_after"] = reduced(after)
        require(after == expected, "source changed during private tests")
        report["source_unchanged"] = True
        observed_process = {"returncode": code, "timed_out": False, "log_truncated": False}
        report["passed"] = child_report_matches({**child, "source": reduced(before),
            "source_after": reduced(after), "source_unchanged": True},
            observed_process, expected, run_id)
    except BaseException as exc:
        report.update(passed=False, error_type=type(exc).__name__)
        if child_path.is_file() and not child_path.is_symlink():
            report["child_report_sha256"] = hashlib.sha256(child_path.read_bytes()).hexdigest()
    finally:
        base.GROUPS = original_groups
    base.store_json(output, report)
    return 0 if report["passed"] is True else 1


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--source-json", type=Path, required=True)
    parser.add_argument("--source-id", required=True)
    parser.add_argument("--run-id", required=True)
    args = parser.parse_args()
    try: return run(args.output, args.source_json, args.source_id, args.run_id)
    except BaseException as exc:
        import json
        print(json.dumps({"schema": 1, "passed": False, "error_type": type(exc).__name__}), flush=True)
        return 1


if __name__ == "__main__": raise SystemExit(main())

