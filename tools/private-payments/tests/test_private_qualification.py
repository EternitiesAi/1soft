"""Private qualification provenance predicates; these are synthetic reports, not consensus."""
import copy
import importlib.util
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
sys.path[:0] = [str(ROOT / "src"), str(ROOT / "scripts"),
                str(ROOT / "tools/local-platform/src"),
                str(ROOT / "tools/private-payments/scripts")] + [str(p) for p in sorted((ROOT / "tools").glob("*/src"))]
try:
    import qualify_private as module
except ImportError:
    module = None
try:
    import private_test_worker as private_worker
except ImportError:
    private_worker = None

SOURCE = {"commit": "a" * 40, "tree": "b" * 40, "source_id": "c" * 64, "tracked_files": 470}
RUN_ID = "d" * 32
PIN = "218628da07bed5d27e178d38d0bef9ecf46f21b214c8e9fea402fd215fccc024"


def child():
    return {"schema": 1, "group": "private_payments", "source_id": SOURCE["source_id"],
            "run_id": RUN_ID, "source": dict(SOURCE), "source_after": dict(SOURCE),
            "source_unchanged": True, "passed": True, "expected_ids": ["fixture.first", "fixture.second"],
            "successful_ids": ["fixture.first", "fixture.second"], "run": 2,
            "errors": 0, "failures": 0, "skips": 0, "expected_failures": 0, "unexpected_successes": 0}


def process():
    return {"returncode": 0, "timed_out": False, "log_truncated": False}


def acceptance():
    return {"schema": 1, "status": "passed", "run_id": RUN_ID, "source": dict(SOURCE),
            "source_after": dict(SOURCE), "source_unchanged": True, "engine_version": "0.38.25",
            "engine_sha256": PIN, "engine_sha256_after": PIN,
            "consensus_executed": True, "owned_processes_after_cleanup": 0,
            "owned_threads_after_cleanup": 0, "cleanup_errors": [],
            "source_qualified": True, "validator_count": 4, "real_funds": False, "public_network": False,
            "onchain_privacy": False, "independent_hosts": False,
            "checks": [{"name": "first", "passed": True}, {"name": "second", "passed": True}]}


def parent_fixture():
    rows = [{"path": "file-%03d.py" % i, "mode": "100644", "git_blob": "%040x" % (i + 1),
             "bytes": i, "sha256": "%064x" % (i + 1)} for i in range(445)]
    inventory = {"schema": 1, "parent_commit": "d14165df5476a617bb3048e61bb80b9767722eac",
                 "files": copy.deepcopy(rows)}
    identity = {"files": copy.deepcopy(rows), "tracked_files": 445}
    git_rows = {row["path"]: (row["mode"], row["git_blob"]) for row in rows}
    return identity, inventory, git_rows


class QualificationContracts(unittest.TestCase):
    def setUp(self):
        self.assertIsNotNone(module, "private qualification implementation is missing")

    def test_complete_exact_parent_membership_and_bytes_are_accepted(self):
        # Catches rejecting the actual inventory shape instead of comparing its source rows.
        self.assertEqual(module.verify_parent_inventory(*parent_fixture()), 445)

    def test_parent_membership_cannot_be_shortened_or_duplicate_filled(self):
        # Catches count-only checks and set comparisons that silently collapse duplicate rows.
        for change in ["missing", "duplicate", "new_path"]:
            identity, inventory, git_rows = parent_fixture()
            if change == "missing": inventory["files"].pop()
            elif change == "duplicate": inventory["files"][-1] = dict(inventory["files"][0])
            else: inventory["files"][-1]["path"] = "invented.py"
            with self.subTest(change=change), self.assertRaises(ValueError):
                module.verify_parent_inventory(identity, inventory, git_rows)

    def test_inherited_blob_mode_bytes_and_sha256_must_all_match(self):
        for field, value in [("mode", "100755"), ("git_blob", "f" * 40), ("bytes", 123456),
                             ("sha256", "f" * 64)]:
            identity, inventory, git_rows = parent_fixture()
            identity["files"][1][field] = value
            with self.subTest(field=field), self.assertRaises(ValueError):
                module.verify_parent_inventory(identity, inventory, git_rows)
        identity, inventory, git_rows = parent_fixture()
        git_rows["file-001.py"] = ("100644", "e" * 40)
        with self.assertRaises(ValueError):
            module.verify_parent_inventory(identity, inventory, git_rows)

    def test_wrong_parent_pin_and_malformed_inventory_are_refused(self):
        for field, value in [("schema", True), ("parent_commit", "f" * 40), ("files", None)]:
            identity, inventory, git_rows = parent_fixture()
            inventory[field] = value
            with self.subTest(field=field), self.assertRaises(ValueError):
                module.verify_parent_inventory(identity, inventory, git_rows)

    def test_valid_private_child_binds_complete_ids_source_and_shared_run(self):
        self.assertTrue(module.child_report_matches(child(), process(), SOURCE, RUN_ID))

    def test_missing_duplicate_skipped_or_partial_test_ids_fail_qualification(self):
        changes = [{"expected_ids": []}, {"successful_ids": ["fixture.first"]},
                   {"expected_ids": ["fixture.first", "fixture.first"]}, {"run": True},
                   {"run": 1}, {"skips": 1}, {"failures": 1}, {"errors": 1},
                   {"expected_failures": 1}, {"unexpected_successes": 1}, {"passed": 1}]
        for change in changes:
            with self.subTest(change=change):
                self.assertFalse(module.child_report_matches({**child(), **change}, process(), SOURCE, RUN_ID))

    def test_child_report_cannot_substitute_source_run_or_group(self):
        changes = [{"source_id": "e" * 64}, {"run_id": "e" * 32}, {"group": "native"},
                   {"schema": True}, {"source_unchanged": False},
                   {"source": {**SOURCE, "commit": "e" * 40}},
                   {"source_after": {**SOURCE, "source_id": "e" * 64}}]
        for change in changes:
            with self.subTest(change=change):
                self.assertFalse(module.child_report_matches({**child(), **change}, process(), SOURCE, RUN_ID))

    def test_child_exit_timeout_truncation_and_malformed_reports_fail(self):
        for change in [{"returncode": 1}, {"timed_out": True}, {"log_truncated": True},
                       {"returncode": False}]:
            with self.subTest(change=change):
                self.assertFalse(module.child_report_matches(child(), {**process(), **change}, SOURCE, RUN_ID))
        for value in [None, [], {}, {"schema": 1}]:
            with self.subTest(value=value):
                self.assertFalse(module.child_report_matches(value, process(), SOURCE, RUN_ID))

    def test_real_acceptance_report_requires_exact_check_membership(self):
        self.assertTrue(module.acceptance_report_matches(acceptance(), SOURCE, RUN_ID, ("first", "second")))
        for checks in [[], [{"name": "first", "passed": True}],
                       [{"name": "first", "passed": True}, {"name": "first", "passed": True}],
                       [{"name": "first", "passed": True}, {"name": "different", "passed": True}],
                       [{"name": "first", "passed": 1}, {"name": "second", "passed": True}]]:
            with self.subTest(checks=checks):
                self.assertFalse(module.acceptance_report_matches({**acceptance(), "checks": checks},
                                                                  SOURCE, RUN_ID, ("first", "second")))

    def test_acceptance_requires_real_execution_engine_and_zero_owned_processes(self):
        for field, value in [("status", "unassessed"), ("consensus_executed", False),
                             ("source_qualified", False), ("validator_count", 3),
                             ("real_funds", True), ("public_network", True),
                             ("onchain_privacy", True), ("independent_hosts", True),
                             ("owned_processes_after_cleanup", 1), ("owned_processes_after_cleanup", False),
                             ("owned_threads_after_cleanup", 1), ("owned_threads_after_cleanup", False),
                             ("cleanup_errors", ["merchant_shutdown_failed"]), ("cleanup_errors", None),
                             ("cleanup_errors", ()),
                             ("engine_version", "0.38.24"), ("engine_sha256", "e" * 64),
                             ("engine_sha256_after", None), ("source_unchanged", False),
                             ("source_after", {**SOURCE, "tree": "e" * 40}), ("run_id", "e" * 32)]:
            with self.subTest(field=field):
                self.assertFalse(module.acceptance_report_matches({**acceptance(), field: value},
                                                                  SOURCE, RUN_ID, ("first", "second")))

    def test_retained_report_parser_refuses_duplicate_and_nonfinite_json(self):
        import tempfile
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "report.json"
            for raw in [b'{"status":"passed","status":"failed"}', b'{"value":NaN}', b" " * (4 * 1024 * 1024 + 1)]:
                path.write_bytes(raw)
                with self.subTest(raw_size=len(raw)), self.assertRaises(ValueError):
                    module.read_report(path)
            path.write_bytes(b'{"status":"failed","seconds":0.125}\n')
            self.assertEqual(module.read_report(path), {"status": "failed", "seconds": 0.125})

    def test_baseline_report_is_not_accepted_from_another_or_incomplete_candidate(self):
        baseline = {"schema": 1, "status": "passed", "local_automated_qualification": True,
                    "source_commit": SOURCE["commit"], "source_tree": SOURCE["tree"],
                    "source_id": SOURCE["source_id"], "source_tracked_files": SOURCE["tracked_files"],
                    "source_identity_after": dict(SOURCE), "source_unchanged": True,
                    "engine_sha256": PIN, "engine_unchanged": True,
                    "python_tests": 2069, "javascript_tests": 38, "go_response_vectors": 4,
                    "gates": [{"name": name, "passed": True} for name in [
                        "inherited-components", "client-components", "wallet-components", "delivery-components",
                        "recovery-components", "explorer-components", "receipts-components", "local-components",
                        "p4-baseline", "p4-delivery", "p4-ledger-receipts", "bootstrap-after-turnover",
                        "commit-reply-loss-at-emission", "local-product", "local-cli"]]}
        self.assertTrue(module.baseline_report_matches(baseline, SOURCE))
        for change in [{"source_id": "e" * 64}, {"gates": []}, {"python_tests": 2068},
                       {"javascript_tests": 37}, {"go_response_vectors": 3}, {"source_unchanged": False},
                       {"local_automated_qualification": 1}]:
            with self.subTest(change=change):
                self.assertFalse(module.baseline_report_matches({**baseline, **change}, SOURCE))


    def test_worker_rejects_source_change_after_child_without_losing_its_report(self):
        # The slow/external group is a literal child receipt; assertions target the real outer report.
        import tempfile
        from unittest.mock import patch
        self.assertIsNotNone(private_worker, "private worker implementation is missing")
        worker = private_worker
        with tempfile.TemporaryDirectory() as directory:
            directory = Path(directory); source_path = directory / "source.json"
            import json
            source_path.write_text(json.dumps(SOURCE))
            output = directory / "worker.json"
            def fixture_child(group, path, source_id, run_id):
                module.legacy.base.store_json(path, child())
                return 0
            with patch.object(worker, "source_checked", side_effect=[dict(SOURCE), {**SOURCE, "tree": "e"*40}]), \
                 patch.object(worker.base, "worker", side_effect=fixture_child):
                self.assertEqual(worker.run(output, source_path, SOURCE["source_id"], RUN_ID), 1)
            result = module.read_report(output)
            self.assertFalse(result["passed"]); self.assertFalse(result["source_unchanged"])
            self.assertEqual(result["run"], 2)
            self.assertEqual(result["successful_ids"], ["fixture.first", "fixture.second"])
            self.assertTrue((directory / "worker.tests.json").is_file())

    def test_worker_preserves_malformed_child_as_separate_evidence(self):
        import tempfile
        import json
        from unittest.mock import patch
        self.assertIsNotNone(private_worker, "private worker implementation is missing")
        worker = private_worker
        with tempfile.TemporaryDirectory() as directory:
            directory = Path(directory); source_path = directory / "source.json"
            source_path.write_text(json.dumps(SOURCE)); output = directory / "worker.json"
            def fixture_child(group, path, source_id, run_id):
                path.write_bytes(b'{"group":"private_payments","group":"other"}')
                return 0
            with patch.object(worker, "source_checked", return_value=dict(SOURCE)), \
                 patch.object(worker.base, "worker", side_effect=fixture_child):
                self.assertEqual(worker.run(output, source_path, SOURCE["source_id"], RUN_ID), 1)
            self.assertFalse(module.read_report(output)["passed"])
            self.assertEqual((directory / "worker.tests.json").read_bytes(),
                             b'{"group":"private_payments","group":"other"}')

    def test_worker_wrong_supplied_identity_fails_before_test_execution(self):
        import tempfile
        import json
        self.assertIsNotNone(private_worker, "private worker implementation is missing")
        worker = private_worker
        with tempfile.TemporaryDirectory() as directory:
            directory = Path(directory); source_path = directory / "source.json"
            source_path.write_text(json.dumps(SOURCE)); output = directory / "worker.json"
            self.assertEqual(worker.run(output, source_path, "e"*64, RUN_ID), 1)
            report = module.read_report(output)
            self.assertFalse(report["passed"]); self.assertEqual(report["run"], 0)
            self.assertFalse((directory / "worker.tests.json").exists())


    def test_failed_baseline_is_retained_and_private_gates_remain_unassessed(self):
        # Inject the expensive unchanged baseline result; test the wrapper's actual persisted outcome.
        import tempfile
        from unittest.mock import patch
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / "qualification"
            def failed_baseline(engine, path):
                path.mkdir(mode=0o700)
                report = {"schema": 1, "status": "failed", "error_type": "ValueError",
                          "source_id": SOURCE["source_id"], "local_automated_qualification": False}
                module.legacy.base.store_json(path / "result.json", report)
                return report
            with patch.object(module, "source_checked", return_value=dict(SOURCE)), \
                 patch.object(module.legacy, "verify_engine", return_value=Path("/unused-engine")), \
                 patch.object(module.legacy, "qualify", side_effect=failed_baseline):
                report = module.qualify("/unused-engine", output)
            self.assertEqual(report["status"], "failed")
            self.assertFalse(report["local_automated_qualification"])
            self.assertEqual(report["unassessed_gates"], ["private-components", "private-consensus"])
            self.assertEqual(module.read_report(output / "baseline/result.json")["error_type"], "ValueError")
            self.assertFalse((output / "private-components.json").exists())


if __name__ == "__main__": unittest.main()

