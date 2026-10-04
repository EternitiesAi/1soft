"""Runner boundary tests; fixtures below never establish engine qualification."""
from __future__ import annotations
import base64
import importlib
import importlib.util
import json
import os
from pathlib import Path
import sqlite3
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch
from protocol5_encoding import canonical_json
from protocol5_fixture import make_genesis
from protocol5_note_capsule import capsule_id

ROOT = Path(__file__).resolve().parents[1]

def runner():
    spec = importlib.util.find_spec("run_protocol5_wallet_engine")
    if spec is None:
        raise AssertionError("Task 8 runner is absent")
    return importlib.import_module("run_protocol5_wallet_engine")

class Protocol5WalletRunnerTests(unittest.TestCase):
    def locations(self, root):
        return {name: root / name for name in (
            "engine", "worker", "client", "prover", "profile", "kat",
            "toolchain", "policy", "genesis")}

    def test_missing_inputs_are_unassessed_without_private_paths_or_launch(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            report = runner().preflight(output=root / "report.json", **self.locations(root))
            self.assertEqual(report["status"], "unassessed")
            self.assertEqual(set(report["missing_inputs"]), set(self.locations(root)) | {"expected_client_sha256", "expected_prover_sha256"})
            self.assertEqual(report["processes"], [])
            self.assertFalse(report["processes_started"])
            self.assertFalse(report["actual_proof_accepted"])
            self.assertNotIn(str(root), json.dumps(report))
            self.assertTrue(all(value is False for value in report["claims"].values()))
            self.assertEqual(json.loads((root / "report.json").read_bytes()), report)

    def test_existing_report_artifacts_or_private_runtime_are_never_overwritten(self):
        for suffix in ("", ".artifacts", ".private"):
            with self.subTest(suffix=suffix), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                output = root / "report.json"
                occupied = output.with_name(output.name + suffix)
                if suffix:
                    occupied.mkdir()
                    marker = occupied / "keep"
                else:
                    marker = occupied
                marker.write_bytes(b"owned-by-another-run")
                with self.assertRaises(FileExistsError):
                    runner().preflight(output=output, **self.locations(root))
                self.assertEqual(marker.read_bytes(), b"owned-by-another-run")

    def test_output_under_checkout_or_symlink_parent_is_refused(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            alias = root / "alias"
            alias.symlink_to(ROOT, target_is_directory=True)
            with self.assertRaises(ValueError):
                runner().preflight(output=alias / "must-not-write.json",
                                   **self.locations(root))
        with self.assertRaises(ValueError):
            runner().preflight(output=ROOT / "must-not-write.json",
                               **self.locations(ROOT / "not-inputs"))

    def test_changed_binary_is_failed_before_engine_launch_and_errors_are_sanitized(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            paths = self.locations(root)
            for path in paths.values():
                path.write_bytes(b"deliberately-invalid-fixture")
            report = runner().preflight(
                output=root / "report.json", **paths,
                expected_client_sha256="00" * 32,
                expected_prover_sha256="00" * 32)
            self.assertEqual(report["status"], "failed")
            self.assertFalse(report["processes_started"])
            self.assertIn("engine binary differs", report["failures"])
            self.assertNotIn(str(root), json.dumps(report))

    def test_missing_controller_pins_are_unassessed_not_fixture_qualified(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            paths = self.locations(root)
            for path in paths.values():
                path.write_bytes(b"fixture-only")
            report = runner().preflight(output=root / "report.json", **paths)
            self.assertEqual(report["status"], "unassessed")
            self.assertEqual(report["missing_inputs"],
                             ["expected_client_sha256", "expected_prover_sha256"])
            self.assertEqual(report["checks"], [])

    def test_validator_command_cannot_receive_controller_paths(self):
        paths = {name: Path("/private/" + name) for name in (
            "engine", "worker", "client", "prover", "profile", "kat", "toolchain", "policy")}
        command = runner().validator_command(
            paths, Path("/private/genesis"), "a" * 64,
            Path("/private/state"), Path("/private/app.sock"))
        self.assertNotIn(str(paths["client"]), command)
        self.assertNotIn(str(paths["prover"]), command)
        self.assertNotIn("--client", command)
        self.assertNotIn("--prover", command)

    def test_leakage_scan_detects_all_secret_encodings_without_echoing_values(self):
        secret = bytes(range(1, 33))
        encodings = [secret, secret.hex().encode(), base64.b64encode(secret),
                     str(int.from_bytes(secret, "little")).encode()]
        objects = [(f"object-{index}", value) for index, value in enumerate(encodings)]
        result = runner().scan_objects(objects, [secret])
        self.assertEqual(result["matches"], 4)
        self.assertEqual(result["objects"], 4)
        self.assertNotIn(secret.hex(), json.dumps(result))
        self.assertNotIn(str(int.from_bytes(secret, "little")), json.dumps(result))

    def test_capsule_mutations_recompute_identity_and_cover_closed_roster(self):
        genesis = make_genesis()
        capsule = {
            "format": "1soft/protocol5-note-capsule/v1", "version": 1,
            "genesis_sha256": "11" * 32, "profile_id": "22" * 32,
            "deployment_id": "33" * 32,
            "origin": {"kind": "transaction", "txid": "44" * 32, "output_index": 0},
            "commitment": (5).to_bytes(32, "little").hex(),
            "owner_key": (6).to_bytes(32, "little").hex(),
            "expiry": 512, "value": 20,
            "note_secret": (7).to_bytes(32, "little").hex(),
            "blinding": (8).to_bytes(32, "little").hex(),
        }
        capsule["capsule_id"] = capsule_id(capsule)
        variants = runner().capsule_mutations(canonical_json(capsule))
        expected = set(json.loads((ROOT / "reference/protocol5-wallet-qualification-settings-v1.json").read_bytes())["capsule_mutations"])
        self.assertEqual(set(variants), expected - {"spent", "uncommitted"})
        for name in ("note_secret", "blinding", "owner_key", "commitment", "origin.txid"):
            changed = json.loads(variants[name])
            self.assertEqual(changed["capsule_id"], capsule_id(changed))
        self.assertNotEqual(variants["note_secret"], canonical_json(capsule))

    def test_manifest_is_schema_bound_without_capsule_or_secret_columns(self):
        with tempfile.TemporaryDirectory() as directory:
            database = Path(directory) / "private.sqlite"
            connection = sqlite3.connect(database)
            connection.execute("CREATE TABLE config(id INTEGER PRIMARY KEY, spend_secret BLOB)")
            connection.execute("INSERT INTO config VALUES(1,?)", (b"never-public-secret",))
            connection.commit()
            connection.close()
            result = runner().journal_manifest(database, "wallet-a",
                                               {"wallet_id": "11" * 32, "values": {"spendable": 100}})
            self.assertEqual(result["name"], "wallet-a")
            self.assertEqual(result["bytes"], database.stat().st_size)
            self.assertEqual(len(result["schema_sha256"]), 64)
            self.assertNotIn("never-public-secret", json.dumps(result))
            self.assertNotIn(str(database), json.dumps(result))

    def test_owned_cleanup_stops_only_registered_process(self):
        child = subprocess.Popen([sys.executable, "-B", "-c", "import time;time.sleep(30)"])
        other = subprocess.Popen([sys.executable, "-B", "-c", "import time;time.sleep(30)"])
        try:
            code = runner().stop_owned(child)
            self.assertIsInstance(code, int)
            self.assertIsNotNone(child.poll())
            self.assertIsNone(other.poll())
        finally:
            for process in (child, other):
                if process.poll() is None:
                    process.terminate()
                process.wait(timeout=5)


    def test_actual_wallet_child_preserves_lost_return_without_reproving(self):
        from test_protocol5_wallet_cli import Protocol5WalletCliTests, SECRET
        fixture = Protocol5WalletCliTests()
        fixture.setUp()
        self.addCleanup(fixture.doCleanups)
        paths = {"client": fixture.client, "prover": fixture.prover}
        receipts = []
        self.assertTrue(hasattr(runner(), "WalletProcesses"), "actual wallet process runner is absent")
        session = runner().WalletProcesses(
            paths, fixture.root, fixture.app_file, fixture.engine,
            {"client": runner()._sha(fixture.client), "prover": runner()._sha(fixture.prover)},
            receipts)
        fixture.wallet = fixture.root / "wallet-a.sqlite"
        session.call("wallet-a", "init", payload={"owner_spend_secret": SECRET.hex()})
        revision = session.call("wallet-a", "status")["revision"]
        session.call("wallet-a", "sync", "--expected-revision", revision,
                     "--input", fixture.observation_file)
        revision = session.call("wallet-a", "status")["revision"]
        session.call("wallet-a", "import-note", "--expected-revision", revision,
                     payload=json.loads(fixture.import_payload()))
        prepared = session.call("wallet-a", "prepare", "--note-id", fixture.note_id,
                                "--recipient-owner-key", (9).to_bytes(32,"little").hex(),
                                "--value", 20, "--valid-until", 20)
        payload = {key: prepared[key] for key in ("review", "confirmation")}
        session.call("wallet-a", "approve", payload=payload,
                     fault="after-commit", expected_code=73)
        before = len([row for row in receipts if row["role"] == "development-prover"])
        fixture.client.unlink()
        fixture.prover.unlink()
        recovered = fixture.root / "recovered.bin"
        result = session.call("wallet-a", "recover", "--review-id",
                              prepared["confirmation"], "--output", recovered)
        with sqlite3.connect(fixture.wallet) as database:
            decision_id, wire = database.execute(
                "SELECT decision_id,transaction_bytes FROM decisions").fetchone()
        self.assertEqual(result["decision_id"], decision_id)
        self.assertEqual(recovered.read_bytes(), wire)
        self.assertEqual(before, 1)
        self.assertEqual(len([r for r in receipts if r["role"] == "development-prover"]), 1)
        self.assertTrue(all(r["node"] is None and r["terminated"] for r in receipts))
        self.assertEqual(next(r["exit_code"] for r in receipts
                              if r["role"] == "wallet-approval-lost-return"), 73)
        self.assertNotIn(SECRET.hex(), json.dumps(receipts))

    def test_actual_before_commit_child_rolls_back_decision_and_reservation(self):
        from test_protocol5_wallet_cli import Protocol5WalletCliTests
        fixture = Protocol5WalletCliTests()
        fixture.setUp()
        self.addCleanup(fixture.doCleanups)
        fixture.wallet = fixture.root / "wallet-a.sqlite"
        fixture.bootstrap()
        prepared = fixture.prepare()
        before = fixture.journal_snapshot()
        receipts = []
        self.assertTrue(hasattr(runner(), "WalletProcesses"), "actual wallet process runner is absent")
        session = runner().WalletProcesses(
            {"client": fixture.client, "prover": fixture.prover},
            fixture.root, fixture.app_file, fixture.engine,
            {"client": runner()._sha(fixture.client), "prover": runner()._sha(fixture.prover)},
            receipts)
        session.call("wallet-a", "approve",
                     payload={key: prepared[key] for key in ("review", "confirmation")},
                     fault="before-commit", expected_code=72)
        self.assertEqual(fixture.journal_snapshot(), before)
        self.assertEqual(fixture.status()["decisions"], [])
        self.assertEqual(fixture.status()["values"]["spendable"], 100)

    def test_proxy_never_forwards_after_close_or_to_nonloopback(self):
        self.assertTrue(hasattr(runner(), "DeliveryProxy"), "owned loopback proxy is absent")
        with self.assertRaises(ValueError):
            runner().DeliveryProxy("https://example.test/")
        proxy = runner().DeliveryProxy("http://127.0.0.1:9/")
        proxy.close()
        self.assertFalse(proxy.thread.is_alive())
        self.assertEqual(proxy.requests, 0)



    def test_normal_proxy_submission_preserves_strict_http11_framing(self):
        import hashlib
        from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
        import threading
        from protocol5_transport import submit_once
        wire = b"synthetic-wire-for-transport-only"
        class Origin(BaseHTTPRequestHandler):
            protocol_version = "HTTP/1.1"
            def do_POST(self):
                value = json.loads(self.rfile.read(int(self.headers["Content-Length"])))
                raw = canonical_json({"jsonrpc": "2.0", "id": value["id"], "result": {
                    "code": 0, "data": "", "log": "", "codespace": "",
                    "hash": hashlib.sha256(wire).hexdigest().upper()}})
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(raw)))
                self.end_headers()
                self.wfile.write(raw)
            def log_message(self, *_):
                pass
        origin = ThreadingHTTPServer(("127.0.0.1", 0), Origin)
        thread = threading.Thread(target=origin.serve_forever, daemon=True)
        thread.start()
        proxy = runner().DeliveryProxy("http://127.0.0.1:"+str(origin.server_port)+"/")
        try:
            result = submit_once(proxy.endpoint, wire, 1)
            self.assertEqual(result["observation"], "endpoint_admitted")
            self.assertEqual(proxy.requests, 1)
            self.assertEqual(proxy.forwarded, 1)
        finally:
            proxy.close()
            origin.shutdown()
            origin.server_close()
            thread.join(timeout=5)

    def test_certificate_mutations_are_rejected_by_real_certificate_parser(self):
        from protocol5_state import execute_block
        from protocol5_state_reader import authenticate_observation
        from test_protocol5_wallet_cli import Protocol5WalletCliTests
        fixture = Protocol5WalletCliTests()
        fixture.setUp()
        self.addCleanup(fixture.doCleanups)
        approved = fixture.approved()
        with sqlite3.connect(fixture.wallet) as database:
            wire = database.execute("SELECT transaction_bytes FROM decisions").fetchone()[0]
        fixture.state, _ = execute_block(fixture.genesis, fixture.state, [wire], 1, fixture.worker)
        fixture.height = 1
        raw = fixture.observation()
        authenticate_observation(raw, fixture.engine, fixture.genesis_raw)
        self.assertTrue(hasattr(runner(), "certificate_mutations"), "certificate mutation runner is absent")
        variants = runner().certificate_mutations(raw)
        settings = json.loads((ROOT / "reference/protocol5-wallet-qualification-settings-v1.json").read_bytes())
        self.assertEqual(set(variants), set(settings["certificate_mutations"]) - {
            "rollback", "stale-revision", "same-height-fork"})
        for name, changed in variants.items():
            with self.subTest(name=name), self.assertRaises(ValueError):
                authenticate_observation(changed, fixture.engine, fixture.genesis_raw)

    def test_real_scenarios_refuse_nonpinned_inputs_before_runtime_creation(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            paths = self.locations(root)
            for path in paths.values():
                path.write_bytes(b"explicitly-unqualified-fixture")
            report = {"processes_started": False, "checks": [], "actual_proof_accepted": False,
                      "expected_sha256": {"client": "00"*32, "prover": "00"*32}}
            with self.assertRaises(ValueError):
                runner().run_wallet_scenarios(
                    paths, root/"report.json", report, runner()._settings())
            self.assertFalse(report["processes_started"])
            self.assertFalse((root/"report.json.private").exists())
            self.assertEqual(report["checks"], [])

    def test_wallet_network_stages_runtime_beside_private_evidence(self):
        module = runner()
        testcase = self
        with tempfile.TemporaryDirectory() as directory:
            private = Path(directory) / "report.json.private"
            private.mkdir(mode=0o700)

            def fake_base_init(network, paths, output, report, *,
                               include_target, runtime_parent=None):
                testcase.assertFalse(include_target)
                testcase.assertEqual(Path(runtime_parent), private)
                network.temp = tempfile.TemporaryDirectory(
                    prefix="one-protocol5-engine-", dir=runtime_parent)
                network.runtime = Path(network.temp.name)
                network.homes = network.runtime / "nodes"
                network.homes.mkdir()

            with patch.object(module.Protocol5Network, "__init__", fake_base_init):
                network = module.WalletNetwork(
                    {}, private / "network-report.json", {}, private)

            self.assertEqual(network.runtime, private / "network")
            self.assertEqual(network.homes, private / "network/nodes")
            self.assertTrue(network.homes.is_dir())
            network.temp.cleanup()

    def test_retained_observation_waits_for_restarted_rpc_listeners(self):
        module = runner()
        height = 7
        app_hash = "11" * 32
        witness = canonical_json({"height": height, "app_hash": app_hash})
        response = canonical_json({"result": {"response": {
            "value": base64.b64encode(witness).decode()}}})

        class Network:
            def __init__(self):
                self.engines = {0: object(), 1: object()}
                self.engine_genesis = {}
                self.http = [1]
                self.retained_app_hashes = []
                self.phase = "held"
                self.restart_probes = 0
                self.ready = False

            def hold_sources_without_quorum(self):
                return {"height": height, "app_hash": app_hash}

            def set_empty_blocks(self, enabled):
                self.phase = "advancing" if enabled else "restarting"
                if not enabled:
                    self.ready = False

            def start_engine(self, index):
                self.engines[index] = object()

            def height(self, _index):
                if self.phase == "restarting":
                    self.restart_probes += 1
                    if self.restart_probes == 1:
                        raise RuntimeError("RPC listener is restarting")
                    self.ready = True
                return height + 1

        class Proxy:
            endpoint = "http://127.0.0.1:1/"
            retained_query = None

        network = Network()
        proxies = [Proxy(), Proxy()]

        def read_when_ready(*_args):
            self.assertTrue(network.ready)
            return b"authenticated-observation"

        with (patch.object(module, "_origin_response", return_value=response),
              patch.object(module, "read_state_observation",
                           side_effect=read_when_ready),
              patch.object(module, "authenticate_observation",
                           return_value=({}, {"state_height": height}))):
            observed = module.collect_retained_observation(
                network, proxies, b"genesis")

        self.assertEqual(observed, b"authenticated-observation")
        self.assertGreaterEqual(network.restart_probes, 2)
        self.assertEqual(proxies[0].retained_query, response)

    def test_ordinary_scenario_validity_survives_height_advancing_faults(self):
        module = runner()
        self.assertEqual(module.qualification_valid_until(511, 0), 511)
        self.assertEqual(module.qualification_valid_until(511, 510), 511)
        for maximum, current in ((511, 511), (511, -1), (True, 0), (511, False)):
            with self.subTest(maximum=maximum, current=current), \
                    self.assertRaises(ValueError):
                module.qualification_valid_until(maximum, current)

    def test_conflicting_statement_changes_outputs_and_authorization_digest(self):
        module = runner()
        original = tuple(index.to_bytes(32, "little") for index in range(14))
        winner = list(original)
        winner[10] = (110).to_bytes(32, "little")
        winner[11] = (111).to_bytes(32, "little")
        winner[13] = (113).to_bytes(32, "little")
        self.assertTrue(module.same_nullifier_conflict(original, tuple(winner)))

        for index in (0, 9, 12):
            changed = list(winner)
            changed[index] = (200 + index).to_bytes(32, "little")
            with self.subTest(index=index):
                self.assertFalse(module.same_nullifier_conflict(
                    original, tuple(changed)))
        unchanged_digest = list(winner)
        unchanged_digest[13] = original[13]
        self.assertFalse(module.same_nullifier_conflict(
            original, tuple(unchanged_digest)))



    def test_artifact_manifest_refuses_omissions_and_unknown_names(self):
        self.assertTrue(hasattr(runner(), "artifact_manifest"), "artifact closure helper is absent")
        settings = runner()._settings()
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "unexpected-private-journal.sqlite").write_bytes(b"secret")
            with self.assertRaises(ValueError):
                runner().artifact_manifest(root, settings)
            self.assertFalse((root / "manifest.json").exists())

    def test_restart_snapshot_detects_committed_private_authority_change(self):
        self.assertTrue(hasattr(runner(), "journal_rows"), "restart snapshot helper is absent")
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "authority.sqlite"
            with sqlite3.connect(path) as database:
                database.execute("CREATE TABLE config(id INTEGER PRIMARY KEY, secret BLOB)")
                database.execute("INSERT INTO config VALUES(1,?)", (b"first",))
            before = runner().journal_rows(path)
            with sqlite3.connect(path) as database:
                database.execute("UPDATE config SET secret=?", (b"second",))
            self.assertNotEqual(before, runner().journal_rows(path))


if __name__ == "__main__":
    unittest.main()
