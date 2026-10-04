from __future__ import annotations

import json
import base64
import struct
import sqlite3
from pathlib import Path
from contextlib import closing
import tempfile
import unittest

from protocol5_encoding import canonical_json, genesis_document
from protocol5_encoding import field_hex, h2f
from protocol5_fixture import make_genesis
from run_protocol5_engine import (
    CLIENT_MAGIC, CLIENT_GENESIS_MAGIC, PROVER_MAGIC, DevelopmentController,
    ENGINE_SHA256, Note, Protocol5Network, _app_start_timeout, _backup_sqlite,
    _check_tx_at_held_state, _prepare_conflict_below_quorum,
    _process_probe_at_held_height,
    finalize_fresh_genesis, fresh_genesis_prefix, p5_app_command, preflight,
)

class Protocol5EngineRunnerTests(unittest.TestCase):
    def test_controller_client_wire_is_exact_and_stdin_only(self):
        captured = []

        class CapturingController(DevelopmentController):
            def _run(self, role, binary, request, **kwargs):
                captured.append((role, bytes(request), kwargs))
                request[:] = b"\0" * len(request)
                if role == "development-client-genesis":
                    values = (h2f(b"commitment", b"a"),
                              h2f(b"commitment", b"b"))
                    return (CLIENT_GENESIS_MAGIC + struct.pack("<HH", 1, 2)
                            + b"".join(values) + h2f(b"root", b"fixture"))
                return PROVER_MAGIC + b"\0" * (1010 - len(PROVER_MAGIC))

        prefix = make_genesis()
        prefix["initial_commitments"] = []
        controller = CapturingController(Path("/client"), Path("/prover"), prefix)
        note = lambda value: Note(
            32, value, value.to_bytes(32, "little"),
            (value + 1).to_bytes(32, "little"),
            (value + 2).to_bytes(32, "little"))
        notes = [note(10), note(20)]
        commitments, _ = controller.commitments(notes)
        self.assertEqual(len(captured[0][1]), 398)
        self.assertEqual(captured[0][1][:12], CLIENT_MAGIC + struct.pack("<HH", 1, 1))
        raw = finalize_fresh_genesis(prefix, commitments)
        request = controller.spend_request(
            raw, commitments, 0, notes[0], (note(3), note(2)),
            valid_from=1, valid_until=20)
        self.assertEqual(len(captured[1][1]), 736)
        self.assertEqual(captured[1][1][:12], CLIENT_MAGIC + struct.pack("<HH", 1, 2))
        self.assertEqual(len(request), 1010)
        self.assertEqual(request[:8], PROVER_MAGIC)

    def test_fresh_genesis_uses_engine_keys_and_waits_for_rust_commitments(self):
        engine_rows = [
            {
                "pub_key": {
                    "type": "tendermint/PubKeyEd25519",
                    "value": base64.b64encode(bytes([byte]) * 32).decode("ascii"),
                },
                "power": "10",
            }
            for byte in (4, 1, 3, 2)
        ]
        prefix = fresh_genesis_prefix(
            canonical_json(make_genesis()), "p5-fresh-chain", engine_rows)
        self.assertEqual(prefix["initial_commitments"], [])
        self.assertEqual(
            [row["public_key"] for row in prefix["validators"]],
            sorted((bytes([byte]) * 32).hex() for byte in (4, 1, 3, 2)),
        )
        commitments = list(make_genesis()["initial_commitments"])
        raw = finalize_fresh_genesis(prefix, commitments)
        parsed = genesis_document(raw)
        self.assertEqual(parsed.value["initial_commitments"], commitments)
        self.assertEqual(parsed.value["chain_id"], "p5-fresh-chain")

    def test_application_startup_wait_covers_worker_kat_budget(self):
        raw = canonical_json(make_genesis())
        self.assertEqual(_app_start_timeout(raw), 150)

    def test_validator_command_never_receives_prover_or_crash_controls(self):
        paths = {
            "worker": Path("/private/bin/worker"),
            "client": Path("/private/controller/client"),
            "prover": Path("/private/controller/prover"),
            "kat": Path("/private/profile/kat"),
            "toolchain": Path("/private/profile/toolchain"),
            "policy": Path("/private/profile/policy"),
        }
        command = p5_app_command(
            paths, Path("/run/genesis"), "a" * 64,
            Path("/run/state"), Path("/run/app.sock"))
        joined = "\0".join(command)
        self.assertNotIn(str(paths["client"]), joined)
        self.assertNotIn(str(paths["prover"]), joined)
        self.assertNotIn("--run-token", command)
        self.assertNotIn("--crash-phase", command)

    def test_direct_proposal_probes_use_held_next_height(self):
        network = object.__new__(Protocol5Network)
        events = []
        holds = []
        network.engines = {index: object() for index in range(4)}

        def hold():
            holds.append(tuple(sorted(network.engines)))
            network.engines.pop(2)
            network.engines.pop(3)
            return {"height": 19, "app_hash": "11" * 32}

        network.hold_sources_without_quorum = hold
        network.direct_check = (
            lambda index, transaction:
            events.append(("check", index, transaction)) or 0)
        network.direct_prepare = (
            lambda index, transactions, height, max_bytes:
            events.append(("prepare", height, max_bytes)) or [transactions[0]])
        network.direct_process = (
            lambda index, transactions, height, validator_hash:
            events.append(("conflict-process", index, transactions, height,
                           validator_hash)) or 2)
        network.start_engine = (
            lambda index: network.engines.setdefault(index, object()))
        admissions, prepared, process_status, checkpoint = (
            _prepare_conflict_below_quorum(
                network, b"a", b"b", 4096, b"V" * 32))
        self.assertEqual(admissions, [0, 0])
        self.assertEqual(prepared, [b"a"])
        self.assertEqual(process_status, 2)
        self.assertEqual(checkpoint["height"], 19)
        self.assertIn(("prepare", 20, 4096), events)
        self.assertIn(
            ("conflict-process", 0, [b"a", b"b"], 20, b"V" * 32),
            events)
        self.assertEqual(set(network.engines), {0, 1})

        network.direct_state = (
            lambda index: {"height": 19, "app_hash": "11" * 32})
        network.broadcast = lambda index, transaction: {"code": "0"}
        network.mempool_transactions = lambda index: [b"a"]
        staged_admissions, staged_checkpoint = network.stage_without_quorum([b"a"])
        self.assertEqual([row["code"] for row in staged_admissions], ["0"])
        self.assertEqual(staged_checkpoint["height"], 19)
        self.assertEqual(holds, [(0, 1, 2, 3)])
        self.assertEqual(set(network.engines), {0, 1, 2, 3})

        network.direct_process = (
            lambda index, transactions, height, validator_hash:
            events.append(("process", height, validator_hash)) or 2)
        result, checkpoint = _process_probe_at_held_height(
            network, [b"a", b"b"], b"V" * 32)
        self.assertEqual(result, 2)
        self.assertEqual(checkpoint["height"], 19)
        self.assertIn(("process", 20, b"V" * 32), events)
        self.assertEqual(set(network.engines), {0, 1, 2, 3})

    def test_direct_check_probes_compare_one_held_state_and_resume_quorum(self):
        network = object.__new__(Protocol5Network)
        events = []
        network.engines = {index: object() for index in range(4)}
        held = {"height": 104, "app_hash": "11" * 32,
                "state": {"accepted_transaction_count": 5}}

        def hold():
            events.append("held")
            network.engines.pop(2)
            network.engines.pop(3)
            return dict(held)

        network.hold_sources_without_quorum = hold
        network.direct_state = (
            lambda index: events.append(("state", index)) or dict(held))
        network.direct_check = (
            lambda index, transaction:
            events.append(("check", index, transaction)) or 4)
        network.start_engine = (
            lambda index:
            events.append(("start", index)) or network.engines.setdefault(index, object()))

        codes, before, after = _check_tx_at_held_state(
            network, [b"unknown", b"tampered"])

        self.assertEqual(codes, [4, 4])
        self.assertEqual(before, held)
        self.assertEqual(after, held)
        self.assertEqual(events, [
            "held", ("state", 0), ("check", 0, b"unknown"),
            ("check", 0, b"tampered"), ("state", 0),
            ("start", 2), ("start", 3),
        ])
        self.assertEqual(set(network.engines), {0, 1, 2, 3})

    def test_no_quorum_staging_waits_for_both_live_mempools(self):
        network = object.__new__(Protocol5Network)
        events = []
        transactions = [b"one", b"two"]
        network.engines = {index: object() for index in range(4)}

        def hold():
            events.append("held")
            network.engines.pop(2)
            network.engines.pop(3)
            return {"height": 7}

        network.hold_sources_without_quorum = hold
        network.broadcast = (
            lambda index, transaction:
            events.append(("broadcast", index, transaction)) or {"code": "0"})
        network.mempool_transactions = (
            lambda index: events.append(("mempool", index)) or transactions)
        network.start_engine = (
            lambda index:
            events.append(("start", index)) or network.engines.setdefault(index, object()))

        admissions, checkpoint = network.stage_without_quorum(transactions)

        self.assertEqual([int(row["code"]) for row in admissions], [0, 0])
        self.assertEqual(checkpoint["height"], 7)
        self.assertEqual(events[:3], [
            "held", ("broadcast", 0, b"one"), ("broadcast", 0, b"two")])
        self.assertIn(("mempool", 0), events)
        self.assertIn(("mempool", 1), events)
        self.assertEqual(events[-2:], [("start", 2), ("start", 3)])

    def test_held_sources_drop_below_quorum_at_one_checkpoint(self):
        network = object.__new__(Protocol5Network)
        network.engines = {index: object() for index in range(4)}
        state = {"height": 8, "app_hash": "11" * 32}
        network.direct_state = lambda index: dict(state)
        stopped = []

        def stop(index):
            stopped.append(index)
            network.engines.pop(index)

        network.stop_engine = stop
        network.start_engine = lambda index: network.engines.setdefault(index, object())
        checkpoint = network.hold_sources_without_quorum(attempts=1)
        self.assertEqual(checkpoint, state)
        self.assertEqual(stopped, [3, 2])
        self.assertEqual(set(network.engines), {0, 1})

    def test_retained_database_backup_includes_wal_commit(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            source = root / "source.sqlite"
            target = root / "target.sqlite"
            connection = sqlite3.connect(source)
            try:
                connection.execute("PRAGMA journal_mode=WAL")
                connection.execute(
                    "CREATE TABLE committed("
                    "id INTEGER PRIMARY KEY, height INTEGER, app_hash TEXT)")
                connection.execute(
                    "INSERT INTO committed VALUES(1, ?, ?)", (9, "41" * 32))
                connection.commit()
                checkpoint = _backup_sqlite(source, target)
            finally:
                connection.close()
            with closing(sqlite3.connect(target)) as retained:
                row = retained.execute(
                    "SELECT height, app_hash FROM committed WHERE id=1").fetchone()
            self.assertEqual(row, (9, "41" * 32))
            self.assertEqual(
                checkpoint, {"height": 9, "app_hash": "41" * 32})

    def test_state_sync_event_log_is_retained_as_bounded_artifact(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            runtime = root / "runtime"
            runtime.mkdir()
            events = runtime / "state-sync-events.jsonl"
            raw = b'{"height":9,"kind":"after_snapshot_commit"}\n'
            events.write_bytes(raw)
            network = object.__new__(Protocol5Network)
            network.runtime = runtime
            network.output = root / "state-sync.json"
            network.report = {}
            network.engines = {}
            network.apps = {}
            network.handles = []
            network.receipts = []

            class RetainRuntime:
                def cleanup(self):
                    pass

            network.temp = RetainRuntime()
            network.close()

            artifacts = root / "state-sync.json.artifacts"
            self.assertEqual(
                (artifacts / "state-sync-events.jsonl").read_bytes(), raw)
            receipt = next(row for row in network.report["artifacts"]
                           if row["name"] == "state-sync-events.jsonl")
            self.assertEqual(receipt["bytes"], len(raw))
            self.assertFalse(receipt["truncated"])
            self.assertEqual(
                json.loads((artifacts / "manifest.json").read_text()),
                network.report["artifacts"])

    def test_missing_exact_inputs_are_unassessed_and_output_is_preserved(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            output = root / "report.json"
            paths = {name: root / name for name in (
                "engine", "worker", "client", "prover", "profile", "kat",
                "toolchain", "policy", "genesis",
            )}
            report = preflight(output=output, **paths)
            self.assertEqual(report["status"], "unassessed")
            self.assertEqual(
                sorted(report["missing_inputs"]), sorted(paths))
            self.assertFalse(report["actual_proof_accepted"])
            with self.assertRaises(FileExistsError):
                preflight(output=output, **paths)

    def test_changed_engine_fails_before_launch(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            for name in ("engine", "worker", "client", "prover", "profile", "kat",
                         "toolchain", "policy", "genesis"):
                (root / name).write_bytes(b"changed")
            output = root / "report.json"
            report = preflight(
                output=output, expected_prover_sha256="00" * 32,
                expected_client_sha256="00" * 32,
                **{name: root / name for name in (
                    "engine", "worker", "client", "prover", "profile", "kat",
                    "toolchain", "policy", "genesis")})
            self.assertEqual(report["status"], "failed")
            self.assertIn("engine binary differs", report["failures"])
            self.assertFalse(report["processes_started"])

if __name__ == "__main__":
    unittest.main()
