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
    ENGINE_SHA256, Note, Protocol5Network, _backup_sqlite,
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
                    "id INTEGER PRIMARY KEY, height INTEGER, app_hash BLOB)")
                connection.execute(
                    "INSERT INTO committed VALUES(1, ?, ?)", (9, b"A" * 32))
                connection.commit()
                checkpoint = _backup_sqlite(source, target)
            finally:
                connection.close()
            with closing(sqlite3.connect(target)) as retained:
                row = retained.execute(
                    "SELECT height, app_hash FROM committed WHERE id=1").fetchone()
            self.assertEqual(row, (9, b"A" * 32))
            self.assertEqual(
                checkpoint, {"height": 9, "app_hash": (b"A" * 32).hex()})

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
