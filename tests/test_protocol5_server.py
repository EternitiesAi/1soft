from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import textwrap
import unittest

from protocol5_application import Protocol5Application
from protocol5_encoding import canonical_json, comet_validator_set, genesis_document
from protocol5_fixture import make_genesis
from test_protocol5_state import FixtureWorker

ROOT = Path(__file__).resolve().parents[1]


class Protocol5ServerTests(unittest.TestCase):
    def setUp(self):
        self.raw = canonical_json(make_genesis())
        self.genesis = genesis_document(self.raw)

    def _seed(self, path: Path) -> None:
        app = Protocol5Application(
            path, FixtureWorker(), expected_genesis=self.raw)
        app.init_chain(
            self.genesis.value["chain_id"], self.raw,
            self.genesis.value["validators"], 1)
        app.close()

    def _crash(self, path: Path, phase: str) -> subprocess.CompletedProcess:
        code = textwrap.dedent("""
            import hashlib,sys
            from protocol5_encoding import canonical_json,comet_validator_set,genesis_document
            from protocol5_fixture import make_genesis
            from serve_abci_p5_test import CrashProtocol5Application
            from test_protocol5_state import FixtureWorker,tx_for
            raw=canonical_json(make_genesis()); genesis=genesis_document(raw)
            token='private-crash-token'
            app=CrashProtocol5Application(
                sys.argv[1],FixtureWorker(),expected_genesis=raw,
                crash_phase=sys.argv[2],run_token=token,
                run_token_sha256=hashlib.sha256(token.encode()).hexdigest())
            anchor=bytes.fromhex(app.state['current_root'])
            wire=tx_for(genesis.value,anchor,b'crash')
            validator_hash=bytes.fromhex(comet_validator_set(genesis.value['validators']).hash)
            app.finalize_block([wire],1,b'C'*32,validator_hash,[],b'crash-request')
            app.commit()
            raise AssertionError('crash hook returned')
        """)
        env = dict(os.environ)
        env["PYTHONPATH"] = ":".join((
            str(ROOT / "src"), str(ROOT / "tests"), str(ROOT / "scripts")))
        return subprocess.run(
            [sys.executable, "-B", "-c", code, str(path), phase],
            env=env, capture_output=True, timeout=10, check=False)

    def test_test_server_crashes_on_both_sides_of_durable_commit(self):
        cases = (("before_commit", 94, 0), ("after_commit", 95, 1))
        for phase, exit_code, expected_height in cases:
            with self.subTest(phase=phase), tempfile.TemporaryDirectory() as td:
                path = Path(td) / "state.sqlite"
                self._seed(path)
                result = self._crash(path, phase)
                self.assertEqual(result.returncode, exit_code, result.stderr.decode())
                app = Protocol5Application(
                    path, FixtureWorker(), expected_genesis=self.raw)
                self.assertEqual(app.height, expected_height)
                self.assertEqual(
                    app.db.execute("SELECT count(*) FROM blocks").fetchone()[0],
                    expected_height)
                app.close()

    def test_test_server_rejects_wrong_run_token_digest(self):
        from serve_abci_p5_test import CrashProtocol5Application

        with self.assertRaises(ValueError):
            CrashProtocol5Application(
                ":memory:", FixtureWorker(), expected_genesis=self.raw,
                crash_phase="before_commit", run_token="secret",
                run_token_sha256="0" * 64)

    def test_snapshot_commit_event_uses_durable_checkpoint_height(self):
        from serve_abci_p5_test import CrashProtocol5Application

        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            path = root / "state.sqlite"
            events = root / "events.jsonl"
            self._seed(path)
            token = "private-crash-token"
            app = CrashProtocol5Application(
                path, FixtureWorker(), expected_genesis=self.raw,
                crash_phase="observe", run_token=token,
                run_token_sha256=hashlib.sha256(token.encode()).hexdigest(),
                event_log=events)
            app.db.execute("UPDATE committed SET height=? WHERE id=1", (9,))
            app.db.commit()
            self.assertEqual(app.height, 0)
            app._state_sync_test_hook("after_snapshot_commit")
            event = json.loads(events.read_text())
            identity = {
                "pid": os.getpid(),
                "start_ticks": int(
                    Path("/proc/self/stat").read_text().split()[21]),
            }
            self.assertEqual(event, {
                "kind": "after_snapshot_commit", "height": 9, **identity})
            app.apply_snapshot_chunk(0, b"bad", "sender")
            apply_event = json.loads(events.read_text().splitlines()[-1])
            self.assertEqual(apply_event, {
                "kind": "apply_snapshot_chunk", "height": 0,
                "index": 0, "result": 2, **identity})
            app.close()

    def test_normal_server_parser_has_no_crash_controls(self):
        from serve_abci_p5 import build_parser

        options = {
            option
            for action in build_parser()._actions
            for option in action.option_strings
        }
        self.assertNotIn("--run-token", options)
        self.assertNotIn("--run-token-sha256", options)
        self.assertNotIn("--crash-phase", options)


if __name__ == "__main__":
    unittest.main()
