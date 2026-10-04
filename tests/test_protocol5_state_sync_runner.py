from __future__ import annotations

from pathlib import Path
import tempfile
import unittest

from run_protocol5_state_sync import preflight_state_sync

class Protocol5StateSyncRunnerTests(unittest.TestCase):
    def test_missing_inputs_remain_unassessed_without_synthetic_transfer(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            report = preflight_state_sync(
                output=root / "state-sync.json",
                **{name: root / name for name in (
                    "engine", "worker", "client", "prover", "profile", "kat",
                    "toolchain", "policy", "genesis")})
            self.assertEqual(report["status"], "unassessed")
            self.assertFalse(report["state_sync_observed"])
            self.assertFalse(report["processes_started"])

if __name__ == "__main__":
    unittest.main()
