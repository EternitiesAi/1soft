#!/usr/bin/env python3
"""Run-token-gated Protocol 5 server for crash-boundary qualification only."""
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))
sys.path.insert(0, str(ROOT / "scripts"))

from protocol5_application import Protocol5Application
from serve_abci_p5 import build_parser, serve

BEFORE_COMMIT_EXIT = 94
AFTER_COMMIT_EXIT = 95
AFTER_SNAPSHOT_COMMIT_EXIT = 96


class CrashProtocol5Application(Protocol5Application):
    """Test-only process crash hook authenticated by a private run token."""

    def __init__(self, *args, crash_phase: str, run_token: str,
                 run_token_sha256: str, event_log: Path | None = None, **kwargs):
        if (type(run_token) is not str or not run_token
                or hashlib.sha256(run_token.encode("ascii", "strict")).hexdigest()
                != run_token_sha256):
            raise ValueError("Protocol 5 crash run token differs")
        if crash_phase not in (
                "observe", "before_commit", "after_commit", "after_snapshot_commit"):
            raise ValueError("unsupported Protocol 5 crash phase")
        self.crash_phase = crash_phase
        self.event_log = event_log
        self.event_pid = os.getpid()
        self.event_start_ticks = int(
            Path("/proc/self/stat").read_text().split()[21])
        super().__init__(*args, **kwargs)

    def _event(self, kind: str, **values) -> None:
        if self.event_log is None:
            return
        raw = (json.dumps(
            {
                "kind": kind, "pid": self.event_pid,
                "start_ticks": self.event_start_ticks, **values,
            },
            sort_keys=True, separators=(",", ":")) + "\n").encode("utf-8")
        flags = os.O_WRONLY | os.O_CREAT | os.O_APPEND | os.O_CLOEXEC
        if hasattr(os, "O_NOFOLLOW"):
            flags |= os.O_NOFOLLOW
        descriptor = os.open(self.event_log, flags, 0o600)
        try:
            os.write(descriptor, raw)
            os.fsync(descriptor)
        finally:
            os.close(descriptor)

    def _commit_test_hook(self, phase: str) -> None:
        if phase == self.crash_phase:
            os._exit(BEFORE_COMMIT_EXIT if phase == "before_commit"
                     else AFTER_COMMIT_EXIT)

    def _state_sync_test_hook(self, phase: str) -> None:
        height = self.height
        if phase == "after_snapshot_commit":
            committed = self.db.execute(
                "SELECT height FROM committed WHERE id=1").fetchone()
            if (committed is None or type(committed[0]) is not int
                    or committed[0] <= 0):
                raise RuntimeError("Protocol 5 snapshot Commit receipt differs")
            height = committed[0]
        self._event(phase, height=height)
        if phase == self.crash_phase:
            os._exit(AFTER_SNAPSHOT_COMMIT_EXIT)

    def offer_snapshot(self, snapshot: dict, app_hash: bytes):
        result = super().offer_snapshot(snapshot, app_hash)
        snapshot_hash = snapshot.get("hash")
        trusted_app_hash = app_hash
        self._event(
            "offer_snapshot",
            height=snapshot.get("height"), format=snapshot.get("format"),
            chunks=snapshot.get("chunks"),
            snapshot_hash=(
                snapshot_hash.hex() if type(snapshot_hash) is bytes else ""),
            trusted_app_hash=(
                trusted_app_hash.hex()
                if type(trusted_app_hash) is bytes else ""),
            result=result)
        return result

    def apply_snapshot_chunk(self, index: int, chunk: bytes, sender: str):
        result = super().apply_snapshot_chunk(index, chunk, sender)
        self._event(
            "apply_snapshot_chunk", height=self.height,
            index=index, result=result["result"])
        return result


def main() -> None:
    parser = build_parser()
    parser.add_argument("--run-token", required=True)
    parser.add_argument("--run-token-sha256", required=True)
    parser.add_argument("--event-log", type=Path)
    parser.add_argument(
        "--crash-phase", required=True,
        choices=("observe", "before_commit", "after_commit", "after_snapshot_commit"))
    args = parser.parse_args()
    serve(
        args, application_type=CrashProtocol5Application,
        crash_phase=args.crash_phase, run_token=args.run_token,
        run_token_sha256=args.run_token_sha256, event_log=args.event_log)


if __name__ == "__main__":
    main()
