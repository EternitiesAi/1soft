#!/usr/bin/env python3
"""Run-token-gated Protocol 5 server for crash-boundary qualification only."""
from __future__ import annotations

import hashlib
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


class CrashProtocol5Application(Protocol5Application):
    """Test-only process crash hook authenticated by a private run token."""

    def __init__(self, *args, crash_phase: str, run_token: str,
                 run_token_sha256: str, **kwargs):
        if (type(run_token) is not str or not run_token
                or hashlib.sha256(run_token.encode("ascii", "strict")).hexdigest()
                != run_token_sha256):
            raise ValueError("Protocol 5 crash run token differs")
        if crash_phase not in ("before_commit", "after_commit"):
            raise ValueError("unsupported Protocol 5 crash phase")
        self.crash_phase = crash_phase
        super().__init__(*args, **kwargs)

    def _commit_test_hook(self, phase: str) -> None:
        if phase == self.crash_phase:
            os._exit(BEFORE_COMMIT_EXIT if phase == "before_commit"
                     else AFTER_COMMIT_EXIT)


def main() -> None:
    parser = build_parser()
    parser.add_argument("--run-token", required=True)
    parser.add_argument("--run-token-sha256", required=True)
    parser.add_argument(
        "--crash-phase", required=True, choices=("before_commit", "after_commit"))
    args = parser.parse_args()
    serve(
        args, application_type=CrashProtocol5Application,
        crash_phase=args.crash_phase, run_token=args.run_token,
        run_token_sha256=args.run_token_sha256)


if __name__ == "__main__":
    main()
