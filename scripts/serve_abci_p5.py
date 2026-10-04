#!/usr/bin/env python3
"""Serve fresh-genesis Protocol 5 on a private local ABCI socket."""
from __future__ import annotations

import argparse
import hashlib
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from abci_server import Server
from protocol5_abci_server import dispatch
from protocol5_abci_wire import Request, Response
from protocol5_application import Protocol5Application
from protocol5_encoding import genesis_document
from protocol5_worker import WorkerClient


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--genesis", type=Path, required=True)
    parser.add_argument("--genesis-sha256", required=True)
    parser.add_argument("--database", type=Path, required=True)
    parser.add_argument("--socket", type=Path, required=True)
    parser.add_argument("--worker", type=Path, required=True)
    parser.add_argument("--kat", type=Path, required=True)
    parser.add_argument("--toolchain", type=Path, required=True)
    parser.add_argument("--policy", type=Path, required=True)
    return parser


def load_inputs(args):
    raw_genesis = args.genesis.read_bytes()
    if hashlib.sha256(raw_genesis).hexdigest() != args.genesis_sha256:
        raise ValueError("Protocol 5 genesis file differs from external pin")
    genesis = genesis_document(raw_genesis)
    return raw_genesis, genesis, args.kat.read_bytes()


def application(args, *, application_type=Protocol5Application, **kwargs):
    raw_genesis, genesis, kat = load_inputs(args)
    worker = WorkerClient(
        args.worker, genesis, kat, args.toolchain, args.policy)
    try:
        app = application_type(
            args.database, worker, expected_genesis=raw_genesis, **kwargs)
    except BaseException:
        worker.close()
        raise
    return app, worker


def serve(args, *, application_type=Protocol5Application, **kwargs) -> None:
    app, worker = application(args, application_type=application_type, **kwargs)
    try:
        with app:
            with Server(
                    str(args.socket), app, request_type=Request,
                    response_type=Response, dispatcher=dispatch) as server:
                server.serve_forever(poll_interval=0.1)
                if server.failed.is_set():
                    raise RuntimeError("Protocol 5 ABCI server failed closed")
    finally:
        worker.close()


def main() -> None:
    serve(build_parser().parse_args())


if __name__ == "__main__":
    main()
