#!/usr/bin/env python3
"""Serve fresh-genesis protocol 4 on a private local ABCI socket."""
from __future__ import annotations

import argparse
import hashlib
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'src'))

from abci_server import Server
from commit_verifier import load_json
from protocol4_abci_server import dispatch
from protocol4_abci_wire import Request, Response
from protocol4_application import Protocol4Application


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--genesis', type=Path, required=True)
    parser.add_argument('--genesis-sha256', required=True)
    parser.add_argument('--database', type=Path, required=True)
    parser.add_argument('--socket', type=Path, required=True)
    args = parser.parse_args()
    raw = args.genesis.read_bytes()
    if hashlib.sha256(raw).hexdigest() != args.genesis_sha256:
        raise ValueError('protocol-4 genesis file differs from external pin')
    genesis = load_json(raw, max_bytes=131_072)
    with Protocol4Application(args.database, expected_genesis=genesis) as app:
        with Server(str(args.socket), app, request_type=Request,
                    response_type=Response, dispatcher=dispatch) as server:
            server.serve_forever(poll_interval=0.1)
            if server.failed.is_set():
                raise RuntimeError('protocol-4 ABCI server failed closed')


if __name__ == '__main__':
    main()
