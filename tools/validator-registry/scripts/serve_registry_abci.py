#!/usr/bin/env python3
"""Serve the isolated development registry to a private local CometBFT socket."""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[3]
sys.path[:0] = [str(ROOT/'src'), str(ROOT/'tools/validator-transition/src'),
                str(ROOT/'tools/validator-registry/src')]
from registry_application import RegistryApplication
from registry_abci_server import Server


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--genesis', type=Path, required=True)
    parser.add_argument('--genesis-sha256', required=True)
    parser.add_argument('--database', type=Path, required=True)
    parser.add_argument('--socket', type=Path, required=True)
    parser.add_argument('--observations', type=Path)
    parser.add_argument('--create', action='store_true')
    args = parser.parse_args()
    raw = args.genesis.read_bytes()
    if hashlib.sha256(raw).hexdigest() != args.genesis_sha256:
        raise ValueError('registry genesis file differs from external pin')
    genesis = json.loads(raw)
    with RegistryApplication(args.database, genesis, create=args.create) as app:
        with Server(args.socket, app, args.observations) as server:
            server.serve_forever(poll_interval=0.1)
            if server.failed:
                raise RuntimeError('registry ABCI server failed closed')


if __name__ == '__main__':
    main()
