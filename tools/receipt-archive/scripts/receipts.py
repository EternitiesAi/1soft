#!/usr/bin/env python3
"""Offline receipt archive. No wallet, signer, RPC, deployment or pruning commands."""
import argparse
import json
import sqlite3
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'src'))
from commit_verifier import encode, load_json
from receipt_capsule import MAX_BYTES, pack_receipt, verify_capsule
from receipt_archive import ReceiptArchive, write_new


def read(path, limit):
    with Path(path).open('rb') as stream:
        raw = stream.read(limit + 1)
    if len(raw) > limit:
        raise ValueError('input exceeds configured bound')
    return raw


def main(argv=None):
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--genesis', type=Path, required=True)
    p.add_argument('--genesis-sha256', required=True, help='Independently pinned engine genesis file digest')
    sub = p.add_subparsers(dest='command', required=True)
    for name in ('pack', 'verify', 'import', 'lookup', 'export', 'init'):
        cmd = sub.add_parser(name)
        if name in ('import', 'lookup', 'export', 'init'):
            cmd.add_argument('--archive', type=Path, required=True)
        if name in ('pack', 'verify', 'import', 'lookup'):
            cmd.add_argument('--transaction', type=Path, required=True, help='Exact signed transaction; not a private key')
        if name in ('pack', 'verify', 'import'):
            cmd.add_argument('--state-header-hash', required=True,
                             help='Final header hash pinned separately from the proof provider')
        if name in ('verify', 'import'):
            cmd.add_argument('--capsule', type=Path, required=True)
        if name == 'pack':
            cmd.add_argument('--packet', type=Path, required=True)
            cmd.add_argument('--continuation', type=Path, help='Exact intervening signed headers, at most 64')
        if name in ('pack', 'export'):
            cmd.add_argument('--output', type=Path, required=True)
        if name == 'export':
            cmd.add_argument('--evidence-id', required=True)
    a = p.parse_args(argv)
    try:
        genesis = read(a.genesis, 1024*1024)
        raw = read(a.transaction, 16384) if hasattr(a, 'transaction') else None
        capsule = load_json(read(a.capsule, MAX_BYTES)) if hasattr(a, 'capsule') else None
        if a.command in ('pack', 'verify'):
            if a.command == 'pack':
                packet = load_json(read(a.packet, MAX_BYTES))
                links = load_json(read(a.continuation, MAX_BYTES)) if a.continuation else None
                capsule = pack_receipt(packet, genesis, a.genesis_sha256, expected_transaction=raw,
                    expected_header_hash=a.state_header_hash, continuation=links)
            result = verify_capsule(capsule, genesis, a.genesis_sha256,
                                   expected_transaction=raw, expected_header_hash=a.state_header_hash)
            result.pop('receipt')
            if a.command == 'pack':
                write_new(a.output, encode(capsule))
        else:
            with ReceiptArchive(a.archive, genesis, a.genesis_sha256, create=a.command == 'init',
                                read_only=a.command in ('lookup', 'export')) as archive:
                if a.command == 'init': result = {'status': 'archive-created', 'wallet_created': False}
                elif a.command == 'import':
                    result = archive.put(capsule, expected_transaction=raw, expected_header_hash=a.state_header_hash)
                elif a.command == 'lookup': result = archive.lookup(raw)
                else:
                    capsule = archive.export(a.evidence_id)
                    write_new(a.output, encode(capsule))
                    result = {'status': 'evidence-exported', 'evidence_id': a.evidence_id,
                              'selected_winner': None, 'wallet_reservations_changed': False}
        print(json.dumps(result, indent=2))
        return 2 if result['status'] in ('conflict', 'unavailable') else 0
    except (OSError, ValueError, KeyError, TypeError, sqlite3.Error):
        # No raw proof, account, path or exception text reaches terminal diagnostics.
        print('Receipt operation refused or evidence unavailable; no payment outcome inferred.', file=sys.stderr)
        return 2


if __name__ == '__main__':
    raise SystemExit(main())
