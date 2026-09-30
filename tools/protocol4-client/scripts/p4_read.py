#!/usr/bin/env python3
"""P4 verified read client. No key, signer, submission or node mutation commands."""
import argparse
import json
from pathlib import Path
import sqlite3
import sys
import time

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'src'))
from block_application import encode
from commit_verifier import load_json
from p4_evidence import MAX_EVIDENCE_BYTES, MAX_GENESIS_BYTES, need, verify_evidence
from p4_read_store import P4ReadStore, write_new


def read(path, maximum):
    with Path(path).open('rb') as file:
        value = file.read(maximum + 1)
    need(len(value) <= maximum, 'file exceeds input limit')
    return value


def summary(report):
    return {k: report[k] for k in ('status', 'evidence_id', 'state_height', 'app_hash',
        'header_height', 'header_hash', 'registry_epoch', 'verified_headers',
        'native_execution_replayed', 'registry_authorization_replayed',
        'latest_state_guaranteed', 'pending_wallet_debits_included', 'spending_authority')}


def main(argv=None):
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--genesis', type=Path, required=True, help='Externally pinned engine genesis bytes')
    p.add_argument('--policy', type=Path, required=True, help='Externally chosen fixed trust policy')
    subs = p.add_subparsers(dest='command', required=True)
    for name in ('verify', 'init', 'import', 'sync', 'inspect', 'account', 'receipt', 'export'):
        c = subs.add_parser(name)
        if name != 'verify':
            c.add_argument('--store', type=Path, required=True, help='Separate P4 read store, never a wallet/node')
        if name in ('verify', 'import'):
            c.add_argument('--evidence', type=Path, required=True)
        if name == 'sync': c.add_argument('--endpoint', required=True, help='Literal loopback HTTP development node')
        if name in ('import', 'sync'):
            c.add_argument('--expected-tip', required=True, help="Reviewed evidence digest, or literal 'empty'")
        if name == 'account': c.add_argument('--account', required=True)
        if name == 'receipt':
            c.add_argument('--transaction', type=Path, required=True, help='Exact signed P4 payment bytes, not a private key')
            c.add_argument('--payer', required=True)
        if name == 'export':
            c.add_argument('--evidence-id', required=True)
            c.add_argument('--output', type=Path, required=True)
    a = p.parse_args(argv)
    try:
        genesis = read(a.genesis, MAX_GENESIS_BYTES)
        policy = load_json(read(a.policy, 4096), max_bytes=4096)
        evidence = (load_json(read(a.evidence, MAX_EVIDENCE_BYTES), max_bytes=MAX_EVIDENCE_BYTES)
                    if hasattr(a, 'evidence') else None)
        if a.command == 'verify':
            result = summary(verify_evidence(evidence, genesis, policy, now_ns=time.time_ns()))
        else:
            with P4ReadStore(a.store, genesis, policy, create=a.command == 'init',
                             read_only=a.command in ('inspect', 'account', 'receipt', 'export')) as store:
                if a.command == 'init':
                    result = {'status': 'empty-read-store-created', 'wallet_created': False}
                elif a.command == 'import':
                    tip = None if a.expected_tip == 'empty' else a.expected_tip
                    result = store.import_evidence(evidence, expected_tip=tip)
                elif a.command == 'sync':
                    from p4_rpc import sync_read_store
                    tip = None if a.expected_tip == 'empty' else a.expected_tip
                    result = sync_read_store(store, a.endpoint, expected_tip=tip)
                elif a.command == 'inspect':
                    report = store.current(); need(report is not None, 'no authenticated checkpoint')
                    result = summary(report)
                elif a.command == 'account': result = store.account(a.account)
                elif a.command == 'receipt':
                    result = store.receipt(read(a.transaction, 16384), payer=a.payer)
                else:
                    evidence = store.export(a.evidence_id)
                    write_new(a.output, encode(evidence))
                    result = {'status': 'evidence-exported', 'evidence_id': a.evidence_id,
                              'wallet_reservations_changed': False}
        print(json.dumps(result, indent=2))
        return 2 if result['status'] == 'unavailable' else 0
    except (OSError, ValueError, KeyError, TypeError, OverflowError, sqlite3.Error):
        print('P4 read refused or evidence unavailable. No payment outcome or spending authority inferred.', file=sys.stderr)
        return 2


if __name__ == '__main__': raise SystemExit(main())
