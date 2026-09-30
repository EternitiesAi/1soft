#!/usr/bin/env python3
"""Export/reopen positive P4 transfer evidence with external trust and local time."""
import argparse
import json
from pathlib import Path
import sqlite3
import sys
import time

sys.dont_write_bytecode = True
ROOT = Path(__file__).resolve().parents[1]
NATIVE = ROOT.parents[1]
sys.path[:0] = [str(ROOT / 'src'), str(NATIVE / 'tools/protocol4-client/src'),
               str(NATIVE / 'src'), str(NATIVE / 'tools/validator-transition/src')]

from commit_verifier import load_json
from p4_evidence import MAX_EVIDENCE_BYTES, MAX_GENESIS_BYTES, need
from p4_receipt_capsule import (MAX_CAPSULE_BYTES, MAX_WIRE_BYTES, encode_capsule,
                                make_capsule, verify_capsule)
from p4_receipt_archive import P4ReceiptArchive, write_new


def read(path, maximum):
    with Path(path).open('rb') as file:
        raw = file.read(maximum + 1)
    need(0 < len(raw) <= maximum, 'input file exceeds size bound')
    return raw


def summary(report):
    keys = ('status', 'capsule_id', 'evidence_id', 'payer', 'recipient', 'grant_id',
            'asset', 'unit', 'amount_units', 'fee_units', 'total_debit_units',
            'binding', 'receipt_height', 'state_height', 'app_hash', 'header_height',
            'header_hash', 'registry_epoch', 'checked_at_ns', 'trust_expires_ns',
            'native_execution_replayed', 'registry_authorization_replayed',
            'signed_block_inclusion_verified', 'latest_network_state_established',
            'spending_authority', 'wallet_reservations_changed',
            'historical_absence_proven', 'external_settlement_verified', 'automatic_resend')
    return {key: report[key] for key in keys}


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--genesis', type=Path, required=True,
                        help='Externally pinned full engine genesis bytes')
    parser.add_argument('--policy', type=Path, required=True,
                        help='Independently chosen fixed P4 read policy')
    commands = parser.add_subparsers(dest='command', required=True)
    for name in ('export', 'verify', 'archive-init', 'archive-put', 'archive-get', 'archive-inspect'):
        command = commands.add_parser(name)
        if name == 'export':
            command.add_argument('--evidence', type=Path, required=True)
            command.add_argument('--transaction', type=Path, required=True,
                                 help='Original canonical signed transfer wire, never a key')
            command.add_argument('--payer', required=True)
        if name in ('verify', 'archive-put'):
            command.add_argument('--capsule', type=Path, required=True)
        if name.startswith('archive-'):
            command.add_argument('--archive', type=Path, required=True,
                                 help='Separate private evidence archive')
        if name == 'archive-init':
            command.add_argument('--max-records', type=int, default=32)
            command.add_argument('--max-bytes', type=int, default=64 * 1024 * 1024)
        if name in ('archive-get', 'archive-inspect'):
            command.add_argument('--capsule-id', required=True)
        if name in ('verify', 'archive-put', 'archive-get', 'archive-inspect'):
            command.add_argument('--expected-payer')
            command.add_argument('--expected-wire-sha256')
        if name in ('export', 'archive-get'):
            command.add_argument('--output', type=Path, required=True)
    args = parser.parse_args(argv)
    try:
        genesis = read(args.genesis, MAX_GENESIS_BYTES)
        policy = load_json(read(args.policy, 4096), max_bytes=4096)
        # The capsule never chooses verification time. There is deliberately no
        # historical-time CLI option; the system clock is an external assumption.
        now = time.time_ns()
        selected = {'expected_payer': getattr(args, 'expected_payer', None),
                    'expected_wire_sha256': getattr(args, 'expected_wire_sha256', None)}
        if args.command == 'export':
            evidence = load_json(read(args.evidence, MAX_EVIDENCE_BYTES), max_bytes=MAX_EVIDENCE_BYTES)
            wire = read(args.transaction, MAX_WIRE_BYTES)
            capsule = make_capsule(evidence, genesis, policy, wire, payer=args.payer, now_ns=now)
            report = verify_capsule(capsule, genesis, policy, now_ns=time.time_ns(),
                                    expected_payer=args.payer)
            write_new(args.output, encode_capsule(capsule))
            result = {**summary(report), 'capsule_exported': True}
        elif args.command == 'verify':
            result = summary(verify_capsule(read(args.capsule, MAX_CAPSULE_BYTES),
                genesis, policy, now_ns=now, **selected))
        else:
            init = args.command == 'archive-init'
            settings = {'max_records': args.max_records, 'max_bytes': args.max_bytes} if init else {}
            with P4ReceiptArchive(args.archive, genesis, policy, now_ns=now,
                create=init, read_only=args.command in ('archive-get', 'archive-inspect'), **settings) as archive:
                if init:
                    result = {'status': 'empty-p4-receipt-archive-created', 'spending_authority': False}
                elif args.command == 'archive-put':
                    result = archive.put(read(args.capsule, MAX_CAPSULE_BYTES),
                                         now_ns=time.time_ns(), **selected)
                elif args.command == 'archive-inspect':
                    result = summary(archive.inspect(args.capsule_id, now_ns=time.time_ns(), **selected))
                else:
                    capsule = archive.get(args.capsule_id, now_ns=time.time_ns(), **selected)
                    result = summary(verify_capsule(capsule, genesis, policy, now_ns=time.time_ns(), **selected))
                    write_new(args.output, encode_capsule(capsule))
                    result['capsule_exported'] = True
        print(json.dumps(result, indent=2))
        return 0
    except (OSError, ValueError, KeyError, TypeError, OverflowError, RecursionError, sqlite3.Error):
        print('P4 receipt refused or unavailable. Payment outcome remains unknown; no spending or retry authority inferred.',
              file=sys.stderr)
        return 2


if __name__ == '__main__':
    raise SystemExit(main())
