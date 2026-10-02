#!/usr/bin/env python3
"""Explicit, loopback-only development payment dispatch. Never signs or unlocks."""
import argparse
import json
import os
from pathlib import Path
import sqlite3
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1]/'src'))
from payment_transport import DispatchJournal
from commit_verifier import MAX_PACKET_BYTES


def read_bounded(path: Path, limit: int) -> bytes:
    with path.open('rb') as source:
        raw = source.read(limit+1)
    if len(raw) > limit:
        raise ValueError('input file exceeds allowed size')
    return raw


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--genesis', type=Path, required=True)
    parser.add_argument('--genesis-sha256', required=True, help='Digest pinned independently, not supplied by an endpoint')
    parser.add_argument('--journal', type=Path, required=True, help='New private dispatch journal, not the signing journal')
    parser.add_argument('--endpoint', required=True, help='Only http://127.0.0.1:PORT/ is supported')
    parser.add_argument('--trust-expires-utc', required=True, help='Explicit UTC deadline; never renewed automatically')
    sub = parser.add_subparsers(dest='command', required=True)
    queue = sub.add_parser('queue'); queue.add_argument('--envelope', type=Path, required=True)
    queue.add_argument('--signer-public-key', required=True)
    for name in ('send','replay','status','events','prove','export','refresh','export-proof'):
        cmd = sub.add_parser(name); cmd.add_argument('--txid', required=True)
        if name in ('send','replay'): cmd.add_argument('--confirm', required=True)
        if name == 'refresh': cmd.add_argument('--read-attempts', type=int, choices=range(1,5), default=1)
        if name == 'prove': cmd.add_argument('--certificate', type=Path, required=True)
        if name in ('export','export-proof'): cmd.add_argument('--output', type=Path, required=True)
    args = parser.parse_args(argv)
    try:
        raw = read_bounded(args.genesis, 1024*1024)
        with DispatchJournal(args.journal, raw, args.genesis_sha256,
                             args.endpoint, args.trust_expires_utc) as journal:
            if args.command == 'queue':
                envelope = read_bounded(args.envelope, 16_385)
                # Both wallet CLIs export canonical JSON with one terminal LF.
                if envelope.endswith(b'\n'): envelope = envelope[:-1]
                result = journal.queue(envelope, args.signer_public_key)
            elif args.command in ('send','replay'):
                result = journal.dispatch(args.txid, args.confirm, replay=args.command == 'replay')
            elif args.command == 'refresh':
                result = journal.refresh_receipt(args.txid, read_attempts=args.read_attempts)
            elif args.command == 'prove':
                result = journal.prove(args.txid, read_bounded(args.certificate, MAX_PACKET_BYTES))
            elif args.command == 'events':
                result = {'native_txid': args.txid, 'events': journal.events(args.txid)}
            elif args.command in ('export','export-proof'):
                envelope = journal.export(args.txid) if args.command == 'export' else journal.export_receipt(args.txid)
                fd = os.open(args.output, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
                with os.fdopen(fd, 'wb') as target:
                    target.write(envelope+b'\n'); target.flush(); os.fsync(target.fileno())
                result = {'status': 'exact-existing-envelope-exported' if args.command == 'export' else 'verified-existing-proof-exported', 'network_contacted': False}
            else:
                result = journal.status(args.txid)
        print(json.dumps(result, indent=2, ensure_ascii=True))
        return 0
    except (OSError, ValueError, sqlite3.Error) as exc:
        print('Dispatch refused: '+str(exc), file=sys.stderr)
        return 2


if __name__ == '__main__':
    raise SystemExit(main())
