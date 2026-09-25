#!/usr/bin/env python3
"""Local payment-job continuity. No signing, vault access or automatic sending."""
import argparse
import json
import os
from pathlib import Path
import sqlite3
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'src'))
from native_core import canonical, parse_wire
from payment_jobs import PaymentJobs
from payment_dispatch import read_bounded


def export_new(path: Path, data: bytes):
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, 'wb') as out:
        out.write(data + b'\n'); out.flush(); os.fsync(out.fileno())


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--genesis', type=Path, required=True)
    parser.add_argument('--genesis-sha256', required=True)
    parser.add_argument('--journal', type=Path, required=True)
    parser.add_argument('--endpoint', required=True, help='literal loopback development RPC only')
    parser.add_argument('--trust-expires-utc', required=True)
    sub = parser.add_subparsers(dest='command', required=True)
    for name in ('prepare', 'signing-request', 'attach', 'send', 'replay', 'refresh',
                 'status', 'events', 'export', 'export-proof'):
        cmd = sub.add_parser(name)
        cmd.add_argument('--job-id', required=True)
        if name == 'prepare':
            cmd.add_argument('--body', type=Path, required=True)
            cmd.add_argument('--signer-public-key', required=True)
        if name == 'attach': cmd.add_argument('--envelope', type=Path, required=True)
        if name in ('send', 'replay'): cmd.add_argument('--confirm', required=True)
        if name == 'refresh': cmd.add_argument('--read-attempts', type=int, choices=range(1, 5), default=1)
        if name in ('signing-request', 'export', 'export-proof'):
            cmd.add_argument('--output', type=Path, required=True)
    args = parser.parse_args(argv)
    try:
        with PaymentJobs(args.journal, read_bounded(args.genesis, 1024*1024), args.genesis_sha256,
                         args.endpoint, args.trust_expires_utc) as jobs:
            if args.command == 'prepare':
                result = jobs.prepare(args.job_id, parse_wire(read_bounded(args.body, 16384)), args.signer_public_key)
            elif args.command == 'signing-request':
                result = jobs.signing_request(args.job_id)
                export_new(args.output, canonical(result.pop('body')))
                result['body_output'] = str(args.output)
            elif args.command == 'attach':
                raw = read_bounded(args.envelope, 16385)
                if raw.endswith(b'\n'): raw = raw[:-1]
                result = jobs.attach(args.job_id, raw)
            elif args.command in ('send', 'replay'):
                result = jobs.send(args.job_id, args.confirm, replay=args.command == 'replay')
            elif args.command == 'refresh':
                result = jobs.refresh(args.job_id, read_attempts=args.read_attempts)
            elif args.command == 'events':
                result = {'job_id': args.job_id, 'events': jobs.events(args.job_id)}
            elif args.command in ('export', 'export-proof'):
                data = jobs.export(args.job_id) if args.command == 'export' else jobs.export_receipt(args.job_id)
                export_new(args.output, data)
                result = {'job_id': args.job_id, 'status': 'existing-data-exported', 'network_contacted': False}
            else:
                result = jobs.status(args.job_id)
        print(json.dumps(result, indent=2, ensure_ascii=True))
        return 0
    except (OSError, ValueError, sqlite3.Error) as exc:
        print('Payment job refused: ' + str(exc), file=sys.stderr)
        return 2


if __name__ == '__main__':
    raise SystemExit(main())
