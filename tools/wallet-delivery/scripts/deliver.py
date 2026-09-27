#!/usr/bin/env python3
"""Explicit delivery of an EXISTING wallet decision. No vault/password/sign command."""
import argparse
import json
import os
import stat
from pathlib import Path
import sqlite3
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT/'src'))
# The account inspector is a published sibling add-on, not the local transfer API.
sys.path.insert(0, str(ROOT.parent/'wallet-account'/'src'))
from commit_verifier import load_json
from decision_delivery import DecisionDelivery


def read(path: Path, limit: int) -> bytes:
    with path.open('rb') as stream:
        data = stream.read(limit + 1)
    if len(data) > limit:
        raise ValueError('input exceeds size bound')
    return data


def write_private(path: Path, data: bytes) -> None:
    path = Path(os.path.abspath(path))
    for parent in (path.parent, *path.parent.parents):
        if parent.is_symlink():
            raise ValueError('output-directory symlink refused')
    info = path.parent.stat()
    if not stat.S_ISDIR(info.st_mode) or info.st_uid != os.geteuid() or info.st_mode & 0o077:
        raise ValueError('private owned output directory required')
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, 'wb') as stream:
        stream.write(data); stream.flush(); os.fsync(stream.fileno())


def main(argv=None) -> int:
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--genesis', type=Path, required=True)
    p.add_argument('--policy', type=Path, required=True)
    p.add_argument('--wallet', type=Path, required=True)
    p.add_argument('--delivery-journal', type=Path, required=True)
    p.add_argument('--endpoint', required=True)
    p.add_argument('--account', required=True)
    p.add_argument('--grant-id', default='', help='Explicit grant role; omitted means owner')
    p.add_argument('--decision-id', required=True)
    sub = p.add_subparsers(dest='command', required=True)
    for name in ('queue','status','review','send','replay','refresh','reconcile','export-proof'):
        cmd = sub.add_parser(name)
        if name == 'review':
            cmd.add_argument('--replay', action='store_true', help='Explicitly review one exact-byte repeat attempt')
        if name in ('send','replay'):
            cmd.add_argument('--confirm', required=True)
        if name == 'refresh':
            cmd.add_argument('--read-attempts', type=int, choices=range(1,5), default=1)
        if name == 'reconcile':
            cmd.add_argument('--continuation', type=Path)
        if name == 'export-proof':
            cmd.add_argument('--output', type=Path, required=True)
    a = p.parse_args(argv)
    try:
        with DecisionDelivery(a.wallet, a.delivery_journal, read(a.genesis, 1024*1024),
                load_json(read(a.policy, 16384), max_bytes=16384), a.endpoint,
                create=a.command=='queue') as delivery:
            selection = {'account': a.account, 'grant_id': a.grant_id}
            if a.command in ('send','replay'):
                result = delivery.send(a.decision_id, a.confirm, replay=a.command=='replay', **selection)
            elif a.command == 'review':
                result = delivery.review(a.decision_id, replay=a.replay, **selection)
            elif a.command == 'refresh':
                result = delivery.refresh(a.decision_id, read_attempts=a.read_attempts, **selection)
            elif a.command == 'reconcile':
                links = load_json(read(a.continuation, 2*1024*1024), max_bytes=2*1024*1024) if a.continuation else None
                result = delivery.reconcile(a.decision_id, continuation=links, **selection)
            elif a.command == 'export-proof':
                write_private(a.output, delivery.export_receipt(a.decision_id, **selection) + b'\n')
                result = {'status': 'existing-verified-receipt-exported', 'network_requested': False}
            else:
                result = getattr(delivery, a.command)(a.decision_id, **selection)
        print(json.dumps(result, indent=2, ensure_ascii=True))
        # Command completion is NOT successful delivery. Callers inspect the two
        # separate status fields. This CLI never prints a generic payment success.
        return 0
    except (OSError, ValueError, sqlite3.Error):
        print('Delivery operation did not complete. A prior submission or wallet commit may exist. '
              'Inspect the original decision; do not prepare a replacement payment.', file=sys.stderr)
        return 2


if __name__ == '__main__':
    raise SystemExit(main())
