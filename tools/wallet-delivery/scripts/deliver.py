#!/usr/bin/env python3
"""Deliver one existing native signing decision. No keys, signing or auto-retry."""
import argparse
import json
import os
from pathlib import Path
import sqlite3
import sys

ADDON = Path(__file__).resolve().parents[1]
sys.path[:0] = [str(ADDON/'src'), str(ADDON.parent/'wallet-account'/'src'), str(ADDON.parent/'wallet-account'/'scripts')]
from decision_delivery import DecisionDelivery
from commit_verifier import load_json
from account import _export as write_private


def read_bounded(path, limit):
    with path.open('rb') as f:
        data = f.read(limit + 1)
    if len(data) > limit:
        raise ValueError('input exceeds configured bound')
    return data


def main(argv=None):
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--genesis', type=Path, required=True)
    p.add_argument('--policy', type=Path, required=True)
    p.add_argument('--journal', type=Path, required=True, help='Existing shared certificate-wallet journal')
    p.add_argument('--dispatch-journal', type=Path, required=True, help='Separate dedicated dispatch journal')
    p.add_argument('--endpoint', required=True, help='Literal http://127.0.0.1:PORT/ only')
    p.add_argument('--account', required=True)
    p.add_argument('--grant-id', default='', help='Explicit grant label; omitted means owner role')
    p.add_argument('--decision-id', required=True, help='Existing signed decision, not transaction JSON')
    sub = p.add_subparsers(dest='command', required=True)
    review = sub.add_parser('review'); review.add_argument('--replay', action='store_true')
    send = sub.add_parser('send'); send.add_argument('--confirm', required=True)
    send.add_argument('--replay', action='store_true')
    sub.add_parser('status')
    refresh = sub.add_parser('refresh')
    refresh.add_argument('--read-attempts', type=int, choices=range(1,5), default=1)
    reconcile = sub.add_parser('reconcile')
    reconcile.add_argument('--continuation', type=Path)
    export = sub.add_parser('export-proof'); export.add_argument('--output', type=Path, required=True)
    a = p.parse_args(argv)
    try:
        service = DecisionDelivery(a.journal, read_bounded(a.genesis, 1024*1024),
            load_json(read_bounded(a.policy, 16384), max_bytes=16384),
            dispatch_journal=a.dispatch_journal, endpoint=a.endpoint, account=a.account,
            grant_id=a.grant_id, decision_id=a.decision_id)
        if a.command == 'review':
            result = service.review(replay=a.replay)
        elif a.command == 'send':
            result = service.send(a.confirm, replay=a.replay)
        elif a.command == 'refresh':
            result = service.refresh(read_attempts=a.read_attempts)
        elif a.command == 'reconcile':
            links = load_json(read_bounded(a.continuation, 2*1024*1024)) if a.continuation else None
            result = service.reconcile(continuation=links)
        elif a.command == 'export-proof':
            write_private(a.output, service.export_receipt() + b'\n')
            result = {'status': 'verified-receipt-exported', 'network_contacted': False}
        else:
            result = service.status()
        print(json.dumps(result, indent=2, ensure_ascii=True))
        # Review/inspection/export success is command success, NOT payment status.
        # Sending can be admitted, declined, or unknown: never return exit 0 as
        # though any of those were financially final.
        if a.command == 'send': return 2
        if a.command == 'refresh': return 0 if result['receipt_verified'] else 2
        if a.command == 'reconcile': return 0 if result['wallet_reconciled'] else 2
        return 0
    except (OSError, ValueError, sqlite3.Error):
        print('Delivery did not complete. An earlier attempt or receipt may be saved. '
              'Inspect status; do not create a replacement payment.', file=sys.stderr)
        return 3


if __name__ == '__main__':
    raise SystemExit(main())
