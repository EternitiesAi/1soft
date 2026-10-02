#!/usr/bin/env python3
"""Private P4 journal backup and recovery-only inspection. Never signs or sends."""
import argparse
import getpass
import hmac
import json
import os
from pathlib import Path
import stat
import sqlite3
import sys
import warnings

ROOT = Path(__file__).resolve().parents[3]
sys.dont_write_bytecode = True
sys.path[:0] = [str(ROOT/'src'), str(ROOT/'tools/validator-transition/src')]
for component in ('protocol4-client','protocol4-wallet','protocol4-delivery','protocol4-custody'):
    sys.path[:0] = [str(ROOT/'tools'/component/'src')]
from block_application import encode
from commit_verifier import load_json
from native_core import Reject
from p4_delivery import P4Delivery
from p4_custody import backup, restore_backup, RecoveryArchive, publish_new, separate_paths


def public_input(path, limit):
    fd = os.open(path, os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK|os.O_CLOEXEC)
    with os.fdopen(fd, 'rb') as source:
        info = os.fstat(source.fileno())
        if not stat.S_ISREG(info.st_mode) or not 0 < info.st_size <= limit:
            raise ValueError('bounded regular genesis/policy file required')
        raw = source.read(limit+1)
    if len(raw) > limit: raise ValueError('input grew beyond bound')
    return raw


def password(*, confirm=False):
    if not sys.stdin.isatty() or not sys.stderr.isatty():
        raise ValueError('a local terminal is required; no password argument or environment fallback')
    try:
        with warnings.catch_warnings():
            warnings.simplefilter('error', getpass.GetPassWarning)
            first = getpass.getpass('Backup passphrase: ').encode('utf-8')
            if confirm:
                second = getpass.getpass('Repeat backup passphrase: ').encode('utf-8')
                if not hmac.compare_digest(first, second): raise ValueError('passphrases differ')
    except getpass.GetPassWarning as exc:
        raise ValueError('terminal echo could not be disabled; passphrase input refused') from exc
    return first


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--genesis', required=True, type=Path)
    parser.add_argument('--policy', required=True, type=Path)
    commands = parser.add_subparsers(dest='command', required=True)
    save = commands.add_parser('backup', help='encrypted complete wallet/delivery snapshot')
    for name in ('wallet','delivery','output'): save.add_argument('--'+name, required=True, type=Path)
    save.add_argument('--endpoint', required=True, help='exact endpoint stored in the bound journal; no network call')
    save.add_argument('--format', choices=('auto','1','2'), default='auto',
                      help='auto keeps small backups v1 and selects bounded v2 for larger admitted pairs')
    restore = commands.add_parser('restore', help='create a recovery-only archive, never an active wallet')
    for name in ('backup','output'): restore.add_argument('--'+name, required=True, type=Path)
    view = commands.add_parser('status', help='historical holds and dispatch claims; no current authority')
    view.add_argument('--archive', required=True, type=Path)
    for name in ('recover','export-receipt'):
        command = commands.add_parser(name, help='export selected original historical evidence')
        command.add_argument('--archive', required=True, type=Path)
        command.add_argument('--decision-id', required=True)
        command.add_argument('--payer', required=True)
        command.add_argument('--grant', default='')
        command.add_argument('--output', required=True, type=Path)
    args = parser.parse_args()
    try:
        genesis = public_input(args.genesis, 1024*1024)
        policy = load_json(public_input(args.policy, 4096), max_bytes=4096)
        if args.command == 'backup':
            # Prompt before opening journals; no SQLite lock spans a prompt.
            secret = password(confirm=True)
            with P4Delivery(args.wallet,args.delivery,genesis,policy,args.endpoint) as delivery:
                result = backup(delivery,args.output,secret,
                                format_version=None if args.format=='auto' else int(args.format))
        elif args.command == 'restore':
            result = restore_backup(args.backup,args.output,genesis,policy,password())
        else:
            with RecoveryArchive(args.archive,genesis,policy) as archive:
                if args.command == 'status': result = archive.inspect()
                else:
                    separate_paths(args.archive, args.output)
                    selection = dict(payer=args.payer,grant_id=args.grant)
                    if args.command == 'recover': raw = archive.recover(args.decision_id,**selection)
                    else: raw = encode(archive.export_receipt(args.decision_id,**selection))
                    publish_new(args.output,raw)
                    result = {'status':'historical-evidence-exported','decision_id':args.decision_id,
                              'signing_performed':False,'submission_performed':False,
                              'current_spending_authority':False}
        print(json.dumps(result,sort_keys=True))
        return 0
    except (ValueError,OSError,Reject,sqlite3.Error,EOFError) as exc:
        print('Recovery refused: '+str(exc),file=sys.stderr)
        return 2


if __name__ == '__main__': raise SystemExit(main())
