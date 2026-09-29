#!/usr/bin/env python3
"""Offline development wallet: create-key, review, sign. Never broadcasts."""
import argparse
import getpass
import json
import os
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'src'))
from native_core import Reject, canonical, parse_wire
from offline_signer import approve_intent, create_vault, review_intent


def read_json(path):
    with Path(path).open('rb') as source:
        return parse_wire(source.read(20001))


def interactive_password():
    if not sys.stdin.isatty():
        raise Reject('unlock requires an interactive terminal; no password arguments or environment variables')
    return getpass.getpass('Vault passphrase: ').encode('utf-8')


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    subs = parser.add_subparsers(dest='command', required=True)
    create = subs.add_parser('create-key')
    create.add_argument('--vault', type=Path, required=True)
    for command in ('review', 'sign'):
        item = subs.add_parser(command)
        item.add_argument('--genesis', type=Path, required=True)
        item.add_argument('--body', type=Path, required=True)
        item.add_argument('--signer-public-key', required=True)
        item.add_argument('--mode', choices=('sign', 'accept'), default='sign')
        if command == 'sign':
            item.add_argument('--vault', type=Path, required=True)
            item.add_argument('--output', type=Path, required=True)
    args = parser.parse_args(argv)
    try:
        if args.command == 'create-key':
            password = interactive_password()
            again = getpass.getpass('Repeat passphrase: ').encode('utf-8')
            if password != again:
                raise Reject('passphrases do not match')
            print(json.dumps({'public_key': create_vault(args.vault, password), 'development_only': True}))
            return 0
        genesis = read_json(args.genesis)
        body = read_json(args.body)
        if (type(genesis) is dict and type(genesis.get('protocol_version', 1)) is int
                and genesis.get('protocol_version', 1) == 4):
            raise Reject('legacy wallet refuses protocol 4 dynamic validators')
        if (type(genesis) is dict and type(genesis.get('protocol_version', 1)) is int
                and genesis.get('protocol_version', 1) == 3):
            raise Reject('protocol 3 shared-budget wallet operations require scripts/certified_wallet.py with one shared journal')
        review = review_intent(genesis, body, args.signer_public_key, mode=args.mode)
        print(json.dumps(review, indent=2, ensure_ascii=True), flush=True)
        if args.command == 'review':
            return 0
        if not sys.stdin.isatty():
            raise Reject('signing requires an interactive terminal to review the exact intention')
        confirmation = input('Type the full confirmation digest shown above to approve: ').strip()
        if confirmation != review['confirmation']:
            raise Reject('confirmation does not match; nothing signed')
        result = approve_intent(args.vault, interactive_password(), genesis, body,
                                args.signer_public_key, confirmation, mode=args.mode)
        # Output contains only the consent body or public signed envelope. Never overwrite.
        fd = os.open(args.output, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, 'O_NOFOLLOW', 0), 0o600)
        with os.fdopen(fd, 'wb') as out:
            out.write(canonical(result) + b'\n'); out.flush(); os.fsync(out.fileno())
        print(json.dumps({'status': 'signed-not-broadcast', 'output': str(args.output)}))
        return 0
    except (OSError, ValueError, EOFError) as exc:
        print('Wallet refused: ' + str(exc), file=sys.stderr)
        return 2


if __name__ == '__main__':
    raise SystemExit(main())
