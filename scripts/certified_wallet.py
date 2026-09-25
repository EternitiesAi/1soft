#!/usr/bin/env python3
"""Offline certified review/sign/export. No download, network or broadcast path."""
import argparse
import getpass
import json
import os
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT/'src'))
from certified_wallet import CertifiedWallet, MAX_EVIDENCE
from commit_verifier import load_json
from native_core import Reject, canonical


def bounded_bytes(path: Path, limit: int) -> bytes:
    with path.open('rb') as stream:
        raw = stream.read(limit+1)
    if len(raw) > limit:
        raise Reject('input exceeds configured bound')
    return raw


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('command', choices=('review','sign','export'))
    parser.add_argument('--genesis', type=Path, required=True, help='Separately trusted engine genesis')
    parser.add_argument('--policy', type=Path, required=True, help='Separately trusted, expiring local policy')
    parser.add_argument('--journal', type=Path, required=True)
    parser.add_argument('--witness', type=Path)
    parser.add_argument('--body', type=Path)
    parser.add_argument('--signer-public-key')
    parser.add_argument('--mode', choices=('sign','accept'), default='sign')
    parser.add_argument('--vault', type=Path)
    parser.add_argument('--output', type=Path)
    parser.add_argument('--decision-id')
    args = parser.parse_args(argv)
    wallet = None
    try:
        genesis = bounded_bytes(args.genesis, 1024*1024)
        policy = load_json(bounded_bytes(args.policy, 16384), max_bytes=16384)
        wallet = CertifiedWallet(args.journal, genesis, policy)
        if args.command == 'export':
            result = wallet.export(args.decision_id)
        else:
            if args.witness is None or args.body is None or args.signer_public_key is None:
                raise Reject('review and sign require witness, body and public signer')
            witness = load_json(bounded_bytes(args.witness, MAX_EVIDENCE))
            body = load_json(bounded_bytes(args.body, 16384), max_bytes=16384)
            review = wallet.review(witness, body, args.signer_public_key, mode=args.mode)
            print(json.dumps(review, indent=2, ensure_ascii=True), flush=True)
            if args.command == 'review':
                return 0
            if args.vault is None or args.output is None:
                raise Reject('sign requires vault and a new output filename')
            if not sys.stdin.isatty():
                raise Reject('signing requires an interactive terminal')
            confirmation = input('Type the certified confirmation digest to approve: ').strip()
            if confirmation != review['confirmation']:
                raise Reject('confirmation does not match; key not unlocked')
            password = getpass.getpass('Vault passphrase: ').encode('utf-8')
            result = wallet.approve(witness, body, args.signer_public_key, confirmation,
                                    args.vault, password, mode=args.mode)
        if args.output is not None:
            # The decision is durably recorded before output. A failed write must
            # be recovered with export, never a new nonce or a different payment.
            fd = os.open(args.output, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os,'O_NOFOLLOW',0), 0o600)
            with os.fdopen(fd,'wb') as stream:
                stream.write(canonical(result['result']) + b'\n')
                stream.flush(); os.fsync(stream.fileno())
            print(json.dumps({k:v for k,v in result.items() if k != 'result'}))
        else:
            print(json.dumps(result, indent=2))
        return 0
    except (OSError, ValueError, EOFError) as exc:
        print('Certified wallet refused: '+str(exc), file=sys.stderr)
        print('After any committed signing decision, recover with export; do not replace the payment.', file=sys.stderr)
        return 2
    finally:
        if wallet is not None: wallet.close()


if __name__ == '__main__':
    raise SystemExit(main())
