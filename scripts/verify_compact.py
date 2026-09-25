#!/usr/bin/env python3
"""Read-only compact record/receipt verifier. Does not contact endpoints or keys."""
import argparse
import json
from pathlib import Path
import sys
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'src'))
from commit_verifier import load_json, pinned_genesis
from compact_verifier import verify_compact_witness, verify_compact_receipt, review_compact_transfer


def read_bytes(path, limit):
    with Path(path).open('rb') as stream:
        data = stream.read(limit + 1)
    if len(data) > limit:
        raise ValueError('input exceeds verifier bound')
    return data


def read_json(path):
    return load_json(read_bytes(path, 1_048_576), max_bytes=1_048_576)


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--genesis', type=Path, required=True)
    parser.add_argument('--genesis-sha256', required=True, help='Digest pinned independently of the proof provider')
    parser.add_argument('--witness', type=Path, required=True)
    parser.add_argument('--header', type=Path, required=True)
    commands = parser.add_subparsers(dest='command', required=True)
    records = commands.add_parser('records')
    records.add_argument('--expect', nargs=2, action='append', required=True, metavar=('TABLE','KEY'))
    review = commands.add_parser('preflight')
    review.add_argument('--body', type=Path, required=True)
    review.add_argument('--signer-public-key', required=True)
    receipt = commands.add_parser('receipt')
    receipt.add_argument('--transaction', type=Path, required=True)
    receipt.add_argument('--block', type=Path, required=True)
    receipt.add_argument('--commit', type=Path, required=True)
    args = parser.parse_args(argv)
    try:
        trust = pinned_genesis(read_bytes(args.genesis, 1_048_576), args.genesis_sha256)
        witness, header = read_json(args.witness), read_json(args.header)
        if args.command == 'records':
            result = verify_compact_witness(witness, header, trust, expected_queries=args.expect)
        elif args.command == 'preflight':
            result = review_compact_transfer(witness, header, trust, read_json(args.body), args.signer_public_key)
        else:
            raw = read_bytes(args.transaction, 16_385)
            if raw.endswith(b'\n'): raw = raw[:-1]
            result = verify_compact_receipt(witness, header, trust, expected_transaction=raw,
                                            block=read_json(args.block), commit=read_json(args.commit))
        print(json.dumps(result, indent=2, ensure_ascii=True))
        return 0
    except (OSError, ValueError, KeyError, TypeError) as exc:
        print('Compact verification refused: ' + str(exc), file=sys.stderr)
        return 2


if __name__ == '__main__':
    raise SystemExit(main())
