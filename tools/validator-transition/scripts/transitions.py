#!/usr/bin/env python3
"""Offline validator-transition drafts and sequential signed-header witnesses.

Does not start a node, unlock keys, issue governance votes, broadcast, or change
any wallet. Input pins are selected by the caller, never taken from a peer reply.
"""
import argparse
import json
from pathlib import Path
import sys
import time

ROOT = Path(__file__).resolve().parents[1]
NATIVE = ROOT.parents[1]
sys.path[:0] = [str(ROOT / 'src'), str(NATIVE / 'src')]
from commit_verifier import pinned_genesis
from validator_sets import draft_transition, document_id
from validator_witness import start_witness, extend_witness, verify_witness, audit_transition, validate_policy
from transition_io import read_json, write_new


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--genesis', type=Path, required=True)
    parser.add_argument('--policy', type=Path, required=True)
    sub = parser.add_subparsers(dest='command', required=True)
    draft = sub.add_parser('draft')
    draft.add_argument('--current-set', type=Path, required=True)
    draft.add_argument('--new-set', type=Path, required=True)
    draft.add_argument('--expected-current-hash', required=True)
    draft.add_argument('--emitted-height', type=int, required=True)
    draft.add_argument('--output', type=Path, required=True)
    start = sub.add_parser('start'); start.add_argument('--entry', type=Path, required=True)
    start.add_argument('--output', type=Path, required=True)
    extend = sub.add_parser('extend'); extend.add_argument('--witness', type=Path, required=True)
    extend.add_argument('--entries', type=Path, required=True)
    extend.add_argument('--expected-parent-sha256', required=True)
    extend.add_argument('--output', type=Path, required=True)
    verify = sub.add_parser('verify'); verify.add_argument('--witness', type=Path, required=True)
    audit = sub.add_parser('audit'); audit.add_argument('--witness', type=Path, required=True)
    audit.add_argument('--draft', type=Path, required=True)
    args = parser.parse_args(argv)
    try:
        with args.genesis.open('rb') as f: genesis = f.read(1024 * 1024 + 1)
        policy = validate_policy(read_json(args.policy, 4096))
        trust = pinned_genesis(genesis, policy['genesis_sha256'])
        now = time.time_ns()
        if args.command == 'draft':
            result = draft_transition(read_json(args.current_set), read_json(args.new_set),
                chain_id=trust.chain_id, native_genesis_hash=trust.native_genesis_hash,
                expected_current_hash=args.expected_current_hash, emitted_height=args.emitted_height)
            write_new(args.output, result)
            result = {'status':'unsigned-draft-created', 'draft_sha256':document_id(result),
                      'governance_authorization_established':False,'activation_performed':False}
        elif args.command == 'start':
            witness = start_witness(read_json(args.entry), genesis, policy, now_ns=now)
            write_new(args.output, witness)
            result = verify_witness(witness, genesis, policy, now_ns=now)
        elif args.command == 'extend':
            witness = extend_witness(read_json(args.witness), read_json(args.entries), genesis, policy,
                expected_parent_sha256=args.expected_parent_sha256, now_ns=now)
            write_new(args.output, witness)
            result = verify_witness(witness, genesis, policy, now_ns=now)
        elif args.command == 'verify':
            result = verify_witness(read_json(args.witness), genesis, policy, now_ns=now)
        else:
            result = audit_transition(read_json(args.draft), read_json(args.witness), genesis, policy, now_ns=now)
        print(json.dumps(result, indent=2)); return 0
    except (ValueError, OSError, KeyError, TypeError, OverflowError):
        print('Transition input refused or trust unavailable. No validator, wallet or network was changed.', file=sys.stderr)
        return 2


if __name__ == '__main__': raise SystemExit(main())
