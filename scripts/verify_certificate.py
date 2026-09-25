#!/usr/bin/env python3
"""Verify a static-devnet receipt packet against a separately pinned genesis.

No network requests, balances changed, keys loaded, or remote signers are used.
A valid local fixture is not evidence that CometBFT actually ran.
"""
import argparse
import json
from pathlib import Path
import sys
ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/'src'))
from commit_verifier import (MAX_PACKET_BYTES, VerificationError, load_json,
                             pinned_genesis, verify_packet)


def bounded_read(path: Path, bound: int) -> bytes:
    with path.open('rb') as f:
        raw=f.read(bound+1)
    if len(raw)>bound:raise VerificationError(f'{path.name} exceeds input bound')
    return raw


def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--genesis',required=True,type=Path)
    p.add_argument('--genesis-sha256',required=True,help='Obtain this trusted digest separately from the packet or RPC server.')
    p.add_argument('--packet',required=True,type=Path)
    p.add_argument('--expect-txid',required=True,action='append',help='Native transaction ID from your original signed intent; repeat for each expected payment.')
    p.add_argument('--expected-state-height',type=int,help='Exact externally expected state height; no latest-head inference is made.')
    args=p.parse_args()
    try:
        trust=pinned_genesis(bounded_read(args.genesis,1024*1024),args.genesis_sha256)
        packet=load_json(bounded_read(args.packet,MAX_PACKET_BYTES))
        report=verify_packet(packet,trust,expected_txids=args.expect_txid)
        if args.expected_state_height is not None and report['state']['state_height']!=args.expected_state_height:
            raise VerificationError('unexpected state height')
        report['genesis_file_sha256']=args.genesis_sha256.lower()
    except (VerificationError,OSError) as exc:
        report={'status':'rejected','reason':str(exc)}
    print(json.dumps(report,indent=2))
    return 0 if report['status']=='verified' else 2


if __name__=='__main__':raise SystemExit(main())
