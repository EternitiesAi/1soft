#!/usr/bin/env python3
"""Offline committed merchant-payment proof check under separately trusted pins.

Use a trusted genesis, original policy, expectation and assignment, and explicit
AS-OF nanosecond time. Bundle metadata cannot select any of these. No engine,
wallet workspace, keys, network, service execution or clock renewal is used.
"""
import argparse
import os
from pathlib import Path
import sys

sys.dont_write_bytecode = True
ROOT = Path(__file__).resolve().parents[3]
sys.path[:0] = [str(ROOT/'src'),str(ROOT/'scripts')]+[str(p) for p in sorted((ROOT/'tools').glob('*/src'))]
from commit_verifier import encode, exact, load_json
from local_devnet import read_private
from merchant_book import EXPECTATION_FIELDS
from merchant_proof import MAX_PROOF_BYTES, verify_merchant_proof
from payment_x402 import NativePaymentExpectation, TrustedMerchantAssignment

REFUSAL = '1soft could not verify this merchant proof under the supplied independent trust, intent and time.'


class Parser(argparse.ArgumentParser):
    def error(self, _): self.exit(2, REFUSAL+'\n')


def main(argv=None):
    os.umask(0o077)
    p = Parser(description=__doc__)
    for name in ('proof','genesis','policy','expectation','assignment'):
        p.add_argument('--'+name,type=Path,required=True)
    p.add_argument('--as-of-ns',type=int,required=True,
                   help='Independently selected historical verification time; never taken from the bundle.')
    p.add_argument('--profile',choices=('legacy','alpha'),default='legacy',help='Explicit trusted proof profile; no automatic format fallback.')
    args = p.parse_args(argv)
    expectation = load_json(read_private(args.expectation,8192), max_bytes=8192)
    exact(expectation, EXPECTATION_FIELDS, 'independent expectation')
    assignment = load_json(read_private(args.assignment,8192), max_bytes=8192)
    exact(assignment, {'quote_sha256','request_id','recipient','payer','wire_sha256'},'independent assignment')
    verifier=verify_merchant_proof;maximum=MAX_PROOF_BYTES
    if args.profile=='alpha':
        from merchant_alpha import verify_proof,MAX_PROOF_BYTES as ALPHA_MAX
        verifier=verify_proof;maximum=ALPHA_MAX
    report = verifier(read_private(args.proof,maximum),
        genesis_bytes=read_private(args.genesis), policy=load_json(read_private(args.policy,4096),max_bytes=4096),
        expectation=NativePaymentExpectation(**expectation), assignment=TrustedMerchantAssignment(**assignment),
        now_ns=args.as_of_ns)
    print(encode(report).decode('ascii'),flush=True)
    return 0


if __name__=='__main__':
    try: raise SystemExit(main())
    except Exception:
        print(REFUSAL,file=sys.stderr);raise SystemExit(1)
    except KeyboardInterrupt:
        print(REFUSAL,file=sys.stderr);raise SystemExit(130)
