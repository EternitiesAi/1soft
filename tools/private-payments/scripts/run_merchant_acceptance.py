#!/usr/bin/env python3
"""Run one outside-source finite merchant journey with the pinned engine."""
import argparse
import json
from pathlib import Path
import sys
sys.dont_write_bytecode=True
ROOT=Path(__file__).resolve().parents[3]
sys.path[:0]=[str(ROOT/p) for p in ('src','scripts','tests','tools/private-payments/scripts')]+[str(p) for p in (ROOT/'tools').glob('*/src')]
from merchant_acceptance import run_merchant

def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--engine',required=True,type=Path);parser.add_argument('--output',required=True,type=Path)
    args=parser.parse_args()
    try:result=run_merchant(args.engine,args.output)
    except BaseException as exc:
        print(json.dumps(dict(status='refused',error_type=type(exc).__name__)),flush=True);return 1
    print(json.dumps(result,sort_keys=True),flush=True)
    return 0 if result['status']=='passed' else 1

if __name__=='__main__':raise SystemExit(main())
