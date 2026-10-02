#!/usr/bin/env python3
"""Namespace and complete the local product tests in a separate interpreter."""
import argparse
from pathlib import Path
import sys
sys.dont_write_bytecode=True
ROOT=Path(__file__).resolve().parents[3]
sys.path[:0]=[str(ROOT/p) for p in ('src','scripts','tools/validator-transition/src',
 'tools/protocol4-client/src','tools/protocol4-wallet/src','tools/protocol4-delivery/src',
 'tools/protocol4-explorer/src','tools/protocol4-receipts/src','tools/local-platform/src')]
from release_check import base


def main():
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--output',type=Path,required=True)
    p.add_argument('--source-id',required=True);p.add_argument('--run-id',required=True);a=p.parse_args()
    paths=['tools/local-platform/src','tools/local-platform/tests','src','scripts','tools/protocol4-client/src',
        'tools/validator-transition/src','tools/protocol4-wallet/src','tools/protocol4-delivery/src',
        'tools/protocol4-explorer/src','tools/protocol4-receipts/src','tools/protocol4-wallet/tests',
        'tools/protocol4-delivery/tests','tools/protocol4-client/tests']
    base.GROUPS={'local_platform':('tools/local-platform/tests','test_*.py',paths)}
    return base.worker('local_platform',a.output,a.source_id,a.run_id)


if __name__=='__main__':raise SystemExit(main())
