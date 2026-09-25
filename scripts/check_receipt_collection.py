#!/usr/bin/env python3
"""Run the hash-checked, local receipt-collection tests without hosted Actions."""
import argparse
import json
import os
from pathlib import Path
import sys
import unittest
from verify_checkout import verify_checkout

ROOT=Path(__file__).resolve().parents[1]


def main(argv=None):
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--parts',type=int,default=1)
    parser.add_argument('--part',type=int,default=0)
    args=parser.parse_args(argv)
    if not 1 <= args.parts <= 32 or not 0 <= args.part < args.parts:
        parser.error('require valid part/parts from 1 through 32')
    try:
        integrity=verify_checkout(ROOT,'RECEIPT_MANIFEST.json')
        if integrity['status']!='passed':raise ValueError('receipt source inventory differs')
        os.chdir(ROOT);sys.path[:0]=[str(ROOT/'src'),str(ROOT/'tests')]
        os.environ['PYTHONPATH']=str(ROOT/'src')+os.pathsep+str(ROOT/'tests')
        def flatten(suite):
            for item in suite:
                if isinstance(item,unittest.TestSuite):yield from flatten(item)
                else:yield item
        cases=list(flatten(unittest.defaultTestLoader.discover(str(ROOT/'tests'),pattern='test_receipt_collection.py')))
        selected=cases[len(cases)*args.part//args.parts:len(cases)*(args.part+1)//args.parts]
        if not selected:raise ValueError('no selected tests')
        ids=[test.id() for test in selected]
        result=unittest.TextTestRunner(verbosity=2).run(unittest.TestSuite(selected))
        passed=result.wasSuccessful() and not result.skipped and result.testsRun==len(ids)
        print(json.dumps({'scope':'receipt collection HTTP fixtures, not validator consensus',
            'part':args.part,'parts':args.parts,'total_cases':len(cases),'executed_ids':ids,
            'passed':passed,'source_manifest_sha256':integrity['manifest_sha256'],
            'consensus_verified':False},indent=2))
        return 0 if passed else 1
    except (OSError,ValueError) as exc:
        print('Receipt gate failed: '+str(exc),file=sys.stderr);return 2


if __name__=='__main__':raise SystemExit(main())
