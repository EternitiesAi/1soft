#!/usr/bin/env python3
"""Local persistent-proof-index tests, not real validator or financial tests."""
import argparse
import json
import os
from pathlib import Path
import sys
import unittest
from verify_checkout import verify_checkout
ROOT=Path(__file__).resolve().parents[1]


def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--application',action='store_true',help='Also test integration; requires the complete local source tree')
    args=p.parse_args()
    try:
        integrity=verify_checkout(ROOT,'SOURCE_MANIFEST.json' if args.application else 'INDEX_MANIFEST.json')
        if integrity['status']!='passed':raise ValueError('required source inventory differs')
        sys.path[:0]=[str(ROOT/'src'),str(ROOT/'tests')]
        os.environ['PYTHONPATH']=str(ROOT/'src')+os.pathsep+str(ROOT/'tests')
        suite=unittest.TestSuite()
        for name in (['test_state_index','test_indexed_application'] if args.application else ['test_state_index']):
            suite.addTests(unittest.defaultTestLoader.loadTestsFromName(name))
        count=suite.countTestCases()
        result=unittest.TextTestRunner(verbosity=2).run(suite)
        passed=count>0 and result.wasSuccessful() and not result.skipped and result.testsRun==count
        print(json.dumps({'scope':'persistent index'+(' and native application' if args.application else ' standalone'),
            'tests_run':result.testsRun,'skipped':len(result.skipped),'failures':len(result.failures),
            'errors':len(result.errors),'passed':passed,'consensus_verified':False,
            'manifest_sha256':integrity['manifest_sha256']},indent=2))
        return 0 if passed else 1
    except (OSError,ValueError) as exc:
        print('Index gate failed: '+str(exc),file=sys.stderr);return 2
if __name__=='__main__':raise SystemExit(main())
