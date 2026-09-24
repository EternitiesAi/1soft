#!/usr/bin/env python3
"""Verify and test the independently runnable transport subset, without Actions.

--part/--parts split the known test cases into explicit bounded groups. A group
pass is not a full-suite pass; reports include the exact requested/successful IDs.
"""
import argparse
import json
import os
from pathlib import Path
import sys
import unittest
from verify_checkout import verify_checkout

ROOT = Path(__file__).resolve().parents[1]


def flatten(suite):
    for item in suite:
        if isinstance(item, unittest.TestSuite):
            yield from flatten(item)
        else:
            yield item


class RecordedResult(unittest.TextTestResult):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.succeeded = []
    def addSuccess(self, test):
        self.succeeded.append(test.id())
        super().addSuccess(test)


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--parts', type=int, default=1)
    parser.add_argument('--part', type=int, default=0)
    args = parser.parse_args(argv)
    if not 1 <= args.parts <= 64 or not 0 <= args.part < args.parts:
        parser.error('require 1 <= parts <= 64 and 0 <= part < parts')
    try:
        integrity = verify_checkout(ROOT, 'TRANSPORT_MANIFEST.json')
        if integrity['status'] != 'passed':
            raise ValueError('transport source inventory does not match')
        os.chdir(ROOT)
        sys.path[:0] = [str(ROOT/'src'), str(ROOT/'tests')]
        os.environ['PYTHONPATH'] = str(ROOT/'src')+os.pathsep+str(ROOT/'tests')
        cases = list(flatten(unittest.defaultTestLoader.discover(str(ROOT/'tests'), pattern='test_payment_transport.py')))
        start = len(cases)*args.part//args.parts
        stop = len(cases)*(args.part+1)//args.parts
        selected = cases[start:stop]
        if not selected:
            raise ValueError('no tests selected; refusing a passing result')
        requested = [case.id() for case in selected]
        result = unittest.TextTestRunner(verbosity=2, resultclass=RecordedResult).run(unittest.TestSuite(selected))
        passed = result.wasSuccessful() and not result.skipped and set(result.succeeded) == set(requested)
        print(json.dumps({'scope':'loopback transport subset, not validator consensus',
            'part':args.part,'parts':args.parts,'total_discovered':len(cases),
            'requested_ids':requested,'succeeded':result.succeeded,'passed':passed,
            'source_manifest_sha256':integrity['manifest_sha256'],'consensus_verified':False},indent=2))
        return 0 if passed else 1
    except (OSError,ValueError) as exc:
        print('Transport gate failed: '+str(exc),file=sys.stderr)
        return 2


if __name__ == '__main__':
    raise SystemExit(main())
