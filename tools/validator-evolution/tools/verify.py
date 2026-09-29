#!/usr/bin/env python3
"""Verify all tracked source, the add-on inventory, then its exact distinct tests."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import sys
import unittest
ADDON=Path(__file__).resolve().parents[1];ROOT=ADDON.parents[1]
sys.path[:0]=[str(ROOT/'tools/release')]
from check_release import source_identity,checked_manifests,successful,store_json


def own_manifest():
    rows=json.loads((ADDON/'SOURCE_MANIFEST.json').read_bytes())['files']
    for e in rows:
        p=Path(e['path']);assert not p.is_absolute() and '..' not in p.parts
        b=(ADDON/p).read_bytes()
        if len(b)!=e['bytes'] or hashlib.sha256(b).hexdigest()!=e['sha256']:raise ValueError('add-on source mismatch')
    return len(rows)


def main():
    p=argparse.ArgumentParser();p.add_argument('--report',type=Path,required=True);a=p.parse_args()
    source=source_identity(ROOT);manifests=checked_manifests(ROOT);own=own_manifest()
    paths=[str(ADDON/'src'),str(ADDON/'tests'),str(ROOT/'src'),str(ROOT/'tests')]
    sys.path[:0]=paths;os.environ['PYTHONPATH']=os.pathsep.join(paths)
    from check_release import flatten
    suite=unittest.TestLoader().discover(str(ADDON/'tests'),pattern='test_*.py')
    expected=[t.id() for t in flatten(suite)]
    class Result(unittest.TextTestResult):
        def __init__(self,*a,**kw):super().__init__(*a,**kw);self.ids=[]
        def addSuccess(self,test):super().addSuccess(test);self.ids.append(test.id())
    r=unittest.TextTestRunner(verbosity=2,resultclass=Result).run(suite)
    report={'source_commit':source['commit'],'source_tree':source['tree'],'source_id':source['source_id'],
            'expected_ids':expected,'successful_ids':r.ids,'run':r.testsRun,'skips':len(r.skipped),
            'failures':len(r.failures),'errors':len(r.errors),'expected_failures':len(r.expectedFailures),
            'unexpected_successes':len(r.unexpectedSuccesses),'addon_manifest':own,
            'native_manifests':manifests,'consensus_executed':False,'governance_implemented':False}
    report['passed']=successful(report) and source_identity(ROOT)==source and own_manifest()==own
    store_json(a.report,report);print(json.dumps({k:v for k,v in report.items() if not k.endswith('_ids')},indent=2))
    return 0 if report['passed'] else 1

if __name__=='__main__':raise SystemExit(main())
