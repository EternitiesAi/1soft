#!/usr/bin/env python3
"""Registry-only local verification against exact unchanged dependencies."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import sys
import unittest
ROOT=Path(__file__).resolve().parents[1]


def check(root, entries):
    for e in entries:
        p=Path(e['path'])
        if p.is_absolute() or '..' in p.parts or (root/p).is_symlink():raise ValueError('unsafe inventory')
        raw=(root/p).read_bytes()
        if len(raw)!=e['bytes'] or hashlib.sha256(raw).hexdigest()!=e['sha256']:raise ValueError('inventory mismatch: '+e['path'])
    return len(entries)


def main():
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--native-root',type=Path,default=ROOT.parents[1])
    p.add_argument('--report',type=Path);args=p.parse_args();native=args.native_root.resolve()
    own=json.loads((ROOT/'SOURCE_MANIFEST.json').read_bytes())['files']
    deps=json.loads((ROOT/'DEPENDENCIES.json').read_bytes())['files']
    counts={'component':check(ROOT,own),'parent_runtime':check(native,deps)}
    paths=[str(ROOT/'src'),str(ROOT/'tests'),str(native/'tools/validator-transition/src'),str(native/'tools/validator-transition/tests'),str(native/'src'),str(native/'tests')]
    sys.path[:0]=paths;os.environ['PYTHONPATH']=os.pathsep.join(paths)
    class Result(unittest.TextTestResult):
        def __init__(self,*a,**kw):super().__init__(*a,**kw);self.ids=[]
        def addSuccess(self,test):super().addSuccess(test);self.ids.append(test.id())
    suite=unittest.defaultTestLoader.discover(str(ROOT/'tests'),pattern='test_*.py');expected=suite.countTestCases()
    result=unittest.TextTestRunner(verbosity=2,resultclass=Result).run(suite)
    counts.update(component_after=check(ROOT,own),parent_runtime_after=check(native,deps))
    passed=expected>0 and expected==result.testsRun==len(set(result.ids)) and result.wasSuccessful() and not result.skipped
    report={'scope':'authorized development registry, not native monetary integration or engine acceptance',
            'tests':result.testsRun,'passed':passed,'successful_ids':result.ids,'source_checks':counts,
            'skips':len(result.skipped),'failures':len(result.failures),'errors':len(result.errors),
            'native_protocol_changed':False,'consensus_executed':False,'public_network_ready':False}
    if args.report:
        with args.report.open('x') as f:json.dump(report,f,indent=2);f.write('\n')
    print(json.dumps(report,indent=2));return 0 if passed else 1
if __name__=='__main__':raise SystemExit(main())
