#!/usr/bin/env python3
"""Run the source-pinned registry experiment suite; never starts an engine."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import sys
import unittest

HERE=Path(__file__).resolve().parents[1];ROOT=HERE.parents[1]


def check():
    m=json.loads((HERE/'SOURCE_MANIFEST.json').read_bytes())
    for e in m['files']:
        p=HERE/e['path'];raw=p.read_bytes()
        if p.is_symlink() or len(raw)!=e['bytes'] or hashlib.sha256(raw).hexdigest()!=e['sha256']:
            raise ValueError('registry source inventory mismatch')
    return len(m['files'])


def main():
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--report',type=Path);a=p.parse_args()
    n=check()
    paths=[str(HERE/'src'),str(HERE/'tests'),str(ROOT/'tools/validator-transition/src'),str(ROOT/'src'),str(ROOT/'tests')]
    sys.path[:0]=paths;os.environ['PYTHONPATH']=os.pathsep.join(paths)
    class Result(unittest.TextTestResult):
        def __init__(self,*args,**kw):super().__init__(*args,**kw);self.ids=[]
        def addSuccess(self,test):super().addSuccess(test);self.ids.append(test.id())
    suite=unittest.defaultTestLoader.discover(str(HERE/'tests'),pattern='test_*.py');expected=suite.countTestCases()
    r=unittest.TextTestRunner(verbosity=2,resultclass=Result).run(suite)
    passed=expected>0 and r.testsRun==expected and r.wasSuccessful() and not r.skipped and len(set(r.ids))==expected
    result={'status':'passed' if passed else 'failed','source_files':n,'source_files_after':check(),
        'tests':r.testsRun,'passed_ids':r.ids,'failures':len(r.failures),'errors':len(r.errors),'skips':len(r.skipped),
        'scope':'isolated registry experiment; not native money or CometBFT','consensus_executed':False}
    if a.report:
        fd=os.open(a.report,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
        with os.fdopen(fd,'w') as f:json.dump(result,f,indent=2);f.write('\n')
    print(json.dumps(result,indent=2));return 0 if passed else 1

if __name__=='__main__':raise SystemExit(main())
