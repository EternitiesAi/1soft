#!/usr/bin/env python3
"""Source-pinned local explorer tests; not a full chain or validator qualification."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import sys
import unittest

ROOT=Path(__file__).resolve().parents[1]

def check(root,files):
    for entry in files:
        p=Path(entry['path'])
        if p.is_absolute() or '..' in p.parts or (root/p).is_symlink():raise ValueError('unsafe inventory')
        raw=(root/p).read_bytes()
        if len(raw)!=entry['bytes'] or hashlib.sha256(raw).hexdigest()!=entry['sha256']:
            raise ValueError('source mismatch: '+entry['path'])
    return len(files)


def main():
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--native-root',type=Path,default=ROOT.parents[1])
    p.add_argument('--report',type=Path);a=p.parse_args();native=a.native_root.resolve()
    own=json.loads((ROOT/'SOURCE_MANIFEST.json').read_bytes())
    deps=json.loads((ROOT/'DEPENDENCIES.json').read_bytes())
    n=check(ROOT,own['files']);d=check(native,deps['files'])
    paths=[str(ROOT/'src'),str(ROOT/'tests'),str(native/'src'),str(native/'tests')]
    sys.path[:0]=paths;os.environ['PYTHONPATH']=os.pathsep.join(paths)
    class Result(unittest.TextTestResult):
        def __init__(self,*args,**kwargs):super().__init__(*args,**kwargs);self.ids=[]
        def addSuccess(self,test):super().addSuccess(test);self.ids.append(test.id())
    suite=unittest.defaultTestLoader.discover(str(ROOT/'tests'),pattern='test_*.py')
    count=suite.countTestCases();result=unittest.TextTestRunner(verbosity=2,resultclass=Result).run(suite)
    passed=count>0 and result.testsRun==count and result.wasSuccessful() and not result.skipped and len(set(result.ids))==count
    report={'scope':'explorer integration, not full native test suite','parent_commit':deps['parent_commit'],
        'tests':result.testsRun,'failures':len(result.failures),'errors':len(result.errors),'skipped':len(result.skipped),
        'passed':passed,'passed_ids':result.ids,'source_checks':{'explorer':n,'native':d,
        'explorer_after':check(ROOT,own['files']),'native_after':check(native,deps['files'])},
        'consensus_executed':False,'real_funds':False}
    if a.report:
        fd=os.open(a.report,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
        with os.fdopen(fd,'w') as f:json.dump(report,f,indent=2);f.write('\n')
    print(json.dumps({k:v for k,v in report.items() if k!='passed_ids'},indent=2))
    return 0 if passed else 1

if __name__=='__main__':raise SystemExit(main())
