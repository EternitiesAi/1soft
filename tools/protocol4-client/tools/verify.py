#!/usr/bin/env python3
"""Exact-source P4 client suite. Not the complete native release or engine gates."""
import argparse
import hashlib
import importlib.metadata
import json
import os
from pathlib import Path
import sys
import unittest

ROOT=Path(__file__).resolve().parents[1]


def checked(root, records):
    seen=set()
    for record in records:
        p=Path(record['path'])
        if p.is_absolute() or '..' in p.parts or p.as_posix() in seen:raise ValueError('invalid source path')
        seen.add(p.as_posix());target=root/p
        if any(parent.is_symlink() for parent in (target,*target.parents)):raise ValueError('aliased source')
        data=target.read_bytes()
        if len(data)!=record['bytes'] or hashlib.sha256(data).hexdigest()!=record['sha256']:
            raise ValueError('source bytes differ: '+p.as_posix())
    return len(seen)


def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--native-root',type=Path,default=ROOT.parents[1])
    p.add_argument('--report',type=Path)
    a=p.parse_args();native=a.native_root.resolve()
    dependencies=json.loads((ROOT/'DEPENDENCIES.json').read_bytes())
    own=json.loads((ROOT/'SOURCE_MANIFEST.json').read_bytes())
    before={'client':checked(ROOT,own['files']),'pinned_native_dependencies':checked(native,dependencies['files'])}
    packages={}
    for line in (native/'requirements.txt').read_text().splitlines():
        if not line.strip() or line.lstrip().startswith('#'):continue
        name,version=line.split('==');packages[name]=importlib.metadata.version(name)
        if packages[name]!=version:raise ValueError('installed dependency differs')
    paths=[str(ROOT/'src'),str(ROOT/'tests'),str(native/'src'),str(native/'tools/validator-transition/src')]
    sys.path[:0]=paths;os.environ['PYTHONPATH']=os.pathsep.join(paths)
    os.environ['PYTHONDONTWRITEBYTECODE']='1'
    suite=unittest.defaultTestLoader.discover(str(ROOT/'tests'),pattern='test_*.py')
    def ids(items):
        for test in items:
            if isinstance(test,unittest.TestSuite):yield from ids(test)
            else:yield test.id()
    expected=list(ids(suite))
    class Result(unittest.TextTestResult):
        def __init__(self,*args,**kw):super().__init__(*args,**kw);self.ids=[]
        def addSuccess(self,test):super().addSuccess(test);self.ids.append(test.id())
    result=unittest.TextTestRunner(verbosity=2,resultclass=Result).run(suite)
    after={'client':checked(ROOT,own['files']),'pinned_native_dependencies':checked(native,dependencies['files'])}
    passed=bool(expected) and len(set(expected))==len(expected) and sorted(result.ids)==sorted(expected) and result.wasSuccessful() and not result.skipped and not result.expectedFailures
    report={'schema':1,'scope':'P4 read client, not full PR28 release or consensus',
        'parent_commit':dependencies['parent_commit'],'parent_native_tree':dependencies['native_runtime_tree'],
        'source_checks_before':before,'source_checks_after':after,'dependencies':packages,
        'tests':result.testsRun,'expected_ids':expected,'successful_ids':result.ids,'passed':passed,
        'failures':len(result.failures),'errors':len(result.errors),'skips':len(result.skipped),
        'expected_failures':len(result.expectedFailures),'unexpected_successes':len(result.unexpectedSuccesses),
        'actual_consensus_executed':False,'real_funds':False}
    if a.report:
        fd=os.open(a.report,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
        with os.fdopen(fd,'w') as f:json.dump(report,f,indent=2);f.write('\n');f.flush();os.fsync(f.fileno())
    print(json.dumps({k:v for k,v in report.items() if not k.endswith('_ids')},indent=2))
    return 0 if passed else 1


if __name__=='__main__':raise SystemExit(main())
