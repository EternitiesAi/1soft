#!/usr/bin/env python3
"""Exact-source local P4 delivery tests; no engine, public network or real funds."""
import argparse
import hashlib
import importlib.metadata
import json
import os
from pathlib import Path
import sys
import unittest

ROOT=Path(__file__).resolve().parents[1]
BASE='b73a88ca53666972ae2c8ce35fd9edb7ac0cb41c'


def checked(root,entries):
    seen=set()
    for e in entries:
        p=Path(e['path'])
        if p.is_absolute() or '..' in p.parts or str(p) in seen or (root/p).is_symlink():raise ValueError('unsafe source entry')
        seen.add(str(p));data=(root/p).read_bytes()
        if len(data)!=e['bytes'] or hashlib.sha256(data).hexdigest()!=e['sha256']:raise ValueError('source mismatch: '+str(p))
    return len(seen)


def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--native-root',type=Path,default=ROOT.parents[1]);p.add_argument('--report',type=Path)
    a=p.parse_args();native=a.native_root.resolve()
    manifest=json.loads((ROOT/'SOURCE_MANIFEST.json').read_bytes())
    dependencies=json.loads((ROOT/'DEPENDENCIES.json').read_bytes())
    before={'delivery':checked(ROOT,manifest['files']),'pinned_dependencies':checked(native,dependencies['files'])}
    paths=[ROOT/'src',ROOT/'tests',native/'src',native/'tests',native/'tools/validator-transition/src']
    for name in ('protocol4-client','protocol4-wallet'):paths.extend([native/'tools'/name/'src',native/'tools'/name/'tests'])
    paths=list(map(str,paths));sys.path[:0]=paths;os.environ['PYTHONPATH']=os.pathsep.join(paths)
    class Result(unittest.TextTestResult):
        def __init__(self,*args,**kwargs):super().__init__(*args,**kwargs);self.ids=[]
        def addSuccess(self,test):super().addSuccess(test);self.ids.append(test.id())
    suite=unittest.defaultTestLoader.discover(str(ROOT/'tests'),pattern='test_*.py')
    def ids(s):
        for t in s:
            if isinstance(t,unittest.TestSuite):yield from ids(t)
            else:yield t.id()
    expected=list(ids(suite));r=unittest.TextTestRunner(verbosity=2,resultclass=Result).run(suite)
    after={'delivery':checked(ROOT,manifest['files']),'pinned_dependencies':checked(native,dependencies['files'])}
    passed=(bool(expected) and len(expected)==len(set(expected)) and sorted(r.ids)==sorted(expected) and r.wasSuccessful()
            and not r.skipped and not r.expectedFailures and not r.unexpectedSuccesses)
    report={'schema':1,'scope':'new local delivery component only; not full PR28 or engine qualification',
        'parent_commit':BASE,'tests':r.testsRun,'passed':passed,'failures':len(r.failures),'errors':len(r.errors),
        'skips':len(r.skipped),'expected_failures':len(r.expectedFailures),'unexpected_successes':len(r.unexpectedSuccesses),
        'expected_ids':expected,'successful_ids':r.ids,'source_checks_before':before,'source_checks_after':after,
        'python':sys.version.split()[0],'dependencies':{k:importlib.metadata.version(k) for k in ('cryptography','protobuf')},
        'consensus_executed':False,'real_funds':False,'scope_of_submissions':'disposable loopback fixture only'}
    if a.report:
        fd=os.open(a.report,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
        with os.fdopen(fd,'w') as f:json.dump(report,f,indent=2);f.write('\n');f.flush();os.fsync(f.fileno())
    print(json.dumps({k:v for k,v in report.items() if not k.endswith('_ids')},indent=2))
    return 0 if passed else 1

if __name__=='__main__':raise SystemExit(main())
