#!/usr/bin/env python3
"""Check exact add-on/dependency bytes, then run bounded local tests. No downloads.

This is not the full PR28 profile or real-engine acceptance. The dependency slice
can run this command, but is explicitly not a complete node release checkout.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import sys
import unittest

ADDON=Path(__file__).resolve().parents[1]
BASE='b73a88ca53666972ae2c8ce35fd9edb7ac0cb41c'
CORE_TREE='7eca75793b8f083216fdfa4a64102c0555713357'

def sha(b):return hashlib.sha256(b).hexdigest()

def check(root,entries):
    seen=set()
    for row in entries:
        p=Path(row['path']);f=root/p
        if p.is_absolute() or '..' in p.parts or row['path'] in seen or f.is_symlink():raise ValueError('unsafe dependency path')
        seen.add(row['path']);raw=f.read_bytes()
        if len(raw)!=row['bytes'] or sha(raw)!=row['sha256']:raise ValueError('source mismatch: '+row['path'])
    return len(seen)

def runtime_tree(root):
    data=bytearray()
    for p in sorted((root/'src').glob('*.py'),key=lambda p:p.name.encode()):
        if p.is_symlink() or p.stat().st_mode&0o111:raise ValueError('unexpected runtime file mode')
        raw=p.read_bytes();blob=hashlib.sha1(b'blob '+str(len(raw)).encode()+b'\0'+raw).digest()
        data.extend(b'100644 '+p.name.encode()+b'\0'+blob)
    return hashlib.sha1(b'tree '+str(len(data)).encode()+b'\0'+data).hexdigest()

def main():
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--native-root',type=Path,default=ADDON.parents[1])
    p.add_argument('--report',type=Path,required=True);p.add_argument('--regressions',action='store_true');a=p.parse_args()
    native=a.native_root.resolve();manifest=json.loads((ADDON/'SOURCE_MANIFEST.json').read_bytes())
    dependency=json.loads((ADDON/'DEPENDENCIES.json').read_bytes())
    counts={'addon':check(ADDON,manifest['files']),'dependencies':check(native,dependency['files'])}
    if runtime_tree(native)!=CORE_TREE:raise ValueError('complete native runtime differs from PR28')
    paths=[str(ADDON/'src'),str(ADDON/'scripts'),str(ADDON/'tests'),str(native/'src'),str(native/'tests'),
           str(native/'scripts'),str(native/'tools/release'),str(native/'tools/validator-transition/src')]
    sys.path[:0]=paths;os.environ['PYTHONPATH']=os.pathsep.join(paths);os.environ['PYTHONDONTWRITEBYTECODE']='1'
    loader=unittest.TestLoader()
    suite=(loader.loadTestsFromNames(['test_protocol4_core','test_native','test_native_budgets','test_account_lifecycle'])
           if a.regressions else loader.discover(str(ADDON/'tests'),pattern='test_*.py'))
    def flatten(s):
        for t in s:
            if isinstance(t,unittest.TestSuite):yield from flatten(t)
            else:yield t.id()
    expected=list(flatten(suite))
    class Result(unittest.TextTestResult):
        def __init__(self,*args,**kwargs):super().__init__(*args,**kwargs);self.ids=[]
        def addSuccess(self,test):self.ids.append(test.id());super().addSuccess(test)
    result=unittest.TextTestRunner(verbosity=2,resultclass=Result).run(suite)
    check(ADDON,manifest['files']);check(native,dependency['files'])
    okay=bool(expected) and len(set(expected))==len(expected) and sorted(expected)==sorted(result.ids) and result.wasSuccessful() and not result.skipped
    report={'schema':1,'parent_commit':BASE,'parent_runtime_tree':CORE_TREE,
       'scope':'selected inherited regressions' if a.regressions else 'P4 recovery local component tests',
       'expected_ids':expected,'passed_ids':result.ids,'tests':result.testsRun,'passed':okay,
       'failures':len(result.failures),'errors':len(result.errors),'skips':len(result.skipped),
       'source_checks':counts,'source_rechecked':True,'consensus_executed':False,'full_release_profile':False}
    fd=os.open(a.report,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
    with os.fdopen(fd,'w') as f:json.dump(report,f,indent=2);f.write('\n');f.flush();os.fsync(f.fileno())
    print(json.dumps({k:v for k,v in report.items() if not k.endswith('_ids')},indent=2))
    return 0 if okay else 1

if __name__=='__main__':raise SystemExit(main())
