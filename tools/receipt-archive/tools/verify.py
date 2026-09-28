#!/usr/bin/env python3
"""Check the exact archive add-on and its pinned runtime dependencies, then test.

Not the full native suite; never downloads, starts an engine or contacts peers.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import sys
import unittest

ROOT=Path(__file__).resolve().parents[1]
PIN='e621222ca58d514beb1b6f6fe6bc84b743f629ff361239b181ede84bd36af017'
BASE='072ebe6a6850c80044a5ad1b0496c6f3a1ffebe0'


def checked(root, entries):
    for entry in entries:
        p=Path(entry['path'])
        if p.is_absolute() or '..' in p.parts or (root/p).is_symlink():
            raise ValueError('unsafe inventory entry')
        raw=(root/p).read_bytes()
        if len(raw)!=entry['bytes'] or hashlib.sha256(raw).hexdigest()!=entry['sha256']:
            raise ValueError('inventory mismatch: '+entry['path'])
    return len(entries)


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--native-root',type=Path,default=ROOT.parents[1])
    parser.add_argument('--report',type=Path)
    args=parser.parse_args();native=args.native_root.resolve()
    raw=(native/'SOURCE_MANIFEST.json').read_bytes()
    if hashlib.sha256(raw).hexdigest()!=PIN:raise ValueError('requires exact PR15 root manifest')
    entries=json.loads(raw)['files']
    # Every native runtime source plus the two native test helpers we import and
    # dependency pins. Unused parent runner/test files are NOT claimed verified.
    deps=[e for e in entries if e['path'].startswith('src/') or e['path'] in
          ('requirements.txt','tests/certificate_fixture.py','tests/test_block_application.py')]
    own=json.loads((ROOT/'SOURCE_MANIFEST.json').read_bytes())['files']
    counts={'addon':checked(ROOT,own),'native_runtime_and_helpers':checked(native,deps)}
    paths=[str(ROOT/'src'),str(native/'src'),str(native/'tests'),str(ROOT/'tests')]
    sys.path[:0]=paths;os.environ['PYTHONPATH']=os.pathsep.join(paths)
    class Recorded(unittest.TextTestResult):
        def __init__(self,*a,**kw):super().__init__(*a,**kw);self.ids=[]
        def addSuccess(self,test):super().addSuccess(test);self.ids.append(test.id())
    suite=unittest.defaultTestLoader.discover(str(ROOT/'tests'),pattern='test_*.py')
    expected=suite.countTestCases()
    result=unittest.TextTestRunner(verbosity=2,resultclass=Recorded).run(suite)
    counts['addon_after']=checked(ROOT,own);counts['native_after']=checked(native,deps)
    passed=(expected>0 and result.testsRun==expected and result.wasSuccessful() and
            not result.skipped and len(set(result.ids))==expected)
    report={'scope':'receipt archive add-on, not full native regression', 'parent_commit':BASE,
            'source_checks':counts,'expected':expected,'run':result.testsRun,'passed':passed,
            'failures':len(result.failures),'errors':len(result.errors),'skipped':len(result.skipped),
            'passed_ids':result.ids,'consensus_executed':False,'native_receipts_pruned':False}
    if args.report:
        fd=os.open(args.report,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
        with os.fdopen(fd,'w') as f:json.dump(report,f,indent=2);f.write('\n')
    print(json.dumps(report,indent=2))
    return 0 if passed else 1

if __name__=='__main__':raise SystemExit(main())
