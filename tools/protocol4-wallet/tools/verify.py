#!/usr/bin/env python3
"""Source-pinned P4 wallet tests, not full PR28 or live-engine qualification."""
import argparse
import hashlib
import importlib.metadata
import json
import os
from pathlib import Path
import sys
import unittest

ROOT=Path(__file__).resolve().parents[1]


def checked(root,entries):
    seen=set()
    for row in entries:
        name=Path(row['path']);path=root/name
        if name.is_absolute() or '..' in name.parts or name.as_posix() in seen:
            raise ValueError('unsafe/duplicate source path')
        seen.add(name.as_posix())
        if any(p.is_symlink() for p in (path,*path.parents)):
            raise ValueError('aliased source path')
        raw=path.read_bytes()
        if len(raw)!=row['bytes'] or hashlib.sha256(raw).hexdigest()!=row['sha256']:
            raise ValueError('source mismatch: '+str(name))
    return len(seen)


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--native-root',type=Path,default=ROOT.parents[1])
    parser.add_argument('--report',type=Path)
    args=parser.parse_args();native=args.native_root.resolve()
    manifest=json.loads((ROOT/'SOURCE_MANIFEST.json').read_bytes())
    dependencies=json.loads((ROOT/'DEPENDENCIES.json').read_bytes())
    def inventories():
        return {'wallet':checked(ROOT,manifest['files']),
                'pr28_runtime_and_helpers':checked(native,dependencies['native_files']),
                'unchanged_p4_read_client':checked(native,dependencies['read_client_files'])}
    before=inventories();packages={}
    for line in (native/'requirements.txt').read_text().splitlines():
        if not line.strip() or line.lstrip().startswith('#'):continue
        name,version=line.strip().split('==');packages[name]=importlib.metadata.version(name)
        if packages[name]!=version:raise ValueError('installed dependency differs: '+name)
    paths=[ROOT/'src',ROOT/'tests',native/'src',native/'tools/validator-transition/src',
           native/'tools/protocol4-client/src',native/'tools/protocol4-client/tests']
    sys.path[:0]=list(map(str,paths));os.environ['PYTHONPATH']=os.pathsep.join(map(str,paths))
    os.environ['PYTHONDONTWRITEBYTECODE']='1'
    suite=unittest.TestLoader().discover(str(ROOT/'tests'),pattern='test_*.py')
    def identities(items):
        for test in items:
            if isinstance(test,unittest.TestSuite):yield from identities(test)
            else:yield test.id()
    expected=list(identities(suite))
    class Result(unittest.TextTestResult):
        def __init__(self,*args,**kw):super().__init__(*args,**kw);self.ids=[]
        def addSuccess(self,test):super().addSuccess(test);self.ids.append(test.id())
    result=unittest.TextTestRunner(verbosity=2,resultclass=Result).run(suite)
    after=inventories()
    passed=(bool(expected) and len(set(expected))==len(expected) and
            len(expected)==result.testsRun and sorted(expected)==sorted(result.ids) and
            result.wasSuccessful() and not result.skipped and not result.expectedFailures and
            not result.unexpectedSuccesses)
    report={'schema':1,'scope':'isolated development P4 transfer wallet, not full native release',
        'parent_commit':dependencies['parent_commit'],
        'source_checks_before':before,'source_checks_after':after,
        'wallet_manifest_sha256':hashlib.sha256((ROOT/'SOURCE_MANIFEST.json').read_bytes()).hexdigest(),
        'tests':result.testsRun,'expected_ids':expected,'successful_ids':result.ids,
        'failures':len(result.failures),'errors':len(result.errors),'skips':len(result.skipped),
        'expected_failures':len(result.expectedFailures),'unexpected_successes':len(result.unexpectedSuccesses),
        'passed':passed,'python':sys.version.split()[0],'dependencies':packages,
        'actual_consensus_executed':False,'real_funds':False,'payment_broadcasts':0}
    if args.report:
        fd=os.open(args.report,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
        with os.fdopen(fd,'w') as f:
            json.dump(report,f,indent=2);f.write('\n');f.flush();os.fsync(f.fileno())
    print(json.dumps({k:v for k,v in report.items() if not k.endswith('_ids')},indent=2))
    return 0 if passed else 1

if __name__=='__main__':raise SystemExit(main())
