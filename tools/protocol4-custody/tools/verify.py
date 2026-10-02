#!/usr/bin/env python3
"""Clean current-source custody checks; no engines, hosted compute or real funds."""
import argparse
import hashlib
import importlib.metadata
import json
import os
from pathlib import Path
import subprocess
import sys
import unittest
import warnings

sys.dont_write_bytecode = True
ROOT = Path(__file__).resolve().parents[3]


def git(*args):
    return subprocess.check_output(['git','-C',str(ROOT),*args], timeout=15)


def inventory():
    if git('status','--porcelain'):
        raise ValueError('verification requires clean committed source')
    rows = []
    names = git('ls-files','-z').decode().split('\0')[:-1]
    for name in sorted(names):
        relative = Path(name)
        if relative.is_absolute() or '..' in relative.parts or (ROOT/relative).is_symlink():
            raise ValueError('unsafe source path')
        raw = (ROOT/relative).read_bytes()
        rows.append({'path':relative.as_posix(),'bytes':len(raw),'sha256':hashlib.sha256(raw).hexdigest()})
    if not rows or len(names) != len(set(names)): raise ValueError('invalid source inventory')
    raw = json.dumps(rows,sort_keys=True,separators=(',',':')).encode()
    return {'commit':git('rev-parse','HEAD').decode().strip(),
            'tree':git('rev-parse','HEAD^{tree}').decode().strip(),
            'source_id':hashlib.sha256(raw).hexdigest(),'files':rows}


def ids(suite):
    for test in suite:
        if isinstance(test,unittest.TestSuite): yield from ids(test)
        else: yield test.id()


class Result(unittest.TextTestResult):
    def __init__(self,*args,**kwargs): super().__init__(*args,**kwargs); self.ids=[]
    def addSuccess(self,test): super().addSuccess(test); self.ids.append(test.id())


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--report',type=Path)
    args=parser.parse_args()
    before=inventory()
    sys.path.insert(0,str(ROOT/'tools/protocol4-custody/tests'))
    warnings.simplefilter('error',ResourceWarning)
    suite=unittest.defaultTestLoader.discover(str(ROOT/'tools/protocol4-custody/tests'))
    expected=list(ids(suite))
    result=unittest.TextTestRunner(verbosity=2,resultclass=Result).run(suite)
    after=inventory()
    passed=(before==after and bool(expected) and len(expected)==len(set(expected)) and
            sorted(expected)==sorted(result.ids) and result.wasSuccessful() and not result.skipped
            and not result.expectedFailures and not result.unexpectedSuccesses)
    report={'schema':1,'scope':'local P4 custody component only; synthetic committee fixtures, no engine',
            'passed':passed,'tests':result.testsRun,'expected_ids':expected,'successful_ids':result.ids,
            'failures':len(result.failures),'errors':len(result.errors),'skips':len(result.skipped),
            'expected_failures':len(result.expectedFailures),'unexpected_successes':len(result.unexpectedSuccesses),
            'source_before':before,'source_after':after,'python':sys.version.split()[0],
            'dependencies':{p:importlib.metadata.version(p) for p in ('cryptography','protobuf')},
            'consensus_executed':False,'private_keys_backed_up':False,'active_wallet_restored':False,
            'old_device_fenced':False,'latestness_established':False,'real_funds':False}
    if args.report:
        fd=os.open(args.report,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
        with os.fdopen(fd,'w') as output:
            json.dump(report,output,indent=2); output.write('\n'); output.flush(); os.fsync(output.fileno())
    print(json.dumps({'passed':passed,'tests':result.testsRun,'source_id':before['source_id']}))
    return 0 if passed else 1


if __name__=='__main__': raise SystemExit(main())
