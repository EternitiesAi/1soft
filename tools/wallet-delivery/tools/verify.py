#!/usr/bin/env python3
"""Check source and execute an explicit delivery-test subset; no downloads/Actions."""
import argparse
import json
import os
from pathlib import Path
import sys
import unittest

ROOT = Path(__file__).resolve().parents[1]


def main(argv=None):
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--native-root', type=Path, required=True)
    p.add_argument('--parts', type=int, default=1)
    p.add_argument('--part', type=int, default=0)
    p.add_argument('--result', type=Path)
    a=p.parse_args(argv); native=a.native_root.resolve()
    if not 1 <= a.parts <= 16 or not 0 <= a.part < a.parts: p.error('invalid part/parts')
    account=native/'tools/wallet-account'
    if not (account/'src/account_view.py').is_file(): p.error('published PR10 account and native source required')
    sys.path.insert(0,str(native/'scripts'))
    from verify_checkout import verify_checkout
    hashes={}
    for name,path in [('native',native),('account',account),('delivery',ROOT)]:
        result=verify_checkout(path)
        if result['status']!='passed': print(json.dumps(result,indent=2)); return 2
        hashes[name]=result['manifest_sha256']
    paths=[str(ROOT/'src'),str(ROOT/'tests'),str(account/'src'),str(native/'src'),str(native/'tests')]
    sys.path[:0]=paths;os.environ['PYTHONPATH']=os.pathsep.join(paths)
    def flatten(suite):
        for item in suite:
            if isinstance(item,unittest.TestSuite): yield from flatten(item)
            else: yield item
    cases=list(flatten(unittest.TestLoader().discover(str(ROOT/'tests'),pattern='test_*.py')))
    chosen=cases[len(cases)*a.part//a.parts:len(cases)*(a.part+1)//a.parts]
    if not chosen: p.error('empty test selection is not a passing gate')
    requested=[t.id() for t in chosen]
    class Recorded(unittest.TextTestResult):
        def __init__(self,*args,**kw): super().__init__(*args,**kw);self.passed_ids=[]
        def addSuccess(self,test): super().addSuccess(test);self.passed_ids.append(test.id())
    outcome=unittest.TextTestRunner(verbosity=2,resultclass=Recorded).run(unittest.TestSuite(chosen))
    passed=outcome.wasSuccessful() and not outcome.skipped and outcome.testsRun==len(requested) and sorted(requested)==sorted(outcome.passed_ids)
    report={'scope':'delivery adapter only; real local HTTP, synthetic committees',
            'passed':passed,'parts':a.parts,'part':a.part,'total_discovered':len(cases),
            'requested_ids':requested,'successful_ids':outcome.passed_ids,'skips':len(outcome.skipped),
            'failures':len(outcome.failures),'errors':len(outcome.errors),
            'manifests':hashes,'new_validator_execution':False}
    if a.result:
        with a.result.open('x') as f:f.write(json.dumps(report,indent=2)+'\n')
    print(json.dumps(report,indent=2)); return 0 if passed else 1


if __name__=='__main__':raise SystemExit(main())
