#!/usr/bin/env python3
"""Hash-checked delivery add-on tests, with explicit core/account dependencies."""
import argparse
import json
import os
from pathlib import Path
import sys
import unittest

ROOT=Path(__file__).resolve().parents[1]


def main(argv=None):
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--native-root',type=Path,required=True)
    p.add_argument('--result',type=Path)
    p.add_argument('--parts',type=int,default=1)
    p.add_argument('--part',type=int,default=0)
    a=p.parse_args(argv)
    if not 1<=a.parts<=16 or not 0<=a.part<a.parts:p.error('invalid test partition')
    native=a.native_root.resolve();account=native/'tools/wallet-account'
    sys.path.insert(0,str(native/'scripts'))
    from verify_checkout import verify_checkout
    inventories={}
    for label,root in [('native',native),('account',account),('delivery',ROOT)]:
        r=verify_checkout(root)
        if r['status']!='passed':print(json.dumps(r,indent=2));return 2
        inventories[label]={'matched':r['matched'],'manifest_sha256':r['manifest_sha256']}
    paths=[str(ROOT/'src'),str(ROOT/'tests'),str(account/'src'),str(native/'src'),str(native/'tests')]
    sys.path[:0]=paths;os.environ['PYTHONPATH']=os.pathsep.join(paths)
    suite=unittest.TestLoader().discover(str(ROOT/'tests'),pattern='test_*.py')
    def flatten(s):
        for t in s:
            if isinstance(t,unittest.TestSuite):yield from flatten(t)
            else:yield t
    cases=list(flatten(suite)); total=len(cases)
    selected=cases[total*a.part//a.parts:total*(a.part+1)//a.parts]
    suite=unittest.TestSuite(selected)
    requested=[t.id() for t in selected]
    class Recorded(unittest.TextTestResult):
        def __init__(self,*arg,**kw):super().__init__(*arg,**kw);self.ids=[]
        def addSuccess(self,t):super().addSuccess(t);self.ids.append(t.id())
    result=unittest.TextTestRunner(verbosity=2,resultclass=Recorded).run(suite)
    passed=bool(requested) and len(requested)==len(set(requested)) and result.wasSuccessful() and not result.skipped and sorted(result.ids)==sorted(requested)
    report={'scope':'decision-delivery add-on, local HTTP/application; not actual validators',
            'passed':passed,'part':a.part,'parts':a.parts,'total_discovered':total,
            'requested_ids':requested,'cases':len(requested),'successful_ids':result.ids,'skips':len(result.skipped),
            'failures':len(result.failures),'errors':len(result.errors),'source_inventories':inventories,
            'new_actual_consensus_execution':False}
    text=json.dumps(report,indent=2)+'\n';print(text)
    if a.result:
        with a.result.open('x') as f:f.write(text)
    return 0 if passed else 1


if __name__=='__main__':raise SystemExit(main())
