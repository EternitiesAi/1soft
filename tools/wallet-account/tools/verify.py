#!/usr/bin/env python3
"""Verify declared sources and test the account add-on; no download or hosted CI."""
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
    p.add_argument('--with-catchup',action='store_true',help='Also run two tests requiring the separate catch-up core')
    p.add_argument('--result',type=Path,help='Write a new result file; never overwrite')
    a=p.parse_args(argv);native=a.native_root.resolve()
    if not (native/'src/wallet_obligations.py').is_file():p.error('PR7-or-compatible complete native source is required')
    sys.path.insert(0,str(native/'scripts'))
    from verify_checkout import verify_checkout
    for path in (native,ROOT):
        result=verify_checkout(path)
        if result['status']!='passed':print(json.dumps(result,indent=2));return 2
    paths=[str(ROOT/'src'),str(native/'src'),str(native/'tests')]
    sys.path[:0]=paths;os.environ['PYTHONPATH']=os.pathsep.join(paths)
    patterns=['test_account_view.py']
    if a.with_catchup:
        if not (native/'src/wallet_catchup.py').is_file():p.error('explicit catch-up source absent; no substituted test')
        patterns.append('test_account_catchup.py')
    suite=unittest.TestSuite()
    loader=unittest.TestLoader()
    for pattern in patterns:suite.addTests(loader.discover(str(ROOT/'tests'),pattern=pattern))
    class Recorded(unittest.TextTestResult):
        def __init__(self,*args,**kwargs):super().__init__(*args,**kwargs);self.passed_ids=[]
        def addSuccess(self,test):super().addSuccess(test);self.passed_ids.append(test.id())
    count=suite.countTestCases()
    result=unittest.TextTestRunner(verbosity=2,resultclass=Recorded).run(suite)
    success=count>0 and result.wasSuccessful() and not result.skipped and len(set(result.passed_ids))==count
    report={'scope':'optional account view, not full native suite or validator run','passed':success,
            'cases':count,'successful_ids':result.passed_ids,'skipped':len(result.skipped),
            'failures':len(result.failures),'errors':len(result.errors),'catchup_integration':a.with_catchup,
            'native_manifest_sha256':verify_checkout(native)['manifest_sha256'],
            'addon_manifest_sha256':verify_checkout(ROOT)['manifest_sha256'],
            'new_consensus_execution':False}
    text=json.dumps(report,indent=2)+'\n';print(text)
    if a.result:
        with a.result.open('x') as out:out.write(text)
    return 0 if success else 1

if __name__=='__main__':raise SystemExit(main())
