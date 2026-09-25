#!/usr/bin/env python3
"""Run this add-on's exact test scope locally; no downloads or hosted CI."""
import argparse,hashlib,json,os,sys,unittest
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]

def main():
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--native-root',type=Path)
    a=p.parse_args();sys.path[:0]=[str(ROOT),str(ROOT/'tests')]
    patterns=['test_resident_pass.py']
    native=None
    if a.native_root:
        native=a.native_root.resolve()
        needed=['src/native_core.py','src/compact_verifier.py','src/block_application.py','tests/certificate_fixture.py']
        if not all((native/n).is_file() for n in needed):p.error('complete v0.13 native source required; no download or substitute')
        manifest=json.loads((native/'SOURCE_MANIFEST.json').read_text())
        for entry in manifest['files']:
            data=(native/entry['path']).read_bytes()
            if len(data)!=entry['bytes'] or hashlib.sha256(data).hexdigest()!=entry['sha256']:
                p.error('native source manifest mismatch: '+entry['path'])
        sys.path.extend([str(native/'src'),str(native/'tests')]);patterns+=['test_native_association.py']
    suite=unittest.TestSuite()
    for pattern in patterns:suite.addTests(unittest.defaultTestLoader.discover(str(ROOT/'tests'),pattern=pattern))
    n=suite.countTestCases()
    class Recorded(unittest.TextTestResult):
        def __init__(self,*args,**kwargs):super().__init__(*args,**kwargs);self.passed_ids=[]
        def addSuccess(self,test):super().addSuccess(test);self.passed_ids.append(test.id())
    result=unittest.TextTestRunner(verbosity=2,resultclass=Recorded).run(suite)
    passed=n>0 and result.wasSuccessful() and len(result.passed_ids)==n and not result.skipped
    report={'scope':'Resident Pass add-on; not full native regression suite','passed':passed,'discovered':n,
            'run':result.testsRun,'skipped':len(result.skipped),'failures':len(result.failures),'errors':len(result.errors),
            'passed_ids':result.passed_ids,'native_integration_executed':native is not None,
            'native_root':None if native is None else str(native),'consensus_executed':False,
            'certificates':'synthetic committee and identity-free subjects','github_actions_used':False}
    print(json.dumps(report,indent=2));return 0 if passed else 1
if __name__=='__main__':raise SystemExit(main())
