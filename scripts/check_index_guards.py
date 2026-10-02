#!/usr/bin/env python3
"""Intentionally weaken guards in disposable copies; require assertion failures.

Never edits the working source or treats an import error as detection. This is a
bounded regression exercise, not adversarial review or an independent audit.
"""
import argparse
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
ROOT=Path(__file__).resolve().parents[1]
CASES=[
 ('expected-final-root','state_index.py',
  "need(actual == expected, 'incremental root differs from finalized application hash')",
  "need(True, 'incremental root differs from finalized application hash')",
  'test_state_index.IndexTests.test_bad_expected_root_rolls_back_savepoint_without_committing_caller'),
 ('old-value-binding','state_index.py',
  "need((None if actual is None else row_bytes(table,key,actual)) == old,",
  "need(True,",
  'test_state_index.IndexTests.test_previous_value_must_match_index'),
 ('startup-audit','block_application.py',
  "index.audit(digest(self.genesis), self.height, self.app_hash)",
  "pass  # intentionally weakened startup audit in disposable test copy",
  'test_indexed_application.IndexedApplicationTests.test_corrupt_index_refused_not_auto_rebuilt_on_open'),
 ('atomic-index-update','block_application.py',
  "self.proof_index.advance(digest(self.genesis), self.height, self.app_hash,\n                                             height, self.native, p['state'], result['app_hash'])",
  "pass  # deliberately omit derived-index update in disposable copy",
  'test_indexed_application.IndexedApplicationTests.test_application_and_index_checkpoint_commit_together'),
]


def main():
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--output',type=Path,required=True)
    args=p.parse_args();args.output.mkdir(parents=True,exist_ok=False);results=[]
    for name,file,old,new,test in CASES:
        with tempfile.TemporaryDirectory() as d:
            source=Path(d)/'src';shutil.copytree(ROOT/'src',source,ignore=shutil.ignore_patterns('__pycache__'))
            path=source/file;text=path.read_text()
            if text.count(old)!=1:raise ValueError('guard target is not unique: '+name)
            path.write_text(text.replace(old,new))
            code='''import json,unittest,sys
suite=unittest.defaultTestLoader.loadTestsFromName(sys.argv[1])
r=unittest.TextTestRunner(verbosity=2).run(suite)
print(json.dumps({'run':r.testsRun,'failures':len(r.failures),'errors':len(r.errors),'skipped':len(r.skipped)}))
'''
            run=subprocess.run([sys.executable,'-c',code,test],cwd=d,
                env=dict(os.environ,PYTHONPATH=str(source)+os.pathsep+str(ROOT/'tests')),
                capture_output=True,text=True,timeout=15)
            (args.output/(name+'.log')).write_text(run.stderr+'\n'+run.stdout)
            result=json.loads(run.stdout)
            caught=run.returncode==0 and result['run']==1 and result['failures']==1 and result['errors']==0 and result['skipped']==0
            results.append({'name':name,'test':test,'detected_by_assertion':caught,**result})
    report={'status':'passed' if all(x['detected_by_assertion'] for x in results) else 'failed','variants':results}
    (args.output/'result.json').write_text(json.dumps(report,indent=2)+'\n');print(json.dumps(report,indent=2))
    return 0 if report['status']=='passed' else 1
if __name__=='__main__':raise SystemExit(main())
