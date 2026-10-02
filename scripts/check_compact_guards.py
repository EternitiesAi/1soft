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
 ('merkle-root','state_tree.py',"need(cur == root, 'Merkle proof does not reach the committed root')",
  "need(True, 'Merkle proof does not reach the committed root')",
  'test_state_tree.StateTreeTests.test_altered_row_refused'),
 ('state-height','state_tree.py',"height.to_bytes(8, 'big')", "(0).to_bytes(8, 'big')",
  'test_state_tree.StateTreeTests.test_root_binding_commits_genesis_and_height'),
 ('signed-root','compact_verifier.py',"ensure(cert['app_hash'] == app_hash, 'root not anchored by the next signed header')",
  "ensure(True, 'root not anchored by the next signed header')",
  'test_compact_state.CompactStateTests.test_legacy_full_snapshot_claim_not_accepted_for_smt_chain'),
 ('shared-allowance','compact_verifier.py',"ensure(item['spent'] + required <= item['cap'], 'authenticated agent or shared budget exceeded')",
  "ensure(True, 'authenticated agent or shared budget exceeded')",
  'test_compact_state.CompactStateTests.test_compact_preflight_rejects_aggregate_overspend'),
 ('atomic-capacity','native_core.py',"require(total_rows <= MAX_ROWS, \"compact-state record capacity reached\")",
  "require(True, \"compact-state record capacity reached\")",
  'test_compact_state.CompactStateTests.test_native_capacity_rejects_before_durable_transaction_commit'),
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
