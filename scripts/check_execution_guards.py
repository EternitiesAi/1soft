#!/usr/bin/env python3
"""Deliberately weaken five controls and require targeted assertion failures.

Runs on disposable source copies, never changes the actual checkout. Detection
is not an independent security audit or proof of resistance to arbitrary faults.
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
 ('committed_source_not_pending','block_application.py',
  "return self._execution.fork(digest(self.genesis), self.height, self.app_hash)",
  "active = self._pending_execution or self._execution\n            return active.fork(active.checkpoint.genesis_hash, active.checkpoint.height, active.checkpoint.app_hash)",
  'ExecutionApplicationTests.test_pending_image_never_used_for_checktx'),
 ('startup_history_validation','block_application.py',
  'checked = restore(genesis, state)', 'checked = NativeLedger(\':memory:\', genesis)',
  'ExecutionApplicationTests.test_corrupt_receipt_cannot_be_smuggled_through_recomputed_disk_root'),
 ('source_authorizer','execution_snapshot.py',
  'item._db.set_authorizer(item._read_only)', '# deliberately removed source authorizer',
  'ImageTests.test_cached_source_denies_writes'),
 ('promotion_after_commit','block_application.py',
  'self._execution, self._pending_execution = self._pending_execution, None',
  'self._execution, self._pending_execution = self._execution, None',
  'ExecutionApplicationTests.test_commit_promotes_once_and_closes_old_image'),
 ('checkpoint_binding','execution_snapshot.py',
  "_need(self._point == _checkpoint(genesis_hash, height, app_hash),",
  '_need(True,',
  'ImageTests.test_old_checkpoint_is_not_accepted_as_new'),
]

def main():
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--output',type=Path,required=True)
    a=p.parse_args();a.output.mkdir(parents=True,exist_ok=False)
    records=[]
    for label,filename,old,new,test in CASES:
        with tempfile.TemporaryDirectory(prefix='1soft-execution-guard-') as temp:
            src=Path(temp)/'src';shutil.copytree(ROOT/'src',src,ignore=shutil.ignore_patterns('__pycache__'))
            path=src/filename;content=path.read_text()
            if content.count(old)!=1:raise ValueError('ambiguous mutation '+label)
            path.write_text(content.replace(old,new))
            env=dict(os.environ,PYTHONPATH=str(src)+os.pathsep+str(ROOT/'tests'))
            r=subprocess.run([sys.executable,'-m','unittest','test_execution_snapshot.'+test,'-v'],
                             cwd=temp,env=env,capture_output=True,text=True,timeout=20)
            log=r.stdout+r.stderr;(a.output/(label+'.log')).write_text(log)
            detected=r.returncode!=0 and 'FAIL:' in log and 'AssertionError' in log and 'ERROR:' not in log
            records.append({'guard':label,'test':test,'returncode':r.returncode,
                            'caught_by_assertion':detected})
    report={'scope':'five selected developer-injected faults; not independent audit',
            'cases':records,'all_caught':all(r['caught_by_assertion'] for r in records)}
    (a.output/'result.json').write_text(json.dumps(report,indent=2)+'\n');print(json.dumps(report,indent=2))
    return 0 if report['all_caught'] else 1
if __name__=='__main__':raise SystemExit(main())
