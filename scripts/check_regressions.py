#!/usr/bin/env python3
"""Run deliberate defects in disposable copies to verify three regression tests fail."""
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
ROOT=Path(__file__).resolve().parents[1]
original=(ROOT/'src/block_application.py').read_text()
mutants=[]
mutants.append(('omit_replay_state_from_root',original.replace("'native': state}","'native': {k:v for k,v in state.items() if k != 'receipts'}}"),
                'test_receipt_set_is_in_application_hash'))
mutants.append(('expose_uncommitted_state',original.replace("                self.pending = {'identity': identity, 'state': state, 'result': result}",
    "                self.height, self.app_hash, self.native = height, app_hash, state\n                self.pending = {'identity': identity, 'state': state, 'result': result}"),
    'test_finalize_not_visible_before_commit'))
head,tail=original.split('    def commit(self,',1)
tail=tail.replace("            self.db.execute('BEGIN IMMEDIATE')","            pass # deliberate loss of atomicity",1)
tail=tail.replace("                self.db.execute('COMMIT')","                pass # deliberate loss of atomicity",1)
mutants.append(('remove_block_commit_transaction',head+'    def commit(self,'+tail,'test_rollback_before_commit'))
report={'scope':'three deliberate faults in disposable source copies, not comprehensive mutation testing','mutants':[]}
for name,text,test in mutants:
    assert text!=original,name
    with tempfile.TemporaryDirectory(prefix='etn-regression-') as d:
        src=Path(d)/'src';shutil.copytree(ROOT/'src',src,ignore=shutil.ignore_patterns('__pycache__'))
        (src/'block_application.py').write_text(text)
        env=dict(os.environ,PYTHONPATH=str(src))
        run=subprocess.run([sys.executable,'-m','unittest','-v',f'test_block_application.BlockTests.{test}'],
             cwd=ROOT/'tests',env=env,capture_output=True,text=True,timeout=20)
        killed=run.returncode!=0 and f'FAIL: {test}' in run.stderr and 'ERROR:' not in run.stderr
        report['mutants'].append({'name':name,'detected_by_test':test,'detected':killed,
                                  'exit_code':run.returncode,'output':run.stdout+run.stderr})
report['source_unchanged']=(ROOT/'src/block_application.py').read_text()==original
report['status']='passed' if report['source_unchanged'] and all(m['detected'] for m in report['mutants']) else 'failed'
(ROOT/'evidence/v05/regression-sensitivity.json').write_text(json.dumps(report,indent=2)+'\n')
print(json.dumps({'status':report['status'],'detected':sum(m['detected'] for m in report['mutants'])}))
raise SystemExit(0 if report['status']=='passed' else 1)
