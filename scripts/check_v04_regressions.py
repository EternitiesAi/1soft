#!/usr/bin/env python3
"""Seven targeted faults in disposable source copies; NOT comprehensive mutation testing."""
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
ROOT=Path(__file__).resolve().parents[1]
verifier=(ROOT/'src/commit_verifier.py').read_text()
block=(ROOT/'src/block_application.py').read_text()
mutants=[
 ('accept_exact_two_thirds','commit_verifier.py',verifier.replace('signed*3>trust.total_power*2','signed*3>=trust.total_power*2'),
  'test_commit_verifier.CommitVerifierTests.test_exactly_two_thirds_rejected'),
 ('ignore_bad_tail_after_quorum','commit_verifier.py',verifier.replace('    for val, sig in zip(trust.validators,sigs):',
  '    for val, sig in zip(trust.validators,sigs):\n        if signed*3>trust.total_power*2: break'),
  'test_commit_verifier.CommitVerifierTests.test_invalid_tail_signature_after_quorum_rejected'),
 ('count_nil_votes_as_commit','commit_verifier.py',verifier.replace('        if flag == 2:', '        if flag in (2,3):'),
  'test_commit_verifier.CommitVerifierTests.test_signed_nil_vote_not_counted'),
 ('omit_header_hash_binding','commit_verifier.py',verifier.replace("ensure(bid.hash==computed,'header/commit hash mismatch')", "ensure(True,'header/commit hash mismatch')"),
  'test_commit_verifier.CommitVerifierTests.test_header_hash_tamper_rejected'),
 ('omit_state_height_lag','commit_verifier.py',verifier.replace('expected_height=height+1','expected_height=None'),
  'test_commit_verifier.CommitVerifierTests.test_same_height_even_with_matching_hash_and_new_signatures_rejected'),
 ('omit_requested_payment_binding','commit_verifier.py',verifier.replace("ensure(set(requested)==seen,'certificate does not match the requested transactions')", "ensure(True,'certificate does not match the requested transactions')"),
  'test_commit_verifier.CommitVerifierTests.test_expected_transaction_intent_bound'),
 ('ignore_protobuf_framing','block_application.py',block.replace('return sum(1 + max(1, (len(tx).bit_length() + 6) // 7) + len(tx) for tx in txs)',
  'return sum(len(tx) for tx in txs)'),
  'test_block_size.BlockSizeTests.test_framing_can_push_block_past_limit'),
]
report={'scope':'seven targeted defects in disposable source copies; not a security audit','mutants':[]}
for name,file,text,test in mutants:
    assert text != (ROOT/'src'/file).read_text(),name
    with tempfile.TemporaryDirectory(prefix='etn-v04-regression-') as d:
        src=Path(d)/'src';shutil.copytree(ROOT/'src',src,ignore=shutil.ignore_patterns('__pycache__'))
        (src/file).write_text(text)
        env=dict(os.environ,PYTHONPATH=str(src))
        result=subprocess.run([sys.executable,'-m','unittest','-v',test],cwd=ROOT/'tests',env=env,
                              capture_output=True,text=True,timeout=20)
        killed=result.returncode!=0 and 'FAIL:' in result.stderr and 'ERROR:' not in result.stderr
        report['mutants'].append({'name':name,'detected':killed,'test':test,'exit_code':result.returncode,
                                  'output':result.stdout+result.stderr})
report['source_unchanged']=verifier==(ROOT/'src/commit_verifier.py').read_text() and block==(ROOT/'src/block_application.py').read_text()
report['status']='passed' if report['source_unchanged'] and all(m['detected'] for m in report['mutants']) else 'failed'
out=ROOT/'evidence/v05/v04-regression-sensitivity.json'
out.parent.mkdir(parents=True,exist_ok=True);out.write_text(json.dumps(report,indent=2)+'\n')
print(json.dumps({'status':report['status'],'detected':sum(m['detected'] for m in report['mutants'])}))
raise SystemExit(0 if report['status']=='passed' else 1)
