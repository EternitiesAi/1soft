#!/usr/bin/env python3
"""Seven deliberate lifecycle faults in disposable copies, not an audit."""
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
ROOT=Path(__file__).resolve().parents[1]
original={name:(ROOT/'src'/name).read_text() for name in ('native_core.py','commit_verifier.py')}
native=original['native_core.py'];verifier=original['commit_verifier.py']
mutants=[
    ('omit_incoming_key_consent','native_core.py',native.replace(
        '                verify_account_key_acceptance(body)', '                pass  # injected missing incoming consent'),
        'test_account_lifecycle.AccountLifecycleTests.test_open_wrong_recipient_signature'),
    ('retain_native_grants_after_rotation','native_core.py',native.replace(
        'UPDATE accounts SET public_key=?,epoch=epoch+1 WHERE id=?',
        'UPDATE accounts SET public_key=? WHERE id=?'),
        'test_account_lifecycle.AccountLifecycleTests.test_rotate_keeps_stable_account_and_fences_grants'),
    ('reset_nonce_during_rotation','native_core.py',native.replace(
        'UPDATE accounts SET public_key=?,epoch=epoch+1 WHERE id=?',
        'UPDATE accounts SET public_key=?,epoch=epoch+1,nonce=0 WHERE id=?'),
        'test_account_lifecycle.AccountLifecycleTests.test_rotate_does_not_reset_nonce'),
    ('use_global_grant_names','native_core.py',native.replace(
        'return label if self.protocol_version == 1 else owner + "::" + label', 'return label'),
        'test_account_lifecycle.AccountLifecycleTests.test_two_owners_can_use_same_grant_label'),
    ('ignore_genesis_transaction_version','native_core.py',native.replace(
        'body["version"] == self.protocol_version', 'body["version"] in (1, 2)'),
        'test_account_lifecycle.ProtocolVersionTests.test_v2_rejects_v1_transaction_version'),
    ('allow_duplicate_active_root_key','native_core.py',native.replace(
        'require(self.db.execute("SELECT 1 FROM accounts WHERE public_key=?", (new_key,)).fetchone() is None,',
        'require(True,'),
        'test_account_lifecycle.AccountLifecycleTests.test_open_cannot_duplicate_active_rotated_key'),
    ('verifier_ignores_incoming_signature','commit_verifier.py',verifier.replace(
        "        Ed25519PublicKey.from_public_bytes(hexbytes(op['public_key'], 32)).verify(\n"
        "            hexbytes(op['acceptance'], 64), b'ETERNITIES/ACCOUNT-KEY-CONSENT/v2\\x00' + encode(payload))",
        '        pass  # injected missing second signature check'),
        'test_lifecycle_signatures.LifecycleSignatureTests.test_independent_verifier_bad_incoming_signature_after_owner_resigns'),
]
report={'scope':'seven targeted code faults; does not establish comprehensive security','mutants':[]}
for name,file,text,test in mutants:
    assert text!=original[file],name+' did not modify code'
    with tempfile.TemporaryDirectory(prefix='etn-v05-fault-') as d:
        src=Path(d)/'src';shutil.copytree(ROOT/'src',src,ignore=shutil.ignore_patterns('__pycache__'))
        (src/file).write_text(text)
        env=dict(os.environ,PYTHONPATH=str(src))
        result=subprocess.run([sys.executable,'-m','unittest','-v',test],cwd=ROOT/'tests',
                              env=env,capture_output=True,text=True,timeout=20)
        detected=result.returncode!=0 and 'FAIL:' in result.stderr and 'ERROR:' not in result.stderr
        report['mutants'].append({'name':name,'detected':detected,'test':test,
            'exit_code':result.returncode,'output':result.stdout+result.stderr})
report['source_unchanged']=all(text==(ROOT/'src'/name).read_text() for name,text in original.items())
report['status']='passed' if report['source_unchanged'] and all(m['detected'] for m in report['mutants']) else 'failed'
out=ROOT/'evidence/v05/v05-regression-sensitivity.json';out.parent.mkdir(parents=True,exist_ok=True)
out.write_text(json.dumps(report,indent=2)+'\n')
print(json.dumps({'status':report['status'],'detected':sum(m['detected'] for m in report['mutants'])}))
raise SystemExit(0 if report['status']=='passed' else 1)
