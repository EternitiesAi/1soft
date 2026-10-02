#!/usr/bin/env python3
"""Bounded, temporary-source mutation checks. Not a security audit or fuzz campaign."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile

ROOT=Path(__file__).resolve().parents[1]
CASES=[
 ('controlling-key', "require(signer_pk == authority['public_key'], 'signer is not the certified controlling key')",
  "require(True, 'signer is not the certified controlling key')", 'test_owner_wrong_key_is_rejected_before_unlock'),
 ('snapshot-age', "require(now - header_ns <= self.policy['maximum_age_seconds'] * 1_000_000_000,",
  'require(True,', 'test_stale_snapshot'),
 ('rollback-floor', "require(cert['height'] >= row[0], 'certificate rolls back the local checkpoint')",
  "require(True, 'certificate rolls back the local checkpoint')", 'test_older_certificate_after_newer_review'),
 ('unlock-age', 'now_after = self._time_check(header_ns)',
  'now_after = now', 'test_time_rechecked_after_slow_unlock'),
 ('nonce-reservation', 'slot_key = _hash(encode([self.policy_id, slot]))',
  'slot_key = _hash(encode([self.policy_id, slot, decision_id]))', 'test_one_authority_nonce_cannot_sign_twice'),
]


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output',type=Path,required=True)
    args=parser.parse_args()
    args.output.mkdir(parents=True,exist_ok=False)
    checks=[]
    original=(ROOT/'src/certified_wallet.py').read_text()
    for name,before,after,test in CASES:
        if original.count(before)!=1:
            raise ValueError('mutation location is not unique: '+name)
        with tempfile.TemporaryDirectory(prefix='1soft-regression-') as temporary:
            root=Path(temporary)
            for directory in ('src','tests','scripts'):
                shutil.copytree(ROOT/directory,root/directory,ignore=shutil.ignore_patterns('__pycache__'))
            changed=original.replace(before,after)
            (root/'src/certified_wallet.py').write_text(changed)
            env={**os.environ,'PYTHONPATH':os.pathsep.join([str(root/'src'),str(root/'tests')])}
            command=[sys.executable,'-m','unittest','test_certified_wallet.CertifiedWalletTests.'+test,'-v']
            result=subprocess.run(command,cwd=root,env=env,capture_output=True,text=True,timeout=25)
            (args.output/(name+'.log')).write_text(result.stdout+result.stderr)
            # Require a real assertion failure, not an import crash or malformed test.
            caught=result.returncode!=0 and 'FAIL: '+test in result.stderr and 'Ran 1 test' in result.stderr
            checks.append({'name':name,'test':test,'detected':caught,'returncode':result.returncode,
                           'mutated_source_sha256':hashlib.sha256(changed.encode()).hexdigest()})
    report={'scope':'five targeted, locally introduced regressions; not independent audit',
            'source_sha256':hashlib.sha256(original.encode()).hexdigest(),
            'status':'passed' if all(c['detected'] for c in checks) else 'failed','checks':checks}
    (args.output/'result.json').write_text(json.dumps(report,indent=2)+'\n')
    print(json.dumps(report,indent=2))
    return 0 if report['status']=='passed' else 1

if __name__=='__main__':raise SystemExit(main())
