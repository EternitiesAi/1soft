"""Required batch startup audit for the successor runtime, not historical runs."""
from protocol8_transfer import PROFILE

def batch_startup(audit):
    calls=audit['calls']
    assert calls and calls[0]['operation']=='startup'
    assert sum(c['operation']=='startup' for c in calls)==1
    row=calls[0]
    assert row['input_bytes']==3592 and 0<row['output_bytes']<=256
    assert row['exit_code']==0 and row['timed_out'] is False and row['process_reaped'] is True
    checks=row['startup_checks']
    assert set(checks)=={'valid_proof_verified','corrupt_proof_refused','parameter_sha256','verifying_key_sha256'}
    assert checks['valid_proof_verified'] is True and checks['corrupt_proof_refused'] is True
    assert all(checks[k]==PROFILE[k] for k in ('parameter_sha256','verifying_key_sha256'))
    return row
