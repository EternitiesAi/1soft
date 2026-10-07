import copy,sys,unittest
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1];sys.path[:0]=[str(ROOT/'src'),str(ROOT/'tools/release')]
from check_protocol8_native import batch_startup
from protocol8_transfer import PROFILE

class BatchAudit(unittest.TestCase):
    def audit(self):
        return {'calls':[{'operation':'startup','input_bytes':3592,'output_bytes':237,
          'exit_code':0,'timed_out':False,'process_reaped':True,'startup_checks':{
          'valid_proof_verified':True,'corrupt_proof_refused':True,
          **{k:PROFILE[k] for k in ('parameter_sha256','verifying_key_sha256')}}}]}
    def test_one_first_batch(self):batch_startup(self.audit())
    def test_legacy_missing_duplicate_and_reordered_refused(self):
        a=self.audit()
        for calls in ([],[{'operation':'verify'},{'operation':'verify'},{'operation':'identities'}],
                      a['calls']*2,[{'operation':'verify'},*a['calls']]):
            with self.subTest(calls=calls),self.assertRaises(AssertionError):batch_startup({'calls':calls})
    def test_strict_flags_profile_and_closed_schema(self):
        for k,v in (('valid_proof_verified',1),('corrupt_proof_refused',1),
                    ('parameter_sha256','00'*32),('extra',True)):
            a=self.audit();a['calls'][0]['startup_checks'][k]=v
            with self.subTest(k=k),self.assertRaises(AssertionError):batch_startup(a)
    def test_bound_lifecycle_and_refusal(self):
        for k,v in (('input_bytes',3591),('output_bytes',257),('exit_code',2),('timed_out',True),('process_reaped',False)):
            a=self.audit();a['calls'][0][k]=v
            with self.subTest(k=k),self.assertRaises(AssertionError):batch_startup(a)
if __name__=='__main__':unittest.main()
