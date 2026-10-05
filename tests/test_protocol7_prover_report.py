"""Adversarial source-bound actual prover receipt checks; no fixture qualification."""
import copy,os,unittest
from pathlib import Path
from check_protocol7_prover import load,validate
@unittest.skipUnless(os.environ.get('P7_PROVER_REPORT') and os.environ.get('P7_WORKER'),
                    'unassessed: clean actual prepared-prover receipt not supplied')
class ReportTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.path=Path(os.environ['P7_PROVER_REPORT']);cls.value=load(cls.path);cls.worker=Path(os.environ['P7_WORKER'])
    def refuse(self,v):
        with self.assertRaises((ValueError,RuntimeError)):validate(v,self.path,self.worker)
    def test_actual_receipt_checks_independently(self):
        self.assertTrue(validate(self.value,self.path,self.worker)['qualified'])
    def test_omitted_duplicate_failed_checks_and_extra_claims_refused(self):
        for i in range(len(self.value['checks'])):
            for mutation in ('omit','duplicate','false'):
                v=copy.deepcopy(self.value)
                if mutation=='omit':v['checks'].pop(i)
                elif mutation=='duplicate':v['checks'].append(copy.deepcopy(v['checks'][i]))
                else:v['checks'][i]['passed']=False
                self.refuse(v)
        for k in ('production_ready','encrypted_custody','cross_device_coordination','automatic_retry'):
            v=copy.deepcopy(self.value);v['claims'][k]=True;self.refuse(v)
    def test_identity_process_and_public_request_bindings_refused(self):
        for field in ('binary_sha256','start_ticks','exit_code'):
            v=copy.deepcopy(self.value)
            v['prover_run'][field]='00'*32 if field=='binary_sha256' else -1
            self.refuse(v)
        for field in ('profile_sha256','parameter_sha256','verifying_key_sha256','bootstrap_sha256','public_prefix_sha256'):
            v=copy.deepcopy(self.value);v['request_binding'][field]='00'*32;self.refuse(v)
        v=copy.deepcopy(self.value);v['processes']=[p for p in v['processes'] if p['role']!='arbitrary-prover'];self.refuse(v)
    def test_wire_quorum_source_artifact_and_candidate_tamper_refused(self):
        v=copy.deepcopy(self.value);v['status']='candidate-passed';self.refuse(v)
        v=copy.deepcopy(self.value);v['source']['files'].pop('src/protocol7_prover.py');self.refuse(v)
        v=copy.deepcopy(self.value);v['artifacts'][0]['sha256']='00'*32;self.refuse(v)
        v=copy.deepcopy(self.value);v['prepared_wire']=v['prepared_wire'][:-2]+'ff';self.refuse(v)
        v=copy.deepcopy(self.value);v['record']['signed_header']['header']['app_hash']='ab'*32;self.refuse(v)
        v=copy.deepcopy(self.value);v['transport']['calls'].append(v['transport']['calls'][0]);self.refuse(v)
if __name__=='__main__':unittest.main()
