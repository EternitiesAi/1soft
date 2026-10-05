"""Actual client report tamper refusals, optional qualified input gate."""
import copy,os,unittest
from pathlib import Path
from check_protocol7_client import load,validate
@unittest.skipUnless(os.environ.get('P7_CLIENT_REPORT') and os.environ.get('P7_WORKER'),'unassessed: actual P7 caller report not supplied')
class ReportTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):cls.path=Path(os.environ['P7_CLIENT_REPORT']);cls.v=load(cls.path);cls.w=Path(os.environ['P7_WORKER'])
    def refuse(self,v):
        with self.assertRaises(ValueError):validate(v,self.path,self.w)
    def test_check_omission_duplicate_false_and_claim_overstatement_refused(self):
        for i in range(len(self.v['checks'])):
            for mutation in ('omit','duplicate','false'):
                v=copy.deepcopy(self.v)
                if mutation=='omit':v['checks'].pop(i)
                elif mutation=='duplicate':v['checks'].append(copy.deepcopy(v['checks'][i]))
                else:v['checks'][i]['passed']=False
                self.refuse(v)
        for k in ('production_ready','custody','freshness_established','automatic_retry','cross_device_coordination'):
            v=copy.deepcopy(self.v);v['claims'][k]=True;self.refuse(v)
    def test_source_and_actual_artifact_changes_refused(self):
        v=copy.deepcopy(self.v);v['source']['files'].pop('scripts/run_protocol7_client.py');self.refuse(v)
        v=copy.deepcopy(self.v);v['artifacts'][0]['sha256']='ab'*32;self.refuse(v)
    def test_unregistered_extra_field_and_candidate_status_refused(self):
        v=copy.deepcopy(self.v);v['extra']=1;self.refuse(v)
        v=copy.deepcopy(self.v);v['status']='candidate-passed';self.refuse(v)
if __name__=='__main__':unittest.main()
