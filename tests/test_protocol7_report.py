"""Actual P7 qualification receipt tamper refusals; optional supplied input gate."""
import copy,json,os,tempfile,unittest
from pathlib import Path
from check_protocol7 import load,validate
@unittest.skipUnless(os.environ.get('P7_REPORT') and os.environ.get('P7_WORKER'),'unassessed: actual P7 qualification receipt/worker not supplied')
class ReportTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):cls.path=Path(os.environ['P7_REPORT']);cls.v=load(cls.path);cls.worker=Path(os.environ['P7_WORKER'])
    def refuse(self,v):
        with self.assertRaises(ValueError):validate(v,self.path,self.worker)
    def test_every_check_omission_duplicate_and_false_result_is_refused(self):
        for i in range(len(self.v['checks'])):
            for mutation in ('omit','duplicate','false'):
                v=copy.deepcopy(self.v)
                if mutation=='omit':v['checks'].pop(i)
                elif mutation=='duplicate':v['checks'].append(copy.deepcopy(v['checks'][i]))
                else:v['checks'][i]['passed']=False
                self.refuse(v)
    def test_overclaims_and_unknown_top_level_fields_are_refused(self):
        for field in ('production_ready','real_funds','public_network','wallet_integrated','freshness_established'):
            v=copy.deepcopy(self.v);v['claims'][field]=True;self.refuse(v)
        v=copy.deepcopy(self.v);v['extra']=0;self.refuse(v)
        v=copy.deepcopy(self.v);v['status']='candidate-passed';self.refuse(v)
    def test_source_missing_dependency_or_changed_digest_is_refused(self):
        for mutation in ('omit','change','dirty'):
            v=copy.deepcopy(self.v);key=next(iter(v['source']['files']))
            if mutation=='omit':v['source']['files'].pop(key)
            elif mutation=='change':v['source']['files'][key]['sha256']='ab'*32
            else:v['source']['clean']=False
            self.refuse(v)
    def test_actual_artifact_roster_and_digest_changes_are_refused(self):
        for mutation in ('omit','duplicate','change'):
            v=copy.deepcopy(self.v)
            if mutation=='omit':v['artifacts'].pop()
            elif mutation=='duplicate':v['artifacts'].append(copy.deepcopy(v['artifacts'][0]))
            else:v['artifacts'][0]['sha256']='ab'*32
            self.refuse(v)
    def test_noncanonical_or_unterminated_actual_report_is_refused(self):
        with tempfile.TemporaryDirectory() as temp:
            path=Path(temp)/'report.json'
            for raw in (json.dumps(self.v).encode(),self.path.read_bytes()[:-1],self.path.read_bytes()+b'\n'):
                path.write_bytes(raw)
                with self.assertRaises(ValueError):load(path)
if __name__=='__main__':unittest.main()
