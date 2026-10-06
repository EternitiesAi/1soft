"""Receipt-envelope tamper refusals; no native execution or proof claim."""
import copy,sys,unittest
from pathlib import Path
root=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(root/'src'));sys.path.insert(0,str(root/'scripts'));sys.path.insert(0,str(root/'tools/release'))
from run_protocol8_engine import CHECKS,CLAIMS
from check_protocol8_engine import envelope
class ReportTests(unittest.TestCase):
    def setUp(self):
        self.v={'format':'1soft/protocol8-recipient-engine/v1','status':'qualified-one-host-recipient-consensus',
            'source':{},'claims':CLAIMS.copy(),'checks':[{'id':n,'passed':True,'evidence':{}} for n in CHECKS],
            'inputs':{},'native_processes':[],'worker_audits':[],'genesis':{},'genesis_sha256':'',
            'bootstrap_sha256':'','state_witness':{},'signed_header':{},'certificate':{},'artifacts':[],'processes':[]}
    def test_exact_envelope(self):self.assertEqual(set(envelope(self.v)),set(CHECKS))
    def test_check_missing_duplicate_failure_and_integer_refused(self):
        for kind in ('missing','duplicate','failed','integer'):
            v=copy.deepcopy(self.v)
            if kind=='missing':v['checks'].pop()
            elif kind=='duplicate':v['checks'][1]=v['checks'][0]
            elif kind=='failed':v['checks'][0]['passed']=False
            else:v['checks'][0]['passed']=1
            with self.subTest(kind=kind),self.assertRaises(ValueError):envelope(v)
    def test_scope_and_extra_claims_refused(self):
        for kind in ('production_ready','state_sync_qualified','custody_qualified','p7_migration','freshness_established','extra'):
            v=copy.deepcopy(self.v);v['claims'][kind]=True
            with self.subTest(kind=kind),self.assertRaises(ValueError):envelope(v)
    def test_failed_candidate_and_extra_fields_refused(self):
        for kind in ('failed','candidate','extra'):
            v=copy.deepcopy(self.v)
            if kind=='extra':v['error']='x'
            else:v['status']=kind
            with self.subTest(kind=kind),self.assertRaises(ValueError):envelope(v)
if __name__=='__main__':unittest.main()
