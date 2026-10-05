import copy,os,unittest,sys
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'tools/release'))
try:
    import check_protocol6 as gate
except ModuleNotFoundError:gate=None
@unittest.skipUnless(os.environ.get('P6_REPORT'),'unassessed: real-engine source-bound report was not supplied')
class ReportTests(unittest.TestCase):
    def setUp(self):
        self.assertIsNotNone(gate,'P6 source/log/certificate report checker is missing')
        self.path=Path(os.environ['P6_REPORT']);self.value=gate.load(self.path)
    def rejected(self,value):
        with self.assertRaises(ValueError):gate.validate(value,self.path)
    def test_actual_qualified_report_passes(self):self.assertTrue(gate.validate(self.value,self.path)['qualified'])
    def test_missing_duplicate_false_or_boolean_check_rejected(self):
        for change in ('missing','duplicate','false','integer'):
            v=copy.deepcopy(self.value)
            if change=='missing':v['checks'].pop()
            elif change=='duplicate':v['checks'][0]=copy.deepcopy(v['checks'][1])
            elif change=='false':v['checks'][0]['passed']=False
            else:v['checks'][0]['passed']=1
            self.rejected(v)
    def test_candidate_dirty_source_and_production_claim_rejected(self):
        for group,key,value in [('top','status','candidate-passed'),('source','clean',False),('claims','production_ready',True)]:
            v=copy.deepcopy(self.value)
            if group=='top':v[key]=value
            else:v[group][key]=value
            self.rejected(v)
    def test_missing_or_tampered_source_binding_rejected(self):
        for missing in (True,False):
            v=copy.deepcopy(self.value);key=next(iter(v['source']['files']))
            if missing:del v['source']['files'][key]
            else:v['source']['files'][key]['sha256']='00'*32
            self.rejected(v)
    def test_raw_log_receipt_and_worker_binary_binding_rejected(self):
        for what in ('log','worker'):
            v=copy.deepcopy(self.value)
            if what=='log':v['artifacts'][0]['sha256']='00'*32
            else:v['inputs']['worker']['sha256']='00'*32
            self.rejected(v)
    def test_signed_header_or_exact_payment_receipt_rejected(self):
        for what in ('header','receipt'):
            v=copy.deepcopy(self.value)
            if what=='header':v['signed_header']['commit']['signatures'][0]['signature']='AA=='
            else:v['state_witness']['state']['receipts'][0]['raw']='00'
            self.rejected(v)
if __name__=='__main__':unittest.main()
