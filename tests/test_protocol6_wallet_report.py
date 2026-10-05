"""Actual report gate tests: forged evidence and unfinished runs cannot qualify."""
import copy,os,sys,unittest
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'tools/release'))
try:import check_protocol6_wallet as gate
except ModuleNotFoundError:gate=None
from test_protocol6_treasury import worker
@unittest.skipUnless(os.environ.get('P6_WALLET_REPORT') and os.environ.get('P6_WORKER'),'unassessed: actual wallet-engine report and pinned worker not supplied')
class ReportTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        if gate is not None:cls.w=worker()
    def setUp(self):
        self.assertIsNotNone(gate,'P6 wallet exact real-engine report checker is missing')
        self.path=Path(os.environ['P6_WALLET_REPORT']);self.v=gate.load(self.path)
    def reject(self,v):
        with self.assertRaises(ValueError):gate.validate(v,self.path,self.w)
    def test_actual_wallet_report_passes(self):self.assertTrue(gate.validate(self.v,self.path,self.w)['qualified'])
    def test_missing_failed_duplicate_checks_and_candidate_refused(self):
        for what in ('missing','false','duplicate','candidate'):
            v=copy.deepcopy(self.v)
            if what=='missing':v['checks'].pop()
            elif what=='false':v['checks'][0]['passed']=False
            elif what=='duplicate':v['checks'][0]=copy.deepcopy(v['checks'][1])
            else:v['status']='candidate-passed'
            self.reject(v)
    def test_source_bootstrap_binary_and_raw_log_tamper_refused(self):
        for what in ('source','wallet-source','runner-source','genesis','worker','log'):
            v=copy.deepcopy(self.v)
            if what=='source':v['source']['files'][next(iter(v['source']['files']))]['sha256']='ab'*32
            elif what=='wallet-source':del v['source']['files']['src/protocol6_wallet.py']
            elif what=='runner-source':v['source']['files']['scripts/run_protocol6_wallet.py']['sha256']='ab'*32
            elif what=='genesis':v['genesis_sha256']='ab'*32
            elif what=='worker':v['inputs']['worker']['sha256']='ab'*32
            else:v['artifacts'][0]['sha256']='ab'*32
            self.reject(v)
    def test_exact_completion_wire_receipt_and_signature_tamper_refused(self):
        for what in ('wire','receipt','signature','attempt'):
            v=copy.deepcopy(self.v)
            if what=='wire':v['wallet_record']['raw']='00'
            elif what=='receipt':v['wallet_record']['receipt']['fee']=999
            elif what=='signature':v['signed_header']['commit']['signatures'][0]['signature']='AA=='
            else:v['wallet_status']['attempts']=0
            self.reject(v)
    def test_conflict_release_production_and_freshness_claims_refused(self):
        for group,key,value in [('claims','production_ready',True),('claims','freshness_established',True),('held_obligation','status','recorded-certified')]:
            v=copy.deepcopy(self.v)
            if group=='held_obligation':v[group]['status'][key]=value
            else:v[group][key]=value
            self.reject(v)
if __name__=='__main__':unittest.main()
