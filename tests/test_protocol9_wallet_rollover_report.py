"""Receipt refusal tests only; no mocked native qualification."""
import copy, sys, unittest
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'tools/release'))
from check_protocol9_wallet_rollover import CHECKS, preflight

def receipt():
    return {'format':'1soft/protocol9-wallet-rollover/v1',
        'status':'qualified-one-host-p9-wallet-rollover',
        'checks':[{'id':name,'passed':True,'evidence':{}} for name in CHECKS],
        'processes':[{'exit_code':0}],
        'cold_process':{'exit_code':0,'process_reaped':True},
        'worker_audits':[{'call_count':1,'reaped_count':1,'timeout_count':0}],
        'private_process_audits':[{'call_count':1,'reaped_count':1,'timeout_count':0}],
        'native_processes':[{'exit_code':0,'process_reaped':True}],
        'payments':[{'input_segment':0,'committed_height':3},
                    {'input_segment':0,'committed_height':70},
                    {'input_segment':1,'committed_height':73}],
        'generator_payments':[{} for _ in range(7)],
        'observations':[{} for _ in range(5)]}

class ReportRefusal(unittest.TestCase):
    def test_well_shaped_is_not_native_qualification(self):
        # Only preflight; real signed replay still mandatory in verify().
        self.assertIsNone(preflight(receipt()))
    def refused(self,edit):
        r=receipt();edit(r)
        with self.assertRaises(ValueError):preflight(r)
    def test_missing_check(self):self.refused(lambda r:r['checks'].pop())
    def test_duplicate_check(self):self.refused(lambda r:r['checks'].append(r['checks'][0]))
    def test_true_like_integer(self):self.refused(lambda r:r['checks'][0].update(passed=1))
    def test_failed_process(self):self.refused(lambda r:r['processes'][0].update(exit_code=1))
    def test_native_timeout(self):self.refused(lambda r:r['worker_audits'][0].update(timeout_count=1))
    def test_unreaped_child(self):self.refused(lambda r:r['cold_process'].update(process_reaped=False))
    def test_missing_old_segment_payment(self):self.refused(lambda r:r['payments'][1].update(input_segment=1))
    def test_missing_new_segment_payment(self):self.refused(lambda r:r['payments'][2].update(input_segment=0))
    def test_pre64_payment(self):self.refused(lambda r:r['payments'][1].update(committed_height=64))
    def test_missing_generator_payment(self):self.refused(lambda r:r['generator_payments'].pop())
    def test_missing_observation(self):self.refused(lambda r:r['observations'].pop())
    def test_cleanup_error(self):self.refused(lambda r:r.update(cleanup_error={'type':'RuntimeError'}))

if __name__=='__main__':unittest.main()
