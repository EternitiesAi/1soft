"""Bounded early receipt tamper refusals; real replay is run separately once."""
import copy,importlib.util,json,os,unittest
from pathlib import Path
from unittest.mock import patch
ROOT=Path(__file__).resolve().parents[1]
spec=importlib.util.spec_from_file_location('vault_check',ROOT/'tools/release/check_protocol7_retained.py');check=importlib.util.module_from_spec(spec)
import sys
sys.path.insert(0,str(ROOT/'tools/release'));spec.loader.exec_module(check)
@unittest.skipUnless(os.environ.get('P7_RETAINED_REPORT') and os.environ.get('P7_RETAINED_CHECK_WORKER'),'unassessed: actual custody report not supplied')
class ReportTests(unittest.TestCase):
    def test_closed_claim_check_source_binary_artifact_process_and_ciphertext_refusals(self):
        path=Path(os.environ['P7_RETAINED_REPORT']);v=check.load(path)
        for label in ('extra','claim','check','candidate','spent_reason','grant_reason','source','binary','artifact','process','ciphertext','cli','retained_reason','handoff'):
            bad=copy.deepcopy(v)
            if label=='extra':bad['unsupported']=True
            elif label=='claim':bad['claims']['rollback_detection']=True
            elif label=='check':bad['checks'][3]['passed']=False
            elif label=='candidate':bad['checks'][0]['evidence']['candidate']=True
            elif label in ('spent_reason','grant_reason'):
                name='spent_input_and_duplicate_refused' if label=='spent_reason' else 'revoked_grant_refused_before_proving'
                next(c for c in bad['checks'] if c['id']==name)['evidence']['refusal']='unrelated refusal'
            elif label=='source':bad['source']['clean']=False
            elif label=='binary':bad['inputs']['engine']['sha256']='ab'*32
            elif label=='artifact':bad['artifacts'][0]['sha256']='ab'*32
            elif label=='process':bad['processes'][0]['exit_code']=None
            elif label=='ciphertext':bad['vault_ciphertext']['header']['revision']=2
            elif label=='retained_reason':next(c for c in bad['checks'] if c['id']=='stale_retained_authority_refused')['evidence']['refusal']='unrelated'
            elif label=='handoff':next(c for c in bad['checks'] if c['id']=='authenticated_handoff_race_refused')['evidence']['prover_calls']=1
            else:bad['cli_commands'][0]['result']['execution']['prover']['exit_code']=1
            with self.subTest(label=label),patch.object(check,'Worker',side_effect=AssertionError('early metadata refusal must precede worker')):
                with self.assertRaises(ValueError):check.validate(bad,path,os.environ['P7_RETAINED_CHECK_WORKER'])
if __name__=='__main__':unittest.main()
