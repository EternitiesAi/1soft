"""Closed receipt regressions over retained real alpha evidence; no native execution."""
import copy,json,sys,tempfile,unittest
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
sys.path[:0]=[str(ROOT/'src'),str(ROOT/'tools/release')]
import check_protocol8_alpha as alpha
import protocol8_transfer as n
REPORT=ROOT/'evidence/protocol8-alpha/20261007/alpha-05.json'

def synchronize(value):
    """Keep public child stdout mirrors coherent after semantic changes."""
    if isinstance(value,dict):
        for item in value.values():synchronize(item)
        if 'child_responses' in value and 'child_invocations' in value:
            for call,reply in zip(value['child_invocations'],value['child_responses']):
                raw=n.canonical(reply)+b'\n';call['stdout_bytes']=len(raw);call['stdout_sha256']=n.sha(raw)
    elif isinstance(value,list):
        for item in value:synchronize(item)

def change_startup(value,key,replacement):
    if isinstance(value,dict):
        if 'startup_checks' in value:value['startup_checks'][key]=replacement
        for item in value.values():change_startup(item,key,replacement)
    elif isinstance(value,list):
        for item in value:change_startup(item,key,replacement)

class AlphaReceipt(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.original=json.loads(REPORT.read_bytes())
    def check(self,value):
        with tempfile.TemporaryDirectory() as name:
            path=Path(name)/'receipt.json';path.write_bytes(n.canonical(value)+b'\n')
            path.with_name(path.name+'.artifacts').symlink_to(REPORT.with_name(REPORT.name+'.artifacts'),target_is_directory=True)
            return alpha.check(path) # Explicit structure-only mode; final CLI requires actual worker replay.
    def test_actual_retained_receipt_has_explicitly_weaker_structural_result(self):
        result=self.check(self.original)
        self.assertEqual(result['status'],'passed-alpha-receipt-structure-only')
        self.assertIsNone(result['independent_replay'])
        self.assertEqual(result['complete_producer_source_membership'],252)
        self.assertEqual(result['actual_browser_payments'],2)
        self.assertEqual(result['fixture_native_processes'],3)
        self.assertEqual(result['validator_application_processes'],24)
    def test_coherent_semantic_alterations_refused(self):
        cases=[]
        def add(name,mutation):cases.append((name,mutation))
        add('missing_fixture_roster',lambda r:r['native_processes'].clear())
        add('missing_one_fixture',lambda r:r['native_processes'].pop())
        for key,value in (('binary','helper'),('operation','other'),('binary_sha256','00'*32),('exit_code',2),
                          ('exit_code',False),('process_reaped',False),('start_ticks',0),('pid',True)):
            add('fixture_'+key+'_'+str(value),lambda r,k=key,v=value:r['native_processes'][0].__setitem__(k,v))
        add('fixture_identity_reused',lambda r:r['native_processes'][1].update({k:r['native_processes'][0][k] for k in ('pid','start_ticks')}))
        add('missing_network_roster',lambda r:r['processes'].clear())
        add('missing_application',lambda r:r['processes'].pop(0))
        add('missing_one_baseline_engine',lambda r:r['processes'].pop())
        add('duplicate_network_process',lambda r:r['processes'].append(copy.deepcopy(r['processes'][0])))
        for key,value in (('role','worker'),('node',4),('node',True),('executable_sha256','00'*32),
                          ('exit_code',0),('exit_code',True),('start_ticks',0),('pid',False)):
            add('network_'+key+'_'+str(value),lambda r,k=key,v=value:r['processes'][0].__setitem__(k,v))
        add('cross_roster_identity',lambda r:r['processes'][0].update({k:r['native_processes'][0][k] for k in ('pid','start_ticks')}))
        add('source_member_omitted',lambda r:r['source']['files'].pop('tools/p8-wallet/web/wallet.js'))
        add('source_map_empty',lambda r:r['source']['files'].clear())
        for key,value in (('valid_proof_verified',False),('corrupt_proof_refused',False),
                          ('parameter_sha256','00'*32),('verifying_key_sha256','00'*32)):
            add('coherent_startup_'+key,lambda r,k=key,v=value:change_startup(r,k,v))
        add('readiness_not_wallet',lambda r:r['browser']['transport_readiness']['bob']['attempts'][-1].update(wallet_page=False))
        add('readiness_wrong_http',lambda r:r['browser']['transport_readiness']['carol']['attempts'][-1].update(http_status=500))
        for key,value in (('can_submit',True),('payment_child_started',True),('prepared_not_sent',False),('state','executed-exact')):
            add('prepare_'+key,lambda r,k=key,v=value:r['browser_actions'][3]['console_receipt']['view'].__setitem__(k,v))
        add('review_other_txid',lambda r:r['browser_actions'][4]['console_receipt']['view']['review'].update(txid='00'*32))
        add('review_has_attempt',lambda r:r['browser_actions'][4]['console_receipt']['view']['review'].update(attempts=1))
        add('unknown_became_success',lambda r:r['browser_actions'][5]['console_receipt']['view'].update(state='executed-exact'))
        add('recovery_unknown',lambda r:r['browser_actions'][7]['console_receipt']['view'].update(state='attempted-outcome-unknown'))
        add('recovery_two_attempts',lambda r:r['browser_actions'][7]['console_receipt']['view'].update(attempts=2))
        add('replay_mutated_wallet',lambda r:r['browser_actions'][8].update(wallet_sha256_after='00'*32))
        add('proxy_second_forward',lambda r:r['proxies'][0]['requests'][0].update(forward_count=2))
        add('proxy_other_txid',lambda r:r['proxies'][1]['requests'][0].update(txid='00'*32))
        add('proxy_reply_delivered',lambda r:r['proxies'][0]['requests'][0].update(reply_forwarded=True))
        add('proxy_not_stopped',lambda r:r['proxies'][1].update(stopped=False))
        add('private_review_retained',lambda r:r['browser'].update(private_display_retained=True))
        add('production_claim',lambda r:r['claims'].update(production_ready=True))
        add('cleanup_failed',lambda r:r['cleanup_errors'].append('owned-process-still-running'))
        add('wrong_engine_pin',lambda r:r['inputs']['engine'].update(sha256='00'*32))
        add('child_identity_mirror',lambda r:r['browser_actions'][0]['console_receipt']['child_invocations'][0].update(pid=1))
        for name,mutation in cases:
            with self.subTest(case=name):
                value=copy.deepcopy(self.original);mutation(value);synchronize(value)
                with self.assertRaises((AssertionError,KeyError,ValueError,TypeError)):self.check(value)
        self.assertEqual(len(cases),51)

if __name__=='__main__':unittest.main()
