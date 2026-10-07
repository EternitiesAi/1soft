#!/usr/bin/env python3
"""Closed read-only guide receipts; actual custody/proof checks are separate."""
import json,math,sys
from pathlib import Path
ROOT=Path(__file__).resolve().parents[2]
sys.path[:0]=[str(ROOT/'src'),str(ROOT/'scripts'),str(ROOT/'tools/payment-console/src'),str(ROOT/'tools/release')]
from protocol8_transfer import canonical,sha
from payment_console import guide_view,render,FORMAT,STATE_TEXT
from run_protocol8_guide import CASES
from profile_protocol8_inventory import FUNCTIONS
from check_protocol8_journey import check as journey_check,native,pin,positive

CLAIMS={'actual_read_only_guide':True,'synthetic_funds':True,'one_trusted_host':True,
    'automatic_retry':False,'freshness_established':False,'production_ready':False,
    'performance_improvement_established':False,'profile_overhead_assessed':False,'private_payloads_retained':False}
CALL={'pid','start_ticks','exit_code','process_reaped','elapsed_seconds','case','lifecycle_ordinal',
    'selection','bad_genesis','expected_refusal','script_sha256','receipt_bytes','receipt_sha256',
    'stdout_bytes','stdout_sha256','stdout','expected_inventory','wallet_sha256_before','wallet_sha256_after',
    'private_fixture_state_unchanged','configuration_journal_output_bytes_unchanged','proxy_requests_before','proxy_requests_after'}
RESPONSE={'format','command','status','pid','start_ticks','genesis_sha256','runtime_sha256','view',
    'child_invocations','child_responses','forced_cleanup','automatic_retry','freshness_established','production_ready','private_review_values_retained'}
CHILD_CALL={'kind','command','pid','start_ticks','exit_code','process_reaped','elapsed_seconds','script_sha256',
    'stdout_bytes','stdout_sha256','diagnostic_present'}
CHILD={'format','command','status','genesis_sha256','wallet_id','runtime_sha256','pid','start_ticks',
    'native_audits','broadcast_calls','automatic_retry','freshness_established','production_ready'}

def elapsed(value):
    assert type(value) in (int,float) and math.isfinite(value) and 0<=value<=1000
def identity(value,seen):
    positive(value['pid']);positive(value['start_ticks']);ident=(value['pid'],value['start_ticks'])
    assert ident not in seen;seen.add(ident);assert value['process_reaped'] is True
    elapsed(value['elapsed_seconds'])
    return ident
def untouched(value):
    assert value['private_fixture_state_unchanged'] is value['configuration_journal_output_bytes_unchanged'] is True
    assert value['proxy_requests_before']==value['proxy_requests_after']
def wallet_reply(value,inner,runtime,genesis):
    assert value['format']=='1soft/protocol8-wallet-cli/v1' and value['command']=='inventory'
    assert value['genesis_sha256']==genesis and value['runtime_sha256']==runtime and value['broadcast_calls']==0
    assert all(value[k] is False for k in ('automatic_retry','freshness_established','production_ready'))
    addition={'error_type','reason'} if value['status']=='refused' else {'inventory'}
    assert set(value)==CHILD|addition
    for name,audit in value['native_audits'].items():native(audit,inner['inputs'][name]['sha256'],name)

def check(path,*,candidate=False):
    raw=path.read_bytes();r=json.loads(raw)
    assert raw==canonical(r)+b'\n' and set(r)=={'format','status','source','journey_report','journey_report_sha256','guide','logs','claims'}
    assert r['format']=='1soft/protocol8-guide-gate/v1' and r['status']==('candidate' if candidate else 'qualified-one-host-wallet-guide')
    assert r['claims']==CLAIMS and r['source']['clean'] is True
    assert Path(r['journey_report']).name==r['journey_report']
    linked=path.parent/r['journey_report'];assert sha(linked.read_bytes())==r['journey_report_sha256'];outer=journey_check(linked)
    cs=json.loads((path.parent/outer['console_report']).read_bytes())
    p=json.loads((path.parent/cs['payment_report']).read_bytes());inner=json.loads((path.parent/p['wallet_report']).read_bytes())
    assert r['source']==outer['source']==inner['source'] and r['guide']==inner['guide']
    g=r['guide'];assert set(g)=={'calls','responses','profile','profile_call','forced_cleanup'} and not g['forced_cleanup']
    assert len(g['calls'])==len(g['responses'])==10 and tuple(x['case'] for x in g['calls'])==CASES
    assert tuple(x['lifecycle_ordinal'] for x in g['calls'])==(1,9,9,9,9,14,21,24,26,31)
    assert {i for i,x in enumerate(g['calls']) if x['expected_refusal']}=={3,4}
    assert set(r['logs'])=={'guide'};log=r['logs']['guide'];assert set(log)=={'name','bytes','sha256'}
    assert Path(log['name']).name==log['name'];b=(path.parent/log['name']).read_bytes()
    assert b==b''.join(canonical(x)+b'\n' for x in g['responses']) and len(b)==log['bytes'] and sha(b)==log['sha256']
    files=r['source']['files'];base={p:e['sha256'] for p,e in files.items() if
        (p.startswith('src/') and p.count('/')==1 and p.endswith('.py')) or p in
        ('scripts/protocol8_wallet.py','scripts/protocol8_worker_exec.py','scripts/protocol8_private_exec.py')}
    wallet_runtime=sha(canonical(dict(sorted(base.items()))))
    console_runtime=sha(canonical(dict(sorted((base|{p:files[p]['sha256'] for p in
        ('scripts/protocol8_payment.py','scripts/protocol8_console.py','tools/payment-console/src/payment_console.py')}).items()))))
    seen=set()
    for i,(call,response) in enumerate(zip(g['calls'],g['responses'])):
        assert set(call)==CALL and set(response)==RESPONSE;ident=identity(call,seen);untouched(call)
        assert (response['pid'],response['start_ticks'])==ident and response['format']==FORMAT and response['command']=='guide'
        assert call['script_sha256']==files['scripts/protocol8_console.py']['sha256']
        assert type(call['expected_refusal']) is bool and call['expected_refusal'] is (i in (3,4))
        assert type(call['bad_genesis']) is bool and call['bad_genesis'] is (i==4)
        genesis='ef'*32 if call['bad_genesis'] else inner['genesis_sha256']
        assert response['genesis_sha256']==genesis and response['runtime_sha256']==console_runtime and not response['forced_cleanup']
        assert all(response[k] is False for k in ('automatic_retry','freshness_established','production_ready','private_review_values_retained'))
        assert call['exit_code']==(1 if i in (3,4) else 0) and response['status']==('refused' if i in (3,4) else 'console-completed')
        encoded=canonical(response)+b'\n'
        assert call['receipt_bytes']==len(encoded) and call['receipt_sha256']==sha(encoded)
        text=call['stdout'].encode();assert call['stdout_bytes']==len(text) and call['stdout_sha256']==sha(text)
        pin(call['wallet_sha256_before']);assert call['wallet_sha256_before']==call['wallet_sha256_after']
        assert len(response['child_invocations'])==len(response['child_responses'])==1
        child=response['child_invocations'][0];reply=response['child_responses'][0]
        assert set(child)==CHILD_CALL and child['kind']=='wallet' and child['command']=='inventory'
        child_ident=identity(child,seen);assert child_ident==(reply['pid'],reply['start_ticks'])
        assert child['diagnostic_present'] is False and child['script_sha256']==files['scripts/protocol8_wallet.py']['sha256']
        child_raw=canonical(reply)+b'\n'
        assert child['stdout_bytes']==len(child_raw) and child['stdout_sha256']==sha(child_raw)
        wallet_reply(reply,inner,wallet_runtime,genesis)
        assert child['exit_code']==(1 if i==4 else 0) and reply['status']==('refused' if i==4 else 'authenticated-inventory')
        selection=call['selection'];assert set(selection)=={'commitment','txid'}
        expected=call['expected_inventory']
        # Validate the complete expected shape even for refusals.
        guide_view(expected,expected['wallet_id'],inner['genesis_sha256'])
        if i!=4:assert reply['inventory']==expected and reply['wallet_id']==expected['wallet_id']
        if i in (3,4):
            assert response['view']=={'state':'refused','message':STATE_TEXT['refused'],'can_submit':False}
            if i==3:assert selection=={'commitment':None,'txid':'98'*32} and '98'*32 not in {x['txid'] for x in expected['obligations']}
            else:assert selection=={'commitment':None,'txid':None}
        else:
            wanted=guide_view(expected,reply['wallet_id'],genesis,**selection)
            assert response['view']==wanted
            assert selection['commitment'] is not None if i in (1,2,7) else selection['txid'] is not None if i in (5,6,8,9) else selection=={'commitment':None,'txid':None}
        assert text==render(response['view']).encode()
    assert g['responses'][1]['view']==g['responses'][2]['view'] and g['calls'][1]['stdout']==g['calls'][2]['stdout']
    pc=g['profile_call'];assert set(pc)=={'pid','start_ticks','exit_code','process_reaped','elapsed_seconds','script_sha256',
        'stdout_bytes','stdout_sha256','expected_inventory','private_fixture_state_unchanged',
        'configuration_journal_output_bytes_unchanged','proxy_requests_before','proxy_requests_after'}
    ident=identity(pc,seen);untouched(pc);assert pc['exit_code']==0
    profile=g['profile'];assert set(profile)=={'format','status','profiled_command','wallet_receipt','host_elapsed_seconds',
        'phases','phase_durations_overlap','profile_overhead_assessed','performance_improvement_established',
        'runtime_or_lifetime_changed','private_payloads_recorded','automatic_retry','freshness_established','production_ready'}
    assert profile['format']=='1soft/protocol8-inventory-host-profile/v1' and profile['status']=='measured-authenticated-inventory' and profile['profiled_command']=='inventory'
    assert profile['phase_durations_overlap'] is True and all(profile[k] is False for k in ('profile_overhead_assessed',
        'performance_improvement_established','runtime_or_lifetime_changed','private_payloads_recorded','automatic_retry','freshness_established','production_ready'))
    assert pc['script_sha256']==files['scripts/profile_protocol8_inventory.py']['sha256']
    b=canonical(profile)+b'\n';assert pc['stdout_bytes']==len(b) and pc['stdout_sha256']==sha(b)
    elapsed(profile['host_elapsed_seconds']);assert set(profile['phases'])==set(FUNCTIONS)
    for phase in profile['phases'].values():
        assert set(phase)=={'calls','primitive_calls','self_seconds','cumulative_seconds'}
        positive(phase['calls']);positive(phase['primitive_calls']);elapsed(phase['self_seconds']);elapsed(phase['cumulative_seconds'])
        assert phase['primitive_calls']<=phase['calls'] and phase['self_seconds']<=phase['cumulative_seconds']<=profile['host_elapsed_seconds']+0.01
    reply=profile['wallet_receipt'];assert ident==(reply['pid'],reply['start_ticks'])
    wallet_reply(reply,inner,wallet_runtime,inner['genesis_sha256'])
    assert reply['status']=='authenticated-inventory' and reply['inventory']==pc['expected_inventory']==g['calls'][1]['expected_inventory']
    assert reply['native_audits']['worker']['calls'][0]['operation']=='startup'
    from protocol8_transfer import PROFILE
    assert reply['native_audits']['worker']['calls'][0]['startup_checks']=={'valid_proof_verified':True,
        'corrupt_proof_refused':True,**{k:PROFILE[k] for k in ('parameter_sha256','verifying_key_sha256')}}
    return r

if __name__=='__main__':
    r=check(Path(sys.argv[1]))
    print('P8 guide closed receipts passed: 10 actual read-only guide calls, one measured protected inventory, inherited14/12/13/22 checks')
