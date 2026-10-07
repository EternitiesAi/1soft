#!/usr/bin/env python3
"""Closed actual journey receipts; separate native replay establishes proof validity."""
import json,math,sys
from pathlib import Path
ROOT=Path(__file__).resolve().parents[2]
sys.path[:0]=[str(ROOT/'src'),str(ROOT/'scripts'),str(ROOT/'tools/payment-console/src'),str(ROOT/'tools/release')]
from protocol8_transfer import canonical,sha,parse,txid
from run_protocol8_journey import CHECKS,CLAIMS,EXPECTED,LINKED,REFUSALS,PREPARES
from run_protocol8_console import STDOUT_SCHEME
from payment_console import render,STATE_TEXT
from check_protocol8_console import check as console_check
from check_protocol8_native import batch_startup

def pin(value):assert type(value) is str and len(value)==64 and all(x in '0123456789abcdef' for x in value)
def positive(value):assert type(value) is int and value>0
def native(audit,binary,kind=None):
    if kind=='worker':batch_startup(audit)
    assert audit['call_count']==audit['retained_count']==audit['reaped_count']==len(audit['calls'])<=512 and audit['timeout_count']==0
    for call in audit['calls']:
        positive(call['pid']);birth=call['start_ticks']
        assert type(birth) is str and birth.isascii() and birth.isdecimal() and int(birth)>0 and birth==str(int(birth))
        assert call['process_reaped'] is True and call['timed_out'] is False and call['exit_code'] in (0,2)
        assert call['binary_sha256']==binary

def check(path):
    raw=path.read_bytes();r=json.loads(raw)
    assert raw==canonical(r)+b'\n' and r['format']=='1soft/protocol8-journey-gate/v1' and r['status']=='qualified-one-host-wallet-journey'
    assert r['claims']==CLAIMS and r['source']['clean'] is True
    assert [x['id'] for x in r['checks']]==list(CHECKS) and all(x['passed'] is True for x in r['checks'])
    assert Path(r['console_report']).name==r['console_report'];linked=path.parent/r['console_report']
    assert sha(linked.read_bytes())==r['console_report_sha256'];outer=console_check(linked)
    payment=json.loads((path.parent/outer['payment_report']).read_bytes());inner=json.loads((path.parent/payment['wallet_report']).read_bytes())
    assert r['source']==outer['source']==inner['source'] and inner['journey']==r['journey']
    j=r['journey'];calls=j['invocations'];responses=j['responses']
    assert len(calls)==len(responses)==35 and tuple(x['command'] for x in calls)==EXPECTED
    assert tuple(x['linked_wallet_ordinal'] for x in calls)==LINKED
    assert {i for i,x in enumerate(calls,1) if x['exit_code']==1}==REFUSALS and not j['forced_cleanup']
    log=r['logs']['journey'];assert Path(log['name']).name==log['name'];b=(path.parent/log['name']).read_bytes()
    assert len(b)==log['bytes'] and sha(b)==log['sha256'] and b==b''.join(canonical(x)+b'\n' for x in responses)
    base={p:e['sha256'] for p,e in r['source']['files'].items() if
        (p.startswith('src/') and p.count('/')==1 and p.endswith('.py')) or p in
        ('scripts/protocol8_wallet.py','scripts/protocol8_worker_exec.py','scripts/protocol8_private_exec.py')}
    wallet_runtime=sha(canonical(dict(sorted(base.items()))))
    console_runtime=sha(canonical(dict(sorted((base|{p:r['source']['files'][p]['sha256'] for p in
        ('scripts/protocol8_payment.py','scripts/protocol8_console.py','tools/payment-console/src/payment_console.py')}).items()))))
    identities=set();children=[]
    child_base={'format','command','status','genesis_sha256','wallet_id','runtime_sha256','pid','start_ticks',
        'native_audits','broadcast_calls','automatic_retry','freshness_established','production_ready'}
    additions={'signed-state-observed':{'certificate'},'note-imported':{'commitment'},'original-wire-retained':{'txid'},
        'exact-wire-exported':{'txid','bytes','sha256','private_file_created'},
        'private-opening-delivered':{'txid','bytes','sha256','private_file_created'},'refused':{'error_type','reason'}}
    call_keys={'command','linked_wallet_ordinal','wallet_id','pid','start_ticks','exit_code','process_reaped','elapsed_seconds',
        'script_sha256','receipt_bytes','receipt_sha256','private_stdout_bytes','private_stdout_commitment',
        'private_stdout_commitment_scheme','private_stdout_blind_retained','private_stdout_retained','private_render_checked',
        'sanitized_stdout','wallet_sha256_before','wallet_sha256_after','refusal_wallet_unchanged','proxy_requests_before','proxy_requests_after'}
    response_keys={'format','command','status','pid','start_ticks','genesis_sha256','runtime_sha256','view','child_invocations',
        'child_responses','forced_cleanup','automatic_retry','freshness_established','production_ready','private_review_values_retained'}
    for i,(call,response) in enumerate(zip(calls,responses),1):
        assert set(call)==call_keys and set(response)==response_keys
        positive(call['pid']);positive(call['start_ticks']);ident=(call['pid'],call['start_ticks'])
        assert ident not in identities;identities.add(ident)
        assert ident==(response['pid'],response['start_ticks']) and call['process_reaped'] is True
        assert call['script_sha256']==r['source']['files']['scripts/protocol8_console.py']['sha256']
        assert response['format']=='1soft/protocol8-payment-console/v1' and response['command']==call['command']
        genesis='ef'*32 if i==35 else inner['genesis_sha256'];assert response['genesis_sha256']==genesis
        assert response['runtime_sha256']==console_runtime and not response['forced_cleanup']
        assert all(response[k] is False for k in ('automatic_retry','freshness_established','production_ready','private_review_values_retained'))
        assert response['status']==('refused' if i in REFUSALS else 'console-completed')
        assert call['receipt_bytes']==len(canonical(response)+b'\n') and call['receipt_sha256']==sha(canonical(response)+b'\n')
        assert type(call['elapsed_seconds']) in (int,float) and math.isfinite(call['elapsed_seconds']) and 0<=call['elapsed_seconds']<=1000
        assert type(call['private_stdout_bytes']) is int and 0<call['private_stdout_bytes']<=16384
        pin(call['private_stdout_commitment']);pin(call['wallet_sha256_before']);pin(call['wallet_sha256_after'])
        assert call['private_stdout_commitment_scheme']==STDOUT_SCHEME
        assert call['private_stdout_retained'] is call['private_stdout_blind_retained'] is False
        assert call['private_render_checked'] is (i in PREPARES)
        assert call['proxy_requests_before']==call['proxy_requests_after']==(0 if i<=20 else 1)
        assert call['refusal_wallet_unchanged'] is (True if i in REFUSALS else None)
        if i in REFUSALS:assert call['wallet_sha256_before']==call['wallet_sha256_after']
        cc=response['child_invocations'];cr=response['child_responses']
        assert len(cc)==len(cr)==(0 if i==13 else 1)
        if i!=13:
            child=cc[0];reply=cr[0];children.append(reply)
            assert child['kind']=='wallet' and child['command']==reply['command']==call['command']
            positive(child['pid']);positive(child['start_ticks']);ident=(child['pid'],child['start_ticks'])
            assert ident not in identities;identities.add(ident);assert ident==(reply['pid'],reply['start_ticks'])
            assert child['process_reaped'] is True and child['diagnostic_present'] is False
            assert child['script_sha256']==r['source']['files']['scripts/protocol8_wallet.py']['sha256']
            assert child['stdout_bytes']==len(canonical(reply)+b'\n') and child['stdout_sha256']==sha(canonical(reply)+b'\n')
            assert child['exit_code']==call['exit_code']==(1 if i in REFUSALS else 0)
            assert reply['format']=='1soft/protocol8-wallet-cli/v1' and reply['runtime_sha256']==wallet_runtime and reply['genesis_sha256']==genesis
            assert reply['broadcast_calls']==0 and all(reply[k] is False for k in ('automatic_retry','freshness_established','production_ready'))
            assert set(reply)==child_base|additions[reply['status']]
            for name,audit in reply['native_audits'].items():native(audit,inner['inputs'][name]['sha256'],name)
            if i not in REFUSALS:assert reply['wallet_id']==call['wallet_id']
            if LINKED[i-1] is not None:
                k=LINKED[i-1]-1;assert reply==payment['wallet_cli']['responses'][k]
                mirrored=payment['wallet_cli']['invocations'][k]
                assert mirrored=={k:v for k,v in child.items() if k not in ('kind','diagnostic_present')}|{'wallet_id':call['wallet_id']}
        view=response['view'];assert view['can_submit'] is False
        human=call['sanitized_stdout'];assert render(view) in human
        for label in ('Recipient: ','Amount: ','Payment expiry: '):assert human.count(label+'[private intent omitted]')==(1 if i in PREPARES else 0)
        if i in PREPARES:
            commitment=responses[11]['view']['commitment'] if i==18 else responses[23]['view']['commitment'] if i in (31,33) else responses[8]['view']['commitment']
            assert human.count('Input commitment: '+commitment+'\n')==1 and human.count('Type PREPARE '+commitment+' to prepare')==1
        common={'state','message','wallet_id','can_submit','payment_child_started','opening_values_omitted'}
        if i in REFUSALS:
            assert set(view)=={'state','message','can_submit'} and view['state']=='refused' and view['message']==STATE_TEXT['refused']
        elif i==13:
            assert set(view)=={'state','message','can_submit','confirmation','wallet_child_started','payment_child_started','prepared_not_sent'}
            assert view['state']=='preparation-cancelled' and view['confirmation']=='cancelled' and view['wallet_child_started'] is False
            assert view['payment_child_started'] is False and view['prepared_not_sent'] is True
            assert call['wallet_sha256_before']==call['wallet_sha256_after']
        else:
            assert view['wallet_id']==call['wallet_id'] and view['payment_child_started'] is False and view['opening_values_omitted'] is True
            reply=cr[0]
            if call['command']=='observe':
                assert set(view)==common|{'as_of_height','app_hash'} and view['state']=='signed-state-observed'
                assert view['as_of_height']==reply['certificate']['state_height'] and view['app_hash']==reply['certificate']['app_hash']
                stages={1:'receive_witness',7:'receive_witness',11:'receive_witness',
                    21:'state_witness',23:'state_witness',26:'conflict_witness'}
                assert i in stages
                witness=inner[stages[i]]
                assert view['as_of_height']==witness['height'] and view['app_hash']==witness['app_hash']
            elif call['command']=='import-note':
                assert set(view)==common|{'commitment'} and view['state']=='note-imported' and view['commitment']==reply['commitment']
            elif call['command']=='prepare':
                assert set(view)==common|{'txid','commitment','confirmation','prepared_not_sent'} and view['state']=='prepared-not-attempted'
                assert view['txid']==reply['txid'] and view['confirmation']=='exact-input-commitment' and view['prepared_not_sent'] is True
            else:
                assert set(view)==common|{'txid','output_sha256','output_bytes','private_file_created'}
                assert view['state']==reply['status'] and view['txid']==reply['txid'] and view['private_file_created'] is True
                assert view['output_sha256']==reply['sha256'] and view['output_bytes']==reply['bytes']
    assert len(children)==34 and len({x['private_stdout_commitment'] for x in calls})==35
    cancel=j['cancellation'];assert cancel['wallet_sha256_before']==cancel['wallet_sha256_after']==calls[12]['wallet_sha256_before']
    assert cancel['wallet_unchanged'] is True and cancel['wallet_child_started'] is cancel['payment_child_started'] is False
    assert cancel['proxy_requests_before']==cancel['proxy_requests_after']==0
    assert responses[8]['view']['commitment']==responses[9]['view']['commitment']==responses[13]['view']['commitment']
    assert calls[8]['wallet_sha256_after']==calls[9]['wallet_sha256_before']==calls[9]['wallet_sha256_after']
    assert responses[13]['view']['txid']==responses[21]['view']['txid']==inner['recovery']['txid']
    assert calls[21]['wallet_id']==calls[13]['wallet_id']==inner['wallet_inventory']['wallet_id']
    respend=j['recipient_respend'];assert Path(respend['artifact']).name==respend['artifact']
    wire=(path.parent/respend['artifact']).read_bytes();assert len(wire)==respend['wire_bytes']==3560 and sha(wire)==respend['wire_sha256']
    assert txid(wire)==respend['txid']==responses[30]['view']['txid']==responses[31]['view']['txid']
    assert responses[31]['view']['output_sha256']==sha(wire) and respend['exported_exact'] is True
    assert respend['incoming_txid']==inner['recovery']['txid'] and respend['incoming_commitment']==parse(bytes.fromhex(inner['recovery']['receipt']['raw']))[10]
    assert respend['incoming_commitment']==responses[23]['view']['commitment']==responses[30]['view']['commitment']
    assert respend['wallet_id']==calls[23]['wallet_id']==calls[30]['wallet_id'] and respend['wallet_id']!=inner['wallet_inventory']['wallet_id']
    assert respend['attempts']==0 and respend['completed'] is respend['chain_executed'] is False and respend['held_input_refused'] is True
    assert len(j['preproof_holds'])==3
    for hold,ordinal,request in zip(j['preproof_holds'],(14,18,31),(71,81,91)):
        reply=responses[ordinal-1]['child_responses'][0];assert (hold['pid'],hold['start_ticks'])==(reply['pid'],reply['start_ticks'])
        assert hold['wire_absent'] is True and hold['attempts']==0;pin(hold['encrypted_file_sha256'])
        assert hold['request']==request.to_bytes(32,'little').hex() and reply['native_audits']['prover']['call_count']==1
    assert parse(wire)[6]==(91).to_bytes(32,'little').hex() and parse(wire)[1]==inner['genesis']['network']
    native(respend['native_audit'],inner['inputs']['worker']['sha256'],'worker')
    a=respend['native_audit'];assert a['call_count']==2 and tuple(x['operation'] for x in a['calls'])==('startup','verify')
    from protocol8_transfer import PROFILE
    assert a['calls'][0]['startup_checks']=={'valid_proof_verified':True,'corrupt_proof_refused':True,
        **{k:PROFILE[k] for k in ('parameter_sha256','verifying_key_sha256')}}
    assert a['calls'][-1]['input_bytes']==3592 and a['calls'][-1]['output_bytes']==3 and a['calls'][-1]['exit_code']==0
    assert j['late_refusals']=={'delivery_symlink_refused':True,'symlink_unchanged':True,'target_absent':True,'wrong_genesis_refused':True}
    assert not responses[-1]['child_responses'][0]['native_audits']
    print('P8 journey closed gate passed: 14 journey +12 console +13 payment +22 wallet checks; 35 lifecycle calls; native replay separate')
    return r

if __name__=='__main__':check(Path(sys.argv[1]))
