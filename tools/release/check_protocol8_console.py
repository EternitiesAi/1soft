#!/usr/bin/env python3
"""Closed console receipt consistency; native replay is a separate check."""
import json,sys
from pathlib import Path
ROOT=Path(__file__).resolve().parents[2]
sys.path[:0]=[str(ROOT/'src'),str(ROOT/'scripts'),str(ROOT/'tools/payment-console/src'),str(ROOT/'tools/release')]
from protocol8_transfer import canonical,sha
from run_protocol8_console import EXPECTED,REFUSALS,CHECKS,CLAIMS
from run_protocol8_payment import EXPECTED_PAYMENT_REFUSALS
from payment_console import STATE_TEXT,render
from check_protocol8_payment import check as payment_check

def check(path):
    raw=path.read_bytes();r=json.loads(raw)
    assert raw==canonical(r)+b'\n' and r['format']=='1soft/protocol8-console-gate/v1' and r['status']=='qualified-one-host-payment-console'
    assert r['claims']==CLAIMS and r['source']['clean'] is True
    assert [x['id'] for x in r['checks']]==list(CHECKS) and all(x['passed'] is True for x in r['checks'])
    assert Path(r['payment_report']).name==r['payment_report'];linked=path.parent/r['payment_report']
    assert sha(linked.read_bytes())==r['payment_report_sha256'];parent=payment_check(linked)
    inner=json.loads((path.parent/parent['wallet_report']).read_bytes())
    assert inner['source']==parent['source']==r['source'] and inner['console']==r['console']
    cs=r['console'];calls=cs['invocations'];responses=cs['responses']
    assert len(calls)==len(responses)==19 and tuple(x['command'] for x in calls)==EXPECTED
    assert {i for i,x in enumerate(calls,1) if x['exit_code']==1}==REFUSALS
    assert cs['legacy_refusal_positions']==sorted(EXPECTED_PAYMENT_REFUSALS) and not cs['forced_cleanup']
    log=r['logs']['console'];assert Path(log['name']).name==log['name'];b=(path.parent/log['name']).read_bytes()
    assert len(b)==log['bytes'] and sha(b)==log['sha256'] and b==b''.join(canonical(x)+b'\n' for x in responses)
    base={name:e['sha256'] for name,e in r['source']['files'].items() if
        (name.startswith('src/') and name.count('/')==1 and name.endswith('.py')) or name in
        ('scripts/protocol8_wallet.py','scripts/protocol8_worker_exec.py','scripts/protocol8_private_exec.py')}
    wallet_runtime=sha(canonical(dict(sorted(base.items()))))
    payment_runtime=sha(canonical(dict(sorted((base|{'scripts/protocol8_payment.py':r['source']['files']['scripts/protocol8_payment.py']['sha256']}).items()))))
    console_runtime=sha(canonical(dict(sorted((base|{name:r['source']['files'][name]['sha256'] for name in
        ('scripts/protocol8_payment.py','scripts/protocol8_console.py','tools/payment-console/src/payment_console.py')}).items()))))
    identities=set();payment_successes=[];reviews=[]
    for ordinal,(call,response) in enumerate(zip(calls,responses),1):
        assert type(call['pid']) is int and call['pid']>0 and type(call['start_ticks']) is int and call['start_ticks']>0
        assert (call['pid'],call['start_ticks'])==(response['pid'],response['start_ticks'])
        identity=(call['pid'],call['start_ticks']);assert identity not in identities;identities.add(identity)
        assert call['process_reaped'] is True and call['script_sha256']==r['source']['files']['scripts/protocol8_console.py']['sha256']
        assert response['format']=='1soft/protocol8-payment-console/v1' and response['command']==call['command']
        assert response['runtime_sha256']==console_runtime and response['genesis_sha256']==inner['genesis_sha256']
        assert call['receipt_bytes']==len(canonical(response)+b'\n') and call['receipt_sha256']==sha(canonical(response)+b'\n')
        assert call['exit_code']==(1 if response['status']=='refused' else 0)
        assert not response['forced_cleanup'] and response['private_review_values_retained'] is False and call['private_stdout_retained'] is False
        assert type(call['private_stdout_bytes']) is int and 0<call['private_stdout_bytes']<=16384 and len(bytes.fromhex(call['private_stdout_sha256']))==32
        assert all(response[k] is False for k in ('automatic_retry','freshness_established','production_ready'))
        child_calls=response['child_invocations'];child_responses=response['child_responses'];assert len(child_calls)==len(child_responses)
        for child,x in zip(child_calls,child_responses):
            assert type(child['pid']) is int and child['pid']>0 and type(child['start_ticks']) is int and child['start_ticks']>0
            assert (child['pid'],child['start_ticks'])==(x['pid'],x['start_ticks'])
            identity=(child['pid'],child['start_ticks']);assert identity not in identities;identities.add(identity)
            assert child['process_reaped'] is True and child['diagnostic_present'] is False and child['kind'] in ('wallet','payment')
            script='scripts/protocol8_'+child['kind']+'.py'
            assert child['script_sha256']==r['source']['files'][script]['sha256']
            assert child['stdout_bytes']==len(canonical(x)+b'\n') and child['stdout_sha256']==sha(canonical(x)+b'\n')
            assert child['command']==x['command'] and child['exit_code']==(1 if x['status']=='refused' else 0)
            assert x['runtime_sha256']==(wallet_runtime if child['kind']=='wallet' else payment_runtime)
            assert x['genesis_sha256']==inner['genesis_sha256'] and all(x[k] is False for k in ('automatic_retry','freshness_established','production_ready'))
            for audit in x['native_audits'].values():
                assert audit['call_count']==audit['retained_count']==audit['reaped_count']==len(audit['calls'])<=512 and audit['timeout_count']==0
                for native in audit['calls']:
                    assert type(native['pid']) is int and native['pid']>0 and str(native['start_ticks']).isdecimal() and int(native['start_ticks'])>0
                    assert native['process_reaped'] is True and native['timed_out'] is False and native['exit_code'] in (0,2)
                    assert native['binary_sha256'] in {e['sha256'] for e in inner['inputs'].values()}
            if child['kind']=='payment' and x['status']!='refused':payment_successes.append(x)
        view=response['view'];assert view['can_submit'] is False or ordinal==7
        human=call['sanitized_stdout'];assert render(view) in human
        assert 'Recipient: [private intent omitted]' in human if call['private_render_checked'] else 'Recipient:' not in human
        assert call['private_render_checked'] is (ordinal in (7,8,9))
        if 'review' in view:
            review=view['review'];reviews.append(review)
            assert set(review)=={'wallet_id','txid','wire_sha256','wire_bytes','fee','valid_from','valid_until','attempts','completed','as_of_height','review_sha256','private_intent_omitted'}
            assert review['private_intent_omitted'] is True and review['attempts']==0 and review['completed'] is False and review['wire_bytes']==3560
            assert review['wallet_id']==parent['payment_caller']['proxy_requests'][0].get('wallet_id',inner['wallet_inventory']['wallet_id'])
        if response['status']=='refused':assert view['state']=='refused'
        if view['state'] in STATE_TEXT:assert view['message']==STATE_TEXT[view['state']]
        protected=[x for child,x in zip(child_calls,child_responses) if child['kind']=='payment']
        if response['status']!='refused' and view['state'] not in ('reviewed','cancelled','authenticated-inventory','configuration-valid'):
            assert len(protected)==1;x=protected[0];result=x['result'];state=result['status'] if result is not None else x['submission_state']
            assert view['state']==state and view['txid']==x['txid'] and view['attempts']==x['wallet_attempts'] and view['execution_confirmed'] is x['execution_confirmed']
            if result is not None:
                assert view['as_of_height']==result.get('state_height',result.get('as_of_height'))
                if 'app_hash' in result:assert view['app_hash']==result['app_hash']
    selected=[x for i,x in enumerate(parent['payment_caller']['responses'],1) if i not in EXPECTED_PAYMENT_REFUSALS]
    assert payment_successes==selected and len(payment_successes)==9
    assert cs['cancellation']['wallet_sha256_before']==cs['cancellation']['wallet_sha256_after']
    assert cs['cancellation']['wallet_unchanged'] is True and cs['cancellation']['private_render_checked'] is True
    assert all(cs['cancellation'][key] is False for key in ('journal_exists_before','journal_exists_after','payment_child_started'))
    assert cs['cancellation']['proxy_requests_before']==cs['cancellation']['proxy_requests_after']==0
    assert responses[7]['view']['state']=='cancelled' and not any(x['kind']=='payment' for x in responses[7]['child_invocations'])
    assert responses[8]['view']['confirmation']=='exact-txid-and-wire' and responses[8]['view']['review_revalidated'] is True
    assert len(responses[8]['child_invocations'])==3 and [x['command'] for x in responses[8]['child_invocations']]==['review','review','submit']
    assert reviews[0]==reviews[1]==reviews[2] and all(x['sha256']==reviews[2]['review_sha256'] for x in responses[8]['child_responses'][:2])
    assert reviews[2]['txid']==parent['payment_caller']['proxy_requests'][0]['txid'] and reviews[2]['wire_sha256']==parent['payment_caller']['proxy_requests'][0]['wire_sha256']
    assert [x['view']['state'] for x in responses[-4:]]==['unresolved-held','executed-exact','executed-exact','conflict-held']
    print('P8 console closed gate passed: 10 console +13 payment +22 wallet checks; 19 actual console calls; native replay separate')
    return r

if __name__=='__main__':check(Path(sys.argv[1]))
