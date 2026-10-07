#!/usr/bin/env python3
"""Closed payment receipt consistency gate; actual native replay is separate."""
import json,sys
from pathlib import Path
ROOT=Path(__file__).resolve().parents[2];sys.path[:0]=[str(ROOT/'src'),str(ROOT/'scripts'),str(ROOT/'tools/release')]
from protocol8_transfer import canonical,sha,parse,txid
from run_protocol8_payment import CHECKS,CLAIMS,EXPECTED_WALLET,EXPECTED_WALLET_REFUSALS,EXPECTED_PAYMENT,EXPECTED_PAYMENT_REFUSALS
from check_protocol8_wallet import check as wallet_check

def check(path):
    raw=path.read_bytes();r=json.loads(raw)
    assert raw==canonical(r)+b'\n' and r['format']=='1soft/protocol8-payment-gate/v1' and r['status']=='qualified-one-host-payment-caller'
    assert r['claims']==CLAIMS and r['source']['clean'] is True
    assert [x['id'] for x in r['checks']]==list(CHECKS) and all(x['passed'] is True for x in r['checks'])
    assert Path(r['wallet_report']).name==r['wallet_report']
    linked=path.parent/r['wallet_report'];inner_raw=linked.read_bytes();assert sha(inner_raw)==r['wallet_report_sha256']
    wallet_check(linked);inner=json.loads(inner_raw)
    assert inner['source']==r['source'] and inner['wallet_cli']==r['wallet_cli'] and inner['payment_caller']==r['payment_caller']
    wallet=r['wallet_cli'];payment=r['payment_caller'];assert not wallet['forced_cleanup'] and not payment['forced_cleanup']
    assert not payment.get('proxy_error_type') and payment['proxy_stopped'] is True
    assert all(wallet[k] is True for k in ('bad_pin_refused','duplicate_owner_refused','early_delivery_refused','output_overwrite_refused'))
    native_ids=set();process_ids=set()
    for kind,e,names,refusals,script in (('wallet',wallet,EXPECTED_WALLET,EXPECTED_WALLET_REFUSALS,'scripts/protocol8_wallet.py'),
        ('payment',payment,EXPECTED_PAYMENT,EXPECTED_PAYMENT_REFUSALS,'scripts/protocol8_payment.py')):
        calls=e['invocations'];responses=e['responses'];assert len(calls)==len(responses)==len(names)
        assert tuple(x['command'] for x in calls)==names
        assert {i for i,x in enumerate(calls,1) if x['exit_code']==1}==refusals
        log=r['logs'][kind];assert Path(log['name']).name==log['name']
        lograw=(path.parent/log['name']).read_bytes()
        assert len(lograw)==log['bytes'] and sha(lograw)==log['sha256'] and lograw==b''.join(canonical(x)+b'\n' for x in responses)
        runtime={p:v['sha256'] for p,v in r['source']['files'].items() if (p.startswith('src/') and p.count('/')==1 and p.endswith('.py')) or
            p in ('scripts/protocol8_wallet.py','scripts/protocol8_worker_exec.py','scripts/protocol8_private_exec.py') or (kind=='payment' and p==script)}
        expected_runtime=sha(canonical(dict(sorted(runtime.items()))))
        for call,x in zip(calls,responses):
            assert type(call['pid']) is int and call['pid']>0 and type(call['start_ticks']) is int and call['start_ticks']>0
            identity=(call['pid'],call['start_ticks']);assert identity not in process_ids;process_ids.add(identity)
            assert type(x['pid']) is int and type(x['start_ticks']) is int and identity==(x['pid'],x['start_ticks'])
            assert call['command']==x['command'] and call['process_reaped'] is True
            assert call['script_sha256']==r['source']['files'][script]['sha256']
            assert call['stdout_bytes']==len(canonical(x)+b'\n') and call['stdout_sha256']==sha(canonical(x)+b'\n')
            assert call['exit_code']==(1 if x['status']=='refused' else 0)
            assert x['runtime_sha256']==expected_runtime and x['automatic_retry'] is False and x['freshness_established'] is False and x['production_ready'] is False
            assert x['format']=='1soft/protocol8-'+('wallet-cli' if kind=='wallet' else 'payment-caller')+'/v1'
            if kind=='wallet':assert x['broadcast_calls']==0
            else:assert type(x['transport_attempts']) is int and x['transport_attempts'] in (0,1) and x['public_network'] is False
            if x['genesis_sha256']!=inner['genesis_sha256']:
                assert kind=='wallet' and x['command']=='init' and x['status']=='refused' and x['genesis_sha256']=='ef'*32 and not x['native_audits']
            if x['status']!='refused':assert x['wallet_id']==call['wallet_id']
            for native_kind,a in x['native_audits'].items():
                if native_kind=='worker':
                    from check_protocol8_native import batch_startup
                    batch_startup(a)
                assert native_kind in ('worker','helper','prover')
                assert a['call_count']==a['retained_count']==a['reaped_count']==len(a['calls'])<=512 and a['timeout_count']==0
                for item in a['calls']:
                    birth=item['start_ticks'];assert type(birth) is str and birth.isascii() and birth.isdecimal() and int(birth)>0 and birth==str(int(birth))
                    assert type(item['pid']) is int and item['pid']>0
                    identity=(item['pid'],birth);assert identity not in native_ids;native_ids.add(identity)
                    assert item['binary_sha256']==inner['inputs'][native_kind]['sha256'] and item['process_reaped'] is True and item['timed_out'] is False and item['exit_code'] in (0,2)
                    assert item['operation'] in {'worker':{'verify','identities','network-domain','note-root','startup'},'helper':{'key','inspect-note','construct'},'prover':{'prove'}}[native_kind]
                    if item['operation']=='startup':
                        from protocol8_transfer import PROFILE
                        assert native_kind=='worker' and item['input_bytes']==3592 and 0<item['output_bytes']<=256
                        assert item['startup_checks']=={'valid_proof_verified':True,'corrupt_proof_refused':True,
                            **{k:PROFILE[k] for k in ('parameter_sha256','verifying_key_sha256')}}
    assert len(wallet['initializations'])==4 and len(wallet['doctors'])==4 and len(wallet['preproof_holds'])==2
    for x in wallet['initializations']:
        assert x in wallet['responses'] and x['status']=='initialized' and x['encrypted_wallet_created'] is True
        assert x['native_startup']['valid_proof_verified'] is True and x['native_startup']['corrupt_proof_refused'] is True
        assert x['native_startup']['binary_sha256']==inner['inputs']['worker']['sha256']
    for x in wallet['doctors']:
        assert x['files_unchanged'] is True and x['native_executed'] is False and x['encrypted_store_authenticated'] is False and not x['native_audits']
        assert {k:v for k,v in x.items() if k!='files_unchanged'} in wallet['responses']
    prepared=[x for x in wallet['responses'] if x['status']=='original-wire-retained'];assert len(prepared)==2
    wires={}
    for name in ('fixture-wallet-spend.tx','fixture-held-competing.tx'):
        wire=(linked.with_name(linked.name+'.artifacts')/name).read_bytes();wires[txid(wire)]=wire
    assert {x['txid'] for x in prepared}==set(wires)
    for hold in wallet['preproof_holds']:
        x=next(x for x in prepared if x['pid']==hold['pid'] and x['start_ticks']==hold['start_ticks'])
        assert hold['wire_absent'] is True and hold['attempts']==0 and parse(wires[x['txid']])[6]==hold['request']
        assert type(hold['encrypted_file_sha256']) is str and len(hold['encrypted_file_sha256'])==64
    interruption=payment['interruption'];assert interruption['before_state']=='prepared-not-attempted' and interruption['after_state']=='attempt-record-incomplete'
    assert interruption['wallet_attempts_before']==0 and interruption['wallet_attempts_after']==1 and interruption['request_count']==0
    assert interruption['constructed_prepared_journal'] is True and interruption['actual_wallet_marker_command'] is True and interruption['process_kill_induced'] is False
    assert payment['responses'][0]['submission_state']==interruption['before_state'] and payment['responses'][1]['submission_state']==interruption['after_state']
    marks=[x for x in wallet['responses'] if x['status']=='attempt-marked'];assert len(marks)==1 and marks[0]['txid']==interruption['txid'] and marks[0]['attempts']==1
    assert sum(x['transport_attempts'] for x in payment['responses'])==1
    submits=[x for x in payment['responses'] if x['command']=='submit' and x['status']!='refused'];assert len(submits)==1
    sent=submits[0];ident=inner['recovery']['txid'];wire=wires[ident]
    assert sent['txid']==ident and sent['submission_state']=='attempted-outcome-unknown' and sent['transport']=={'outcome':'unknown','admission_code':None}
    assert sent['wallet_attempts']==1 and sent['wallet_completed'] is False and sent['execution_confirmed'] is False and sent['reconciliation_required'] is True
    fixtures=payment['fixture_broadcasts'];assert [x['fixture'] for x in fixtures]==['first.tx','executed-competing.tx']
    for fixture in fixtures:
        b=(linked.with_name(linked.name+'.artifacts')/('fixture-'+fixture['fixture'])).read_bytes()
        assert fixture['txid']==txid(b) and fixture['wire_sha256']==sha(b) and fixture['admission_code']==0
    assert len(payment['proxy_requests'])==1;proxy=payment['proxy_requests'][0]
    assert proxy['txid']==ident and proxy['wire_bytes']==3560 and proxy['wire_sha256']==sha(wire)==proxy['actual_node_wire_hash']
    assert proxy['actual_node_admission_code']==0 and proxy['reply_forwarded'] is False and proxy['wallet_attempts_before_io']==1 and proxy['journal_phase_before_io']=='attempt-marked'
    import base64
    request=canonical({'jsonrpc':'2.0','id':1,'method':'broadcast_tx_sync','params':{'tx':base64.b64encode(wire).decode()}})
    assert proxy['request_sha256']==sha(request) and proxy['request_bytes']==len(request)
    reconciled=[x for x in payment['responses'] if x['command']=='reconcile'];assert len(reconciled)==4
    assert [x['result']['status'] for x in reconciled]==['unresolved-held','executed-exact','executed-exact','conflict-held']
    assert reconciled[1]['result']==reconciled[2]['result']==inner['recovery'] and reconciled[3]['result']==inner['conflict_resolution']
    recovery=inner['recovery'];spent=inner['state_witness']
    receipt=next(x for x in spent['state']['ledger']['receipts'] if x['txid']==ident)
    assert recovery=={'status':'executed-exact','txid':ident,'raw_sha256':sha(wire),'receipt':receipt,
        'observation':1,'state_height':spent['height'],'app_hash':spent['app_hash'],
        'genesis_sha256':sha(canonical(inner['genesis'])),
        'claim':'AS-OF exact certified execution; no freshness or retry authority'}
    assert receipt['raw']==wire.hex() and receipt['statement']==parse(wire)
    unresolved=reconciled[0]['result']
    assert unresolved=={'status':'unresolved-held','txid':ident,'attempts':1,
        'as_of_height':inner['receive_witness']['height'],'automatic_retry':False,'freshness_established':False}
    held_id=interruption['txid'];held=wires[held_id];held_statement=parse(held);conflict=inner['conflict_witness']
    competitor=(linked.with_name(linked.name+'.artifacts')/'fixture-executed-competing.tx').read_bytes()
    assert held_id!=txid(competitor) and held_statement[5]==parse(competitor)[5]
    assert held_statement[5] in conflict['state']['ledger']['nullifiers'] or held_statement[6] in conflict['state']['ledger']['requests']
    assert inner['conflict_resolution']=={'status':'conflict-held','txid':held_id,'attempts':1,
        'as_of_height':conflict['height'],'automatic_retry':False,'freshness_established':False}
    journals=payment['journal_receipts'];assert len(journals)==2 and {x['txid'] for x in journals}==set(wires)
    runtime_sha=sent['runtime_sha256']
    for journal in journals:
        raw=canonical(journal['envelope']);assert len(raw)==journal['bytes'] and sha(raw)==journal['sha256']
        envelope=journal['envelope'];assert set(envelope)=={'record','hmac_sha256'}
        tag=envelope['hmac_sha256'];assert type(tag) is str and len(tag)==64 and bytes.fromhex(tag).hex()==tag
        record=envelope['record'];assert set(record)=={'format','journal_path','workspace','wallet_id','wallet_manifest_sha256',
            'genesis_sha256','runtime_sha256','endpoint','txid','wire_sha256','wire_bytes','phase','admission_code'}
        assert record['format']=='1soft/protocol8-payment-journal/v1' and record['txid']==journal['txid'] and record['wallet_id']==journal['wallet_id']
        assert record['genesis_sha256']==inner['genesis_sha256'] and record['runtime_sha256']==runtime_sha
        assert record['wire_sha256']==sha(wires[journal['txid']]) and type(record['wire_bytes']) is int and record['wire_bytes']==3560
        assert record['phase']==('unknown' if record['txid']==ident else 'prepared') and record['admission_code'] is None
        from protocol8_payment import endpoint_port
        endpoint_port(record['endpoint'])
        assert all(x['journal_sha256']==journal['sha256'] for x in payment['responses'] if x['status']!='refused' and x['txid']==journal['txid'])
    for x in payment['responses']:
        if x['status']!='refused':
            assert x['wallet_attempts'] in (0,1) and type(x['wallet_completed']) is bool
            assert x['execution_confirmed'] is (x['result'] is not None and x['result']['status']=='executed-exact')
        else:assert x['execution_confirmed'] is False and x['reconciliation_required'] is True
    print('P8 payment closed gate passed: 13 caller checks, 22 actual wallet checks, 53 wallet/15 payment calls; no native execution by this checker')
    return r

if __name__=='__main__':check(Path(sys.argv[1]))
