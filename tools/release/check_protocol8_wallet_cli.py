#!/usr/bin/env python3
"""Closed actual-wallet caller receipt gate. Native replay is a separate check."""
import json,sys
from pathlib import Path
ROOT=Path(__file__).resolve().parents[2];sys.path[:0]=[str(ROOT/'scripts'),str(ROOT/'src'),str(ROOT/'tools/release')]
from run_protocol8_wallet_cli import CHECKS,EXPECTED_COMMANDS,EXPECTED_REFUSALS
from protocol8_transfer import canonical,sha,parse,txid,PROFILE_SHA256,PROFILE
from check_protocol8_wallet import check as wallet_check
from check_protocol8_native import batch_startup

CLAIMS={'actual_wallet_cli':True,'one_trusted_host':True,'synthetic_funds':True,'broadcast_by_cli':False,
    'automatic_retry':False,'freshness_established':False,'production_ready':False,'public_network':False,
    'production_key_management':False,'local_rollback_resistance':False}

def check(path):
    raw=path.read_bytes();r=json.loads(raw)
    assert raw==canonical(r)+b'\n' and r['format']=='1soft/protocol8-wallet-cli-gate/v1' and r['status']=='qualified-one-host-wallet-cli'
    assert r['claims']==CLAIMS and r['source']['clean'] is True
    assert [c['id'] for c in r['checks']]==list(CHECKS) and all(c['passed'] is True for c in r['checks'])
    assert Path(r['wallet_report']).name==r['wallet_report'] and Path(r['cli_log']).name==r['cli_log']
    linked=path.parent/r['wallet_report'];inner_bytes=linked.read_bytes();assert sha(inner_bytes)==r['wallet_report_sha256']
    wallet_check(linked);inner=json.loads(inner_bytes);assert inner['source']==r['source'] and inner['wallet_cli']==r['wallet_cli']
    e=r['wallet_cli'];assert not e['forced_cleanup']
    assert all(e[k] is True for k in ('bad_pin_refused','duplicate_owner_refused','early_delivery_refused','output_overwrite_refused'))
    calls=e['invocations'];responses=e['responses'];assert len(calls)==len(responses)==len(EXPECTED_COMMANDS)==57
    assert tuple(x['command'] for x in calls)==EXPECTED_COMMANDS
    assert {i for i,x in enumerate(calls,1) if x['exit_code']==1}==EXPECTED_REFUSALS
    raw_log=(path.parent/r['cli_log']).read_bytes()
    assert len(raw_log)==r['cli_log_bytes'] and sha(raw_log)==r['cli_log_sha256']
    assert raw_log==b''.join(canonical(x)+b'\n' for x in responses)
    script_sha=r['source']['files']['scripts/protocol8_wallet.py']['sha256']
    runtime={p:v['sha256'] for p,v in r['source']['files'].items() if
        (p.startswith('src/') and p.count('/')==1 and p.endswith('.py')) or
        p in ('scripts/protocol8_wallet.py','scripts/protocol8_worker_exec.py','scripts/protocol8_private_exec.py')}
    runtime_sha=sha(canonical(dict(sorted(runtime.items()))))
    identities=set();native_ids=set();prepare=[];marks=[];bad=[]
    for call,x in zip(calls,responses):
        assert type(call['pid']) is int and call['pid']>0
        assert type(call['start_ticks']) is int and call['start_ticks']>0
        assert type(x['pid']) is int and type(x['start_ticks']) is int
        ident=(call['pid'],call['start_ticks']);assert ident not in identities;identities.add(ident)
        assert call['process_reaped'] is True and call['script_sha256']==script_sha
        assert call['pid']==x['pid'] and call['start_ticks']==x['start_ticks'] and call['command']==x['command']
        assert call['stdout_sha256']==sha(canonical(x)+b'\n') and call['stdout_bytes']==len(canonical(x)+b'\n')
        assert call['exit_code']==(1 if x['status']=='refused' else 0)
        assert x['format']=='1soft/protocol8-wallet-cli/v1' and x['runtime_sha256']==runtime_sha
        assert x['broadcast_calls']==0 and x['automatic_retry'] is False and x['freshness_established'] is False and x['production_ready'] is False
        if x['status']!='refused':assert call['wallet_id']==x['wallet_id']
        if x['genesis_sha256']!=inner['genesis_sha256']:
            assert x['command']=='init' and x['status']=='refused' and x['genesis_sha256']=='ef'*32 and not x['native_audits'];bad.append(x)
        for kind,a in x['native_audits'].items():
            if kind=='worker':batch_startup(a)
            assert kind in ('worker','helper','prover') and a['call_count']==a['reaped_count']==a['retained_count']==len(a['calls'])<=512 and a['timeout_count']==0
            for n in a['calls']:
                assert type(n['pid']) is int and n['pid']>0
                birth=n['start_ticks']
                assert type(birth) is str and birth.isascii() and birth.isdecimal() and int(birth)>0 and birth==str(int(birth))
                pid=(n['pid'],str(n['start_ticks']));assert pid not in native_ids;native_ids.add(pid)
                assert n['binary_sha256']==inner['inputs'][kind]['sha256'] and n['process_reaped'] is True and not n['timed_out'] and n['exit_code'] in (0,2)
                assert n['operation'] in {'worker':{'verify','identities','network-domain','note-root','startup'},'helper':{'key','inspect-note','construct'},'prover':{'prove'}}[kind]
                if n['operation']=='startup':
                    assert kind=='worker' and n['input_bytes']==3592 and 0<n['output_bytes']<=256
                    assert n['startup_checks']=={'valid_proof_verified':True,'corrupt_proof_refused':True,
                        **{k:PROFILE[k] for k in ('parameter_sha256','verifying_key_sha256')}}
        if x['command']=='doctor':assert not x['native_audits']
        if x['status']=='original-wire-retained':prepare.append(x);assert x['native_audits']['prover']['call_count']==1
        if x['status']=='attempt-marked':marks.append(x);assert x['attempts']==1
    assert len(bad)==1 and len(prepare)==2 and len(marks)==1
    assert {x['command'] for x in calls}=={'init','doctor','inventory','observe','import-note','prepare','mark-attempt','reconcile','export','deliver'}
    assert len(e['initializations'])==4 and len({x['wallet_id'] for x in e['initializations']})==4
    for x in e['initializations']:
        assert x in responses and x['status']=='initialized' and x['encrypted_wallet_created'] is True
        batch_startup(x['native_audits']['worker'])
        startup=x['native_startup'];assert all(startup[k] is True for k in ('valid_proof_verified','corrupt_proof_refused','verifier_only'))
        assert startup['binary_sha256']==inner['inputs']['worker']['sha256'] and startup['kat_sha256']==inner['genesis']['kat_sha256']
        assert startup['profile_sha256']==PROFILE_SHA256 and all(startup[k]==PROFILE[k] for k in ('parameter_sha256','verifying_key_sha256'))
    assert len(e['doctors'])==4
    for x in e['doctors']:
        assert x['files_unchanged'] is True and x['native_executed'] is False and x['encrypted_store_authenticated'] is False
        assert {k:v for k,v in x.items() if k!='files_unchanged'} in responses
    assert len(e['preproof_holds'])==2
    wires={}
    for name in ('fixture-wallet-spend.tx','fixture-held-competing.tx'):
        wire=(linked.with_name(linked.name+'.artifacts')/name).read_bytes();wires[txid(wire)]=parse(wire)
    assert {x['txid'] for x in prepare}==set(wires)
    for hold in e['preproof_holds']:
        x=next(x for x in prepare if x['pid']==hold['pid'] and x['start_ticks']==hold['start_ticks'])
        assert hold['wire_absent'] is True and hold['attempts']==0 and len(hold['encrypted_file_sha256'])==64
        assert wires[x['txid']][6]==hold['request']
    bob=inner['wallet_inventory']['wallet_id'];ident=inner['recovery']['txid']
    assert marks[0]['wallet_id']==bob and marks[0]['txid']==ident
    assert any(x.get('result')==inner['recovery'] and x['wallet_id']==bob for x in responses)
    assert any(x.get('result')==inner['conflict_resolution'] and x['status']=='original-reconciled' for x in responses)
    assert any(x.get('inventory')==inner['wallet_inventory'] and x['wallet_id']==bob for x in responses)
    print('P8 wallet CLI closed gate passed: 13 caller checks and 22 actual wallet checks; no native execution by this checker')
    return r

if __name__=='__main__':check(Path(sys.argv[1]))
