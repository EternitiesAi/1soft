#!/usr/bin/env python3
"""Closed public alpha receipts and optional independent native signed-state replay."""
import argparse,json,sys
from pathlib import Path
ROOT=Path(__file__).resolve().parents[2]
sys.path[:0]=[str(ROOT/'src'),str(ROOT/'tools/release')]
import protocol8_transfer as n
from protocol8_worker import Worker
from protocol8_consensus import genesis_document
from protocol8_certificate import verify_state
from check_protocol8_native import batch_startup

CLAIMS={'one_trusted_host':True,'synthetic_funds':True,'actual_browser_required':True,
 'automatic_retry':False,'freshness_established':False,'production_ready':False,
 'public_network':False,'independent_operators':False,'production_custody':False}
CHECKS=('fresh_native_four_validators','actual_browser_two_wallet_flow','two_lost_reply_one_attempts',
 'two_signed_exact_recoveries','recipient_received_funds_used','duplicate_submit_refused_without_io',
 'native_children_reaped','owned_servers_nodes_stopped','known_private_material_absent','source_unchanged')

def check(path,worker=None):
    raw=path.read_bytes();assert 0<len(raw)<=8*1024**2
    r=json.loads(raw);assert raw==n.canonical(r)+b'\n'
    assert set(r)=={'format','status','source','inputs','native_processes','browser_actions','signed_packets','claims','checks',
        'wallet_cli','genesis','genesis_sha256','wallet_cli_inputs','wallet_servers','proxies','worker_audits','helper_audits',
        'artifacts','processes','cleanup_errors','source_unchanged','browser'}
    assert r['format']=='1soft/protocol8-browser-alpha/v1' and r['status']=='qualified-one-host-synthetic-browser-alpha'
    assert r['claims']==CLAIMS and all(type(v) is bool for v in r['claims'].values())
    assert r['source']['clean'] is True and r['source_unchanged'] is True and r['cleanup_errors']==[]
    assert [c['id'] for c in r['checks']]==list(CHECKS) and all(c['passed'] is True for c in r['checks'])
    for name,meta in r['source']['files'].items():
        assert not Path(name).is_absolute() and '..' not in Path(name).parts
        data=(ROOT/name).read_bytes();assert len(data)==meta['bytes'] and n.sha(data)==meta['sha256']
    browser=r['browser'];assert browser['status']=='passed-actual-browser-flow'
    assert browser['driver_sha256']==r['source']['files']['tools/p8-wallet/tests/browser_native.test.cjs']['sha256']
    assert set(browser['transport_readiness'])=={'bob','carol'}
    for value in browser['transport_readiness'].values():
        assert value['read_only_gets'] is True and value['page_html_or_token_retained'] is False
        assert value['attempts'] and len(value['attempts'])<=121
        assert value['attempts'][-1]['http_status']==200 and value['attempts'][-1]['wallet_page'] is True
    for k in ('actual_receive_prepare_review_send_recovery_delivery','recipient_received_funds_used','two_explicit_one_attempt_sends',
        'two_replay_refusals','private_display_checked_in_memory','browser_storage_empty','private_display_cleared','mobile_no_page_overflow'):
        assert browser[k] is True
    assert browser['private_display_retained'] is False and browser['page_errors']==browser['external_requests']==[]
    roles=('bob','carol');txids=browser['txids'];assert len(txids)==len(set(txids))==2
    assert set(r['wallet_servers'])==set(roles) and len({x['origin'] for x in r['wallet_servers'].values()})==2
    for s in r['wallet_servers'].values():assert s['origin'].startswith('http://127.0.0.1:') and s['loopback_only'] is True and s['session_token_retained'] is False
    proxies=r['proxies'];assert len(proxies)==2 and {p['role'] for p in proxies}==set(roles)
    actions=r['browser_actions'];assert actions and all('private_display' not in a and a['private_display_retained'] is False for a in actions)
    for role,ident in zip(roles,txids):
        proxy=next(p for p in proxies if p['role']==role)
        assert proxy['stopped'] is True and proxy['error_type'] is None and len(proxy['requests'])==1
        q=proxy['requests'][0];assert q['txid']==ident and q['forward_count']==q['wallet_attempts_before_io']==1
        assert type(q['forward_count']) is int and type(q['wallet_attempts_before_io']) is int and type(q['node_admission_code']) is int
        assert q['journal_phase_before_io']=='attempt-marked' and q['reply_forwarded'] is False and q['node_admission_code']==0
        rows=[a for a in actions if a['role']==role]
        expected=('observe','import-note','guide','prepare','review','submit','status','reconcile','submit','export','deliver','guide')
        assert tuple(a['command'] for a in rows)==expected
        assert [a['status'] for a in rows]==['console-completed']*8+['refused']+['console-completed']*3
        for a in (rows[4],rows[5],rows[6],rows[7],rows[9],rows[10]):assert a['console_receipt']['view']['txid']==ident
        assert rows[5]['console_receipt']['view']['state']==rows[6]['console_receipt']['view']['state']=='attempted-outcome-unknown'
        assert rows[7]['console_receipt']['view']['state']=='executed-exact'
        assert all(rows[i]['console_receipt']['view']['attempts']==1 for i in (5,6,7))
        assert rows[8]['wallet_sha256_before']==rows[8]['wallet_sha256_after']
        prepare=rows[3]['console_receipt']['child_responses'][0]
        view=rows[3]['console_receipt']['view']
        assert prepare['status']=='original-wire-retained' and view['state']=='prepared-not-attempted'
        assert view['prepared_not_sent'] is True and view['can_submit'] is False and view['payment_child_started'] is False
        assert prepare['txid']==ident and prepare['native_audits']['prover']['call_count']==1
    packets=r['signed_packets'];assert [p['phase'] for p in packets]==['receive','bob-executed','carol-executed']
    assert [len(p['witness']['state']['ledger']['receipts']) for p in packets]==[1,2,3]
    assert [p['witness']['state']['ledger']['receipts'][-1]['txid'] for p in packets[1:]]==txids
    assert n.sha(n.canonical(r['genesis']))==r['genesis_sha256']
    artifacts=path.with_name(path.name+'.artifacts');names={p.name for p in artifacts.iterdir()}
    expected={f'{kind}{i}.log' for kind in ('app','engine') for i in range(4)}|{
      'fixture-first.tx','fixture-genesis.json','fixture-bob-spend.tx','fixture-carol-spend.tx',
      'fixture-receive-signed.json','fixture-bob-executed-signed.json','fixture-carol-executed-signed.json'}
    assert names==expected=={a['name'] for a in r['artifacts']}
    for a in r['artifacts']:
        data=(artifacts/a['name']).read_bytes();assert len(data)==a['bytes'] and n.sha(data)==a['sha256']
    for role,ident in zip(roles,txids):
        wire=(artifacts/('fixture-'+role+'-spend.tx')).read_bytes();q=next(p for p in proxies if p['role']==role)['requests'][0]
        assert n.txid(wire)==ident and n.sha(wire)==q['wire_sha256']==q['node_wire_hash'] and len(wire)==q['wire_bytes']==3560
    public_wire_hex=b''.join(bytes.fromhex(x['raw']).hex().encode() for p in packets for x in p['witness']['state']['ledger']['receipts'])
    known=[i.to_bytes(32,'little').hex().encode() for i in (31,32,33,34,35,41,42,43,51)]
    needles=[s for s in known if s not in public_wire_hex and s not in n.canonical(r['genesis'])]
    material=raw+b''.join((artifacts/a['name']).read_bytes() for a in r['artifacts'])
    assert all(s not in material for s in needles)
    # Native receipts are nested/mirrored. Validate semantics in every enclosing
    # audit; deduplicate only process identity when measuring unique work.
    native_ids={};process_ids=set();audits=[]
    def visit(value):
        if type(value) is dict:
            if 'native_audits' in value:
                for kind,a in value['native_audits'].items():
                    if kind=='worker':batch_startup(a)
                    audits.append((kind,a))
            for v in value.values():visit(v)
        elif type(value) is list:
            for v in value:visit(v)
    visit(actions);visit(r['wallet_cli']['responses'])
    for a in r['worker_audits']:batch_startup(a);audits.append(('worker',a))
    audits.extend(('helper',a) for a in r['helper_audits'])
    for kind,a in audits:
        assert a['call_count']==a['reaped_count']==a['retained_count']==len(a['calls'])<=512 and a['timeout_count']==0
        for c in a['calls']:
            assert c['binary_sha256']==r['inputs'][kind]['sha256'] and c['process_reaped'] is True and c['timed_out'] is False and c['exit_code'] in (0,2)
            key=(c['pid'],str(c['start_ticks']));assert str(c['start_ticks']).isdecimal()
            if key in native_ids:assert native_ids[key]==c
            native_ids[key]=c
    for a in actions:
        p=a['process'];key=(p['pid'],p['start_ticks']);assert key not in process_ids;process_ids.add(key)
        receipt=a['console_receipt'];assert key==(receipt['pid'],receipt['start_ticks'])
        assert receipt['command']==a['command'] and receipt['status']==a['status']
        assert type(p['pid']) is int and p['pid']>0 and type(p['start_ticks']) is int and p['start_ticks']>0
        assert p['process_reaped'] is True and p['exit_code']==(1 if a['status']=='refused' else 0)
        assert receipt['private_review_values_retained'] is False and receipt['forced_cleanup']==[]
        assert all(receipt[k] is False for k in ('automatic_retry','freshness_established','production_ready'))
        children=receipt['child_responses'];calls=receipt['child_invocations'];assert len(children)==len(calls)
        for call,reply in zip(calls,children):
            assert (call['pid'],call['start_ticks'])==(reply['pid'],reply['start_ticks'])
            assert call['command']==reply['command'] and call['process_reaped'] is True and call['diagnostic_present'] is False
            assert call['stdout_bytes']==len(n.canonical(reply)+b'\n') and call['stdout_sha256']==n.sha(n.canonical(reply)+b'\n')
            assert all(reply[k] is False for k in ('automatic_retry','freshness_established','production_ready'))
    assert all(type(p['exit_code']) is int for p in r['processes'])
    replay=None
    if worker is not None:
        assert n.sha(worker.read_bytes())==r['genesis']['worker_sha256']==r['inputs']['worker']['sha256']
        kat=(artifacts/'fixture-first.tx').read_bytes();w=Worker(worker,r['genesis']['worker_sha256'],kat)
        rawgen=n.canonical(r['genesis']);assert genesis_document(rawgen,w)==r['genesis']
        for p in packets:verify_state(p['witness'],p['signed_header'],rawgen,w)
        a=w.audit();batch_startup(a)
        assert a['call_count']==a['retained_count']==a['reaped_count']==len(a['calls']) and a['timeout_count']==0
        replay={'distinct_public_proofs':3,'signed_as_of_states':3,'audit':a,'independent_native_replay':True,'latest_network_freshness':False}
    # Structural receipt validation is explicitly weaker than native replay.
    # Only the required replay mode may emit a qualified release result.
    return {'status':'passed-closed-alpha-native-replay' if replay else 'passed-alpha-receipt-structure-only','actual_browser_payments':2,'one_request_proxies':2,
      'unique_native_processes':len(native_ids),'console_processes':len(process_ids),'independent_replay':replay,
      'recognized_fixture_secret_scan':{'patterns_tested':len(needles),'public_small_field_exclusions':len(known)-len(needles),
          'unknown_random_private_keys_available':False,'universal_secret_detection':False},
      'private_review_values_retained':False,'scope':'One trusted host, synthetic disposable browser wallet flow; no production/public-launch certification'}

if __name__=='__main__':
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('report',type=Path);p.add_argument('--worker',type=Path,required=True);p.add_argument('--output',type=Path);a=p.parse_args()
    value=check(a.report,a.worker);raw=n.canonical(value)+b'\n'
    if a.output:assert not a.output.exists();a.output.write_bytes(raw)
    print(n.canonical({k:v for k,v in value.items() if k!='independent_replay'}).decode())
