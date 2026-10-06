#!/usr/bin/env python3
"""Strict source-bound receipt checks; independent native replay is separate."""
import json,sys
from pathlib import Path
ROOT=Path(__file__).resolve().parents[2];sys.path.insert(0,str(ROOT/'scripts'));sys.path.insert(0,str(ROOT/'src'))
from run_protocol8_recovery import CHECKS,CLAIMS
from protocol8_consensus import canonical,digest
from protocol8_transfer import parse,txid
from protocol8_state_sync import payload_hash,FORMAT

def check(path):
    raw=path.read_bytes();r=json.loads(raw)
    assert raw==canonical(r)+b'\n' and r['format']=='1soft/protocol8-recipient-recovery-gate/v1'
    assert r['status']=='qualified-one-host-recipient-recovery' and r['claims']==CLAIMS
    assert not r.get('error') and not r.get('cleanup_error') and r['source']['clean'] is True
    assert [x['id'] for x in r['checks']]==list(CHECKS) and all(x['passed'] is True for x in r['checks'])
    checks={x['id']:x['evidence'] for x in r['checks']};s=r['snapshot'];h=s['height']
    assert s['format']==FORMAT and s['payload']['height']==h and s['payload_sha256']==payload_hash(canonical(s['payload'])).hex()
    assert s['metadata']['app_hash']==s['payload']['app_hash'] and s['payload']['genesis']==r['genesis']
    assert digest(canonical(r['genesis']))==r['genesis_sha256']
    assert checks['origin_no_invented_responses']['local_response_rows']==0
    expected_marker=[h,s['payload']['app_hash'],s['payload_sha256']]
    assert checks['origin_no_invented_responses']['origin_marker']==expected_marker
    assert checks['origin_real_suffix_audited']['origin_marker']==expected_marker
    assert checks['origin_real_suffix_audited']['origin_height']==h
    suffix=checks['origin_real_suffix_audited'];assert suffix['real_local_response_heights']==list(range(h+1,suffix['checkpoint_height']+1))
    offers=[e for e in r['state_sync_events'] if e['kind']=='offer_snapshot' and e['result']==1]
    assert len(offers)>=2 and len({(e['pid'],e['start_ticks']) for e in offers})==2
    assert all(e['height']==h and e['app_hash']==s['payload']['app_hash'] and e['payload_sha256']==s['payload_sha256'] and e['chunks']==s['chunks'] for e in offers)
    for offer in offers:
        identity=(offer['pid'],offer['start_ticks']);rows=[e for e in r['state_sync_events'] if (e['pid'],e['start_ticks'])==identity]
        assert all(type(x) is int and x>0 for x in identity)
        offer_index=rows.index(offer)
        commits=[i for i,e in enumerate(rows) if e['kind']=='after_snapshot_commit' and e['height']==h and e['app_hash']==s['payload']['app_hash']]
        assert len(commits)==1 and commits[0]>offer_index
        if offer['pid']!=checks['actual_snapshot_commit_crash']['pid']:
            assert any(i>commits[0] and e['kind']=='apply_snapshot_chunk' and e['index']==s['chunks']-1 and e['height']==h and e['result']==1 for i,e in enumerate(rows))
    assert any(e['kind']=='apply_snapshot_chunk' and e['index']==s['chunks']-1 and e['height']==h and e['result']==1 and e['pid']!=checks['actual_snapshot_commit_crash']['pid'] for e in r['state_sync_events'])
    assert checks['actual_snapshot_commit_crash']['exit_code']==96
    assert r['light_client']['trust_height']==h-1 and r['light_client']['rpc_sources']==[1,2] and r['light_client']['snapshot_peer']==0
    assert [int(e['header']['height']) for e in r['light_client']['provider_headers']]==[h+1,h+2]
    assert r['snapshot_certificate']['state_height']==h and r['snapshot_certificate']['app_hash']==s['payload']['app_hash']
    assert r['proof_count']==2 and r['broadcast_calls']==1
    assert len(s['payload']['state']['ledger']['receipts'])==1 and len(r['post_state']['state']['ledger']['receipts'])==2
    assert r['post_state']['state']['blocks'][:h]==s['payload']['state']['blocks']
    assert r['post_state']['state']['ledger']['receipts'][-1]['txid']==r['post_txid']
    assert len(r['wallet_inventory']['obligations'])==1 and r['wallet_inventory']['obligations'][0]['attempts']==1
    for witness in (s['payload'],r['post_state']):
        for receipt in witness['state']['ledger']['receipts']:
            b=bytes.fromhex(receipt['raw']);assert parse(b)==receipt['statement'] and txid(b)==receipt['txid']
    for a in r['worker_audits']+r['private_audits']:
        assert a['call_count']==a['reaped_count'] and a['timeout_count']==0
        assert len(a['calls'])==a['retained_count'] and a['retained_count']<=a['retention_limit']
        assert all(x['process_reaped'] and x['start_ticks'] is not None and x['exit_code'] in (0,2) and not x['timed_out'] for x in a['calls'])
    assert all(x['process_reaped'] and x['start_ticks'] is not None and x['exit_code']==0 for x in r['native_processes'])
    assert all(type(x['exit_code']) is int for x in r['processes'])
    crash=[x for x in r['processes'] if x['pid']==checks['actual_snapshot_commit_crash']['pid']]
    assert len(crash)==1 and crash[0]['role']=='application' and crash[0]['node']==4 and crash[0]['exit_code']==96
    artifacts=path.with_name(path.name+'.artifacts');names={x['name'] for x in r['artifacts']}
    assert names=={f'engine{i}.log' for i in range(5)}|{f'app{i}.log' for i in range(5)}|{
        'state-sync-events.log','fixture-first.tx','fixture-post-sync-spend.tx','fixture-genesis.json'}
    assert {p.name for p in artifacts.iterdir()}==names
    for a in r['artifacts']:
        p=artifacts/a['name'];b=p.read_bytes();assert p.is_file() and not p.is_symlink() and len(b)==a['bytes'] and digest(b)==a['sha256']
    assert json.loads((artifacts/'fixture-genesis.json').read_bytes())==r['genesis']
    assert txid((artifacts/'fixture-post-sync-spend.tx').read_bytes())==r['post_txid']
    assert [json.loads(line) for line in (artifacts/'state-sync-events.log').read_bytes().splitlines()]==r['state_sync_events']
    engine_log=(artifacts/'engine4.log').read_text()
    assert 'Verified ABCI app' in engine_log and 'Snapshot restored' in engine_log
    assert ('height='+str(h)) in engine_log and ('appHash='+s['payload']['app_hash'].upper()) in engine_log
    print('P8 recovery closed receipt/artifact gate passed: 22 checks, actual state sync/reoffer, two proofs, AS-OF only')
    return r
if __name__=='__main__':check(Path(sys.argv[1]))
