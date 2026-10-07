#!/usr/bin/env python3
"""Closed evidence gate. It inspects receipts; it does not rerun native proofs."""
import json,sys
from pathlib import Path
ROOT=Path(__file__).resolve().parents[2];sys.path.insert(0,str(ROOT/'scripts'));sys.path.insert(0,str(ROOT/'src'))
from run_protocol8_wallet import CHECKS,CLAIMS
from protocol8_transfer import canonical,sha,parse,txid
def check(path):
    raw=path.read_bytes();r=json.loads(raw)
    assert raw==canonical(r)+b'\n'
    assert r['format']=='1soft/protocol8-recipient-wallet-gate/v1' and r['status']=='qualified-one-host-recipient-wallet'
    assert r['claims']==CLAIMS and not r.get('error') and not r.get('cleanup_error')
    assert [x['id'] for x in r['checks']]==list(CHECKS) and all(x['passed'] is True for x in r['checks'])
    assert r['source']['clean'] is True and r['broadcast_calls']==1 and r['proof_count']==4
    assert r['recovery']['status']=='executed-exact' and r['conflict_resolution']['status']=='conflict-held'
    assert r['conflict_resolution']['automatic_retry'] is False
    assert len(r['wallet_inventory']['obligations'])==1 and r['wallet_inventory']['obligations'][0]['attempts']==1
    for a in r['worker_audits']+r['private_worker_audits']:
        if a in r['worker_audits']:
            from check_protocol8_native import batch_startup
            batch_startup(a)
        assert a['call_count']==a['reaped_count'] and a['timeout_count']==0
        assert len(a['calls'])==a['retained_count'] and a['retained_count']<=a['retention_limit']
        assert all(x['process_reaped'] and x['start_ticks'] is not None and x['exit_code'] in (0,2) and not x['timed_out'] for x in a['calls'])
    assert all(x['process_reaped'] and x['start_ticks'] is not None and x['exit_code']==0 for x in r['native_processes'])
    assert all(type(x['exit_code']) is int for x in r['processes'])
    artifacts=path.with_name(path.name+'.artifacts');names={x['name'] for x in r['artifacts']}
    assert names=={f'engine{i}.log' for i in range(4)}|{f'app{i}.log' for i in range(4)}|{
        'fixture-first.tx','fixture-wallet-spend.tx','fixture-held-competing.tx','fixture-executed-competing.tx','fixture-genesis.json'}
    assert {p.name for p in artifacts.iterdir()}==names
    for x in r['artifacts']:
        p=artifacts/x['name'];b=p.read_bytes();assert p.is_file() and not p.is_symlink() and len(b)==x['bytes'] and sha(b)==x['sha256']
    for witness in (r['receive_witness'],r['state_witness'],r['conflict_witness']):
        for receipt in witness['state']['ledger']['receipts']:
            b=bytes.fromhex(receipt['raw']);assert parse(b)==receipt['statement'] and txid(b)==receipt['txid']
    assert len(r['receive_witness']['state']['ledger']['receipts'])==1
    assert len(r['state_witness']['state']['ledger']['receipts'])==2
    assert len(r['conflict_witness']['state']['ledger']['receipts'])==3
    print('P8 wallet closed report/artifact gate passed: 22 checks, four native proofs, one broadcast, AS-OF only')
if __name__=='__main__':check(Path(sys.argv[1]))
