#!/usr/bin/env python3
"""Compare unchanged CheckTx results with/without validated execution images.

Runs signed transfers locally, then measures repeated noncommitting admission
checks on the SAME persisted state. No network, votes, TPS or gas claim. The
reference path retains the v0.14 reconstruction/history-verification behavior.
"""
import argparse
import hashlib
import json
from pathlib import Path
import platform
import sqlite3
import statistics
import sys
import time
from unittest.mock import patch

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/'src'))
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from native_core import NativeLedger, address, public, canonical, sign
from block_application import BlockApplication


def measure(folder: Path, transfers: int, repeats: int) -> dict:
    folder=folder.resolve();folder.mkdir(parents=True,exist_ok=False)
    owner,merchant=[Ed25519PrivateKey.from_private_bytes(bytes([n])*32) for n in (91,92)]
    g={'protocol_version':3,'state_commitment':'smt-v1','chain_id':'1soft-execution-measurement',
       'asset':'DEV','fee':2,'allocations':[{'public_key':public(owner),'units':10_000_000},
                                          {'public_key':public(merchant),'units':0}]}
    maker=NativeLedger(':memory:',g)
    def signed(n):
        return canonical(sign(owner,maker.body(address(public(owner)),n,
                {'type':'transfer','to':address(public(merchant)),'units':1},valid_until=100000)))
    path=folder/'measured.sqlite'
    app=BlockApplication(path,expected_genesis=g)
    blocks=[]
    try:
        app.init_chain(g['chain_id'],g)
        for start in range(0,transfers,64):
            txs=[signed(n) for n in range(start,min(transfers,start+64))]
            h=app.height+1
            result=app.finalize_block(txs,h,hashlib.sha256(str(h).encode()).digest())
            if not all(row['code']==0 for row in result['tx_results']):raise AssertionError('setup execution failed')
            app.commit();blocks.append({'height':h,'transfers':len(txs),'app_hash':app.app_hash})
        expected=app.query('/state')['value'];height=app.height;state_hash=app.app_hash
    finally:app.close()
    # SQLite backup here just makes an identical test database; it does not seed
    # trusted execution. Each node below performs its normal full startup audit.
    reference_path=folder/'reference.sqlite'
    source=sqlite3.connect(path);target=sqlite3.connect(reference_path)
    source.backup(target);target.close();source.close()
    fast=BlockApplication(path,expected_genesis=g,execution_cache=True,admission_cache=False)
    reference=BlockApplication(reference_path,expected_genesis=g,execution_cache=False,admission_cache=False)
    valid=signed(transfers);altered=json.loads(valid);altered['signature']='0'*128;invalid=canonical(altered)
    maker.close()
    evidence=[]
    try:
        for label,tx in (('valid_new_payment',valid),('invalid_signature',invalid)):
            samples={'cached':[],'reference':[]}
            answers={mode:node.check_tx(tx) for mode,node in (('cached',fast),('reference',reference))}
            if answers['cached']!=answers['reference']:raise AssertionError('CheckTx differs')
            if answers['cached']['code'] != (0 if label=='valid_new_payment' else 1):raise AssertionError('unexpected acceptance')
            for i in range(repeats):
                for mode,node in ((('cached',fast),('reference',reference)) if i%2 else
                                  (('reference',reference),('cached',fast))):
                    before=time.perf_counter_ns();result=node.check_tx(tx);elapsed=time.perf_counter_ns()-before
                    if result!=answers['reference']:raise AssertionError('unstable response')
                    samples[mode].append(elapsed)
            counts={}
            original=NativeLedger.verify_receipts
            for mode,node in (('cached',fast),('reference',reference)):
                calls=[]
                def observed(ledger):
                    calls.append(ledger.db.execute('SELECT count(*) FROM receipts').fetchone()[0])
                    return original(ledger)
                with patch.object(NativeLedger,'verify_receipts',observed):node.check_tx(tx)
                counts[mode]={'history_scan_calls':len(calls),'old_receipts_in_scans':sum(calls)}
            evidence.append({'case':label,'response':answers['cached'],'nanoseconds':samples,
                'median_nanoseconds':{k:int(statistics.median(v)) for k,v in samples.items()},
                'ratio_in_this_run':statistics.median(samples['reference'])/statistics.median(samples['cached']),
                'history_validation_counts':counts})
        for node in (fast,reference):
            if node.query('/state')['value']!=expected or node.height!=height or node.app_hash!=state_hash:
                raise AssertionError('checks changed committed state')
        report={'schema':1,'scope':'local noncommitting transaction checks; not consensus or throughput',
            'setup_signed_transfers':transfers,'setup_blocks':len(blocks),'checkpoint_height':height,
            'checkpoint_app_hash':state_hash,'same_checktx_responses':True,'committed_state_unchanged':True,
            'repeats_per_path_per_case':repeats,'sqlite_execution_image_bytes':fast._execution.storage_bytes(),
            'measurements':evidence,'network_requests':0,'validator_processes':0,
            'python':platform.python_version(),'sqlite':sqlite3.sqlite_version,'platform':platform.platform(),
            'remaining_costs':['database-page copy per trial','full-state scans for native invariants and hashes',
                'full-state snapshots and reference root finalization','full startup receipt validation',
                'additional process-local memory for committed and staged images']}
        (folder/'result.json').write_text(json.dumps(report,indent=2)+'\n')
        (folder/'setup-blocks.json').write_text(json.dumps(blocks,indent=2)+'\n')
        print(json.dumps(report,indent=2))
        return report
    finally:fast.close();reference.close()


def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--output',type=Path,required=True);p.add_argument('--transfers',type=int,default=1024)
    p.add_argument('--repeats',type=int,default=12)
    a=p.parse_args()
    if not 1<=a.transfers<=4096 or not 1<=a.repeats<=100:p.error('bounded positive transfers/repeats required')
    measure(a.output,a.transfers,a.repeats)
if __name__=='__main__':main()
