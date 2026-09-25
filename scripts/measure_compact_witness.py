#!/usr/bin/env python3
"""Measure witness bytes over 1,024 locally executed signed transfers.

Single local application with disposable known keys, not consensus, throughput,
privacy certification, network cost, or a production scaling benchmark.
"""
import argparse
import hashlib
import json
from pathlib import Path
import sys
ROOT=Path(__file__).resolve().parents[1]
sys.path[:0]=[str(ROOT/'src'),str(ROOT/'tests')]
from block_application import BlockApplication
from native_core import NativeLedger,sign,canonical,public
from test_native_budgets import genesis,KEYS,IDS
from certificate_fixture import validators,make_header,make_commit
from compact_verifier import verify_compact_witness
from commit_verifier import encode,verify_state_witness


def main():
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--output',type=Path,required=True)
    args=p.parse_args();args.output.mkdir(parents=True,exist_ok=False)
    g={**genesis(),'state_commitment':'smt-v1'}
    app=BlockApplication(':memory:');app.init_chain(g['chain_id'],g)
    model=NativeLedger(':memory:',g)
    try:
        for start in range(0,1024,64):
            txs=[canonical(sign(KEYS[0],model.body(IDS[0],n,
                  {'type':'transfer','to':IDS[1],'units':1},valid_until=10000))) for n in range(start,start+64)]
            height=start//64+1;result=app.finalize_block(txs,height,hashlib.sha256(str(height).encode()).digest())
            if any(x['code'] for x in result['tx_results']):raise AssertionError('transfer rejected')
            app.commit()
        state=json.loads(app.query('/state')['value']);engine,trust,keys=validators(g)
        header=make_header(trust,app.height+1,app.app_hash);header['version']['app']='3'
        header['last_block_id']={'hash':'12'*32,'parts':{'total':1,'hash':'13'*32}}
        cert=make_commit(header,trust,keys)
        witness=app.compact_witness([('accounts',IDS[0])])
        compact=verify_compact_witness(witness,cert,trust,expected_queries=[('accounts',IDS[0])])
        full=verify_state_witness(state,cert,trust)
        assert full['state_app_hash']==compact['state_app_hash']
        assert len(state['native']['receipts'])==1024
        full_bytes=len(encode({'schema':1,'state':state,'state_commit':cert}))
        compact_bytes=len(encode({'schema':1,'state':witness,'state_commit':cert}))
        report={'scope':'serialized evidence over one local application; not validator/network benchmark',
            'signed_transfers_executed':1024,'blocks_committed_locally':16,
            'native_rows':sum(len(rows) for rows in state['native'].values()),
            'full_witness_bytes':full_bytes,'compact_witness_bytes':compact_bytes,
            'reduction_percent':round(100*(1-compact_bytes/full_bytes),4),
            'ratio_full_to_compact':round(full_bytes/compact_bytes,4),
            'proof_siblings':len(witness['entries'][0]['siblings']),
            'account_records_disclosed':1,'unrelated_receipts_disclosed':0,
            'both_verify_against_same_signed_root':True,'certificates_synthetic':True,
            'whole_state_node_storage_unchanged':True,'consensus_verified':False}
        (args.output/'result.json').write_text(json.dumps(report,indent=2)+'\n')
        (args.output/'compact-witness.json').write_text(json.dumps(witness,indent=2)+'\n')
        (args.output/'signed-header.json').write_text(json.dumps(cert,indent=2)+'\n')
        (args.output/'public-genesis.json').write_text(json.dumps(engine,indent=2)+'\n')
        print(json.dumps(report,indent=2));return 0
    finally:app.close();model.close()

if __name__=='__main__':raise SystemExit(main())
