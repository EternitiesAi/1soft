#!/usr/bin/env python3
"""Compare bounded and retain-all local block metadata on identical native work.

Disposable application databases only: no engine, RPC, peers, keys on disk or
funds. Logical result-payload sizes are NOT total database or node-disk sizes.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import sys
import tempfile

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT/'src'))
from block_application import BlockApplication, encode
from block_history import validate_keep
from native_core import NativeLedger, address, canonical, public, sign
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey


def measure(blocks=512, keep=16):
    validate_keep(keep)
    if type(blocks) is not int or not keep < blocks <= 10000:
        raise ValueError('require keep < blocks <= 10000')
    key=Ed25519PrivateKey.from_private_bytes(bytes([201])*32)
    other=Ed25519PrivateKey.from_private_bytes(bytes([202])*32)
    payer=address(public(key));recipient=address(public(other))
    genesis={'chain_id':'1soft-history-measurement','asset':'DEV','fee':2,
             'protocol_version':3,'state_commitment':'smt-v1',
             'allocations':[{'public_key':public(key),'units':1000000},
                            {'public_key':public(other),'units':0}]}
    with tempfile.TemporaryDirectory(prefix='1soft-history-measure-') as name:
        root=Path(name);full=BlockApplication(root/'all.sqlite',expected_genesis=genesis)
        bounded=BlockApplication(root/'bounded.sqlite',expected_genesis=genesis,block_history_keep=keep)
        model=NativeLedger(':memory:',genesis)
        first_receipt=None;tx_count=0
        try:
            for app in (full,bounded):app.init_chain(genesis['chain_id'],genesis)
            for h in range(1,blocks+1):
                txs=[]
                if (h-1)%16==0:
                    body=model.body(payer,tx_count,{'type':'transfer','to':recipient,'units':10},valid_until=10000)
                    txs=[canonical(sign(key,body))];tx_count+=1
                previous=None
                for app in (full,bounded):
                    result=app.finalize_block(txs,h,hashlib.sha256(str(h).encode()).digest());app.commit()
                    if previous is not None and result!=previous:raise AssertionError('execution result changed')
                    previous=result
                if full.query('/state')['value']!=bounded.query('/state')['value']:
                    raise AssertionError('native state or AppHash changed')
                if h==1:first_receipt=bounded.native['receipts'][0]
            def stored(app):
                row=app.db.execute('SELECT count(*),coalesce(sum(length(block_hash)+length(tx_digest)+length(app_hash)+length(results)),0) FROM blocks').fetchone()
                return {'records':row[0],'logical_text_payload_bytes':row[1]}
            snapshots=full.list_snapshots(),bounded.list_snapshots()
            if snapshots[0]!=snapshots[1]:raise AssertionError('snapshot descriptor changed')
            for i in range(snapshots[0][0]['chunks']):
                if full.load_snapshot_chunk(blocks,1,i)!=bounded.load_snapshot_chunk(blocks,1,i):
                    raise AssertionError('snapshot bytes changed')
            if bounded.native['receipts'][0]!=first_receipt:raise AssertionError('old receipt changed')
            proof=bounded.compact_witness([('accounts',payer)])
            if proof!=full.compact_witness([('accounts',payer)]):raise AssertionError('account proof changed')
            return {'schema':1,'blocks':blocks,'transactions':tx_count,'keep_blocks':keep,
                    'retain_all':stored(full),'bounded':stored(bounded),
                    'app_hash':bounded.app_hash,'identical_native_state_at_every_height':True,
                    'identical_snapshots':True,'identical_account_proof':True,
                    'first_receipt_preserved':True,'native_receipts_retained':len(bounded.native['receipts']),
                    'pruned_first_block_status':json.loads(bounded.query('/block/1')['value'])['status'],
                    'consensus_executed':False,'real_funds':False,'total_node_disk_bound_claimed':False}
        finally:model.close();bounded.close();full.close()


def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--blocks',type=int,default=512);p.add_argument('--keep',type=int,default=16)
    p.add_argument('--output',type=Path,required=True);args=p.parse_args()
    # Exclusive output prevents replacing an earlier measurement.
    fd=os.open(args.output,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
    with os.fdopen(fd,'w') as f:
        result=measure(args.blocks,args.keep);json.dump(result,f,indent=2);f.write('\n');f.flush();os.fsync(f.fileno())
    print(json.dumps(result,indent=2))

if __name__=='__main__':main()
