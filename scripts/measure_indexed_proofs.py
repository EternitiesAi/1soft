#!/usr/bin/env python3
"""Measure identical indexed/reference proofs after signed local native transfers.
Single-host developer benchmark, not consensus, HTTP, fee or TPS measurement.
"""
from __future__ import annotations
import argparse
from dataclasses import asdict
import hashlib
import json
from pathlib import Path
import platform
import sqlite3
import statistics
import sys
import time
ROOT=Path(__file__).resolve().parents[1]
sys.path[:0]=[str(ROOT/'src')]
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from block_application import BlockApplication
from native_core import NativeLedger, address, public, sign, canonical
from state_tree import encoded, make_witness, verify_proof


def measure(output: Path, transfers: int, repeats: int):
    output.mkdir(parents=True,exist_ok=False)
    owner=Ed25519PrivateKey.from_private_bytes(bytes([81])*32)
    merchant=Ed25519PrivateKey.from_private_bytes(bytes([82])*32)
    a,b=address(public(owner)),address(public(merchant))
    genesis={'protocol_version':3,'state_commitment':'smt-v1','chain_id':'1soft-index-measurement-dev',
             'asset':'DEV','fee':2,'allocations':[{'public_key':public(owner),'units':1000000},
                                               {'public_key':public(merchant),'units':0}]}
    (output/'genesis.json').write_text(json.dumps(genesis,indent=2)+'\n')
    application=BlockApplication(output/'node.sqlite',expected_genesis=genesis)
    application.init_chain(genesis['chain_id'],genesis)
    maker=NativeLedger(':memory:',genesis)
    try:
        def tx(n):return canonical(sign(owner,maker.body(a,n,{'type':'transfer','to':b,'units':1},valid_until=1000000)))
        blocks=[]
        for start in range(0,transfers,64):
            h=application.height+1
            raws=[tx(n) for n in range(start,min(start+64,transfers))]
            result=application.finalize_block(raws,h,hashlib.sha256(str(h).encode()).digest())
            if not all(row['code']==0 for row in result['tx_results']):raise AssertionError('native transfer failed')
            application.commit();blocks.append({'height':h,'executed':len(raws),'app_hash':application.app_hash})
        q=[('accounts',a)]
        baseline=make_witness(genesis,application.height,application.native,q)
        if application.compact_witness(q)!=baseline:raise AssertionError('proof bytes differ')
        if verify_proof(bytes.fromhex(baseline['root']),'accounts',a,baseline['entries'][0]) is None:raise AssertionError('account absent')
        reference_ns=[];indexed_ns=[];read_counts=[]
        for i in range(repeats):
            for mode in (('indexed','reference') if i%2 else ('reference','indexed')):
                start=time.perf_counter_ns()
                proof=(application.compact_witness(q) if mode=='indexed'
                       else make_witness(genesis,application.height,application.native,q))
                elapsed=time.perf_counter_ns()-start
                if proof!=baseline:raise AssertionError('measurement proof differs')
                if mode=='indexed':indexed_ns.append(elapsed);read_counts.append(asdict(application.proof_index.work))
                else:reference_ns.append(elapsed)
        record_count=application.proof_index.checkpoint()['record_count']
        node_count=application.db.execute('SELECT count(*) FROM proof_nodes').fetchone()[0]
        h=application.height+1
        result=application.finalize_block([tx(transfers)],h,hashlib.sha256(str(h).encode()).digest())
        if result['tx_results'][0]['code']!=0:raise AssertionError('delta transfer failed')
        application.commit();delta=asdict(application.proof_index.work)
        if application.compact_witness(q)!=make_witness(genesis,h,application.native,q):raise AssertionError('delta proof differs')
        audit=application.proof_index.audit(hashlib.sha256(encoded(genesis)).hexdigest(),h,application.app_hash)
        report={'schema':1,'scope':'single-host native execution and proof reads; not consensus or TPS',
            'network_executed':False,'validator_signatures_used':False,'application_blocks_before_delta':len(blocks),
            'signed_native_transfers_before_delta':transfers,'additional_delta_transfers':1,
            'repeats_per_path':repeats,'records_before_delta':record_count,'stored_nodes_before_delta':node_count,
            'proof_bytes_identical':True,'proof_bytes':len(encoded(baseline)),
            'reference_rebuild_nanoseconds':reference_ns,'indexed_read_nanoseconds':indexed_ns,
            'reference_median_nanoseconds':int(statistics.median(reference_ns)),
            'indexed_median_nanoseconds':int(statistics.median(indexed_ns)),
            'median_read_ratio_in_this_run':statistics.median(reference_ns)/statistics.median(indexed_ns),
            'indexed_read_work':read_counts,'single_transfer_index_work':delta,'final_audit':audit,
            'python':platform.python_version(),'sqlite':sqlite3.sqlite_version,'platform':platform.platform(),
            'limitations':['native execution still restores/scans full state','finalization builds the reference root',
                          'snapshot serialization persists','index uses additional disk space','no live-network result']}
        (output/'blocks.json').write_text(json.dumps(blocks,indent=2)+'\n')
        (output/'result.json').write_text(json.dumps(report,indent=2)+'\n')
        (output/'proof-before-delta.json').write_text(json.dumps(baseline,indent=2)+'\n')
        print(json.dumps(report,indent=2),flush=True)
    finally:maker.close();application.close()


def main():
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--output',type=Path,required=True)
    p.add_argument('--transfers',type=int,default=1024);p.add_argument('--repeats',type=int,default=12)
    a=p.parse_args()
    if not 1<=a.transfers<=4096 or not 1<=a.repeats<=100:p.error('transfers 1..4096 and repeats 1..100 required')
    measure(a.output,a.transfers,a.repeats)
if __name__=='__main__':main()
