#!/usr/bin/env python3
"""Produce reproducible P4 read artifacts from disposable actual native execution.

Synthetic committee signatures; never a validator-run, production key or wallet.
No node, wallet, archive or user database is included in exported evidence.
"""
import argparse
import json
from pathlib import Path
import sys

ROOT=Path(__file__).resolve().parents[1]
sys.path[:0]=[str(ROOT/'src'),str(ROOT/'tests')]
from block_application import encode
from p4_evidence import content_id, verify_evidence, verify_receipt
from p4_read_store import P4ReadStore, write_new
from p4_fixture import build,bundle


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output',type=Path,required=True)
    a=parser.parse_args();a.output.mkdir(mode=0o700,exist_ok=False)
    c=build();write_new(a.output/'fixture-genesis.json',c['genesis'])
    write_new(a.output/'fixture-policy.json',encode(c['policy']))
    tip=None;checkpoints=[];proofs=[]
    path=a.output/'local-demo-read.sqlite'
    for height in (3,5,8,16):
        evidence=bundle(c,height)
        with P4ReadStore(path,c['genesis'],c['policy'],create=height==3,clock=lambda:c['now_ns']) as store:
            saved=store.import_evidence(evidence,expected_tip=tip)
            report=store.current();tip=saved['evidence_id'];proofs.append(tip)
            filename=f'evidence-height-{height}.json';write_new(a.output/filename,encode(store.export(tip)))
            checkpoints.append({'state_height':height,'signed_header_height':report['header_height'],
                'registry_epoch':report['registry_epoch'],'pending_transition_phase':
                report['registry']['pending']['phase'] if report['registry']['pending'] else None,
                'evidence_id':tip,'evidence_file':filename,'app_hash':report['app_hash'],
                'recorded_payer_balance':store.account(c['payer'])['account']['recorded_balance'],
                'recorded_budget_spent':report['budgets'][0][4]})
    # The native source application was already closed by the fixture. The read
    # store is reopened once more; all receipt proof checks use only exported bytes.
    with P4ReadStore(path,c['genesis'],c['policy'],read_only=True,clock=lambda:c['now_ns']) as store:
        final_evidence=store.export(tip);current=store.current()
        receipts=[]
        for name in ('before','raven','after','replacement'):
            raw=c['wires'][name];result=store.receipt(raw,payer=c['payer'])
            assert result['status']=='recorded'
            write_new(a.output/f'{name}-payment.json',raw)
            receipts.append({'payment':name,'native_txid':result['receipt']['native_txid'],
                'height':result['receipt']['height'],'wire_sha256':result['receipt']['wire_sha256'],
                'wallet_reservations_changed':False})
        first=store.export(proofs[0]);assert content_id(first)==proofs[0]
    # The demo-only read DB is not portable signed evidence and need not be shipped.
    for suffix in ('','-wal','-shm'):
        file=Path(str(path)+suffix)
        if file.exists():file.unlink()
    unknown=verify_receipt(bundle(c,3),c['genesis'],c['policy'],c['wires']['replacement'],
                           payer=c['payer'],now_ns=c['now_ns'])
    assert unknown['status']=='unavailable' and not unknown['historical_absence_proven']
    result={'schema':1,'profile':'synthetic-committee-over-actual-P4-execution',
        'parent_commit':'b73a88ca53666972ae2c8ce35fd9edb7ac0cb41c',
        'checkpoints':checkpoints,'receipts':receipts,'final_epoch':current['registry_epoch'],
        'full_validator_roster_replacement_verified':True,'native_receipts':len(current['receipts']),
        'recorded_supply_units':current['recorded_supply_units'],'payer':c['payer'],
        'recorded_payer_balance':'874','budget_spent_units':100,
        'later_payment_at_earlier_checkpoint_status':unknown['status'],
        'earlier_evidence_preserved':True,'native_source_closed_before_reads':True,
        'private_key_files_created':False,'wallet_signing_enabled':False,
        'actual_consensus_executed':False,'real_funds':False}
    write_new(a.output/'result.json',encode(result));print(json.dumps(result,indent=2))


if __name__=='__main__':main()
