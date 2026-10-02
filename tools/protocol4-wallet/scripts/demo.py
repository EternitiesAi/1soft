#!/usr/bin/env python3
"""Execute local P4 transfers across full validator replacement; never dispatch.

Public deterministic keys, actual native state transitions, synthetic committee
signatures. Proofs/payment wires exported, but never keys or wallet databases.
"""
import argparse
import json
from pathlib import Path
import sys
import tempfile
from unittest.mock import patch

ROOT=Path(__file__).resolve().parents[1]
REPO=ROOT.parents[1]
sys.path[:0]=[str(ROOT/'src'),str(ROOT/'tests'),str(REPO/'src'),
    str(REPO/'tools/validator-transition/src'),str(REPO/'tools/protocol4-client/src'),
    str(REPO/'tools/protocol4-client/tests')]
from block_application import encode
from native_core import canonical
from p4_evidence import verify_evidence,verify_receipt
from p4_read_store import write_new
from p4_wallet import P4Wallet
from wallet_fixture import Chain,PASSWORD


def demonstrate(output):
    output=Path(output);output.mkdir(mode=0o700,exist_ok=False)
    with tempfile.TemporaryDirectory(prefix='1soft-p4-wallet-fixture-') as directory:
        root=Path(directory);c=Chain(root);w=None;stages=[];proofs=[];decisions=[]
        try:
            path=root/'wallet.sqlite'
            w=P4Wallet(path,c.genesis,c.policy,create=True,clock=c.clock)
            write_new(output/'engine-genesis.json',c.genesis)
            write_new(output/'policy.json',encode(c.policy))
            def record(name):
                state=w.status();owner=next(a for a in state['accounts'] if a['id']==c.payer)
                stages.append({'stage':name,'state_height':state['state_height'],
                    'validator_epoch':state['registry_epoch'],'pending_units':state['pending_debit_units'],
                    'recorded_payer_balance':owner['recorded_balance'],
                    'recorded_budget_spent':state['budgets'][0]['spent'],
                    'decision_statuses':[d['status'] for d in state['decisions']]})
            def sync():
                e=c.evidence();r=w.sync(e,expected_revision=w.status()['revision'])
                proofs.append(e);write_new(output/f'proof-{len(proofs):02}.json',encode(e));return r
            first=c.evidence();w.sync(first,expected_revision=None);proofs.append(first)
            write_new(output/'proof-01.json',encode(first));record('initial_verified_setup')
            def approve(units,role):
                q=w.prepare(payer=c.payer,recipient=c.merchant,units=units,valid_until=30,grant_id=role)
                name=role or 'owner'
                write_new(output/f'review-{name}.json',encode(q))
                s=w.approve(q['review'],q['confirmation'],vault=root/(name+'.pem'),password=PASSWORD)
                wire=canonical(s['transaction']);decisions.append((s['decision_id'],wire,role))
                write_new(output/f'payment-{name}.json',wire);return wire
            raven=approve(58,'raven')
            with patch('p4_wallet._load_vault',side_effect=AssertionError('overcommit must not unlock')):
                try:w.prepare(payer=c.payer,recipient=c.merchant,units=39,valid_until=30,grant_id='atlas')
                except ValueError:pass
                else:raise AssertionError('overcommit was accepted')
            atlas=approve(38,'atlas');record('two_agent_payments_signed')
            c.block([raven,c.admin()]);sync();record('first_payment_recorded_change_queued')
            w.close();w=P4Wallet(path,c.genesis,c.policy,clock=c.clock)
            while c.app.state['registry']['epoch']==0:c.block()
            sync();record('entire_validator_roster_replaced_second_hold_preserved')
            c.block([atlas]);sync();record('second_payment_recorded_after_turnover')
            # Sign a NEW owner transfer from the post-turnover checkpoint as well.
            owner=approve(1,'');record('new_owner_payment_signed_after_turnover')
            c.block([owner]);sync();record('new_owner_payment_recorded')
            final=proofs[-1];review=verify_evidence(final,c.genesis,c.policy,now_ns=c.now)
            final_receipts=[]
            for ident,raw,role in decisions:
                result=verify_receipt(final,c.genesis,c.policy,raw,payer=c.payer,
                                      now_ns=c.now)
                final_receipts.append({'decision_id':ident,'role':role,
                    'status':result['status'],'wire_sha256':__import__('hashlib').sha256(raw).hexdigest()})
            # The selected historical checkpoint stays usable as raw proof, but
            # no wallet read/export is relabelled fresh after policy expiry.
            c.app.close()
            for vault in root.glob('*.pem'):vault.unlink()
            c.now+=7200*10**9
            w.close();w=P4Wallet(path,c.genesis,c.policy,clock=c.clock)
            with patch('p4_wallet._load_vault',side_effect=AssertionError('recovery must not unlock')):
                for ident,raw,role in decisions:
                    assert w.recover(ident,payer=c.payer,grant_id=role)==raw
            try:w.status()
            except ValueError:pass
            else:raise AssertionError('expired policy was silently renewed')
            expected=[('0','994','0'),('100','994','0'),('40','934','60'),('40','934','60'),
                      ('0','894','100'),('3','894','100'),('0','891','100')]
            assert [(r['pending_units'],r['recorded_payer_balance'],r['recorded_budget_spent']) for r in stages]==expected
            result={'schema':1,'status':'passed','base_commit':'b73a88ca53666972ae2c8ce35fd9edb7ac0cb41c',
                'stages':stages,'selected_receipts':final_receipts,'signed_decisions':len(decisions),
                'native_receipts':len(review['receipts']),'historical_recovery_after_expiry':True,
                'private_keys_exported':False,'wallet_database_exported':False,
                'actual_native_execution':True,'synthetic_committee_signatures':True,
                'network_requests':0,'broadcasts':0,'actual_consensus_executed':False,
                'real_funds':False,'source_node_mutations_by_wallet':False}
            write_new(output/'result.json',encode(result))
            print(json.dumps(result,indent=2));return result
        finally:
            if w is not None:w.close()
            c.close()


def main():
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--output',type=Path,required=True)
    a=p.parse_args();demonstrate(a.output)

if __name__=='__main__':main()
