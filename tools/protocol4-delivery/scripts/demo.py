#!/usr/bin/env python3
"""P4 delivery demo: local native execution with synthetic committee signatures."""
import argparse
import json
from pathlib import Path
import tempfile
import sys
from unittest.mock import patch

ROOT=Path(__file__).resolve().parents[3]
sys.path[:0]=[str(ROOT/'src'),str(ROOT/'tests'),str(ROOT/'tools/validator-transition/src')]
for name in ('protocol4-client','protocol4-wallet','protocol4-delivery'):
    sys.path[:0]=[str(ROOT/'tools'/name/'src'),str(ROOT/'tools'/name/'tests')]
from block_application import encode
from p4_read_store import write_new
from delivery_fixture import Fixture


def run(output):
    output=Path(output);output.mkdir(mode=0o700,parents=False,exist_ok=False)
    with tempfile.TemporaryDirectory(prefix='1soft-p4-delivery-demo-') as tmp:
        f=Fixture(tmp);stages=[]
        try:
            raven=f.sign();refused=False
            try:f.sign('atlas',39)
            except ValueError:refused=True
            assert refused
            atlas=f.sign('atlas',38)
            original={raven:f.wallet.recover(raven,**f.selection()),atlas:f.wallet.recover(atlas,**f.selection('atlas'))}
            # No private-key operation may occur in any delivery phase.
            for path in Path(tmp).glob('*.pem'):path.unlink()
            def record(label):
                st=f.wallet.status();native=f.chain.app.state['native']
                stage={'stage':label,'wallet_state_height':st['state_height'],
                    'registry_epoch':st['registry_epoch'],'pending_units':int(st['pending_debit_units']),
                    'wallet_recorded_budget_spent':int(st['budgets'][0]['spent']),
                    'source_budget_spent':native['budgets'][0][4],
                    'submissions':len(f.submissions)}
                stages.append(stage)
            record('both_signed')
            with patch('p4_wallet._load_vault',side_effect=AssertionError('no signing vault')):
                first=f.send(raven);assert first['transport_observation']=='unresolved'
                f.delivery.close();f.delivery=f.open_delivery()
                f.delivery.collect(raven,**f.selection());record('raven_receipt_collected_wallet_unchanged')
                f.delivery.reconcile(raven,**f.selection(),expected_revision=f.wallet.status()['revision'])
                record('raven_reconciled')
                f.turnover();f.sync();record('all_validators_replaced_atlas_still_pending')
                f.delivery.close();f.delivery=f.open_delivery()
                f.mode='normal';second=f.send(atlas,'atlas');assert second['transport_observation']=='endpoint_admitted'
                f.delivery.collect(atlas,**f.selection('atlas'));record('atlas_receipt_collected_wallet_unchanged')
                f.delivery.reconcile(atlas,**f.selection('atlas'),expected_revision=f.wallet.status()['revision'])
                record('both_reconciled')
                replay=f.delivery.reconcile(raven,**f.selection(),expected_revision=f.wallet.status()['revision'])
                assert replay['status']=='already_recorded' and f.held()==0
            assert f.submissions==[original[raven],original[atlas]]
            assert [s['pending_units'] for s in stages]==[100,100,40,40,40,0]
            assert [s['wallet_recorded_budget_spent'] for s in stages]==[0,0,60,60,60,100]
            for did,name in ((raven,'raven'),(atlas,'atlas')):
                write_new(output/f'{name}-signed.json',original[did])
                write_new(output/f'{name}-receipt-evidence.json',encode(f.delivery.export_receipt(did,**f.selection(name))))
            write_new(output/'engine-genesis.json',f.chain.genesis);write_new(output/'policy.json',encode(f.chain.policy))
            f.chain.now+=4000*10**9
            observed=[f.delivery.inspect(raven,**f.selection()),f.delivery.inspect(atlas,**f.selection('atlas'))]
            report={'schema':1,'status':'passed','stages':stages,'overcommit_refused':refused,
                'original_wire_submission_count':len(f.submissions),'original_bytes_preserved':True,
                'old_receipt_reconciliation':replay['status'],'historical_observations_after_expiry':observed,
                'payer_recorded_balance':next(r[4] for r in f.chain.app.state['native']['accounts'] if r[0]==f.chain.payer),
                'actual_loopback_http':True,'first_response_dropped_after_native_execution':True,
                'second_response_forwarded':True,'native_execution':True,'committee':'synthetic-fixture',
                'actual_cometbft_consensus':False,'real_funds':False,'private_keys_exported':False,
                'scope':'one local signing journal and one local delivery journal; not global exactly-once'}
            write_new(output/'result.json',encode(report));return report
        finally:f.close()


def main():
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--output',type=Path,required=True);a=p.parse_args()
    print(json.dumps(run(a.output),indent=2))

if __name__=='__main__':main()
