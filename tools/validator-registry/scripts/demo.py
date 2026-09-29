#!/usr/bin/env python3
"""Execute an authorized registry lifecycle with disposable public fixture keys."""
import argparse
from pathlib import Path
import sys

HERE=Path(__file__).resolve().parents[1];ROOT=HERE.parents[1]
sys.path[:0]=[str(HERE/'src'),str(HERE/'tests'),str(ROOT/'tools/validator-transition/src'),str(ROOT/'src')]
from commit_verifier import encode
from registry_application import RegistryApplication
from registry_rules import state_hash,sha
from registry_fixture import fixture,schedule,cancel
from validator_sets import canonical_roster
from transition_io import write_new


def demonstrate(output):
    output.mkdir(mode=0o700,exist_ok=False)
    g,admins,validators,target=fixture();write_new(output/'genesis.json',g)
    path=output/'experiment.sqlite';app=RegistryApplication(path,g,create=True)
    stages=[];wires={};replicas=[]
    try:
        for h in range(1,13):
            txs=[]
            if h==1:txs=[schedule(g,app.state(),admins[:2],target,3)]
            elif h==6:txs=[schedule(g,app.state(),admins[:2],g['validators'],8)]
            elif h==7:txs=[cancel(g,app.state(),admins[:2])]
            elif h==8:
                reweighted=[dict(r) for r in target];reweighted[0]['power']=11
                txs=[schedule(g,app.state(),admins[:2],canonical_roster(reweighted),10)]
            result=app.finalize_block(txs,h,sha(str(h).encode()));wire=app.update_wire().hex();app.commit()
            assert all(t['code']==0 for t in result['tx_results'])
            wires[h]=[raw.hex() for raw in txs]
            for replica in replicas:
                other=replica.finalize_block(txs,h,sha(str(h).encode()));replica.commit()
                assert other==result and replica.state()==app.state()
            state=app.state()
            if h in (1,3,5):
                write_new(output/f'snapshot-{h}.json',state)
                replica=RegistryApplication(output/f'restored-{h}.sqlite',g,create=True)
                replica.install_snapshot(state,expected_app_hash=state_hash(state));replicas.append(replica)
            stages.append({'height':h,'epoch':state['epoch'],'active_count':len(state['active_set']),
                'pending':None if state['pending'] is None else {'emission':state['pending']['emission_height'],
                'activation':state['pending']['activation_height'],'emitted':state['pending']['emitted']},
                'update_count':len(result['validator_updates']),'app_hash':state_hash(state),
                'field_three_wire':wire,'accepted_commands':len(state['receipts'])})
            # Reopen the same store at every completed height, including emission.
            app.close();app=RegistryApplication(path,g)
        assert [s['height'] for s in stages if s['update_count']]==[3,10]
        assert app.state()['epoch']==2 and len(app.state()['receipts'])==4
        summary={'schema':1,'status':'passed','profile':g['profile'],'administrative_policy':'2 of 3 separate fixture keys',
            'stages':stages,'emitted_heights':[3,10],'active_heights':[5,12],
            'cancelled_removal_never_emitted':True,'snapshots_restored_at':[1,3,5],
            'restored_replicas_match':True,'private_key_files_created':False,'consensus_executed':False,
            'native_money_integrated':False,'real_funds':False,'public_network_ready':False}
        write_new(output/'signed-block-commands.json',wires);write_new(output/'result.json',summary)
        return summary
    finally:
        app.close()
        for replica in replicas:replica.close()


if __name__=='__main__':
    import json
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--output',type=Path,required=True)
    print(json.dumps(demonstrate(p.parse_args().output),indent=2))
