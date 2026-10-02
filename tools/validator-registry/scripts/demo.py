#!/usr/bin/env python3
"""Execute the isolated registry demo; fixture keys are public and disposable."""
import argparse
import json
from pathlib import Path
import sys
import tempfile

ROOT=Path(__file__).resolve().parents[1];REPO=ROOT.parents[1]
sys.path[:0]=[str(ROOT/'src'),str(ROOT/'tests'),str(REPO/'tools/validator-transition/src'),
             str(REPO/'tools/validator-transition/tests'),str(REPO/'src'),str(REPO/'tests')]
from registry_history_fixture import history_case
from registry_evidence import verify_registry_history
from registry_application import RegistryApplication,write_new
from registry_wire import encode_finalize
from validator_sets import ValidatorSet
from commit_verifier import encode


def main():
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--output',type=Path,required=True);a=p.parse_args()
    a.output.mkdir(mode=0o700,parents=False,exist_ok=False)
    with tempfile.TemporaryDirectory(prefix='1soft-registry-demo-') as tmp:
        path=Path(tmp)/'registry.sqlite';case=history_case(path)
        verified=verify_registry_history(case['snapshot'],case['witness'],case['engine_genesis'],case['policy'],now_ns=case['now_ns'])
        with RegistryApplication(path,case['genesis']) as app:
            restored=RegistryApplication.restore_new(Path(tmp)/'restored.sqlite',case['genesis'],case['snapshot'],
                            expected_app_hash=app.info()['app_hash'],expected_height=7)
            try:
                if restored.state()!=app.state():raise AssertionError('registry snapshot restoration differs')
            finally:restored.close()
    for name,value in [('registry-genesis.json',case['genesis']),('snapshot.json',case['snapshot']),
                       ('policy.json',case['policy']),('witness.json',case['witness']),('verification.json',verified)]:
        write_new(a.output/name,encode(value))
    write_new(a.output/'engine-genesis.json',case['engine_genesis']);write_new(a.output/'authorized-action.json',case['signed_action'])
    vectors=[]
    for r in case['responses']:
        current=case['genesis']['validators'] if r['epoch']==0 else case['target']
        target=case['target'] if r['validator_updates'] else current
        vectors.append({'name':f"registry-height-{r['height']}",'current':current,'target':target,
                        'current_hash':ValidatorSet.parse(current).hash,'target_hash':ValidatorSet.parse(target).hash,
                        'updates':r['validator_updates'],'app_hash':r['app_hash'],
                        'tx_results':[{'code':t['code'],'data':t['data'],'log':t['log']} for t in r['tx_results']],
                        'wire':encode_finalize(r).hex()})
    write_new(a.output/'upstream-vectors.json',encode(vectors))
    timeline=[{'height':r['height'],'epoch':r['epoch'],'current':r['validators_hash'],'next':r['next_validators_hash'],
               'last_commit':r['last_commit_validators_hash'],'update_count':len(r['validator_updates'])} for r in case['responses']]
    report={'schema':1,'status':'passed','timeline':timeline,'administrative_threshold':'3 of 4 separate fixture keys',
            'accepted_at_height':1,'emitted_at_height':4,'active_at_height':6,'last_commit_uses_new_set_at_height':7,
            'final_epoch':verified['epoch'],'final_app_hash':verified['app_hash'],'snapshot_replayed':True,
            'signed_header_history_verified':True,'committee_signatures':'synthetic-fixture',
            'consensus_executed':False,'native_money_protocol_integrated':False,'real_funds':False,
            'production_activation_performed':False,'release_status':'blocked'}
    write_new(a.output/'result.json',encode(report));print(json.dumps(report,indent=2))

if __name__=='__main__':main()
