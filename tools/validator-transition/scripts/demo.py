#!/usr/bin/env python3
"""Deterministic validator keys and synthetic headers; no live chain or governance."""
import argparse
import json
from pathlib import Path
import sys
ROOT=Path(__file__).resolve().parents[1];NATIVE=ROOT.parents[1]
sys.path[:0]=[str(ROOT/'src'),str(ROOT/'tests'),str(NATIVE/'src'),str(NATIVE/'tests')]
from commit_verifier import encode
from validator_sets import document_id,validator_updates,ValidatorSet
from validator_witness import start_witness,extend_witness,verify_witness,audit_transition
from validator_wire import encode_update_response
from transition_fixture import scenario
from transition_io import write_new,read_json


def main():
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--output',type=Path,required=True);args=p.parse_args()
    args.output.mkdir(mode=0o700,exist_ok=False)
    c=scenario();out=args.output
    (out/'genesis.json').write_bytes(c['genesis']);(out/'genesis.json').chmod(0o600)
    write_new(out/'policy.json',c['policy']);write_new(out/'draft.json',c['draft'])
    first=start_witness(c['entries'][0],c['genesis'],c['policy'],now_ns=c['now_ns'])
    intermediate=extend_witness(first,c['entries'][1:4],c['genesis'],c['policy'],
                                expected_parent_sha256=document_id(first),now_ns=c['now_ns'])
    write_new(out/'announced-not-active.json',intermediate)
    # Reopen saved proof; this does not renew its trust interval or replace history.
    before=(out/'announced-not-active.json').read_bytes();saved=read_json(out/'announced-not-active.json')
    final=extend_witness(saved,c['entries'][4:],c['genesis'],c['policy'],
                         expected_parent_sha256=document_id(saved),now_ns=c['now_ns'])
    write_new(out/'active-witness.json',final)
    assert (out/'announced-not-active.json').read_bytes()==before
    result=audit_transition(c['draft'],final,c['genesis'],c['policy'],now_ns=c['now_ns'])
    result.update(fixture_signatures=True,consensus_executed=False,private_key_files_created=False,
                  old_witness_preserved=True,proof_result=verify_witness(final,c['genesis'],c['policy'],now_ns=c['now_ns']))
    write_new(out/'result.json',result)
    vectors=[]
    for name,old,new in [('replace-remove-reweight',c['sets']['old'],c['sets']['new'])]:
        updates=validator_updates(old,new)
        vectors.append({'name':name,'current':old.json(),'target':new.json(),'updates':updates,
                        'current_hash':old.hash,'target_hash':new.hash,'wire':encode_update_response(updates).hex()})
    second=scenario(full_replace=True);old,new=second['sets']['old'],second['sets']['new'];updates=validator_updates(old,new)
    vectors.append({'name':'full-roster-replacement','current':old.json(),'target':new.json(),'updates':updates,
                    'current_hash':old.hash,'target_hash':new.hash,'wire':encode_update_response(updates).hex()})
    write_new(out/'upstream-vectors.json',vectors)
    print(json.dumps(result,indent=2))
if __name__=='__main__':main()
