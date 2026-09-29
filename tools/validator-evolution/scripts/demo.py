#!/usr/bin/env python3
"""Reproduce local committee transitions. No live validators or private-key files."""
import argparse
from pathlib import Path
import sys
ADDON=Path(__file__).resolve().parents[1];ROOT=ADDON.parents[1]
sys.path[:0]=[str(ADDON/'src'),str(ADDON/'tests'),str(ROOT/'src'),str(ROOT/'tests')]
from commit_verifier import encode
from validator_store import ValidatorStore,write_new
from transition_fixture import fixture


def main():
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--output',type=Path,required=True);a=p.parse_args()
    a.output.mkdir(mode=0o700,exist_ok=False)
    reports=[]
    for smt in (False,True):
        f=fixture(smt);path=a.output/('smt.sqlite' if smt else 'flat.sqlite');states=[]
        with ValidatorStore(path,f['genesis'],f['policy'],anchor=f['steps'][0],clock=lambda:f['now']) as store:
            states.append(store.inspect())
            store.advance(f['steps'][1:4],expected_tip_hash=store.inspect()['header_hash']);states.append(store.inspect())
        with ValidatorStore(path,f['genesis'],f['policy'],clock=lambda:f['now']) as store:
            store.advance(f['steps'][4:7],expected_tip_hash=store.inspect()['header_hash']);states.append(store.inspect())
        with ValidatorStore(path,f['genesis'],f['policy'],clock=lambda:f['now']) as store:
            store.advance(f['steps'][7:],expected_tip_hash=store.inspect()['header_hash']);states.append(store.inspect())
            exact=store.export();assert exact==f['steps']
            prefix='smt' if smt else 'flat'
            write_new(a.output/(prefix+'-headers.json'),encode(exact))
            write_new(a.output/(prefix+'-genesis.json'),f['genesis'])
            write_new(a.output/(prefix+'-policy.json'),encode(f['policy']))
        reports.append({'commitment':prefix,'states':states,'plans':f['plans'],
                        'native_execution':f['native_execution'],'fixture_committee':True,
                        'new_validator_network_executed':False,'private_key_files_created':False})
    write_new(a.output/'result.json',encode({'scope':'synthetic committee signatures with actual native application execution',
        'reports':reports,'activation_scheduled':False,'governance_implemented':False,'production_wallet_changed':False}))
    print(encode({'status':'demonstrations-completed','profiles':2,'real_funds':False}).decode())

if __name__=='__main__':main()
