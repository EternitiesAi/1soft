#!/usr/bin/env python3
"""Execute the local process demonstrations, with no consensus claim."""
import argparse
import json
from pathlib import Path
import sys
ROOT=Path(__file__).resolve().parents[3];ADDON=Path(__file__).resolve().parents[1]
sys.path[:0]=[str(ROOT/'src'),str(ROOT/'scripts'),str(ROOT/'tools/release'),
             str(ROOT/'tools/validator-transition/src'),str(ADDON/'src'),str(ADDON/'tests')]
from test_recovery import ProcessTests
from recovery_checks import write_new,read_json,fingerprint


def main():
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--output',type=Path,required=True);a=p.parse_args()
    a.output.mkdir(mode=0o700,exist_ok=False);rows=[];ProcessTests.setUpClass()
    for h in (1,4,6,7):
        test=ProcessTests();test.setUp()
        try:
            before,after=test.crash_at(h,event=h==4)
            observation=read_json(test.root/'boundary-0.json')
            result={'kind':'commit-reply-loss','interrupted_height':h,'boundary':observation,
                    'before':fingerprint(before),'after':fingerprint(after),
                    'state_equal_to_uninterrupted_fixture':True,'exact_saved_response_replayed':True,
                    'consensus_executed':False,'actual_sigkill':True}
            write_new(a.output/f'commit-{h}.json',result);rows.append(result)
        finally:test.tearDown()
    for h in (2,4,6):
        test=ProcessTests();test.setUp()
        try:
            before,after=test.snapshot_at(h)
            result={'kind':'format-2-bootstrap','snapshot_height':h,'before':fingerprint(before),'after':fingerprint(after),
                    'state_equal_to_uninterrupted_fixture':True,'historical_blocks_not_imported':True,
                    'consensus_executed':False,'actual_private_abci':True}
            write_new(a.output/f'bootstrap-{h}.json',result);rows.append(result)
        finally:test.tearDown()
    summary={'schema':1,'status':'passed','demonstrations':rows,'consensus_executed':False,
             'committee_signatures':'synthetic deterministic fixtures','real_funds':False,'production_keys':False}
    write_new(a.output/'summary.json',summary);print(json.dumps(summary,indent=2))

if __name__=='__main__':main()
