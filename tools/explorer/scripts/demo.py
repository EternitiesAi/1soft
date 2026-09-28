#!/usr/bin/env python3
"""Create the explicit synthetic-fixture explorer demo from real native execution.

Not a live chain. Public deterministic fixture keys only; no private key files.
"""
import argparse
import json
import os
from pathlib import Path
import sys
ROOT=Path(__file__).resolve().parents[1]
sys.path[:0]=[str(ROOT/'src'),str(ROOT/'tests')]
from fixture_explorer import scenario,bundle,pin
from explorer_index import ExplorerIndex,write_new
from explorer_web import render
from commit_verifier import encode


def main():
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--output',type=Path,required=True);a=p.parse_args()
    a.output.mkdir(mode=0o700,parents=False,exist_ok=False)
    c=scenario()
    write_new(a.output/'fixture-genesis.json',c['genesis'])
    first=bundle(c,12);second=bundle(c,24,first=13)
    with ExplorerIndex(a.output/'index.sqlite',c['genesis'],c['genesis_sha256'],create=True,profile='synthetic-fixture') as index:
        first_result=index.ingest(first,initial_header_hash=pin(c,12))
    with ExplorerIndex(a.output/'index.sqlite',c['genesis'],c['genesis_sha256']) as index:
        second_result=index.ingest(second);view=index.current();repeat=index.ingest(second)
        write_new(a.output/'explorer.html',render(view))
        write_new(a.output/'view.json',encode(view))
        write_new(a.output/'evidence.json',encode(index.evidence()))
    report={'schema':1,'profile':'synthetic-fixture','native_execution':True,'consensus_executed':False,
        'real_funds':False,'first_import':first_result,'reopened_import':second_result,
        'repeat_import':repeat,'genesis_sha256':c['genesis_sha256'],'initial_header_hash':pin(c,12),
        'final_header_hash':pin(c,24),'recorded_supply':view['supply_units'],
        'budget_spent':view['budgets'][0]['spent'],'old_source_block_result_code':c['old_block_status'],
        'private_key_files_created':False}
    write_new(a.output/'result.json',encode(report));print(json.dumps(report,indent=2))

if __name__=='__main__':main()
