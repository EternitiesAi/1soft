#!/usr/bin/env python3
"""Local-only validator continuity and update previews; never submits an update."""
import argparse
from pathlib import Path
import json
import sqlite3
import sys

ADDON=Path(__file__).resolve().parents[1]
ROOT=ADDON.parents[1]
sys.path[:0]=[str(ADDON/'src'),str(ROOT/'src')]
from commit_verifier import encode,load_json
from validator_store import ValidatorStore,write_new
from validator_transition import MAX_BATCH_BYTES,preview_update


def read(path,limit=MAX_BATCH_BYTES):
    with Path(path).open('rb') as f:raw=f.read(limit+1)
    if len(raw)>limit:raise ValueError('input too large')
    return raw


def main(argv=None):
    p=argparse.ArgumentParser(description=__doc__)
    sub=p.add_subparsers(dest='command',required=True)
    for name in ('init','advance','inspect','export'):
        cmd=sub.add_parser(name)
        cmd.add_argument('--genesis',type=Path,required=True)
        cmd.add_argument('--policy',type=Path,required=True,help='Operator-supplied external trust pins and time limits')
        cmd.add_argument('--store',type=Path,required=True)
        if name=='init':cmd.add_argument('--anchor',type=Path,required=True)
        if name=='advance':
            cmd.add_argument('--steps',type=Path,required=True)
            cmd.add_argument('--expected-tip-hash',required=True)
        if name=='export':cmd.add_argument('--output',type=Path,required=True)
    cmd=sub.add_parser('preview')
    cmd.add_argument('--next-set',type=Path,required=True,help='Public set already scheduled for H+1')
    cmd.add_argument('--changes',type=Path,required=True)
    cmd.add_argument('--finalize-height',type=int,required=True)
    a=p.parse_args(argv)
    try:
        if a.command=='preview':
            result=preview_update(load_json(read(a.next_set)),load_json(read(a.changes)),a.finalize_height)
        else:
            g=read(a.genesis,1024*1024);pol=load_json(read(a.policy,16384),max_bytes=16384)
            anchor=load_json(read(a.anchor)) if a.command=='init' else None
            with ValidatorStore(a.store,g,pol,anchor=anchor,read_only=a.command in ('inspect','export')) as store:
                if a.command=='advance':
                    result=store.advance(load_json(read(a.steps)),expected_tip_hash=a.expected_tip_hash)
                elif a.command=='export':
                    write_new(a.output,encode(store.export()))
                    result={'status':'historical-evidence-exported','financial_authority':False}
                else:result=store.inspect()
        print(json.dumps(result,indent=2));return 0
    except (OSError,ValueError,KeyError,TypeError,sqlite3.Error):
        print('Validator evidence refused or unavailable; no chain or wallet was changed.',file=sys.stderr)
        return 2

if __name__=='__main__':raise SystemExit(main())
