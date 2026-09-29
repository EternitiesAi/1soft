#!/usr/bin/env python3
"""Offline registry experiment. Never signs, connects to a node or moves funds."""
import argparse
import json
from pathlib import Path
import sqlite3
import sys

HERE = Path(__file__).resolve().parents[1]
ROOT = HERE.parents[1]
sys.path[:0] = [str(HERE/'src'), str(ROOT/'tools/validator-transition/src'), str(ROOT/'src')]
from commit_verifier import load_json
from registry_application import RegistryApplication
from registry_rules import MAX_STATE_BYTES, draft, state_hash, validate_genesis
from transition_io import read_json, write_new


def main(argv=None):
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--genesis',type=Path,required=True)
    p.add_argument('--store',type=Path,required=True)
    sub=p.add_subparsers(dest='command',required=True)
    sub.add_parser('init'); sub.add_parser('inspect')
    d=sub.add_parser('draft'); d.add_argument('--operation',type=Path,required=True)
    d.add_argument('--valid-from',type=int,required=True);d.add_argument('--valid-until',type=int,required=True)
    d.add_argument('--output',type=Path,required=True)
    b=sub.add_parser('block');b.add_argument('--transactions',type=Path,required=True,
        help='JSON list of exact canonical signed-command bytes in lowercase hex')
    b.add_argument('--height',type=int,required=True);b.add_argument('--block-hash',required=True)
    x=sub.add_parser('export');x.add_argument('--output',type=Path,required=True)
    s=sub.add_parser('restore');s.add_argument('--snapshot',type=Path,required=True);s.add_argument('--expected-hash',required=True)
    a=p.parse_args(argv)
    try:
        g=validate_genesis(read_json(a.genesis,256*1024))
        with RegistryApplication(a.store,g,create=a.command=='init',read_only=a.command in ('inspect','draft','export')) as app:
            if a.command=='block':
                values=read_json(a.transactions,1024*1024)
                if type(values) is not list or not all(type(v) is str for v in values):raise ValueError('bad block')
                txs=[bytes.fromhex(v) for v in values]
                if [v.hex() for v in txs]!=values:raise ValueError('noncanonical command hex')
                result=app.finalize_block(txs,a.height,a.block_hash)
                committed=app.commit()
                result={'finalize':result,'commit':committed}
            elif a.command=='draft':
                result=draft(g,app.state(),read_json(a.operation),valid_from=a.valid_from,valid_until=a.valid_until)
                write_new(a.output,result)
                result={'status':'unsigned-draft-written','administrative_authorization':False}
            elif a.command=='export':
                s=app.state();write_new(a.output,s)
                result={'status':'snapshot-exported','height':s['height'],'app_hash':state_hash(s)}
            elif a.command=='restore':
                result=app.install_snapshot(read_json(a.snapshot,MAX_STATE_BYTES),expected_app_hash=a.expected_hash)
            else:
                s=app.state();result={'height':s['height'],'epoch':s['epoch'],'nonce':s['nonce'],
                    'app_hash':state_hash(s),'active_set':s['active_set'],'pending':s['pending'],
                    'accepted_commands':len(s['receipts'])}
        print(json.dumps({'scope':'isolated-registry-experiment','network_requested':False,
                          'monetary_state_changed':False,'result':result},indent=2))
        return 0
    except (ValueError,KeyError,TypeError,OSError,sqlite3.Error):
        print('Registry operation refused. Local commit status must be inspected before retrying; no network action was requested.',file=sys.stderr)
        return 2


if __name__=='__main__':raise SystemExit(main())
