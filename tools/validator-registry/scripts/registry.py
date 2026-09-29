#!/usr/bin/env python3
"""Offline development registry. No private keys, network, wallet or production activation."""
import argparse
import json
from pathlib import Path
import sqlite3
import sys

ROOT=Path(__file__).resolve().parents[1];REPO=ROOT.parents[1]
sys.path[:0]=[str(ROOT/'src'),str(REPO/'tools/validator-transition/src'),str(REPO/'src')]
from commit_verifier import encode,load_json,exact
from registry_application import RegistryApplication,write_new,decode_txs,MAX_STORE_BYTES
from registry_rules import digest,require,MAX_TX_BYTES
from validator_sets import hex_text


def read(path,limit):
    with Path(path).open('rb') as f:data=f.read(limit+1)
    require(len(data)<=limit,'input exceeds limit');return data


def main(argv=None):
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--genesis',type=Path,required=True);parser.add_argument('--genesis-sha256',required=True)
    parser.add_argument('--database',type=Path,required=True)
    sub=parser.add_subparsers(dest='command',required=True)
    sub.add_parser('init');sub.add_parser('inspect')
    check=sub.add_parser('check');check.add_argument('--transaction',type=Path,required=True)
    execute=sub.add_parser('apply-block');execute.add_argument('--block',type=Path,required=True)
    result=sub.add_parser('committed-result');result.add_argument('--height',type=int,required=True)
    for name in ('draft-schedule','draft-cancel'):
        p=sub.add_parser(name);p.add_argument('--valid-from',type=int,required=True);p.add_argument('--valid-until',type=int,required=True)
        p.add_argument('--output',type=Path,required=True)
        if name=='draft-schedule':p.add_argument('--target',type=Path,required=True);p.add_argument('--emit-height',type=int,required=True)
        else:p.add_argument('--proposal-id',required=True)
    export=sub.add_parser('export');export.add_argument('--output',type=Path,required=True)
    restore=sub.add_parser('restore');restore.add_argument('--snapshot',type=Path,required=True)
    restore.add_argument('--expected-height',type=int,required=True);restore.add_argument('--expected-app-hash',required=True)
    a=parser.parse_args(argv)
    try:
        raw=read(a.genesis,131072);require(digest(raw)==hex_text(a.genesis_sha256),'genesis file differs from external pin')
        g=load_json(raw,max_bytes=131072)
        if a.command=='restore':
            snap=load_json(read(a.snapshot,MAX_STORE_BYTES),max_bytes=MAX_STORE_BYTES)
            with RegistryApplication.restore_new(a.database,g,snap,expected_app_hash=a.expected_app_hash,
                                                  expected_height=a.expected_height) as app:out=app.info()
        else:
            with RegistryApplication(a.database,g,create=a.command=='init',
                                     read_only=a.command not in ('init','apply-block')) as app:
                if a.command=='init':out=app.info()
                elif a.command=='inspect':out={'info':app.info(),'registry_state':app.state()}
                elif a.command=='check':out=app.check_tx(read(a.transaction,MAX_TX_BYTES))
                elif a.command=='apply-block':
                    b=load_json(read(a.block,MAX_STORE_BYTES),max_bytes=MAX_STORE_BYTES)
                    exact(b,{'height','block_hash','transactions'},'offline registry block')
                    out=app.finalize_block(decode_txs(b['transactions']),b['height'],bytes.fromhex(hex_text(b['block_hash'])))
                    app.commit()  # Printing failure after this does NOT undo commit.
                elif a.command=='committed-result':out=app.committed_result(a.height)
                elif a.command.startswith('draft-'):
                    op=({'kind':'schedule','emitted_height':a.emit_height,
                         'target_validators':load_json(read(a.target,131072),max_bytes=131072)}
                        if a.command=='draft-schedule' else {'kind':'cancel','proposal_id':a.proposal_id})
                    body=app.rules.body(app.state(),op,valid_from=a.valid_from,valid_until=a.valid_until)
                    payload=app.rules.signing_bytes(body)
                    write_new(a.output,encode({'body':body,'signing_bytes_hex':payload.hex(),'signed':False}))
                    out={'status':'unsigned-draft-written','authorization_established':False}
                else:
                    write_new(a.output,encode(app.export_snapshot()));out={'status':'registry-snapshot-exported','wallet_changed':False}
        print(json.dumps(out,indent=2))
        return 2 if out.get('code')==1 or any(r['code']!=0 for r in out.get('tx_results',[])) else 0
    except (OSError,ValueError,KeyError,TypeError,sqlite3.Error):
        print('Registry operation refused or incomplete; persisted progress may exist. No production activation requested.',file=sys.stderr)
        return 2

if __name__=='__main__':raise SystemExit(main())
