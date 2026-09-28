#!/usr/bin/env python3
"""1soft Explorer: import, inspect and serve verified historical chain data locally."""
import argparse
import json
from pathlib import Path
import sqlite3
import sys

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/'src'))
from commit_verifier import encode,load_json
from explorer_index import ExplorerIndex,MAX_INPUT,write_new,need
from explorer_rpc import refresh
from explorer_web import render,server


def read(path,limit):
    with Path(path).open('rb') as f:raw=f.read(limit+1)
    need(len(raw)<=limit,'input exceeds limit')
    return raw


def main(argv=None):
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--genesis',type=Path,required=True)
    p.add_argument('--genesis-sha256',required=True)
    p.add_argument('--index',type=Path,required=True)
    sub=p.add_subparsers(dest='command',required=True)
    sub.add_parser('init')
    ingest=sub.add_parser('import');ingest.add_argument('--evidence',type=Path,required=True)
    ingest.add_argument('--initial-header-hash',help='Required out-of-band anchor for an empty index')
    sync=sub.add_parser('sync');sync.add_argument('--endpoint',required=True)
    sync.add_argument('--initial-header-hash',help='Required out-of-band anchor for an empty index')
    sub.add_parser('inspect')
    export=sub.add_parser('export');export.add_argument('--output',type=Path,required=True)
    serve=sub.add_parser('serve');serve.add_argument('--port',type=int,default=8787)
    a=p.parse_args(argv)
    try:
        genesis=read(a.genesis,1024*1024)
        with ExplorerIndex(a.index,genesis,a.genesis_sha256,create=a.command=='init',
                           read_only=a.command in ('inspect','export','serve')) as index:
            if a.command=='init':result={'status':'empty-index-created','wallet_created':False}
            elif a.command=='import':
                result=index.ingest(load_json(read(a.evidence,MAX_INPUT),max_bytes=MAX_INPUT),
                                    initial_header_hash=a.initial_header_hash)
            elif a.command=='sync':result=refresh(index,a.endpoint,initial_header_hash=a.initial_header_hash)
            else:
                view=index.current();need(view is not None,'index has no verified state')
                result={k:view[k] for k in ('state_height','anchor_height','anchor_hash','transaction_count',
                                            'indexed_block_count','account_count','latest_state_guaranteed')}
                if a.command=='export':write_new(a.output,render(view));result['status']='snapshot-exported'
        if a.command=='serve':
            http=server(a.index,genesis,a.genesis_sha256,port=a.port)
            print(json.dumps({'viewer':f'http://127.0.0.1:{http.server_port}/','read_only':True}),flush=True)
            try:http.serve_forever(poll_interval=.2)
            except KeyboardInterrupt:pass
            finally:http.server_close()
        else:print(json.dumps(result,indent=2))
        return 0
    except (OSError,ValueError,KeyError,TypeError,sqlite3.Error):
        print('Explorer operation refused or evidence unavailable. No transaction was signed or submitted.',file=sys.stderr)
        return 2


if __name__=='__main__':raise SystemExit(main())
