#!/usr/bin/env python3
"""View an existing P4 read store. Never collects RPC data, signs, or creates a wallet."""
import argparse,json,sqlite3,sys,time
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1];NATIVE=ROOT.parents[1]
sys.path[:0]=[str(ROOT/'src'),str(NATIVE/'src'),str(NATIVE/'tools/validator-transition/src'),str(NATIVE/'tools/protocol4-client/src'),str(NATIVE/'tools/protocol4-receipts/src')]
from commit_verifier import load_json
from p4_explorer import current_view
from p4_explorer_web import server
from p4_evidence import need,MAX_GENESIS_BYTES

def read(path,cap):
    with path.open('rb') as f:raw=f.read(cap+1)
    need(len(raw)<=cap,'bounded external input required');return raw

def main():
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--genesis',type=Path,required=True);p.add_argument('--policy',type=Path,required=True);p.add_argument('--store',type=Path,required=True)
    sub=p.add_subparsers(dest='command',required=True);sub.add_parser('inspect');s=sub.add_parser('serve');s.add_argument('--port',type=int,default=0);s.add_argument('--label',default='Local development ledger');a=p.parse_args()
    try:
        g=read(a.genesis,MAX_GENESIS_BYTES);policy=load_json(read(a.policy,4096),max_bytes=4096)
        if a.command=='inspect':print(json.dumps(current_view(a.store,g,policy),indent=2));return 0
        # Verify before opening the listener. Every later view/capsule request checks again.
        current_view(a.store,g,policy);http=server(a.store,g,policy,port=a.port,label=a.label)
        print('http://127.0.0.1:'+str(http.server_port),flush=True)
        try:http.serve_forever()
        finally:http.server_close()
        return 0
    except KeyboardInterrupt:return 130
    except (OSError,ValueError,sqlite3.Error):print('P4 explorer unavailable; no outcome or spending authority inferred.',file=sys.stderr);return 2
if __name__=='__main__':raise SystemExit(main())
