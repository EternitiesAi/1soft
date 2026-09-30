#!/usr/bin/env python3
"""Synthetic signed fixture viewer; not engine evidence, public network or live funds."""
import argparse,sys
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1];NATIVE=ROOT.parents[1]
sys.path[:0]=[str(ROOT/'src'),str(NATIVE/'src'),str(NATIVE/'tools/validator-transition/src'),str(NATIVE/'tools/protocol4-client/src'),str(NATIVE/'tools/protocol4-client/tests'),str(NATIVE/'tools/protocol4-receipts/src')]
from p4_fixture import build,bundle
from p4_read_store import P4ReadStore
from p4_explorer_web import server

def main():
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--output',type=Path,required=True);p.add_argument('--port',type=int,default=0);a=p.parse_args()
    a.output.mkdir(mode=0o700,parents=True,exist_ok=False);c=build(rejected=True);path=a.output/'read.sqlite'
    with P4ReadStore(path,c['genesis'],c['policy'],create=True,clock=lambda:c['now_ns']) as s:s.import_evidence(bundle(c),expected_tip=None)
    http=server(path,c['genesis'],c['policy'],port=a.port,label='Synthetic signed fixture · not a live network')
    print('http://127.0.0.1:'+str(http.server_port),flush=True)
    try:http.serve_forever()
    except KeyboardInterrupt:pass
    finally:http.server_close()
if __name__=='__main__':main()
