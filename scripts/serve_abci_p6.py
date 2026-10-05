#!/usr/bin/env python3
"""Serve pinned static P6 treasury over an owner-only engine socket."""
import argparse,hashlib,sys
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1];sys.path.insert(0,str(ROOT/'src'))
from abci_server import Server
from protocol6_abci_server import Request,Response,dispatch
from protocol6_application import Application
from protocol6_treasury import genesis_document
from protocol6_worker import Worker
def main():
    p=argparse.ArgumentParser(description=__doc__)
    for name in ('genesis','database','socket','worker','kat'):p.add_argument('--'+name,type=Path,required=True)
    p.add_argument('--genesis-sha256',required=True);args=p.parse_args()
    raw=args.genesis.read_bytes()
    if hashlib.sha256(raw).hexdigest()!=args.genesis_sha256:raise ValueError('P6 external genesis hash differs')
    g=genesis_document(raw);kat=args.kat.read_bytes()
    if hashlib.sha256(kat).hexdigest()!=g['kat_sha256']:raise ValueError('P6 known-answer hash differs')
    w=Worker(args.worker,g['worker_sha256'],kat)
    with Application(args.database,w,expected_genesis=raw) as app:
        with Server(str(args.socket),app,request_type=Request,response_type=Response,dispatcher=dispatch) as s:
            s.serve_forever(poll_interval=0.1)
            if s.failed.is_set():raise RuntimeError('P6 server failed closed')
if __name__=='__main__':main()
