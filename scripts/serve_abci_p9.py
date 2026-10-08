#!/usr/bin/env python3
"""Owner-only private segmented recipient application; no public binding."""
import argparse
import sys
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1];sys.path.insert(0,str(ROOT/'src'))
import protocol8_transfer as n
from protocol9_consensus import genesis_shape
from protocol9_application import Application
from protocol9_abci_server import Request,Response,dispatch
from protocol8_worker import Worker
from abci_server import Server

def main():
    p=argparse.ArgumentParser(description=__doc__)
    for key in ('genesis','database','socket','worker','kat'):p.add_argument('--'+key,type=Path,required=True)
    p.add_argument('--genesis-sha256',required=True);args=p.parse_args()
    n.need(not args.genesis.is_symlink() and args.genesis.is_file() and args.genesis.stat().st_size<=16384,'P9 genesis file')
    raw=args.genesis.read_bytes();n.need(n.sha(raw)==args.genesis_sha256,'P9 external genesis digest differs');g=genesis_shape(raw)
    n.need(not args.kat.is_symlink() and args.kat.is_file() and args.kat.stat().st_size==3560,'P9 KAT file')
    kat=args.kat.read_bytes();n.need(n.sha(kat)==g['kat_sha256'],'P9 KAT digest differs')
    worker=Worker(args.worker,g['worker_sha256'],kat)
    with Application(args.database,worker,expected_genesis=raw) as app:
        with Server(str(args.socket),app,request_type=Request,response_type=Response,dispatcher=dispatch) as server:
            server.serve_forever(poll_interval=0.1)
            if server.failed.is_set():raise RuntimeError('P9 application failed closed')

if __name__=='__main__':main()
