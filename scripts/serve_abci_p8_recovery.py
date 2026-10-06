#!/usr/bin/env python3
"""Serve the separate P8 recovery schema on an owner-only engine socket."""
import argparse, hashlib, sys
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1];sys.path.insert(0,str(ROOT/'src'))
from abci_server import Server
from protocol8_recovery_abci import Request,Response,dispatch
from protocol8_recovery import RecoveryApplication
from protocol8_consensus import genesis_shape
from protocol8_worker import Worker

def build_parser():
    p=argparse.ArgumentParser(description=__doc__)
    for name in ('genesis','database','socket','worker','kat'):p.add_argument('--'+name,type=Path,required=True)
    p.add_argument('--genesis-sha256',required=True)
    return p

def serve(args, application_type=RecoveryApplication, **kwargs):
    if args.genesis.is_symlink() or not args.genesis.is_file() or args.genesis.stat().st_size>16384:
        raise ValueError('bounded P8 genesis required')
    raw=args.genesis.read_bytes()
    if hashlib.sha256(raw).hexdigest()!=args.genesis_sha256:raise ValueError('P8 external genesis hash differs')
    g=genesis_shape(raw)
    if args.kat.is_symlink() or not args.kat.is_file() or args.kat.stat().st_size!=3560:raise ValueError('bounded P8 KAT required')
    kat=args.kat.read_bytes()
    if hashlib.sha256(kat).hexdigest()!=g['kat_sha256']:raise ValueError('P8 KAT hash differs')
    worker=Worker(args.worker,g['worker_sha256'],kat)
    with application_type(args.database,worker,expected_genesis=raw,**kwargs) as app:
        with Server(str(args.socket),app,request_type=Request,response_type=Response,dispatcher=dispatch) as server:
            server.serve_forever(poll_interval=0.1)
            if server.failed.is_set():raise RuntimeError('P8 recovery server failed closed')

if __name__=='__main__':serve(build_parser().parse_args())
