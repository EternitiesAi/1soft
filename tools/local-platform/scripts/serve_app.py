#!/usr/bin/env python3
"""Gracefully stop the unchanged P4 application and its owned private socket."""
import argparse
import hashlib
from pathlib import Path
import signal
import sys
import threading

ROOT=Path(__file__).resolve().parents[3]
sys.path[:0]=[str(ROOT/'src')]
from abci_server import Server
from commit_verifier import load_json
from protocol4_abci_server import dispatch
from protocol4_abci_wire import Request,Response
from protocol4_application import Protocol4Application


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--genesis',type=Path,required=True);parser.add_argument('--genesis-sha256',required=True)
    parser.add_argument('--database',type=Path,required=True);parser.add_argument('--socket',type=Path,required=True)
    args=parser.parse_args();raw=args.genesis.read_bytes()
    if hashlib.sha256(raw).hexdigest()!=args.genesis_sha256:raise ValueError('development genesis differs')
    genesis=load_json(raw,max_bytes=131072)
    with Protocol4Application(args.database,expected_genesis=genesis) as app:
        with Server(str(args.socket),app,request_type=Request,response_type=Response,dispatcher=dispatch) as srv:
            stopping=threading.Event()
            def stop(*_):
                if not stopping.is_set():
                    stopping.set();threading.Thread(target=srv.shutdown,daemon=True).start()
            signal.signal(signal.SIGTERM,stop);signal.signal(signal.SIGINT,stop)
            srv.serve_forever(poll_interval=.1)
            if srv.failed.is_set():raise RuntimeError('P4 application failed closed')


if __name__=='__main__':main()
