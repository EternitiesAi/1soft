#!/usr/bin/env python3
"""One entry point for the bounded 1soft local developer release."""
import argparse
import getpass
import os
from pathlib import Path
import signal
import sys
import threading
sys.dont_write_bytecode=True

ROOT=Path(__file__).resolve().parents[3]
sys.path[:0]=[str(ROOT/p) for p in ('src','scripts','tools/validator-transition/src',
    'tools/protocol4-client/src','tools/protocol4-wallet/src','tools/protocol4-delivery/src',
    'tools/protocol4-explorer/src','tools/protocol4-receipts/src','tools/local-platform/src')]
from block_application import encode
from p4_evidence import need
from local_devnet import initialize,LocalNetwork,load_configuration,PIN_SHA
from platform_http import server


def password(confirm=False):
    first=getpass.getpass('Development vault password (16+ characters): ').encode('utf-8')
    if confirm:need(first==getpass.getpass('Repeat password: ').encode('utf-8'),'passwords differ')
    return first


def main():
    os.umask(0o077)
    parser=argparse.ArgumentParser(description=__doc__)
    sub=parser.add_subparsers(dest='command',required=True)
    for name in ('new','init','start','status'):
        p=sub.add_parser(name);p.add_argument('--workspace',type=Path,required=True)
        if name!='status':p.add_argument('--engine',type=Path,required=True)
        if name in ('new','start'):p.add_argument('--port',type=int,default=0)
    p=sub.add_parser('qualify');p.add_argument('--engine',type=Path,required=True)
    p.add_argument('--output',type=Path,required=True)
    args=parser.parse_args()
    if args.command=='qualify':
        from release_check import qualify
        result=qualify(args.engine,args.output)
        print(encode(result).decode());return 0 if result['status']=='passed' else 1
    if args.command=='status':
        cfg=load_configuration(args.workspace)
        print(encode({'status':'retained_workspace_inspected','chain_id':cfg['chain_id'],
            'genesis_sha256':cfg['genesis_sha256'],'endpoint':cfg['endpoint'],
            'ready_marker_present':(args.workspace/'READY.json').is_file(),
            'running_state':'not probed','data_modified':False,'trust_renewed':False}).decode());return 0
    secret=None
    if args.command in ('new','init'):
        secret=password(confirm=True);initialize(args.workspace,args.engine,PIN_SHA,password=secret)
        if args.command=='init':
            print(encode({'status':'private_development_workspace_initialized','ready':False,
                'next':'start with the same workspace and engine; original password required once'}).decode());return 0
    stopped=threading.Event()
    signal.signal(signal.SIGINT,lambda *_:stopped.set());signal.signal(signal.SIGTERM,lambda *_:stopped.set())
    net=LocalNetwork(args.workspace,args.engine);web=None
    try:
        if not net.ready() and secret is None:secret=password()
        net.start()
        if not net.ready():net.bootstrap(password=secret)
        secret=None
        web=server(net.service,port=args.port);web.timeout=.25
        print(encode({'status':'local_development_wallet_running','url':f'http://127.0.0.1:{web.server_port}/',
            'validator_count':4,'workspace':str(net.root),'genesis_sha256':net.config['genesis_sha256'],
            'rpc_collection_height_limit':64,'real_funds_supported':False,
            'shutdown':'Ctrl+C stops only owned processes and preserves data'}).decode(),flush=True)
        while not stopped.is_set():
            net.health();web.handle_request()
    finally:
        secret=None
        if web is not None:web.server_close()
        result=net.stop();print(encode(result).decode(),flush=True)
    return 0


if __name__=='__main__':
    try:raise SystemExit(main())
    except (ValueError,OSError,RuntimeError):
        print('1soft refused or could not finish this local operation. Original files and obligations are retained; inspect the private workspace. No reset or trust renewal was performed.',file=sys.stderr)
        raise SystemExit(1)
