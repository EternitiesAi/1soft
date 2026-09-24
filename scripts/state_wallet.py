#!/usr/bin/env python3
"""Offline attested-state wallet: sync, prepare, sign, pending, export. No broadcast."""
import argparse
import getpass
import json
import os
from pathlib import Path
import sqlite3
import sys

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/'src'))
from commit_verifier import load_json, MAX_PACKET_BYTES, encode
from native_core import require, canonical
from wallet_state import WalletState


def read_bytes(path, limit):
    with Path(path).open('rb') as source:
        raw=source.read(limit+1)
    require(len(raw)<=limit,'input exceeds allowed size')
    return raw


def write_new(path, value):
    fd=os.open(path,os.O_WRONLY|os.O_CREAT|os.O_EXCL|getattr(os,'O_NOFOLLOW',0),0o600)
    with os.fdopen(fd,'wb') as target:
        target.write(encode(value)+b'\n');target.flush();os.fsync(target.fileno())


def main(argv=None):
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--genesis',type=Path,required=True,help='Separately trusted engine genesis, never an RPC-supplied validator list')
    parser.add_argument('--genesis-sha256',required=True,help='Separately pinned digest of the exact genesis bytes')
    parser.add_argument('--workspace',type=Path,required=True,help='Private SQLite file in a directory you own with mode 0700')
    commands=parser.add_subparsers(dest='command',required=True)
    sync=commands.add_parser('sync');sync.add_argument('--packet',type=Path,required=True)
    sync.add_argument('--continuation',type=Path,help='JSON list of intermediate signed headers when catching up')
    prepare=commands.add_parser('prepare')
    prepare.add_argument('--account',required=True);prepare.add_argument('--recipient',required=True)
    prepare.add_argument('--units',type=int,required=True);prepare.add_argument('--valid-until',type=int,required=True)
    prepare.add_argument('--grant-id',default='');prepare.add_argument('--output',type=Path,required=True)
    sign=commands.add_parser('sign');sign.add_argument('--review',type=Path,required=True)
    sign.add_argument('--vault',type=Path,required=True);sign.add_argument('--output',type=Path,required=True)
    commands.add_parser('pending')
    export=commands.add_parser('export');export.add_argument('--txid',required=True);export.add_argument('--output',type=Path,required=True)
    args=parser.parse_args(argv)
    try:
        raw=read_bytes(args.genesis,1024*1024)
        with WalletState(args.workspace,raw,args.genesis_sha256) as wallet:
            if args.command=='sync':
                packet=load_json(read_bytes(args.packet,MAX_PACKET_BYTES))
                links=load_json(read_bytes(args.continuation,MAX_PACKET_BYTES)) if args.continuation else None
                result=wallet.import_state(packet,continuation=links)
            elif args.command=='prepare':
                result=wallet.build_transfer(args.account,args.recipient,args.units,
                    valid_until=args.valid_until,grant_id=args.grant_id)
                write_new(args.output,result)
            elif args.command=='sign':
                require(sys.stdin.isatty(),'signing requires an interactive terminal; no password arguments or environment unlock')
                supplied=load_json(read_bytes(args.review,20000),max_bytes=20000)
                require(type(supplied) is dict and {'body','signer_public_key','confirmation'}<=set(supplied),'invalid review document')
                fresh=wallet.review(supplied['body'],supplied['signer_public_key'])
                require(supplied['confirmation']==fresh['confirmation'],'saved review context changed; prepare again')
                print(json.dumps(fresh,indent=2,ensure_ascii=True),flush=True)
                confirmation=input('Type the full certified review digest to approve: ').strip()
                require(confirmation==fresh['confirmation'],'confirmation mismatch; no key unlocked')
                password=getpass.getpass('Vault passphrase: ').encode('utf-8')
                envelope=wallet.approve(fresh['body'],fresh['signer_public_key'],confirmation,vault=args.vault,password=password)
                write_new(args.output,envelope)
                result={'status':'signed-and-recorded-locally-not-broadcast','native_txid':fresh['native_txid'],
                        'output':str(args.output),'warning':'If output writing failed, export the saved signature from the outbox; do not create a replacement payment.'}
            elif args.command=='pending':
                result={'scope':'this local workspace only','intentions':wallet.outbox(),'network_contacted':False}
            else:
                write_new(args.output,wallet.export(args.txid))
                result={'status':'existing-envelope-exported-not-broadcast','txid':args.txid}
        print(json.dumps(result,indent=2,ensure_ascii=True))
        return 0
    except (OSError,ValueError,sqlite3.Error,EOFError) as exc:
        print('State wallet refused: '+str(exc),file=sys.stderr)
        return 2


if __name__=='__main__':raise SystemExit(main())
