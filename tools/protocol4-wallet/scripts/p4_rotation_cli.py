#!/usr/bin/env python3
"""Explicit offline P4 owner replacement. Existing owner key remains required."""
import argparse
import getpass
import json
import os
from pathlib import Path
import sqlite3
import stat
import sys
import warnings

ROOT=Path(__file__).resolve().parents[3]
sys.dont_write_bytecode=True
sys.path[:0]=[str(ROOT/'src'),str(ROOT/'tools/validator-transition/src')]
for name in ('protocol4-client','protocol4-wallet','protocol4-delivery','protocol4-custody'):
    sys.path[:0]=[str(ROOT/'tools'/name/'src')]
from block_application import encode
from commit_verifier import load_json
from native_core import Reject
from p4_wallet import P4Wallet
from p4_custody import publish_new, separate_paths
from p4_evidence import MAX_EVIDENCE_BYTES


def read_input(path,limit):
    fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK|os.O_CLOEXEC)
    with os.fdopen(fd,'rb') as source:
        info=os.fstat(source.fileno())
        if not stat.S_ISREG(info.st_mode) or not 0<info.st_size<=limit:
            raise ValueError('bounded regular input required')
        raw=source.read(limit+1)
    if len(raw)>limit:raise ValueError('input grew beyond bound')
    return raw


def password():
    if not sys.stdin.isatty() or not sys.stderr.isatty():
        raise ValueError('a local terminal is required; no password argument or environment fallback')
    try:
        with warnings.catch_warnings():
            warnings.simplefilter('error',getpass.GetPassWarning)
            return getpass.getpass('Vault password: ').encode('utf-8')
    except getpass.GetPassWarning as exc:
        raise ValueError('terminal echo could not be disabled; passphrase input refused') from exc


def output_checked(args):
    if not hasattr(args,'output'):return
    separate_paths(args.wallet,args.output)
    target=os.path.abspath(args.output)
    family={target+s for s in ('','-wal','-shm','-journal')}
    for name in ('genesis','policy','review','vault','evidence'):
        source=getattr(args,name,None)
        if source is not None and family.intersection(
                os.path.abspath(source)+s for s in ('','-wal','-shm','-journal')):
            raise ValueError('input/output paths overlap')
    if args.output.exists() or args.output.is_symlink():raise ValueError('output already exists')


def main():
    p=argparse.ArgumentParser(description=__doc__)
    for name in ('genesis','policy','wallet'):p.add_argument('--'+name,required=True,type=Path)
    commands=p.add_subparsers(dest='command',required=True)
    prepare=commands.add_parser('prepare',help='review account, fee and original grants; no signing')
    prepare.add_argument('--payer',required=True);prepare.add_argument('--new-public-key',required=True)
    prepare.add_argument('--valid-until',required=True,type=int);prepare.add_argument('--output',required=True,type=Path)
    for name in ('accept','approve'):
        c=commands.add_parser(name,help='incoming consent' if name=='accept' else 'owner signature and fee hold')
        for field in ('review','vault','output'):c.add_argument('--'+field,required=True,type=Path)
        c.add_argument('--confirmation',required=True)
    for name in ('recover','status'):
        c=commands.add_parser(name,help='original signed rotation' if name=='recover' else 'fresh positive rotation evidence')
        c.add_argument('--payer',required=True);c.add_argument('--decision-id',required=True)
        c.add_argument('--'+('output' if name=='recover' else 'evidence'),required=True,type=Path)
    args=p.parse_args()
    committed=None
    try:
        output_checked(args)
        genesis=read_input(args.genesis,1024*1024)
        policy=load_json(read_input(args.policy,4096),max_bytes=4096)
        review=None
        if args.command in ('accept','approve'):
            review=load_json(read_input(args.review,32768),max_bytes=32768)
            secret=password()  # No SQLite lock spans a human password prompt.
        with P4Wallet(args.wallet,genesis,policy) as wallet:
            if args.command=='prepare':
                q=wallet.prepare_rotation(payer=args.payer,new_public_key=args.new_public_key,valid_until=args.valid_until)
                raw=encode(q['review']);result={k:v for k,v in q.items() if k!='review'}
            elif args.command=='accept':
                q=wallet.accept_rotation(review,args.confirmation,incoming_vault=args.vault,password=secret)
                raw=encode(q['review']);result={k:v for k,v in q.items() if k!='review'}
            elif args.command=='approve':
                q=wallet.approve_rotation(review,args.confirmation,owner_vault=args.vault,password=secret)
                committed=q['decision_id']
                print('Rotation saved. decision_id='+committed+'; recover this original wire if output fails.',file=sys.stderr)
                raw=encode(q['transaction']);result={k:v for k,v in q.items() if k!='transaction'}
            elif args.command=='recover':
                raw=wallet.recover(args.decision_id,payer=args.payer)
                packet=load_json(raw,max_bytes=16384)
                if packet['body']['op']['type']!='rotate_key':raise ValueError('selected decision is not a rotation')
                result={'status':'original-rotation-recovered','decision_id':args.decision_id,'signing_performed':False,'broadcast':False}
            else:
                evidence=load_json(read_input(args.evidence,MAX_EVIDENCE_BYTES),max_bytes=MAX_EVIDENCE_BYTES)
                result=wallet.rotation_status(args.decision_id,payer=args.payer,evidence=evidence)
        if hasattr(args,'output'):publish_new(args.output,raw)
        print(json.dumps(result,sort_keys=True));return 0
    except (ValueError,OSError,Reject,sqlite3.Error,EOFError,KeyError,TypeError) as exc:
        print('Rotation refused: '+str(exc),file=sys.stderr)
        if committed:print('Signed decision remains saved: '+committed+'. Recover it; do not sign again.',file=sys.stderr)
        return 2


if __name__=='__main__':raise SystemExit(main())
