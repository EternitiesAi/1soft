#!/usr/bin/env python3
"""Offline development P4 transfer wallet. No network or administrative actions."""
import argparse
import getpass
import json
from pathlib import Path
import sqlite3
import sys

ROOT=Path(__file__).resolve().parents[1]
REPO=ROOT.parents[1]
# Resolve only this checkout; evidence and request data never choose import paths.
sys.path[:0]=[str(ROOT/'src'),str(REPO/'src'),
    str(REPO/'tools/validator-transition/src'),str(REPO/'tools/protocol4-client/src')]
from block_application import encode
from commit_verifier import load_json
from p4_evidence import MAX_EVIDENCE_BYTES,need
from p4_read_store import write_new,private_path
from p4_wallet import P4Wallet


def read(path,limit):
    with Path(path).open('rb') as f:raw=f.read(limit+1)
    need(len(raw)<=limit,'input exceeds bound')
    return raw


def main(argv=None):
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--genesis',type=Path,required=True);p.add_argument('--policy',type=Path,required=True)
    p.add_argument('--wallet',type=Path,required=True)
    sub=p.add_subparsers(dest='command',required=True)
    sub.add_parser('init');sub.add_parser('status')
    sync=sub.add_parser('sync');sync.add_argument('--evidence',type=Path,required=True)
    sync.add_argument('--expected-revision',required=True,help='Exact reviewed revision, or empty for first import')
    prepare=sub.add_parser('prepare')
    prepare.add_argument('--payer',required=True);prepare.add_argument('--to',required=True)
    prepare.add_argument('--units',type=int,required=True,help='Exact native atomic units, not USD')
    prepare.add_argument('--valid-until',type=int,required=True);prepare.add_argument('--grant',default='')
    prepare.add_argument('--output',type=Path,required=True)
    approve=sub.add_parser('approve');approve.add_argument('--review',type=Path,required=True)
    approve.add_argument('--confirmation',required=True);approve.add_argument('--vault',type=Path,required=True)
    approve.add_argument('--output',type=Path,required=True)
    recover=sub.add_parser('recover');recover.add_argument('--decision-id',required=True)
    recover.add_argument('--payer',required=True);recover.add_argument('--grant',default='')
    recover.add_argument('--output',type=Path,required=True)
    a=p.parse_args(argv);committed_id=None
    try:
        genesis=read(a.genesis,1024*1024);policy=load_json(read(a.policy,4096),max_bytes=4096)
        if hasattr(a,'output'):
            path=private_path(a.output)
            need(not path.exists(),'output already exists')
        with P4Wallet(a.wallet,genesis,policy,create=a.command=='init') as w:
            if a.command=='init':result={'status':'empty-p4-wallet-created','keys_created':False}
            elif a.command=='status':result=w.status()
            elif a.command=='sync':
                result=w.sync(load_json(read(a.evidence,MAX_EVIDENCE_BYTES),max_bytes=MAX_EVIDENCE_BYTES),
                    expected_revision=None if a.expected_revision=='empty' else a.expected_revision)
            elif a.command=='prepare':
                result=w.prepare(payer=a.payer,recipient=a.to,units=a.units,
                                 valid_until=a.valid_until,grant_id=a.grant)
                write_new(a.output,encode(result))
            elif a.command=='approve':
                proposal=load_json(read(a.review,32768),max_bytes=32768)
                # No passphrase in command arguments, environment, files or logs.
                need(sys.stdin.isatty(),'approval requires a local terminal; no echoed password fallback')
                password=getpass.getpass('Vault passphrase: ').encode('utf8')
                signed=w.approve(proposal['review'],a.confirmation,vault=a.vault,password=password)
                committed_id=signed['decision_id']
                print('Durable decision: '+committed_id,file=sys.stderr,flush=True)
                write_new(a.output, __import__('native_core').canonical(signed['transaction']))
                result={k:v for k,v in signed.items() if k!='transaction'}
            else:
                raw=w.recover(a.decision_id,payer=a.payer,grant_id=a.grant)
                write_new(a.output,raw)
                result={'status':'original-signed-bytes-exported','decision_id':a.decision_id,
                        'historical_recovery_only':True,'broadcast':False}
        print(json.dumps(result,indent=2));return 0
    except (OSError,ValueError,KeyError,TypeError,sqlite3.Error,EOFError):
        message=('Signed decision '+committed_id+' remains journaled; recover it before any further action.'
                 if committed_id else 'Wallet operation refused or incomplete. No payment outcome inferred.')
        print(message,file=sys.stderr);return 2

if __name__=='__main__':raise SystemExit(main())
