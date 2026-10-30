#!/usr/bin/env python3
"""PURCHASE-V0 buyer processes (Eternities Network PURCHASE-V0.md); synthetic funds, not production custody.

send     opens the buyer's wallet and submits its retained original once through the given endpoint, then prints
         the caller result. The journey kills this process right after: the buyer dies not knowing the outcome.
recover  a fresh process reopens the wallet, authenticates a supplied signed observation through native replay,
         and reconciles the original. It never sends.
verify   a fresh process with no wallet: authenticates the public history and finds the payment's exact receipt
         and request. Its report is what the Network records as the settlement's native authentication.

Wallet secrets arrive on bounded stdin, never argv, environment or logs. Public history comes from files."""
import argparse, json, sys, time
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1];sys.path.insert(0,str(ROOT/'src'))
import protocol8_transfer as n
from protocol8_worker import Worker
from protocol9_consensus import closed, genesis_document
from protocol9_certificate import verify_history
from protocol9_notes import NoteController
from protocol9_history_wallet import RecipientWallet
from protocol9_payment import send_once

VERIFY_FORMAT='eternities/onesoft-purchase-verify/v0'

def pinned(args):
    raw=args.genesis.read_bytes();n.need(len(raw)<=16384 and n.sha(raw)==args.genesis_sha256,'P9 full genesis pin')
    worker=Worker(args.worker,args.worker_sha256,args.kat.read_bytes());return raw,worker,genesis_document(raw,worker)

def wallet(args,worker,g):
    row=closed(sys.stdin.buffer.read(4097),4096)
    n.need(type(row) is dict and set(row)=={'path','key','wallet_id','recipient_secret'},'purchase closed wallet record')
    n.need(type(row['key']) is str and len(row['key'])==64,'purchase external key bound')
    controller=NoteController(args.helper,args.helper_sha256,g=g,worker=worker)
    return RecipientWallet(row['path'],key=bytes.fromhex(row['key']),wallet_id=row['wallet_id'],recipient_secret=row['recipient_secret'],controller=controller),controller

def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('mode',choices=('send','recover','verify'))
    for name in ('genesis','kat','worker'):parser.add_argument('--'+name,type=Path,required=True)
    for name in ('genesis-sha256','worker-sha256','txid'):parser.add_argument('--'+name,required=True)
    parser.add_argument('--helper',type=Path);parser.add_argument('--helper-sha256')
    parser.add_argument('--endpoint');parser.add_argument('--witness',type=Path);parser.add_argument('--header',type=Path)
    parser.add_argument('--wire',type=Path);parser.add_argument('--request')
    args=parser.parse_args()
    try:
        raw,worker,g=pinned(args)
        if args.mode=='send':
            w,_=wallet(args,worker,g);result=send_once(w,args.txid,args.endpoint)
            sys.stdout.buffer.write(n.canonical({'mode':'send','result':result})+b'\n');sys.stdout.flush()
            time.sleep(600) # the journey kills this process here: it never learns the outcome.
            return 0
        witness=json.loads(args.witness.read_bytes());header=json.loads(args.header.read_bytes())
        if args.mode=='recover':
            w,controller=wallet(args,worker,g);w.observe(witness,header);result=w.reconcile(args.txid)
            out={'mode':'recover','result':result,'inventory':w.inventory(),'worker_audit':worker.audit(),'private_process_audit':controller.audit(),'automatic_retry':False}
        else:
            wire=args.wire.read_bytes();public=n.parse(wire)
            n.need(n.txid(wire)==args.txid and public[6]==args.request,'purchase wire is not the named payment')
            cert,ledger=verify_history(witness,header,raw,worker)
            receipt=next((r for r in ledger['receipts'] if r['txid']==args.txid),None)
            out={'format':VERIFY_FORMAT,'mode':'verify','status':'executed-exact' if receipt is not None and args.request in ledger['requests'] else 'not-found',
                'txid':args.txid,'request':args.request,'receipt':receipt,'state_height':witness['height'],'app_hash':witness['app_hash'],
                'genesis_sha256':args.genesis_sha256,'worker_sha256':args.worker_sha256,'certificate_sha256':n.sha(n.canonical(cert)),
                'worker_audit':worker.audit(),'claim':'AS-OF exact certified execution of this request on this genesis; no freshness'}
        sys.stdout.buffer.write(n.canonical(out)+b'\n');return 0
    except Exception as exc:
        # Diagnostics never echo secret inputs or tracebacks.
        sys.stdout.buffer.write(n.canonical({'mode':args.mode,'status':'refused','error_type':type(exc).__name__,'error':str(exc)[:200]})+b'\n');return 1

if __name__=='__main__':raise SystemExit(main())
