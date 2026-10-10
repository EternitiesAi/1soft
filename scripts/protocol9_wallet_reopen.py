#!/usr/bin/env python3
"""Reopen externally keyed P9 wallets in a fresh process; no submission.

Private keys/recipient secrets arrive through bounded stdin, never argv, logs,
environment or a generated key file. This does not establish production custody.
"""
import argparse, sys
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1];sys.path.insert(0,str(ROOT/'src'))
import protocol8_transfer as n
from protocol8_worker import Worker
from protocol9_consensus import closed, genesis_document
from protocol9_notes import NoteController
from protocol9_wallet import RecipientWallet

def main():
    parser=argparse.ArgumentParser(description=__doc__)
    for name in ('genesis','kat','worker','helper'):parser.add_argument('--'+name,type=Path,required=True)
    for name in ('genesis-sha256','worker-sha256','helper-sha256'):parser.add_argument('--'+name,required=True)
    args=parser.parse_args()
    try:
        data=closed(sys.stdin.buffer.read(16385),16384)
        n.need(type(data) is list and 1<=len(data)<=2,'P9 explicit reopen inputs')
        raw=args.genesis.read_bytes();n.need(len(raw)<=16384 and n.sha(raw)==args.genesis_sha256,'P9 full genesis pin')
        worker=Worker(args.worker,args.worker_sha256,args.kat.read_bytes());g=genesis_document(raw,worker)
        controller=NoteController(args.helper,args.helper_sha256,g=g,worker=worker);out=[]
        for row in data:
            n.need(type(row) is dict and set(row)=={'path','key','wallet_id','recipient_secret','txid'},'P9 closed reopen record')
            n.need(type(row['key']) is str and len(row['key'])==64,'P9 external key bound')
            wallet=RecipientWallet(row['path'],key=bytes.fromhex(row['key']),wallet_id=row['wallet_id'],recipient_secret=row['recipient_secret'],controller=controller)
            out.append({'inventory':wallet.inventory(),'result':wallet.reconcile(row['txid'])})
        result={'format':'1soft/protocol9-cold-process/v1','status':'reopened-authenticated','wallets':out,
            'worker_audit':worker.audit(),'private_process_audit':controller.audit(),'automatic_retry':False}
        sys.stdout.buffer.write(n.canonical(result)+b'\n');return 0
    except Exception as exc:
        # Diagnostics never echo secret inputs or tracebacks.
        sys.stdout.buffer.write(n.canonical({'format':'1soft/protocol9-cold-process/v1','status':'refused','error_type':type(exc).__name__})+b'\n');return 1

if __name__=='__main__':raise SystemExit(main())
