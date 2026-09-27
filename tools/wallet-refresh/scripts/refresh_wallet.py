#!/usr/bin/env python3
"""Refresh one local 1soft wallet using read-only loopback RPC; never signs/sends."""
import argparse
import json
from pathlib import Path
import sqlite3
import sys
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'src'))
from certified_wallet import CertifiedWallet
from commit_verifier import load_json
from wallet_refresh import refresh_wallet


def read(path,limit):
    with path.open('rb') as f:raw=f.read(limit+1)
    if len(raw)>limit:raise ValueError('input exceeds bound')
    return raw


def main(argv=None):
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--genesis',type=Path,required=True)
    p.add_argument('--policy',type=Path,required=True)
    p.add_argument('--journal',type=Path,required=True)
    p.add_argument('--endpoint',required=True)
    p.add_argument('--max-batches',type=int,choices=range(1,5),default=2)
    p.add_argument('--headers-per-batch',type=int,choices=range(1,65),default=64)
    a=p.parse_args(argv);wallet=None
    try:
        wallet=CertifiedWallet(a.journal,read(a.genesis,1024*1024),load_json(read(a.policy,16384),max_bytes=16384))
        report=refresh_wallet(wallet,a.endpoint,max_batches=a.max_batches,headers_per_batch=a.headers_per_batch)
        print(json.dumps(report,indent=2))
        return 0 if report['state_synced'] else 2
    except (OSError,ValueError,sqlite3.Error):
        print('Wallet refresh refused. No signing or broadcast was requested.',file=sys.stderr)
        return 2
    finally:
        if wallet is not None:wallet.close()
if __name__=='__main__':raise SystemExit(main())
