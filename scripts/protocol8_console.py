#!/usr/bin/env python3
"""1soft local terminal payment console. Private review values are shown locally."""
import argparse,signal,sys
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
sys.path[:0]=[str(ROOT/'tools/payment-console/src'),str(ROOT/'src'),str(ROOT/'scripts')]
from payment_console import execute

def parser():
    p=argparse.ArgumentParser(description=__doc__)
    for name in ('workspace','credentials'):p.add_argument('--'+name,type=Path,required=True)
    p.add_argument('--genesis-sha256',required=True)
    p.add_argument('--receipt',type=Path,help='Optional new owner-only public metadata receipt; no private intent values')
    sub=p.add_subparsers(dest='command',required=True)
    for name in ('inventory','doctor'):sub.add_parser(name)
    for name in ('review','submit','status','reconcile'):
        cmd=sub.add_parser(name);cmd.add_argument('--txid',required=True)
        cmd.add_argument('--endpoint',required=True);cmd.add_argument('--journal',type=Path,required=True)
        if name=='reconcile':cmd.add_argument('--packet',type=Path)
    return p

def interrupted(signum,frame):raise KeyboardInterrupt

if __name__=='__main__':
    signal.signal(signal.SIGTERM,interrupted)
    _,code=execute(parser().parse_args());raise SystemExit(code)
