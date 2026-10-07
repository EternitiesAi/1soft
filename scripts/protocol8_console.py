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
    observe=sub.add_parser('observe');observe.add_argument('--packet',type=Path,required=True)
    imp=sub.add_parser('import-note');imp.add_argument('--opening',type=Path,required=True)
    source=imp.add_mutually_exclusive_group(required=True)
    source.add_argument('--wire',type=Path);source.add_argument('--genesis-note',action='store_true')
    imp.add_argument('--output-index',type=int,choices=(10,11),default=10)
    prep=sub.add_parser('prepare')
    for name in ('commitment','request','destination'):prep.add_argument('--'+name,required=True)
    for name in ('payment','valid-until','payment-expiry'):prep.add_argument('--'+name,type=int,required=True)
    for name in ('export','deliver'):
        cmd=sub.add_parser(name);cmd.add_argument('--txid',required=True)
        cmd.add_argument('--output',type=Path,required=True)
        if name=='deliver':cmd.add_argument('--output-index',type=int,choices=(10,11),default=10)
    for name in ('review','submit','status','reconcile'):
        cmd=sub.add_parser(name);cmd.add_argument('--txid',required=True)
        cmd.add_argument('--endpoint',required=True);cmd.add_argument('--journal',type=Path,required=True)
        if name=='reconcile':cmd.add_argument('--packet',type=Path)
    return p

def interrupted(signum,frame):raise KeyboardInterrupt

if __name__=='__main__':
    signal.signal(signal.SIGTERM,interrupted)
    _,code=execute(parser().parse_args());raise SystemExit(code)
