#!/usr/bin/env python3
"""Protected P8 local wallet commands. Secrets are private files, never arguments."""
import argparse,sys
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'src'))
from protocol8_consensus import canonical
from protocol8_wallet_cli import execute

def parser():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--workspace',type=Path,required=True)
    p.add_argument('--genesis-sha256',required=True)
    p.add_argument('--credentials',type=Path,required=True)
    sub=p.add_subparsers(dest='command',required=True)
    init=sub.add_parser('init')
    for name in ('genesis','kat','worker','helper','prover','wallet'):init.add_argument('--'+name,type=Path,required=True)
    for name in ('helper-sha256','prover-sha256'):init.add_argument('--'+name,required=True)
    for name in ('doctor','inventory'):sub.add_parser(name)
    observe=sub.add_parser('observe');observe.add_argument('--packet',type=Path,required=True)
    imp=sub.add_parser('import-note');imp.add_argument('--opening',type=Path,required=True)
    source=imp.add_mutually_exclusive_group(required=True)
    source.add_argument('--wire',type=Path);source.add_argument('--genesis-note',action='store_true')
    imp.add_argument('--output-index',type=int,choices=(10,11),default=10)
    prep=sub.add_parser('prepare')
    for name in ('commitment','request','destination'):prep.add_argument('--'+name,required=True)
    for name in ('payment','valid-until','payment-expiry'):prep.add_argument('--'+name,type=int,required=True)
    for name in ('mark-attempt','reconcile','export','deliver','review'):
        cmd=sub.add_parser(name);cmd.add_argument('--txid',required=True)
        if name in ('export','deliver','review'):cmd.add_argument('--output',type=Path,required=True)
        if name=='deliver':cmd.add_argument('--output-index',type=int,choices=(10,11),default=10)
    return p

def main():
    result,status=execute(parser().parse_args());sys.stdout.buffer.write(canonical(result)+b'\n');sys.stdout.flush()
    raise SystemExit(status)
if __name__=='__main__':main()
