#!/usr/bin/env python3
"""Submit one retained P8 wire locally or reconcile its signed AS-OF outcome."""
import argparse,sys
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'src'))
from protocol8_consensus import canonical
from protocol8_payment import execute

def parser():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--workspace',type=Path,required=True)
    p.add_argument('--genesis-sha256',required=True)
    p.add_argument('--credentials',type=Path,required=True)
    p.add_argument('--endpoint',required=True)
    p.add_argument('--journal',type=Path,required=True)
    p.add_argument('--txid',required=True)
    sub=p.add_subparsers(dest='command',required=True)
    sub.add_parser('submit');sub.add_parser('status')
    reconcile=sub.add_parser('reconcile');reconcile.add_argument('--packet',type=Path)
    return p

def main():
    result,code=execute(parser().parse_args());sys.stdout.buffer.write(canonical(result)+b'\n');sys.stdout.flush()
    raise SystemExit(code)
if __name__=='__main__':main()
