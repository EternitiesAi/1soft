#!/usr/bin/env python3
"""Explicit P4 decision delivery on loopback; never accepts a key or raw transaction."""
import argparse
import json
from pathlib import Path
import sqlite3
import sys

ROOT=Path(__file__).resolve().parents[3]
sys.path[:0]=[str(ROOT/'src'),str(ROOT/'tools/validator-transition/src'),
              str(ROOT/'tools/protocol4-client/src'),str(ROOT/'tools/protocol4-wallet/src'),
              str(ROOT/'tools/protocol4-delivery/src')]
from block_application import encode
from commit_verifier import load_json
from p4_delivery import P4Delivery
from p4_evidence import MAX_EVIDENCE_BYTES,need
from p4_read_store import write_new


def read(path,limit):
    with path.open('rb') as f:raw=f.read(limit+1)
    need(len(raw)<=limit,'bounded input required')
    return raw


def main(argv=None):
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--genesis',type=Path,required=True);p.add_argument('--policy',type=Path,required=True)
    p.add_argument('--wallet',type=Path,required=True);p.add_argument('--journal',type=Path,required=True)
    p.add_argument('--endpoint',required=True)
    sub=p.add_subparsers(dest='command',required=True)
    sub.add_parser('init')
    for cmd in ('prepare','inspect','collect','import-receipt','export-receipt','reconcile'):
        c=sub.add_parser(cmd);c.add_argument('--decision-id',required=True);c.add_argument('--payer',required=True)
        c.add_argument('--grant',default='')
        if cmd in ('prepare','export-receipt'):c.add_argument('--output',type=Path,required=True)
        if cmd=='import-receipt':c.add_argument('--evidence',type=Path,required=True)
        if cmd=='reconcile':c.add_argument('--expected-revision',required=True)
    c=sub.add_parser('send');c.add_argument('--review',type=Path,required=True);c.add_argument('--confirmation',required=True)
    a=p.parse_args(argv)
    try:
        genesis=read(a.genesis,1024*1024);policy=load_json(read(a.policy,4096),max_bytes=4096)
        with P4Delivery(a.wallet,a.journal,genesis,policy,a.endpoint,create=a.command=='init') as d:
            if a.command=='init':result={'status':'delivery-journal-created','wallet_created':False,'submission_performed':False}
            elif a.command=='send':
                wrapper=load_json(read(a.review,32768),max_bytes=32768)
                result=d.send(wrapper['review'],a.confirmation)
            else:
                selection={'payer':a.payer,'grant_id':a.grant};did=a.decision_id
                if a.command=='prepare':
                    result=d.prepare(did,**selection);write_new(a.output,encode(result))
                    result={'status':'delivery-reviewed','confirmation':result['confirmation'],'submission_performed':False}
                elif a.command=='inspect':result=d.inspect(did,**selection)
                elif a.command=='collect':result=d.collect(did,**selection)
                elif a.command=='import-receipt':
                    result=d.import_receipt(did,load_json(read(a.evidence,MAX_EVIDENCE_BYTES),max_bytes=MAX_EVIDENCE_BYTES),**selection)
                elif a.command=='export-receipt':
                    evidence=d.export_receipt(did,**selection);write_new(a.output,encode(evidence))
                    result={'status':'historical-receipt-exported','wallet_reservations_changed':False}
                else:result=d.reconcile(did,**selection,expected_revision=a.expected_revision)
        print(json.dumps(result,indent=2))
        return 2 if result.get('status')=='unavailable' or result.get('transport_observation') in ('unresolved','endpoint_declined') else 0
    except (OSError,ValueError,KeyError,TypeError,sqlite3.Error):
        print('P4 delivery did not complete. A durable attempt or wallet progress may exist; inspect before continuing. No automatic resend.',file=sys.stderr)
        return 2

if __name__=='__main__':raise SystemExit(main())
