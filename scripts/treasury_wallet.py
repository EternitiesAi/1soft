#!/usr/bin/env python3
"""Operate one local prepared-proof journal with explicit genesis and verifier pins."""
import argparse,json,os,stat,sys
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/'src'))
from protocol6_treasury import digest,genesis_document,decode_canonical_json
from protocol6_wallet import CertifiedTreasuryJournal
from protocol6_worker import Worker
from protocol6_delivery import LoopbackSubmit

def read_input(path,limit):
    fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW)
    with os.fdopen(fd,'rb') as stream:
        info=os.fstat(stream.fileno())
        if not stat.S_ISREG(info.st_mode) or info.st_size>limit:
            raise ValueError('bounded regular input required')
        raw=stream.read(limit+1)
    if len(raw)>limit:raise ValueError('input exceeded byte bound')
    return raw

def arguments():
    p=argparse.ArgumentParser(description=__doc__)
    for name in ('journal','genesis','worker','kat'):
        p.add_argument('--'+name,type=Path,required=True)
    p.add_argument('--genesis-sha256',required=True)
    p.add_argument('--worker-sha256',required=True)
    sub=p.add_subparsers(dest='command',required=True)
    retain=sub.add_parser('retain')
    retain.add_argument('--transaction',type=Path,required=True)
    inspect=sub.add_parser('inspect')
    inspect.add_argument('--txid',required=True)
    observe=sub.add_parser('observe')
    observe.add_argument('--packet',type=Path,required=True)
    export=sub.add_parser('export')
    export.add_argument('--txid',required=True)
    export.add_argument('--output',type=Path,required=True)
    deliver=sub.add_parser('deliver-once')
    deliver.add_argument('--txid',required=True)
    deliver.add_argument('--rpc-url',required=True)
    return p.parse_args()

def main():
    a=arguments()
    try:
        raw_genesis=read_input(a.genesis,16384)
        if digest(raw_genesis)!=a.genesis_sha256:
            raise ValueError('external bootstrap genesis pin differs')
        genesis=genesis_document(raw_genesis)
        if a.worker_sha256!=genesis['worker_sha256']:
            raise ValueError('external verifier pin differs from genesis')
        transport=LoopbackSubmit(a.rpc_url) if a.command=='deliver-once' else None
        worker=Worker(a.worker,a.worker_sha256,read_input(a.kat,4008))
        with CertifiedTreasuryJournal(a.journal,expected_genesis=raw_genesis,worker=worker) as journal:
            if a.command=='retain':
                ident=journal.retain(read_input(a.transaction,4008))
                result=journal.status(ident)
            elif a.command=='inspect':
                result=journal.status(a.txid)
            elif a.command=='observe':
                packet=decode_canonical_json(read_input(a.packet,1048576),max_bytes=1048576)
                if type(packet) is not dict or set(packet)!={'witness','signed_header'}:
                    raise ValueError('closed observation packet required')
                result=journal.observe(packet['witness'],packet['signed_header'])
            elif a.command=='deliver-once':
                result=journal.deliver_once(a.txid,transport)
            else:
                raw=journal.export(a.txid)
                fd=os.open(a.output,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
                with os.fdopen(fd,'wb') as stream:stream.write(raw)
                result={'txid':a.txid,'raw_sha256':digest(raw),'purpose':'original recovery bytes; export does not authorize retry'}
        print(json.dumps({'status':'completed-local-command','result':result},sort_keys=True))
        return 0
    except Exception as exc:
        print(json.dumps({'status':'failed','error':str(exc)},sort_keys=True))
        return 1
if __name__=='__main__':raise SystemExit(main())
