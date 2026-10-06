#!/usr/bin/env python3
"""One-shot local P7 merchant; external key and disclosures only through stdin."""
import argparse,json,os,signal,sys
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1];sys.path.insert(0,str(ROOT/'src'))
from protocol7_treasury import canonical,closed_json,digest,hexbytes,genesis_shape,Unavailable
from protocol7_worker import Worker
from protocol7_notes import NoteController
from protocol7_merchant import MerchantBook
from owner_treasury_wallet import read_input

FORMAT='1soft/protocol7-merchant-command-result/v1'
OPS={'quote':{'resource','amount','payment_expiry','grant_id','generation','valid_from','valid_until'},
     'enroll':{'request','origin','opening'},'fulfill':{'request'},'inspect':{'request'}}
MAX_INPUT=2*1024*1024
class Arguments(argparse.ArgumentParser):
    def error(self,message):raise ValueError('public merchant arguments refused')
def main(argv=None):
    operation=None;mutation_entered=False
    try:
        p=Arguments(description=__doc__)
        for name in ('book','genesis','worker','kat','controller'):p.add_argument('--'+name,type=Path,required=True)
        for name in ('genesis-sha256','worker-sha256','controller-sha256','book-id','merchant-namespace','recipient'):
            p.add_argument('--'+name,required=True)
        p.add_argument('--execution-receipt',action='store_true');p.add_argument('operation',choices=sorted(OPS))
        a=p.parse_args(argv);operation=a.operation
        if os.name=='posix':
            import resource
            resource.setrlimit(resource.RLIMIT_CORE,(0,0))
        if sys.stdin.isatty():raise ValueError('protected stdin required')
        request=closed_json(sys.stdin.buffer.read(MAX_INPUT+1),MAX_INPUT)
        if type(request) is not dict or set(request)!={'key',*OPS[operation]}:raise ValueError('closed merchant input required')
        key=hexbytes(request['key'],32);rawg=read_input(a.genesis,16384)
        if digest(rawg)!=a.genesis_sha256:raise ValueError('merchant external genesis differs')
        g=genesis_shape(rawg)
        if a.worker_sha256!=g['worker_sha256']:raise ValueError('merchant external worker differs')
        worker=Worker(a.worker,a.worker_sha256,read_input(a.kat,4168))
        controller=NoteController(a.controller,a.controller_sha256,expected_genesis=rawg,worker=worker)
        if operation=='inspect' and not a.book.exists():raise ValueError('inspection cannot create merchant book')
        creating=operation=='quote' and not a.book.exists()
        if creating:mutation_entered=True
        with MerchantBook(a.book,expected_genesis=rawg,controller=controller,key=key,book_id=a.book_id,
                          merchant_namespace=a.merchant_namespace,recipient=a.recipient,
                          create=creating) as book:
            if operation=='quote':
                data={k:request[k] for k in OPS[operation]};r=data['resource']
                if type(r) is not str or len(r)%2 or not 2<=len(r)<=16384:raise ValueError('resource byte bound')
                data['resource']=hexbytes(r,len(r)//2);mutation_entered=True;result=book.create_quote(**data)
            elif operation=='enroll':
                mutation_entered=True;result=book.enroll(request['request'],request['origin'],request['opening'])
            elif operation=='fulfill':
                mutation_entered=True;result=json.loads(book.fulfill(request['request']))
            else:result=book.inspect(request['request'])
            if a.execution_receipt:result={**result,'execution':{'note_controller':controller.runs}}
        out=canonical({'format':FORMAT,'status':'completed-local-command','operation':operation,'result':result})
        if len(out)>65536:raise ValueError('merchant public output bound')
        sys.stdout.buffer.write(out+b'\n');return 0
    except (Exception,KeyboardInterrupt) as exc:
        # A failed return after entering a mutator is uncertain. Inspection may
        # reconcile an existing row; it never authorizes wallet dispatch/retry.
        out={'format':FORMAT,'status':'command-not-returned' if mutation_entered else 'command-refused',
             'operation':operation,'failure_class':'unknown' if mutation_entered else
                 ('unavailable' if isinstance(exc,(Unavailable,KeyboardInterrupt)) else 'refused'),
             'reconcile_required':mutation_entered,'retry_authorized':False}
        sys.stdout.buffer.write(canonical(out)+b'\n');return 1
def interrupted(*_):raise Unavailable('merchant command interrupted')
if __name__=='__main__':
    signal.signal(signal.SIGTERM,interrupted);raise SystemExit(main())
