#!/usr/bin/env python3
"""One-shot trusted-local P7 restricted-change custody; private inputs only on stdin."""
import argparse,json,os,signal,stat,sys
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1];sys.path.insert(0,str(ROOT/'src'))
from protocol7_treasury import canonical,closed_json,digest,genesis_shape,hexbytes,Unavailable
from protocol7_worker import Worker
from protocol7_prover import Prover
from protocol7_notes import NoteController
from protocol7_vault import ChangeVault
from protocol7_wallet import CertifiedTreasuryJournal
from owner_treasury_wallet import read_input

OPS={'create':set(),'inventory':set(),'import-change':{'txid','opening'},
     'prepare':{'commitment','authority','amount','valid_until','request'},
     'prepare-retained':{'source_txid','amount','valid_until','request'},
     'recover-prepared':{'commitment'},'import-prepared':{'txid'}}
PROVING_OPS={'prepare','prepare-retained'}
MAX_INPUT=8192
MAX_OUTPUT=32768 # optional public process receipts, never private requests
FORMAT='1soft/protocol7-custody-command-result/v1'
class Arguments(argparse.ArgumentParser):
    def error(self,message):raise ValueError('public command arguments refused')

def arguments(argv=None):
    p=Arguments(description=__doc__)
    for name in ('journal','vault','genesis','worker','kat','controller'):
        p.add_argument('--'+name,type=Path,required=True)
    for name in ('genesis-sha256','worker-sha256','controller-sha256','vault-id'):
        p.add_argument('--'+name,required=True)
    p.add_argument('--prover',type=Path);p.add_argument('--prover-sha256')
    p.add_argument('--execution-receipt',action='store_true')
    p.add_argument('operation',choices=sorted(OPS));return p.parse_args(argv)

def main(argv=None):
    operation=None;prepare_entered=False
    try:
        a=arguments(argv);operation=a.operation
        if sys.stdin.isatty():raise ValueError('private input requires a protected pipe')
        raw=sys.stdin.buffer.read(MAX_INPUT+1)
        request=closed_json(raw,MAX_INPUT)
        if type(request) is not dict or set(request)!={'key',*OPS[operation]}:
            raise ValueError('closed private command required')
        key=hexbytes(request['key'],32)
        if not any(key):raise ValueError('nonzero external key required')
        if operation in PROVING_OPS:
            if a.prover is None or a.prover_sha256 is None:raise ValueError('explicit measured prover required')
            hexbytes(a.prover_sha256,32)
        elif a.prover is not None or a.prover_sha256 is not None:raise ValueError('unused prover configuration refused')
        for value in (a.genesis_sha256,a.worker_sha256,a.controller_sha256,a.vault_id):hexbytes(value,32)
        rawg=read_input(a.genesis,16384)
        if digest(rawg)!=a.genesis_sha256:raise ValueError('external genesis pin differs')
        g=genesis_shape(rawg)
        if a.worker_sha256!=g['worker_sha256']:raise ValueError('external worker pin differs')
        # The caller must initialize/authenticate its canonical journal through
        # the journal interface. Creating a vault does not create a new journal.
        s=a.journal.lstat()
        if not stat.S_ISREG(s.st_mode) or s.st_uid!=os.geteuid() or s.st_nlink!=1 or stat.S_IMODE(s.st_mode)!=0o600:
            raise ValueError('existing private canonical journal required')
        worker=Worker(a.worker,a.worker_sha256,read_input(a.kat,4168))
        controller=NoteController(a.controller,a.controller_sha256,expected_genesis=rawg,worker=worker)
        with CertifiedTreasuryJournal(a.journal,expected_genesis=rawg,worker=worker) as journal:
            vault=ChangeVault(a.vault,key=key,expected_vault_id=a.vault_id,controller=controller,create=operation=='create')
            if operation in ('create','inventory'):result=vault.inventory()
            elif operation=='import-change':
                commitment=vault.import_change(journal,request['txid'],request['opening'])
                result={'commitment':commitment,'revision':vault.inventory()['revision']}
            elif operation in PROVING_OPS:
                prover=Prover(a.prover,a.prover_sha256,expected_genesis=rawg,worker=worker)
                prepare_entered=True
                if operation=='prepare':
                    ident=vault.prepare_payment(journal,prover,request['commitment'],authority=request['authority'],
                         amount=request['amount'],valid_until=request['valid_until'],request=request['request'])
                else:
                    ident=vault.prepare_retained_change(journal,prover,request['source_txid'],
                         amount=request['amount'],valid_until=request['valid_until'],request=request['request'])
                result={'txid':ident,'attempts':journal.status(ident)['attempts'],
                        'request':request['request'],'raw_sha256':digest(journal.export(ident))}
            elif operation=='recover-prepared':
                ident=vault.recover_prepared(journal,request['commitment'])
                result={'txid':ident,'raw_sha256':digest(journal.export(ident))}
            else:
                commitment=vault.import_prepared_change(journal,request['txid'])
                result={'commitment':commitment,'revision':vault.inventory()['revision']}
            if a.execution_receipt:
                result['execution']={'note_controller':controller.runs}
                if operation in PROVING_OPS:result['execution']['prover']=prover.last_run
        response={'format':FORMAT,'status':'completed-local-command','operation':operation,'result':result}
        encoded=canonical(response)
        if len(encoded)>MAX_OUTPUT:raise ValueError('public response bound')
        sys.stdout.buffer.write(encoded+b'\n');return 0
    except (Exception,KeyboardInterrupt) as exc:
        response={'format':FORMAT,'status':'prepare-not-returned' if prepare_entered else 'command-refused',
                  'operation':operation,'failure_class':'unknown' if prepare_entered else ('unavailable' if isinstance(exc,(Unavailable,KeyboardInterrupt)) else 'refused'),
                  'reconcile_required':prepare_entered}
        # Exception strings, private request bytes and decrypted payload never
        # enter this diagnostic. Once prepare is entered, conservatively inspect
        # and reconcile; this does not itself prove a durable stage exists.
        # Unknown prepare outcomes are not safe retries.
        sys.stdout.buffer.write(canonical(response)+b'\n');return 1
def interrupted(*_):raise Unavailable('local command interrupted')
if __name__=='__main__':
    signal.signal(signal.SIGTERM,interrupted)
    raise SystemExit(main())
