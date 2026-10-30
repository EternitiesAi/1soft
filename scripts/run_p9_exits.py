#!/usr/bin/env python3
"""The two P9 wallet exits, on four validators of one host (10-30). Found by a simulated developer's crash drills.

1. A proof cut off after the hold is persisted (injected: the prover dies once) leaves a hold with no wire. A cold
   wallet resumes it from the retained request; prepare and release stay refused.
2. An attempt marked whose wire never left (the caller died before I/O) stays unresolved-held while its window is
   open, then reconciles as expired-unexecuted from a certified observation past valid_until. release_expired frees
   the input; the stale wire broadcast afterwards never executes; a new payment for the same intent executes once.
Synthetic funds and keys; not production readiness."""
import argparse, base64, json, os, signal, subprocess, sys
from pathlib import Path
from unittest.mock import patch
ROOT=Path(__file__).resolve().parents[1];sys.path.insert(0,str(ROOT/'src'))
import protocol8_transfer as n
from protocol8_worker import Worker
from protocol9_consensus import GENESIS_FORMAT, bootstrap_digest, genesis_document
from protocol9_certificate import export_history, verify_history
from protocol9_notes import NoteController, Prover
from protocol9_history_wallet import RecipientWallet
from protocol9_payment import send_once
from run_protocol9_engine import Network, source
from run_protocol8_engine import field
from run_protocol5_engine import ENGINE_SHA256
from run_devnet import rpc, wait_until

CHECKS=('source_clean','engine_identity','four_validators_initialized','proof_cut_off_leaves_unproven_hold',
    'unproven_hold_refuses_prepare_and_export','cold_resume_proves_retained_request','resume_refused_once_proven',
    'attempt_marked_never_sent','open_window_stays_unresolved','release_refused_while_open',
    'closed_window_reconciles_expired_unexecuted','release_frees_input_and_intent','stale_wire_never_executes',
    'same_intent_paid_once_after_release','native_processes_reaped','workers_stopped','source_unchanged')

class Died(BaseException):pass

def run(args):
    output=args.output.absolute();n.need(not output.exists(),'fresh exits receipt')
    before=source();report={'format':'1soft/p9-wallet-exits/v0','status':'failed','source':before,'checks':[],'inputs':{},'native_processes':[],
        'claims':{'synthetic_funds':True,'one_host_four_validators':True,'proof_interruption_injected':True,'independent_operators':False,
        'public_network':False,'freshness':False,'external_review':False}}
    network=None;workers=[];private=[]
    def check(name,ok,evidence=None):
        report['checks'].append({'id':name,'passed':bool(ok),'evidence':evidence or {}})
        print('EXITS_CHECK '+name+' '+str(bool(ok)),flush=True);n.need(ok,'exits gate failed: '+name)
    def refused(call):
        try:call();return False
        except n.Invalid:return True
    def fixture(op,bootstrap):
        fd=os.open(args.fixture,os.O_RDONLY|os.O_NOFOLLOW);child=None
        try:
            child=subprocess.Popen(['/proc/self/fd/'+str(fd),op],stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=subprocess.PIPE,env={},pass_fds=(fd,),start_new_session=True)
            out,err=child.communicate(bootstrap,timeout=45)
            n.need(child.returncode==0 and not err and len(out)<=1160,'P9 fixture output');return out
        finally:
            if child:
                try:os.killpg(child.pid,signal.SIGKILL)
                except ProcessLookupError:pass
                child.communicate();report['native_processes'].append({'operation':op,'pid':child.pid,'exit_code':child.returncode,'process_reaped':child.poll() is not None})
            os.close(fd)
    def observation(label):
        held=network.hold_sources_without_quorum();witness=export_history(network.runtime/'app0/state.sqlite')
        n.need(witness['height']==held['height'] and witness['app_hash']==held['app_hash'],'P9 history export checkpoint race')
        network.start_engine(2);network.start_engine(3)
        wait_until(lambda:network.height(0)>=witness['height']+1,120)
        signed=rpc(network.http[0],'commit',{'height':str(witness['height']+1)})['signed_header']
        network.hold_sources_without_quorum()
        _,ledger=verify_history(witness,signed,raw,w)
        report.setdefault('observations',[]).append({'label':label,'height':witness['height'],'app_hash':witness['app_hash']})
        return witness,signed,ledger
    def advance(height):
        network.start_engine(2);network.start_engine(3);wait_until(lambda:network.height(0)>=height,300)
    try:
        check('source_clean',before['clean'])
        for name in ('engine','worker','helper','fixture','prover'):
            path=getattr(args,name);n.need(path.is_file() and not path.is_symlink(),'P9 binary input')
            report['inputs'][name]={'sha256':n.sha(path.read_bytes()),'bytes':path.stat().st_size}
        check('engine_identity',report['inputs']['engine']['sha256']==ENGINE_SHA256 and subprocess.check_output([str(args.engine),'version'],text=True).strip()=='0.38.25')
        seed=Worker(args.worker,report['inputs']['worker']['sha256'],args.kat.read_bytes());workers.append(seed)
        network=Network({'engine':args.engine,'worker':args.worker},output,report)
        vals=sorted([{'public_key':base64.b64decode(v['pub_key']['value'],validate=True).hex(),'power':int(v['power'])} for v in network.engine_genesis['validators']],key=lambda v:v['public_key'])
        g={'format':GENESIS_FORMAT,'protocol_version':9,'chain_id':network.chain_id,'profile_sha256':n.PROFILE_SHA256,
            'worker_sha256':seed.sha256,'kat_sha256':seed.kat_sha256,'validators':vals,'pool_id':os.urandom(32).hex(),
            'network':field(1),'asset':field(2),'mission':field(3),'fee':1,'notes':[]}
        bootstrap=bytes.fromhex(bootstrap_digest(g));g['network']=seed.network_domain(bootstrap)
        note=fixture('genesis-note',bootstrap);g['notes']=[{'kind':'p8-recipient-v1','commitment':note.hex()}]
        controller=NoteController(args.helper,report['inputs']['helper']['sha256'],g=g,worker=seed)
        prover=Prover(args.prover,report['inputs']['prover']['sha256'],g=g,worker=seed);private.extend((controller,prover))
        request=bytearray(fixture('first',bootstrap))
        try:first=prover.produce(bytes(request))
        finally:request[:]=bytes(len(request))
        g['kat_sha256']=n.sha(first);raw=n.canonical(g);w=Worker(args.worker,g['worker_sha256'],first);workers.append(w)
        genesis_document(raw,w);controller.worker=w;prover.worker=w
        fixtures=network.runtime/'public-proofs';fixtures.mkdir(mode=0o700);network.paths.update(fixtures=fixtures,kat=fixtures/'kat.tx')
        (fixtures/'genesis.json').write_bytes(raw);(fixtures/'kat.tx').write_bytes(first)
        network.install_genesis(raw,w);network.start_sources();wait_until(lambda:all(network.direct_state(i)['height']>=1 for i in range(4)),120)
        check('four_validators_initialized',all(network.direct_state(i)['genesis']==g for i in range(4)))
        initial,signed,_=observation('initial')
        homes=network.runtime/'wallets';homes.mkdir(mode=0o700)
        keys={'buyer':os.urandom(32),'provider':os.urandom(32)};ids={k:os.urandom(32).hex() for k in keys};secrets={'buyer':field(31),'provider':field(41)}
        open_wallet=lambda name,create=False:RecipientWallet(homes/name,key=keys[name],wallet_id=ids[name],recipient_secret=secrets[name],controller=controller,create=create)
        buyer=open_wallet('buyer',True);provider=open_wallet('provider',True)
        for x in (buyer,provider):x.observe(initial,signed)
        buyer.import_note(note.hex(),{'origin':field(111),'value':1000,'expiry':100000,'note_secret':field(32),'blind':field(33)},genesis=True)
        req=field(777);dest=provider.recipient_key;short=initial['height']+8

        # 1. the proof is cut off once, after the hold is persisted
        with patch.object(prover,'produce',side_effect=Died()):
            try:buyer.prepare(prover,note.hex(),request=req,destination=dest,payment=80,valid_until=short,payment_expiry=100000);died=False
            except Died:died=True
        cold=open_wallet('buyer');held=cold.inventory()['obligations']
        check('proof_cut_off_leaves_unproven_hold',died and held==[{'input':note.hex(),'request':req,'txid':None,'attempts':0,'completed':False}])
        check('unproven_hold_refuses_prepare_and_export',refused(lambda:cold.prepare(prover,note.hex(),request=req,destination=dest,payment=80,valid_until=short,payment_expiry=100000)) and
            refused(lambda:cold.export('00'*32)))
        ident=cold.resume(prover,req);wire=cold.export(ident)
        check('cold_resume_proves_retained_request',n.parse(wire)[6]==req and n.integer(n.parse(wire)[8])==short and cold.inventory()['obligations'][0]['txid']==ident,{'txid':ident})
        check('resume_refused_once_proven',refused(lambda:cold.resume(prover,req)))

        # 2. the attempt is marked and the caller dies before any byte leaves
        cold.mark_attempt(ident)
        check('attempt_marked_never_sent',refused(lambda:send_once(cold,ident,'http://127.0.0.1:'+str(network.http[0]))) and cold.inventory()['obligations'][0]['attempts']==1)
        mid,signed,_=observation('window-open');cold.observe(mid,signed)
        r=cold.reconcile(ident)
        check('open_window_stays_unresolved',mid['height']<short and r['status']=='unresolved-held',{'as_of_height':mid['height'],'valid_until':short})
        check('release_refused_while_open',refused(lambda:cold.release_expired(ident)))
        advance(short+1);late,signed,_=observation('window-closed');cold.observe(late,signed)
        r=cold.reconcile(ident)
        check('closed_window_reconciles_expired_unexecuted',late['height']>=short and r['status']=='expired-unexecuted' and r['valid_until']==short,{'as_of_height':late['height'],'result':r})
        released=cold.release_expired(ident)
        check('release_frees_input_and_intent',released['status']=='released-expired' and cold.inventory()['obligations']==[] and cold.inventory()['notes']==[note.hex()])

        # the stale wire is broadcast anyway (a lost copy, an attacker): it can never execute
        try:report['stale_admission_code']=int(network.broadcast(0,wire)['code'])
        except Exception as exc:report['stale_admission_code']=type(exc).__name__
        until=late['height']+4
        ident2=cold.prepare(prover,note.hex(),request=req,destination=dest,payment=80,valid_until=100000,payment_expiry=100000)
        sent=send_once(cold,ident2,'http://127.0.0.1:'+str(network.http[0]))
        advance(until);wait_until(lambda:all(network.direct_state(i)['checkpoint']['accepted_count']==1 for i in range(4)),240)
        done,signed,ledger=observation('paid');cold.observe(done,signed)
        receipts=[x['txid'] for x in ledger['receipts']]
        check('stale_wire_never_executes',ident not in receipts,{'stale_admission_code':report['stale_admission_code']})
        r=cold.reconcile(ident2)
        check('same_intent_paid_once_after_release',ident2!=ident and sent['outcome']=='admission-accepted' and r['status']=='executed-exact' and
            receipts==[ident2] and req in ledger['requests'],{'txid':ident2,'receipts':receipts})
        report['worker_audits']=[{'node':i,**network.worker_audit(i)} for i in range(4)]+[{'node':'wallet-'+str(i),**x.audit()} for i,x in enumerate(workers)]
        report['private_process_audits']=[item.audit() for item in private]
        audits=report['worker_audits']+report['private_process_audits']
        check('native_processes_reaped',all(a['call_count']==a['reaped_count'] and a['timeout_count']==0 for a in audits) and all(r['process_reaped'] for r in report['native_processes']))
    except Exception as exc:
        report['error']={'type':type(exc).__name__,'message':str(exc)}
    finally:
        if network:
            try:network.close();check('workers_stopped',all(type(p.get('exit_code')) is int for p in report['processes']))
            except Exception as exc:report['cleanup_error']={'type':type(exc).__name__,'message':str(exc)}
        report['checks'].append({'id':'source_unchanged','passed':source()==before,'evidence':{}})
        if tuple(c['id'] for c in report['checks'])==CHECKS and all(c['passed'] for c in report['checks']) and not report.get('cleanup_error'):report['status']='qualified-one-host-p9-exits'
        output.write_bytes(n.canonical(report)+b'\n')
    return 0 if report['status']=='qualified-one-host-p9-exits' else 1

if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__)
    for name in ('engine','worker','helper','fixture','prover','kat','output'):parser.add_argument('--'+name,type=Path,required=True)
    raise SystemExit(run(parser.parse_args()))
