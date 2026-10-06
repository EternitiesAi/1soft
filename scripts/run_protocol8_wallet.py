#!/usr/bin/env python3
"""Fresh four-validator synthetic recipient wallet/import/preparation/recovery gate."""
from __future__ import annotations
import argparse,base64,copy,json,os,signal,subprocess,sys,time
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1];sys.path.insert(0,str(ROOT/'src'))
import protocol8_transfer as n
from protocol8_consensus import canonical,digest,bootstrap_digest,genesis_document,GENESIS_FORMAT,PROFILE_SHA256
from protocol8_worker import Worker
from protocol8_notes import NoteController
from protocol8_prover import Prover
from protocol8_wallet import RecipientWallet
from protocol8_certificate import verify_state
from run_protocol8_engine import Network,source as consensus_source,field
from run_protocol5_engine import ENGINE_SHA256,_hold_transaction_height
from run_devnet import rpc,wait_until
CHECKS=('source_clean','engine_identity','fresh_native_receive_proof','four_validators_receive',
 'signed_receive_state','opening_mutations_refused','encrypted_import_cold_reopen','duplicate_import_idempotent',
 'native_arbitrary_spend_prepared','original_input_intent_held','unresolved_original_held',
 'one_attempt_reply_discarded','exact_spend_four_validator_agreement','signed_exact_recovery',
 'recovery_cold_reopen_idempotent','recipient_private_delivery_import','certified_conflict_held',
 'certificate_rollback_tamper_refused','private_material_absent','native_processes_reaped','workers_stopped','source_unchanged')
CLAIMS={'one_host_four_validators':True,'native_arbitrary_recipient_spend':True,'encrypted_private_store':True,
 'exact_certified_receive_import':True,'lost_rpc_reply_exact_recovery':True,'certified_conflict_held':True,
 'as_of_only':True,'automatic_retry':False,'freshness_established':False,'production_ready':False,
 'real_funds':False,'public_network':False,'state_sync_qualified':False,'hostile_host_custody':False,
 'local_rollback_resistance':False,'recipient_discovery':False,'p7_migration':False,'independent_cryptographic_audit':False}
def source():
    out=consensus_source()
    for p in sorted((ROOT/'tools/recipient-wallet').rglob('*')):
        if p.is_file():out['files'][p.relative_to(ROOT).as_posix()]={'bytes':p.stat().st_size,'sha256':digest(p.read_bytes())}
    out['files']=dict(sorted(out['files'].items()));return out
def run(args):
    output=args.output.absolute();n.need(not output.exists() and not output.with_name(output.name+'.artifacts').exists(),'fresh wallet output required')
    before=source();report={'format':'1soft/protocol8-recipient-wallet-gate/v1','status':'failed','source':before,
        'claims':CLAIMS.copy(),'checks':[],'inputs':{},'native_processes':[],'worker_audits':[]};network=None;controllers=[];workers=[]
    secrets=[]
    def check(ident,ok,evidence=None):
        report['checks'].append({'id':ident,'passed':bool(ok),'evidence':evidence or {}})
        print('P8_WALLET '+ident+' '+str(bool(ok)),flush=True);n.need(ok,'wallet gate failed: '+ident)
    def refuse(call):
        try:call()
        except (n.Invalid,n.Unavailable,ValueError):return True
        raise AssertionError('expected refusal absent')
    def invoke(name,op,raw):
        path=getattr(args,name);n.need(digest(path.read_bytes())==report['inputs'][name]['sha256'],'wallet binary changed')
        p=subprocess.Popen([str(path)]+([op] if op else []),stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=subprocess.PIPE,env={},start_new_session=True)
        ticks=Path(f'/proc/{p.pid}/stat').read_text().rsplit(')',1)[1].split()[19];out=b''
        try:
            out,err=p.communicate(raw,timeout=180);n.need(p.returncode==0 and not err and len(out)<=4096,'wallet fixture/prover output')
            return out
        finally:
            try:os.killpg(p.pid,signal.SIGKILL)
            except ProcessLookupError:pass
            p.communicate();report['native_processes'].append({'binary':name,'operation':op or 'prove','pid':p.pid,
                'start_ticks':ticks,'exit_code':p.returncode,'binary_sha256':report['inputs'][name]['sha256'],
                'input_bytes':len(raw),'output_bytes':len(out),'process_reaped':p.poll() is not None})
    try:
        check('source_clean',before['clean'])
        for name in ('engine','worker','helper','fixture','prover'):
            path=getattr(args,name);n.need(path.is_file() and not path.is_symlink() and 0<path.stat().st_size<=64*1024**2,'wallet bounded binary')
            report['inputs'][name]={'bytes':path.stat().st_size,'sha256':digest(path.read_bytes())}
        check('engine_identity',report['inputs']['engine']['sha256']==ENGINE_SHA256 and subprocess.check_output([str(args.engine),'version'],text=True).strip()=='0.38.25')
        preliminary=Worker(args.worker,report['inputs']['worker']['sha256'],args.kat.read_bytes());workers.append(preliminary)
        network=Network({'engine':args.engine,'worker':args.worker},output,report)
        validators=sorted([{'public_key':base64.b64decode(v['pub_key']['value'],validate=True).hex(),'power':int(v['power'])}
                           for v in network.engine_genesis['validators']],key=lambda v:v['public_key'])
        g={'format':GENESIS_FORMAT,'protocol_version':8,'chain_id':network.chain_id,'profile_sha256':PROFILE_SHA256,
            'worker_sha256':report['inputs']['worker']['sha256'],'kat_sha256':preliminary.kat_sha256,'validators':validators,
            'pool_id':os.urandom(32).hex(),'asset':field(2),'mission':field(3),'fee':1,'network':field(1),'notes':[]}
        bootstrap=bytes.fromhex(bootstrap_digest(g));domain=preliminary.network_domain(bootstrap)
        private=invoke('fixture','first',bootstrap)
        # These are the secret/origin/blind fields. Destination is a public key;
        # value/expiry/position/path are not credential material. Do not classify
        # the receiver's public H810 key as a leaked recipient secret.
        private_slots=(0,1,4,5,14,15,17,18)
        def capture(request):
            secrets.append(request.hex().encode())
            secrets.extend(request[552+i*32:584+i*32].hex().encode() for i in private_slots)
        capture(private);first=invoke('prover',None,private)
        private=None;note=invoke('fixture','genesis-note',bootstrap)
        g.update(network=domain,notes=[{'kind':'p8-recipient-v1','commitment':note.hex()}],kat_sha256=digest(first));raw=canonical(g)
        fixtures=network.runtime/'proof-fixtures';fixtures.mkdir(mode=0o700);network.paths['fixtures']=fixtures
        (fixtures/'first.tx').write_bytes(first);(fixtures/'genesis.json').write_bytes(raw);network.paths['kat']=fixtures/'first.tx'
        w=Worker(args.worker,g['worker_sha256'],first);workers.append(w)
        report.update(genesis=g,genesis_sha256=digest(raw),bootstrap_sha256=bootstrap.hex())
        check('fresh_native_receive_proof',genesis_document(raw,w)==g and w.verify(first,domain) and domain!=preliminary.kat_statement[1])
        controller=NoteController(args.helper,report['inputs']['helper']['sha256'],expected_genesis=raw,worker=w)
        class AuditedProver(Prover):
            def produce(self,request):
                capture(request)
                return super().produce(request)
        prover=AuditedProver(args.prover,report['inputs']['prover']['sha256'],expected_genesis=raw,worker=w);controllers.extend([controller,prover])
        # Exact synthetic first output origin, reproduced using frozen native H816.
        original={'origin':field(111),'value':20,'expiry':64,'note_secret':field(32),'blind':field(33)}
        req,origin=controller.construct(original,field(31),[note.hex()],request=field(21),valid_from=2,valid_until=32,
            fee=1,destination=controller.key(field(41)),payment=12,payment_expiry=60,payment_secret=field(42),payment_blind=field(43),change_secret=field(34),change_blind=field(35))
        n.need(req[136:552]==first[8:424],'fresh received fixture public request differs')
        received={'origin':origin,'value':12,'expiry':60,'note_secret':field(42),'blind':field(43)}
        alice_change={'origin':origin,'value':7,'expiry':64,'note_secret':field(34),'blind':field(35)}
        network.install_genesis(raw,w);network.start_sources();_hold_transaction_height(network)
        network.stage_without_quorum([first])
        def count(k):
            rows=[network.direct_state(i) for i in range(4)]
            return rows if all(len(r['state']['ledger']['receipts'])==k for r in rows) else None
        rows=wait_until(lambda:count(1),180);receive=network.hold_sources_without_quorum()
        check('four_validators_receive',all(canonical(r)==canonical(receive) for r in rows))
        def sign(witness):
            network.start_engine(2);network.start_engine(3)
            wait_until(lambda:network.height(0)>=witness['height']+1,180)
            signed=rpc(network.http[0],'commit',{'height':str(witness['height']+1)})['signed_header']
            verify_state(witness,signed,raw,w);network.hold_sources_without_quorum();return signed
        receive_header=sign(receive);check('signed_receive_state',True)
        bobdir=network.runtime/'bob-wallet';bobdir.mkdir(mode=0o700);key=os.urandom(32);wid=os.urandom(32).hex()
        secrets.extend([key.hex().encode(),field(41).encode()]);bobargs=dict(key=key,wallet_id=wid,recipient_secret=field(41),controller=controller)
        bob=RecipientWallet(bobdir/'wallet',create=True,**bobargs);bob.observe(receive,receive_header)
        mutations=[];unchanged=bob.path.read_bytes()
        for name in ('origin','value','expiry','note_secret','blind'):
            wrong=copy.deepcopy(received);wrong[name]=wrong[name]+1 if name in ('value','expiry') else field(99)
            refuse(lambda: bob.import_note(wrong,raw=first));n.need(bob.path.read_bytes()==unchanged,'failed import mutated ciphertext');mutations.append(name)
        wrongrecipient=RecipientWallet(bobdir/'other',create=True,**{**bobargs,'wallet_id':os.urandom(32).hex(),'recipient_secret':field(99)})
        wrongrecipient.observe(receive,receive_header);refuse(lambda:wrongrecipient.import_note(received,raw=first));mutations.append('recipient-secret')
        check('opening_mutations_refused',len(mutations)==6,{'mutations':mutations})
        commitment=bob.import_note(received,raw=first);beforeopen=bob.path.read_bytes();inventory=bob.inventory()
        bob=RecipientWallet(bob.path,**bobargs)
        check('encrypted_import_cold_reopen',bob.inventory()==inventory and bob.path.read_bytes()==beforeopen)
        check('duplicate_import_idempotent',bob.import_note(received,raw=first)==commitment and bob.path.read_bytes()==beforeopen)
        # Alice keeps a genuine competing intent held, later superseded on chain.
        adir=network.runtime/'alice-wallet';adir.mkdir(mode=0o700);akey=os.urandom(32);aid=os.urandom(32).hex()
        secrets.append(akey.hex().encode());aliceargs=dict(key=akey,wallet_id=aid,recipient_secret=field(31),controller=controller)
        alice=RecipientWallet(adir/'wallet',create=True,**aliceargs);alice.observe(receive,receive_header)
        change=alice.import_note(alice_change,raw=first,output=11)
        carol=controller.key(field(51))
        ident=bob.prepare(prover,commitment,request=field(71),destination=carol,payment=4,valid_until=32,payment_expiry=56)
        wire=bob.export(ident);(fixtures/'wallet-spend.tx').write_bytes(wire)
        held=alice.prepare(prover,change,request=field(81),destination=carol,payment=2,valid_until=32,payment_expiry=56)
        (fixtures/'held-competing.tx').write_bytes(alice.export(held))
        check('native_arbitrary_spend_prepared',n.parse(wire)[6]==field(71) and wire!=first and prover.call_count==2,
              {'txid':ident,'payment':4,'change':7,'fee':1,'destination_public_key':carol})
        refused=refuse(lambda:bob.prepare(prover,commitment,request=field(72),destination=carol,payment=3,valid_until=32,payment_expiry=56))
        check('original_input_intent_held',refused and prover.call_count==2 and len(bob.inventory()['obligations'])==1)
        check('unresolved_original_held',bob.reconcile(ident)['status']=='unresolved-held' and not bob.reconcile(ident)['automatic_retry'])
        # Only one broadcast. Deliberately discard its RPC result before wallet recovery.
        bob.mark_attempt(ident);reply=network.broadcast(0,wire);n.need(int(reply['code'])==0,'actual wallet broadcast refused');reply=None
        wait_until(lambda:wire in network.mempool_transactions(0) and wire in network.mempool_transactions(1),30)
        network.start_engine(2);network.start_engine(3)
        check('one_attempt_reply_discarded',bob.inventory()['obligations'][0]['attempts']==1 and bob.reconcile(ident)['status']=='unresolved-held',{'broadcast_calls':1,'reply_retained':False})
        wait_until(lambda:count(2),180);spent=network.hold_sources_without_quorum()
        check('exact_spend_four_validator_agreement',all(canonical(network.direct_state(i))==canonical(spent) for i in range(4)) and
              [r['txid'] for r in spent['state']['ledger']['receipts']]==[n.txid(first),ident])
        spent_header=sign(spent);bob.observe(spent,spent_header);recovered=bob.reconcile(ident)
        check('signed_exact_recovery',recovered['status']=='executed-exact' and recovered['receipt']['raw']==wire.hex() and recovered['receipt']['statement']==n.parse(wire))
        stable=bob.path.read_bytes();result=canonical(recovered);bob=RecipientWallet(bob.path,**bobargs)
        check('recovery_cold_reopen_idempotent',canonical(bob.reconcile(ident))==result and bob.path.read_bytes()==stable and
              bob.inventory()['obligations'][0]['attempts']==1 and refuse(lambda:bob.mark_attempt(ident)) and prover.call_count==2)
        cdir=network.runtime/'carol-wallet';cdir.mkdir(mode=0o700);ckey=os.urandom(32);secrets.extend([ckey.hex().encode(),field(51).encode()])
        delivered=bob.output_opening(ident);secrets.extend(delivered[k].encode() for k in ('origin','note_secret','blind'))
        carolwallet=RecipientWallet(cdir/'wallet',create=True,key=ckey,wallet_id=os.urandom(32).hex(),recipient_secret=field(51),controller=controller)
        carolwallet.observe(spent,spent_header);imported=carolwallet.import_note(delivered,raw=wire)
        check('recipient_private_delivery_import',imported==n.parse(wire)[10] and carolwallet.inventory()['recipient_key']==carol)
        # A distinct genuine proof spends Alice's held input. Certified conflict never retries/releases.
        notes=[r['commitment'] for r in spent['state']['ledger']['notes']]
        conflict_request,_=controller.construct(alice_change,field(31),notes,request=field(82),valid_from=spent['height']+2,
            valid_until=32,fee=1,destination=carol,payment=3,payment_expiry=56,payment_secret=field(83),payment_blind=field(84),change_secret=field(85),change_blind=field(86))
        competitor=prover.produce(conflict_request);(fixtures/'executed-competing.tx').write_bytes(competitor)
        n.need(n.parse(competitor)[5]==n.parse(alice.export(held))[5] and n.txid(competitor)!=held,'genuine competing input required')
        network.stage_without_quorum([competitor]);wait_until(lambda:count(3),180);conflict=network.hold_sources_without_quorum();conflict_header=sign(conflict)
        alice.observe(conflict,conflict_header);held_bytes=alice.path.read_bytes();held_result=alice.reconcile(held)
        check('certified_conflict_held',held_result['status']=='conflict-held' and not held_result['automatic_retry'] and
              alice.path.read_bytes()==held_bytes and prover.call_count==3 and len(alice.inventory()['obligations'])==1)
        current=bob.path.read_bytes();forged=copy.deepcopy(spent);forged['state']['ledger']['fees']+=1
        refused=[refuse(lambda:bob.observe(receive,receive_header)),refuse(lambda:bob.observe(forged,spent_header)),
                 refuse(lambda:bob.import_note(delivered,raw=competitor)),refuse(lambda:bob.import_note(received,raw=first,output=11))]
        check('certificate_rollback_tamper_refused',all(refused) and bob.path.read_bytes()==current,{'mutations':['rollback','state-fees','wrong-origin-wire','wrong-output']})
        report.update(receive_witness=receive,receive_signed_header=receive_header,state_witness=spent,signed_header=spent_header,
            recovery=recovered,conflict_witness=conflict,conflict_signed_header=conflict_header,conflict_resolution=held_result,
            wallet_inventory=bob.inventory(),broadcast_calls=1,proof_count=4)
        # Filter secret primitives that are also public small-integer/context values.
        needles=[s for s in secrets if s and s not in canonical(g) and s not in first.hex().encode() and s not in wire.hex().encode()]
        public=canonical(report)
        n.need(all(s not in public for s in needles),'private primitive in public report')
        for p in list(network.runtime.glob('*.log'))+list(fixtures.glob('*')):
            blob=p.read_bytes();n.need(all(s not in blob for s in needles),'private primitive in public artifact')
        n.need(set(p.name for p in bobdir.iterdir())=={'wallet','wallet.lock','other','other.lock'},'plaintext wallet sidecar')
        check('private_material_absent',True,{'private_requests_archived':False,'wallet_keys_archived':False,'wallet_files_archived':False})
        report['worker_audits'].extend({'node':i,**network.worker_audit(i)} for i in range(4))
        report['worker_audits'].extend({'node':'host-'+str(i),**worker.audit()} for i,worker in enumerate(workers))
        report['private_worker_audits']=[{'kind':'helper' if i==0 else 'prover',**c.audit()} for i,c in enumerate(controllers)]
        check('native_processes_reaped',all(a['call_count']==a['reaped_count'] and a['timeout_count']==0 and all(c['process_reaped'] and c['start_ticks'] is not None for c in a['calls'])
            for a in report['worker_audits']+report['private_worker_audits']) and all(c['process_reaped'] and c['start_ticks'] is not None for c in report['native_processes']))
    except Exception as exc:report['error']={'type':type(exc).__name__,'message':str(exc)}
    finally:
        if network:
            try:network.close();check('workers_stopped',all(type(r.get('exit_code')) is int for r in report['processes']))
            except Exception as exc:report['cleanup_error']={'type':type(exc).__name__,'message':str(exc)}
        report['checks'].append({'id':'source_unchanged','passed':source()==before,'evidence':{}})
        if [r['id'] for r in report['checks']]==list(CHECKS) and all(r['passed'] for r in report['checks']) and not report.get('error') and not report.get('cleanup_error'):
            report['status']='qualified-one-host-recipient-wallet'
        output.write_bytes(canonical(report)+b'\n')
    return 0 if report['status']=='qualified-one-host-recipient-wallet' else 1
def main():
    p=argparse.ArgumentParser(description=__doc__)
    for name in ('engine','worker','helper','fixture','prover','kat','output'):p.add_argument('--'+name,type=Path,required=True)
    raise SystemExit(run(p.parse_args()))
if __name__=='__main__':main()
