#!/usr/bin/env python3
"""V2 wallet history reuse after old/new segment payments on four validators.

Three wallet payments and seven separately identified setup-generator payments.
Synthetic funds/keys only; full signed history replay, not production readiness."""
import argparse, base64, copy, http.server, os, signal, subprocess, sys, threading
from pathlib import Path
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

CHECKS=('source_clean','engine_identity','four_validators_initialized','signed_initial_history',
    'alice_payment_prepared','lost_response_single_forward','duplicate_send_refused',
    'alice_exact_execution_recovered','bob_authenticated_receive',
    'seven_generator_payments_committed','rollover_authenticated_after64','spent_original_refused',
    'older_segment_wallet_prepared','older_segment_wallet_committed',
    'native_older_segment_competing_refused','new_segment_wallet_prepared',
    'new_segment_wallet_committed','all_wallet_exact_execution','authenticated_change_and_conservation',
    'twelve_signed_updates_retained','original_payment_records_immutable','single_history_storage_measured',
    'tampered_history_and_header_refused','cold_wallets_replayed','cold_retry_refused',
    'native_processes_reaped','workers_stopped','source_unchanged')

def run(args):
    output=args.output.absolute();n.need(not output.exists() and not output.with_name(output.name+'.artifacts').exists(),'fresh P9 wallet receipt')
    before=source();report={'format':'1soft/protocol9-history-wallet/v2','status':'failed','source':before,
        'checks':[],'inputs':{},'native_processes':[],'worker_audits':[],
        'claims':{'synthetic_funds':True,'one_host_four_validators':True,'independent_operators':False,
        'public_network':False,'production_custody':False,'compact_witness':False,'freshness':False,
        'external_review':False,'old_wallet_migration':False}}
    network=None;workers=[];private=[];server=None;thread=None
    def check(name,ok,evidence=None):
        report['checks'].append({'id':name,'passed':bool(ok),'evidence':evidence or {}})
        print('P9_HISTORY_CHECK '+name+' '+str(bool(ok)),flush=True);n.need(ok,'P9 wallet gate failed: '+name)
    def fixture(op,bootstrap):
        n.need(n.sha(args.fixture.read_bytes())==report['inputs']['fixture']['sha256'],'P9 fixture identity changed')
        fd=os.open(args.fixture,os.O_RDONLY|os.O_NOFOLLOW);child=None;out=b'';ticks=None
        try:
            child=subprocess.Popen(['/proc/self/fd/'+str(fd),op],stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=subprocess.PIPE,env={},pass_fds=(fd,),start_new_session=True)
            ticks=Path('/proc/'+str(child.pid)+'/stat').read_text().rsplit(')',1)[1].split()[19]
            out,err=child.communicate(bootstrap,timeout=45)
            n.need(child.returncode==0 and not err and len(out)<=1160,'P9 fixture output');return out
        finally:
            if child:
                try:os.killpg(child.pid,signal.SIGKILL)
                except ProcessLookupError:pass
                child.communicate();report['native_processes'].append({'operation':op,'pid':child.pid,'start_ticks':ticks,
                    'binary_sha256':report['inputs']['fixture']['sha256'],'exit_code':child.returncode,'output_bytes':len(out),'process_reaped':child.poll() is not None})
            os.close(fd)
    def observation(label):
        held=network.hold_sources_without_quorum();witness=export_history(network.runtime/'app0/state.sqlite')
        n.need(witness['height']==held['height'] and witness['app_hash']==held['app_hash'],'P9 history export checkpoint race')
        network.start_engine(2);network.start_engine(3)
        wait_until(lambda:network.height(0)>=witness['height']+1,120)
        signed=rpc(network.http[0],'commit',{'height':str(witness['height']+1)})['signed_header']
        network.hold_sources_without_quorum() # Bound height while native proving/replay runs.
        cert,ledger=verify_history(witness,signed,raw,w)
        report.setdefault('observations',[]).append({'label':label,'witness':witness,'signed_header':signed,'certificate':cert})
        return witness,signed,ledger
    def resume_and_wait(count):
        network.start_engine(2);network.start_engine(3)
        wait_until(lambda:all(network.direct_state(i)['checkpoint']['accepted_count']==count for i in range(4)),240)
    try:
        check('source_clean',before['clean'])
        for name in ('engine','worker','helper','fixture','prover'):
            path=getattr(args,name);n.need(path.is_file() and not path.is_symlink() and 0<path.stat().st_size<=64*1024**2,'P9 binary input')
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
        initial,signed,_=observation('initial');check('signed_initial_history',initial['checkpoint']['accepted_count']==0)
        homes=network.runtime/'wallets';homes.mkdir(mode=0o700)
        keys={'alice':os.urandom(32),'bob':os.urandom(32)};ids={name:os.urandom(32).hex() for name in keys}
        secrets={'alice':field(31),'bob':field(41)}
        wallets={name:RecipientWallet(homes/name,key=keys[name],wallet_id=ids[name],recipient_secret=secrets[name],controller=controller,create=True) for name in keys}
        alice,bob=wallets['alice'],wallets['bob']
        for wallet in wallets.values():wallet.observe(initial,signed)
        alice.import_note(note.hex(),{'origin':field(111),'value':1000,'expiry':100000,'note_secret':field(32),'blind':field(33)},genesis=True)
        ident1=alice.prepare(prover,note.hex(),request=field(901),destination=bob.recipient_key,payment=400,valid_until=100000,payment_expiry=100000)
        wire1=alice.export(ident1);(fixtures/'alice-payment.tx').write_bytes(wire1)
        check('alice_payment_prepared',alice.inventory()['obligations'][0]['attempts']==0)
        forwarded=[];forward_errors=[]
        class DropReply(http.server.BaseHTTPRequestHandler):
            def log_message(self,*args):pass
            def do_POST(self):
                try:
                    length=int(self.headers.get('Content-Length','0'));n.need(0<length<8192,'bounded drop proxy')
                    import json
                    value=json.loads(self.rfile.read(length));wire=base64.b64decode(value['params']['tx'],validate=True)
                    n.need(wire==wire1,'drop proxy exact original wire');forwarded.append(n.txid(wire))
                    admitted=network.broadcast(0,wire);n.need(int(admitted['code'])==0,'drop proxy admission')
                except Exception as exc:forward_errors.append(type(exc).__name__)
                finally:self.close_connection=True;self.connection.close()
        server=http.server.HTTPServer(('127.0.0.1',0),DropReply);thread=threading.Thread(target=server.serve_forever,daemon=True);thread.start()
        # The gate's forwarding receiver only discards the response; production
        # transport and wallet marker remain unchanged and execute real HTTP.
        lost=send_once(alice,ident1,'http://127.0.0.1:'+str(server.server_port))
        server.shutdown();server.server_close();thread.join(5);server=None
        check('lost_response_single_forward',lost['outcome']=='unknown' and forwarded==[ident1] and not forward_errors,{'caller':lost,'forwards':len(forwarded)})
        try:send_once(alice,ident1,'http://127.0.0.1:'+str(network.http[0]));raise AssertionError('duplicate original send accepted')
        except n.Invalid:pass
        check('duplicate_send_refused',alice.reconcile(ident1)['status']=='unresolved-held')
        resume_and_wait(1);received,signed,_=observation('alice-executed')
        for wallet in wallets.values():wallet.observe(received,signed)
        result1=alice.reconcile(ident1);check('alice_exact_execution_recovered',result1['status']=='executed-exact' and result1['txid']==ident1)
        bob_note=n.parse(wire1)[10];bob.import_note(bob_note,alice.output_opening(ident1),raw=wire1)
        check('bob_authenticated_receive',bob.inventory()['notes']==[bob_note])
        # Setup generator follows Bob's change. These seven payments do not
        # claim wallet origin, and their openings never enter public receipts.
        generator=[];opening=alice.output_opening(ident1);last_wire=wire1
        for i in range(1,8):
            ps,pb,cs,cb=[field(700+i*4+j) for j in range(4)]
            req,origin=controller.construct(opening,secrets['bob'],network.direct_state(0)['checkpoint']['active_notes'],
                request=field(920+i),valid_from=2,valid_until=100000,destination=controller.key(field(51)),
                payment=1,payment_expiry=100000,payment_secret=ps,payment_blind=pb,change_secret=cs,change_blind=cb)
            private_request=bytearray(req);req=None
            try:last_wire=prover.produce(bytes(private_request))
            finally:private_request[:]=bytes(len(private_request))
            (fixtures/('generator-%02d.tx'%i)).write_bytes(last_wire)
            admitted=network.broadcast(0,last_wire);n.need(int(admitted['code'])==0,'generator admission')
            resume_and_wait(1+i);network.hold_sources_without_quorum()
            generator.append({'txid':n.txid(last_wire),'wire_sha256':n.sha(last_wire),'artifact':'fixture-generator-%02d.tx'%i})
            opening={'origin':origin,'value':opening['value']-2,'expiry':100000,'note_secret':cs,'blind':cb}
            print('P9_GENERATOR_PAYMENT '+str(i)+' committed',flush=True)
        check('seven_generator_payments_committed',len(generator)==7 and all(network.direct_state(i)['checkpoint']['notes_count']==17 for i in range(4)),
            {'wallet_payments':1,'generator_payments':7,'ledger_notes':17})
        network.start_engine(2);network.start_engine(3)
        wait_until(lambda:all(network.direct_state(i)['height']>64 for i in range(4)),180)
        rollover,signed,ledger=observation('rollover-past64')
        check('rollover_authenticated_after64',rollover['height']>64 and rollover['checkpoint']['accepted_count']==8 and
            {row['segment'] for row in ledger['notes']}=={0,1},{'height':rollover['height'],'notes':len(ledger['notes'])})
        for wallet in wallets.values():wallet.observe(rollover,signed)
        unchanged_bob=bob.path.read_bytes()
        try:bob.prepare(prover,bob_note,request=field(998),destination=alice.recipient_key,payment=1,valid_until=100000,payment_expiry=100000);raise AssertionError('spent received note accepted')
        except n.Invalid:pass
        check('spent_original_refused',bob.path.read_bytes()==unchanged_bob,{'wallet_unchanged':True})
        ac=alice.output_opening(ident1,11);old_note=n.parse(wire1)[11];new_note=n.parse(last_wire)[11]
        alice.import_note(old_note,ac,raw=wire1,output=11)
        bob.import_note(new_note,opening,raw=last_wire,output=11)
        segments={row['commitment']:row['segment'] for row in ledger['notes']}
        n.need(segments[old_note]==0 and segments[new_note]==1,'actual old/new input locations')
        ident2=alice.prepare(prover,old_note,request=field(902),destination=bob.recipient_key,payment=100,valid_until=100000,payment_expiry=100000)
        wire2=alice.export(ident2);(fixtures/'old-segment-wallet.tx').write_bytes(wire2)
        old_prefix=[row['commitment'] for row in ledger['notes'] if row['segment']==0]
        req,_=controller.construct(ac,secrets['alice'],old_prefix,request=field(990),valid_from=rollover['height']+2,
            valid_until=100000,destination=bob.recipient_key,payment=101,payment_expiry=100000,
            payment_secret=field(991),payment_blind=field(992),change_secret=field(993),change_blind=field(994))
        private_request=bytearray(req);req=None
        try:competing=prover.produce(bytes(private_request))
        finally:private_request[:]=bytes(len(private_request))
        (fixtures/'old-segment-competing.tx').write_bytes(competing)
        check('older_segment_wallet_prepared',w.verify(competing,g['network']) and
            n.parse(competing)[5]==n.parse(wire2)[5] and n.parse(competing)[6]!=n.parse(wire2)[6] and
            n.integer(n.parse(wire2)[7])>64,{'input_segment':0,'valid_from':n.integer(n.parse(wire2)[7])})
        sent=send_once(alice,ident2,'http://127.0.0.1:'+str(network.http[0]));n.need(sent['outcome']=='admission-accepted','old segment wallet admission')
        resume_and_wait(9);old_done,signed,ledger=observation('old-segment-wallet-executed')
        for wallet in wallets.values():wallet.observe(old_done,signed)
        result2=alice.reconcile(ident2)
        check('older_segment_wallet_committed',result2['status']=='executed-exact' and result2['receipt']['height']>64 and old_done['checkpoint']['notes_count']==19,
            {'committed_height':result2['receipt']['height'],'notes':19})
        codes=[network.direct_check(i,competing) for i in range(4)]
        check('native_older_segment_competing_refused',codes==[5]*4,{'codes':codes,'native_valid_proof':True})
        ident3=bob.prepare(prover,new_note,request=field(903),destination=alice.recipient_key,payment=50,valid_until=100000,payment_expiry=100000)
        wire3=bob.export(ident3);(fixtures/'new-segment-wallet.tx').write_bytes(wire3)
        check('new_segment_wallet_prepared',n.integer(n.parse(wire3)[7])>64,{'input_segment':1,'valid_from':n.integer(n.parse(wire3)[7])})
        sent=send_once(bob,ident3,'http://127.0.0.1:'+str(network.http[0]));n.need(sent['outcome']=='admission-accepted','new segment wallet admission')
        resume_and_wait(10);final,signed,ledger=observation('new-segment-wallet-executed')
        for wallet in wallets.values():wallet.observe(final,signed)
        result3=bob.reconcile(ident3)
        check('new_segment_wallet_committed',result3['status']=='executed-exact' and result3['receipt']['height']>64 and final['checkpoint']['notes_count']==21,
            {'committed_height':result3['receipt']['height'],'notes':21})
        check('all_wallet_exact_execution',alice.reconcile(ident1)==result1 and alice.reconcile(ident2)==result2 and bob.reconcile(ident3)==result3)
        ac2=alice.output_opening(ident2,11);bp=alice.output_opening(ident2);bc=bob.output_opening(ident3,11);back=bob.output_opening(ident3)
        alice.import_note(n.parse(wire2)[11],ac2,raw=wire2,output=11)
        bob.import_note(n.parse(wire2)[10],bp,raw=wire2)
        bob.import_note(n.parse(wire3)[11],bc,raw=wire3,output=11)
        alice.import_note(n.parse(wire3)[10],back,raw=wire3)
        check('authenticated_change_and_conservation',ac2['value']==498 and bp['value']==100 and bc['value']==335 and back['value']==50 and
            ac2['value']+bp['value']+bc['value']+back['value']+len(generator)+final['checkpoint']['fees']==1000,
            {'alice_unspent_value':548,'bob_unspent_value':435,'generator_recipient_value':7,'fees':10,'synthetic_initial_value':1000})
        # Advance real quorum-certified states after every original payment.
        # Exact preparation/result slots are immutable; only the unused tail
        # is replaceable. This is storage reuse, not incremental proof replay.
        from protocol9_history_codec import pack
        starting={name:wallet.inventory()['as_of_height'] for name,wallet in wallets.items()}
        for index in range(12):
            final,signed,ledger=observation('history-update-%02d'%(index+1))
            for wallet in wallets.values():wallet.observe(final,signed)
            n.need(alice.reconcile(ident1)==result1 and alice.reconcile(ident2)==result2 and bob.reconcile(ident3)==result3,'update changed original exact result')
            n.need(alice.export(ident1)==wire1 and alice.export(ident2)==wire2 and bob.export(ident3)==wire3,'update changed original wire')
            n.need(all(row['attempts']==1 for wallet in wallets.values() for row in wallet.inventory()['obligations']),'update changed attempt marker')
            print('P9_HISTORY_UPDATE '+str(index+1)+' authenticated',flush=True)
        check('twelve_signed_updates_retained',len(report['observations'])==17 and all(wallet.inventory()['as_of_height']==final['height']>starting[name] for name,wallet in wallets.items()),{'updates':12,'final_height':final['height']})
        check('original_payment_records_immutable',alice.reconcile(ident1)==result1 and alice.reconcile(ident2)==result2 and bob.reconcile(ident3)==result3,{'payment_records':3,'original_wires_unchanged':True,'attempts_per_original':1})
        storage={}
        for name,wallet in wallets.items():
            with wallet._locked():
                logical=wallet._read();history,refs=pack(logical['observations'],wallet.g)
                physical={**logical,'history':history,'observations':refs}
                compact=len(n.canonical(physical));duplicated=len(n.canonical(logical))
                storage[name]={'retained_observations':len(refs),'stored_histories':1,'history_blocks':len(history['blocks']),
                    'compact_plaintext_bytes':compact,'equivalent_duplicated_plaintext_bytes':duplicated,
                    'encrypted_file_bytes':wallet.path.stat().st_size,'plaintext_reduction_bytes':duplicated-compact}
                n.need(n.canonical(physical).count(b'"blocks":')==1 and len(refs)<=8 and compact<duplicated,'one-copy storage measurement differs')
        report['storage']=storage
        check('single_history_storage_measured',all(row['plaintext_reduction_bytes']>0 for row in storage.values()),storage)
        refused=[];unchanged=alice.path.read_bytes()
        for kind in ('history','checkpoint','header','owner','rollback'):
            try:
                bad=copy.deepcopy(final);header=copy.deepcopy(signed)
                if kind=='history':bad['blocks'][0]['transactions']=['aa'];verify_history(bad,header,raw,w)
                elif kind=='checkpoint':bad['checkpoint']['fees']+=1;verify_history(bad,header,raw,w)
                elif kind=='header':header['commit']['signatures'][0]['signature']='AA==';verify_history(bad,header,raw,w)
                elif kind=='owner':alice.import_note(bob_note,alice.output_opening(ident1),raw=wire1)
                else:alice.observe(initial,report['observations'][0]['signed_header'])
                raise AssertionError('tamper accepted: '+kind)
            except ValueError:refused.append(kind)
            except n.Unavailable:
                # The private native helper deliberately suppresses diagnostic
                # contents. Wrong-owner inspection must exit unsuccessfully,
                # be reaped without timeout, and leave the wallet unchanged.
                run=controller.runs[-1]
                n.need(kind=='owner' and run['operation']=='inspect-note' and run['exit_code']!=0 and run['process_reaped'] and not run['timed_out'],'unexpected private worker failure')
                alice.import_note(n.parse(wire1)[11],ac,raw=wire1,output=11)
                refused.append(kind)
            n.need(alice.path.read_bytes()==unchanged,'negative test changed wallet')
        check('tampered_history_and_header_refused',len(refused)==5,{'refused':refused,'wallet_unchanged':True})
        expected={name:wallet.inventory() for name,wallet in wallets.items()};cold_worker=Worker(args.worker,g['worker_sha256'],first);workers.append(cold_worker)
        cold_controller=NoteController(args.helper,report['inputs']['helper']['sha256'],g=g,worker=cold_worker);private.append(cold_controller)
        cold={name:RecipientWallet(homes/name,key=keys[name],wallet_id=ids[name],recipient_secret=secrets[name],controller=cold_controller) for name in keys}
        command=[sys.executable,'-B',str(ROOT/'scripts/protocol9_history_wallet_reopen.py'),'--genesis',str(fixtures/'genesis.json'),
            '--genesis-sha256',n.sha(raw),'--kat',str(fixtures/'kat.tx'),'--worker',str(args.worker),
            '--worker-sha256',g['worker_sha256'],'--helper',str(args.helper),'--helper-sha256',report['inputs']['helper']['sha256']]
        child=subprocess.Popen(command,stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=subprocess.PIPE)
        secret_rows=[{'path':str(homes/name),'key':keys[name].hex(),'wallet_id':ids[name],'recipient_secret':secrets[name],'txid':ident} for name,ident in (('alice',ident2),('bob',ident3))]
        try:out,err=child.communicate(n.canonical(secret_rows),timeout=300)
        finally:
            if child.poll() is None:child.kill()
            child.communicate()
        n.need(child.returncode==0 and not err and len(out)<=2*1024**2,'P9 cold child failed')
        import json
        cold_result=json.loads(out);report['cold_process']={'pid':child.pid,'exit_code':child.returncode,'process_reaped':child.poll() is not None,'script_sha256':n.sha((ROOT/'scripts/protocol9_history_wallet_reopen.py').read_bytes()),'result':cold_result}
        check('cold_wallets_replayed',all(cold[name].inventory()==expected[name] for name in keys) and cold['alice'].reconcile(ident1)==result1 and cold_result['status']=='reopened-authenticated' and
            cold_result['wallets']==[{'inventory':expected['alice'],'result':result2},{'inventory':expected['bob'],'result':result3}],{'inventories':expected,'fresh_python_process':True})
        for name,ident in (('alice',ident2),('bob',ident3)):
            try:send_once(cold[name],ident,'http://127.0.0.1:'+str(network.http[0]));raise AssertionError('cold retry accepted')
            except n.Invalid:pass
        check('cold_retry_refused',all(row['attempts']==1 for wallet in cold.values() for row in wallet.inventory()['obligations']))
        report['genesis_sha256']=n.sha(raw)
        report['generator_payments']=generator
        report['payments']=[{'txid':ident,'wire_sha256':n.sha(wire),'input':commitment,'input_segment':segment,
            'committed_height':result['receipt']['height'],'artifact':artifact,'result':result}
            for ident,wire,commitment,segment,result,artifact in (
                (ident1,wire1,note.hex(),0,result1,'fixture-alice-payment.tx'),
                (ident2,wire2,old_note,0,result2,'fixture-old-segment-wallet.tx'),
                (ident3,wire3,new_note,1,result3,'fixture-new-segment-wallet.tx'))]
        report['competing']={'artifact':'fixture-old-segment-competing.tx','wire_sha256':n.sha(competing),'codes':codes}

        report['worker_audits']=[{'node':i,**network.worker_audit(i)} for i in range(4)]+[{'node':'wallet-'+str(i),**worker.audit()} for i,worker in enumerate(workers)]
        report['worker_audits'].append({'node':'cold-child',**cold_result['worker_audit']})
        report['private_process_audits']=[item.audit() for item in private]+[cold_result['private_process_audit']]
        audits=report['worker_audits']+report['private_process_audits']
        check('native_processes_reaped',all(a['call_count']==a['reaped_count'] and a['timeout_count']==0 for a in audits) and all(r['process_reaped'] for r in report['native_processes']))
    except Exception as exc:report['error']={'type':type(exc).__name__,'message':str(exc)}
    finally:
        if server:server.shutdown();server.server_close()
        if thread:thread.join(5)
        if network:
            try:network.close();check('workers_stopped',all(type(p.get('exit_code')) is int for p in report['processes']))
            except Exception as exc:report['cleanup_error']={'type':type(exc).__name__,'message':str(exc)}
        report['checks'].append({'id':'source_unchanged','passed':source()==before,'evidence':{}})
        if tuple(c['id'] for c in report['checks'])==CHECKS and all(c['passed'] for c in report['checks']) and not report.get('cleanup_error'):report['status']='qualified-one-host-p9-history-wallet'
        output.write_bytes(n.canonical(report)+b'\n')
    return 0 if report['status']=='qualified-one-host-p9-history-wallet' else 1

if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__)
    for name in ('engine','worker','helper','fixture','prover','kat','output'):parser.add_argument('--'+name,type=Path,required=True)
    raise SystemExit(run(parser.parse_args()))
