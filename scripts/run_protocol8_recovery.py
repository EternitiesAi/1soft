#!/usr/bin/env python3
"""Actual CometBFT P8 snapshot/lost-reply/rejoin/recipient-spend qualification."""
from __future__ import annotations
import argparse,base64,copy,json,os,signal,sqlite3,subprocess,sys,time
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1];sys.path.insert(0,str(ROOT/'src'))
import protocol8_transfer as n
from protocol8_consensus import canonical,digest,bootstrap_digest,genesis_document,GENESIS_FORMAT,PROFILE_SHA256,application_hash
from protocol8_worker import Worker
from protocol8_recovery import RecoveryApplication
from protocol8_notes import NoteController
from protocol8_prover import Prover
from protocol8_wallet import RecipientWallet
from protocol8_certificate import verify_state
import protocol8_state_sync as sync
from state_sync import OFFER_ACCEPT,OFFER_REJECT,APPLY_ACCEPT,APPLY_REJECT_SNAPSHOT
from run_protocol8_engine import Network as OrdinaryNetwork,field
from run_protocol8_wallet import source
from run_protocol5_engine import ENGINE_SHA256,_application_ready
from run_protocol5_state_sync import (_snapshot,_load,_prepare_snapshot_provider,_restore_source_peers,
                                     _snapshot_engine_ready,_state_sync_events)
from run_devnet import rpc,patch_toml,wait_until

CHECKS=('source_clean','engine_identity','fresh_native_network_proof','four_source_receive',
 'actual_native_hostile_snapshots_refused','actual_atomic_import_reopen','snapshot_provider_headers',
 'target_fresh_nonvalidator','actual_snapshot_commit_crash','actual_engine_reoffer_recovered',
 'trusted_snapshot_full_replay','origin_no_invented_responses','source_target_rejoin',
 'recipient_from_restored_state','post_sync_payment_five_node_agreement','signed_post_sync_exact_receipt',
 'target_same_store_restart','origin_real_suffix_audited','private_material_absent','native_processes_reaped',
 'workers_stopped','source_unchanged')
CLAIMS={'one_host_four_validators':True,'one_fresh_nonvalidator':True,'actual_comet_state_sync':True,
 'lost_final_apply_reoffer':True,'full_native_replay':True,'post_sync_recipient_spend':True,
 'as_of_only':True,'production_ready':False,'real_funds':False,'public_network':False,
 'independent_operators':False,'freshness_established':False,'validator_signer_recovery':False,
 'hostile_host_custody':False,'power_loss_durability':False,'p7_migration':False,
 'independent_cryptographic_audit':False}

class Network(OrdinaryNetwork):
    def start_app(self,i,*,crash=None):
        endpoint=self.runtime/f'app{i}/a.sock'
        if endpoint.exists():
            n.need(i not in self.apps or self.apps[i].poll() is not None,'live recovery socket owner')
            endpoint.unlink()
        script='serve_abci_p8_recovery_test.py' if crash is not None else 'serve_abci_p8_recovery.py'
        log=(self.runtime/f'app{i}.log').open('ab');self.handles.append(log)
        cmd=[sys.executable,'-B',str(ROOT/'scripts'/script),'--genesis',str(self.genesis_path),
             '--genesis-sha256',self.genesis_sha256,'--database',str(self.runtime/f'app{i}/state.sqlite'),
             '--socket',str(endpoint),'--worker',str(self.paths['worker']),'--kat',str(self.paths['kat'])]
        if crash is not None:
            n.need(set(crash)=={'run_token','run_token_sha256','crash_phase','event_log'},'test crash controls differ')
            for key,value in crash.items():cmd.extend(['--'+key.replace('_','-'),str(value)])
        proc=subprocess.Popen(cmd,stdout=log,stderr=log);self.apps[i]=proc
        self._record('application',i,proc,digest((ROOT/'scripts'/script).read_bytes()))
        wait_until(lambda:_application_ready(self,i,proc,endpoint),120)

def host_probes(network,raw,w,snapshot,payload):
    """Untrusted-byte application tests using the actual verifier, not light-client claims."""
    root=network.runtime/'host-probes';root.mkdir(mode=0o700)
    results=[]
    def fresh(name):return RecoveryApplication(root/(name+'.sqlite'),w,expected_genesis=raw)
    def chunks(app,d,b):
        for i in range(d['chunks']):r=app.apply_snapshot_chunk(i,b[i*sync.CHUNK_BYTES:(i+1)*sync.CHUNK_BYTES],'probe')
        return r['result']
    base=json.loads(payload)
    with fresh('tamper') as app:
        for name in ('genesis-note','fees','nullifier','history','proof','receipt','height','hash'):
            v=copy.deepcopy(base)
            if name=='genesis-note':v['genesis']['notes'][0]['commitment']=field(999)
            elif name=='fees':v['state']['ledger']['fees']+=1
            elif name=='nullifier':v['state']['ledger']['nullifiers'][0]=field(999)
            elif name=='history':v['state']['blocks'][0]['results'].append({'code':0,'data':'','log':''})
            elif name=='proof':
                block=next(b for b in v['state']['blocks'] if b['transactions']);tx=bytearray.fromhex(block['transactions'][0]);tx[-1]^=1;block['transactions'][0]=tx.hex()
            elif name=='receipt':v['state']['ledger']['receipts'][0]['statement'][10]=field(999)
            elif name=='height':v['height']+=1
            else:v['app_hash']='ef'*32
            b=canonical(v);d={'height':snapshot['height'],'format':sync.FORMAT,'chunks':(len(b)+sync.CHUNK_BYTES-1)//sync.CHUNK_BYTES,
                'hash':sync.payload_hash(b),'metadata':sync.metadata(app,snapshot['height'],base['app_hash'],b)}
            n.need(app.offer_snapshot(d,bytes.fromhex(base['app_hash']))==OFFER_ACCEPT,'semantic probe descriptor refused prematurely')
            n.need(chunks(app,d,b)==APPLY_REJECT_SNAPSHOT and app.state is None,'actual semantic snapshot accepted')
            results.append(name)
        n.need(app.offer_snapshot(snapshot,b'x'*32)==OFFER_REJECT,'wrong trusted AppHash accepted')
        results.append('wrong-trusted-apphash')
    app=fresh('atomic')
    try:
        app.db.execute("CREATE TEMP TRIGGER fail BEFORE INSERT ON p8_snapshot_origin BEGIN SELECT RAISE(ABORT,'injected'); END")
        n.need(app.offer_snapshot(snapshot,bytes.fromhex(base['app_hash']))==OFFER_ACCEPT,'atomic offer refused')
        try:chunks(app,snapshot,payload);raise AssertionError('atomic failure absent')
        except sqlite3.IntegrityError:pass
        n.need(app.state is None and app.db.execute('SELECT count(*) FROM p8_checkpoint').fetchone()[0]==0,'atomic install changed old state')
    finally:app.close()
    with fresh('atomic') as app:
        n.need(app.state is None,'atomic rollback did not reopen empty')
        n.need(app.offer_snapshot(snapshot,bytes.fromhex(base['app_hash']))==OFFER_ACCEPT and chunks(app,snapshot,payload)==APPLY_ACCEPT,'atomic retry failed')
    with fresh('atomic') as app:
        n.need(app.query('/state')['value']==payload,'actual import reopen differs')
        n.need(app.db.execute('SELECT count(*) FROM p8_blocks').fetchone()[0]==0,'host fabricated historical responses')
    return results

def run(args):
    output=args.output.absolute();n.need(not output.exists() and not output.with_name(output.name+'.artifacts').exists(),'fresh recovery output required')
    before=source();report={'format':'1soft/protocol8-recipient-recovery-gate/v1','status':'failed','source':before,
        'claims':CLAIMS.copy(),'checks':[],'inputs':{},'native_processes':[],'worker_audits':[]}
    network=None;controllers=[];workers=[];private=[]
    def check(name,ok,evidence=None):
        report['checks'].append({'id':name,'passed':bool(ok),'evidence':evidence or {}})
        print('P8_RECOVERY '+name+' '+str(bool(ok)),flush=True);n.need(ok,'recovery gate failed: '+name)
    def capture(request):
        private.append(request.hex().encode())
        for i in (0,1,4,5,14,15,17,18):private.append(request[552+i*32:584+i*32].hex().encode())
    def invoke(name,op,raw):
        path=getattr(args,name);n.need(digest(path.read_bytes())==report['inputs'][name]['sha256'],'native input changed')
        proc=subprocess.Popen([str(path)]+([op] if op else []),stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=subprocess.PIPE,env={},start_new_session=True)
        ticks=int(Path(f'/proc/{proc.pid}/stat').read_text().rsplit(')',1)[1].split()[19]);out=b''
        try:
            out,err=proc.communicate(raw,timeout=180);n.need(proc.returncode==0 and not err and len(out)<=4096,'native fixture/prover failed')
            return out
        finally:
            try:os.killpg(proc.pid,signal.SIGKILL)
            except ProcessLookupError:pass
            proc.communicate();report['native_processes'].append({'binary':name,'operation':op or 'prove','pid':proc.pid,'start_ticks':ticks,
                'exit_code':proc.returncode,'binary_sha256':report['inputs'][name]['sha256'],'input_bytes':len(raw),'output_bytes':len(out),'process_reaped':proc.poll() is not None})
    try:
        check('source_clean',before['clean'])
        for name in ('engine','worker','helper','fixture','prover'):
            path=getattr(args,name);n.need(path.is_file() and not path.is_symlink() and 0<path.stat().st_size<=64*1024**2,'bounded recovery input')
            report['inputs'][name]={'bytes':path.stat().st_size,'sha256':digest(path.read_bytes())}
        check('engine_identity',report['inputs']['engine']['sha256']==ENGINE_SHA256 and subprocess.check_output([str(args.engine),'version'],text=True).strip()=='0.38.25')
        preliminary=Worker(args.worker,report['inputs']['worker']['sha256'],args.kat.read_bytes());workers.append(preliminary)
        network=Network({'engine':args.engine,'worker':args.worker},output,report)
        validators=sorted([{'public_key':base64.b64decode(v['pub_key']['value'],validate=True).hex(),'power':int(v['power'])} for v in network.engine_genesis['validators']],key=lambda v:v['public_key'])
        g={'format':GENESIS_FORMAT,'protocol_version':8,'chain_id':network.chain_id,'profile_sha256':PROFILE_SHA256,
            'worker_sha256':report['inputs']['worker']['sha256'],'kat_sha256':preliminary.kat_sha256,'validators':validators,
            'pool_id':os.urandom(32).hex(),'asset':field(2),'mission':field(3),'fee':1,'network':field(1),'notes':[]}
        bootstrap=bytes.fromhex(bootstrap_digest(g));domain=preliminary.network_domain(bootstrap)
        request=invoke('fixture','first',bootstrap);capture(request);first=invoke('prover',None,request);request=None
        note=invoke('fixture','genesis-note',bootstrap)
        g.update(network=domain,notes=[{'kind':'p8-recipient-v1','commitment':note.hex()}],kat_sha256=digest(first));raw=canonical(g)
        fixtures=network.runtime/'proof-fixtures';fixtures.mkdir(mode=0o700);network.paths['fixtures']=fixtures
        (fixtures/'first.tx').write_bytes(first);(fixtures/'genesis.json').write_bytes(raw);network.paths['kat']=fixtures/'first.tx'
        w=Worker(args.worker,g['worker_sha256'],first);workers.append(w)
        report.update(genesis=g,genesis_sha256=digest(raw),bootstrap_sha256=bootstrap.hex())
        check('fresh_native_network_proof',genesis_document(raw,w)==g and w.verify(first,domain) and domain!=preliminary.kat_statement[1])
        network.install_genesis(raw,w);network.start_sources()
        network.set_empty_blocks(True)
        wait_until(lambda:min(network.height(i) for i in range(4))>=1,60)
        held=network.hold_sources_without_quorum();network.stage_without_quorum([first])
        wait_until(lambda:all(len(network.direct_state(i)['state']['ledger']['receipts'])==1 for i in range(4)),180)
        wait_until(lambda:min(network.height(i) for i in range(4))>=4,60)
        frozen=network.hold_sources_without_quorum();h=frozen['height']
        check('four_source_receive',all(canonical(network.direct_state(i))==canonical(frozen) for i in range(4)) and frozen['state']['ledger']['receipts'][0]['txid']==n.txid(first),{'height':h,'txid':n.txid(first)})
        descriptor=_snapshot(network);payload=b''.join(_load(network,descriptor,i) for i in range(descriptor['chunks']))
        n.need(payload==canonical(frozen) and sync.payload_hash(payload)==descriptor['hash'],'source snapshot bytes differ')
        report['snapshot']={**{k:v for k,v in descriptor.items() if k not in ('hash','metadata')},'payload_sha256':descriptor['hash'].hex(),'metadata':json.loads(descriptor['metadata']),'payload':frozen}
        refused=host_probes(network,raw,w,descriptor,payload)
        check('actual_native_hostile_snapshots_refused',len(refused)==9,{'mutations':refused})
        check('actual_atomic_import_reopen',True,{'transaction_rollback':True,'full_replay_reopen':True,'local_responses':0})
        _prepare_snapshot_provider(network,h)
        # Keep RPC1/2 available but remove the advancing subgroup's quorum.
        # Provider0 is isolated at H; discovery/reoffer cannot exhaust height64.
        network.stop_engine(3)
        trust_h=h-1;trust_block=rpc(network.http[1],'block',{'height':str(trust_h)})
        signed=rpc(network.http[1],'commit',{'height':str(h+1)})['signed_header']
        cert=verify_state(frozen,signed,raw,w)
        report.update(snapshot_signed_header=signed,snapshot_certificate=cert,
            light_client={'trust_height':trust_h,'trust_hash':trust_block['block_id']['hash'],
                          'provider_headers':[rpc(network.http[1],'commit',{'height':str(x)})['signed_header'] for x in (h+1,h+2)],
                          'rpc_sources':[1,2],'snapshot_peer':0,'trust_period':'168h0m0s'})
        check('snapshot_provider_headers',network.direct_state(0)==frozen and all(network.height(i)>=h+2 for i in (1,2)) and cert['app_hash']==frozen['app_hash'])
        config=network.homes/'node4/config/config.toml'
        config.write_text(patch_toml(config.read_text(),{'statesync.enable':True,
            'statesync.rpc_servers':f'http://127.0.0.1:{network.http[1]},http://127.0.0.1:{network.http[2]}',
            'statesync.trust_height':trust_h,'statesync.trust_hash':trust_block['block_id']['hash'],'statesync.trust_period':'168h0m0s'}))
        target_key=json.loads((network.homes/'node4/config/priv_validator_key.json').read_bytes())['pub_key']['value']
        check('target_fresh_nonvalidator',not (network.runtime/'app4/state.sqlite').exists() and 4 not in network.apps and 4 not in network.engines and
            base64.b64decode(target_key).hex() not in {v['public_key'] for v in validators})
        token=os.urandom(32).hex();private.append(token.encode());events=network.runtime/'state-sync-events.log'
        controls={'run_token':token,'run_token_sha256':digest(token.encode()),'crash_phase':'after_snapshot_commit','event_log':events}
        network.start_app(4,crash=controls);network.start_engine(4)
        wait_until(lambda:network.apps[4].poll() is not None,180)
        crash_pid=network.apps[4].pid;crash_code=network.apps[4].returncode
        check('actual_snapshot_commit_crash',crash_code==96,{'pid':crash_pid,'exit_code':crash_code,'phase':'after_snapshot_commit_before_final_apply_reply'})
        network.stop_engine(4);network.stop_app(4);controls['crash_phase']='observe'
        network.start_app(4,crash=controls);offset=len(_state_sync_events(events));network.start_engine(4)
        target=wait_until(lambda:_snapshot_engine_ready(network,4,h,events,offset),240)
        observed=_state_sync_events(events);offers=[e for e in observed if e['kind']=='offer_snapshot' and e['result']==OFFER_ACCEPT]
        report['state_sync_events']=observed
        check('actual_engine_reoffer_recovered',len(offers)>=2 and len({(e['pid'],e['start_ticks']) for e in offers})==2 and
            all(e['app_hash']==frozen['app_hash'] and e['payload_sha256']==descriptor['hash'].hex() for e in offers) and
            rpc(network.http[4],'status')['sync_info']['catching_up'] is False,{'offers':offers,'height':target['height']})
        check('trusted_snapshot_full_replay',target==frozen and verify_state(target,signed,raw,w)==cert)
        db=network.runtime/'app4/state.sqlite'
        with sqlite3.connect(db) as c:
            rows=c.execute('SELECT count(*) FROM p8_blocks').fetchone()[0];origin=c.execute('SELECT height,app_hash,payload_sha256 FROM p8_snapshot_origin WHERE id=1').fetchone()
        check('origin_no_invented_responses',rows==0 and origin==(h,frozen['app_hash'],descriptor['hash'].hex()),{'origin_height':h,'local_response_rows':rows})
        # Rejoin with the marker-only app still live. Its engine store is intact.
        network.start_engine(3);_restore_source_peers(network)
        network.set_empty_blocks(False,commit_delay='60s')
        joined=network.hold_sources_without_quorum()
        wait_until(lambda:canonical(network.direct_state(4))==canonical(joined),180)
        check('source_target_rejoin',all(canonical(network.direct_state(i))==canonical(joined) for i in range(5)),{'height':joined['height']})
        def sign(witness):
            for i in (2,3):
                if i not in network.engines:network.start_engine(i)
            wait_until(lambda:network.height(0)>=witness['height']+1,180)
            sh=rpc(network.http[0],'commit',{'height':str(witness['height']+1)})['signed_header']
            network.hold_sources_without_quorum();return sh
        joined_header=sign(joined)
        controller=NoteController(args.helper,report['inputs']['helper']['sha256'],expected_genesis=raw,worker=w)
        class AuditedProver(Prover):
            def produce(self,r):capture(r);return super().produce(r)
        prover=AuditedProver(args.prover,report['inputs']['prover']['sha256'],expected_genesis=raw,worker=w);controllers.extend([controller,prover])
        original={'origin':field(111),'value':20,'expiry':64,'note_secret':field(32),'blind':field(33)}
        request,origin=controller.construct(original,field(31),[note.hex()],request=field(21),valid_from=2,valid_until=32,fee=1,
            destination=controller.key(field(41)),payment=12,payment_expiry=60,payment_secret=field(42),payment_blind=field(43),change_secret=field(34),change_blind=field(35))
        capture(request);n.need(request[136:552]==first[8:424],'original received note reproduction differs')
        received={'origin':origin,'value':12,'expiry':60,'note_secret':field(42),'blind':field(43)}
        private.extend(received[k].encode() for k in ('origin','note_secret','blind'))
        d=network.runtime/'bob-wallet';d.mkdir(mode=0o700);key=os.urandom(32);private.extend([key.hex().encode(),field(41).encode()])
        bob=RecipientWallet(d/'wallet',create=True,key=key,wallet_id=os.urandom(32).hex(),recipient_secret=field(41),controller=controller)
        bob.observe(joined,joined_header);commitment=bob.import_note(received,raw=first)
        ident=bob.prepare(prover,commitment,request=field(71),destination=controller.key(field(51)),payment=4,valid_until=56,payment_expiry=56)
        spend=bob.export(ident);(fixtures/'post-sync-spend.tx').write_bytes(spend)
        check('recipient_from_restored_state',commitment==n.parse(first)[10] and prover.call_count==1 and n.parse(spend)[4] in joined['state']['ledger']['anchors'],{'txid':ident,'origin_state_height':joined['height'],'proof_count':2})
        bob.mark_attempt(ident);reply=network.broadcast(0,spend);n.need(int(reply['code'])==0,'post-sync broadcast refused')
        wait_until(lambda:spend in network.mempool_transactions(0) and spend in network.mempool_transactions(1),30)
        network.start_engine(2);network.start_engine(3)
        wait_until(lambda:all(len(network.direct_state(i)['state']['ledger']['receipts'])==2 for i in range(5)),180)
        spent=network.hold_sources_without_quorum();wait_until(lambda:canonical(network.direct_state(4))==canonical(spent),180)
        check('post_sync_payment_five_node_agreement',all(canonical(network.direct_state(i))==canonical(spent) for i in range(5)) and
              [r['txid'] for r in spent['state']['ledger']['receipts']]==[n.txid(first),ident],{'txids':[n.txid(first),ident],'height':spent['height'],'app_hash':spent['app_hash'],'broadcast_calls':1})
        spent_header=sign(spent);post_cert=verify_state(spent,spent_header,raw,w);bob.observe(spent,spent_header);resolution=bob.reconcile(ident)
        report.update(post_state=spent,post_signed_header=spent_header,post_certificate=post_cert,post_txid=ident,
            wallet_inventory=bob.inventory(),broadcast_calls=1,proof_count=2)
        check('signed_post_sync_exact_receipt',resolution['status']=='executed-exact' and resolution['receipt']['raw']==spend.hex() and
              bob.inventory()['obligations'][0]['attempts']==1)
        current=network.direct_state(0);wait_until(lambda:network.direct_state(4)==current,180)
        report['worker_audits'].append({'node':4,'phase':'before-restart',**network.worker_audit(4)})
        network.stop_node(4);network.start_app(4);network.start_engine(4)
        wait_until(lambda:rpc(network.http[4],'status')['sync_info']['catching_up'] is False and network.direct_state(4)==current,180)
        check('target_same_store_restart',network.direct_state(4)==current,{'height':current['height'],'app_hash':current['app_hash']})
        with sqlite3.connect(db) as c:
            local=[r[0] for r in c.execute('SELECT height FROM p8_blocks ORDER BY height')]
            marker=c.execute('SELECT height,app_hash,payload_sha256 FROM p8_snapshot_origin WHERE id=1').fetchone()
        check('origin_real_suffix_audited',local==list(range(h+1,current['height']+1)) and marker==origin,
              {'origin_height':h,'checkpoint_height':current['height'],'real_local_response_heights':local})
        report['worker_audits'].extend({'node':i,'phase':'final',**network.worker_audit(i)} for i in range(5))
        report['worker_audits'].extend({'node':'host','phase':str(i),**worker.audit()} for i,worker in enumerate(workers))
        report['private_audits']=[c.audit() for c in controllers]
        # Public evidence is scanned before owned cleanup copies exactly these files.
        public=canonical(report)+b''.join(p.read_bytes() for p in network.runtime.glob('*.log'))+b''.join(p.read_bytes() for p in fixtures.iterdir())
        # Small fixture secrets can numerically equal public window fields.
        # Full requests and random keys remain covered; do not label those
        # deliberately public numbers or destination keys as secret leakage.
        needles=[s for s in private if s not in raw and s not in first.hex().encode() and s not in spend.hex().encode()]
        n.need(all(s not in public and s.upper() not in public for s in needles),'private material in public evidence')
        check('private_material_absent',True,{'private_requests_archived':False,'wallet_files_archived':False,'private_keys_archived':False})
        audits=report['worker_audits']+report['private_audits']
        check('native_processes_reaped',all(a['call_count']==a['reaped_count'] and a['timeout_count']==0 and all(c['process_reaped'] for c in a['calls']) for a in audits) and
            all(c['process_reaped'] and c['exit_code']==0 for c in report['native_processes']))
    except Exception as e:report['error']={'type':type(e).__name__,'message':str(e)}
    finally:
        if network:
            try:network.close();check('workers_stopped',all(type(r.get('exit_code')) is int for r in report['processes']))
            except Exception as e:report['cleanup_error']={'type':type(e).__name__,'message':str(e)}
        report['checks'].append({'id':'source_unchanged','passed':source()==before,'evidence':{}})
        if [c['id'] for c in report['checks']]==list(CHECKS) and all(c['passed'] for c in report['checks']) and not report.get('error') and not report.get('cleanup_error'):
            report['status']='qualified-one-host-recipient-recovery'
        output.write_bytes(canonical(report)+b'\n')
    return 0 if report['status']=='qualified-one-host-recipient-recovery' else 1

if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__)
    for name in ('engine','worker','helper','fixture','prover','kat','output'):parser.add_argument('--'+name,type=Path,required=True)
    raise SystemExit(run(parser.parse_args()))
