#!/usr/bin/env python3
"""Finite synthetic P8 receive/spend qualification on four actual local validators."""
from __future__ import annotations
import argparse, base64, copy, hashlib, json, os, signal, socket, sqlite3, subprocess, sys, time, urllib.request
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1];sys.path.insert(0,str(ROOT/'src'))
import protocol8_transfer as native
from protocol8_consensus import (canonical,digest,genesis_document,bootstrap_digest,GENESIS_FORMAT,PROFILE_SHA256,StateError,application_hash)
from protocol8_worker import Worker
from protocol8_application import Application
from protocol8_certificate import verify_state
from protocol5_encoding import comet_validator_set
from protocol5_abci_wire import Response
from abci_wire import write_frame,read_frame
from run_protocol5_engine import Protocol5Network,ENGINE_SHA256,_application_ready,_engine_consensus_ready,_stop,_hold_transaction_height
from run_devnet import patch_toml,rpc,wait_until

CHECKS=('source_clean','engine_identity','fresh_native_network_proofs','atomic_store_failure_and_recovery',
        'all_four_initialized','malformed_context_badproof_refused','nonreserving_admission',
        'ordered_dependent_proposals','competing_nullifier_proposals','recipient_receive_committed',
        'valid_spent_note_and_intent_refused','recipient_respend_committed','same_store_restart_converges',
        'four_validator_agreement','signed_next_header_replayed','certificate_tampers_refused',
        'native_processes_reaped','workers_stopped','source_unchanged')
CLAIMS={'one_host_four_validators':True,'native_recipient_proof':True,'recipient_receive_respend':True,
        'authenticated_full_state':True,'as_of_only':True,'production_ready':False,'real_funds':False,
        'public_network':False,'independent_operators':False,'custody_qualified':False,'state_sync_qualified':False,
        'p7_migration':False,'owner_allowance_composition':False,'freshness_established':False,
        'seccomp_worker':False,'independent_cryptographic_audit':False}
SOURCE_NAMES=('src/protocol8_consensus.py','src/protocol8_worker.py','src/protocol8_application.py',
    'src/protocol8_abci_server.py','src/protocol8_certificate.py','scripts/protocol8_worker_exec.py',
    'scripts/serve_abci_p8.py','scripts/run_protocol8_engine.py','tests/test_protocol8_consensus.py','tests/test_protocol8_engine_report.py',
    'tools/release/check_protocol8_engine.py')
SOURCE_PREFIXES=('src/','scripts/','tools/recipient-transfer/','tools/recipient-consensus-bridge/','tools/shielded-consensus/halo2/')
def source():
    def git(*args):return subprocess.check_output(['git','-C',str(ROOT),*args],text=True).strip()
    paths=set(SOURCE_NAMES)|{p for p in git('ls-files').splitlines() if p.startswith(SOURCE_PREFIXES)}
    return {'commit':git('rev-parse','HEAD'),'tree':git('rev-parse','HEAD^{tree}'),'clean':not git('status','--porcelain'),
        'files':{p:{'bytes':(ROOT/p).stat().st_size,'sha256':digest((ROOT/p).read_bytes())} for p in sorted(paths)}}
def field(v):return v.to_bytes(32,'little').hex()

class Network(Protocol5Network):
    # Inherit only owned-process and loopback RPC mechanics; no P5 state or worker.
    def __init__(self,paths,output,report):
        super().__init__(paths,output,report,include_target=False)
        self.chain_id='one-p8-'+os.urandom(6).hex();self.genesis_path=self.runtime/'p8-genesis.json'
    def install_genesis(self,raw,worker):
        g=genesis_document(raw,worker)
        expected={base64.b64decode(v['pub_key']['value'],validate=True).hex():int(v['power']) for v in self.engine_genesis['validators']}
        native.need(g['chain_id']==self.chain_id and {v['public_key']:v['power'] for v in g['validators']}==expected,'P8 engine roster differs')
        self.genesis_path.write_bytes(raw);self.genesis_sha256=digest(raw)
        self.engine_genesis.update(chain_id=self.chain_id,initial_height='1',app_state=g)
        self.engine_genesis['consensus_params']['block'].update(max_bytes='1048576',max_gas='-1')
        for i in range(5):
            home=self.homes/f'node{i}';(home/'config/genesis.json').write_bytes(canonical(self.engine_genesis)+b'\n')
            app=self.runtime/f'app{i}';app.mkdir(mode=0o700)
            config=home/'config/config.toml';config.write_text(patch_toml(config.read_text(),{
                'proxy_app':f"unix://{app/'a.sock'}",'abci':'socket','rpc.laddr':f'tcp://127.0.0.1:{self.http[i]}',
                'rpc.unsafe':False,'rpc.timeout_broadcast_tx_commit':'50s',
                'p2p.laddr':f'tcp://127.0.0.1:{self.p2p[i]}',
                'p2p.persistent_peers':','.join(f'{self.node_ids[j]}@127.0.0.1:{self.p2p[j]}' for j in range(4) if j!=i),
                'p2p.addr_book_strict':False,'p2p.allow_duplicate_ip':True,'p2p.pex':False,
                'consensus.timeout_propose':'30s','consensus.timeout_prevote':'10s','consensus.timeout_precommit':'10s',
                'consensus.timeout_commit':'3s','consensus.create_empty_blocks':False,
                'consensus.create_empty_blocks_interval':'0s','mempool.max_tx_bytes':4096}))
    def abci(self,index,request):
        with socket.socket(socket.AF_UNIX,socket.SOCK_STREAM) as connection:
            connection.settimeout(100);connection.connect(str(self.runtime/f'app{index}/a.sock'))
            with connection.makefile('rwb',buffering=0) as stream:write_frame(stream,request);raw=read_frame(stream)
        native.need(raw is not None,'P8 private endpoint closed')
        response=Response.FromString(raw);native.need(response.WhichOneof('value')!='exception','P8 private exception')
        return response
    def start_app(self,i,*,crash=None):
        native.need(crash is None,'no P8 runtime fault endpoint')
        endpoint=self.runtime/f'app{i}/a.sock'
        if endpoint.exists():
            native.need(i not in self.apps or self.apps[i].poll() is not None,'P8 live socket owner')
            endpoint.unlink()
        log=(self.runtime/f'app{i}.log').open('ab');self.handles.append(log)
        cmd=[sys.executable,'-B',str(ROOT/'scripts/serve_abci_p8.py'),'--genesis',str(self.genesis_path),
            '--genesis-sha256',self.genesis_sha256,'--database',str(self.runtime/f'app{i}/state.sqlite'),
            '--socket',str(endpoint),'--worker',str(self.paths['worker']),'--kat',str(self.paths['kat'])]
        p=subprocess.Popen(cmd,stdout=log,stderr=log);self.apps[i]=p
        self._record('application',i,p,digest((ROOT/'scripts/serve_abci_p8.py').read_bytes()))
        wait_until(lambda:_application_ready(self,i,p,endpoint),120)
    def broadcast(self,index,transaction):
        body=canonical({'jsonrpc':'2.0','id':1,'method':'broadcast_tx_sync',
            'params':{'tx':base64.b64encode(transaction).decode('ascii')}})
        req=urllib.request.Request(f'http://127.0.0.1:{self.http[index]}',data=body,headers={'Content-Type':'application/json'})
        with urllib.request.build_opener(urllib.request.ProxyHandler({})).open(req,timeout=90) as response:value=json.load(response)
        native.need('error' not in value,'P8 broadcast RPC failed');return value['result']
    def worker_audit(self,i):
        from protocol5_abci_wire import Request
        q=Request();q.query.path='/worker-receipts';out=self.abci(i,q).query
        native.need(out.code==0,'P8 worker audit query failed');return json.loads(out.value)
    def close(self):
        for process in list(self.engines.values())+list(self.apps.values()):self._record_exit(process.pid,_stop(process))
        for f in self.handles:f.close()
        artifacts=self.output.with_name(self.output.name+'.artifacts');artifacts.mkdir(mode=0o700)
        manifest=[]
        for original in sorted(self.runtime.glob('*.log')):
            raw=original.read_bytes();native.need(len(raw)<=8*1024**2,'raw log bound; never silently truncated')
            raw=raw.replace(str(self.runtime).encode(),b'<private-run>');target=artifacts/original.name;target.write_bytes(raw)
            manifest.append({'name':target.name,'bytes':len(raw),'sha256':digest(raw)})
        for original in sorted(self.paths.get('fixtures',self.runtime/'absent').glob('*')):
            native.need(original.is_file() and not original.is_symlink() and original.suffix in ('.tx','.json'),'public fixture membership')
            raw=original.read_bytes();target=artifacts/('fixture-'+original.name);target.write_bytes(raw)
            manifest.append({'name':target.name,'bytes':len(raw),'sha256':digest(raw)})
        self.report['artifacts']=manifest;self.report['processes']=self.receipts
        self.temp.cleanup() # Only this qualification's owned temporary runtime.

def run(args):
    output=args.output.absolute();native.need(not output.exists() and not output.with_name(output.name+'.artifacts').exists(),'fresh output required')
    before=source();report={'format':'1soft/protocol8-recipient-engine/v1','status':'failed','source':before,
        'claims':CLAIMS.copy(),'checks':[],'inputs':{},'native_processes':[],'worker_audits':[]};network=None;w=None;preliminary=None
    def check(name,ok,evidence=None):
        report['checks'].append({'id':name,'passed':bool(ok),'evidence':evidence or {}})
        print('P8_CHECK '+name+' '+str(bool(ok)),flush=True);native.need(ok,'gate failed: '+name)
    def invoke(name,op,raw):
        path=getattr(args,name);native.need(digest(path.read_bytes())==report['inputs'][name]['sha256'],'native binary changed')
        started=time.monotonic();proc=subprocess.Popen([str(path)]+([op] if op else []),stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,stderr=subprocess.PIPE,env={},start_new_session=True)
        try:ticks=Path(f'/proc/{proc.pid}/stat').read_text().rsplit(')',1)[1].split()[19]
        except OSError:ticks=None
        timed_out=False
        try:out,err=proc.communicate(raw,timeout=120)
        except subprocess.TimeoutExpired:
            timed_out=True;os.killpg(proc.pid,signal.SIGKILL);out,err=proc.communicate();raise native.Unavailable('fixture/prover deadline')
        finally:
            if proc.poll() is None:os.killpg(proc.pid,signal.SIGKILL);proc.communicate()
            report['native_processes'].append({'binary':name,'operation':op or 'prove','pid':proc.pid,'start_ticks':ticks,
                'exit_code':proc.returncode,'binary_sha256':report['inputs'][name]['sha256'],'process_reaped':proc.poll() is not None,
                'input_bytes':len(raw),'output_bytes':len(out) if 'out' in locals() else 0,'timed_out':timed_out,
                'elapsed_seconds':round(time.monotonic()-started,6)})
        native.need(proc.returncode==0 and not err and len(out)<=4096,'closed fixture/prover result');return out
    try:
        check('source_clean',before['clean'])
        for name in ('engine','worker','fixture','prover'):
            path=getattr(args,name);native.need(path.is_file() and not path.is_symlink() and 0<path.stat().st_size<=64*1024**2,'bounded binary')
            report['inputs'][name]={'bytes':path.stat().st_size,'sha256':digest(path.read_bytes())}
        report['inputs']['verifier_feature_mode']='no-default-features';report['inputs']['fixture_feature_mode']='fixtures/prover'
        check('engine_identity',report['inputs']['engine']['sha256']==ENGINE_SHA256 and subprocess.check_output([str(args.engine),'version'],text=True).strip()=='0.38.25')
        preliminary=Worker(args.worker,report['inputs']['worker']['sha256'],args.kat.read_bytes())
        network=Network({'engine':args.engine,'worker':args.worker},output,report)
        validators=sorted([{'public_key':base64.b64decode(v['pub_key']['value'],validate=True).hex(),'power':int(v['power'])}
                           for v in network.engine_genesis['validators']],key=lambda v:v['public_key'])
        g={'format':GENESIS_FORMAT,'protocol_version':8,'chain_id':network.chain_id,'profile_sha256':PROFILE_SHA256,
            'worker_sha256':report['inputs']['worker']['sha256'],'kat_sha256':preliminary.kat_sha256,
            'validators':validators,'pool_id':os.urandom(32).hex(),'asset':field(2),'mission':field(3),
            'fee':1,'network':field(1),'notes':[]}
        bootstrap=bytes.fromhex(bootstrap_digest(g));domain=preliminary.network_domain(bootstrap)
        fixtures=network.runtime/'proof-fixtures';fixtures.mkdir(mode=0o700);network.paths['fixtures']=fixtures
        txs={}
        for name in ('first','second','competing','duplicate-intent','wrong-fee'):
            request=bytearray(invoke('fixture',name,bootstrap))
            native.need(len(request)==1160,'private synthetic request size')
            try:txs[name]=invoke('prover',None,request)
            finally:request[:]=b'\0'*len(request)
            native.parse(txs[name]);(fixtures/(name+'.tx')).write_bytes(txs[name])
            print('P8_PROOF '+name+' generated',flush=True)
        note=invoke('fixture','genesis-note',bootstrap);native.need(len(note)==32,'typed genesis commitment')
        g['network']=domain;g['notes']=[{'kind':'p8-recipient-v1','commitment':note.hex()}];g['kat_sha256']=digest(txs['first'])
        network.paths['kat']=fixtures/'first.tx';w=Worker(args.worker,g['worker_sha256'],txs['first']);raw=canonical(g)
        (fixtures/'genesis.json').write_bytes(raw);report.update(genesis=g,genesis_sha256=digest(raw),bootstrap_sha256=bootstrap.hex())
        report['inputs']['fixtures']={name:digest(tx) for name,tx in txs.items()}
        check('fresh_native_network_proofs',genesis_document(raw,w)==g and all(w.verify(tx,domain) for tx in txs.values()) and
            domain!=preliminary.kat_statement[1] and native.parse(txs['first'])[5]==native.parse(txs['competing'])[5],
            {'proof_count':5,'worker_startup':w.startup,'domain':domain})
        # Fault injection stays in a separate owned synthetic database, never a live validator store.
        d=network.runtime/'atomic-probe';d.mkdir(mode=0o700);db=d/'state.sqlite'
        a=Application(db,w,expected_genesis=raw);a.init_chain(g['chain_id'],raw,validators);old=a.query('/state')['value']
        # The first fixture begins at height 2: commit an empty block 1 first.
        a.finalize_block([],1,b'a'*32,bytes.fromhex(a.validators.hash),[],b'empty');a.commit();old=a.query('/state')['value']
        votes=[{'address':v.address.hex(),'power':v.power,'block_id_flag':2} for v in a.validators.validators]
        value,response=a.finalize_block([txs['first']],2,b'x'*32,bytes.fromhex(a.validators.hash),votes,b'probe')
        native.need(value['tx_results'][0]['code']==0,'actual atomic probe payment')
        a.db.execute("CREATE TEMP TRIGGER fail BEFORE INSERT ON p8_blocks BEGIN SELECT RAISE(ABORT,'injected'); END")
        try:a.commit();raise AssertionError('atomic failure not injected')
        except sqlite3.IntegrityError:pass
        native.need(a.query('/state')['value']==old,'atomic checkpoint changed')
        a.close();a=Application(db,w,expected_genesis=raw);native.need(a.query('/state')['value']==old,'atomic reopen changed')
        a.finalize_block([txs['first']],2,b'x'*32,bytes.fromhex(a.validators.hash),votes,b'probe');a.commit();a.close()
        a=Application(db,w,expected_genesis=raw);native.need(a.finalize_block([txs['first']],2,b'x'*32,bytes.fromhex(a.validators.hash),votes,b'probe')==(value,response),'exact durable recovery response')
        try:a.finalize_block([txs['first']],2,b'x'*32,bytes.fromhex(a.validators.hash),votes,b'changed');raise AssertionError('conflict accepted')
        except StateError:pass
        a.close();check('atomic_store_failure_and_recovery',True)
        network.install_genesis(raw,w);network.start_sources()
        from protocol5_abci_wire import Request
        startup=[]
        for i in range(4):
            q=Request();q.query.path='/info';startup.append(json.loads(network.abci(i,q).query.value)['worker_startup'])
        check('all_four_initialized',all(network.direct_state(i)['genesis']==g for i in range(4)) and all(s==w.startup for s in startup),{'worker_startup':startup})
        held=_hold_transaction_height(network);h=held['height']+1;vh=bytes.fromhex(comet_validator_set(validators).hash)
        native.need(2<=h<32,'finite synthetic transfer height')
        bad=bytearray(txs['first']);bad[-1]^=1
        check('malformed_context_badproof_refused',all(network.direct_check(i,txs['first']+b'x')==1 and
            network.direct_check(i,args.kat.read_bytes())==2 and network.direct_check(i,bytes(bad))==6 and
            network.direct_check(i,txs['wrong-fee'])==2 for i in range(4)))
        check('nonreserving_admission',all(network.direct_check(i,txs['first'])==0 and
            network.direct_check(i,txs['competing'])==0 and network.direct_state(i)==held for i in range(4)))
        probes=[]
        for i in range(4):
            ordered=[txs['first'],txs['second']];reverse=list(reversed(ordered))
            ok=(network.direct_prepare(i,ordered,h,8208)==ordered and network.direct_process(i,ordered,h,vh)==1 and
                network.direct_prepare(i,reverse,h,8208)==[txs['first']] and network.direct_process(i,reverse,h,vh)==2 and network.direct_state(i)==held)
            probes.append({'node':i,'passed':ok})
        check('ordered_dependent_proposals',all(v['passed'] for v in probes),{'probes':probes})
        check('competing_nullifier_proposals',all(network.direct_prepare(i,[txs['first'],txs['competing']],h,8208)==[txs['first']] and
            network.direct_process(i,[txs['first'],txs['competing']],h,vh)==2 for i in range(4)))
        def accepted(count):
            rows=[network.direct_state(i) for i in range(4)]
            return rows if all(len(r['state']['ledger']['receipts'])==count for r in rows) else None
        network.stage_without_quorum([txs['first']]);rows=wait_until(lambda:accepted(1),180);held=network.hold_sources_without_quorum()
        check('recipient_receive_committed',all(r['state']['ledger']['fees']==1 and len(r['state']['ledger']['notes'])==3 and
            r['state']['ledger']['notes'][1]['commitment']==native.parse(txs['first'])[10] for r in rows))
        check('valid_spent_note_and_intent_refused',all(network.direct_check(i,txs['competing'])==5 and network.direct_check(i,txs['duplicate-intent'])==5 for i in range(4)))
        network.stage_without_quorum([txs['second']]);rows=wait_until(lambda:accepted(2),180);held=network.hold_sources_without_quorum()
        expected=[native.txid(txs['first']),native.txid(txs['second'])]
        check('recipient_respend_committed',all([r['txid'] for r in row['state']['ledger']['receipts']]==expected and
            row['state']['ledger']['fees']==2 and len(row['state']['ledger']['notes'])==5 for row in rows),{'txids':expected})
        # Save the outgoing app's bounded native receipts before ordinary same-store restart.
        report['worker_audits'].append({'node':3,'phase':'before-restart',**network.worker_audit(3)})
        network.start_engine(2);network.start_engine(3);network.stop_node(3);network.start_app(3);network.start_engine(3)
        wait_until(lambda:_engine_consensus_ready(network,3,max(network.height(i) for i in (0,1,2))),180)
        check('same_store_restart_converges',[r['txid'] for r in network.direct_state(3)['state']['ledger']['receipts']]==expected)
        witness=network.hold_sources_without_quorum();allstates=[network.direct_state(i) for i in range(4)]
        check('four_validator_agreement',all(canonical(s)==canonical(witness) for s in allstates))
        network.start_engine(2);network.start_engine(3);wait_until(lambda:network.height(0)>=witness['height']+1,180)
        signed=rpc(network.http[0],'commit',{'height':str(witness['height']+1)})['signed_header'];cert=verify_state(witness,signed,raw,w)
        report.update(state_witness=witness,signed_header=signed,certificate=cert)
        check('signed_next_header_replayed',cert['state_height']==witness['height'] and cert['app_hash']==witness['app_hash'])
        refused=[]
        for name in ('fees','history','genesis','height','app_hash'):
            forged=copy.deepcopy(witness)
            if name=='fees':forged['state']['ledger']['fees']+=1
            elif name=='history':forged['state']['blocks'][-1]['results'].append({'code':0,'data':'','log':''})
            elif name=='genesis':forged['genesis']['pool_id']='ef'*32
            elif name=='height':forged['height']+=1
            else:forged['app_hash']='ff'*32
            try:verify_state(forged,signed,raw,w);raise AssertionError('certificate tamper accepted')
            except StateError:refused.append(name)
        for name in ('header-apphash','header-height','signature'):
            forged=copy.deepcopy(signed)
            if name=='header-apphash':forged['header']['app_hash']='FF'*32
            elif name=='header-height':forged['header']['height']=str(witness['height']+2)
            else:
                voting=[r for r in forged['commit']['signatures'] if r['block_id_flag']==2]
                native.need(len(voting)>=3,'actual signed quorum missing')
                for row in voting[:2]:
                    signature=bytearray(base64.b64decode(row['signature'],validate=True));signature[0]^=1
                    row['signature']=base64.b64encode(signature).decode()
            try:verify_state(witness,forged,raw,w);raise AssertionError('signed certificate tamper accepted')
            except ValueError:refused.append(name)
        check('certificate_tampers_refused',len(refused)==8,{'mutations':refused})
        report['worker_audits'].extend({'node':i,'phase':'final',**network.worker_audit(i)} for i in range(4))
        report['worker_audits'].extend([{'node':'host','phase':'fresh',**w.audit()},{'node':'host','phase':'bootstrap',**preliminary.audit()}])
        check('native_processes_reaped',all(r['call_count']==r['reaped_count'] and r['timeout_count']==0 and
            all(c['process_reaped'] and c['start_ticks'] is not None for c in r['calls']) for r in report['worker_audits']) and
            all(r['process_reaped'] and not r['timed_out'] and r['start_ticks'] is not None for r in report['native_processes']))
    except Exception as e:report['error']={'type':type(e).__name__,'message':str(e)}
    finally:
        if network:
            try:network.close();check('workers_stopped',all(type(r.get('exit_code')) is int for r in report['processes']))
            except Exception as e:report['cleanup_error']={'type':type(e).__name__,'message':str(e)}
        report['checks'].append({'id':'source_unchanged','passed':source()==before,'evidence':{}})
        if [c['id'] for c in report['checks']]==list(CHECKS) and all(c['passed'] for c in report['checks']) and not report.get('cleanup_error'):
            report['status']='qualified-one-host-recipient-consensus'
        output.write_bytes(canonical(report)+b'\n')
    return 0 if report['status']=='qualified-one-host-recipient-consensus' else 1

def main():
    parser=argparse.ArgumentParser(description=__doc__)
    for name in ('engine','worker','fixture','prover','kat','output'):parser.add_argument('--'+name,type=Path,required=True)
    raise SystemExit(run(parser.parse_args()))
if __name__=='__main__':main()
