#!/usr/bin/env python3
"""Bounded one-host synthetic qualification of the segmented recipient ledger."""
import argparse
import base64
import hashlib
import json
import os
import signal
import subprocess
import sys
import time
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1];sys.path.insert(0,str(ROOT/'src'))
import protocol8_transfer as n
from protocol8_worker import Worker
from protocol9_consensus import GENESIS_FORMAT,bootstrap_digest,genesis_document
from protocol9_application import Application
from protocol9_notes import NoteController,Prover
from protocol5_abci_wire import Request
from commit_verifier import Validator,TrustAnchor,merkle_root,verify_signed_header
from run_protocol8_engine import Network as BaseNetwork,field
from run_protocol5_engine import ENGINE_SHA256,_application_ready,_engine_consensus_ready
from run_devnet import patch_toml,rpc,wait_until

CHECKS=('source_clean','engine_identity','fresh_native_proofs','direct_attempt_history_exceeds32',
        'direct_store_streamed_native_reopen','four_validators_initialized','nine_payments_committed',
        'old_segment_valid_competing_spend_refused','past64_and_payment_committed',
        'same_store_validator_restart','four_validator_checkpoint_agreement','signed_next_header',
        'stopped_store_separate_native_replay','native_processes_reaped','workers_stopped','source_unchanged')

def source():
    def git(*args):return subprocess.check_output(['git','-C',str(ROOT),*args],text=True).strip()
    names=git('ls-files').splitlines()
    return {'commit':git('rev-parse','HEAD'),'tree':git('rev-parse','HEAD^{tree}'),
            'clean':not git('status','--porcelain'),'files':{name:{'bytes':(ROOT/name).stat().st_size,
            'sha256':n.sha((ROOT/name).read_bytes())} for name in names}}

def finalize(app,txs):
    h=app.height+1;q=Request().finalize_block;q.height=h;q.hash=h.to_bytes(32,'big')
    q.next_validators_hash=bytes.fromhex(app.validators.hash);q.txs.extend(txs);votes=[]
    if h>1:
        for v in app.validators.validators:
            x=q.decided_last_commit.votes.add();x.validator.address=v.address;x.validator.power=v.power;x.block_id_flag=2
            votes.append({'address':v.address.hex(),'power':v.power,'block_id_flag':2})
    value,_=app.finalize_block(txs,h,bytes(q.hash),bytes(q.next_validators_hash),votes,q.SerializeToString(deterministic=True))
    app.commit();return value

class Network(BaseNetwork):
    def __init__(self,paths,output,report):
        super().__init__(paths,output,report);self.chain_id='one-p9-'+os.urandom(6).hex()
        self.genesis_path=self.runtime/'p9-genesis.json'
    def install_genesis(self,raw,worker):
        g=genesis_document(raw,worker)
        roster={base64.b64decode(v['pub_key']['value'],validate=True).hex():int(v['power']) for v in self.engine_genesis['validators']}
        n.need(g['chain_id']==self.chain_id and {v['public_key']:v['power'] for v in g['validators']}==roster,'P9 engine roster')
        self.genesis_path.write_bytes(raw);self.genesis_sha256=n.sha(raw)
        self.engine_genesis.update(chain_id=self.chain_id,initial_height='1',app_state=g)
        self.engine_genesis['consensus_params']['block'].update(max_bytes='1048576',max_gas='-1')
        for i in range(5):
            home=self.homes/f'node{i}';(home/'config/genesis.json').write_bytes(n.canonical(self.engine_genesis)+b'\n')
            app=self.runtime/f'app{i}';app.mkdir(mode=0o700)
            config=home/'config/config.toml';config.write_text(patch_toml(config.read_text(),{
                'proxy_app':f"unix://{app/'a.sock'}",'abci':'socket','rpc.laddr':f'tcp://127.0.0.1:{self.http[i]}',
                'rpc.unsafe':False,'rpc.timeout_broadcast_tx_commit':'50s','p2p.laddr':f'tcp://127.0.0.1:{self.p2p[i]}',
                'p2p.persistent_peers':','.join(f'{self.node_ids[j]}@127.0.0.1:{self.p2p[j]}' for j in range(4) if j!=i),
                'p2p.addr_book_strict':False,'p2p.allow_duplicate_ip':True,'p2p.pex':False,
                'consensus.timeout_propose':'10s','consensus.timeout_prevote':'1s','consensus.timeout_precommit':'1s',
                'consensus.timeout_commit':'500ms','consensus.create_empty_blocks':True,
                'consensus.create_empty_blocks_interval':'0s','mempool.max_tx_bytes':4096}))
    def start_app(self,i,*,crash=None):
        n.need(crash is None,'no P9 fault endpoint');endpoint=self.runtime/f'app{i}/a.sock'
        if endpoint.exists():
            n.need(i not in self.apps or self.apps[i].poll() is not None,'P9 live socket owner');endpoint.unlink()
        log=(self.runtime/f'app{i}.log').open('ab');self.handles.append(log)
        command=[sys.executable,'-B',str(ROOT/'scripts/serve_abci_p9.py'),'--genesis',str(self.genesis_path),
                 '--genesis-sha256',self.genesis_sha256,'--database',str(self.runtime/f'app{i}/state.sqlite'),
                 '--socket',str(endpoint),'--worker',str(self.paths['worker']),'--kat',str(self.paths['kat'])]
        child=subprocess.Popen(command,stdout=log,stderr=log);self.apps[i]=child
        self._record('application',i,child,n.sha((ROOT/'scripts/serve_abci_p9.py').read_bytes()))
        wait_until(lambda:_application_ready(self,i,child,endpoint),180)

def run(args):
    output=args.output.absolute();n.need(not output.exists() and not output.with_name(output.name+'.artifacts').exists(),'fresh P9 output')
    before=source();report={'format':'1soft/segmented-recipient-engine/v1','status':'failed','source':before,
        'checks':[],'inputs':{},'native_processes':[],'worker_audits':[],
        'claims':{'one_host_four_validators':True,'real_funds':False,'public_network':False,
        'independent_operators':False,'production_custody':False,'external_cryptographic_review':False,
        'wallet_compatible':False,'state_sync':False,'pruning':False,'long_duration_load':False}}
    network=None;private=[];workers=[];probe=None
    def check(name,ok,evidence=None):
        report['checks'].append({'id':name,'passed':bool(ok),'evidence':evidence or {}})
        print('P9_CHECK '+name+' '+str(bool(ok)),flush=True);n.need(ok,'P9 gate failed: '+name)
    def invoke_fixture(op,bootstrap):
        n.need(n.sha(args.fixture.read_bytes())==report['inputs']['fixture']['sha256'],'P9 fixture binary changed')
        child=subprocess.Popen([str(args.fixture),op],stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=subprocess.PIPE,env={},start_new_session=True)
        ticks=Path(f'/proc/{child.pid}/stat').read_text().rsplit(')',1)[1].split()[19];out=b'';timed_out=False
        try:
            try:out,err=child.communicate(bootstrap,timeout=45)
            except subprocess.TimeoutExpired:timed_out=True;raise n.Unavailable('fixture deadline') from None
            n.need(child.returncode==0 and not err and len(out)<=1160,'P9 fixture output');return out
        finally:
            try:os.killpg(child.pid,signal.SIGKILL)
            except ProcessLookupError:pass
            child.communicate();report['native_processes'].append({'operation':op,'pid':child.pid,'start_ticks':ticks,
                'binary_sha256':report['inputs']['fixture']['sha256'],'exit_code':child.returncode,
                'input_bytes':32,'output_bytes':len(out),'process_reaped':child.poll() is not None,'timed_out':timed_out})
    try:
        check('source_clean',before['clean'])
        for name in ('engine','worker','helper','fixture','prover'):
            path=getattr(args,name);n.need(path.is_file() and not path.is_symlink() and 0<path.stat().st_size<=64*1024**2,'P9 binary input')
            report['inputs'][name]={'bytes':path.stat().st_size,'sha256':n.sha(path.read_bytes())}
        check('engine_identity',report['inputs']['engine']['sha256']==ENGINE_SHA256 and
              subprocess.check_output([str(args.engine),'version'],text=True).strip()=='0.38.25')
        seed=Worker(args.worker,report['inputs']['worker']['sha256'],args.kat.read_bytes());workers.append(seed)
        network=Network({'engine':args.engine,'worker':args.worker},output,report)
        vals=sorted([{'public_key':base64.b64decode(v['pub_key']['value'],validate=True).hex(),'power':int(v['power'])}
                     for v in network.engine_genesis['validators']],key=lambda v:v['public_key'])
        g={'format':GENESIS_FORMAT,'protocol_version':9,'chain_id':network.chain_id,'profile_sha256':n.PROFILE_SHA256,
            'worker_sha256':seed.sha256,'kat_sha256':seed.kat_sha256,'validators':vals,'pool_id':os.urandom(32).hex(),
            'asset':field(2),'mission':field(3),'fee':1,'network':field(1),'notes':[]}
        bootstrap=bytes.fromhex(bootstrap_digest(g));g['network']=seed.network_domain(bootstrap)
        note=invoke_fixture('genesis-note',bootstrap);n.need(len(note)==32,'P9 initial note size')
        g['notes']=[{'kind':'p8-recipient-v1','commitment':note.hex()}]
        controller=NoteController(args.helper,report['inputs']['helper']['sha256'],g=g,worker=seed)
        prover=Prover(args.prover,report['inputs']['prover']['sha256'],g=g,worker=seed);private.extend((controller,prover))
        request=bytearray(invoke_fixture('first',bootstrap))
        try:first=prover.produce(bytes(request))
        finally:request[:]=bytes(len(request))
        g['kat_sha256']=n.sha(first);raw=n.canonical(g);w=Worker(args.worker,g['worker_sha256'],first);workers.append(w)
        n.need(genesis_document(raw,w)==g,'P9 genesis native validation');controller.worker=w;prover.worker=w
        request=bytearray(invoke_fixture('competing',bootstrap))
        try:competing=prover.produce(bytes(request))
        finally:request[:]=bytes(len(request))
        fixtures=network.runtime/'public-proofs';fixtures.mkdir(mode=0o700);network.paths['fixtures']=fixtures
        (fixtures/'genesis.json').write_bytes(raw);(fixtures/'first.tx').write_bytes(first);(fixtures/'competing.tx').write_bytes(competing)
        network.paths['kat']=fixtures/'first.tx'
        d=network.runtime/'direct-probe';d.mkdir(mode=0o700);probe=Application(d/'state.sqlite',w,expected_genesis=raw)
        probe.init_chain(g['chain_id'],raw,vals);finalize(probe,[]);finalize(probe,[first])
        initial={'origin':field(111),'value':1000,'expiry':100000,'note_secret':field(32),'blind':field(33)}
        req,origin=controller.construct(initial,field(31),[note.hex()],request=field(21),valid_from=2,valid_until=100000,
            destination=controller.key(field(41)),payment=400,payment_expiry=100000,payment_secret=field(42),
            payment_blind=field(43),change_secret=field(34),change_blind=field(35))
        n.need(req[136:552]==first[8:424],'P9 synthetic opening projection differs');req=None
        opening={'origin':origin,'value':400,'expiry':100000,'note_secret':field(42),'blind':field(43)}
        txs=[first]
        # Eight further spends follow the recipient's change, including rollover.
        for i in range(1,10):
            ps,pb,cs,cb=[field(700+i*4+j) for j in range(4)]
            req,origin=controller.construct(opening,field(41),probe.checkpoint['active_notes'],request=field(900+i),
                valid_from=2,valid_until=100000,destination=controller.key(field(51)),payment=1,payment_expiry=100000,
                payment_secret=ps,payment_blind=pb,change_secret=cs,change_blind=cb)
            request=bytearray(req);req=None
            try:wire=prover.produce(bytes(request))
            finally:request[:]=bytes(len(request))
            txs.append(wire);(fixtures/(f'payment-{i:02}.tx')).write_bytes(wire)
            n.need(finalize(probe,[wire])['tx_results'][0]['code']==0,'P9 direct actual spend failed')
            opening={'origin':origin,'value':opening['value']-2,'expiry':100000,'note_secret':cs,'blind':cb}
            print('P9_PROOF '+str(i)+' generated',flush=True)
        check('fresh_native_proofs',len(txs)==10 and w.verify(competing,g['network']) and
              n.parse(first)[5]==n.parse(competing)[5] and g['network']!=seed.kat_statement[1],{'accepted_proofs':10,'competing_proofs':1})
        for _ in range(40):n.need(finalize(probe,[b'malformed'])['tx_results'][0]['code']==1,'P9 decided refusal')
        check('direct_attempt_history_exceeds32',probe.checkpoint['attempt_count']==50 and probe.checkpoint['notes_count']==21,
              {'height':probe.height,'attempts':50,'notes':21,'scope':'direct application, not engine consensus'})
        before_probe=probe.info();probe.close();probe=Application(d/'state.sqlite',w,expected_genesis=raw)
        check('direct_store_streamed_native_reopen',probe.info()==before_probe);probe.close();probe=None
        network.install_genesis(raw,w);network.start_sources()
        check('four_validators_initialized',all(network.direct_state(i)['genesis']==g for i in range(4)))
        for count,wire in enumerate(txs[:9],1):
            admission=network.broadcast(0,wire);n.need(int(admission['code'])==0,'P9 engine admission refused')
            wait_until(lambda:all(network.direct_state(i)['checkpoint']['accepted_count']==count for i in range(4)),240)
            print('P9_PAYMENT '+str(count)+' committed',flush=True)
        check('nine_payments_committed',all(network.direct_state(i)['checkpoint']['notes_count']==19 for i in range(4)),{'notes':19,'payments':9})
        check('old_segment_valid_competing_spend_refused',all(network.direct_check(i,competing)==5 for i in range(4)))
        wait_until(lambda:all(network.direct_state(i)['height']>64 for i in range(4)),180)
        admission=network.broadcast(0,txs[9]);n.need(int(admission['code'])==0,'P9 post64 admission refused')
        wait_until(lambda:all(network.direct_state(i)['checkpoint']['accepted_count']==10 for i in range(4)),240)
        final_height=network.direct_state(0)['height']
        check('past64_and_payment_committed',final_height>64 and all(network.direct_state(i)['checkpoint']['notes_count']==21 for i in range(4)),
              {'observed_height':final_height,'notes':21,'payments':10})
        report['worker_audits'].append({'node':3,'phase':'before-restart',**network.worker_audit(3)})
        network.stop_node(3);network.start_app(3);network.start_engine(3)
        wait_until(lambda:_engine_consensus_ready(network,3,max(network.height(i) for i in (0,1,2))-2),240)
        check('same_store_validator_restart',network.direct_state(3)['checkpoint']['accepted_count']==10)
        witness=network.hold_sources_without_quorum()
        check('four_validator_checkpoint_agreement',all(n.canonical(network.direct_state(i))==n.canonical(witness) for i in range(4)))
        network.start_engine(2);network.start_engine(3);wait_until(lambda:network.height(0)>=witness['height']+1,90)
        signed=rpc(network.http[0],'commit',{'height':str(witness['height']+1)})['signed_header']
        validators=[Validator(hashlib.sha256(bytes.fromhex(v['public_key'])).digest()[:20],bytes.fromhex(v['public_key']),v['power']) for v in vals]
        validators.sort(key=lambda v:(-v.power,v.address));frozen=tuple(validators)
        trust=TrustAnchor(g['chain_id'],frozen,merkle_root([v.encoded() for v in frozen]),n.sha(raw),sum(v.power for v in frozen))
        cert=verify_signed_header(signed,trust,expected_height=witness['height']+1)
        check('signed_next_header',cert['app_hash']==witness['app_hash'])
        report.update(genesis=g,genesis_sha256=n.sha(raw),checkpoint_witness=witness,signed_header=signed,
                      certificate={**cert,'claim':'AS-OF signed compact checkpoint, no client native history replay or freshness'})
        report['worker_audits'].extend({'node':i,'phase':'final',**network.worker_audit(i)} for i in range(4))
        for i in range(4):network.stop_node(i)
        replay_worker=Worker(args.worker,g['worker_sha256'],first);workers.append(replay_worker)
        with Application(network.runtime/'app3/state.sqlite',replay_worker,expected_genesis=raw) as reopened:
            check('stopped_store_separate_native_replay',reopened.checkpoint['accepted_count']==10 and reopened.height>64,
                  {'height':reopened.height,'notes':reopened.checkpoint['notes_count']})
        report['worker_audits'].extend({'node':'host','phase':str(i),**worker.audit()} for i,worker in enumerate(workers))
        report['private_process_audits']=[p.audit() for p in private]
        audits=report['worker_audits']+report['private_process_audits']
        check('native_processes_reaped',all(a['call_count']==a['reaped_count'] and a['timeout_count']==0 for a in audits) and
              all(r['process_reaped'] and not r['timed_out'] for r in report['native_processes']))
    except Exception as e:report['error']={'type':type(e).__name__,'message':str(e)}
    finally:
        if probe:probe.close()
        if network:
            try:network.close();check('workers_stopped',all(type(r.get('exit_code')) is int for r in report['processes']))
            except Exception as e:report['cleanup_error']={'type':type(e).__name__,'message':str(e)}
        report['checks'].append({'id':'source_unchanged','passed':source()==before,'evidence':{}})
        if tuple(c['id'] for c in report['checks'])==CHECKS and all(c['passed'] for c in report['checks']) and not report.get('cleanup_error'):
            report['status']='qualified-one-host-segmented-recipient-ledger'
        output.write_bytes(n.canonical(report)+b'\n')
    return 0 if report['status']=='qualified-one-host-segmented-recipient-ledger' else 1

def main():
    parser=argparse.ArgumentParser(description=__doc__)
    for name in ('engine','worker','helper','fixture','prover','kat','output'):parser.add_argument('--'+name,type=Path,required=True)
    raise SystemExit(run(parser.parse_args()))
if __name__=='__main__':main()
