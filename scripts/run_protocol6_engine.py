#!/usr/bin/env python3
"""Finite source-bound real CometBFT P6 treasury qualification; loopback only."""
from __future__ import annotations
import argparse,base64,concurrent.futures,hashlib,json,os,subprocess,sys,time,urllib.request
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1];sys.path.insert(0,str(ROOT/'src'))
from protocol6_treasury import canonical,genesis_document,digest,txid
from protocol6_certificate import verify_state
from run_protocol5_engine import Protocol5Network,ENGINE_SHA256,_application_ready,_engine_consensus_ready,_stop,_start_ticks
from run_devnet import patch_toml,rpc,wait_until

CHECKS=('source_clean','engine_identity','fresh_genesis_pins','all_four_initialized','conflicts_admit_without_reservation',
        'ordered_proposal_filters_conflict','mixed_proposal_refused','malformed_and_bad_proof_refused','competing_payment_committed',
        'stale_competing_authority_refused','refreshed_payment_committed','accepted_transaction_replay_refused','aggregate_allowance_exact',
        'same_store_restart_converges','four_validator_agreement','signed_next_header_receipt','workers_stopped','source_unchanged')
SOURCE_NAMES=('src/protocol6_treasury.py','src/protocol6_worker.py','src/protocol6_application.py','src/protocol6_abci_server.py','src/protocol6_certificate.py',
              'scripts/protocol6_worker_exec.py','scripts/serve_abci_p6.py','scripts/run_protocol6_engine.py',
              'tools/treasury-consensus-bridge/Cargo.toml','tools/treasury-consensus-bridge/Cargo.lock','tools/treasury-consensus-bridge/src/main.rs','tools/release/check_protocol6.py')
def source():
    def git(*args):return subprocess.check_output(['git','-C',str(ROOT),*args],text=True).strip()
    paths=set(SOURCE_NAMES)
    paths.update(p for p in git('ls-files').splitlines() if p.startswith(('src/','scripts/','tools/private-treasury-payment-lab/','tools/shielded-consensus/halo2/')))
    return {'commit':git('rev-parse','HEAD'),'tree':git('rev-parse','HEAD^{tree}'),'clean':not git('status','--porcelain'),'status_porcelain':git('status','--porcelain'),
            'files':{p:{'bytes':(ROOT/p).stat().st_size,'sha256':digest((ROOT/p).read_bytes())} for p in sorted(paths)}}
class Network(Protocol5Network):
    # Reuse only owned process/RPC mechanics. P5 state, worker and genesis are not used.
    def __init__(self,paths,output,report):
        super().__init__(paths,output,report,include_target=False)
        self.chain_id='one-p6-'+os.urandom(6).hex();self.genesis_path=self.runtime/'protocol6-genesis.json'
    def install_genesis(self,raw):
        g=genesis_document(raw)
        expected={base64.b64decode(r['pub_key']['value'],validate=True).hex():int(r['power']) for r in self.engine_genesis['validators']}
        if g['chain_id']!=self.chain_id or {r['public_key']:r['power'] for r in g['validators']}!=expected:raise ValueError('P6 engine/genesis identities differ')
        self.genesis_path.write_bytes(raw);self.genesis_sha256=digest(raw)
        self.engine_genesis.update(chain_id=self.chain_id,initial_height='1',app_state=g)
        self.engine_genesis['consensus_params']['block'].update(max_bytes='1048576',max_gas='-1')
        for i in range(5):
            home=self.homes/f'node{i}';(home/'config/genesis.json').write_text(json.dumps(self.engine_genesis,sort_keys=True,separators=(',',':'))+'\n')
            app=self.runtime/f'app{i}';app.mkdir(mode=0o700)
            config=home/'config/config.toml';config.write_text(patch_toml(config.read_text(),{
                'proxy_app':f"unix://{app/'a.sock'}",'abci':'socket','rpc.laddr':f'tcp://127.0.0.1:{self.http[i]}','rpc.unsafe':False,'rpc.timeout_broadcast_tx_commit':'50s',
                'p2p.laddr':f'tcp://127.0.0.1:{self.p2p[i]}','p2p.persistent_peers':','.join(f'{self.node_ids[j]}@127.0.0.1:{self.p2p[j]}' for j in range(4) if j!=i),
                'p2p.addr_book_strict':False,'p2p.allow_duplicate_ip':True,'p2p.pex':False,'consensus.timeout_commit':'3s',
                'consensus.create_empty_blocks':False,'consensus.create_empty_blocks_interval':'0s','mempool.max_tx_bytes':4096}))
    def start_app(self,i,*,crash=None):
        if crash is not None:raise ValueError('P6 has no runtime fault endpoint')
        socket=self.runtime/f'app{i}/a.sock'
        if socket.exists():
            if i in self.apps and self.apps[i].poll() is None:raise ValueError('P6 live socket owner')
            socket.unlink()
        log=(self.runtime/f'app{i}.log').open('ab');self.handles.append(log)
        cmd=[sys.executable,'-B',str(ROOT/'scripts/serve_abci_p6.py'),'--genesis',str(self.genesis_path),'--genesis-sha256',self.genesis_sha256,
            '--database',str(self.runtime/f'app{i}/state.sqlite'),'--socket',str(socket),'--worker',str(self.paths['worker']),'--kat',str(self.paths['kat'])]
        p=subprocess.Popen(cmd,stdout=log,stderr=log);self.apps[i]=p
        self._record('application',i,p,digest((ROOT/'scripts/serve_abci_p6.py').read_bytes()))
        wait_until(lambda:_application_ready(self,i,p,socket),90)
    def broadcast(self,index,transaction):
        # A cold frozen verifier exceeds the old shared eight-second RPC budget.
        payload=json.dumps({'jsonrpc':'2.0','id':1,'method':'broadcast_tx_sync','params':{'tx':base64.b64encode(transaction).decode('ascii')}}).encode()
        req=urllib.request.Request(f'http://127.0.0.1:{self.http[index]}',data=payload,headers={'Content-Type':'application/json'})
        with urllib.request.build_opener(urllib.request.ProxyHandler({})).open(req,timeout=60) as response:value=json.load(response)
        if 'error' in value:raise RuntimeError('P6 broadcast RPC refused')
        return value['result']
    def close(self):
        for p in list(self.engines.values())+list(self.apps.values()):self._record_exit(p.pid,_stop(p))
        for f in self.handles:f.close()
        artifacts=self.output.with_name(self.output.name+'.artifacts');artifacts.mkdir(mode=0o700)
        manifest=[]
        for p in sorted(self.runtime.glob('*.log')):
            raw=p.read_bytes()
            if len(raw)>8*1024*1024:raise ValueError('P6 raw log bound exceeded; not silently truncated')
            raw=raw.replace(str(self.runtime).encode(),b'<private-run>');target=artifacts/p.name;target.write_bytes(raw)
            manifest.append({'name':p.name,'bytes':len(raw),'sha256':digest(raw)})
        for name in ('a','b','after_a_b','after_b_a','duplicate_request','genesis'):
            original=self.paths['fixtures']/(name+('.json' if name=='genesis' else '.tx'));raw=original.read_bytes();target=artifacts/('fixture-'+original.name);target.write_bytes(raw)
            manifest.append({'name':target.name,'bytes':len(raw),'sha256':digest(raw)})
        self.report['artifacts']=manifest;self.report['processes']=self.receipts
        # Synthetic private keys and SQLite state are not delivered; public full state is in report.
        self.temp.cleanup()
def run(args):
    output=args.output.absolute()
    if output.exists() or output.with_name(output.name+'.artifacts').exists():raise FileExistsError('fresh P6 report required')
    needed={'engine':args.engine,'worker':args.worker,'treasury_genesis':args.fixtures/'genesis.json'}
    needed.update({name:args.fixtures/(name+'.tx') for name in ('a','b','after_a_b','after_b_a','duplicate_request')})
    missing=[name for name,p in needed.items() if not p.exists() and not p.is_symlink()]
    if os.name!='posix':missing.append('POSIX execution platform')
    if missing:
        output.write_bytes(canonical({'format':'1soft/protocol6-treasury-engine/v1','status':'unassessed','missing_inputs':missing,'checks':[],'processes':[]})+b'\n')
        return 2
    for name,p in needed.items():
        maximum=64*1024*1024 if name in ('engine','worker') else (16384 if name=='treasury_genesis' else 4008)
        if p.is_symlink() or not p.is_file() or p.stat().st_size>maximum:raise ValueError('unsafe or oversized P6 input: '+name)
    before=source();report={'format':'1soft/protocol6-treasury-engine/v1','status':'failed','source':before,'checks':[],
        'claims':{'one_host_four_validators':True,'static_genesis_grants':True,'production_ready':False,'public_network':False,
        'independent_operators':False,'seccomp_worker':False,'wallet_integrated':False,'merchant_redemption':False,'owner_lifecycle':False,
        'real_funds':False,'freshness_established':False,'independent_cryptographic_audit':False},'inputs':{}}
    network=None
    def check(name,passed,evidence=None):
        report['checks'].append({'id':name,'passed':bool(passed),'evidence':evidence or {}})
        print('P6_CHECK '+name+' '+str(bool(passed)),flush=True)
        if not passed:raise AssertionError(name)
    try:
        check('source_clean',before['clean'] or args.candidate,{'candidate':args.candidate})
        for name,p in [('engine',args.engine),('worker',args.worker)]:
            if p.is_symlink() or not p.is_file():raise ValueError('regular pinned executable required')
            report['inputs'][name]={'bytes':p.stat().st_size,'sha256':digest(p.read_bytes())}
        check('engine_identity',report['inputs']['engine']['sha256']==ENGINE_SHA256 and subprocess.check_output([str(args.engine),'version'],text=True).strip()=='0.38.25')
        names=('a','b','after_a_b','after_b_a','duplicate_request')
        txs={n:(args.fixtures/(n+'.tx')).read_bytes() for n in names}
        report['inputs']['fixtures']={n:digest(raw) for n,raw in txs.items()};report['inputs']['treasury_genesis']=digest((args.fixtures/'genesis.json').read_bytes())
        network=Network({'engine':args.engine,'worker':args.worker,'kat':args.fixtures/'a.tx','fixtures':args.fixtures},output,report)
        v=sorted([{'public_key':base64.b64decode(r['pub_key']['value']).hex(),'power':int(r['power'])} for r in network.engine_genesis['validators']],key=lambda r:r['public_key'])
        g={'protocol_version':6,'chain_id':network.chain_id,'profile_sha256':'4e12c9a2eafd2d4f3e82106ba1128e1fc6301b24b871d30714eb0ca3b93115bd',
            'worker_sha256':report['inputs']['worker']['sha256'],'kat_sha256':digest(txs['a']),'validators':v,'treasury':json.loads((args.fixtures/'genesis.json').read_bytes())}
        raw=canonical(g);network.install_genesis(raw);report['genesis']=g;report['genesis_sha256']=digest(raw)
        check('fresh_genesis_pins',genesis_document(raw)==g)
        network.start_sources()
        startup=[json.loads(base64.b64decode(rpc(network.http[i],'abci_query',{'path':'/info','prove':False})['response']['value']))['worker_startup'] for i in range(4)]
        check('all_four_initialized',all(network.direct_state(i)['genesis']==g for i in range(4)),{'worker_startup':startup})
        held=network.hold_sources_without_quorum();vh=bytes.fromhex(network.validators_hash) if hasattr(network,'validators_hash') else bytes.fromhex(__import__('protocol5_encoding').comet_validator_set(v).hash)
        check('conflicts_admit_without_reservation',[network.direct_check(0,txs[n]) for n in ('a','b')]==[0,0])
        check('ordered_proposal_filters_conflict',network.direct_prepare(0,[txs['a'],txs['b']],held['height']+1,8200)==[txs['a']])
        check('mixed_proposal_refused',network.direct_process(0,[txs['a'],txs['b']],held['height']+1,vh)==2)
        bad=bytearray(txs['a']);bad[-1]^=1
        check('malformed_and_bad_proof_refused',network.direct_check(0,txs['a']+b'x')==1 and network.direct_check(0,bytes(bad))==6)
        admissions,_=network.stage_without_quorum([txs['a'],txs['b']])
        def accepted(count):
            states=[network.direct_state(i) for i in range(4)]
            return states if all(len(s['state']['receipts'])==count for s in states) else None
        states=wait_until(lambda:accepted(1),120);first=states[0]['state']['receipts'][0]['txid']
        winner='a' if first==txid(txs['a']) else 'b';loser='b' if winner=='a' else 'a';refresh='after_a_b' if winner=='a' else 'after_b_a'
        check('competing_payment_committed',first==txid(txs[winner]),{'winner':winner,'txid':first})
        network.hold_sources_without_quorum();check('stale_competing_authority_refused',all(network.direct_check(i,txs[loser])==2 for i in range(4)))
        network.stage_without_quorum([txs[refresh]])
        states=wait_until(lambda:accepted(2),120);check('refreshed_payment_committed',all(s['state']['receipts'][1]['txid']==txid(txs[refresh]) for s in states))
        check('accepted_transaction_replay_refused',all(network.direct_check(i,txs[winner])!=0 for i in range(4)))
        check('aggregate_allowance_exact',all(s['state']['treasury']['fees']==4 and len(s['state']['treasury']['notes'])==6 and len(s['state']['treasury']['nullifiers'])==2 and len(s['state']['treasury']['authority_nullifiers'])==4 for s in states))
        network.stop_node(3);network.start_app(3);network.start_engine(3)
        wait_until(lambda:_engine_consensus_ready(network,3,max(network.height(i) for i in (0,1,2))),120)
        check('same_store_restart_converges',len(network.direct_state(3)['state']['receipts'])==2)
        witness=network.hold_sources_without_quorum();allstates=[network.direct_state(i) for i in range(4)]
        check('four_validator_agreement',all(canonical(s)==canonical(witness) for s in allstates))
        network.start_engine(2);network.start_engine(3)
        wait_until(lambda:network.height(0)>=witness['height']+1,90)
        signed=rpc(network.http[0],'commit',{'height':str(witness['height']+1)})['signed_header']
        cert=verify_state(witness,signed,raw);report['state_witness']=witness;report['signed_header']=signed;report['certificate']=cert
        check('signed_next_header_receipt',cert['state_height']==witness['height'] and len(witness['state']['receipts'])==2)
    except Exception as exc:
        report['error']={'type':type(exc).__name__,'message':str(exc)}
    finally:
        if network:
            try:network.close();check('workers_stopped',all('exit_code' in p for p in report['processes']))
            except Exception as exc:report['cleanup_error']={'type':type(exc).__name__,'message':str(exc)}
        unchanged=source()==before
        report['checks'].append({'id':'source_unchanged','passed':unchanged,'evidence':{}})
        if [c['id'] for c in report['checks']]==list(CHECKS) and all(c['passed'] for c in report['checks']) and not report.get('cleanup_error'):
            report['status']='candidate-passed' if args.candidate else 'qualified-one-host-static-treasury-consensus'
        output.write_bytes(canonical(report)+b'\n')
    return 0 if report['status'] in ('candidate-passed','qualified-one-host-static-treasury-consensus') else 1
def main():
    p=argparse.ArgumentParser(description=__doc__)
    for n in ('engine','worker','fixtures','output'):p.add_argument('--'+n,type=Path,required=True)
    p.add_argument('--candidate',action='store_true');raise SystemExit(run(p.parse_args()))
if __name__=='__main__':main()
