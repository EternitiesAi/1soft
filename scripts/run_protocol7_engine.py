#!/usr/bin/env python3
"""Fresh network-bound P7 owner lifecycle qualification on four actual local validators."""
from __future__ import annotations
import argparse,base64,hashlib,json,os,subprocess,sys,urllib.request
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1];sys.path.insert(0,str(ROOT/'src'))
from protocol7_treasury import canonical,genesis_document,digest,txid,parse,command,bootstrap_digest,PROFILE_SHA256,ZERO,field
from protocol7_certificate import verify_state
from protocol7_worker import Worker
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from run_protocol5_engine import Protocol5Network,ENGINE_SHA256,_application_ready,_engine_consensus_ready,_stop,_hold_transaction_height
from run_devnet import patch_toml,rpc,wait_until
from protocol5_encoding import comet_validator_set
CHECKS=('source_clean','engine_identity','fresh_network_bound_proofs','all_four_initialized','malformed_wrong_network_badproof_refused',
    'nonreserving_owner_payment_admission','both_ordered_races','competing_owner_successor','owner_only_mutation',
    'lifecycle_receipts_exact','old_context_or_generation_quarantined','fresh_domain_payment_committed',
    'same_store_restart_converges','four_validator_agreement','signed_next_header_replayed','workers_stopped','source_unchanged')
CLAIMS={'one_host_four_validators':True,'owner_lifecycle':True,'network_bound_proofs':True,'production_ready':False,'public_network':False,
    'independent_operators':False,'seccomp_worker':False,'wallet_integrated':False,'merchant_redemption':False,'real_funds':False,
    'freshness_established':False,'independent_cryptographic_audit':False,'old_note_migration':False,'owner_key_recovery':False}
SOURCE_NAMES=('src/protocol7_treasury.py','src/protocol7_worker.py','src/protocol7_application.py','src/protocol7_abci_server.py','src/protocol7_certificate.py',
    'scripts/protocol7_worker_exec.py','scripts/serve_abci_p7.py','scripts/run_protocol7_engine.py','tools/release/check_protocol7.py')
SOURCE_PREFIXES=('src/','scripts/','tools/owner-treasury-lab/','tools/owner-consensus-bridge/','tools/shielded-consensus/halo2/')
def source():
    def git(*a):return subprocess.check_output(['git','-C',str(ROOT),*a],text=True).strip()
    paths=set(SOURCE_NAMES)|{p for p in git('ls-files').splitlines() if p.startswith(SOURCE_PREFIXES)}
    return {'commit':git('rev-parse','HEAD'),'tree':git('rev-parse','HEAD^{tree}'),'clean':not git('status','--porcelain'),'status_porcelain':git('status','--porcelain'),
        'files':{p:{'bytes':(ROOT/p).stat().st_size,'sha256':digest((ROOT/p).read_bytes())} for p in sorted(paths)}}
class Network(Protocol5Network):
    # Reuse only owned process/RPC mechanics. P5 state, worker and genesis are not used.
    def __init__(self,paths,output,report):
        super().__init__(paths,output,report,include_target=False)
        self.chain_id='one-p7-'+os.urandom(6).hex();self.genesis_path=self.runtime/'protocol7-genesis.json'
    def install_genesis(self,raw,worker):
        g=genesis_document(raw,worker)
        expected={base64.b64decode(r['pub_key']['value'],validate=True).hex():int(r['power']) for r in self.engine_genesis['validators']}
        if g['chain_id']!=self.chain_id or {r['public_key']:r['power'] for r in g['validators']}!=expected:raise ValueError('P7 engine/genesis identities differ')
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
                'consensus.create_empty_blocks':False,'consensus.create_empty_blocks_interval':'0s','mempool.max_tx_bytes':8192}))
    def start_app(self,i,*,crash=None):
        if crash is not None:raise ValueError('P7 has no runtime fault endpoint')
        socket=self.runtime/f'app{i}/a.sock'
        if socket.exists():
            if i in self.apps and self.apps[i].poll() is None:raise ValueError('P7 live socket owner')
            socket.unlink()
        log=(self.runtime/f'app{i}.log').open('ab');self.handles.append(log)
        cmd=[sys.executable,'-B',str(ROOT/'scripts/serve_abci_p7.py'),'--genesis',str(self.genesis_path),'--genesis-sha256',self.genesis_sha256,
            '--database',str(self.runtime/f'app{i}/state.sqlite'),'--socket',str(socket),'--worker',str(self.paths['worker']),'--kat',str(self.paths['kat'])]
        p=subprocess.Popen(cmd,stdout=log,stderr=log);self.apps[i]=p
        self._record('application',i,p,digest((ROOT/'scripts/serve_abci_p7.py').read_bytes()))
        wait_until(lambda:_application_ready(self,i,p,socket),90)
    def broadcast(self,index,transaction):
        # A cold frozen verifier exceeds the old shared eight-second RPC budget.
        payload=json.dumps({'jsonrpc':'2.0','id':1,'method':'broadcast_tx_sync','params':{'tx':base64.b64encode(transaction).decode('ascii')}}).encode()
        req=urllib.request.Request(f'http://127.0.0.1:{self.http[index]}',data=payload,headers={'Content-Type':'application/json'})
        with urllib.request.build_opener(urllib.request.ProxyHandler({})).open(req,timeout=60) as response:value=json.load(response)
        if 'error' in value:raise RuntimeError('P7 broadcast RPC refused')
        return value['result']
    def close(self):
        for p in list(self.engines.values())+list(self.apps.values()):self._record_exit(p.pid,_stop(p))
        for f in self.handles:f.close()
        artifacts=self.output.with_name(self.output.name+'.artifacts');artifacts.mkdir(mode=0o700)
        manifest=[]
        for p in sorted(self.runtime.glob('*.log')):
            raw=p.read_bytes()
            if len(raw)>8*1024*1024:raise ValueError('P7 raw log bound exceeded; not silently truncated')
            raw=raw.replace(str(self.runtime).encode(),b'<private-run>');target=artifacts/p.name;target.write_bytes(raw)
            manifest.append({'name':p.name,'bytes':len(raw),'sha256':digest(raw)})
        for original in sorted(self.paths['fixtures'].iterdir()):
            if original.suffix not in ('.tx','.json') or not original.is_file() or original.is_symlink():raise ValueError('P7 fixture roster differs')
            raw=original.read_bytes();target=artifacts/('fixture-'+original.name);target.write_bytes(raw)
            manifest.append({'name':target.name,'bytes':len(raw),'sha256':digest(raw)})
        target=artifacts/'commands.json';raw=canonical(self.report['commands']);target.write_bytes(raw)
        manifest.append({'name':target.name,'bytes':len(raw),'sha256':digest(raw)})
        self.report['artifacts']=manifest;self.report['processes']=self.receipts
        # Synthetic private keys and SQLite state are not delivered; public full state is in report.
        self.temp.cleanup()
def run(args):
    output=args.output.absolute()
    if output.exists() or output.with_name(output.name+'.artifacts').exists():raise FileExistsError('fresh P7 report required')
    before=source();report={'format':'1soft/protocol7-owner-engine/v1','status':'failed','source':before,'scenario':args.scenario,'checks':[],
        'claims':CLAIMS.copy(),'inputs':{},'commands':[]};network=None
    def check(name,passed,evidence=None):
        report['checks'].append({'id':name,'passed':bool(passed),'evidence':evidence or {}});print('P7_CHECK '+name+' '+str(bool(passed)),flush=True)
        if not passed:raise AssertionError(name)
    try:
        if os.name!='posix':raise RuntimeError('P7 requires POSIX')
        check('source_clean',before['clean'] or args.candidate,{'candidate':args.candidate})
        for name,p in [('engine',args.engine),('worker',args.worker),('prover',args.prover)]:
            if p.is_symlink() or not p.is_file() or p.stat().st_size>64*1024*1024:raise ValueError('P7 regular bounded executable required')
            report['inputs'][name]={'bytes':p.stat().st_size,'sha256':digest(p.read_bytes())}
        check('engine_identity',report['inputs']['engine']['sha256']==ENGINE_SHA256 and subprocess.check_output([str(args.engine),'version'],text=True).strip()=='0.38.25')
        # The template is synthetic metadata/KAT only. Fresh domain commitments,
        # proofs and KAT are generated for this exact new roster before any node.
        for name,bound in [('genesis.json',16384),('a.tx',4168)]:
            p=args.template/name
            if p.is_symlink() or not p.is_file() or p.stat().st_size>bound:raise ValueError('P7 bounded regular template required')
        template=json.loads((args.template/'genesis.json').read_bytes());oldkat=(args.template/'a.tx').read_bytes()
        preliminary=Worker(args.worker,report['inputs']['worker']['sha256'],oldkat)
        network=Network({'engine':args.engine,'worker':args.worker},output,report)
        v=sorted([{'public_key':base64.b64decode(r['pub_key']['value']).hex(),'power':int(r['power'])} for r in network.engine_genesis['validators']],key=lambda r:r['public_key'])
        g={'protocol_version':7,'chain_id':network.chain_id,'profile_sha256':PROFILE_SHA256,'worker_sha256':report['inputs']['worker']['sha256'],
            'kat_sha256':digest(oldkat),'validators':v,'treasury':template}
        domain=preliminary.network_domain(bytes.fromhex(bootstrap_digest(g)));fixtures=network.runtime/'proof-fixtures';network.paths['fixtures']=fixtures
        with (network.runtime/'fixture.log').open('wb') as log:
            prover=subprocess.Popen([str(args.prover),'fixtures-domain',str(fixtures),domain],stdin=subprocess.DEVNULL,stdout=log,stderr=log,start_new_session=True,env={'RAYON_NUM_THREADS':'2'})
            network._record('fixture-prover',0,prover,report['inputs']['prover']['sha256'])
            try:code=prover.wait(timeout=300)
            except subprocess.TimeoutExpired:network._record_exit(prover.pid,_stop(prover));raise
            network._record_exit(prover.pid,code)
            if code:raise RuntimeError('P7 actual fixture prover failed')
        txs={p.stem:p.read_bytes() for p in fixtures.glob('*.tx')};report['inputs']['fixtures']={n:digest(r) for n,r in txs.items()}
        initial='enroll-genesis.json' if args.scenario=='enroll' else 'genesis.json';g['treasury']=json.loads((fixtures/initial).read_bytes());g['kat_sha256']=digest(txs['pre_enroll_a'] if args.scenario=='enroll' else txs['a'])
        network.paths['kat']=fixtures/('pre_enroll_a.tx' if args.scenario=='enroll' else 'a.tx');w=Worker(args.worker,g['worker_sha256'],network.paths['kat'].read_bytes())
        raw=canonical(g);report['genesis']=g;report['genesis_sha256']=digest(raw);report['bootstrap_sha256']=bootstrap_digest(g)
        check('fresh_network_bound_proofs',genesis_document(raw,w)==g and len(txs)==12 and all(parse(r)[1]==domain and w.verify(r) for r in txs.values()),{'domain':domain,'actual_proofs':12})
        network.install_genesis(raw,w);network.start_sources()
        startup=[network.direct_state(i)['genesis'] for i in range(4)]
        startup_info=[json.loads(base64.b64decode(rpc(network.http[i],'abci_query',{'path':'/info','prove':False})['response']['value']))['worker_startup'] for i in range(4)]
        check('all_four_initialized',all(s==g for s in startup),{'worker_startup':startup_info})
        held=_hold_transaction_height(network);vh=bytes.fromhex(comet_validator_set(v).hash);key=Ed25519PrivateKey.from_private_bytes(bytes([7])*32)
        def owner(kind,state,slot=0):
            old=state['state']['treasury']['grants'][slot]
            if kind=='revoke':commit,newkey=ZERO,old['agent_key']
            else:
                p=parse(txs['b'] if kind=='enroll' else txs['rotated_a']);commit,newkey=p[8],p[29]
            r=command(g,state['state'],kind=kind,grant_id=old['id'],height=state['height']+1,new_commitment=commit,new_agent_key=newkey,key=key,worker=w)
            report['commands'].append(r.hex());return r
        oldpayment=txs['pre_enroll_a'] if args.scenario=='enroll' else txs['a'];bad=bytearray(oldpayment);bad[-1]^=1
        check('malformed_wrong_network_badproof_refused',network.direct_check(0,oldpayment+b'x')==1 and network.direct_check(0,bytes(bad))==6 and network.direct_check(0,oldkat)==2)
        kind='enroll' if args.scenario=='enroll' else ('rotate' if args.scenario=='rotate' else 'revoke');slot=1 if kind=='enroll' else 0
        first=owner(kind,held,slot);state_before=network.direct_state(0)
        check('nonreserving_owner_payment_admission',network.direct_check(0,first)==0 and network.direct_check(0,oldpayment)==0 and network.direct_state(0)==state_before)
        probes=[]
        for order in ([first,oldpayment],[oldpayment,first]):
            prepared=network.direct_prepare(0,order,held['height']+1,16400);status=network.direct_process(0,order,held['height']+1,vh)
            probes.append({'first_sha256':digest(order[0]),'prepared':[digest(r) for r in prepared],'process_status':status})
        check('both_ordered_races',all(p['prepared']==[p['first_sha256']] and p['process_status']==2 for p in probes),{'probes':probes})
        alternative=first if args.scenario=='enroll' else owner('revoke' if kind=='rotate' else 'rotate',held)
        check('competing_owner_successor',network.direct_prepare(0,[first,alternative],held['height']+1,16400)==[first] and network.direct_process(0,[first,alternative],held['height']+1,vh)==2)
        def accepted(count):
            rows=[network.direct_state(i) for i in range(4)]
            return rows if all(len(r['state']['receipts'])==count for r in rows) else None
        network.stage_without_quorum([first]);rows=wait_until(lambda:accepted(1),150);t=rows[0]['state']['treasury'];before_t=held['state']['treasury']
        check('owner_only_mutation',all(t[k]==before_t[k] for k in ('parent','notes','fees','nullifiers','authority_nullifiers')) and t['owner_sequence']==1)
        expected=[txid(first)];held=network.hold_sources_without_quorum()
        if args.scenario=='reactivate':
            follow=owner('rotate',held);network.stage_without_quorum([follow]);rows=wait_until(lambda:accepted(2),150);expected.append(txid(follow));held=network.hold_sources_without_quorum();payment=txs['reactivated_a']
        else:payment=txs['after_enroll_b'] if args.scenario=='enroll' else txs['rotated_a']
        network.stage_without_quorum([payment]);rows=wait_until(lambda:accepted(len(expected)+1),150);expected.append(txid(payment));held=network.hold_sources_without_quorum()
        if args.scenario=='rotate':
            follow=owner('revoke',held);network.stage_without_quorum([follow]);rows=wait_until(lambda:accepted(3),150);expected.append(txid(follow));held=network.hold_sources_without_quorum()
            survivor=txs['after_rotated_a_revoke_b'];network.stage_without_quorum([survivor]);rows=wait_until(lambda:accepted(4),150);expected.append(txid(survivor));held=network.hold_sources_without_quorum()
        check('lifecycle_receipts_exact',all([r['txid'] for r in s['state']['receipts']]==expected for s in rows),{'txids':expected})
        check('old_context_or_generation_quarantined',all(network.direct_check(i,oldpayment)==2 and network.direct_check(i,txs['b'])==2 for i in range(4)))
        payments=[r for r in held['state']['receipts'] if r['kind']=='payment'];t=held['state']['treasury']
        check('fresh_domain_payment_committed',len(payments)==(2 if args.scenario=='rotate' else 1) and t['fees']==2*len(payments) and len(t['notes'])==3+2*len(payments)
            and all(r['statement'][1]==domain for r in payments),{'payments':len(payments),'fees':t['fees']})
        # Ordinary same-store restart preserves WAL/signing state; do not reset.
        for i in (2,3):network.start_engine(i)
        network.stop_node(3);network.start_app(3);network.start_engine(3)
        wait_until(lambda:_engine_consensus_ready(network,3,max(network.height(i) for i in (0,1,2))),150)
        check('same_store_restart_converges',[r['txid'] for r in network.direct_state(3)['state']['receipts']]==expected)
        witness=network.hold_sources_without_quorum();allstates=[network.direct_state(i) for i in range(4)]
        check('four_validator_agreement',all(canonical(s)==canonical(witness) for s in allstates))
        network.start_engine(2);network.start_engine(3);wait_until(lambda:network.height(0)>=witness['height']+1,150)
        signed=rpc(network.http[0],'commit',{'height':str(witness['height']+1)})['signed_header'];cert=verify_state(witness,signed,raw,w)
        report['state_witness']=witness;report['signed_header']=signed;report['certificate']=cert
        check('signed_next_header_replayed',cert['state_height']==witness['height'] and [r['txid'] for r in witness['state']['receipts']]==expected)
    except Exception as exc:report['error']={'type':type(exc).__name__,'message':str(exc)}
    finally:
        if network:
            try:network.close();check('workers_stopped',all(type(p.get('exit_code')) is int for p in report['processes']))
            except Exception as exc:report['cleanup_error']={'type':type(exc).__name__,'message':str(exc)}
        report['checks'].append({'id':'source_unchanged','passed':source()==before,'evidence':{}})
        if [c['id'] for c in report['checks']]==list(CHECKS) and all(c['passed'] for c in report['checks']) and not report.get('cleanup_error'):
            report['status']='candidate-passed' if args.candidate else 'qualified-one-host-owner-treasury-consensus'
        output.write_bytes(canonical(report)+b'\n')
    return 0 if report['status'] in ('candidate-passed','qualified-one-host-owner-treasury-consensus') else 1
def main():
    p=argparse.ArgumentParser(description=__doc__)
    for name in ('engine','worker','prover','template','output'):p.add_argument('--'+name,type=Path,required=True)
    p.add_argument('--scenario',choices=('rotate','reactivate','enroll'),required=True);p.add_argument('--candidate',action='store_true')
    raise SystemExit(run(p.parse_args()))
if __name__=='__main__':main()
