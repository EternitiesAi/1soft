#!/usr/bin/env python3
"""Actual local P7 owner/payment callers and exact certificate recovery; no public service."""
from __future__ import annotations
import argparse,base64,copy,json,os,subprocess,sys
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1];sys.path.insert(0,str(ROOT/'src'))
import run_protocol7_engine as engine
from protocol7_treasury import canonical,genesis_document,digest,txid,parse,command,bootstrap_digest,PROFILE_SHA256
from protocol7_worker import Worker
from protocol7_certificate import verify_state
from protocol7_wallet import CertifiedTreasuryJournal
from protocol7_delivery import LoopbackSubmit
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from run_protocol5_engine import _application_ready,_hold_transaction_height
from run_devnet import rpc,wait_until
from protocol5_encoding import comet_validator_set
CHECKS=('source_clean','engine_identity','fresh_network_bound_proofs','external_genesis_pinned','all_four_initialized',
        'local_owner_payment_conflict_refused','future_owner_admission_nonreserving','early_owner_consensus_refused',
        'owner_claim_before_io','owner_lost_return_held','owner_exact_height_committed','owner_signed_exact_execution',
        'owner_reopen_export_no_redelivery','stale_unclaimed_payment_held','stale_first_claim_refused',
        'payment_claim_before_io','payment_lost_return_held','actual_payment_committed','four_validator_agreement',
        'payment_signed_exact_execution','payment_reopen_export_no_redelivery','forged_certificate_preserves_records',
        'same_store_restart_converges','workers_stopped','source_unchanged')
CLAIMS={'protocol7_rules_unchanged':True,'owner_and_payment_callers':True,'independent_bounded_replay':True,
        'exact_certificate_recovery':True,'one_attempt_local_controller':True,'one_host_four_validators':True,
        'synthetic_conflict_fixture':True,'production_ready':False,'public_network':False,'real_funds':False,
        'independent_operators':False,'custody':False,'merchant_redemption':False,'recipient_discovery':False,
        'proving_or_signing_wallet':False,'freshness_established':False,'journal_rollback_protected':False,
        'cross_device_coordination':False,'automatic_retry':False}
SOURCE_NAMES=(*engine.SOURCE_NAMES,'src/protocol7_wallet.py','src/protocol7_delivery.py','src/protocol7_admission.py','src/protocol7_admission_application.py','scripts/run_protocol7_client.py','scripts/serve_abci_p7_admission.py','scripts/owner_treasury_wallet.py','tools/release/check_protocol7_client.py')
SOURCE_PREFIXES=engine.SOURCE_PREFIXES
def source():
    v=engine.source()
    for p in SOURCE_NAMES:
        raw=(ROOT/p).read_bytes();v['files'][p]={'bytes':len(raw),'sha256':digest(raw)}
    return v
class Network(engine.Network):
    def start_app(self,i,*,crash=None):
        if crash is not None:raise ValueError('no runtime fault endpoint')
        socket=self.runtime/f'app{i}/a.sock'
        if socket.exists():
            if i in self.apps and self.apps[i].poll() is None:raise ValueError('live socket owner')
            socket.unlink()
        log=(self.runtime/f'app{i}.log').open('ab');self.handles.append(log)
        cmd=[sys.executable,'-B',str(ROOT/'scripts/serve_abci_p7_admission.py'),'--genesis',str(self.genesis_path),'--genesis-sha256',self.genesis_sha256,
            '--database',str(self.runtime/f'app{i}/state.sqlite'),'--socket',str(socket),'--worker',str(self.paths['worker']),'--kat',str(self.paths['kat'])]
        p=subprocess.Popen(cmd,stdout=log,stderr=log);self.apps[i]=p
        self._record('application',i,p,digest((ROOT/'scripts/serve_abci_p7_admission.py').read_bytes()))
        wait_until(lambda:_application_ready(self,i,p,socket),90)
def run(args):
    output=args.output.absolute()
    if output.exists() or output.with_name(output.name+'.artifacts').exists():raise FileExistsError('fresh client report required')
    before=source();report={'format':'1soft/protocol7-client-engine/v1','status':'failed','source':before,'checks':[],
        'claims':CLAIMS.copy(),'inputs':{},'commands':[]};network=None;primary=None;losing=None
    def check(name,passed,evidence=None):
        report['checks'].append({'id':name,'passed':bool(passed),'evidence':evidence or {}});print('P7_CLIENT_CHECK '+name+' '+str(bool(passed)),flush=True)
        if not passed:raise AssertionError(name)
    def refused(fn):
        try:fn()
        except ValueError:return True
        return False
    try:
        if os.name!='posix':raise RuntimeError('P7 client requires POSIX')
        check('source_clean',before['clean'] or args.candidate,{'candidate':args.candidate})
        for name,p in [('engine',args.engine),('worker',args.worker),('prover',args.prover)]:
            if p.is_symlink() or not p.is_file() or p.stat().st_size>64*1024*1024:raise ValueError('regular bounded executable required')
            report['inputs'][name]={'bytes':p.stat().st_size,'sha256':digest(p.read_bytes())}
        check('engine_identity',report['inputs']['engine']['sha256']==engine.ENGINE_SHA256 and subprocess.check_output([str(args.engine),'version'],text=True).strip()=='0.38.25')
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
        g['treasury']=json.loads((fixtures/'genesis.json').read_bytes());g['kat_sha256']=digest(txs['a'])
        network.paths['kat']=fixtures/'a.tx';w=Worker(args.worker,g['worker_sha256'],network.paths['kat'].read_bytes())
        raw=canonical(g);report['genesis']=g;report['genesis_sha256']=digest(raw);report['bootstrap_sha256']=bootstrap_digest(g)
        check('fresh_network_bound_proofs',genesis_document(raw,w)==g and len(txs)==12 and all(parse(r)[1]==domain and w.verify(r) for r in txs.values()),{'domain':domain,'actual_proofs':12})
        report['wallet_startup']=w.startup
        external=network.runtime/'trusted-client-genesis.json';external.write_bytes(raw)
        check('external_genesis_pinned',external.read_bytes()==raw and digest(external.read_bytes())==report['genesis_sha256'] and genesis_document(external.read_bytes(),w)==g)
        network.install_genesis(raw,w);network.start_sources()
        startup=[json.loads(base64.b64decode(rpc(network.http[i],'abci_query',{'path':'/info','prove':False})['response']['value']))['worker_startup'] for i in range(4)]
        check('all_four_initialized',all(network.direct_state(i)['genesis']==g for i in range(4)),{'worker_startup':startup})
        held=_hold_transaction_height(network);key=Ed25519PrivateKey.from_private_bytes(bytes([7])*32)
        policy=held['state']['treasury']['grants'][0];p=parse(txs['rotated_a']);declared=held['height']+2
        owner=command(g,held['state'],kind='rotate',grant_id=policy['id'],height=declared,new_commitment=p[8],new_agent_key=p[29],key=key,worker=w)
        report['commands']=[owner.hex()];report['prepared_at_height']=held['height'];report['declared_owner_height']=declared
        for name in ('primary','stale'):(network.runtime/('client-'+name)).mkdir(mode=0o700)
        primary_path=network.runtime/'client-primary/journal.sqlite'
        primary=CertifiedTreasuryJournal(primary_path,expected_genesis=raw,worker=w)
        losing=CertifiedTreasuryJournal(network.runtime/'client-stale/journal.sqlite',expected_genesis=raw,worker=w)
        oid=primary.retain(owner);staleid=losing.retain(txs['a'])
        check('local_owner_payment_conflict_refused',refused(lambda:primary.retain(txs['a'])))
        snap=network.direct_state(0);vh=bytes.fromhex(comet_validator_set(v).hash)
        check('future_owner_admission_nonreserving',network.direct_check(0,owner)==0 and network.direct_state(0)==snap and declared==snap['height']+2,{'state_height':snap['height'],'declared_height':declared,'raw_sha256':digest(owner),'check_code':0})
        check('early_owner_consensus_refused',network.direct_prepare(0,[owner],declared-1,8192)==[] and network.direct_process(0,[owner],declared-1,vh)==2,{'height':declared-1,'prepared':[],'process_status':2})
        submit=LoopbackSubmit('http://127.0.0.1:'+str(network.http[0]));transports={}
        def delivery(ident,wire,kind):
            calls=[];returned={'rpc_returned':False,'response_accepted':False,'response_discarded':False}
            def discard(sent):
                check(kind+'_claim_before_io',primary.status(ident)['attempts']==1 and sent==wire and not calls)
                calls.append(digest(sent));reply=submit(sent);returned.update(rpc_returned=True,response_accepted=reply.get('code')==0,response_discarded=True)
                raise TimeoutError('intentional acknowledgement discard after actual RPC return')
            result=primary.deliver_once(ident,discard)
            transports[kind]={**returned,'calls':calls,'delivery':result,'test_injection':'intentional response discard; actual validator submission'}
            check(kind+'_lost_return_held',result['outcome']=='unknown' and returned['response_accepted'] and primary.status(ident)['status'] in ('attempted-held','observed-held') and len(calls)==1)
            wait_until(lambda:all(wire in network.mempool_transactions(i) for i in (0,1)),30)
            network.start_engine(2);network.start_engine(3)
        def accepted(n):
            rows=[network.direct_state(i) for i in range(4)]
            return rows if all(len(s['state']['receipts'])==n for s in rows) else None
        def certify():
            witness=network.hold_sources_without_quorum()
            network.start_engine(2);network.start_engine(3)
            wait_until(lambda:network.height(0)>=witness['height']+1,150)
            signed=rpc(network.http[0],'commit',{'height':str(witness['height']+1)})['signed_header']
            verify_state(witness,signed,raw,w)
            # Capture a real H+1 commit and then hold current engines; never invent its state.
            live=network.hold_sources_without_quorum()
            return witness,signed,live
        delivery(oid,owner,'owner');rows=wait_until(lambda:accepted(1),240)
        check('owner_exact_height_committed',all(s['state']['receipts'][0]['raw']==owner.hex() and s['state']['receipts'][0]['height']==declared for s in rows))
        witness,signed,live=certify();primary.observe(witness,signed);owner_record=primary.recorded_receipt(oid)
        report['owner_record']=owner_record
        check('owner_signed_exact_execution',owner_record['receipt']['kind']=='owner' and owner_record['raw']==owner.hex())
        primary.close();primary=CertifiedTreasuryJournal(primary_path,expected_genesis=raw,worker=w)
        check('owner_reopen_export_no_redelivery',primary.recorded_receipt(oid)==owner_record and primary.export(oid)==owner and refused(lambda:primary.deliver_once(oid,submit)))
        losing.observe(witness,signed);held_status=losing.status(staleid)
        report['held_obligation']={'txid':staleid,'raw':txs['a'].hex(),'status':held_status,'witness':witness,'signed_header':signed}
        check('stale_unclaimed_payment_held',held_status['hold_reason']=='rotated-grant' and held_status['attempts']==0 and refused(lambda:losing.recorded_receipt(staleid)))
        check('stale_first_claim_refused',refused(lambda:losing.claim(staleid)) and losing.status(staleid)['attempts']==0)
        payment=txs['rotated_a'];pid=primary.retain(payment);delivery(pid,payment,'payment');rows=wait_until(lambda:accepted(2),180)
        check('actual_payment_committed',all(s['state']['receipts'][1]['raw']==payment.hex() and s['state']['receipts'][1]['kind']=='payment' for s in rows))
        witness,signed,live=certify()
        check('four_validator_agreement',all(canonical(network.direct_state(i))==canonical(live) for i in range(4)))
        primary.observe(witness,signed);payment_record=primary.recorded_receipt(pid);report['payment_record']=payment_record
        check('payment_signed_exact_execution',payment_record['receipt']['kind']=='payment' and payment_record['raw']==payment.hex())
        primary.close();primary=CertifiedTreasuryJournal(primary_path,expected_genesis=raw,worker=w)
        check('payment_reopen_export_no_redelivery',primary.recorded_receipt(pid)==payment_record and primary.export(pid)==payment and refused(lambda:primary.deliver_once(pid,submit)))
        forged=copy.deepcopy(signed);forged['header']['app_hash']='ab'*32
        check('forged_certificate_preserves_records',refused(lambda:primary.observe(witness,forged)) and primary.recorded_receipt(oid)==owner_record and primary.recorded_receipt(pid)==payment_record)
        network.start_engine(2);network.start_engine(3);network.stop_node(3);network.start_app(3);network.start_engine(3)
        wait_until(lambda:len(network.direct_state(3)['state']['receipts'])==2,150)
        check('same_store_restart_converges',network.direct_state(3)['state']['receipts']==witness['state']['receipts'])
        report['transport']=transports;report['wallet_status']={'owner':primary.status(oid),'payment':primary.status(pid)}
    except Exception as exc:report['error']={'type':type(exc).__name__,'message':str(exc)}
    finally:
        if primary:primary.close()
        if losing:losing.close()
        if network:
            try:
                network.close();directory=output.with_name(output.name+'.artifacts')
                for name,value in [('bootstrap-genesis.json',report.get('genesis',{})),('owner-record.json',report.get('owner_record',{})),('payment-record.json',report.get('payment_record',{})),('held-obligation.json',report.get('held_obligation',{}))]:
                    raw=canonical(value);(directory/name).write_bytes(raw);report['artifacts'].append({'name':name,'bytes':len(raw),'sha256':digest(raw)})
                check('workers_stopped',all(type(p.get('exit_code')) is int for p in report['processes']))
            except Exception as exc:report['cleanup_error']={'type':type(exc).__name__,'message':str(exc)}
        report['checks'].append({'id':'source_unchanged','passed':source()==before,'evidence':{}})
        if [c['id'] for c in report['checks']]==list(CHECKS) and all(c['passed'] for c in report['checks']) and not report.get('cleanup_error'):
            report['status']='candidate-passed' if args.candidate else 'qualified-one-host-certified-owner-payment-client'
        output.write_bytes(canonical(report)+b'\n')
    return 0 if report['status'] in ('candidate-passed','qualified-one-host-certified-owner-payment-client') else 1
def main():
    p=argparse.ArgumentParser(description=__doc__)
    for name in ('engine','worker','prover','template','output'):p.add_argument('--'+name,type=Path,required=True)
    p.add_argument('--candidate',action='store_true');a=p.parse_args();raise SystemExit(run(a))
if __name__=='__main__':main()
