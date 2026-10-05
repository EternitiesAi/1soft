#!/usr/bin/env python3
"""Bounded arbitrary developer proving -> retained payment -> actual local quorum recovery."""
import argparse, base64, copy, json, os, subprocess, sys
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1];sys.path.insert(0,str(ROOT/'src'))
import run_protocol7_engine as engine
from run_protocol7_client import Network
from run_protocol5_engine import _hold_transaction_height, _stop
from run_devnet import rpc, wait_until
from protocol7_treasury import canonical, digest, bootstrap_digest, PROFILE_SHA256, genesis_document, parse
from protocol7_worker import Worker
from protocol7_prover import Prover
from protocol7_wallet import CertifiedTreasuryJournal
from protocol7_delivery import LoopbackSubmit
from protocol7_certificate import verify_state

CHECKS=('source_clean','engine_identity','fresh_network_bound_genesis','all_four_initialized',
        'arbitrary_prepare_and_retention','held_resources_refused_before_proving',
        'durable_claim_before_io','lost_return_preserves_obligation','actual_arbitrary_payment_committed',
        'four_validator_agreement','signed_exact_execution','reopen_exact_wire_no_redelivery',
        'forged_certificate_preserves_record','same_store_restart_converges','workers_stopped','source_unchanged')
CLAIMS={'bounded_arbitrary_development_proving':True,'journal_atomic_prepare_and_recovery':True,
        'one_host_four_validators':True,'synthetic_openings':True,'production_ready':False,
        'encrypted_custody':False,'recipient_discovery':False,'freshness_established':False,
        'cross_device_coordination':False,'automatic_retry':False,'real_funds':False,'public_network':False}
SOURCE_NAMES=(*engine.SOURCE_NAMES,'tools/release/check_protocol7_prover.py',
              'tests/test_protocol7_prover.py','tests/test_protocol7_prover_report.py')
def source():
    v=engine.source()
    for name in SOURCE_NAMES:
        raw=(ROOT/name).read_bytes();v['files'][name]={'bytes':len(raw),'sha256':digest(raw)}
    return v

def run(args):
    output=args.output.absolute()
    if output.exists() or output.with_name(output.name+'.artifacts').exists():
        raise FileExistsError('fresh prover report required')
    before=source()
    report={'format':'1soft/protocol7-prepared-prover-engine/v1','status':'failed','source':before,
            'checks':[],'claims':CLAIMS.copy(),'inputs':{},'commands':[]}
    network=wallet=None
    def check(name,passed,evidence=None):
        report['checks'].append({'id':name,'passed':bool(passed),'evidence':evidence or {}})
        print('P7_PROVER_CHECK '+name+' '+str(bool(passed)),flush=True)
        if not passed:raise AssertionError(name)
    def refused(fn):
        try:fn()
        except (ValueError,RuntimeError):return True
        return False
    try:
        check('source_clean',before['clean'] or args.candidate,{'candidate':args.candidate})
        for name in ('engine','worker','fixture_prover','prover','request_fixture'):
            p=getattr(args,name)
            if p.is_symlink() or not p.is_file() or not 0<p.stat().st_size<=64*1024*1024:
                raise ValueError('bounded regular binary required')
            report['inputs'][name]={'bytes':p.stat().st_size,'sha256':digest(p.read_bytes())}
        check('engine_identity',report['inputs']['engine']['sha256']==engine.ENGINE_SHA256
              and subprocess.check_output([str(args.engine),'version'],text=True).strip()=='0.38.25')
        template=json.loads((args.template/'genesis.json').read_bytes())
        kat=(args.template/'a.tx').read_bytes()
        preliminary=Worker(args.worker,report['inputs']['worker']['sha256'],kat)
        network=Network({'engine':args.engine,'worker':args.worker},output,report)
        roster=sorted([{'public_key':base64.b64decode(r['pub_key']['value']).hex(),'power':int(r['power'])}
                       for r in network.engine_genesis['validators']],key=lambda r:r['public_key'])
        g={'protocol_version':7,'chain_id':network.chain_id,'profile_sha256':PROFILE_SHA256,
           'worker_sha256':report['inputs']['worker']['sha256'],'kat_sha256':digest(kat),
           'validators':roster,'treasury':template}
        domain=preliminary.network_domain(bytes.fromhex(bootstrap_digest(g)))
        fixtures=network.runtime/'proof-fixtures';network.paths['fixtures']=fixtures
        with (network.runtime/'fixture.log').open('wb') as log:
            child=subprocess.Popen([str(args.fixture_prover),'fixtures-domain',str(fixtures),domain],
                  stdin=subprocess.DEVNULL,stdout=log,stderr=log,start_new_session=True,env={'RAYON_NUM_THREADS':'2'})
            network._record('fixture-prover',0,child,report['inputs']['fixture_prover']['sha256'])
            try:code=child.wait(timeout=300)
            except subprocess.TimeoutExpired:
                network._record_exit(child.pid,_stop(child));raise
            network._record_exit(child.pid,code)
            if code:raise RuntimeError('fixture preparation failed')
        txs={p.stem:p.read_bytes() for p in fixtures.glob('*.tx')}
        g['treasury']=json.loads((fixtures/'genesis.json').read_bytes());g['kat_sha256']=digest(txs['a'])
        network.paths['kat']=fixtures/'a.tx';worker=Worker(args.worker,g['worker_sha256'],txs['a'])
        rawg=canonical(g)
        report.update(genesis=g,genesis_sha256=digest(rawg),bootstrap_sha256=bootstrap_digest(g))
        check('fresh_network_bound_genesis',len(txs)==12 and genesis_document(rawg,worker)==g
              and g['treasury']['genesis']==domain)
        network.install_genesis(rawg,worker);network.start_sources()
        check('all_four_initialized',all(network.direct_state(i)['genesis']==g for i in range(4)))
        held=_hold_transaction_height(network)
        # Explicit synthetic generator only. Request/private openings are never written to artifacts.
        request=subprocess.check_output([str(args.request_fixture)],input=bytes.fromhex(bootstrap_digest(g)),timeout=30)
        if len(request)!=2088:raise ValueError('synthetic request length differs')
        public=[request[136+i*32:136+(i+1)*32].hex() for i in range(30)]
        witness=[request[1096+i*32:1096+(i+1)*32].hex() for i in range(31)]
        directory=network.runtime/'client';directory.mkdir(mode=0o700)
        wallet=CertifiedTreasuryJournal(directory/'journal.sqlite',expected_genesis=rawg,worker=worker)
        prover=Prover(args.prover,report['inputs']['prover']['sha256'],expected_genesis=rawg,worker=worker)
        ident=wallet.prepare(prover,public,witness);wire=wallet.export(ident)
        report.update(prepared_public=public,prepared_wire=wire.hex(),prepared_txid=ident)
        report['prover_run']=prover.last_run
        report['request_binding']=prover.request_binding
        network.receipts.append({'role':'arbitrary-prover','node':0,
             'pid':prover.last_run['pid'],'start_ticks':prover.last_run['start_ticks'],
             'executable_sha256':prover.last_run['binary_sha256'],'exit_code':prover.last_run['exit_code']})
        check('arbitrary_prepare_and_retention',parse(wire)==public and worker.verify(wire)
              and all(public!=parse(v) for v in txs.values()) and wallet.status(ident)['attempts']==0)
        calls=[]
        old=prover.produce
        def forbidden(*_):calls.append('unexpected');raise AssertionError('duplicate must refuse before proving')
        prover.produce=forbidden
        try:check('held_resources_refused_before_proving',
                  refused(lambda:wallet.prepare(prover,public,witness)) and not calls)
        finally:prover.produce=old
        submit=LoopbackSubmit('http://127.0.0.1:'+str(network.http[0]))
        sent=[];returned={'rpc_returned':False,'response_accepted':False,'response_discarded':False}
        def discard(raw):
            check('durable_claim_before_io',wallet.status(ident)['attempts']==1 and raw==wire and not sent)
            sent.append(digest(raw));reply=submit(raw)
            returned.update(rpc_returned=True,response_accepted=reply.get('code')==0,response_discarded=True)
            raise TimeoutError('intentional acknowledgement discard')
        delivery=wallet.deliver_once(ident,discard)
        report['transport']={**returned,'calls':sent,'delivery':delivery}
        check('lost_return_preserves_obligation',delivery['outcome']=='unknown' and returned['response_accepted']
              and wallet.status(ident)['attempts']==1 and len(sent)==1)
        network.start_engine(2);network.start_engine(3)
        wait_until(lambda:all(len(network.direct_state(i)['state']['receipts'])==1 for i in range(4)),180)
        check('actual_arbitrary_payment_committed',
              all(network.direct_state(i)['state']['receipts'][0]['raw']==wire.hex() for i in range(4)))
        observation=network.hold_sources_without_quorum()
        network.start_engine(2);network.start_engine(3)
        wait_until(lambda:network.height(0)>=observation['height']+1,150)
        signed=rpc(network.http[0],'commit',{'height':str(observation['height']+1)})['signed_header']
        verify_state(observation,signed,rawg,worker)
        live=network.hold_sources_without_quorum()
        check('four_validator_agreement',all(canonical(network.direct_state(i))==canonical(live) for i in range(4)))
        wallet.observe(observation,signed);record=wallet.recorded_receipt(ident);report['record']=record
        check('signed_exact_execution',record['raw']==wire.hex() and record['receipt']['kind']=='payment')
        wallet.close();wallet=CertifiedTreasuryJournal(directory/'journal.sqlite',expected_genesis=rawg,worker=worker)
        check('reopen_exact_wire_no_redelivery',wallet.export(ident)==wire and wallet.recorded_receipt(ident)==record
              and refused(lambda:wallet.deliver_once(ident,submit)))
        forged=copy.deepcopy(signed);forged['header']['app_hash']='ab'*32
        check('forged_certificate_preserves_record',refused(lambda:wallet.observe(observation,forged))
              and wallet.recorded_receipt(ident)==record)
        network.start_engine(2);network.start_engine(3)
        network.stop_node(3);network.start_app(3);network.start_engine(3)
        wait_until(lambda:len(network.direct_state(3)['state']['receipts'])==1,150)
        check('same_store_restart_converges',network.direct_state(3)['state']['receipts']==observation['state']['receipts'])
    except Exception as exc:
        report['error']={'type':type(exc).__name__,'message':str(exc)}
    finally:
        if wallet:
            try:wallet.close()
            except Exception as exc:report['cleanup_error']={'type':type(exc).__name__,'message':'journal cleanup failed'}
        if network:
            try:
                network.close()
                check('workers_stopped',all(type(row.get('exit_code')) is int for row in report['processes']))
            except Exception as exc:
                report['cleanup_error']={'type':type(exc).__name__,'message':'network cleanup failed'}
        report['checks'].append({'id':'source_unchanged','passed':source()==before,'evidence':{}})
        if [c['id'] for c in report['checks']]==list(CHECKS) and all(c['passed'] for c in report['checks']) and not report.get('cleanup_error'):
            report['status']='candidate-passed' if args.candidate else 'qualified-one-host-prepared-prover'
        output.write_bytes(canonical(report)+b'\n')
    return 0 if report['status'] in ('candidate-passed','qualified-one-host-prepared-prover') else 1
def main():
    p=argparse.ArgumentParser(description=__doc__)
    for name in ('engine','worker','fixture-prover','prover','request-fixture','template','output'):
        p.add_argument('--'+name,type=Path,required=True)
    p.add_argument('--candidate',action='store_true')
    raise SystemExit(run(p.parse_args()))
if __name__=='__main__':main()
