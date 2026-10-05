#!/usr/bin/env python3
"""Actual loopback validators + certified exact wallet recovery; no public service."""
from __future__ import annotations
import argparse,base64,json,os,subprocess,sys
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1];sys.path.insert(0,str(ROOT/'src'))
import run_protocol6_engine as engine
from protocol6_treasury import canonical,digest,genesis_document,txid,PROFILE_SHA256
from protocol6_certificate import verify_state
from protocol6_worker import Worker
from protocol6_wallet import CertifiedTreasuryJournal
from protocol6_delivery import LoopbackSubmit
from run_devnet import rpc,wait_until

CHECKS=('source_clean','engine_identity','external_genesis_pinned','actual_proofs_checked','shared_authority_reservation_refused',
        'all_four_initialized','claim_before_io','discarded_return_stays_held','actual_payment_committed',
        'four_validator_agreement','signed_exact_execution','journal_reopen_exact','exact_wire_export','second_delivery_refused',
        'conflicting_obligation_held','known_conflict_first_claim_refused','forged_certificate_preserves_record','workers_stopped','source_unchanged')
CLAIMS={'protocol6_rules_unchanged':True,'independent_bounded_replay':True,'exact_certificate_recovery':True,
        'one_attempt_local_controller':True,'one_host_four_validators':True,'synthetic_conflict_fixture':True,
        'production_ready':False,'public_network':False,'real_funds':False,'independent_operators':False,
        'owner_lifecycle':False,'merchant_redemption':False,'recipient_discovery':False,'custody':False,
        'proving_or_signing_wallet':False,'freshness_established':False,'journal_rollback_protected':False,'cross_device_coordination':False}
SOURCE_NAMES=(*engine.SOURCE_NAMES,'src/protocol6_wallet.py','src/protocol6_delivery.py','scripts/run_protocol6_wallet.py','scripts/treasury_wallet.py','tools/release/check_protocol6_wallet.py')
def source():
    s=engine.source()
    for rel in SOURCE_NAMES:
        raw=(ROOT/rel).read_bytes();s['files'][rel]={'bytes':len(raw),'sha256':digest(raw)}
    return s
def run(args):
    out=args.output.absolute();neededs={'engine':args.engine,'worker':args.worker,'genesis':args.fixtures/'genesis.json'}
    neededs.update({n:args.fixtures/(n+'.tx') for n in ('a','b','after_a_b','after_b_a','duplicate_request')})
    if out.exists() or out.with_name(out.name+'.artifacts').exists():raise FileExistsError('fresh wallet evidence required')
    missing=[n for n,p in neededs.items() if not p.exists() and not p.is_symlink()]
    if os.name!='posix':missing.append('POSIX platform')
    if missing:
        out.write_bytes(canonical({'format':'1soft/protocol6-wallet-engine/v1','status':'unassessed','missing_inputs':missing,'checks':[],'processes':[]})+b'\n');return 2
    for n,p in neededs.items():
        bound=64*1024*1024 if n in ('engine','worker') else (16384 if n=='genesis' else 4008)
        if p.is_symlink() or not p.is_file() or p.stat().st_size>bound:raise ValueError('unsafe wallet runner input: '+n)
    before=source();report={'format':'1soft/protocol6-wallet-engine/v1','status':'failed','source':before,'checks':[],'claims':CLAIMS.copy(),'inputs':{}}
    network=None;primary=None;losing=None
    def check(name,passed,evidence=None):
        report['checks'].append({'id':name,'passed':bool(passed),'evidence':evidence or {}})
        print('P6_WALLET_CHECK '+name+' '+str(bool(passed)),flush=True)
        if not passed:raise AssertionError(name)
    def refused(fn):
        try:fn()
        except ValueError:return True
        return False
    try:
        check('source_clean',before['clean'] or args.candidate,{'candidate':args.candidate})
        for n in ('engine','worker'):
            p=neededs[n];report['inputs'][n]={'bytes':p.stat().st_size,'sha256':digest(p.read_bytes())}
        check('engine_identity',report['inputs']['engine']['sha256']==engine.ENGINE_SHA256 and subprocess.check_output([str(args.engine),'version'],text=True).strip()=='0.38.25')
        txs={n:neededs[n].read_bytes() for n in ('a','b','after_a_b','after_b_a','duplicate_request')}
        report['inputs']['fixtures']={n:digest(raw) for n,raw in txs.items()};report['inputs']['treasury_genesis']=digest(neededs['genesis'].read_bytes())
        network=engine.Network({'engine':args.engine,'worker':args.worker,'kat':neededs['a'],'fixtures':args.fixtures},out,report)
        vals=sorted([{'public_key':base64.b64decode(v['pub_key']['value'],validate=True).hex(),'power':int(v['power'])} for v in network.engine_genesis['validators']],key=lambda v:v['public_key'])
        g={'protocol_version':6,'chain_id':network.chain_id,'profile_sha256':PROFILE_SHA256,'worker_sha256':report['inputs']['worker']['sha256'],
           'kat_sha256':digest(txs['a']),'validators':vals,'treasury':json.loads(neededs['genesis'].read_bytes())}
        raw=canonical(g);expected=digest(raw);network.install_genesis(raw)
        # This trusted owned-bootstrap file is pinned before any application/peer starts.
        external=network.runtime/'wallet-trusted-genesis.json';external.write_bytes(raw)
        pinned=external.read_bytes()
        check('external_genesis_pinned',digest(pinned)==expected and genesis_document(pinned)==g and network.genesis_path.read_bytes()==pinned)
        report['genesis']=g;report['genesis_sha256']=expected
        w=Worker(args.worker,g['worker_sha256'],txs['a']);report['wallet_startup']=w.startup
        for name in ('primary','conflict'):(network.runtime/('wallet-'+name)).mkdir(mode=0o700)
        primary_path=network.runtime/'wallet-primary/journal.sqlite'
        primary=CertifiedTreasuryJournal(primary_path,expected_genesis=pinned,worker=w)
        losing=CertifiedTreasuryJournal(network.runtime/'wallet-conflict/journal.sqlite',expected_genesis=pinned,worker=w)
        a=primary.retain(txs['a']);b=losing.retain(txs['b'])
        check('actual_proofs_checked',a==txid(txs['a']) and b==txid(txs['b']) and w.verify(txs['a']) and w.verify(txs['b']))
        check('shared_authority_reservation_refused',refused(lambda:primary.retain(txs['b'])))
        network.start_sources()
        startup=[json.loads(base64.b64decode(rpc(network.http[i],'abci_query',{'path':'/info','prove':False})['response']['value']))['worker_startup'] for i in range(4)]
        check('all_four_initialized',all(network.direct_state(i)['genesis']==g for i in range(4)),{'worker_startup':startup})
        submit=LoopbackSubmit('http://127.0.0.1:'+str(network.http[0]))
        calls=[];transport={'response_discarded':False,'rpc_returned':False,'response_accepted':False}
        def discard(sent):
            check('claim_before_io',primary.status(a)['attempts']==1 and sent==txs['a'] and not calls)
            calls.append(digest(sent));reply=submit(sent)
            transport['rpc_returned']=True;transport['response_accepted']=reply.get('code')==0
            transport['response_discarded']=True
            raise TimeoutError('intentional acknowledgement discard after actual RPC return')
        delivery=primary.deliver_once(a,discard);report['transport']={**transport,'calls':calls,'delivery':delivery,'test_injection':'intentional response discard; actual validator submission'}
        check('discarded_return_stays_held',delivery['outcome']=='unknown' and transport['response_accepted'] and primary.status(a)['status']=='attempted-held' and len(calls)==1)
        def accepted():
            states=[network.direct_state(i) for i in range(4)]
            return states if all(len(s['state']['receipts'])==1 for s in states) else None
        states=wait_until(accepted,120)
        check('actual_payment_committed',all(s['state']['receipts'][0]['txid']==a for s in states))
        witness=network.hold_sources_without_quorum();states=[network.direct_state(i) for i in range(4)]
        check('four_validator_agreement',all(canonical(s)==canonical(witness) for s in states))
        network.start_engine(2);network.start_engine(3)
        wait_until(lambda:network.height(0)>=witness['height']+1,90)
        signed=rpc(network.http[0],'commit',{'height':str(witness['height']+1)})['signed_header']
        report['state_witness']=witness;report['signed_header']=signed;report['certificate']=verify_state(witness,signed,pinned)
        primary.observe(witness,signed);record=primary.recorded_receipt(a);report['wallet_record']=record
        check('signed_exact_execution',record['receipt']==witness['state']['receipts'][0] and record['raw']==txs['a'].hex())
        primary.close();primary=CertifiedTreasuryJournal(primary_path,expected_genesis=pinned,worker=w)
        check('journal_reopen_exact',primary.recorded_receipt(a)==record and primary.status(a)['status']=='recorded-certified')
        check('exact_wire_export',primary.export(a)==txs['a'])
        check('second_delivery_refused',refused(lambda:primary.deliver_once(a,discard)) and len(calls)==1)
        losing.observe(witness,signed);held=losing.status(b);report['held_obligation']={'raw':txs['b'].hex(),'txid':b,'status':held}
        check('conflicting_obligation_held',held['status']=='observed-held' and held['hold_reason']=='conflict' and refused(lambda:losing.recorded_receipt(b)))
        check('known_conflict_first_claim_refused',refused(lambda:losing.claim(b)) and losing.status(b)['attempts']==0)
        import copy
        forged=copy.deepcopy(signed);forged['commit']['signatures'][0]['signature']='AA=='
        check('forged_certificate_preserves_record',refused(lambda:primary.observe(witness,forged)) and primary.recorded_receipt(a)==record)
        report['wallet_status']=primary.status(a)
    except Exception as exc:report['error']={'type':type(exc).__name__,'message':str(exc)}
    finally:
        if primary:primary.close()
        if losing:losing.close()
        if network:
            try:
                network.close()
                artifacts=out.with_name(out.name+'.artifacts')
                extras={'bootstrap-genesis.json':canonical(report['genesis']),'wallet-record.json':canonical(report.get('wallet_record',{})),'wallet-held.json':canonical(report.get('held_obligation',{}))}
                for name,raw in extras.items():
                    (artifacts/name).write_bytes(raw);report['artifacts'].append({'name':name,'bytes':len(raw),'sha256':digest(raw)})
                check('workers_stopped',all('exit_code' in p for p in report['processes']))
            except Exception as exc:report['cleanup_error']={'type':type(exc).__name__,'message':str(exc)}
        report['checks'].append({'id':'source_unchanged','passed':source()==before,'evidence':{}})
        if [c['id'] for c in report['checks']]==list(CHECKS) and all(c['passed'] for c in report['checks']) and not report.get('cleanup_error'):
            report['status']='candidate-passed' if args.candidate else 'qualified-one-host-certified-treasury-wallet'
        out.write_bytes(canonical(report)+b'\n')
    return 0 if report['status'] in ('qualified-one-host-certified-treasury-wallet','candidate-passed') else 1
def main():
    p=argparse.ArgumentParser(description=__doc__)
    for n in ('engine','worker','fixtures','output'):p.add_argument('--'+n,type=Path,required=True)
    p.add_argument('--candidate',action='store_true');raise SystemExit(run(p.parse_args()))
if __name__=='__main__':main()
