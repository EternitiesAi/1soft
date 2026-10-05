#!/usr/bin/env python3
"""Actual restricted CHANGE import, encrypted reopen and re-spend on four local validators."""
import argparse,base64,copy,json,os,subprocess,sys
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1];sys.path.insert(0,str(ROOT/'src'))
import run_protocol7_engine as engine
from run_protocol7_client import Network
from run_protocol5_engine import _hold_transaction_height,_stop
from run_devnet import rpc,wait_until
from protocol7_treasury import canonical,digest,bootstrap_digest,PROFILE_SHA256,genesis_document,parse,integer,numfield,ZERO,command
from protocol7_worker import Worker
from protocol7_prover import Prover
from protocol7_notes import NoteController
from protocol7_vault import ChangeVault
from protocol7_wallet import CertifiedTreasuryJournal
from protocol7_delivery import LoopbackSubmit
from protocol7_certificate import verify_state
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

CHECKS=('source_clean','engine_identity','fresh_network_bound_genesis','all_four_initialized',
        'first_arbitrary_prepare','first_exact_quorum_execution','authenticated_change_import',
        'encrypted_reopen_and_wrong_key_refusal','owner_sequence_advance_certified',
        'sequence_preserves_restricted_note_identity','change_respend_prepared_and_staged',
        'cold_recovery_exact_wire_no_regeneration','second_lost_return_one_attempt',
        'import_before_certificate_refused','second_exact_quorum_execution',
        'second_change_import_and_reopen','spent_input_and_duplicate_refused',
        'active_grant_revocation_certified','revoked_grant_refused_before_proving',
        'forged_certificate_preserves_custody','four_validator_agreement',
        'same_store_restart_converges','workers_stopped','source_unchanged')
CLAIMS={'restricted_change_encrypted_custody':True,'actual_imported_change_respend':True,
        'owner_sequence_is_provenance':True,'exact_journal_recovery':True,
        'one_host_four_validators':True,'synthetic_openings':True,'external_key_required':True,
        'private_openings_delivered':False,'independent_ciphertext_decryption':False,
        'production_ready':False,'merchant_redemption':False,'recipient_discovery':False,
        'rollback_detection':False,'cross_device_coordination':False,'automatic_retry':False,
        'real_funds':False,'public_network':False,'freshness_established':False}
SOURCE_NAMES=(*engine.SOURCE_NAMES,'scripts/run_protocol7_vault.py','tools/release/check_protocol7_vault.py',
              'tests/test_protocol7_vault.py','tests/test_protocol7_vault_report.py',
              'tools/owner-treasury-lab/halo2/tests/note_request.rs')

def source():
    v=engine.source()
    for name in SOURCE_NAMES:
        raw=(ROOT/name).read_bytes();v['files'][name]={'bytes':len(raw),'sha256':digest(raw)}
    return v

def run(args):
    output=args.output.absolute()
    if output.exists() or output.with_name(output.name+'.artifacts').exists():raise FileExistsError('fresh custody report required')
    before=source();network=journal=controller=None;ciphertext=None
    report={'format':'1soft/protocol7-change-vault-engine/v1','status':'failed','source':before,
            'checks':[],'claims':CLAIMS.copy(),'inputs':{},'commands':[],
            'records':{},'transports':{},'prover_runs':[]}
    def check(name,passed,evidence=None):
        report['checks'].append({'id':name,'passed':bool(passed),'evidence':evidence or {}})
        print('P7_VAULT_CHECK '+name+' '+str(bool(passed)),flush=True)
        if not passed:raise AssertionError(name)
    def refused(fn):
        try:fn()
        except (ValueError,RuntimeError):return True
        return False
    try:
        check('source_clean',before['clean'] or args.candidate,{'candidate':args.candidate})
        for name in ('engine','worker','fixture_prover','prover','request_fixture','controller'):
            p=getattr(args,name)
            if p.is_symlink() or not p.is_file() or not 0<p.stat().st_size<=64*1024*1024:raise ValueError('bounded regular binary required')
            report['inputs'][name]={'bytes':p.stat().st_size,'sha256':digest(p.read_bytes())}
        check('engine_identity',report['inputs']['engine']['sha256']==engine.ENGINE_SHA256
              and subprocess.check_output([str(args.engine),'version'],text=True).strip()=='0.38.25')
        template=json.loads((args.template/'genesis.json').read_bytes());kat=(args.template/'a.tx').read_bytes()
        preliminary=Worker(args.worker,report['inputs']['worker']['sha256'],kat)
        network=Network({'engine':args.engine,'worker':args.worker},output,report)
        roster=sorted([{'public_key':base64.b64decode(r['pub_key']['value']).hex(),'power':int(r['power'])}
                       for r in network.engine_genesis['validators']],key=lambda r:r['public_key'])
        g={'protocol_version':7,'chain_id':network.chain_id,'profile_sha256':PROFILE_SHA256,
           'worker_sha256':report['inputs']['worker']['sha256'],'kat_sha256':digest(kat),'validators':roster,'treasury':template}
        domain=preliminary.network_domain(bytes.fromhex(bootstrap_digest(g)))
        fixtures=network.runtime/'proof-fixtures';network.paths['fixtures']=fixtures
        with (network.runtime/'fixture.log').open('wb') as log:
            child=subprocess.Popen([str(args.fixture_prover),'fixtures-domain',str(fixtures),domain],
                  stdin=subprocess.DEVNULL,stdout=log,stderr=log,start_new_session=True,env={'RAYON_NUM_THREADS':'2'})
            network._record('fixture-prover',0,child,report['inputs']['fixture_prover']['sha256'])
            try:code=child.wait(timeout=300)
            except subprocess.TimeoutExpired:network._record_exit(child.pid,_stop(child));raise
            network._record_exit(child.pid,code)
            if code:raise RuntimeError('fixture preparation failed')
        txs={p.stem:p.read_bytes() for p in fixtures.glob('*.tx')}
        g['treasury']=json.loads((fixtures/'genesis.json').read_bytes());g['kat_sha256']=digest(txs['a'])
        network.paths['kat']=fixtures/'a.tx';worker=Worker(args.worker,g['worker_sha256'],txs['a']);rawg=canonical(g)
        report.update(genesis=g,genesis_sha256=digest(rawg),bootstrap_sha256=bootstrap_digest(g))
        check('fresh_network_bound_genesis',len(txs)==12 and genesis_document(rawg,worker)==g and g['treasury']['genesis']==domain)
        network.install_genesis(rawg,worker);network.start_sources()
        check('all_four_initialized',all(network.direct_state(i)['genesis']==g for i in range(4)))
        _hold_transaction_height(network)
        request=subprocess.check_output([str(args.request_fixture)],input=bytes.fromhex(bootstrap_digest(g)),timeout=30)
        if len(request)!=2088:raise ValueError('synthetic request length differs')
        public=[request[136+i*32:168+i*32].hex() for i in range(30)]
        witness=[request[1096+i*32:1128+i*32].hex() for i in range(31)]
        directory=network.runtime/'client';directory.mkdir(mode=0o700)
        path=directory/'journal.sqlite';vaultpath=directory/'vault.json'
        journal=CertifiedTreasuryJournal(path,expected_genesis=rawg,worker=worker)
        prover=Prover(args.prover,report['inputs']['prover']['sha256'],expected_genesis=rawg,worker=worker)
        controller=NoteController(args.controller,report['inputs']['controller']['sha256'],expected_genesis=rawg,worker=worker)
        key=os.urandom(32);vid=os.urandom(32).hex()
        def reopen():return ChangeVault(vaultpath,key=key,expected_vault_id=vid,controller=controller)
        vault=ChangeVault(vaultpath,key=key,expected_vault_id=vid,controller=controller,create=True)
        submit=LoopbackSubmit('http://127.0.0.1:'+str(network.http[0]))
        def measured_proof():
            run=prover.last_run.copy();report['prover_runs'].append(run)
            network.receipts.append({'role':'arbitrary-prover','node':0,'pid':run['pid'],'start_ticks':run['start_ticks'],
                                     'executable_sha256':run['binary_sha256'],'exit_code':run['exit_code']})
        def deliver(ident,wire,label):
            calls=[];returns={'rpc_returned':False,'response_accepted':False,'response_discarded':False}
            def discard(sent):
                if journal.status(ident)['attempts']!=1 or sent!=wire or calls:raise AssertionError('claim before IO differs')
                calls.append(digest(sent));reply=submit(sent)
                returns.update(rpc_returned=True,response_accepted=reply.get('code')==0,response_discarded=True)
                raise TimeoutError('intentional actual RPC acknowledgement discard')
            result=journal.deliver_once(ident,discard)
            report['transports'][label]={**returns,'calls':calls,'delivery':result}
            if not (result['outcome']=='unknown' and returns['response_accepted'] and calls==[digest(wire)]):
                raise AssertionError('actual single delivery lost-return contract failed')
        def certify(ident,wire,count):
            network.start_engine(2);network.start_engine(3)
            wait_until(lambda:all(len(network.direct_state(i)['state']['receipts'])==count for i in range(4)),240)
            observation=network.hold_sources_without_quorum()
            network.start_engine(2);network.start_engine(3)
            wait_until(lambda:network.height(0)>=observation['height']+1,150)
            signed=rpc(network.http[0],'commit',{'height':str(observation['height']+1)})['signed_header']
            verify_state(observation,signed,rawg,worker);network.hold_sources_without_quorum()
            journal.observe(observation,signed);record=journal.recorded_receipt(ident)
            if record['raw']!=wire.hex():raise AssertionError('exact execution differs')
            return record
        first=journal.prepare(prover,public,witness);firstwire=journal.export(first);measured_proof()
        check('first_arbitrary_prepare',parse(firstwire)==public and worker.verify(firstwire)
              and all(public!=parse(v) for v in txs.values()) and journal.status(first)['attempts']==0)
        deliver(first,firstwire,'first');firstrecord=certify(first,firstwire,1);report['records']['first']=firstrecord
        check('first_exact_quorum_execution',firstrecord['receipt']['kind']=='payment')
        opening={'agent_secret':witness[11],'value':integer(witness[24]),'expiry':integer(witness[26]),
                 'note_secret':witness[27],'blind':witness[28]}
        commitment=vault.import_change(journal,first,opening)
        d0=controller.derive(public,opening,firstrecord['witness']['state']['treasury']['notes'],
                             firstrecord['witness']['state']['treasury']['notes'].index(commitment))
        report['imported_note']=d0
        check('authenticated_change_import',commitment==public[23] and vault.inventory()['notes']==[commitment])
        encrypted=vaultpath.read_bytes();inventory=vault.inventory()
        def wrongkey():ChangeVault(vaultpath,key=os.urandom(32),expected_vault_id=vid,controller=controller)
        check('encrypted_reopen_and_wrong_key_refusal',reopen().inventory()==inventory and refused(wrongkey)
              and all(s not in encrypted for s in (key,key.hex().encode(),opening['note_secret'].encode(),opening['blind'].encode())))
        ownerkey=Ed25519PrivateKey.from_private_bytes(bytes([7])*32)
        def revoke(grant_id,label,count):
            live=network.direct_state(0);t=live['state']['treasury'];slot=next(x for x in t['grants'] if x['id']==grant_id)
            wire=command(g,live['state'],kind='revoke',grant_id=grant_id,height=live['height']+2,
                         new_commitment=ZERO,new_agent_key=slot['agent_key'],key=ownerkey,worker=worker)
            report['commands'].append(wire.hex());ident=journal.retain(wire)
            deliver(ident,wire,label);record=certify(ident,wire,count);report['records'][label]=record
            return record
        other=next(x['id'] for x in g['treasury']['grants'] if x['id']!=public[6])
        otherrecord=revoke(other,'other_revoke',2);t=otherrecord['witness']['state']['treasury']
        check('owner_sequence_advance_certified',t['owner_sequence']==1 and otherrecord['receipt']['kind']=='owner')
        d1=controller.derive(public,opening,t['notes'],t['notes'].index(commitment))
        check('sequence_preserves_restricted_note_identity',d0==d1 and integer(public[25])==0)
        debit=integer(witness[13])+integer(public[17])
        authority={'parent':[witness[0],numfield(integer(witness[1])+debit),numfield(integer(witness[2])+1),witness[4]],
                   'grant':[witness[5],numfield(integer(witness[6])+debit),numfield(integer(witness[7])+1),witness[9],witness[10],witness[12]]}
        vault=reopen();second=vault.prepare_payment(journal,prover,commitment,authority=authority,amount=1,valid_until=60,request=numfield(9019))
        secondwire=journal.export(second);secondpublic=parse(secondwire);measured_proof()
        check('change_respend_prepared_and_staged',secondpublic[21]==d0['nullifier'] and secondpublic[20]==d0['root']
              and integer(secondpublic[25])==1 and worker.verify(secondwire) and len(vault.inventory()['retained_preparations'])==1)
        journal.close();journal=CertifiedTreasuryJournal(path,expected_genesis=rawg,worker=worker);vault=reopen()
        check('cold_recovery_exact_wire_no_regeneration',vault.recover_prepared(journal,commitment)==second
              and journal.export(second)==secondwire and len(report['prover_runs'])==2)
        deliver(second,secondwire,'second')
        check('second_lost_return_one_attempt',journal.status(second)['attempts']==1)
        check('import_before_certificate_refused',refused(lambda:vault.import_prepared_change(journal,second)))
        secondrecord=certify(second,secondwire,3);report['records']['second']=secondrecord
        check('second_exact_quorum_execution',secondrecord['receipt']['kind']=='payment'
              and secondpublic[21] in secondrecord['witness']['state']['treasury']['nullifiers'])
        secondcommit=vault.import_prepared_change(journal,second);inv=vault.inventory();vault=reopen()
        check('second_change_import_and_reopen',secondcommit==secondpublic[23] and vault.inventory()==inv
              and inv['revision']==3 and inv['notes']==[commitment,secondcommit])
        check('spent_input_and_duplicate_refused',refused(lambda:vault.prepare_payment(journal,prover,commitment,
              authority=authority,amount=1,valid_until=60,request=numfield(9020)))
              and refused(lambda:vault.import_prepared_change(journal,second))
              and refused(lambda:journal.deliver_once(second,submit)))
        revoked=revoke(public[6],'active_revoke',4);rt=revoked['witness']['state']['treasury']
        check('active_grant_revocation_certified',rt['owner_sequence']==2
              and next(x for x in rt['grants'] if x['id']==public[6])['commitment']==ZERO)
        beforevault=vaultpath.read_bytes();calls=[];produce=prover.produce
        def forbidden(*_):calls.append('unexpected');raise AssertionError('revoked grant must refuse before proving')
        prover.produce=forbidden
        try:check('revoked_grant_refused_before_proving',refused(lambda:vault.prepare_payment(journal,prover,secondcommit,
                  authority=authority,amount=1,valid_until=60,request=numfield(9021))) and not calls and vaultpath.read_bytes()==beforevault)
        finally:prover.produce=produce
        forged=copy.deepcopy(revoked['signed_header']);forged['header']['app_hash']='ab'*32
        check('forged_certificate_preserves_custody',refused(lambda:journal.observe(revoked['witness'],forged))
              and vault.inventory()==inv and vaultpath.read_bytes()==beforevault and journal.recorded_receipt(second)==secondrecord)
        live=network.direct_state(0)
        check('four_validator_agreement',all(canonical(network.direct_state(i))==canonical(live) for i in range(4)))
        network.start_engine(2);network.start_engine(3);network.stop_node(3);network.start_app(3);network.start_engine(3)
        wait_until(lambda:len(network.direct_state(3)['state']['receipts'])==4,150)
        check('same_store_restart_converges',network.direct_state(3)['state']['receipts']==revoked['witness']['state']['receipts'])
        report['vault_inventory']=inv;ciphertext=vaultpath.read_bytes()
        report['vault_ciphertext']={'bytes':len(ciphertext),'sha256':digest(ciphertext),'header':json.loads(ciphertext)['header']}
    except Exception as exc:report['error']={'type':type(exc).__name__,'message':str(exc)}
    finally:
        if journal:journal.close()
        if network:
            try:
                if controller:
                    report['controller_runs']=controller.runs
                    for r in controller.runs:network.receipts.append({'role':'note-controller','node':0,'pid':r['pid'],
                        'start_ticks':r['start_ticks'],'executable_sha256':r['binary_sha256'],'exit_code':r['exit_code']})
                network.close()
                if ciphertext:
                    directory=output.with_name(output.name+'.artifacts');(directory/'vault-encrypted.json').write_bytes(ciphertext)
                    report['artifacts'].append({'name':'vault-encrypted.json','bytes':len(ciphertext),'sha256':digest(ciphertext)})
                check('workers_stopped',all(type(r.get('exit_code')) is int for r in report['processes']))
            except Exception as exc:report['cleanup_error']={'type':type(exc).__name__,'message':'network cleanup failed'}
        report['checks'].append({'id':'source_unchanged','passed':source()==before,'evidence':{}})
        if [c['id'] for c in report['checks']]==list(CHECKS) and all(c['passed'] for c in report['checks']) and not report.get('cleanup_error'):
            report['status']='candidate-passed' if args.candidate else 'qualified-one-host-encrypted-change-custody'
        output.write_bytes(canonical(report)+b'\n')
    return 0 if report['status'] in ('candidate-passed','qualified-one-host-encrypted-change-custody') else 1

def main():
    p=argparse.ArgumentParser(description=__doc__)
    for name in ('engine','worker','fixture-prover','prover','request-fixture','controller','template','output'):
        p.add_argument('--'+name,type=Path,required=True)
    p.add_argument('--candidate',action='store_true');raise SystemExit(run(p.parse_args()))
if __name__=='__main__':main()
