#!/usr/bin/env python3
"""Actual quote-bound P7 proof, four validators and encrypted local fulfillment."""
import argparse,base64,copy,json,os,subprocess,sys
from pathlib import Path
from unittest.mock import patch
ROOT=Path(__file__).resolve().parents[1];sys.path.insert(0,str(ROOT/'src'))
import run_protocol7_engine as engine
from run_protocol7_client import Network
from run_protocol5_engine import _hold_transaction_height,_stop
from run_devnet import rpc,wait_until
from protocol7_treasury import canonical,digest,bootstrap_digest,PROFILE_SHA256,genesis_document,parse,integer,numfield,ZERO,Unavailable
from protocol7_worker import Worker
from protocol7_prover import Prover
from protocol7_notes import NoteController
from protocol7_wallet import CertifiedTreasuryJournal
from protocol7_merchant import MerchantBook,MerchantError
from protocol7_delivery import LoopbackSubmit
from protocol7_certificate import verify_state
CHECKS=('source_clean','engine_identity','fresh_network_bound_genesis','all_four_initialized',
 'precommitted_quote_actual_caller','unpaid_fulfillment_refused','actual_quote_bound_proof',
 'single_payment_lost_acknowledgement','actual_payment_four_state_agreement','signed_exact_execution',
 'certificate_only_refused','wrong_quote_refused','five_opening_mutations_refused','helper_unavailable_refused',
 'actual_enrollment_caller','encrypted_disclosure_retained','actual_fulfillment_lost_return',
 'duplicate_and_cold_recovery_exact','read_only_inspection_unchanged','immutable_origin_conflict_refused',
 'wrong_key_and_ciphertext_refused','same_store_restart_authenticated','valid_recertification_conflict_refused','no_second_wallet_attempt',
 'workers_stopped','source_unchanged')
CLAIMS={'quote_precommitted_request':True,'native604_explicit_disclosure':True,'actual_merchant_cli':True,
 'encrypted_disclosure_cold_reverification':True,'local_fulfillment_recovery':True,'one_host_four_validators':True,
 'synthetic_openings':True,'injected_helper_unavailability':True,'deliberate_return_discard':True,
 'production_ready':False,'selective_zk_disclosure':False,'merchant_redemption':False,'recipient_identity_authenticated':False,
 'external_exactly_once_delivery':False,'host_rollback_protected':False,'automatic_retry':False,
 'freshness_established':False,'independent_disclosure_decryption':False,'real_funds':False,'public_network':False}
SOURCE_NAMES=(*engine.SOURCE_NAMES,'scripts/run_protocol7_merchant.py','scripts/owner_treasury_merchant.py',
 'src/protocol7_merchant.py','tools/release/check_protocol7_merchant.py','tests/test_protocol7_merchant.py',
 'tests/test_protocol7_merchant_report.py','tools/owner-treasury-lab/halo2/tests/merchant_request.rs')
def source():
    v=engine.source()
    for name in SOURCE_NAMES:
        raw=(ROOT/name).read_bytes();v['files'][name]={'bytes':len(raw),'sha256':digest(raw)}
    return v
def run(args):
    output=args.output.absolute()
    if output.exists() or output.with_name(output.name+'.artifacts').exists():raise FileExistsError('fresh merchant report required')
    before=source();network=wallet=book=controller=None;encrypted=None
    report={'format':'1soft/protocol7-merchant-engine/v1','status':'failed','source':before,'checks':[],
            'claims':CLAIMS.copy(),'inputs':{},'commands':[],'cli_commands':[],'quotes':{},'inspections':[]}
    def check(name,passed,evidence=None):
        report['checks'].append({'id':name,'passed':bool(passed),'evidence':evidence or {}})
        print('P7_MERCHANT_CHECK '+name+' '+str(bool(passed)),flush=True)
        if not passed:raise AssertionError(name)
    def refusal(fn):
        try:fn()
        except ValueError as exc:return str(exc)
        return None
    try:
        check('source_clean',before['clean'] or args.candidate,{'candidate':args.candidate})
        for name in ('engine','worker','fixture_prover','prover','request_fixture','controller'):
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
        path=directory/'journal.sqlite';bookpath=directory/'merchant.sqlite'
        wallet=CertifiedTreasuryJournal(path,expected_genesis=rawg,worker=worker)
        prover=Prover(args.prover,report['inputs']['prover']['sha256'],expected_genesis=rawg,worker=worker)
        controller=NoteController(args.controller,report['inputs']['controller']['sha256'],expected_genesis=rawg,worker=worker)
        key=os.urandom(32);bookid=os.urandom(32).hex();recipient=witness[12];cli_runs=[]
        def openbook(key_override=None):
            return MerchantBook(bookpath,expected_genesis=rawg,controller=controller,key=key_override or key,
                                book_id=bookid,merchant_namespace='local.synthetic.resource',recipient=recipient)
        def merchant_cli(op,data):
            argv=[sys.executable,'-B',str(ROOT/'scripts/owner_treasury_merchant.py'),
              '--book',str(bookpath),'--genesis',str(network.genesis_path),'--worker',str(args.worker),
              '--kat',str(network.paths['kat']),'--controller',str(args.controller),'--genesis-sha256',digest(rawg),
              '--worker-sha256',worker.sha256,'--controller-sha256',controller.sha256,'--book-id',bookid,
              '--merchant-namespace','local.synthetic.resource','--recipient',recipient,'--execution-receipt',op]
            child=subprocess.Popen(argv,stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=subprocess.PIPE,
                    env={'PYTHONPATH':str(ROOT/'src')+':'+str(ROOT/'scripts')},start_new_session=True)
            network._record('merchant-cli',0,child,digest((ROOT/'scripts/owner_treasury_merchant.py').read_bytes()))
            try:out,err=child.communicate(canonical({'key':key.hex(),**data}),timeout=180)
            except subprocess.TimeoutExpired:network._record_exit(child.pid,_stop(child));raise
            network._record_exit(child.pid,child.returncode)
            if child.returncode or err or len(out)>65536:raise RuntimeError('actual merchant CLI failed')
            reply=json.loads(out)
            if canonical(reply)+b'\n'!=out or reply.get('status')!='completed-local-command' or reply.get('operation')!=op:
                raise ValueError('closed merchant response differs')
            if key.hex().encode() in out or any(opening[k].encode() in out for k in ('payment_blind','payment_note_secret')):
                raise AssertionError('private merchant material exposed')
            report['cli_commands'].append(reply);cli_runs.extend(reply['result']['execution']['note_controller'])
            return {k:v for k,v in reply['result'].items() if k!='execution'}
        opening={'recipient':recipient,'payment':integer(witness[13]),'payment_blind':witness[14],
                 'payment_expiry':integer(witness[29]),'payment_note_secret':witness[30]}
        resource=b'1soft synthetic purchased resource v1\n'
        terms={'resource':resource.hex(),'amount':opening['payment'],'payment_expiry':opening['payment_expiry'],
               'grant_id':public[6],'generation':integer(public[26]),'valid_from':integer(public[15]),'valid_until':integer(public[16])}
        quote=merchant_cli('quote',terms);requestid=quote['request'];report['quotes']['original']=quote
        book=openbook();report['inspections'].append(book.inspect(requestid))
        check('precommitted_quote_actual_caller',report['inspections'][-1]['status']=='quoted' and
              quote['core']['resource']==resource.hex() and quote['core']['recipient']==recipient)
        check('unpaid_fulfillment_refused',refusal(lambda:book.fulfill(requestid))=='P7 certified enrolled payment required')
        public[18]=requestid
        for i in (9,10,11,12,13,19,21,22,23,24):public[i]=ZERO
        public,witness=controller.construct(public,witness);public=list(public);witness=list(witness)
        ident=wallet.prepare(prover,public,witness);wire=wallet.export(ident)
        report.update(prepared_public=public,prepared_wire=wire.hex(),prepared_txid=ident,prover_run=prover.last_run)
        r=prover.last_run;network.receipts.append({'role':'arbitrary-prover','node':0,'pid':r['pid'],
          'start_ticks':r['start_ticks'],'executable_sha256':r['binary_sha256'],'exit_code':r['exit_code']})
        check('actual_quote_bound_proof',public[18]==requestid and worker.verify(wire) and
              controller.merchant_commitment(public,opening)==public[22] and all(public!=parse(v) for v in txs.values()))
        submit=LoopbackSubmit('http://127.0.0.1:'+str(network.http[0]));sent=[];returned={'rpc_returned':False,'response_accepted':False,'response_discarded':False}
        def discard(raw):
            if wallet.status(ident)['attempts']!=1 or raw!=wire or sent:raise AssertionError('single claim before IO differs')
            sent.append(digest(raw));reply=submit(raw)
            returned.update(rpc_returned=True,response_accepted=reply.get('code')==0,response_discarded=True)
            raise TimeoutError('intentional RPC return discard')
        delivery=wallet.deliver_once(ident,discard);report['transport']={**returned,'calls':sent,'delivery':delivery}
        check('single_payment_lost_acknowledgement',delivery['outcome']=='unknown' and returned['response_accepted'] and len(sent)==1)
        network.start_engine(2);network.start_engine(3)
        wait_until(lambda:all(len(network.direct_state(i)['state']['receipts'])==1 for i in range(4)),180)
        observation=network.hold_sources_without_quorum()
        check('actual_payment_four_state_agreement',all(canonical(network.direct_state(i))==canonical(observation) for i in range(4))
              and observation['state']['receipts'][0]['raw']==wire.hex())
        network.start_engine(2);network.start_engine(3)
        wait_until(lambda:network.height(0)>=observation['height']+1,150)
        signed=rpc(network.http[0],'commit',{'height':str(observation['height']+1)})['signed_header']
        verify_state(observation,signed,rawg,worker);network.hold_sources_without_quorum()
        wallet.observe(observation,signed);record=wallet.recorded_receipt(ident);report['record']=record
        check('signed_exact_execution',record['raw']==wire.hex() and record['receipt']['kind']=='payment')
        snap=lambda:canonical(list(book.db.iterdump()))
        beforestore=snap();certificate_only=refusal(lambda:book.enroll(requestid,record['certificate'],opening))
        check('certificate_only_refused',certificate_only=='P7 exact certified merchant payment required' and snap()==beforestore,{'refusal':certificate_only})
        badterms={**terms,'resource':b'different exact resource'.hex()}
        other=book.create_quote(**{**badterms,'resource':bytes.fromhex(badterms['resource'])});report['quotes']['other']=other
        beforestore=snap();wrongquote=refusal(lambda:book.enroll(other['request'],record,opening))
        check('wrong_quote_refused',wrongquote=='P7 certified payment differs from retained quote' and snap()==beforestore,{'refusal':wrongquote})
        mutations={}
        for k in opening:
            bad=copy.deepcopy(opening);bad[k]=opening[k]+1 if type(opening[k]) is int else numfield(9919)
            why=refusal(lambda:book.enroll(requestid,record,bad));mutations[k]=why
            if why!='P7 merchant opening commitment mismatch' or snap()!=beforestore:raise AssertionError('opening mutation guard differs')
        check('five_opening_mutations_refused',len(mutations)==5,{'refusals':mutations})
        unavailable=False
        with patch.object(controller,'call',side_effect=Unavailable('injected unavailable helper')):
            try:book.enroll(requestid,record,opening)
            except Unavailable:unavailable=True
        check('helper_unavailable_refused',unavailable and snap()==beforestore,{'injected':True,'failure_class':'unavailable'})
        enrolled=merchant_cli('enroll',{'request':requestid,'origin':record,'opening':opening})
        check('actual_enrollment_caller',enrolled['txid']==ident and book.inspect(requestid)['status']=='certified-enrolled')
        public_dump=snap();ciphertext=bytes(book.db.execute('SELECT disclosure FROM payments').fetchone()[0])
        check('encrypted_disclosure_retained',len(ciphertext)>16 and all(s not in public_dump for s in
              (key,key.hex().encode(),opening['payment_blind'].encode(),opening['payment_note_secret'].encode())))
        nonce=book.db.execute('SELECT nonce FROM payments').fetchone()[0]
        encrypted=canonical({'format':'1soft/protocol7-merchant-disclosure-envelope/v1','pins':book.pins,
            'request':requestid,'origin_sha256':digest(canonical(record)),'nonce':bytes(nonce).hex(),'ciphertext':ciphertext.hex()})
        report['encrypted_disclosure']={'bytes':len(encrypted),'sha256':digest(encrypted)}
        # The observation log retains the public child response. The calling
        # application receives an exception, never the resource/result value.
        def discard_fulfillment_return():
            merchant_cli('fulfill',{'request':requestid})
            raise TimeoutError('intentional application fulfillment return discard')
        unknown=False
        try:discard_fulfillment_return()
        except TimeoutError:unknown=True
        lost={k:v for k,v in report['cli_commands'][-1]['result'].items() if k!='execution'}
        report['lost_result']=lost
        check('actual_fulfillment_lost_return',unknown and lost['resource']==resource.hex() and book.inspect(requestid)['status']=='fulfilled',
              {'actual_cli_returned':True,'application_return_discarded':True,'application_outcome':'unknown'})
        book.close();book=openbook();recovered=merchant_cli('fulfill',{'request':requestid})
        report['recovered_result']=recovered
        check('duplicate_and_cold_recovery_exact',recovered==lost and book.fulfill(requestid)==canonical(lost) and
              book.db.execute('SELECT count(*) FROM fulfillments').fetchone()[0]==1)
        def storage():return {suffix:Path(str(bookpath)+suffix).read_bytes() for suffix in ('','-wal','-shm') if Path(str(bookpath)+suffix).exists()}
        beforebytes=storage();inspection=book.inspect(requestid);report['inspections'].append(inspection)
        api_unchanged=storage()==beforebytes;logical=snap()
        cli_inspection=merchant_cli('inspect',{'request':requestid});report['inspections'].append(cli_inspection)
        check('read_only_inspection_unchanged',inspection==cli_inspection and inspection['status']=='fulfilled' and
              inspection['retry_authorized'] is False and api_unchanged and snap()==logical,
              {'api_main_wal_shm_bytes_unchanged':api_unchanged,'actual_cli_rows_unchanged':snap()==logical})
        beforestore=snap();forged=copy.deepcopy(record);forged['certificate']={}
        conflict=refusal(lambda:book.enroll(requestid,forged,opening))
        check('immutable_origin_conflict_refused',conflict=='P7 merchant certified exact execution required' and snap()==beforestore,
              {'refusal':conflict})
        wrongkey=refusal(lambda:openbook(os.urandom(32)))
        nonce,ct=book.db.execute('SELECT nonce,disclosure FROM payments').fetchone()
        book.db.execute('UPDATE payments SET disclosure=?',(bytes([ct[0]^1])+ct[1:],))
        altered=refusal(lambda:book.inspect(requestid))
        book.db.execute('UPDATE payments SET disclosure=?',(ct,))
        check('wrong_key_and_ciphertext_refused',wrongkey=='P7 merchant key authentication refused' and
              altered=='P7 merchant disclosure authentication refused' and snap()==beforestore,
              {'wrong_key_refusal':wrongkey,'ciphertext_refusal':altered,'synthetic_store_mutation':True})
        def store_ref():
            s=(network.runtime/'app3/state.sqlite').lstat()
            return {'device':s.st_dev,'inode':s.st_ino,'uid':s.st_uid,'mode':s.st_mode&0o777}
        store_before=store_ref()
        old_app=network.apps[3].pid
        # Holding sources removes engines 2/3 from the live-process map. Capture
        # both engine identities while running, before stop/hold removes them.
        network.start_engine(2);network.start_engine(3);old_engine=network.engines[3].pid
        network.stop_node(3);network.start_app(3);network.start_engine(3)
        new_app=network.apps[3].pid;new_engine=network.engines[3].pid
        wait_until(lambda:canonical(network.direct_state(3))==canonical(network.direct_state(0)),150)
        restarted=network.hold_sources_without_quorum();network.start_engine(2);network.start_engine(3)
        wait_until(lambda:network.height(0)>=restarted['height']+1,150)
        next_signed=rpc(network.http[0],'commit',{'height':str(restarted['height']+1)})['signed_header']
        certificate=verify_state(restarted,next_signed,rawg,worker);network.hold_sources_without_quorum()
        report['restart']={'witness':restarted,'signed_header':next_signed,'certificate':certificate,
            'store_before':store_before,'store_after':store_ref(),'old_application_pid':old_app,'old_engine_pid':old_engine,
            'new_application_pid':new_app,'new_engine_pid':new_engine}
        check('same_store_restart_authenticated',all(canonical(network.direct_state(i))==canonical(network.direct_state(0)) for i in range(4)) and
              restarted['state']['receipts']==observation['state']['receipts'] and book.fulfill(requestid)==canonical(lost) and
              store_before==store_ref() and store_before['uid']==os.getuid() and store_before['mode']==0o600 and
              old_app!=new_app and old_engine!=new_engine)
        recertified=copy.deepcopy(record);recertified.update(witness=restarted,signed_header=next_signed,
            certificate=certificate,state_height=restarted['height'])
        if canonical(recertified)==canonical(record):raise AssertionError('distinct actual recertification required')
        beforestore=snap();why=refusal(lambda:book.enroll(requestid,recertified,opening))
        check('valid_recertification_conflict_refused',why=='P7 immutable merchant origin conflict' and snap()==beforestore,
              {'refusal':why,'new_state_height':restarted['height'],'original_state_height':record['state_height']})
        check('no_second_wallet_attempt',wallet.status(ident)['attempts']==1 and len(sent)==1 and
              refusal(lambda:wallet.deliver_once(ident,submit))=='P7 one delivery attempt already claimed or completed')
    except Exception as exc:report['error']={'type':type(exc).__name__,'message':str(exc)}
    finally:
        if book:book.close()
        if wallet:wallet.close()
        if network:
            try:
                if controller:
                    report['controller_runs']=controller.runs+cli_runs
                    for r in report['controller_runs']:network.receipts.append({'role':'note-controller','node':0,'pid':r['pid'],
                      'start_ticks':r['start_ticks'],'executable_sha256':r['binary_sha256'],'exit_code':r['exit_code']})
                network.close()
                if encrypted:
                    (output.with_name(output.name+'.artifacts')/'merchant-disclosure-encrypted.json').write_bytes(encrypted)
                    report['artifacts'].append({'name':'merchant-disclosure-encrypted.json','bytes':len(encrypted),'sha256':digest(encrypted)})
                check('workers_stopped',all(type(p.get('exit_code')) is int for p in report['processes']))
            except Exception as exc:report['cleanup_error']={'type':type(exc).__name__,'message':'merchant network cleanup failed'}
        report['checks'].append({'id':'source_unchanged','passed':source()==before,'evidence':{}})
        if [c['id'] for c in report['checks']]==list(CHECKS) and all(c['passed'] for c in report['checks']) and not report.get('cleanup_error'):
            report['status']='candidate-passed' if args.candidate else 'qualified-one-host-merchant-fulfillment'
        output.write_bytes(canonical(report)+b'\n')
    return 0 if report['status'] in ('candidate-passed','qualified-one-host-merchant-fulfillment') else 1
def main():
    p=argparse.ArgumentParser(description=__doc__)
    for name in ('engine','worker','fixture-prover','prover','request-fixture','controller','template','output'):
        p.add_argument('--'+name,type=Path,required=True)
    p.add_argument('--candidate',action='store_true');raise SystemExit(run(p.parse_args()))
if __name__=='__main__':main()
