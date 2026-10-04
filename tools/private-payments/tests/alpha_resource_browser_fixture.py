#!/usr/bin/env python3
"""Short actual Chromium merchant journey over four original local validators.

The page owns payment/retrieval consent. Narrow fixture IPC owns separate
operator enrollment and auditing. Fresh private DEV homes only; no scaled
clock, new dependencies, public services, real funds or trust renewal.
"""
import base64,json,hashlib,os,secrets,selectors,socket,subprocess,sys,threading,time,traceback,uuid
from dataclasses import asdict
from pathlib import Path
sys.dont_write_bytecode=True
ROOT=Path(__file__).resolve().parents[3]
sys.path[:0]=[str(ROOT/'src'),str(ROOT/'scripts'),str(ROOT/'tools/release'),str(ROOT/'tools/private-payments/tests')]+[str(p) for p in sorted((ROOT/'tools').glob('*/src'))]
import check_release as evidence
from block_application import encode
from commit_verifier import load_json
from local_devnet import initialize,LocalNetwork,read_private,private_new,verify_engine,PIN_SHA,rpc,wait
from alpha_acceptance import _birth,_files,stop_with_facts,role_budget_observation
from invoice_book import initialize_invoice_storage,open_invoice_storage
from private_payment_desk import AlphaPrivatePaymentDesk
from merchant_alpha_ops import AlphaMerchantOps
from merchant_alpha import verify_proof,MAX_PROOF_BYTES
from merchant_http import server
from merchant_ops import SESSION_FORMAT
from alpha_merchant_comet import financial_pin
from native_core import DOMAIN,canonical
from p4_evidence import need
from p4_read_store import private_path
PASSWORD=b'fixture passphrase not for funds'
ROLES=('owner','raven','atlas')
EXPECTED=('four_actual_owned_validators','original_committed_invoice_catalog')+tuple(r+'_operator_enrollment_exact' for r in ROLES)+(
    'lost_return_retained_once',)+tuple(r+'_pending_resource_and_proof_audited' for r in ROLES)+(
    'three_payments_exact_accounting','three_original_signatures_and_submissions','cold_listeners_same_home_no_financial_change',)+tuple(r+'_cold_resource_and_proof_audited' for r in ROLES)+(
    'four_matching_app_hashes','original_invoice_ciphertext_and_identities_preserved','source_engine_unchanged','evidence_has_no_private_material','all_owned_children_and_threads_closed')


def read_line(child,seconds=60):
    with selectors.DefaultSelector() as selector:
        selector.register(child.stdout,selectors.EVENT_READ)
        need(bool(selector.select(seconds)),'wallet listener startup deadline exceeded')
        line=child.stdout.readline();need(bool(line),'wallet listener exited before ready')
        return json.loads(line)


def main():
    os.umask(0o077);engine=verify_engine(Path(sys.argv[1]));out=Path(sys.argv[2]).absolute()
    need(not out.exists() and not out.is_relative_to(ROOT),'new external evidence required');private_path(out);out.mkdir(mode=0o700)
    source=evidence.source_identity(ROOT);private_new(out/'source.json',encode(source))
    runtime=Path.home()/('1sb-'+uuid.uuid4().hex[:12]);runtime.mkdir(mode=0o700)
    workspace=runtime/'net';invoices=runtime/'invoices';downloads=runtime/'downloads';downloads.mkdir(mode=0o700)
    report=dict(schema=1,format='1soft/alpha-resource-browser-acceptance/v1',status='running',
        source={k:source[k] for k in ('commit','tree','source_id','tracked_files')},engine_sha256=PIN_SHA,runtime=str(runtime),
        workspace=str(workspace),checks=[],payments=[],download_audits=[],owned_processes=[],merchant_listeners=[],cleanup_errors=[],expected_checks=list(EXPECTED),
        clock='unscaled host time and monotonic elapsed',required_real_seconds=None,long_horizon_qualified=False,
        real_funds=False,public_network=False,onchain_privacy=False,independent_operators=False,production_qualified=False,
        browser_direct_cross_origin_transport=False,merchant_transport='actual fixed loopback HTTP through guarded same-origin host bridge')
    net=None;web=None;merchant=None;thread=None;log=None;generation=0;rows=[];tokens=[];started=time.monotonic();ops=None
    pins={};enrolled=set();audited=set();cold=False;closed_wallets=[]
    def save():evidence.store_json(out/'progress.json',report,replace=(out/'progress.json').exists())
    def check(name,ok,**facts):
        need(name in EXPECTED and name not in {c['name'] for c in report['checks']},'unknown/duplicate actual check')
        report['checks'].append(dict(name=name,passed=bool(ok),**facts));save();need(ok,'actual browser qualification failed: '+name)
    def reply(q):print(encode(q).decode(),flush=True)
    def command(label,op,args):
        run=subprocess.run([sys.executable,'-B',str(ROOT/'tools/private-payments/scripts/1soft_merchant.py'),op,
            '--workspace',str(workspace),'--engine',str(engine),*map(str,args)],capture_output=True,timeout=120)
        private_new(out/(label+'.stdout.log'),run.stdout);private_new(out/(label+'.stderr.log'),run.stderr)
        need(run.returncode==0,'operator CLI refused: '+label);return load_json(run.stdout)
    def selected(q):
        matches=[r for r in rows if r['request_id']==q['request_id']];need(len(matches)==1,'known original invoice required');return matches[0]
    def finance():
        with net.service() as svc,open_invoice_storage(invoices,config['genesis_sha256']) as inv:
            signed=[dict(rid=r['request_id'],role=r['role']) for r in rows if svc.book.selected(r['request_id'])['decision_id'] is not None]
            return financial_pin(svc,signed,AlphaPrivatePaymentDesk(svc,inv))
    def close_listeners():
        nonlocal web,merchant,thread,log
        if web is not None:
            need(web.poll() is None,'wallet listener exited unexpectedly');web.terminate();web.wait(20)
            remaining=web.stdout.read();private_new(out/('wallet-%d-close.log'%generation),remaining)
            record=next(r for r in report['owned_processes'] if r['pid']==web.pid)
            record.update(returncode=web.returncode,reaped=True,same_birth_still_present=_birth(web.pid)==record['birth'],expected_stop_outcome=web.returncode==0)
            need(web.returncode==0 and b'owned_http_listener_closed' in remaining,'wallet graceful closure failed');closed_wallets.append(web);web=None
        if log is not None:log.close();log=None
        if merchant is not None:
            merchant.shutdown();thread.join(10);merchant.server_close()
            report['merchant_listeners'][-1].update(thread_closed=not thread.is_alive(),socket_closed=merchant.socket.fileno()==-1)
            need(not thread.is_alive() and merchant.socket.fileno()==-1,'owned merchant listener did not close');merchant=None;thread=None
        save()
    def start_listeners():
        nonlocal web,merchant,thread,log
        token=secrets.token_hex(32);tokens.append(token.encode());until=time.monotonic()+75
        while True:
            try:merchant=server(lambda:ops.book(),session_token=token,port=port);break
            except OSError:
                need(time.monotonic()<until,'original pinned merchant port unavailable');time.sleep(.25)
        merchant.configure_quotes(tuple(r['quote_sha256'] for r in rows));thread=threading.Thread(target=merchant.serve_forever,daemon=True);thread.start()
        session=runtime/('merchant-session-%d.json'%generation)
        private_new(session,encode(dict(schema=1,format=SESSION_FORMAT,origin=merchant.origin,quote_ids=[r['quote_sha256'] for r in rows],session_token=token,configured_seconds=300)))
        report['merchant_listeners'].append(dict(generation=generation,origin=merchant.origin,session_preserved=True,thread_closed=False,socket_closed=False))
        log=(out/('wallet-%d.stderr.log'%generation)).open('xb')
        web=subprocess.Popen([sys.executable,'-B',str(ROOT/'tools/private-payments/scripts/serve_private_wallet.py'),
            '--workspace',str(workspace),'--engine',str(engine),'--invoices',str(invoices),'--merchant-session',str(session)],
            stdout=subprocess.PIPE,stderr=log,umask=0o077,env={k:v for k,v in os.environ.items() if k!='PYTHONPATH'})
        report['owned_processes'].append(dict(kind='wallet_listener',pid=web.pid,birth=_birth(web.pid),generation=generation));save()
        ready=read_line(web);private_new(out/('wallet-%d-ready.json'%generation),encode(ready))
        need(ready['status']=='committed_merchant_wallet_running' and ready['merchant_fulfillment_available'] and not ready['network_lifecycle_performed'],'configured wallet listener unavailable')
        return dict(origin=ready['url'].rstrip('/'),generation=generation,invoices=rows,
            download_dir_windows=chr(92)*2+'wsl.localhost'+chr(92)+'Ubuntu'+str(downloads).replace('/',chr(92)),
            scope='short original-home alpha browser/merchant journey; four actual local validators, no renewed trust or real-hour claim')
    try:
        config=initialize(workspace,engine,password=PASSWORD,profile='durable-private-alpha-v1',invoice_commitments=True)
        net=LocalNetwork(workspace,engine).start();net.bootstrap(password=PASSWORD)
        report['owned_processes'].extend(dict(kind=kind,pid=p.pid,birth=_birth(p.pid),generation=0)
            for kind,items in [('application',net.apps),('validator',net.engines)] for p in items)
        check('four_actual_owned_validators',len(net.apps)==len(net.engines)==4 and all(net.height(i)>=1 for i in range(4)))
        initialize_invoice_storage(invoices,config['genesis_sha256'],password=PASSWORD);ops=AlphaMerchantOps(net);command('init','init-book',[])
        genesis=read_private(workspace/'engine-genesis.json');policy_bytes=read_private(workspace/'policy.json');policy=net.policy()
        private_new(out/'engine-genesis.json',genesis);private_new(out/'policy.json',policy_bytes)
        identities=_files(workspace);merchant_identity=(ops.path.stat().st_dev,ops.path.stat().st_ino)
        with socket.socket() as sock:sock.bind(('127.0.0.1',0));port=sock.getsockname()[1]
        origin='http://127.0.0.1:'+str(port)
        with net.service() as svc,open_invoice_storage(invoices,config['genesis_sha256']) as inv:
            desk=AlphaPrivatePaymentDesk(svc,inv)
            for role,amount in zip(ROLES,('7','11','13')):
                resource=('Public alpha browser purchase '+role+'\n').encode();target=out/(role+'-expected-resource.bin');private_new(target,resource)
                q=command(role+'-quote','add-quote',['--recipient-index','0','--origin',origin,'--resource-path','/premium/'+role,
                    '--amount-units',amount,'--resource',target,'--public-resource-confirmation',hashlib.sha256(resource).hexdigest(),'--expires-ns',time.time_ns()+600*10**9])
                qid=q['quote_sha256'];command(role+'-quote-export','export-quote',['--quote-id',qid,'--required-out',out/(role+'-required.txt'),'--expectation-out',out/(role+'-expectation.json')])
                with ops.book(read_only=True) as book:quote=book.selected(qid)
                retained=desk.import_invoice(quote['required_header'],quote['expectation'],dict(description='private fixture invoice',contact='',content='PRIVATE_RESOURCE_BROWSER_SENTINEL'),invoice_password=PASSWORD)
                rows.append(dict(request_id=retained['request_id'],role=role,amount=amount,quote_sha256=qid,resource_sha256=hashlib.sha256(resource).hexdigest()))
            invoice_ciphertext=encode(inv.entries())
        check('original_committed_invoice_catalog',len(rows)==3 and len({r['quote_sha256'] for r in rows})==3)
        reply(dict(ready=start_listeners()))
        for line in sys.stdin:
            need(time.monotonic()-started<900,'finite browser fixture exceeded its declared budget')
            if line.strip()=='stop':break
            q=json.loads(line);need(type(q) is dict,'exact fixture control required');operation=q.get('operation')
            if operation=='operator-enroll':
                need(set(q)=={'operation','request_id'} and not cold,'exact independent enrollment control required');r=selected(q);role=r['role'];rid=r['request_id'];need(role not in enrolled,'original role already enrolled')
                before=finance()
                with net.service() as svc,open_invoice_storage(invoices,config['genesis_sha256']) as inv:
                    desk=AlphaPrivatePaymentDesk(svc,inv);state=svc.state();entry=next(e for e in state['requests'] if e['request_id']==rid)
                    need(entry['delivery']['receipt_status']=='verified_historical_receipt' and len(entry['capsule_ids'])==1 and state['wallet']['pending_debit_units']==str(int(r['amount'])+2),'original positive receipt and unreconciled hold required')
                    cid=entry['capsule_ids'][0];wire=desk.recover(rid);packet=svc.capsule(rid,cid);body=load_json(wire)['body']
                    tx=wait(lambda:rpc(config['ports'][4],'tx',{'hash':base64.b64encode(hashlib.sha256(wire).digest()).decode()}),30)
                    need(tx['tx_result']['code']==0 and base64.b64decode(tx['tx'],validate=True)==wire and body['sender']==config['roles'][role]['payer'] and body['grant_id']==config['roles'][role]['grant_id'],'included original role wire differs')
                    wire_path=out/(role+'-wire.json');packet_path=out/(role+'-capsule.json');private_new(wire_path,wire);private_new(packet_path,packet)
                command(role+'-enroll','enroll-wire',['--quote-id',r['quote_sha256'],'--payer',body['sender'],'--wire',wire_path,
                    '--wire-confirmation',hashlib.sha256(wire).hexdigest(),'--evidence',packet_path])
                after=finance();pins[(role,'pending')]=after
                with ops.book(read_only=True) as book:
                    binding=book.payment_binding(r['quote_sha256']);private_new(out/(role+'-assignment.json'),encode(asdict(book.assignment(r['quote_sha256']))))
                payment=dict(role=role,request_id=rid,quote_sha256=r['quote_sha256'],resource_sha256=r['resource_sha256'],
                    native_txid=hashlib.sha256(DOMAIN+canonical(body)).hexdigest(),wire_sha256=hashlib.sha256(wire).hexdigest(),capsule_sha256=hashlib.sha256(packet).hexdigest(),reference_id=cid,grant_id=body['grant_id'],invoice_commitment=body['op']['invoice_commitment'])
                need(all(binding[k]==payment[k] for k in ('native_txid','wire_sha256','capsule_sha256','reference_id')),'operator enrollment changed original payment');report['payments'].append(payment);enrolled.add(role)
                check(role+'_operator_enrollment_exact',before==after,pending_debit_units=after['pending_debit_units'],financial_pin=after)
                reply(dict(reply='operator-enroll',request_id=rid,passed=True,pending_debit_units=after['pending_debit_units']));continue
            if operation=='inspect-retained':
                need(set(q)=={'operation','request_id'},'exact retained inspection required');r=selected(q);need(r['role']=='owner' and not cold,'lost-return owner inspection required')
                with ops.book(read_only=True) as book:fulfillment=book.selected(r['quote_sha256'])['fulfillment'];binding=book.payment_binding(r['quote_sha256'])
                check('lost_return_retained_once',fulfillment is not None and sum(x['fulfillment'] is not None for x in ops.inspect()['quotes'])==1 and finance()==pins[('owner','pending')],fulfilled_ns=str(binding['fulfilled_ns']))
                reply(dict(reply=operation,request_id=r['request_id'],passed=True,fulfilled_ns=str(binding['fulfilled_ns'])));continue
            if operation=='audit-downloads':
                need(set(q)=={'operation','request_id','phase'} and q['phase'] in ('pending','cold'),'exact download phase required');r=selected(q);role=r['role'];phase=q['phase'];need((phase=='cold')==cold and (role,phase) not in audited,'download phase/uniqueness differs')
                values={}
                for kind,maximum in [('resource',65536),('proof',MAX_PROOF_BYTES)]:
                    path=downloads/(role+'-'+phase+'.'+kind);need(path.is_file() and not path.is_symlink() and path.stat().st_nlink==1 and path.stat().st_uid==os.getuid(),'owned single-link browser download required');path.chmod(0o600);values[kind]=read_private(path,maximum)
                with ops.book(read_only=True) as book:
                    original=book.selected(r['quote_sha256']);binding=book.payment_binding(r['quote_sha256']);assignment=book.assignment(r['quote_sha256']);proof=book.export_proof(r['quote_sha256'])
                    checked=verify_proof(values['proof'],genesis_bytes=genesis,policy=policy,expectation=original['expectation'],assignment=assignment,now_ns=binding['fulfilled_ns'])
                payment=next(p for p in report['payments'] if p['role']==role);public=load_json(proof,max_bytes=MAX_PROOF_BYTES)
                need(values['resource']==read_private(out/(role+'-expected-resource.bin')) and values['proof']==proof and
                    checked['native_txid']==payment['native_txid'] and checked['capsule_sha256']==payment['capsule_sha256'] and
                    checked['resource_sha256']==r['resource_sha256'] and not checked['spending_authority'],'downloaded original resource/proof differs')
                financial=finance();need(financial==pins[(role,'pending')] if phase=='pending' else financial==pins['cold'],'retrieval changed financial rows/hold')
                if phase=='pending':
                    payment.update(fulfilled_ns=str(binding['fulfilled_ns']),proof_sha256=hashlib.sha256(proof).hexdigest(),response_sha256=hashlib.sha256(public['response_header'].encode()).hexdigest())
                else:need(str(binding['fulfilled_ns'])==payment['fulfilled_ns'] and hashlib.sha256(proof).hexdigest()==payment['proof_sha256'],'cold original completion changed')
                for kind,raw in values.items():private_new(out/(role+'-'+phase+'-downloaded.'+kind),raw)
                audit=dict(role=role,phase=phase,request_id=r['request_id'],passed=True,fulfilled_ns=str(binding['fulfilled_ns']),resource_sha256=checked['resource_sha256'],proof_sha256=hashlib.sha256(proof).hexdigest(),pending_debit_units=financial['pending_debit_units'],financial_rows_unchanged=True,native_execution_replayed=True,external_merchant_identity_authenticated=False)
                report['download_audits'].append(audit);audited.add((role,phase));check(role+'_'+phase+'_resource_and_proof_audited',True,audit=audit)
                reply(dict(reply=operation,**audit));continue
            if operation=='restart-listeners':
                need(set(q)=={'operation'} and not cold and all((r,'pending') in audited for r in ROLES),'complete pending journey required before cold reopen')
                pins['cold']=finance();need(pins['cold']['pending_debit_units']=='0','explicit reconciliation required before listener reopen')
                close_listeners();generation=1;cold=True;ready=start_listeners()
                check('cold_listeners_same_home_no_financial_change',finance()==pins['cold'] and _files(workspace)==identities and (ops.path.stat().st_dev,ops.path.stat().st_ino)==merchant_identity and read_private(workspace/'policy.json')==policy_bytes)
                reply(dict(reply=operation,ready=ready,passed=True));continue
            raise ValueError('unsupported fixture control')
        else:raise ValueError('browser must explicitly finish fixture')
        need(enrolled==set(ROLES) and audited=={(r,p) for r in ROLES for p in ('pending','cold')},'actual browser journey incomplete')
        close_listeners()
        with net.service() as svc,open_invoice_storage(invoices,config['genesis_sha256']) as inv:
            state=svc.state();accounts={a['id']:a['recorded_balance'] for a in state['wallet']['accounts']};raven,atlas,budget=role_budget_observation(state['ledger'],config['roles']['owner']['payer'])
            money=dict(payer=accounts[config['roles']['owner']['payer']],merchant=accounts[config['merchant']],fees=accounts['system:fees'],supply=str(sum(map(int,accounts.values()))),budget_spent=budget['spent'],raven_spent=raven['spent'],atlas_spent=atlas['spent'],pending=state['wallet']['pending_debit_units'])
            check('three_payments_exact_accounting',money==dict(payer='957',merchant='31',fees='12',supply='1000',budget_spent='28',raven_spent='13',atlas_spent='15',pending='0'),accounting=money)
            check('three_original_signatures_and_submissions',svc.wallet.db.execute('SELECT count(*) FROM decisions').fetchone()[0]==3 and svc.delivery.db.execute('SELECT count(*) FROM attempts').fetchone()[0]==3)
            check('original_invoice_ciphertext_and_identities_preserved',encode(inv.entries())==invoice_ciphertext and _files(workspace)==identities and read_private(workspace/'engine-genesis.json')==genesis and read_private(workspace/'policy.json')==policy_bytes)
            private_new(out/'final-wallet-state.json',encode(state))
        height=min(net.height(i) for i in range(4));roots=[rpc(p,'commit',{'height':str(height)})['signed_header']['header']['app_hash'] for p in config['ports'][4:]]
        check('four_matching_app_hashes',len(set(roots))==1,height=height,app_hashes=roots)
        check('source_engine_unchanged',evidence.source_identity(ROOT)==source and hashlib.sha256(engine.read_bytes()).hexdigest()==PIN_SHA)
        needles=tokens+[PASSWORD,b'PRIVATE_RESOURCE_BROWSER_SENTINEL'];files=[p for p in out.rglob('*') if p.is_file()]
        check('evidence_has_no_private_material',not any(any(n in p.read_bytes() for n in needles) for p in files),files_scanned=len(files))
        need(stop_with_facts(net,report['owned_processes']),'native closure failed')
        check('all_owned_children_and_threads_closed',all(r.get('reaped') and not r.get('same_birth_still_present') and r.get('expected_stop_outcome') for r in report['owned_processes']) and all(r['thread_closed'] and r['socket_closed'] for r in report['merchant_listeners']))
        need({c['name'] for c in report['checks']}==set(EXPECTED) and all(c['passed'] for c in report['checks']),'exact check membership incomplete');report['status']='passed'
    except BaseException as exc:
        report.update(status='failed',failure_type=type(exc).__name__)
        private_new(out/'failure.log',encode(dict(type=type(exc).__name__,frames=[dict(file=f.filename,line=f.lineno,function=f.name) for f in traceback.extract_tb(exc.__traceback__)])))
    finally:
        try:
            if web is not None or merchant is not None:close_listeners()
        except BaseException:report['cleanup_errors'].append('listener_cleanup_failed')
        if net is not None and not net.stopped:
            try:need(stop_with_facts(net,report['owned_processes']),'native closure failed')
            except BaseException:report['cleanup_errors'].append('native_cleanup_failed')
        if report['cleanup_errors']:report['status']='failed'
        report.update(elapsed_seconds=time.monotonic()-started,original_runtime_preserved=runtime.is_dir(),owned_processes_after_cleanup=sum(_birth(r['pid'])==r['birth'] for r in report['owned_processes']))
        save();private_new(out/'result.json',encode(report))
        reply(dict(status=report['status'],checks=len(report['checks']),payments=len(report['payments']),owned_processes_after_cleanup=report['owned_processes_after_cleanup'],cleanup_errors=report['cleanup_errors'],source_unchanged=report.get('status')=='passed'))
    return 0 if report['status']=='passed' else 1


if __name__=='__main__':raise SystemExit(main())
