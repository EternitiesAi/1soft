#!/usr/bin/env python3
"""One real hour, original alpha homes, then actual browser invoice payments.

Known fixture password applies only to newly generated local DEV keys. No
scaled clocks, trust renewal, merchant fulfillment, installs or public network.
"""
import hashlib,json,os,selectors,subprocess,sys,time,traceback,uuid
from pathlib import Path
sys.dont_write_bytecode=True
ROOT=Path(__file__).resolve().parents[3]
sys.path[:0]=[str(ROOT/'src'),str(ROOT/'scripts')]+[str(p) for p in sorted((ROOT/'tools').glob('*/src'))]
sys.path.insert(0,str(ROOT/'tools/release'))
import check_release as evidence
from block_application import encode
from commit_verifier import load_json
from local_devnet import initialize,LocalNetwork,read_private,private_new,verify_engine,PIN_SHA
from alpha_acceptance import _birth,_files,stop_with_facts,role_budget_observation
from invoice_book import initialize_invoice_storage,open_invoice_storage
from payment_x402 import NativePaymentExpectation,make_payment_required
from private_payment_desk import AlphaPrivatePaymentDesk
from p4_alpha_custody import restore_backup,RecoveryArchive,verify_receipt,MAGIC,MAX_BACKUP_BYTES
from p4_evidence import need,content_id,nanos
from p4_read_store import private_path
PASSWORD=b'fixture passphrase not for funds'
DURATION=3660

def read_line(child,seconds=60):
    with selectors.DefaultSelector() as selector:
        selector.register(child.stdout,selectors.EVENT_READ)
        need(bool(selector.select(seconds)),'owned listener startup timeout')
        line=child.stdout.readline();need(bool(line),'owned listener exited before ready')
        return json.loads(line)

def logical_rows(svc):
    return {'wallet':{t:svc.wallet.db.execute('SELECT * FROM '+t+' ORDER BY seq' if t!='config' else 'SELECT * FROM config').fetchall()
                      for t in ('config','observations','decisions')},
            'delivery':{t:svc.delivery.db.execute('SELECT * FROM '+t+' ORDER BY '+('seq' if t in ('attempts','receipts') else 'decision_id')).fetchall()
                        if t!='config' else svc.delivery.db.execute('SELECT * FROM config').fetchall()
                        for t in ('config','attempts','responses','receipts')}}

def main():
    os.umask(0o077);binary=verify_engine(Path(sys.argv[1]));output=Path(sys.argv[2]).absolute()
    need(not output.exists() and not output.is_relative_to(ROOT),'new external evidence required')
    private_path(output);output.mkdir(mode=0o700)
    source=evidence.source_identity(ROOT);private_new(output/'source.json',encode(source))
    runtime=Path.home()/('1si-'+uuid.uuid4().hex[:12]);runtime.mkdir(mode=0o700)
    workspace=runtime/'net';invoices=runtime/'invoices';downloads=runtime/'downloads';downloads.mkdir(mode=0o700)
    report=dict(schema=1,format='1soft/durable-invoice-browser-acceptance/v1',status='running',
        source={k:source[k] for k in ('commit','tree','source_id','tracked_files')},engine_sha256=PIN_SHA,
        runtime=str(runtime),workspace=str(workspace),checks=[],phases=[],payments=[],backup_audits=[],owned_processes=[],
        real_funds=False,public_network=False,onchain_privacy=False,merchant_fulfillment_performed=False,
        production_qualified=False,clock='unscaled time.time_ns and monotonic elapsed',required_real_seconds=DURATION)
    net=None;listener=None;logs=None;started=time.monotonic();start_ns=time.time_ns();generation=0
    def save():evidence.store_json(output/'progress.json',report,replace=(output/'progress.json').exists())
    def check(name,condition,**details):
        need(name not in [c['name'] for c in report['checks']],'duplicate check')
        report['checks'].append(dict(name=name,passed=bool(condition),**details));save();need(condition,'actual invoice acceptance check failed')
    def own(network):
        report['owned_processes'].extend(dict(kind=kind,pid=p.pid,birth=_birth(p.pid),generation=generation)
            for kind,items in [('application',network.apps),('validator',network.engines)] for p in items);save()
    def stop(network):need(stop_with_facts(network,report['owned_processes']),'owned process closure failed');save()
    def phase(svc,label):
        cp=svc.store.current()['checkpoint'];state=svc.state()
        row=dict(index=len(report['phases'])+1,label=label,elapsed_seconds=time.monotonic()-started,
            observed_ns=time.time_ns(),checkpoint=cp,node_heights=[net.height(i) for i in range(4)],
            pending_debit_units=state['wallet']['pending_debit_units'],wallet_revision=state['wallet']['revision'])
        report['phases'].append(row);private_new(output/('phase-%04d.json'%row['index']),encode(row));save()
        print(encode(dict(phase=label,height=cp['height'],elapsed_seconds=round(row['elapsed_seconds'],3))).decode(),flush=True)
    try:
        config=initialize(workspace,binary,password=PASSWORD,profile='durable-private-alpha-v1',invoice_commitments=True)
        net=LocalNetwork(workspace,binary).start();own(net);net.bootstrap(password=PASSWORD)
        genesis=read_private(workspace/'engine-genesis.json');policy_bytes=read_private(workspace/'policy.json');policy=net.policy()
        private_new(output/'engine-genesis.json',genesis);private_new(output/'policy.json',policy_bytes)
        file_ids=_files(workspace);identities=None;rows=[]
        check('fresh_explicit_combined_capability',config['format']=='1soft/local-alpha-invoice-workspace/v1' and
            load_json(read_private(workspace/'app-genesis.json'))['invoice_commitment_version']==1)
        check('four_actual_owned_validators',len(net.apps)==len(net.engines)==4 and all(net.height(i)>=1 for i in range(4)))
        initialize_invoice_storage(invoices,config['genesis_sha256'],password=PASSWORD)
        with net.service() as svc,open_invoice_storage(invoices,config['genesis_sha256']) as inv:
            identities=dict(wallet=svc.wallet._catalog()[0],delivery=svc.delivery.config[2],store=svc.store.store_id)
            for i,(role,amount) in enumerate(zip(('owner','raven','atlas'),('7','11','13'))):
                resource=('Public durable invoice report '+role+'\n').encode();resource_hash=hashlib.sha256(resource).hexdigest()
                expected=NativePaymentExpectation('https://merchant.example','https://merchant.example/premium/'+role,
                    '1soft:local-dev','1soft:DEV',config['genesis_sha256'],config['merchant'],amount)
                now=time.time_ns();header=make_payment_required(expected,created_ns=now,expires_ns=now+7200*10**9,
                    quote_nonce=hashlib.sha256((str(runtime)+role).encode()).hexdigest(),resource_sha256=resource_hash)
                retained=AlphaPrivatePaymentDesk(svc,inv).import_invoice(header,expected,
                    dict(description='private fixture invoice '+role,contact='private@example.invalid',content='PRIVATE_ALPHA_INVOICE_SENTINEL'),invoice_password=PASSWORD)
                rows.append(dict(request_id=retained['request_id'],role=role,amount=amount,resource_sha256=resource_hash,
                    envelope_sha256=retained['envelope_sha256']))
            invoice_before=encode(inv.entries());request_before=encode(svc.book.entries());phase(svc,'original-invoices-bootstrap')
        report.update(original_identities=identities,original_file_identities=file_ids,genesis_sha256=config['genesis_sha256'],policy_id=content_id(policy),original_invoices=rows)
        save();restarted=False
        while time.monotonic()-started<DURATION or net.height()<=512:
            net.health()
            with net.service() as svc:
                cp=svc.store.current()['checkpoint']
                if net.height()>=cp['height']+16:
                    svc.refresh(expected_tip=cp['id']);svc.sync(expected_revision=svc.state()['wallet']['revision'])
                    phase(svc,'continuous-original-history')
            if not restarted and net.height()>512:
                with net.service() as svc:logical_before=logical_rows(svc)
                stop(net);generation+=1;net=LocalNetwork(workspace,binary).start();own(net)
                check('same_home_restart_without_rebootstrap',net.ready() and net.bootstrap(password=PASSWORD)['status']=='original_workspace_retained')
                with net.service() as svc,open_invoice_storage(invoices,config['genesis_sha256']) as inv:
                    check('restart_preserves_original_files_journals_and_ciphertext',_files(workspace)==file_ids and logical_rows(svc)==logical_before
                        and encode(inv.entries())==invoice_before and encode(svc.book.entries())==request_before
                        and read_private(workspace/'engine-genesis.json')==genesis and read_private(workspace/'policy.json')==policy_bytes)
                    phase(svc,'same-home-restart-after512')
                restarted=True
            need(time.monotonic()-started<DURATION+600,'finite actual-hour gate timed out');time.sleep(4)
        with net.service() as svc:
            cp=svc.store.current()['checkpoint'];svc.refresh(expected_tip=cp['id']);svc.sync(expected_revision=svc.state()['wallet']['revision'])
            phase(svc,'actual-original-hour-crossed')
            check('actual_original_hour_and_height_crossed',time.monotonic()-started>=DURATION and svc.store.current()['checkpoint']['height']>512
                and time.time_ns()>nanos(policy['anchor_time'])+3600*10**9,elapsed_seconds=time.monotonic()-started,start_ns=start_ns,end_ns=time.time_ns())
            check('original_policy_and_journal_identities_preserved',read_private(workspace/'policy.json')==policy_bytes and
                dict(wallet=svc.wallet._catalog()[0],delivery=svc.delivery.config[2],store=svc.store.store_id)==identities)
        logs=(output/'listener.stderr.log').open('xb')
        listener=subprocess.Popen([sys.executable,'-B',str(ROOT/'tools/private-payments/scripts/serve_private_wallet.py'),
            '--workspace',str(workspace),'--engine',str(binary),'--invoices',str(invoices)],stdout=subprocess.PIPE,stderr=logs,
            umask=0o077,env={k:v for k,v in os.environ.items() if k!='PYTHONPATH'})
        report['owned_processes'].append(dict(kind='invoice_listener',pid=listener.pid,birth=_birth(listener.pid),generation=0));save()
        ready=read_line(listener);need(ready['status']=='committed_merchant_wallet_running' and not ready['network_lifecycle_performed'],'actual listener unavailable')
        print(json.dumps(dict(schema=1,origin=ready['url'].rstrip('/'),scope='one original real-hour alpha, actual four local validators, payer-side invoices only',
            download_dir_linux=str(downloads),download_dir_windows=chr(92)*2+'wsl.localhost'+chr(92)+'Ubuntu'+str(downloads).replace('/',chr(92)),invoices=rows)),flush=True)
        for line in sys.stdin:
            if line.strip()=='stop':break
            q=json.loads(line);need(type(q) is dict and set(q)=={'operation','filename','stage'} and q['operation']=='audit-backup','unsupported fixture control')
            need(q['stage'] in ('signed-pending','receipt-complete') and q['filename']==q['stage']+'.backup','exact backup selection required')
            path=downloads/q['filename'];need(path.is_file() and not path.is_symlink() and path.stat().st_nlink==1 and path.stat().st_uid==os.getuid(),'owned single-link browser download required');path.chmod(0o600)
            raw=read_private(path,MAX_BACKUP_BYTES);need(raw.startswith(MAGIC),'download is not alpha A1')
            with net.service() as svc:
                before=logical_rows(svc);state=svc.state();restore=runtime/(q['stage']+'.inert')
                restore_backup(path,restore,genesis,policy,PASSWORD)
                with RecoveryArchive(restore,genesis,policy) as archive:
                    inert=archive.inspect();selected=[e for e in svc.book.entries() if e['decision_id'] is not None]
                    originals=[]
                    for e in selected:
                        body=e['review']['body'];wire=svc.recover(e['request_id'])
                        need(archive.recover(e['decision_id'],payer=body['sender'],grant_id=body['grant_id'])==wire,'inert original differs')
                        originals.append(dict(request_id=e['request_id'],decision_id=e['decision_id'],wire_sha256=hashlib.sha256(wire).hexdigest()))
                    need(inert['pending_debit_units']==state['wallet']['pending_debit_units'] and not inert['signing_enabled'] and not inert['dispatch_enabled'],'inert scope differs')
                    restored_snapshot=load_json(archive._snapshot,max_bytes=128*1024*1024)
                    expected_financial=logical_rows(svc)
                    from p4_alpha_custody import _cell
                    for group in ('wallet','delivery'):
                        for table,cells in expected_financial[group].items():
                            need(restored_snapshot[group][table]==[[_cell(c) for c in row] for row in cells],'restored original rows differ')
                    need(logical_rows(svc)==before,'backup changed financial records')
                    audit=dict(passed=True,stage=q['stage'],backup_format_version=1,all_seven_tables_exact=True,
                        source_logical_rows_unchanged=True,spending_authority=False,keys_unlocked=False,
                        signing_or_submission_performed=False,pending_debit_units=inert['pending_debit_units'],
                        recovered_originals=originals,retained_delivery_receipts=len([d for d in inert['decisions'] if d['delivery_receipt_status']=='verified_historical_receipt']),
                        invoice_book_recovered=False,invoice_data_vault_recovered=False,backup_sha256=hashlib.sha256(raw).hexdigest())
                    report['backup_audits'].append(audit);save();print(json.dumps({'backup_audit':audit}),flush=True)
        else:raise ValueError('browser must explicitly finish fixture')
        need([a['stage'] for a in report['backup_audits']]==['signed-pending','receipt-complete'],'actual backup stages incomplete')
        listener.terminate();listener.wait(15);closing=listener.stdout.read().decode();need(listener.returncode==0 and 'owned_http_listener_closed' in closing,'listener closure failed')
        listener_row=report['owned_processes'][-1];listener_row.update(returncode=listener.returncode,reaped=True,same_birth_still_present=_birth(listener.pid)==listener_row['birth'],expected_stop_outcome=True)
        net.health();check('listener_closes_without_stopping_network',all(p.poll() is None for p in net.apps+net.engines))
        with net.service() as svc,open_invoice_storage(invoices,config['genesis_sha256']) as inv:
            desk=AlphaPrivatePaymentDesk(svc,inv);state=svc.state()
            for row in rows:
                rid=row['request_id'];entry=svc.book.selected(rid);wire=desk.recover(rid);payment=next(e for e in state['requests'] if e['request_id']==rid)
                need(payment['stage']=='recorded' and len(payment['capsule_ids'])==1,'original payment is not reconciled')
                body=load_json(wire)['body'];capsule=svc.capsule(rid,payment['capsule_ids'][0]);checked=verify_receipt(capsule,genesis,policy,payer=body['sender'],wire_sha256=hashlib.sha256(wire).hexdigest())
                need(body['grant_id']==config['roles'][row['role']]['grant_id'] and body['op']['units']==int(row['amount']) and
                     checked['status']=='verified-historical-alpha-receipt' and not checked['current_spending_authority'] and
                     entry['review']['state_height']>512 and entry['review']['invoice_terms']['resource_sha256']==row['resource_sha256'],'actual invoice binding differs')
                need(svc.delivery.db.execute('SELECT count(*) FROM attempts WHERE decision_id=?',(entry['decision_id'],)).fetchone()[0]==1,'original attempt membership differs')
                for name,data in [(row['role']+'-wire.json',wire),(row['role']+'-capsule.json',capsule)]:private_new(output/name,data)
                record=dict(role=row['role'],request_id=rid,decision_id=entry['decision_id'],amount=row['amount'],fee='2',
                    signed_state_height=entry['review']['state_height'],wire_sha256=hashlib.sha256(wire).hexdigest(),
                    capsule_sha256=hashlib.sha256(capsule).hexdigest(),invoice_commitment=body['op']['invoice_commitment'],resource_sha256=row['resource_sha256'],native_execution_reverified=True,merchant_fulfillment_performed=False)
                report['payments'].append(record)
            raven,atlas,budget=role_budget_observation(state['ledger'],config['roles']['owner']['payer'])
            accounts={a['id']:a['recorded_balance'] for a in state['wallet']['accounts']}
            check('three_actual_committed_invoice_payments_after_original_hour',len(report['payments'])==3 and all(p['signed_state_height']>512 for p in report['payments']))
            check('exact_nonce_fee_budget_and_supply_accounting',accounts[config['roles']['owner']['payer']]=='957' and accounts[config['merchant']]=='31' and accounts['system:fees']=='12'
                and raven['nonce']==atlas['nonce']=='1' and raven['spent']=='13' and atlas['spent']=='15' and budget['spent']=='28'
                and state['wallet']['pending_debit_units']=='0' and sum(map(int,accounts.values()))==1000,
                recorded_treasury=accounts[config['roles']['owner']['payer']],budget_spent=budget['spent'],pending_debit_units='0')
            check('three_original_attempts_without_resend',svc.delivery.db.execute('SELECT count(*) FROM attempts').fetchone()[0]==3)
            check('original_encrypted_invoice_book_retained',encode(inv.entries())==invoice_before)
            private_new(output/'final-wallet-state.json',encode(state));phase(svc,'three-original-invoices-complete')
        check('exact_source_and_engine_unchanged',evidence.source_identity(ROOT)==source and verify_engine(binary)==binary)
        stop(net);check('all_owned_native_and_listener_processes_reaped',all(p.get('reaped') and p.get('same_birth_still_present') is False and p.get('expected_stop_outcome') for p in report['owned_processes']))
        check('original_private_runtime_preserved',_files(workspace)==file_ids and read_private(workspace/'policy.json')==policy_bytes)
        report.update(status='passed',source_unchanged=True,elapsed_seconds=time.monotonic()-started,completed_ns=time.time_ns())
    except BaseException as exc:
        report.update(status='failed',failure_type=type(exc).__name__,elapsed_seconds=time.monotonic()-started)
        print(json.dumps(dict(failure_type=type(exc).__name__,frames=[dict(file=f.filename,line=f.lineno,function=f.name) for f in traceback.extract_tb(exc.__traceback__)])),file=sys.stderr,flush=True)
    finally:
        if listener is not None and listener.poll() is None:
            listener.terminate()
            try:listener.wait(15)
            except subprocess.TimeoutExpired:listener.kill();listener.wait(10);report['status']='failed'
        if net is not None and not net.stopped:
            try:stop(net)
            except BaseException:report.update(status='failed',cleanup_failed=True)
        if logs is not None:logs.close()
        save();private_new(output/'result.json',encode(report))
    print(json.dumps(dict(status=report['status'],payments=len(report['payments']),owned_processes_after_cleanup=sum(
        _birth(p['pid'])==p['birth'] for p in report['owned_processes']),source_unchanged=report.get('source_unchanged',False))),flush=True)
    return 0 if report['status']=='passed' else 1

if __name__=='__main__':raise SystemExit(main())
