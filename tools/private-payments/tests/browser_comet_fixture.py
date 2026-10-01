#!/usr/bin/env python3
"""Owned actual four-validator/browser fixture; DEV only, never user workspaces.

The known password below is public test input for newly generated throwaway keys.
It is never a production credential. No network/compute purchases or installs.
"""
import hashlib,http.client,json,os,selectors,shutil,subprocess,sys,tempfile,time,uuid
from contextlib import ExitStack
from pathlib import Path
sys.dont_write_bytecode=True
ROOT=Path(__file__).resolve().parents[3]
sys.path[:0]=[str(ROOT/'src'),str(ROOT/'scripts')]+[str(p) for p in sorted((ROOT/'tools').glob('*/src'))]
from block_application import encode
from commit_verifier import load_json
from invoice_book import initialize_invoice_storage,open_invoice_storage
from local_devnet import read_private,rpc,wait,verify_engine
from merchant_devnet import initialize,MerchantNetwork
from merchant_ops import MerchantOps
from private_payment_desk import PrivatePaymentDesk
from p4_receipt_capsule import verify_capsule
from native_core import digest
PASSWORD=b'fixture passphrase not for funds'


def inventory():
    result=subprocess.run(['git','ls-files','-z','--cached','--others','--exclude-standard'],cwd=ROOT,capture_output=True,check=True)
    return {name:hashlib.sha256((ROOT/name).read_bytes()).hexdigest() for name in sorted(set(result.stdout.decode().strip('\0').split('\0'))) if name}


def read_line(child,seconds=30):
    with selectors.DefaultSelector() as selector:
        selector.register(child.stdout,selectors.EVENT_READ)
        if not selector.select(seconds):raise RuntimeError('owned listener startup timeout')
        line=child.stdout.readline()
        if not line:raise RuntimeError('owned listener exited before ready')
        return json.loads(line)


def main():
    os.umask(0o077)
    engine=Path(sys.argv[1]);output=Path(sys.argv[2]).absolute()
    assert not output.exists() and not output.is_relative_to(ROOT)
    output.mkdir(mode=0o700);before=inventory();verify_engine(engine)
    report=dict(schema=1,status='running',source_before=before,source_after=None,source_unchanged=False,
        consensus_executed=False,validator_count=0,payments=[],cleanup_errors=[],
        real_funds=False,public_network=False,onchain_privacy=False,independent_operators=False)
    runtime=Path(tempfile.mkdtemp(prefix='one-mbrowser-'));runtime.chmod(0o700)
    net=None;listener=None;children=[];logs=None;failed=False
    try:
        workspace=runtime/'network';invoices=runtime/'invoices'
        initialize(workspace,engine,password=PASSWORD,recipient_count=3,invoice_commitments=True)
        net=MerchantNetwork(workspace,engine);net.start();children.extend(net.apps+net.engines)
        net.bootstrap(password=PASSWORD);assert len(net.apps)==len(net.engines)==4
        report.update(consensus_executed=True,validator_count=4,engine_version='0.38.25',engine_sha256=hashlib.sha256(engine.read_bytes()).hexdigest())
        initialize_invoice_storage(invoices,net.config['genesis_sha256'],password=PASSWORD)
        ops=MerchantOps(net);ops.init_book();rows=[]
        for i,(role,amount) in enumerate(zip(('owner','raven','atlas'),('7','11','13'))):
            resource=('Public browser report '+role+'\n').encode()
            result=ops.add_quote(recipient_index=i,merchant_origin='http://127.0.0.1:18947',
                resource_path='/premium/'+role,amount_units=amount,resource=resource,expires_ns=time.time_ns()+600*10**9)
            with ops.book() as book:quote=book.selected(result['quote_sha256'])
            with net.service() as svc,open_invoice_storage(invoices,net.config['genesis_sha256']) as inv:
                desk=PrivatePaymentDesk(svc,inv)
                retained=desk.import_invoice(quote['required_header'],quote['expectation'],
                    dict(description='private '+uuid.uuid4().hex,contact=uuid.uuid4().hex+'@example.invalid',content='private '+uuid.uuid4().hex),invoice_password=PASSWORD)
            rows.append(dict(request_id=retained['request_id'],role=role,amount=amount,quote_id=result['quote_sha256'],
                resource_sha256=hashlib.sha256(resource).hexdigest(),resource=resource))
        logs=(output/'listener.log').open('xb')
        listener=subprocess.Popen([sys.executable,'-B',str(ROOT/'tools/private-payments/scripts/serve_private_wallet.py'),
            '--workspace',str(workspace),'--engine',str(engine),'--invoices',str(invoices)],stdout=subprocess.PIPE,stderr=logs,umask=0o077)
        children.append(listener);ready=read_line(listener)
        assert ready['status']=='committed_merchant_wallet_running' and ready['network_lifecycle_performed'] is False
        print(json.dumps(dict(schema=1,origin=ready['url'].rstrip('/'),scope='actual CometBFT 0.38.25 four local validators, guarded HTTP, native P4; newly owned DEV keys',
            invoices=[{k:v for k,v in row.items() if k not in ('resource','quote_id')} for row in rows])),flush=True)
        # Node owns the browser. Explicit stop/EOF closes only fixture resources.
        sys.stdin.readline()
        listener.terminate();listener.wait(10)
        closing=listener.stdout.read().decode()
        assert listener.returncode==0 and 'owned_http_listener_closed' in closing
        report['listener_shutdown']=json.loads(closing)
        net.health();report['external_network_survived_listener_shutdown']=True
        genesis=read_private(workspace/'engine-genesis.json');policy=net.policy()
        with net.service() as svc,open_invoice_storage(invoices,net.config['genesis_sha256']) as inv:
            desk=PrivatePaymentDesk(svc,inv);state=svc.state()
            assert state['wallet']['pending_debit_units']=='0'
            for row in rows:
                rid=row['request_id'];entry=svc.book.selected(rid);wire=desk.recover(rid)
                body=json.loads(wire)['body'];fixed_role=net.config['roles'][row['role']]
                assert body['sender']==fixed_role['payer'] and body['grant_id']==fixed_role['grant_id']
                payment=next(r for r in state['requests'] if r['request_id']==rid)
                assert payment['stage']=='recorded' and payment['delivery']['attempt_recorded']
                assert payment['delivery']['receipt_status']=='verified_historical_receipt' and len(payment['capsule_ids'])==1
                capsule=svc.capsule(rid,payment['capsule_ids'][0])
                verified=verify_capsule(capsule,genesis,policy,now_ns=time.time_ns(),expected_payer=net.config['roles'][row['role']]['payer'],expected_wire_sha256=hashlib.sha256(wire).hexdigest())
                assert verified['amount_units']==row['amount']
                with ops.book() as book:
                    book.enroll_wire(row['quote_id'],entry['review']['body']['sender'],wire,evidence=svc.store.export(svc.store.current()['evidence_id']))
                    signature=desk.payment_header(rid,payment['capsule_ids'][0])['payment_signature_header']
                    fulfilled=book.fulfill(row['quote_id'],signature,capsule)
                    assert fulfilled['resource']==row['resource'] and fulfilled['native_execution_reverified']
                for name,raw in ((row['role']+'-wire.json',wire),(row['role']+'-capsule.json',capsule)):
                    (output/name).write_bytes(raw)
                record=dict(role=row['role'],request_id=rid,amount=row['amount'],resource_sha256=row['resource_sha256'],
                    wire_sha256=hashlib.sha256(wire).hexdigest(),capsule_sha256=hashlib.sha256(capsule).hexdigest(),
                    invoice_commitment=body['op']['invoice_commitment'],sender=body['sender'],grant_id=body['grant_id'],execution_replayed=True,merchant_fulfillment_reverified=True)
                report['payments'].append(record)
            treasury=next(a for a in state['wallet']['accounts'] if a['id']==net.config['roles']['owner']['payer'])
            assert treasury['recorded_balance']=='957'
            report['recorded_treasury']='957';report['pending_debit_units']='0'
        # Cold-start the real CLI after a trusted-clock jump beyond the original deadline.
        # Test wrapper injects the clock; it neither rewrites policy nor exposes a product override.
        policy_before=read_private(workspace/'policy.json')
        listener=subprocess.Popen([sys.executable,'-B',str(ROOT/'tools/private-payments/tests/historical_browser_fixture.py'),
            str(time.time_ns()+7200*10**9),'--workspace',str(workspace),'--engine',str(engine),'--invoices',str(invoices)],
            stdout=subprocess.PIPE,stderr=logs,umask=0o077)
        children.append(listener);historical=read_line(listener)
        from urllib.parse import urlsplit
        port=urlsplit(historical['url']).port
        def get(path):
            conn=http.client.HTTPConnection('127.0.0.1',port,timeout=10)
            conn.request('GET',path);response=conn.getresponse();value=(response.status,response.read());conn.close();return value
        code,raw=get('/api/state');assert code==200
        state=json.loads(raw);assert state['current_evidence_available'] is False and state['wallet'] is None
        for row in rows:
            code,raw=get('/api/original/'+row['request_id']);assert code==200
            assert hashlib.sha256(raw).hexdigest()==next(p['wire_sha256'] for p in report['payments'] if p['role']==row['role'])
        listener.terminate();listener.wait(10);closing=listener.stdout.read().decode()
        assert listener.returncode==0 and 'owned_http_listener_closed' in closing
        assert read_private(workspace/'policy.json')==policy_before
        report.update(cold_historical_cli_startup_passed=True,historical_export_without_unlock=True,
            original_trust_policy_unchanged=True,historical_clock_scope='test-only injected trusted clock beyond original expiry')
        net.health()
        # Inspect all four actual nodes at a shared block and require identical app hashes.
        tip=min(int(rpc(port,'status')['sync_info']['latest_block_height']) for port in net.config['ports'][4:])
        hashes=[rpc(port,'commit',{'height':str(tip)})['signed_header']['header']['app_hash'] for port in net.config['ports'][4:]]
        assert len(set(hashes))==1
        report.update(all_four_validator_app_hashes_match=True,shared_committed_height=tip)
        (output/'engine-genesis.json').write_bytes(genesis);(output/'policy.json').write_bytes(encode(policy))
        report['status']='passed'
    except BaseException as exc:
        failed=True;report.update(status='failed',error_type=type(exc).__name__)
        import traceback
        (output/'failure.log').write_text(traceback.format_exc())
    finally:
        if listener is not None and listener.poll() is None:
            try:listener.terminate();listener.wait(10)
            except BaseException:report['cleanup_errors'].append('listener_cleanup_failed')
        if net is not None:
            try:
                shutdown=net.stop();report['native_shutdown']=shutdown
                if shutdown['warnings']:report['cleanup_errors'].append('native_shutdown_warning')
            except BaseException:report['cleanup_errors'].append('native_cleanup_failed')
        for child in reversed(children):
            if child.poll() is None:
                try:child.terminate();child.wait(5)
                except BaseException:
                    report['cleanup_errors'].append('owned_child_required_kill')
                    try:child.kill();child.wait(5)
                    except BaseException:report['cleanup_errors'].append('owned_child_cleanup_failed')
        if net is not None:
            for name in [f'{kind}{i}.log' for kind in ('app','engine') for i in range(4)]:
                try:
                    p=net.root/name
                    if p.is_file():
                        raw=read_private(p,5*1024*1024).replace(PASSWORD,b'[PUBLIC_FIXTURE_PASSWORD]')
                        (output/name).write_bytes(raw)
                except BaseException:report['cleanup_errors'].append('owned_log_retention_failed')
        if logs is not None:
            try:logs.close()
            except BaseException:report['cleanup_errors'].append('listener_log_close_failed')
        report['owned_processes_after_cleanup']=sum(p.poll() is None for p in children)
        report['source_after']=inventory();report['source_unchanged']=before==report['source_after']
        if report['cleanup_errors'] or report['owned_processes_after_cleanup'] or not report['source_unchanged']:report['status']='failed'
        if not failed and report['status']=='passed':
            assert runtime.parent==Path(tempfile.gettempdir()).resolve() and runtime.name.startswith('one-mbrowser-') and not runtime.is_symlink()
            shutil.rmtree(runtime);report['owned_runtime_removed']=True
        else:report['retained_private_runtime']=str(runtime)
        (output/'actual-validator-result.json').write_text(json.dumps(report,indent=2)+'\n')
        print(json.dumps(dict(schema=1,status=report['status'],payments=len(report['payments']),owned_processes_after_cleanup=report['owned_processes_after_cleanup'],source_unchanged=report['source_unchanged'])),flush=True)
    return 0 if report['status']=='passed' else 1
if __name__=='__main__':raise SystemExit(main())
