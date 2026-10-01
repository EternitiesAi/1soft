#!/usr/bin/env python3
"""Owned four-validator payment/export gate and cold standalone offline replay.

New throwaway DEV keys only. No installs or public/paid services. Public proof
artifacts are retained, never wallet/vault/database/private-invoice bytes.
"""
import base64
import copy
from dataclasses import asdict, replace
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import time
import traceback

sys.dont_write_bytecode=True
ROOT=Path(__file__).resolve().parents[3]
sys.path[:0]=[str(ROOT/'src'),str(ROOT/'scripts'),str(Path(__file__).parent)]+[str(p) for p in sorted((ROOT/'tools').glob('*/src'))]
from block_application import encode
from browser_comet_fixture import inventory
from invoice_book import initialize_invoice_storage,open_invoice_storage
from invoice_terms import terms_commitment
from local_devnet import private_new,read_private,rpc,wait,verify_engine
from merchant_devnet import initialize,MerchantNetwork
from merchant_ops import MerchantOps
from merchant_proof import verify_merchant_proof
from native_core import canonical
from payment_x402 import TrustedMerchantAssignment,make_payment_required,parse_payment_required
from private_payment_desk import PrivatePaymentDesk
PASSWORD=b'public disposable fixture passphrase'


def main():
    os.umask(0o077)
    engine=Path(sys.argv[1]);output=Path(sys.argv[2]).absolute()
    assert not output.exists() and not output.is_relative_to(ROOT)
    output.mkdir(mode=0o700);before=inventory();verify_engine(engine)
    runtime=Path(tempfile.mkdtemp(prefix='one-mproof-'));runtime.chmod(0o700)
    net=None;children=[];rows=[]
    report=dict(schema=1,status='running',source_before=before,payments=[],cleanup_errors=[],
        consensus_executed=False,real_funds=False,public_network=False,onchain_privacy=False,
        independent_operators=False,offline_checks_after_runtime_removal=False)
    try:
        workspace=runtime/'network';invoices=runtime/'invoices'
        initialize(workspace,engine,password=PASSWORD,recipient_count=3,invoice_commitments=True)
        net=MerchantNetwork(workspace,engine);net.start();children.extend(net.apps+net.engines)
        net.bootstrap(password=PASSWORD);assert len(net.apps)==len(net.engines)==4
        genesis=read_private(workspace/'engine-genesis.json');policy=net.policy()
        report.update(consensus_executed=True,validator_count=4,engine_sha256=hashlib.sha256(engine.read_bytes()).hexdigest(),engine_version='0.38.25')
        initialize_invoice_storage(invoices,net.config['genesis_sha256'],password=PASSWORD)
        ops=MerchantOps(net);ops.init_book()
        private_new(output/'engine-genesis.json',genesis);private_new(output/'policy.json',encode(policy))
        with net.service() as svc,open_invoice_storage(invoices,net.config['genesis_sha256']) as inv:
            desk=PrivatePaymentDesk(svc,inv)
            for i,(role,amount) in enumerate(zip(('owner','raven','atlas'),('7','11','13'))):
                resource=('Public portable report '+role+'\n').encode()
                retained=ops.add_quote(recipient_index=i,merchant_origin='http://127.0.0.1:18947',
                    resource_path='/premium/'+role,amount_units=amount,resource=resource,expires_ns=time.time_ns()+600*10**9)
                qid=retained['quote_sha256']
                with ops.book(read_only=True) as book:quote=book.selected(qid)
                rid=desk.import_invoice(quote['required_header'],quote['expectation'],
                    dict(description='private fixture brief',contact='private@example.invalid',content='PRIVATE_CONTENT_SENTINEL'),
                    invoice_password=PASSWORD)['request_id']
                prepared=desk.prepare(rid,role,valid_until=svc.state()['wallet']['state_height']+64)
                desk.approve(rid,role,prepared['review'],prepared['confirmation'],prepared['terms_confirmation'],payment_password=PASSWORD)
                wire=desk.recover(rid);body=json.loads(wire)['body'];chosen=net.config['roles'][role]
                assert body['sender']==chosen['payer'] and body['grant_id']==chosen['grant_id']
                ops.enroll_wire(qid,payer=chosen['payer'],wire=wire,evidence=svc.store.export(svc.store.current()['evidence_id']))
                submit=desk.submission_review(rid);sent=desk.submit(rid,submit['review'],submit['confirmation'])
                assert sent['submission_attempt_recorded'] is True
                tx=wait(lambda:rpc(net.config['ports'][4],'tx',{'hash':base64.b64encode(hashlib.sha256(wire).digest()).decode()}),30)
                assert tx['tx_result']['code']==0 and base64.b64decode(tx['tx'],validate=True)==wire
                assert desk.collect(rid)['status']=='receipt_collected'
                cid=desk.retain_receipt(rid)['capsule_id'];capsule=svc.capsule(rid,cid)
                signature=desk.payment_header(rid,cid)['payment_signature_header']
                with ops.book() as book:fulfilled=book.fulfill(qid,signature,capsule)
                assert fulfilled['resource']==resource
                # Actual operator CLI, with exclusive output and no signing/submission.
                target=output/(role+'-proof.json');book_before=ops.inspect();decisions=svc.wallet.db.total_changes
                policy_before=read_private(workspace/'policy.json')
                command=[sys.executable,'-B',str(ROOT/'tools/private-payments/scripts/1soft_merchant.py'),
                    'export-proof','--workspace',str(workspace),'--engine',str(engine),'--quote-id',qid,'--proof-out',str(target)]
                run=subprocess.run(command,capture_output=True,timeout=30)
                private_new(output/(role+'-export.stdout.log'),run.stdout);private_new(output/(role+'-export.stderr.log'),run.stderr)
                assert run.returncode==0
                raw=read_private(target);value=json.loads(raw)
                assert base64.b64decode(value['wire_b64'])==wire and base64.b64decode(value['capsule_b64'])==capsule
                assert base64.b64decode(value['resource_b64'])==resource
                assert base64.b64decode(value['invoice_terms_b64'])==canonical(prepared['review']['invoice_terms'])
                assert value['required_header']==quote['required_header'] and value['signature_header']==signature
                assert ops.inspect()==book_before and svc.wallet.db.total_changes==decisions
                assert read_private(workspace/'policy.json')==policy_before
                collision=subprocess.run(command,capture_output=True,timeout=10)
                assert collision.returncode!=0 and collision.stdout==b'' and read_private(target)==raw
                assignment=TrustedMerchantAssignment(qid,rid,quote['expectation'].recipient,chosen['payer'],hashlib.sha256(wire).hexdigest())
                as_of=time.time_ns()
                verified=verify_merchant_proof(raw,genesis_bytes=genesis,policy=policy,expectation=quote['expectation'],assignment=assignment,now_ns=as_of)
                assert verified['amount_units']==amount and verified['fee_units']=='2'
                assert verified['native_signature_authenticates_resource'] and verified['resource_bytes_match_commitment']
                for name,material in (('wire',wire),('capsule',capsule),('required',quote['required_header'].encode()),
                                      ('terms',canonical(prepared['review']['invoice_terms'])),('resource',resource),
                                      ('expectation',encode(asdict(quote['expectation']))),('assignment',encode(asdict(assignment)))):
                    private_new(output/(role+'-'+name+'.json'),material)
                rows.append(dict(role=role,as_of=as_of,expected=quote['expectation'],assignment=assignment))
                report['payments'].append(dict(role=role,as_of_ns=as_of,proof_sha256=hashlib.sha256(raw).hexdigest(),
                    quote_sha256=qid,request_id=rid,wire_sha256=hashlib.sha256(wire).hexdigest(),capsule_sha256=hashlib.sha256(capsule).hexdigest(),
                    resource_sha256=hashlib.sha256(resource).hexdigest(),invoice_commitment=body['op']['invoice_commitment'],
                    native_txid=verified['native_txid'],amount_units=amount,fee_units='2',grant_id=body['grant_id'],
                    exporter_journals_unchanged=True,output_collision_preserved=True))
            assert svc.wallet.db.execute('SELECT count(*) FROM decisions').fetchone()[0]==3
            assert svc.delivery.db.execute('SELECT count(*) FROM attempts').fetchone()[0]==3
            svc.sync(expected_revision=svc.state()['wallet']['revision'])
            state=svc.state();assert state['wallet']['pending_debit_units']=='0'
            treasury=next(a for a in state['wallet']['accounts'] if a['id']==net.config['roles']['owner']['payer'])
            assert treasury['recorded_balance']=='957'
            report.update(recorded_treasury='957',pending_debit_units='0',original_decisions=3,original_submission_attempts=3)
        height=min(int(rpc(port,'status')['sync_info']['latest_block_height']) for port in net.config['ports'][4:])
        hashes=[rpc(port,'commit',{'height':str(height)})['signed_header']['header']['app_hash'] for port in net.config['ports'][4:]]
        assert len(set(hashes))==1;report.update(all_four_validator_app_hashes_match=True,shared_committed_height=height)
        report['status']='native-passed'
    except BaseException as exc:
        report.update(status='failed',error_type=type(exc).__name__);private_new(output/'failure.log',traceback.format_exc().encode())
    finally:
        if net is not None:
            try:
                stop=net.stop();report['native_shutdown']=stop
                if stop['warnings']:report['cleanup_errors'].append('native_shutdown_warning')
            except BaseException:report['cleanup_errors'].append('native_shutdown_failed')
        for child in reversed(children):
            if child.poll() is None:
                try:child.terminate();child.wait(5)
                except BaseException:
                    report['cleanup_errors'].append('owned_child_required_kill');child.kill();child.wait(5)
        if net is not None:
            for name in [f'{kind}{i}.log' for kind in ('app','engine') for i in range(4)]:
                try:
                    path=net.root/name
                    if path.is_file():private_new(output/name,read_private(path,5*1024*1024).replace(PASSWORD,b'[PUBLIC_FIXTURE_PASSWORD]'))
                except BaseException:report['cleanup_errors'].append('owned_log_retention_failed')
        report['owned_processes_after_cleanup']=sum(child.poll() is None for child in children)
        if report['cleanup_errors'] or report['owned_processes_after_cleanup']:report['status']='failed'
        if report['status']=='native-passed':
            assert runtime.parent==Path(tempfile.gettempdir()).resolve() and runtime.name.startswith('one-mproof-') and not runtime.is_symlink()
            shutil.rmtree(runtime);report['owned_runtime_removed']=not runtime.exists()
        else:report['retained_private_runtime']=str(runtime)
    if report['status']=='native-passed':
        try:
            # Cold standalone processes consume only exported public material.
            for row in rows:
                role=row['role'];command=[sys.executable,'-B',str(ROOT/'tools/private-payments/scripts/verify_merchant_proof.py'),
                    '--proof',str(output/(role+'-proof.json')),'--genesis',str(output/'engine-genesis.json'),
                    '--policy',str(output/'policy.json'),'--expectation',str(output/(role+'-expectation.json')),
                    '--assignment',str(output/(role+'-assignment.json')),'--as-of-ns',str(row['as_of'])]
                result=subprocess.run(command,capture_output=True,timeout=30)
                private_new(output/(role+'-offline.stdout.log'),result.stdout);private_new(output/(role+'-offline.stderr.log'),result.stderr)
                assert result.returncode==0 and json.loads(result.stdout)['resource_bytes_match_commitment']
                raw=read_private(output/(role+'-proof.json'));bad=json.loads(raw)
                bad['resource_b64']=base64.b64encode(b'changed resource').decode()
                target=output/(role+'-changed-resource-proof.json');private_new(target,encode(bad))
                negative=command.copy();negative[negative.index('--proof')+1]=str(target)
                result=subprocess.run(negative,capture_output=True,timeout=30)
                assert result.returncode!=0 and result.stdout==b'' and len(result.stderr)<512
                report['payments'][rows.index(row)].update(cold_offline_cli_passed=True,changed_resource_cli_refused=True)
            # Relabel a genuine payment with otherwise coherent new quote + pins.
            row=rows[0];bad=json.loads(read_private(output/'owner-proof.json'));original=json.loads(base64.b64decode(bad['invoice_terms_b64']))
            other=replace(row['expected'],resource_url='http://127.0.0.1:18947/other')
            resource=b'other public resource'
            required=make_payment_required(other,created_ns=original['created_ns'],expires_ns=original['expires_ns'],
                quote_nonce='b'*64,resource_sha256=hashlib.sha256(resource).hexdigest())
            quote=parse_payment_required(required,other,now_ns=row['as_of'])
            signature=json.loads(base64.b64decode(bad['signature_header']));signature.update(resource=quote['offer']['resource'],accepted=quote['offer']['accepts'][0])
            signature['payload'].update(quoteSha256=quote['quote_sha256'],requestId=quote['request_id'])
            bad.update(required_header=required,invoice_terms_b64=base64.b64encode(canonical(quote['invoice_terms'])).decode(),
                resource_b64=base64.b64encode(resource).decode(),signature_header=base64.b64encode(encode(signature)).decode())
            raw=encode(bad);private_new(output/'owner-wrong-terms-proof.json',raw)
            assignment=replace(row['assignment'],quote_sha256=quote['quote_sha256'],request_id=quote['request_id'])
            try:verify_merchant_proof(raw,genesis_bytes=genesis,policy=policy,expectation=other,assignment=assignment,now_ns=row['as_of'])
            except ValueError as exc:assert 'commitment' in str(exc)
            else:raise AssertionError('genuine payment relabeled to another invoice')
            report.update(status='passed',offline_checks_after_runtime_removal=True,coherent_wrong_invoice_commitment_refused=True)
        except BaseException as exc:
            report.update(status='failed',error_type=type(exc).__name__);private_new(output/'offline-failure.log',traceback.format_exc().encode())
    report['source_after']=inventory();report['source_unchanged']=before==report['source_after']
    if not report['source_unchanged']:report['status']='failed'
    private_new(output/'actual-validator-result.json',encode(report))
    print(encode({k:report[k] for k in ('status','owned_processes_after_cleanup','source_unchanged','offline_checks_after_runtime_removal')}).decode(),flush=True)
    return 0 if report['status']=='passed' else 1


if __name__=='__main__':raise SystemExit(main())
