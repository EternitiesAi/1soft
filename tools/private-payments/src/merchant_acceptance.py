"""Three actual native DEV payments over one finite local merchant book.

Runs real command callers, four local validators and independently replayed
public receipts. No public network, real funds or production privacy claim.
"""
import base64
from dataclasses import asdict, replace
from contextlib import ExitStack
import hashlib
import http.client
from pathlib import Path
import secrets
import shutil
import socket
import sys
import tempfile
import threading
import time
import traceback
import uuid

from block_application import encode, restore
from invoice_terms import terms_commitment
from native_invoice_qualification import INVOICE_CHECKS,invoice_report_matches
from commit_verifier import load_json
from invoice_book import open_invoice_storage
from local_devnet import ROOT, PIN_SHA, private_new, read_private, rpc, wait, verify_engine
from merchant_devnet import MerchantNetwork
from merchant_http import server
from merchant_ops import MerchantOps
from merchant_qualification import MERCHANT_CHECKS, actual_report_matches
from p4_evidence import need
from p4_receipt_capsule import verify_capsule
from payment_x402 import (NativePaymentExpectation,TrustedMerchantAssignment,make_payment_required,
    parse_payment_required,parse_payment_response,payment_header,verify_merchant_payment)
from private_acceptance import source_snapshot, stop_owned_web
from private_cli_acceptance import terminal_command
from private_payment_desk import PrivatePaymentDesk
from run_devnet import free_ports


def cleanup_owned_native(children, *, errors, seconds=5):
    """Terminate only original Popen handles; one failure cannot skip the rest."""
    for process in reversed(children):
        try:
            if process.poll() is not None:continue
            try:process.terminate()
            except BaseException:errors.append('owned_native_terminate_failed')
            try:process.wait(timeout=seconds)
            except BaseException:
                errors.append('owned_native_required_kill')
                try:process.kill()
                except BaseException:errors.append('owned_native_kill_failed')
                try:process.wait(timeout=seconds)
                except BaseException:errors.append('owned_native_wait_failed')
        except BaseException:errors.append('owned_native_poll_failed')


def owned_remaining(children, threads, *, errors):
    """Unavailable ownership state counts as live and remains an explicit failure."""
    processes=workers=0
    for process in children:
        try:processes+=process.poll() is None
        except BaseException:
            processes+=1;errors.append('owned_native_state_unavailable')
    for thread in threads:
        try:workers+=thread.is_alive()
        except BaseException:
            workers+=1;errors.append('owned_thread_state_unavailable')
    return processes,workers


def cleanup_owned_runtime(root, *, children, threads, errors):
    """Retain private runtime evidence whenever exact owned cleanup is uncertain."""
    try:
        remaining=owned_remaining(children,threads,errors=errors)
        if errors or remaining!=(0,0):return False
        root=Path(root)
        need(root.parent==Path(tempfile.gettempdir()).resolve() and root.name.startswith('one-merchant-') and
             not root.is_symlink(),'exact private disposable runtime required')
        shutil.rmtree(root)
        return True
    except BaseException:
        errors.append('private_runtime_cleanup_failed')
        return False


def run_merchant(engine,output,*,source=None,run_id=None,invoice_commitments=False):
    need(type(invoice_commitments) is bool,'explicit invoice capability selection required')
    output=Path(output).absolute()
    need(not output.is_relative_to(ROOT) and not output.is_symlink(),'outside-source evidence required')
    for parent in (output.parent,*output.parent.parents): need(not parent.is_symlink(),'aliased evidence parent')
    output.mkdir(mode=0o700,exist_ok=False)
    report=dict(schema=1,status='running',run_id=run_id or uuid.uuid4().hex,
        source_qualified=source is not None,consensus_executed=False,validator_count=0,
        pool_size=3,payer_roles=['owner','raven','atlas'],checks=[],cli_calls=[],payments=[],
        real_funds=False,public_network=False,independent_hosts=False,onchain_privacy=False,
        native_signature_authenticates_resource=False,full_public_ledger_disclosed=True,
        globally_exactly_once_service_delivery=False,cleanup_errors=[],
        single_financial_journal=True,recipient_assignments_never_reused=False,
        native_genesis_unchanged=False,scope='finite three-invoice local actual-validator journey')
    net=web=thread=None;children=[];threads=[];retained_logs=False
    payment_password=secrets.token_urlsafe(32).encode();invoice_password=secrets.token_urlsafe(32).encode()
    token=secrets.token_hex(32)
    content=[dict(description='Private negotiated invoice '+secrets.token_hex(16),
        contact=secrets.token_hex(16)+'@example.invalid',content='Confidential detail '+secrets.token_hex(16)) for _ in range(3)]
    forbidden=[payment_password,invoice_password,token.encode(),*(v.encode() for row in content for v in row.values())]

    def check(index,condition):
        name=MERCHANT_CHECKS[index]
        need(name not in {c['name'] for c in report['checks']},'duplicate actual check')
        report['checks'].append(dict(name=name,passed=bool(condition)))
        print(encode(dict(check=name,passed=bool(condition))).decode(),flush=True)
        need(condition,name)

    def invoice_check(index,condition):
        need(invoice_commitments,'invoice check requires explicit fresh capability')
        name=INVOICE_CHECKS[index]
        need(name not in {c['name'] for c in report['checks']},'duplicate invoice check')
        report['checks'].append(dict(name=name,passed=bool(condition)))
        print(encode(dict(check=name,passed=bool(condition))).decode(),flush=True)
        need(condition,name)

    def cli(interface,command,args,password=None):
        scripts={'private':'1soft_private.py','merchant':'1soft_merchant.py','network':'1soft_merchant_network.py'}
        value=terminal_command([sys.executable,'-B',str(ROOT/'tools/private-payments/scripts'/scripts[interface]),
            command,*[str(a) for a in args]],password=password,seconds=120)
        report['cli_calls'].append(dict(interface=interface,command=command,
            **{k:value[k] for k in ('returncode','password_prompts','stdout_sha256','terminal_sha256','owned_processes_after_cleanup')}))
        return value['value']

    def stop_web():
        nonlocal web,thread
        try: stop_owned_web(web,thread,workers=threads,errors=report['cleanup_errors'])
        except BaseException: report['cleanup_errors'].append('merchant_cleanup_failed')
        finally: web=thread=None

    def logs(workspace):
        nonlocal retained_logs
        if retained_logs:return
        for name in [f'{kind}{i}.log' for kind in ('app','engine') for i in range(4)]:
            p=workspace/name
            if p.exists():
                raw=read_private(p,5*1024*1024)
                for secret in forbidden:raw=raw.replace(secret,b'[REDACTED]')
                private_new(output/name,raw)
        retained_logs=True

    try:
        report['source']=source_snapshot(source);verify_engine(engine)
        report.update(engine_version='0.38.25',engine_sha256=PIN_SHA)
        with ExitStack() as stack:
            root=Path(tempfile.mkdtemp(prefix='one-merchant-'));root.chmod(0o700)
            def remove_runtime():
                if not cleanup_owned_runtime(root,children=children,threads=threads,errors=report['cleanup_errors']):
                    report['retained_private_runtime']=str(root)
            stack.callback(remove_runtime)
            workspace=root/'network';invoices=root/'invoices'
            n_args=['--workspace',workspace,'--engine',engine]
            cli('network','init',[*n_args,'--recipient-count',3,*(['--invoice-commitments'] if invoice_commitments else [])],payment_password)
            launched=cli('network','run',[*n_args,'--seconds',1],payment_password)
            need(launched['validator_count']==4 and launched['merchant_recipient_count']==3 and
                 launched['trust_renewed'] is False and launched['owned_processes_after_cleanup']==0 and
                 launched['cleanup_errors']==[],'actual bounded network lifecycle CLI')
            net=MerchantNetwork(workspace,engine)
            config=net.config
            check(0,len(config['merchant_recipients'])==3 and report['cli_calls'][0]['password_prompts']==2)
            genesis=read_private(workspace/'engine-genesis.json');app_genesis=load_json(read_private(workspace/'app-genesis.json'))
            check(1,app_genesis['protocol_version']==4 and app_genesis['fee']==2 and
                [r['units'] for r in app_genesis['allocations']]==[1000,0,0,0])
            if invoice_commitments:
                report.update(invoice_commitment_version=1,workspace_schema=config['schema'])
                invoice_check(0,config['schema']==3 and config['format']=='1soft/local-development-workspace/v3' and
                    type(app_genesis.get('invoice_commitment_version')) is int and app_genesis['invoice_commitment_version']==1)
            def stop_net():
                if net is not None:
                    for process in net.apps+net.engines:
                        if process not in children:children.append(process)
                try:
                    if net is not None:
                        report['shutdown']=net.stop()
                        if report['shutdown']['warnings']:report['cleanup_errors'].append('native_shutdown_warning')
                except BaseException:report['cleanup_errors'].append('native_cleanup_failed')
                cleanup_owned_native(children,errors=report['cleanup_errors'])
                try:logs(workspace)
                except BaseException:report['cleanup_errors'].append('log_retention_failed')
            stack.callback(stop_net);stack.callback(stop_web)
            net.start();children.extend(net.apps+net.engines);net.bootstrap(password=payment_password)
            policy=net.policy();payer=config['roles']['owner']['payer']
            report.update(consensus_executed=True,validator_count=4)
            with net.service() as svc:
                state=svc.state();initial={a['id']:a['recorded_balance'] for a in state['wallet']['accounts']}
                check(2,len(net.apps)==len(net.engines)==4 and initial[payer]=='994' and initial['system:fees']=='6')
                independent=svc.store.export(svc.store.current()['evidence_id'])
                restored=restore(app_genesis,independent['state']['native'])
                try:
                    grants=restored.db.execute('SELECT * FROM grants').fetchall()
                    budgets=restored.db.execute('SELECT * FROM budgets').fetchall()
                    links=restored.db.execute('SELECT * FROM grant_budgets').fetchall()
                    check(3,len(grants)==2 and len(budgets)==1 and all(
                        set(load_json(g['recipients'].encode()))==set(config['merchant_recipients']) for g in grants) and
                        set(load_json(budgets[0]['recipients'].encode()))==set(config['merchant_recipients']) and
                        len(links)==2 and {r['grant_id'] for r in links}=={g['id'] for g in grants} and
                        all(r['budget_id']==budgets[0]['id'] for r in links))
                finally:restored.close()
            cli('private','init-invoices',['--invoices',invoices,'--genesis-sha256',config['genesis_sha256']],invoice_password)
            init=cli('merchant','init-book',n_args)
            check(4,init['recipient_count']==3 and init['spending_authority'] is False)
            ops=MerchantOps(net);port=free_ports(1)[0];origin='http://127.0.0.1:'+str(port)
            rows=[]
            for i,amount in enumerate(('7','11','13')):
                directory=root/f'invoice{i}';directory.mkdir(mode=0o700)
                resource=('Public 1soft resource '+str(i)+'\n').encode();private_new(directory/'resource.txt',resource)
                result=cli('merchant','add-quote',[*n_args,'--recipient-index',i,'--origin',origin,
                    '--resource-path','/premium/invoice-'+str(i),'--amount-units',amount,'--resource',directory/'resource.txt',
                    '--public-resource-confirmation',hashlib.sha256(resource).hexdigest(),'--expires-ns',time.time_ns()+600*10**9])
                qid=result['quote_sha256']
                cli('merchant','export-quote',[*n_args,'--quote-id',qid,'--required-out',directory/'required.txt',
                    '--expectation-out',directory/'expectation.json'])
                header=read_private(directory/'required.txt').decode();expected=NativePaymentExpectation(**load_json(read_private(directory/'expectation.json')))
                quote=parse_payment_required(header,expected,now_ns=time.time_ns())
                rows.append(dict(directory=directory,resource=resource,qid=qid,expected=expected,header=header,
                    rid=quote['request_id'],amount=amount,role=('owner','raven','atlas')[i],route='/premium/invoice-'+str(i),terms=quote.get('invoice_terms')))
            check(5,all(row['expected'].recipient==config['merchant_recipients'][i] and row['expected'].amount_units==row['amount'] for i,row in enumerate(rows)))
            if invoice_commitments:
                invoice_check(1,all(r['terms'] is not None and r['terms']['resource_sha256']==hashlib.sha256(r['resource']).hexdigest() for r in rows))
            inspected=cli('merchant','inspect',n_args)
            check(6,inspected['assigned_recipient_count']==3 and len({r['expected'].recipient for r in rows})==3)
            def exhausted():
                try:ops.add_quote(recipient_index=0,merchant_origin=origin,resource_path='/fourth',amount_units='1',
                    resource=b'Fourth public resource',expires_ns=time.time_ns()+600*10**9)
                except ValueError:return len(ops.inspect()['quotes'])==3
                return False
            check(7,exhausted())
            serve_args=[*n_args,*[v for r in rows for v in ('--quote-id',r['qid'])],'--session-file',root/'cli-session.json','--seconds',1]
            served=cli('merchant','serve',serve_args)
            cli_session=load_json(read_private(root/'cli-session.json'));forbidden.append(cli_session['session_token'].encode())
            check(8,served['owned_handlers_after_cleanup']==0 and served['quote_ids']==[r['qid'] for r in rows] and
                cli_session['origin']==origin and cli_session['quote_ids']==served['quote_ids'] and
                cli_session['session_token'].encode() not in encode(served) and
                not (root/'cli-session.json').stat().st_mode&0o077)
            web=server(ops.book,session_token=token,port=port);web.configure_quotes(tuple(r['qid'] for r in rows))
            thread=threading.Thread(target=lambda:web.serve_forever(poll_interval=.01),daemon=True);threads.append(thread);thread.start()
            def request_http(method,row,body=None,signature=None):
                connection=http.client.HTTPConnection('127.0.0.1',port,timeout=30)
                headers={'X-1soft-Merchant-Session':token,'Origin':origin,'Sec-Fetch-Site':'same-origin'}
                if method=='POST':headers.update({'Content-Type':'application/json','PAYMENT-SIGNATURE':signature or 'invalid'})
                try:
                    connection.request(method,row['route'],body,headers);response=connection.getresponse()
                    return response.status,list(response.getheaders()),response.read(128*1024)
                finally:connection.close()
            check(9,all((lambda response:response[0]==402 and payment_header(response[1],'PAYMENT-REQUIRED')==r['header'])(request_http('GET',r)) for r in rows))
            base_args=[*n_args,'--invoices',invoices]
            for i,row in enumerate(rows):
                private_new(row['directory']/'content.json',encode(content[i]))
                imported=cli('private','import-invoice',[*base_args,'--required',row['directory']/'required.txt',
                    '--expectation',row['directory']/'expectation.json','--content',row['directory']/'content.json'],invoice_password)
                need(imported['request_id']==row['rid'] and imported['spending_authority'] is False,'unsigned invoice import')
            with net.service() as svc,open_invoice_storage(invoices,config['genesis_sha256']) as invoice:
                desk=PrivatePaymentDesk(svc,invoice)
                check(10,svc.state()['wallet']['pending_debit_units']=='0' and len(invoice.entries())==3)
                public=encode(svc.state())+encode(ops.inspect())
                check(11,all(v.encode() not in public for c in content for v in c.values()))
                check(12,len({row['rid'] for row in rows})==3)
                for row in rows:
                    directory=row['directory'];rid=row['rid'];role=row['role']
                    cli('private','prepare',[*base_args,'--request-id',rid,'--role',role,'--valid-until',
                        svc.state()['wallet']['state_height']+32,'--output',directory/'approval.json'])
                    prepared=load_json(read_private(directory/'approval.json'))['prepared']
                    need(prepared['terms']['quote_sha256']==row['qid'] and prepared['terms']['recipient']==row['expected'].recipient,
                        'separate immutable merchant consent')
                    cli('private','approve',[*base_args,'--request-id',rid,'--role',role,'--review',directory/'approval.json',
                        '--confirmation',prepared['confirmation'],'--terms-confirmation',prepared['terms_confirmation']],payment_password)
                    cli('private','recover',[*base_args,'--request-id',rid,'--output',directory/'wire.json'])
                    row['wire']=read_private(directory/'wire.json');row['wire_hash']=hashlib.sha256(row['wire']).hexdigest()
                    row['ciphertext']=invoice.envelope(rid)
                    if invoice_commitments:
                        row['signed_terms_match']=(prepared['review']['invoice_terms']==row['terms'] and
                            load_json(row['wire'])['body']['op']['invoice_commitment']==terms_commitment(row['terms']))
                    independent=svc.store.export(svc.store.current()['evidence_id'])
                    private_new(directory/'enrollment-evidence.json',encode(independent))
                    enrolled=cli('merchant','enroll-wire',[*n_args,'--quote-id',row['qid'],'--payer',payer,
                        '--wire',directory/'wire.json','--wire-confirmation',row['wire_hash'],'--evidence',directory/'enrollment-evidence.json'])
                    need(enrolled['wire_sha256']==row['wire_hash'],'independent operator enrollment')
                    review=desk.submission_review(rid);sent=desk.submit(rid,review['review'],review['confirmation'])
                    need(sent['submission_attempt_recorded'] is True,'original single attempt')
                    committed=wait(lambda:rpc(config['ports'][4],'tx',{'hash':base64.b64encode(hashlib.sha256(row['wire']).digest()).decode()}),30)
                    need(committed['tx_result']['code']==0 and base64.b64decode(committed['tx'],validate=True)==row['wire'],'actual original native execution')
                    need(desk.collect(rid)['status']=='receipt_collected','actual receipt collection')
                    cid=desk.retain_receipt(rid)['capsule_id'];row['cid']=cid
                    cli('private','export-receipt',[*base_args,'--request-id',rid,'--capsule-id',cid,'--output',directory/'capsule.json'])
                    cli('private','payment-header',[*base_args,'--request-id',rid,'--capsule-id',cid,'--output',directory/'payment-header.json'])
                    row['capsule']=read_private(directory/'capsule.json',16*1024*1024)
                    row['signature']=load_json(read_private(directory/'payment-header.json'))['payment_signature_header']
                    verified=verify_capsule(row['capsule'],genesis,policy,now_ns=time.time_ns(),expected_payer=payer,expected_wire_sha256=row['wire_hash'])
                    need(verified['native_execution_replayed'] is True and verified['amount_units']==row['amount'] and
                        verified['fee_units']=='2' and verified['recipient']==row['expected'].recipient and
                        verified['grant_id']==config['roles'][role]['grant_id'],'independent native payment terms replay')
                    if invoice_commitments:
                        row['generic_capsule_unclaimed']=verified.get('native_signature_authenticates_resource',False) is False
                    report['payments'].append(dict(role=role,recipient=verified['recipient'],units=verified['amount_units'],fee=verified['fee_units'],
                        request_id=rid,quote_sha256=row['qid'],wire_sha256=row['wire_hash'],native_txid=verified['binding']['native_txid'],capsule_sha256=cid))
                    if invoice_commitments:
                        report['payments'][-1].update(invoice_commitment=terms_commitment(row['terms']),resource_sha256=row['terms']['resource_sha256'])
                    for name,raw in (('wire',row['wire']),('capsule',row['capsule']),('envelope',row['ciphertext'])):
                        private_new(output/(name+'-'+role+'.json'),raw)
                if invoice_commitments:
                    invoice_check(2,all(r['signed_terms_match'] for r in rows))
                    invoice_check(3,all(r['generic_capsule_unclaimed'] for r in rows))
                    positives=[]
                    for row in rows:
                        assignment=TrustedMerchantAssignment(row['qid'],row['rid'],row['expected'].recipient,payer,row['wire_hash'])
                        row['verification_ns']=time.time_ns()
                        positive=verify_merchant_payment(signature_header=row['signature'],required_header=row['header'],
                            expectation=row['expected'],assignment=assignment,exact_wire=row['wire'],capsule=row['capsule'],
                            genesis_bytes=genesis,policy=policy,payer=payer,now_ns=row['verification_ns'])
                        positives.append(positive['native_signature_authenticates_resource'] is True)
                        artifact=encode(dict(schema=1,required_header=row['header'],expectation=asdict(row['expected']),
                            invoice_terms=row['terms'],public_resource=base64.b64encode(row['resource']).decode('ascii'),
                            resource_sha256=hashlib.sha256(row['resource']).hexdigest(),payment_signature_header=row['signature'],
                            historical_verification_ns=row['verification_ns']))
                        need(all(secret not in artifact for secret in forbidden),'private data in public invoice proof')
                        name='public-invoice-'+row['role']+'.json';private_new(output/name,artifact)
                        payment=next(p for p in report['payments'] if p['role']==row['role'])
                        payment.update(invoice_artifact=name,invoice_artifact_sha256=hashlib.sha256(artifact).hexdigest())
                    invoice_check(4,all(positives));report['native_signature_authenticates_resource']=True
                    original=rows[0];other=replace(original['expected'],resource_url=origin+'/different-exact-invoice')
                    other_header=make_payment_required(other,created_ns=original['terms']['created_ns'],
                        expires_ns=original['terms']['expires_ns'],quote_nonce=secrets.token_hex(32),resource_sha256=hashlib.sha256(b'Different public resource').hexdigest())
                    quote=parse_payment_required(other_header,other,now_ns=time.time_ns())
                    wrapper=load_json(base64.b64decode(original['signature'],validate=True))
                    wrapper.update(resource=quote['offer']['resource'],accepted=quote['offer']['accepts'][0])
                    wrapper['payload'].update(quoteSha256=quote['quote_sha256'],requestId=quote['request_id'])
                    wrong=base64.b64encode(encode(wrapper)).decode('ascii')
                    assignment=TrustedMerchantAssignment(quote['quote_sha256'],quote['request_id'],other.recipient,payer,original['wire_hash'])
                    refused=False;wrong_verification_ns=time.time_ns()
                    try:
                        verify_merchant_payment(signature_header=wrong,required_header=other_header,expectation=other,
                            assignment=assignment,exact_wire=original['wire'],capsule=original['capsule'],genesis_bytes=genesis,
                            policy=policy,payer=payer,now_ns=wrong_verification_ns)
                    except ValueError as exc:refused='commitment' in str(exc)
                    invoice_check(5,refused and other.recipient==original['expected'].recipient and other.amount_units==original['amount'])
                    negative=encode(dict(schema=1,original_role=original['role'],required_header=other_header,
                        expectation=asdict(other),payment_signature_header=wrong,original_wire_sha256=original['wire_hash'],
                        original_capsule_sha256=original['cid'],historical_verification_ns=wrong_verification_ns,
                        refused_for_commitment=refused))
                    need(all(secret not in negative for secret in forbidden),'private data in negative public proof')
                    private_new(output/'wrong-invoice-proof.json',negative)
                    report['wrong_invoice_proof_sha256']=hashlib.sha256(negative).hexdigest()
                check(13,len(report['payments'])==3 and all(c['password_prompts']==1 for c in report['cli_calls'] if c['command']=='approve'))
                check(14,svc.state()['wallet']['pending_debit_units']=='37' and svc.wallet.db.execute('SELECT count(*) FROM decisions').fetchone()[0]==3)
                check(15,all(r['enrollment']['wire_sha256']==rows[i]['wire_hash'] for i,r in enumerate(ops.inspect()['quotes'])))
                check(16,svc.delivery.db.execute('SELECT count(*) FROM attempts').fetchone()[0]==3)
                check(17,len({p['native_txid'] for p in report['payments']})==3)
                check(18,all(hashlib.sha256(r['capsule']).hexdigest()==r['cid'] for r in rows))
                check(19,svc.state()['wallet']['pending_debit_units']=='37')
                wrong=request_http('POST',rows[1],rows[0]['capsule'],rows[0]['signature'])
                check(20,wrong[0]==400 and all(r['fulfillment'] is None for r in ops.inspect()['quotes']))
                first=rows[0];raw=('POST '+first['route']+' HTTP/1.0\r\nHost: 127.0.0.1:'+str(port)+
                    '\r\nX-1soft-Merchant-Session: '+token+'\r\nContent-Type: application/json\r\nPAYMENT-SIGNATURE: '+
                    first['signature']+'\r\nContent-Length: '+str(len(first['capsule']))+'\r\n\r\n').encode()+first['capsule']
                with socket.create_connection(('127.0.0.1',port),timeout=30) as connection:
                    connection.sendall(raw)
                    observed=wait(lambda:ops.inspect()['quotes'][0]['fulfillment'],30)
                check(21,observed['capsule_sha256']==first['cid'])
                returns=[]
                for row in rows:
                    status,headers,body=request_http('POST',row,row['capsule'],row['signature'])
                    response=parse_payment_response(payment_header(headers,'PAYMENT-RESPONSE'),row['expected'],payer=payer,
                        quote_sha256=row['qid'],wire_sha256=row['wire_hash'],capsule_sha256=row['cid'])
                    returns.append(status==200 and body==row['resource'] and response['wallet_reservations_changed'] is False)
                check(22,all(returns))
                with ops.book() as book:
                    merchant_before=book.db.execute('SELECT * FROM fulfillments ORDER BY quote_id').fetchall()
                check(23,len(merchant_before)==3 and len({r['fulfillment']['native_txid'] for r in ops.inspect()['quotes']})==3)
                check(24,svc.state()['wallet']['pending_debit_units']=='37')
                financial={n:svc.wallet.db.execute('SELECT * FROM '+n).fetchall() for n in ('observations','decisions')}
                delivery={n:svc.delivery.db.execute('SELECT * FROM '+n).fetchall() for n in ('attempts','responses','receipts')}
            original_policy=read_private(workspace/'policy.json');original_config=read_private(workspace/'workspace.json')
            pinned_hashes={name:hashlib.sha256(read_private(workspace/name)).hexdigest() for name in config['files']}
            invoice_key=read_private(invoices/'invoice-data.pem');before_inspection=ops.inspect()
            height=net.height();old=list(net.apps+net.engines);stop_web();stopped=net.stop()
            check(25,all(p.poll() is not None for p in old) and not stopped['warnings'])
            net=MerchantNetwork(workspace,engine);net.start();children.extend(net.apps+net.engines)
            wait(lambda:all(net.height(i)>height for i in range(4)),30)
            check(26,net.ready() and read_private(workspace/'policy.json')==original_policy and
                read_private(workspace/'workspace.json')==original_config and read_private(invoices/'invoice-data.pem')==invoice_key and
                all(hashlib.sha256(read_private(workspace/name)).hexdigest()==digest for name,digest in pinned_hashes.items()))
            ops=MerchantOps(net)
            with net.service() as svc,open_invoice_storage(invoices,config['genesis_sha256']) as invoice:
                desk=PrivatePaymentDesk(svc,invoice)
                check(27,financial=={n:svc.wallet.db.execute('SELECT * FROM '+n).fetchall() for n in financial} and
                    delivery=={n:svc.delivery.db.execute('SELECT * FROM '+n).fetchall() for n in delivery})
                recovered=[];decrypted=[]
                for i,row in enumerate(rows):
                    cli('private','recover',[*base_args,'--request-id',row['rid'],'--output',row['directory']/'cold-wire.json'])
                    recovered.append(read_private(row['directory']/'cold-wire.json')==row['wire'] and invoice.envelope(row['rid'])==row['ciphertext'])
                    cli('private','open-invoice',['--invoices',invoices,'--genesis-sha256',config['genesis_sha256'],
                        '--request-id',row['rid'],'--output',row['directory']/'cold-private.json'],invoice_password)
                    decrypted.append(load_json(read_private(row['directory']/'cold-private.json'))==content[i])
                check(28,all(recovered));check(29,all(decrypted))
                if invoice_commitments:
                    invoice_check(6,all(recovered) and all(load_json(read_private(r['directory']/'cold-wire.json'))['body']['op']['invoice_commitment']==terms_commitment(r['terms']) for r in rows))
                cold=cli('merchant','inspect',n_args)
                check(30,cold==before_inspection)
                with ops.book() as book:
                    replay=[book.fulfill(r['qid'],r['signature'],r['capsule']) for r in rows]
                    unchanged=book.db.execute('SELECT * FROM fulfillments ORDER BY quote_id').fetchall()==merchant_before
                check(31,unchanged and all(r['native_execution_reverified'] is True and r['resource']==rows[i]['resource'] for i,r in enumerate(replay)))
                check(32,exhausted() and svc.state()['wallet']['pending_debit_units']=='37' and
                    svc.wallet.db.execute('SELECT count(*) FROM decisions').fetchone()[0]==3 and
                    svc.delivery.db.execute('SELECT count(*) FROM attempts').fetchone()[0]==3)
                for row in rows:
                    cli('private','reconcile',[*base_args,'--request-id',row['rid'],'--expected-revision',svc.state()['wallet']['revision']])
                final=svc.state();check(33,final['wallet']['pending_debit_units']=='0')
                balances={a['id']:int(a['recorded_balance']) for a in final['wallet']['accounts']}
                report['final_balances']=dict(payer=str(balances[payer]),merchants=[str(balances[r]) for r in config['merchant_recipients']],
                    fees=str(balances['system:fees']),supply=str(sum(balances.values())),budget_spent=final['wallet']['budgets'][0]['spent'],
                    pending_debit_units=final['wallet']['pending_debit_units'])
                check(34,report['final_balances']==dict(payer='957',merchants=['7','11','13'],fees='12',supply='1000',budget_spent='28',pending_debit_units='0'))
                private_new(output/'public-final-state.json',encode(final))
            report['native_genesis_unchanged']=genesis==read_private(workspace/'engine-genesis.json')
            report['recipient_assignments_never_reused']=len(rows)==len({r['expected'].recipient for r in rows})==3
            private_new(output/'engine-genesis.json',genesis);private_new(output/'policy.json',encode(policy))
            private_new(output/'merchant-public-inspection.json',encode(cold))
            verify_engine(engine);report['engine_sha256_after']=PIN_SHA
            report['source_after']=source_snapshot(source);report['source_unchanged']=report['source_after']==report['source']
            check(35,report['source_unchanged'] and report['native_genesis_unchanged'])
        report['owned_processes_after_cleanup'],report['owned_threads_after_cleanup']=owned_remaining(children,threads,errors=report['cleanup_errors'])
        check(36,report['owned_processes_after_cleanup']==report['owned_threads_after_cleanup']==0 and not report['cleanup_errors'])
        report['status']='passed'
        if source is not None:
            predicate=invoice_report_matches if invoice_commitments else actual_report_matches
            need(predicate(report,{k:source[k] for k in ('commit','tree','source_id','tracked_files')},report['run_id']),'complete attributed merchant report')
        else:need(len(report['checks'])==len(MERCHANT_CHECKS)+(len(INVOICE_CHECKS) if invoice_commitments else 0) and all(c['passed'] for c in report['checks']),'complete exploratory checks')
    except Exception as exc:
        report.update(status='failed',error_type=type(exc).__name__,error_frames=[dict(file=Path(f.filename).name,line=f.lineno,function=f.name) for f in traceback.extract_tb(exc.__traceback__)])
    finally:
        stop_web()
        if net is not None:
            for p in net.apps+net.engines:
                if p not in children:children.append(p)
            try:
                stopped=net.stop()
                if stopped['warnings']:report['cleanup_errors'].append('final_shutdown_warning')
            except BaseException:report['cleanup_errors'].append('final_native_cleanup_failed')
        cleanup_owned_native(children,errors=report['cleanup_errors'])
        report['owned_processes_after_cleanup'],report['owned_threads_after_cleanup']=owned_remaining(children,threads,errors=report['cleanup_errors'])
        if report['owned_processes_after_cleanup'] or report['owned_threads_after_cleanup'] or report['cleanup_errors']:report['status']='failed'
        raw=encode(report);need(all(secret not in raw for secret in forbidden),'private actual data in report')
        private_new(output/'result.json',raw)
    return report
