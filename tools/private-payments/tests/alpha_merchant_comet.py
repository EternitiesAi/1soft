#!/usr/bin/env python3
"""Short actual four-validator alpha receipt-to-resource qualification.

Fresh private DEV homes/keys only. Original runtime remains preserved. Public
artifact logs omit tokens, keys, passwords and private invoice/store bytes.
No scaled clock, trust renewal, installs, public services or paid compute.
"""
import base64
from dataclasses import asdict
import hashlib
import http.client
import json
import os
from pathlib import Path
import socket
import subprocess
import sys
import time
import traceback
import uuid
sys.dont_write_bytecode=True
ROOT=Path(__file__).resolve().parents[3]
sys.path[:0]=[str(ROOT/'src'),str(ROOT/'scripts'),str(ROOT/'tools/release')]+[str(p) for p in sorted((ROOT/'tools').glob('*/src'))]
import check_release as evidence
from block_application import encode
from commit_verifier import load_json
from local_devnet import initialize,LocalNetwork,private_new,read_private,verify_engine,rpc,wait,PIN_SHA
from invoice_book import initialize_invoice_storage,open_invoice_storage
from private_payment_desk import AlphaPrivatePaymentDesk
from merchant_alpha_ops import AlphaMerchantOps
from alpha_acceptance import _birth,_files,stop_with_facts
from p4_evidence import need
PASSWORD=b'public disposable fixture passphrase'


def main():
    os.umask(0o077);engine=verify_engine(Path(sys.argv[1]));out=Path(sys.argv[2]).absolute()
    need(not out.exists() and not out.is_relative_to(ROOT),'new external evidence required');out.mkdir(mode=0o700)
    source=evidence.source_identity(ROOT);private_new(out/'source.json',encode(source))
    runtime=Path.home()/('1sm-'+uuid.uuid4().hex[:12]);runtime.mkdir(mode=0o700)
    workspace=runtime/'net';invoices=runtime/'invoices';net=None;servers=[];allchildren=[];generation=0;rows=[];started=time.monotonic()
    report=dict(schema=1,format='1soft/alpha-merchant-actual-acceptance/v1',status='running',runtime=str(runtime),
        source={k:source[k] for k in ('commit','tree','source_id','tracked_files')},engine_sha256=PIN_SHA,checks=[],payments=[],
        owned_processes=[],real_funds=False,public_network=False,onchain_privacy=False,independent_operators=False,
        long_horizon_qualified=False,cleanup_errors=[])
    def save():evidence.store_json(out/'progress.json',report,replace=(out/'progress.json').exists())
    def check(name,condition,**facts):
        report['checks'].append(dict(name=name,passed=bool(condition),**facts));save();need(condition,'actual merchant check failed: '+name)
        print(encode(dict(check=name,passed=True)).decode(),flush=True)
    def command(label,script,args):
        run=subprocess.run([sys.executable,'-B',str(ROOT/'tools/private-payments/scripts'/script),*map(str,args)],capture_output=True,timeout=120)
        private_new(out/(label+'.stdout.log'),run.stdout);private_new(out/(label+'.stderr.log'),run.stderr)
        need(run.returncode==0,'cold caller refused: '+label)
        return load_json(run.stdout)
    def merchant(label,op,args):return command(label,'1soft_merchant.py',[op,'--workspace',workspace,'--engine',engine,*args])
    def payer(label,op,rid,args):return command(label,'1soft_private.py',[op,'--workspace',workspace,'--engine',engine,'--invoices',invoices,'--request-id',rid,*args])
    def own(n):
        allchildren.extend(n.apps+n.engines)
        report['owned_processes'].extend(dict(kind=kind,pid=p.pid,birth=_birth(p.pid),generation=generation)
            for kind,items in [('application',n.apps),('validator',n.engines)] for p in items);save()
    def start_server(label):
        target=runtime/(label+'-session.json')
        argv=[sys.executable,'-B',str(ROOT/'tools/private-payments/scripts/1soft_merchant.py'),'serve','--workspace',str(workspace),
            '--engine',str(engine),'--session-file',str(target),'--seconds','12']
        for r in rows:argv+=['--quote-id',r['qid']]
        std=(out/(label+'.stdout.log')).open('wb');err=(out/(label+'.stderr.log')).open('wb')
        p=subprocess.Popen(argv,stdout=std,stderr=err);servers.append((p,std,err));allchildren.append(p)
        until=time.monotonic()+120
        while not target.exists():
            need(p.poll() is None and time.monotonic()<until,'owned merchant listener failed to start');time.sleep(.05)
        session=load_json(read_private(target));return p,session['session_token']
    def request(token,r,method='GET',capsule=None,header=None,drop_return=False):
        headers={'X-1soft-Merchant-Session':token}
        if method=='POST':headers.update({'Content-Type':'application/json','PAYMENT-SIGNATURE':header})
        c=http.client.HTTPConnection('127.0.0.1',port,timeout=120)
        try:
            c.request(method,r['path'],body=capsule,headers=headers)
            if drop_return:return None
            response=c.getresponse();return response.status,dict(response.getheaders()),response.read()
        finally:c.close()
    def await_port():
        begin=time.monotonic()
        while time.monotonic()-begin<75:
            with socket.socket() as s:
                try:s.bind(('127.0.0.1',port));return time.monotonic()-begin
                except OSError:time.sleep(.25)
        raise ValueError('original pinned merchant port still unavailable')
    try:
        config=initialize(workspace,engine,password=PASSWORD,profile='durable-private-alpha-v1',invoice_commitments=True)
        net=LocalNetwork(workspace,engine).start();own(net);net.bootstrap(password=PASSWORD)
        check('four_actual_owned_validators',len(net.apps)==len(net.engines)==4 and all(net.height(i)>=1 for i in range(4)))
        initialize_invoice_storage(invoices,config['genesis_sha256'],password=PASSWORD)
        ops=AlphaMerchantOps(net);merchant('init','init-book',[])
        genesis=read_private(workspace/'engine-genesis.json');policy=read_private(workspace/'policy.json')
        private_new(out/'engine-genesis.json',genesis);private_new(out/'policy.json',policy)
        with socket.socket() as s:s.bind(('127.0.0.1',0));port=s.getsockname()[1]
        origin='http://127.0.0.1:'+str(port)
        with net.service() as svc,open_invoice_storage(invoices,config['genesis_sha256']) as inv:
            desk=AlphaPrivatePaymentDesk(svc,inv)
            for role,amount in zip(('owner','raven','atlas'),('7','11','13')):
                resource=('Public paid alpha resource '+role+'\n').encode();path='/premium/'+role
                resource_file=out/(role+'-resource.bin');private_new(resource_file,resource)
                q=merchant(role+'-quote','add-quote',['--recipient-index','0','--origin',origin,'--resource-path',path,'--amount-units',amount,
                    '--resource',resource_file,'--public-resource-confirmation',hashlib.sha256(resource).hexdigest(),'--expires-ns',time.time_ns()+600*10**9])
                qid=q['quote_sha256'];req=out/(role+'-required.txt');exp=out/(role+'-expectation.json')
                merchant(role+'-quote-export','export-quote',['--quote-id',qid,'--required-out',req,'--expectation-out',exp])
                with ops.book(read_only=True) as book:quote=book.selected(qid)
                svc.refresh();svc.sync(expected_revision=svc.state()['wallet']['revision'])
                rid=desk.import_invoice(quote['required_header'],quote['expectation'],dict(description='private invoice',contact='',
                    content='PRIVATE_ALPHA_MERCHANT_SENTINEL'),invoice_password=PASSWORD)['request_id']
                prepared=desk.prepare(rid,role,valid_until=svc.state()['wallet']['state_height']+32)
                desk.approve(rid,role,prepared['review'],prepared['confirmation'],prepared['terms_confirmation'],payment_password=PASSWORD)
                wire=desk.recover(rid);wirepath=out/(role+'-wire.json');private_new(wirepath,wire)
                submit=desk.submission_review(rid);desk.submit(rid,submit['review'],submit['confirmation'])
                tx=wait(lambda:rpc(config['ports'][4],'tx',{'hash':base64.b64encode(hashlib.sha256(wire).digest()).decode()}),30)
                check(role+'_actual_included_payment',tx['tx_result']['code']==0 and base64.b64decode(tx['tx'],validate=True)==wire)
                need(desk.collect(rid)['status']=='receipt_collected','original positive receipt unavailable')
                cid=desk.retain_receipt(rid)['capsule_id'];capsule=out/(role+'-capsule.json');headerpath=out/(role+'-header.json')
                payer(role+'-capsule-export','export-receipt',rid,['--capsule-id',cid,'--output',capsule])
                payer(role+'-header-export','payment-header',rid,['--capsule-id',cid,'--output',headerpath])
                header=load_json(read_private(headerpath))['payment_signature_header'];raw=read_private(capsule,64*1024*1024+65536)
                merchant(role+'-enrollment','enroll-wire',['--quote-id',qid,'--payer',config['roles'][role]['payer'],'--wire',wirepath,
                    '--wire-confirmation',hashlib.sha256(wire).hexdigest(),'--evidence',capsule])
                rows.append(dict(role=role,qid=qid,rid=rid,path=path,resource=resource,header=header,capsule=raw,expected=quote['expectation']))
                report['payments'].append(dict(role=role,amount_units=amount,quote_sha256=qid,request_id=rid,
                    wire_sha256=hashlib.sha256(wire).hexdigest(),capsule_sha256=hashlib.sha256(raw).hexdigest(),reference_id=cid,
                    resource_sha256=hashlib.sha256(resource).hexdigest(),invoice_commitment=json.loads(wire)['body']['op']['invoice_commitment']))
            check('same_recipient_three_distinct_committed_routes',len({r['expected'].recipient for r in rows})==1 and len({r['qid'] for r in rows})==3)
            financial_before=(svc.wallet.db.execute('SELECT count(*) FROM decisions').fetchone()[0],svc.delivery.db.execute('SELECT count(*) FROM attempts').fetchone()[0])
            p,token=start_server('http-original')
            for r in rows:
                status,headers,body=request(token,r)
                check(r['role']+'_get402',status==402 and headers['PAYMENT-REQUIRED']==read_private(out/(r['role']+'-required.txt')).decode())
            r=rows[0];request(token,r,'POST',r['capsule'],r['header'],drop_return=True)
            wait(lambda:ops.inspect()['quotes'][0] if any(x['fulfillment'] is not None for x in ops.inspect()['quotes']) else None,30)
            check('closed_first_http_return_keeps_consumption',sum(x['fulfillment'] is not None for x in ops.inspect()['quotes'])==1)
            for r in rows:
                status,headers,body=request(token,r,'POST',r['capsule'],r['header'])
                check(r['role']+'_actual_http_resource',status==200 and body==r['resource'] and 'PAYMENT-RESPONSE' in headers)
                r['response']=headers['PAYMENT-RESPONSE']
            bad=rows[1];status,_,_=request(token,bad,'POST',rows[0]['capsule'],rows[0]['header'])
            check('cross_invoice_http_refused',status==400)
            status,_,_=request('0'*64,rows[0]);check('unauthorized_http_refused',status==403)
            p.wait(30);check('first_listener_normal_exit',p.returncode==0)
            before_book=ops.inspect();check('three_durable_consumptions',sum(x['fulfillment'] is not None for x in before_book['quotes'])==3)
            check('http_did_not_change_financial_journals',financial_before==(3,3) and financial_before==(
                svc.wallet.db.execute('SELECT count(*) FROM decisions').fetchone()[0],svc.delivery.db.execute('SELECT count(*) FROM attempts').fetchone()[0]))
            desk.reconcile(rows[-1]['rid'],expected_revision=svc.state()['wallet']['revision'])
            state=svc.state();payer_account=next(a for a in state['wallet']['accounts'] if a['id']==config['roles']['owner']['payer'])
            check('exact_money_and_holds',payer_account['recorded_balance']=='957' and state['wallet']['pending_debit_units']=='0')
            for r in rows:
                target=out/(r['role']+'-proof.json');merchant(r['role']+'-proof-export','export-proof',['--quote-id',r['qid'],'--proof-out',target])
                with ops.book(read_only=True) as book:
                    assignment=book.assignment(r['qid']);fulfilled=book.selected(r['qid'])['fulfillment'];r['asof']=fulfilled['fulfilled_ns']
                private_new(out/(r['role']+'-assignment.json'),encode(asdict(assignment)))
                r['proof']=read_private(target,100*1024*1024)
        height=min(net.height(i) for i in range(4));roots=[rpc(p,'commit',{'height':str(height)})['signed_header']['header']['app_hash'] for p in config['ports'][4:]]
        check('all_four_matching_app_hashes',len(set(roots))==1,height=height,app_hashes=roots)
        identities=_files(workspace);check('first_native_normal_shutdown',stop_with_facts(net,report['owned_processes']))
        generation=1;net=LocalNetwork(workspace,engine).start();own(net)
        check('same_home_restart_without_bootstrap',net.ready() and _files(workspace)==identities and read_private(workspace/'policy.json')==policy)
        ops=AlphaMerchantOps(net);waited=await_port();report['merchant_original_port_wait_seconds']=waited
        p,token=start_server('http-cold-reopen')
        for r in rows:
            status,headers,body=request(token,r,'POST',r['capsule'],r['header'])
            check(r['role']+'_cold_original_result',status==200 and body==r['resource'] and headers['PAYMENT-RESPONSE']==r['response'])
        p.wait(30);check('cold_listener_normal_exit',p.returncode==0)
        check('cold_book_unchanged',ops.inspect()==before_book)
        with net.service() as svc:
            check('cold_financial_no_new_charge',svc.wallet.db.execute('SELECT count(*) FROM decisions').fetchone()[0]==3 and
                svc.delivery.db.execute('SELECT count(*) FROM attempts').fetchone()[0]==3 and svc.state()['wallet']['pending_debit_units']=='0')
        check('second_native_normal_shutdown',stop_with_facts(net,report['owned_processes']))
        for r in rows:
            report_proof=command(r['role']+'-cold-proof','verify_merchant_proof.py',['--profile','alpha','--proof',out/(r['role']+'-proof.json'),
                '--genesis',out/'engine-genesis.json','--policy',out/'policy.json','--expectation',out/(r['role']+'-expectation.json'),
                '--assignment',out/(r['role']+'-assignment.json'),'--as-of-ns',r['asof']])
            check(r['role']+'_offline_public_proof',report_proof['native_signature_authenticates_resource'] and not report_proof['spending_authority'])
        check('source_engine_unchanged',evidence.source_identity(ROOT)==source and hashlib.sha256(engine.read_bytes()).hexdigest()==PIN_SHA)
        report['status']='passed'
    except BaseException as exc:
        report.update(status='failed',error_type=type(exc).__name__);private_new(out/'failure.log',traceback.format_exc().encode())
    finally:
        if net is not None and not net.stopped:
            try:stop_with_facts(net,report['owned_processes'])
            except BaseException:report['cleanup_errors'].append('native_cleanup_failed')
        for p,std,err in servers:
            if p.poll() is None:
                try:p.terminate();p.wait(5)
                except BaseException:report['cleanup_errors'].append('listener_cleanup_failed')
            std.close();err.close()
        allchildren=list({id(p):p for p in allchildren+([] if net is None else net.apps+net.engines)}.values())
        for p in allchildren:
            if p.poll() is None:
                try:p.terminate();p.wait(5)
                except BaseException:report['cleanup_errors'].append('owned_child_cleanup_failed')
        report.update(all_owned_processes_reaped=all(p.poll() is not None for p in allchildren),original_runtime_preserved=runtime.is_dir(),elapsed_seconds=time.monotonic()-started)
        if report['cleanup_errors'] or not report['all_owned_processes_reaped']:report['status']='failed'
        evidence.store_json(out/'result.json',report);save();print(encode(report).decode(),flush=True)
    return 0 if report['status']=='passed' else 1

if __name__=='__main__':raise SystemExit(main())
