"""Actual four-validator local product journey, not browser or public qualification."""
import hashlib
import base64
from contextlib import ExitStack
import http.client
import json
import os
from pathlib import Path
import secrets
import stat
import sys
import tempfile
import threading
import time

from block_application import encode
from local_devnet import initialize,LocalNetwork,PIN_SHA,load_configuration,read_private,private_new,rpc,wait
from platform_http import server
from p4_evidence import need
from p4_receipt_capsule import verify_capsule
from commit_verifier import load_json


def run_product(engine,output):
    output=Path(output).absolute();output.mkdir(mode=0o700,exist_ok=False)
    report={'schema':1,'status':'running','scope':'actual four-validator local development product',
        'engine_sha256':PIN_SHA,'checks':[],'stages':[],'payments':[],
        'real_funds':False,'independent_hosts':False,'browser_visual_check':'unassessed',
        'browser_interaction_executed':False,'public_release_ready':False,
        'software_vault_host_security':'unassessed'}
    net=web=thread=None
    password=secrets.token_urlsafe(32).encode('utf-8')
    def check(name,condition,details=None):
        report['checks'].append({'name':name,'passed':bool(condition),'details':details})
        need(condition,name)
    try:
        with ExitStack() as stack:
            temporary=stack.enter_context(tempfile.TemporaryDirectory(prefix='one-local-release-'))
            workspace=Path(temporary)/'wallet'
            config=initialize(workspace,engine,password=password)
            net=LocalNetwork(workspace,engine).start()
            def stop_runtime():
                if net is not None:report['shutdown']=net.stop()
            stack.callback(stop_runtime)
            net.bootstrap(password=password)
            check('four actual validators and applications remain owned',
                  len(net.apps)==len(net.engines)==4 and all(p.poll() is None for p in net.apps+net.engines))
            with net.service() as svc:
                state=svc.state();check('initial P4 checkpoint fully verified',state['current_evidence_available'])
                payer=config['roles']['owner']['payer']
                balances={a['id']:a['recorded_balance'] for a in state['wallet']['accounts']}
                check('three initial setup fees recorded before wallet use',balances[payer]=='994' and balances['system:fees']=='6')
            web=server(net.service,port=0)
            thread=threading.Thread(target=lambda:web.serve_forever(poll_interval=.01),daemon=True);thread.start()
            def close_web():
                if web is not None:web.shutdown();web.server_close()
                if thread is not None:thread.join(3)
            stack.callback(close_web)
            origin=f'http://127.0.0.1:{web.server_port}'
            def call(method,path,value=None,raw_response=False):
                conn=http.client.HTTPConnection('127.0.0.1',web.server_port,timeout=55)
                headers={'Origin':origin,'Sec-Fetch-Site':'same-origin'}
                if method=='POST':headers.update({'Content-Type':'application/json','X-1soft-CSRF':csrf})
                raw=None if value is None else encode(value)
                try:
                    conn.request(method,path,raw,headers);response=conn.getresponse();body=response.read(17*1024*1024)
                    need(response.status==200,'actual product route did not complete')
                    return body if raw_response else load_json(body,max_bytes=17*1024*1024)
                finally:conn.close()
            csrf=call('GET','/api/session')['csrf']
            for path in ('/','/wallet.js','/wallet.css'):
                check('actual product serves '+path,len(call('GET',path,raw_response=True))>100)
            requests={}
            for role,units in (('raven','58'),('atlas','38')):
                rid=call('POST','/api/create-request',{'recipient':config['merchant'],'units':units,
                    'note':role+' development payment','lifetime_seconds':600})['request_id']
                state=call('GET','/api/state')
                prepared=call('POST','/api/prepare',{'request_id':rid,'role':role,'valid_until':state['wallet']['state_height']+32})
                check(role+' review contains fee-inclusive exact string debit',prepared['summary']['debit_units']==str(int(units)+2))
                result=call('POST','/api/sign',{'request_id':rid,'role':role,'review_json':prepared['review_json'],
                    'confirmation':prepared['confirmation'],'password':password.decode('utf-8')})
                original=call('GET','/api/original/'+rid,raw_response=True)
                check(role+' durable original signature is recoverable',hashlib.sha256(original).hexdigest()==result['wire_sha256'])
                requests[role]={'request_id':rid,'decision_id':result['decision_id'],'wire_sha256':result['wire_sha256']}
            password=None
            state=call('GET','/api/state')
            check('two agent lanes reserve the same complete shared budget',
                  state['wallet']['pending_debit_units']=='100' and state['wallet']['budgets'][0]['uncommitted_units']=='0')
            def stage(name):
                s=call('GET','/api/state');report['stages'].append({'name':name,'wallet_pending_units':s['wallet']['pending_debit_units'],
                    'wallet_budget_spent_units':s['wallet']['budgets'][0]['spent'],'wallet_state_height':s['wallet']['state_height']})
                return s
            stage('both signed')
            for role in ('raven','atlas'):
                row=requests[role];rid=row['request_id'];prepared=call('POST','/api/submission-review',{'request_id':rid})
                result=call('POST','/api/submit',{'request_id':rid,'review_json':prepared['review_json'],'confirmation':prepared['confirmation']})
                check(role+' admitted attempt is not execution proof',result['submission_attempt_recorded'] and not result['execution_proven'])
                original=call('GET','/api/original/'+rid,raw_response=True)
                txhash=base64.b64encode(hashlib.sha256(original).digest()).decode()
                committed=wait(lambda:rpc(config['ports'][4],'tx',{'hash':txhash}),30)
                check(role+' original transfer committed before positive receipt collection',
                      type(committed['tx_result']['code']) is int and committed['tx_result']['code']==0 and
                      base64.b64decode(committed['tx'],validate=True)==original)
                collected=call('POST','/api/collect',{'request_id':rid})
                check(role+' exact receipt collected from actual signed chain',collected['status']=='receipt_collected')
                before=stage(role+' collected before reconcile')
                retained=call('POST','/api/retain',{'request_id':rid});cid=retained['capsule_id']
                capsule=call('GET','/api/capsule/'+rid+'/'+cid,raw_response=True)
                proof=verify_capsule(capsule,read_private(workspace/'engine-genesis.json'),net.policy(),now_ns=time.time_ns(),
                                     expected_payer=payer,expected_wire_sha256=row['wire_sha256'])
                check(role+' portable capsule independently replays actual history',proof['capsule_id']==cid)
                after=call('GET','/api/state');check(role+' receipt archive does not retire wallet hold',
                    after['wallet']['pending_debit_units']==before['wallet']['pending_debit_units'])
                call('POST','/api/reconcile',{'request_id':rid,'expected_revision':after['wallet']['revision']})
                after=stage(role+' reconciled')
                private_new(output/(role+'-capsule.json'),capsule)
                private_new(output/(role+'-original.json'),call('GET','/api/original/'+rid,raw_response=True))
                private_new(output/(role+'-request.json'),call('GET','/api/request/'+rid,raw_response=True))
                report['payments'].append({**row,'role':role,'capsule_id':cid,'receipt_evidence_id':collected['evidence_id'],
                    'native_txid':proof['binding']['native_txid'],'inclusion_height':proof['binding']['height']})
            check('only exact reconciliation retires both original obligations',after['wallet']['pending_debit_units']=='0')
            call('POST','/api/refresh',{'expected_tip':after['ledger']['checkpoint']['evidence_id']})
            after=call('GET','/api/state');check('explicit ledger collection displays both actual payments',
                len(after['ledger']['payments'])==2 and after['wallet']['budgets'][0]['spent']=='100')
            balances={a['id']:int(a['recorded_balance']) for a in after['wallet']['accounts']}
            check('native development supply conserved after complete workflow',
                  balances[payer]==894 and balances[config['merchant']]==96 and balances['system:fees']==10 and sum(balances.values())==1000)
            private_new(output/'state-before-restart.json',encode(after))
            private_new(output/'engine-genesis.json',read_private(workspace/'engine-genesis.json'))
            private_new(output/'policy.json',read_private(workspace/'policy.json'))
            original_policy=read_private(workspace/'policy.json');original_cfg=read_private(workspace/'workspace.json')
            with net.service() as svc:
                financial_before={name:svc.wallet.db.execute('SELECT * FROM '+name).fetchall() for name in ('observations','decisions')}
                delivery_before={name:svc.delivery.db.execute('SELECT * FROM '+name).fetchall() for name in ('attempts','responses','receipts')}
                wires_before={r:svc.recover(requests[r]['request_id']) for r in requests}
            old_children=net.apps+net.engines;old_height=net.height()
            web.shutdown();web.server_close();thread.join(3);web=None;thread=None
            stopped=net.stop();check('shutdown stops only owned processes and cleans their sockets',
                all(p.poll() is not None for p in old_children) and not stopped['warnings'] and
                all(not (workspace/f'app{i}/a.sock').exists() for i in range(4)))
            check('all retained development files stay private and unaliased',
                all(not p.is_symlink() and not (p.stat().st_mode&0o077) for p in workspace.rglob('*')))
            net=LocalNetwork(workspace,engine).start()
            check('reopen retains original readiness and external trust policy',net.ready() and
                  read_private(workspace/'policy.json')==original_policy and read_private(workspace/'workspace.json')==original_cfg)
            wait(lambda:net.height()>old_height,30)
            check('same four validators continue after cold restart',all(net.height(i)>old_height for i in range(4)))
            with net.service() as svc:
                reopened=svc.state();private_new(output/'state-after-restart.json',encode(reopened))
                check('reopen preserves every financial observation and signed decision',
                    financial_before=={name:svc.wallet.db.execute('SELECT * FROM '+name).fetchall() for name in financial_before})
                check('reopen preserves attempts, observations and exact delivery receipts',
                    delivery_before=={name:svc.delivery.db.execute('SELECT * FROM '+name).fetchall() for name in delivery_before})
                check('reopen recovers original wires without re-signing',
                    wires_before=={r:svc.recover(requests[r]['request_id']) for r in requests})
                check('reopen keeps zero reconciled obligations and positive exact receipts',
                    reopened['wallet']['pending_debit_units']=='0' and all(e['stage']=='recorded' for e in reopened['requests']))
                for r in report['payments']:
                    check(r['role']+' archived capsule survives cold restart',
                          hashlib.sha256(svc.capsule(r['request_id'],r['capsule_id'])).hexdigest()==r['capsule_id'])
                    try:svc.submission_review(r['request_id'])
                    except ValueError:check(r['role']+' attempted decision cannot be rearmed',True)
                    else:check(r['role']+' attempted decision cannot be rearmed',False)
            # Immutable configuration mutation is exercised only on this owned
            # disposable test workspace and restored to its exact original bytes.
            config_path=workspace/'nodes/node0/config/config.toml';original=read_private(config_path)
            config_path.write_bytes(original+b'\n# changed fixture configuration\n')
            try:
                try:load_configuration(workspace)
                except ValueError:check('modified node configuration is refused before restart',True)
                else:check('modified node configuration is refused before restart',False)
            finally:config_path.write_bytes(original)
            report['status']='passed';report['validator_count']=4;report['operator_created_anchor']=True
    except Exception as exc:
        report['status']='failed';report['error_type']=type(exc).__name__
    finally:
        password=None
        if web is not None:web.shutdown();web.server_close()
        if thread is not None:thread.join(3)
        if net is not None:
            if 'shutdown' not in report:report['shutdown']=net.stop()
            if report['shutdown']['warnings']:report['status']='failed'
        private_new(output/'result.json',encode(report))
    return report
