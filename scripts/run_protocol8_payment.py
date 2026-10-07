#!/usr/bin/env python3
"""Actual payment caller through the unchanged four-validator wallet journey.

An owned loopback proxy forwards one exact request to the real node, then closes
without returning its actual admission reply. Interruption state is constructed
separately using a real encrypted-wallet attempt marker; no process kill is claimed.
"""
import argparse,http.client,json,os,socket,subprocess,sys,threading,time
from http.server import BaseHTTPRequestHandler,HTTPServer
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1];sys.path.insert(0,str(ROOT/'src'))
import protocol8_transfer as n
import protocol8_payment as payment
import protocol8_wallet_cli as cli
import run_protocol8_wallet as gate
import run_protocol8_wallet_cli as old

ACTIVE=None
CHECKS=('inherited_actual_wallet_gate','four_wallet_native_initializations','four_static_doctors',
 'wallet_boundaries_retained','exact_wallet_command_order','exact_payment_command_order',
 'actual_one_request_lost_reply','interrupted_marker_recognized_without_send','original_recovery_and_conflict',
 'all_caller_processes_reaped','all_caller_native_calls_reaped','private_material_absent','source_unchanged')
CLAIMS={'actual_local_payment_caller':True,'one_trusted_host':True,'synthetic_funds':True,
 'loopback_only':True,'one_actual_payment_rpc_request':True,'lost_reply_reconciliation':True,
 'constructed_interruption_state':True,'actual_process_kill_at_marker':False,
 'automatic_retry':False,'freshness_established':False,'production_ready':False,'public_network':False,
 'production_key_management':False,'local_rollback_resistance':False}
# Reuse the frozen old journey, substituting four reconciliations and the first
# marker with caller operations; add Alice's actual marker for interruption state.
REMOVED={34,36,38,40,51}
EXPECTED_WALLET=tuple(command for i,name in enumerate(old.EXPECTED_COMMANDS,1)
    if i not in REMOVED for command in ((name,'mark-attempt') if i==28 else (name,)))
EXPECTED_WALLET_REFUSALS=set()
position=0
for i,name in enumerate(old.EXPECTED_COMMANDS,1):
    if i in REMOVED:continue
    position+=1
    if i in old.EXPECTED_REFUSALS:EXPECTED_WALLET_REFUSALS.add(position)
    if i==28:position+=1
EXPECTED_PAYMENT=('status','status','submit','submit','submit','status','submit','submit','status','status','status',
    'reconcile','reconcile','reconcile','reconcile')
EXPECTED_PAYMENT_REFUSALS={3,4,7,8,9,10}

class Network(old.Network):
    def __init__(self,*args):
        super().__init__(*args)
        global ACTIVE;ACTIVE=self
        self.payments={};self.pending=None;self.payment_raw=[];self.proxy_reply=None
        self.p={'invocations':[],'responses':[],'proxy_requests':[],'fixture_broadcasts':[],
            'journal_receipts':[],'interruption':{},'forced_cleanup':[]}
        self.report['payment_caller']=self.p
        owner=self
        class Handler(BaseHTTPRequestHandler):
            def log_message(self,*args):pass
            def do_POST(self):
                connection=None
                try:
                    size=int(self.headers['Content-Length']);n.need(0<size<=8192,'proxy request bound')
                    raw=self.rfile.read(size);value=json.loads(raw)
                    import base64
                    wire=base64.b64decode(value['params']['tx'],validate=True)
                    n.need(value=={'jsonrpc':'2.0','id':1,'method':'broadcast_tx_sync',
                        'params':{'tx':base64.b64encode(wire).decode()}},'exact proxy request required')
                    row=owner.pending;n.need(row is not None and n.txid(wire)==row['txid'],'proxy original wire differs')
                    plain=owner.plain(row['wallet']);obligation=next(x for x in plain['obligations'] if x['raw']==wire.hex())
                    journal=json.loads(row['journal'].read_bytes())['record']
                    n.need(obligation['attempts']==1 and journal['phase']=='attempt-marked','durable marker must precede request')
                    n.need(not owner.p['proxy_requests'],'only one actual forwarded request permitted')
                    connection=http.client.HTTPConnection('127.0.0.1',owner.http[0],timeout=90)
                    connection.request('POST','/',body=raw,headers={'Content-Type':'application/json'})
                    response=connection.getresponse();reply=response.read(8193)
                    n.need(response.status==200 and len(reply)<=8192,'real node reply bound')
                    result=json.loads(reply)['result'];n.need(type(result['code']) is int and result['code']==0,'real node admission refused')
                    n.need(result['hash'].lower()==n.sha(wire),'real node wire identity differs')
                    owner.proxy_reply=result
                    owner.p['proxy_requests'].append({'request_bytes':len(raw),'request_sha256':n.sha(raw),
                        'txid':n.txid(wire),'wire_sha256':n.sha(wire),'wire_bytes':len(wire),
                        'wallet_attempts_before_io':1,'journal_phase_before_io':journal['phase'],
                        'actual_node_admission_code':result['code'],'actual_node_wire_hash':result['hash'].lower(),
                        'reply_forwarded':False,'upstream_response_bytes':len(reply),'upstream_response_sha256':n.sha(reply)})
                except Exception as exc:owner.p['proxy_error_type']=type(exc).__name__
                finally:
                    if connection is not None:connection.close()
                    self.close_connection=True
                    try:self.connection.shutdown(socket.SHUT_RDWR)
                    except OSError:pass
        self.proxy=HTTPServer(('127.0.0.1',0),Handler);self.endpoint='http://127.0.0.1:'+str(self.proxy.server_port)
        self.thread=threading.Thread(target=self.proxy.serve_forever);self.thread.start()
    def payment_call(self,row,command,*,journal=None,endpoint=None,packet=None,expect_refusal=False):
        journal=journal or row['journal'];endpoint=endpoint or self.endpoint
        wallet=row['wallet'];cmd=[sys.executable,'-B',str(ROOT/'scripts/protocol8_payment.py'),
            '--workspace',str(wallet['workspace']),'--genesis-sha256',self.genesis_sha256,
            '--credentials',str(wallet['credentials']),'--endpoint',endpoint,'--journal',str(journal),'--txid',row['txid'],command]
        if packet is not None:cmd+=['--packet',str(packet)]
        started=time.monotonic();proc=subprocess.Popen(cmd,stdout=subprocess.PIPE,stderr=subprocess.PIPE,start_new_session=True)
        ticks=old.process_identity(proc.pid)[0];raw=err=b''
        try:raw,err=proc.communicate(timeout=480)
        finally:
            if proc.poll() is None:self.p['forced_cleanup'].extend(old.abort_owned_tree(proc))
            self.p['invocations'].append({'command':command,'pid':proc.pid,'start_ticks':ticks,
                'wallet_id':wallet['secret']['wallet_id'],'txid':row['txid'],'exit_code':proc.returncode,
                'process_reaped':proc.poll() is not None,'elapsed_seconds':round(time.monotonic()-started,6),
                'script_sha256':n.sha((ROOT/'scripts/protocol8_payment.py').read_bytes())})
        n.need(not err and len(raw)<=384*1024,'payment reply/diagnostic bound')
        result=json.loads(raw);n.need(raw==n.canonical(result)+b'\n' and result['pid']==proc.pid and result['start_ticks']==ticks,'payment process identity differs')
        self.p['invocations'][-1].update(stdout_sha256=n.sha(raw),stdout_bytes=len(raw))
        self.payment_raw.append(raw);self.p['responses'].append(result)
        n.need(proc.returncode==(1 if expect_refusal else 0) and (result['status']=='refused')==expect_refusal,'payment refusal expectation differs')
        return result
    def interrupted(self,wallet,ident):
        row={'wallet':wallet,'txid':ident,'journal':self.io/'alice-interrupted'};self.payments[wallet['path']]=row
        args=argparse.Namespace(journal=row['journal'],txid=ident,genesis_sha256=self.genesis_sha256,endpoint=self.endpoint)
        plain=self.plain(wallet);wire=bytes.fromhex(next(x['raw'] for x in plain['obligations'] if x['raw'] and n.txid(bytes.fromhex(x['raw']))==ident))
        config=json.loads((wallet['workspace']/'wallet-cli.json').read_bytes())
        record={**payment.base_record(args,wallet['workspace'],config,wire),'phase':'prepared','admission_code':None}
        payment.save(row['journal'],record,payment.journal_key(wallet['secret']),initial=True)
        before=self.payment_call(row,'status');n.need(before['submission_state']=='prepared-not-attempted' and before['wallet_attempts']==0,'constructed prepared state differs')
        self.call(wallet,'mark-attempt',['--txid',ident])
        after=self.payment_call(row,'status');n.need(after['submission_state']=='attempt-record-incomplete' and after['wallet_attempts']==1,'actual durable marker not recovered')
        self.payment_call(row,'submit',expect_refusal=True)
        fresh=self.io/'alice-second-journal';self.payment_call(row,'submit',journal=fresh,expect_refusal=True);n.need(not fresh.exists(),'fresh journal bypassed held marker')
        self.p['interruption']={'txid':ident,'wallet_id':wallet['secret']['wallet_id'],
            'before_state':before['submission_state'],'after_state':after['submission_state'],
            'wallet_attempts_before':0,'wallet_attempts_after':1,'request_count':len(self.p['proxy_requests']),
            'constructed_prepared_journal':True,'actual_wallet_marker_command':True,'process_kill_induced':False}
    def broadcast(self,index,wire):
        if self.pending is None or n.txid(wire)!=self.pending['txid']:
            fixtures=self.paths['fixtures']
            names=[name for name in ('first.tx','executed-competing.tx') if (fixtures/name).exists() and (fixtures/name).read_bytes()==wire]
            n.need(index==0 and len(names)==1,'only original funding/competitor fixture routing permitted')
            result=super().broadcast(index,wire)
            self.p['fixture_broadcasts'].append({'fixture':names[0],'txid':n.txid(wire),'wire_sha256':n.sha(wire),'admission_code':int(result['code'])})
            return result
        n.need(index==0 and self.pending is not None and n.txid(wire)==self.pending['txid'],'exact original caller binding')
        row=self.pending;reply=self.payment_call(row,'submit')
        n.need(reply['submission_state']=='attempted-outcome-unknown' and not reply['execution_confirmed'] and reply['transport_attempts']==1,'lost reply was not unknown')
        self.payment_call(row,'status')
        self.payment_call(row,'submit',expect_refusal=True)
        fresh=self.io/'bob-second-journal';self.payment_call(row,'submit',journal=fresh,expect_refusal=True);n.need(not fresh.exists(),'held wallet allowed a fresh attempt')
        self.payment_call(row,'status',endpoint='http://127.0.0.1:1',expect_refusal=True)
        original=row['journal'].read_bytes();bad=json.loads(original);bad['record']['phase']='admission-accepted';bad['record']['admission_code']=0
        row['journal'].write_bytes(n.canonical(bad))
        self.payment_call(row,'status',expect_refusal=True);row['journal'].write_bytes(original)
        self.payment_call(row,'status')
        n.need(len(self.p['proxy_requests'])==1 and self.proxy_reply is not None and not self.p.get('proxy_error_type'),'real forwarded admission receipt missing')
        # The inherited fixture checks the real node's captured admission code,
        # then discards it. The production caller never received this reply.
        return self.proxy_reply
    def close(self):
        try:
            for row in self.payments.values():
                if row['journal'].exists():
                    raw=row['journal'].read_bytes()
                    self.p['journal_receipts'].append({'wallet_id':row['wallet']['secret']['wallet_id'],
                        'txid':row['txid'],'bytes':len(raw),'sha256':n.sha(raw),'envelope':json.loads(raw)})
            self.proxy.shutdown();self.thread.join(timeout=5);self.proxy.server_close()
            n.need(not self.thread.is_alive(),'owned proxy did not stop')
            self.p['proxy_stopped']=True
        finally:super().close()

class Wallet(old.Wallet):
    def prepare(self,prover,commitment,**kw):
        ident=super().prepare(prover,commitment,**kw)
        if kw['request']==gate.field(81):self.h.interrupted(self.row,ident)
        return ident
    def mark_attempt(self,ident):
        if self.path not in self.h.payments:
            row={'wallet':self.row,'txid':ident,'journal':self.h.io/'bob-payment'}
            self.h.payments[self.path]=row;self.h.pending=row
        else:super().mark_attempt(ident)
    def reconcile(self,ident):
        row=self.h.payments.get(self.path)
        if row is None:return super().reconcile(ident)
        n.need(row['txid']==ident,'caller original binding differs')
        observation=self.h.plain(self.row)['observations'][-1]
        packet=self.h.file(n.canonical({'witness':observation['witness'],'signed_header':observation['signed_header']}))
        return self.h.payment_call(row,'reconcile',packet=packet)['result']

def run(args):
    output=args.output.absolute();n.need(not output.exists(),'fresh payment report required')
    inner=output.with_name(output.stem+'.wallet.json');oldnetwork=gate.Network;oldwallet=gate.RecipientWallet
    class ConfiguredNetwork(Network):
        def __init__(self,*kw):
            super().__init__(*kw);self.report['wallet_cli_inputs']={name:str(getattr(args,name)) for name in ('helper','prover')}
    gate.Network=ConfiguredNetwork;gate.RecipientWallet=Wallet
    try:params=argparse.Namespace(**vars(args));params.output=inner;code=gate.run(params)
    finally:gate.Network=oldnetwork;gate.RecipientWallet=oldwallet
    r=json.loads(inner.read_bytes());e=r.get('wallet_cli',{});p=r.get('payment_caller',{})
    responses=e.get('responses',[])+p.get('responses',[]);audits=[a for x in responses for a in x['native_audits'].values()]
    context=n.canonical(r.get('genesis',{}))+b''.join(x.read_bytes().hex().encode() for x in inner.with_name(inner.name+'.artifacts').glob('*.tx'))
    needles=[x for x in (ACTIVE.needles if ACTIVE else []) if x and x not in context]
    material=n.canonical(r)+b''.join(x.read_bytes() for x in inner.with_name(inner.name+'.artifacts').iterdir() if x.is_file())
    validorder=lambda calls,names,refusals:tuple(x['command'] for x in calls)==names and {i for i,x in enumerate(calls,1) if x['exit_code']==1}==refusals
    interruption=p.get('interruption',{});proxy=p.get('proxy_requests',[])
    checks=[code==0,len(e.get('initializations',[]))==4 and all(x['native_startup']['valid_proof_verified'] and x['native_startup']['corrupt_proof_refused'] for x in e.get('initializations',[])),
        len(e.get('doctors',[]))==4 and all(x['files_unchanged'] and not x['native_executed'] for x in e.get('doctors',[])),
        all(e.get(k) is True for k in ('bad_pin_refused','duplicate_owner_refused','early_delivery_refused','output_overwrite_refused')),
        validorder(e.get('invocations',[]),EXPECTED_WALLET,EXPECTED_WALLET_REFUSALS),validorder(p.get('invocations',[]),EXPECTED_PAYMENT,EXPECTED_PAYMENT_REFUSALS),
        len(proxy)==1 and len(p.get('fixture_broadcasts',[]))==2 and proxy[0]['wallet_attempts_before_io']==1 and proxy[0]['journal_phase_before_io']=='attempt-marked' and not proxy[0]['reply_forwarded'] and p.get('proxy_stopped') is True and not p.get('proxy_error_type'),
        interruption.get('before_state')=='prepared-not-attempted' and interruption.get('after_state')=='attempt-record-incomplete' and interruption.get('request_count')==0 and interruption.get('process_kill_induced') is False,
        any(x.get('result')==r.get('recovery') for x in p.get('responses',[])) and any(x.get('result')==r.get('conflict_resolution') for x in p.get('responses',[])),
        not e.get('forced_cleanup') and not p.get('forced_cleanup') and all(x['process_reaped'] and x['exit_code'] in (0,1) for x in e.get('invocations',[])+p.get('invocations',[])),
        bool(audits) and all(a['call_count']==a['reaped_count']==a['retained_count']==len(a['calls'])<=512 and a['timeout_count']==0 for a in audits),
        all(x not in material for x in needles),gate.source()==r['source']]
    logs={}
    for name,raws in (('wallet',ACTIVE.raw_responses if ACTIVE else []),('payment',ACTIVE.payment_raw if ACTIVE else [])):
        path=output.with_name(output.stem+'.'+name+'.jsonl');n.need(not path.exists(),'fresh raw caller log required');path.write_bytes(b''.join(raws))
        logs[name]={'name':path.name,'bytes':path.stat().st_size,'sha256':n.sha(path.read_bytes())}
    result={'format':'1soft/protocol8-payment-gate/v1','status':'qualified-one-host-payment-caller' if all(checks) else 'failed',
        'source':r['source'],'wallet_report':inner.name,'wallet_report_sha256':n.sha(inner.read_bytes()),'logs':logs,
        'wallet_cli':e,'payment_caller':p,'claims':CLAIMS,'checks':[{'id':name,'passed':bool(ok)} for name,ok in zip(CHECKS,checks)]}
    output.write_bytes(n.canonical(result)+b'\n');return 0 if all(checks) else 1

if __name__=='__main__':
    p=argparse.ArgumentParser(description=__doc__)
    for name in ('engine','worker','helper','fixture','prover','kat','output'):p.add_argument('--'+name,type=Path,required=True)
    raise SystemExit(run(p.parse_args()))
