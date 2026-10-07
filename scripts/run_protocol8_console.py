#!/usr/bin/env python3
"""Actual terminal console over the unchanged payment/four-validator journey."""
import argparse,json,subprocess,sys,time
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
sys.path[:0]=[str(ROOT/'src'),str(ROOT/'scripts'),str(ROOT/'tools/payment-console/src')]
import protocol8_transfer as n
import protocol8_wallet_cli as cli
from protocol8_notes import statement
import run_protocol8_payment as payment
import run_protocol8_wallet_cli as old
import payment_console as console

ACTIVE=None
EXTRA=('tools/payment-console/src/payment_console.py','tools/release/check_protocol8_console.py','tests/test_protocol8_console.py')
EXPECTED=('inventory','doctor','status','status','submit','submit','review','submit','submit','status',
    'submit','submit','status','status','status','reconcile','reconcile','reconcile','reconcile')
REFUSALS={5,6,11,12,13,14}
CHECKS=('inherited_actual_payment_wallet_gate','exact_console_order','actual_console_child_identity',
    'actual_private_review_rendered_and_redacted','cancel_without_wallet_or_transport_effect',
    'one_confirmed_original_submission','signed_states_rendered_distinctly','all_console_children_reaped',
    'no_private_intent_values_retained','source_unchanged')
CLAIMS={'actual_local_terminal_console':True,'protected_private_intent_projection':True,
    'explicit_exact_wire_confirmation':True,'cancellation_before_payment_child':True,
    'one_actual_payment_rpc_request':True,'synthetic_funds':True,'one_trusted_host':True,
    'automatic_retry':False,'freshness_established':False,'production_ready':False,
    'actual_process_kill_at_marker':False,'private_review_values_retained':False}

class Network(payment.Network):
    def __init__(self,*args):
        super().__init__(*args)
        global ACTIVE;ACTIVE=self
        self.cs={'invocations':[],'responses':[],'forced_cleanup':[],'cancellation':{},'legacy_refusal_positions':[]}
        self.report['console']=self.cs;self.console_raw=[];self.first_interruption=True;self.cancelled=False
    def console_call(self,row,command,*,journal=None,endpoint=None,packet=None,cancel=False,expect_refusal=False):
        wallet=row['wallet'];journal=journal or row['journal'];endpoint=endpoint or self.endpoint
        receipt=self.io/('console-receipt-'+str(len(self.cs['invocations'])))
        cmd=[sys.executable,'-B',str(ROOT/'scripts/protocol8_console.py'),'--workspace',str(wallet['workspace']),
            '--genesis-sha256',self.genesis_sha256,'--credentials',str(wallet['credentials']),'--receipt',str(receipt),command]
        if command not in ('inventory','doctor'):
            cmd+=['--txid',row['txid'],'--endpoint',endpoint,'--journal',str(journal)]
        if packet is not None:cmd+=['--packet',str(packet)]
        wire=bytes.fromhex(next(x['raw'] for x in self.plain(wallet)['obligations'] if x['raw'] and n.txid(bytes.fromhex(x['raw']))==row['txid']))
        confirmation=b'\n' if cancel else ('SUBMIT '+row['txid']+' '+n.sha(wire)+'\n').encode()
        started=time.monotonic();proc=subprocess.Popen(cmd,stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=subprocess.PIPE,start_new_session=True)
        identity=old.process_identity(proc.pid);n.need(identity is not None,'console birth missing');text=err=b''
        try:text,err=proc.communicate(confirmation,timeout=960)
        finally:
            if proc.poll() is None:self.cs['forced_cleanup'].extend(old.abort_owned_tree(proc))
        n.need(not err and len(text)<=16384,'console human output bound')
        raw=cli.read_file(receipt,2*1024**2,private=True);value=json.loads(raw)
        n.need(raw==n.canonical(value)+b'\n' and value['pid']==proc.pid and value['start_ticks']==identity[0],'console receipt identity differs')
        n.need(proc.returncode==(1 if expect_refusal else 0) and (value['status']=='refused')==expect_refusal,'console refusal differs')
        plain=self.plain(wallet);held=next(x for x in plain['obligations'] if x['raw']==wire.hex())
        _,w=statement(bytes.fromhex(held['private_request']),self.report['genesis'])
        rendered=text.decode('utf-8');private_rendered=False;sanitized=[]
        private_lines={'Recipient: ':w[11],'Amount: ':str(n.integer(w[12]))+' atomic units',
            'Payment expiry: ':str(n.integer(w[13]))+' (protocol height)'}
        for line in rendered.splitlines():
            matched=next((prefix for prefix in private_lines if line.startswith(prefix)),None)
            if matched:
                n.need(line==matched+private_lines[matched],'private intent rendered from wrong data')
                sanitized.append(matched+'[private intent omitted]');private_rendered=True
            else:sanitized.append(line)
        n.need(not private_rendered or command in ('review','submit'),'unexpected private rendering')
        n.need('Automatic retry: disabled' in rendered and (value['view']['can_submit'] is False or command=='review'),'console retry view differs')
        entry={'command':command,'pid':proc.pid,'start_ticks':identity[0],'exit_code':proc.returncode,
            'process_reaped':proc.poll() is not None,'elapsed_seconds':round(time.monotonic()-started,6),
            'script_sha256':n.sha((ROOT/'scripts/protocol8_console.py').read_bytes()),
            'receipt_bytes':len(raw),'receipt_sha256':n.sha(raw),'private_stdout_bytes':len(text),
            'private_stdout_sha256':n.sha(text),'private_stdout_retained':False,
            'private_render_checked':private_rendered,'sanitized_stdout':'\n'.join(sanitized)+'\n'}
        self.cs['invocations'].append(entry);self.cs['responses'].append(value);self.console_raw.append(raw)
        return value
    def interrupted(self,wallet,ident):
        row={'wallet':wallet,'txid':ident,'journal':self.io/'alice-interrupted'}
        self.console_call(row,'inventory');self.console_call(row,'doctor')
        return super().interrupted(wallet,ident)
    def payment_call(self,row,command,*,journal=None,endpoint=None,packet=None,expect_refusal=False):
        if expect_refusal:
            original=super().payment_call(row,command,journal=journal,endpoint=endpoint,packet=packet,expect_refusal=True)
            self.cs['legacy_refusal_positions'].append(len(self.p['invocations']))
            self.console_call(row,command,journal=journal,endpoint=endpoint,packet=packet,expect_refusal=True)
            return original
        if command=='submit' and not self.cancelled:
            self.console_call(row,'review')
            before=self.plain(row['wallet']);before_sha=n.sha(row['wallet']['path'].read_bytes());before_requests=len(self.p['proxy_requests'])
            before_journal=row['journal'].exists();n.need(not before_journal,'cancel fixture requires no existing journal')
            cancelled=self.console_call(row,'submit',cancel=True)
            after=self.plain(row['wallet']);after_sha=n.sha(row['wallet']['path'].read_bytes())
            n.need(before==after and before_sha==after_sha and not row['journal'].exists() and
                len(self.p['proxy_requests'])==before_requests==0 and cancelled['view']['state']=='cancelled','cancel changed payment authority')
            n.need(not any(x['kind']=='payment' for x in cancelled['child_invocations']),'cancel started a payment child')
            self.cs['cancellation']={'wallet_sha256_before':before_sha,'wallet_sha256_after':after_sha,
                'wallet_unchanged':True,'journal_exists_before':before_journal,'journal_exists_after':row['journal'].exists(),
                'proxy_requests_before':before_requests,'proxy_requests_after':len(self.p['proxy_requests']),
                'private_render_checked':self.cs['invocations'][-1]['private_render_checked'],'payment_child_started':False}
            self.cancelled=True
        value=self.console_call(row,command,journal=journal,endpoint=endpoint,packet=packet)
        payments=[(call,response) for call,response in zip(value['child_invocations'],value['child_responses']) if call['kind']=='payment']
        n.need(len(payments)==1,'successful console requires one protected payment child')
        call,response=payments[0];n.need(response['command']==command and response['status']!='refused','successful child command differs')
        self.p['invocations'].append({k:v for k,v in call.items() if k not in ('kind','diagnostic_present')}|
            {'wallet_id':row['wallet']['secret']['wallet_id'],'txid':row['txid']})
        self.p['responses'].append(response);self.payment_raw.append(n.canonical(response)+b'\n')
        return response

def run(args):
    output=args.output.absolute();n.need(not output.exists(),'fresh console output required')
    linked=output.with_name(output.stem+'.payment.json');prior_network=payment.Network;prior_source=payment.gate.source
    def source():
        value=prior_source()
        for name in EXTRA:
            b=(ROOT/name).read_bytes();value['files'][name]={'bytes':len(b),'sha256':n.sha(b)}
        value['files']=dict(sorted(value['files'].items()));return value
    payment.Network=Network;payment.gate.source=source
    try:params=argparse.Namespace(**vars(args));params.output=linked;code=payment.run(params)
    finally:payment.Network=prior_network;payment.gate.source=prior_source
    parent=json.loads(linked.read_bytes());inner=json.loads((linked.parent/parent['wallet_report']).read_bytes())
    cs=inner.get('console',{});calls=cs.get('invocations',[]);responses=cs.get('responses',[])
    views=[x['view']['state'] for x in responses];cancel=cs.get('cancellation',{})
    succeeded=[x for x in responses if x['command']=='submit' and x['view'].get('confirmation')=='exact-txid-and-wire']
    checks=[code==0,tuple(x['command'] for x in calls)==EXPECTED and {i for i,x in enumerate(calls,1) if x['exit_code']==1}==REFUSALS,
        len(calls)==len(responses)==19 and all(x['process_reaped'] for x in calls),
        sum(x['private_render_checked'] for x in calls)==3 and all(not x['private_stdout_retained'] for x in calls),
        bool(cancel) and cancel.get('wallet_unchanged') is True and cancel.get('payment_child_started') is False and cancel.get('proxy_requests_after')==0,
        len(succeeded)==1 and succeeded[0]['view'].get('review_revalidated') is True and len(parent['payment_caller']['proxy_requests'])==1,
        views[-4:]==['unresolved-held','executed-exact','executed-exact','conflict-held'],
        not cs.get('forced_cleanup') and all(not x['forced_cleanup'] and all(c['process_reaped'] for c in x['child_invocations']) for x in responses),
        all(x['private_review_values_retained'] is False for x in responses),source()==parent['source']]
    raw=b''.join(ACTIVE.console_raw if ACTIVE else []);log=output.with_name(output.stem+'.console.jsonl');n.need(not log.exists(),'fresh console raw log required');log.write_bytes(raw)
    result={'format':'1soft/protocol8-console-gate/v1','status':'qualified-one-host-payment-console' if all(checks) else 'failed',
        'source':parent['source'],'payment_report':linked.name,'payment_report_sha256':n.sha(linked.read_bytes()),
        'console':cs,'logs':{'console':{'name':log.name,'bytes':len(raw),'sha256':n.sha(raw)}},
        'claims':CLAIMS,'checks':[{'id':name,'passed':bool(ok)} for name,ok in zip(CHECKS,checks)]}
    output.write_bytes(n.canonical(result)+b'\n');return 0 if all(checks) else 1

if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__)
    for name in ('engine','worker','helper','fixture','prover','kat','output'):parser.add_argument('--'+name,type=Path,required=True)
    raise SystemExit(run(parser.parse_args()))
