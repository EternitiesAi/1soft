#!/usr/bin/env python3
"""Actual lifecycle console children through the unchanged four-validator journey."""
import argparse,json,os,subprocess,sys,time
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
sys.path[:0]=[str(ROOT/'src'),str(ROOT/'scripts'),str(ROOT/'tools/payment-console/src')]
import protocol8_transfer as n
import protocol8_wallet_cli as cli
from protocol8_notes import statement
from protocol8_worker import Worker
import run_protocol8_console as parent
import run_protocol8_wallet_cli as old
import payment_console as console

ACTIVE=None
OUTPUT=None
LINKED=(5,6,7,8,9,10,13,14,15,19,22,23,None,24,25,26,27,28,30,31,36,40,43,44,46,47,49,50,51,52,None,None,None,None,None)
EXPECTED=('observe','import-note','import-note','import-note','import-note','import-note','observe',
    'import-note','import-note','import-note','observe','import-note','prepare','prepare','deliver',
    'export','export','prepare','export','prepare','observe','deliver','observe','import-note','export',
    'observe','observe','observe','import-note','import-note','prepare','export','prepare','deliver','observe')
REFUSALS={2,3,4,5,6,8,15,17,20,27,28,29,30,33,34,35}
PREPARES={13,14,18,20,31,33}
CHECKS=('inherited_actual_console_gate','literal_lifecycle_sequence','actual_nested_wallet_identity',
    'private_preparation_display_checked','preparation_cancel_without_effect','durable_preproof_holds',
    'received_input_prepared_original','private_delivery_recipient_import','recipient_native_respend_prepared',
    'recipient_respend_input_held','refusal_wallet_bytes_unchanged','all_lifecycle_processes_reaped',
    'private_material_absent','source_unchanged')
CLAIMS={'actual_lifecycle_console':True,'synthetic_funds':True,'one_trusted_host':True,
    'recipient_respend_prepared':True,'recipient_respend_chain_executed':False,
    'preparation_is_submission':False,'automatic_retry':False,'freshness_established':False,
    'production_ready':False,'private_openings_retained':False}
EXTRA=('scripts/run_protocol8_journey.py','tools/release/check_protocol8_journey.py')

class Network(parent.Network):
    def __init__(self,*args):
        super().__init__(*args)
        global ACTIVE;ACTIVE=self
        self.j={'invocations':[],'responses':[],'forced_cleanup':[],'preproof_holds':[],
            'cancellation':{},'recipient_respend':{},'late_refusals':{}}
        self.report['journey']=self.j;self.jraw=[];self.prepare_cancelled=False

    def life_call(self,row,command,extra,*,linked=None,cancel=False,hold_request=None,bad_pin=False):
        receipt=self.io/('journey-receipt-'+str(len(self.j['invocations'])))
        genesis='ef'*32 if bad_pin else self.genesis_sha256
        cmd=[sys.executable,'-B',str(ROOT/'scripts/protocol8_console.py'),'--workspace',str(row['workspace']),
            '--genesis-sha256',genesis,'--credentials',str(row['credentials']),'--receipt',str(receipt),command,*map(str,extra)]
        fields=dict(zip(extra[::2],extra[1::2])) if command=='prepare' else {}
        confirmation=('PREPARE '+str(fields['--commitment'])+'\n').encode() if command=='prepare' and not cancel else b'\n'
        before=row['path'].read_bytes();plain_before=self.plain(row);requests_before=len(self.p['proxy_requests'])
        blind=os.urandom(32);started=time.monotonic();hold=None
        proc=subprocess.Popen(cmd,stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=subprocess.PIPE,start_new_session=True)
        identity=old.process_identity(proc.pid);n.need(identity is not None,'lifecycle console birth unavailable')
        try:
            if hold_request is not None:
                proc.stdin.write(confirmation);proc.stdin.flush()
                def held():
                    n.need(proc.poll() is None,'console exited before native preproof hold')
                    item=next((x for x in self.plain(row)['obligations'] if x['request']==hold_request),None)
                    return item and item['raw'] is None and item['attempts']==0
                old.wait_until(held,180)
                children=[int(x) for x in Path(f'/proc/{proc.pid}/task/{proc.pid}/children').read_text().split()]
                n.need(len(children)==1,'one live wallet child required before proof')
                child_identity=old.process_identity(children[0]);n.need(child_identity is not None,'wallet child birth missing')
                hold={'request':hold_request,'pid':children[0],'start_ticks':child_identity[0],
                    'encrypted_file_sha256':n.sha(row['path'].read_bytes()),'wire_absent':True,'attempts':0}
                text,err=proc.communicate(timeout=960)
            else:text,err=proc.communicate(confirmation,timeout=960)
        finally:
            if proc.poll() is None:self.j['forced_cleanup'].extend(old.abort_owned_tree(proc))
        n.need(not err and 0<len(text)<=16384,'lifecycle human stream bound')
        raw=cli.read_file(receipt,2*1024**2,private=True);value=json.loads(raw)
        n.need(raw==n.canonical(value)+b'\n' and (value['pid'],value['start_ticks'])==(proc.pid,identity[0]),'lifecycle receipt identity differs')
        n.need(proc.returncode==(1 if value['status']=='refused' else 0),'lifecycle exit differs')
        rendered=[];sanitized=[]
        private={'Recipient: ':str(fields.get('--destination')),
            'Amount: ':str(fields.get('--payment'))+' atomic units',
            'Payment expiry: ':str(fields.get('--payment-expiry'))+' (protocol height)'}
        for line in text.decode().splitlines():
            prefix=next((x for x in private if line.startswith(x)),None)
            if prefix:
                n.need(command=='prepare' and line==prefix+private[prefix],'private preparation display differs')
                rendered.append(prefix);sanitized.append(prefix+'[private intent omitted]')
            else:sanitized.append(line)
        n.need(rendered==(list(private) if command=='prepare' else []),'private preparation display missing or duplicated')
        after=row['path'].read_bytes();plain_after=self.plain(row)
        if value['status']=='refused':n.need(before==after and plain_before==plain_after,'refusal changed wallet')
        n.need(len(self.p['proxy_requests'])==requests_before,'lifecycle contacted payment endpoint')
        if hold is not None:
            child=value['child_responses'][0]
            n.need((child['pid'],child['start_ticks'])==(hold['pid'],hold['start_ticks']) and child['status']=='original-wire-retained',
                'preproof hold not bound to actual wallet child')
            self.j['preproof_holds'].append(hold)
        if command=='prepare' and value['status']!='refused' and not cancel:
            child=value['child_responses'][0];item=next(x for x in plain_after['obligations'] if x['request']==fields['--request'])
            wire=bytes.fromhex(item['raw']);public,witness=statement(bytes.fromhex(item['private_request']),self.report['genesis'])
            n.need(item['input']==fields['--commitment'] and item['attempts']==0 and item['result'] is None and
                child['txid']==n.txid(wire) and witness[11]==fields['--destination'] and
                n.integer(witness[12])==fields['--payment'] and n.integer(witness[13])==fields['--payment-expiry'] and
                n.integer(public[8])==fields['--valid-until'],'prepared original differs from explicit input')
        entry={'command':command,'linked_wallet_ordinal':linked,'wallet_id':row['secret']['wallet_id'],
            'pid':proc.pid,'start_ticks':identity[0],'exit_code':proc.returncode,'process_reaped':proc.poll() is not None,
            'elapsed_seconds':round(time.monotonic()-started,6),'script_sha256':n.sha((ROOT/'scripts/protocol8_console.py').read_bytes()),
            'receipt_bytes':len(raw),'receipt_sha256':n.sha(raw),'private_stdout_bytes':len(text),
            'private_stdout_commitment':n.sha(parent.STDOUT_DOMAIN+blind+text),'private_stdout_commitment_scheme':parent.STDOUT_SCHEME,
            'private_stdout_blind_retained':False,'private_stdout_retained':False,'private_render_checked':bool(rendered),
            'sanitized_stdout':'\n'.join(sanitized)+'\n','wallet_sha256_before':n.sha(before),'wallet_sha256_after':n.sha(after),
            'refusal_wallet_unchanged':before==after if value['status']=='refused' else None,
            'proxy_requests_before':requests_before,'proxy_requests_after':len(self.p['proxy_requests'])}
        self.j['invocations'].append(entry);self.j['responses'].append(value);self.jraw.append(raw)
        if cancel:
            n.need(before==after and plain_before==plain_after and not value['child_invocations'] and
                value['view']['state']=='preparation-cancelled' and requests_before==0,'prepare cancellation had an effect')
            self.j['cancellation']={'wallet_sha256_before':n.sha(before),'wallet_sha256_after':n.sha(after),
                'wallet_unchanged':True,'wallet_child_started':False,'payment_child_started':False,
                'proxy_requests_before':requests_before,'proxy_requests_after':len(self.p['proxy_requests'])}
        return value,hold

    def call(self,row,command,extra=(),*,bad_pin=False,hold_request=None):
        if command not in console.LIFECYCLE:return super().call(row,command,extra,bad_pin=bad_pin,hold_request=hold_request)
        linked=len(self.e['invocations'])+1
        if command=='prepare' and not self.prepare_cancelled:
            self.life_call(row,command,extra,cancel=True);self.prepare_cancelled=True
        value,hold=self.life_call(row,command,extra,linked=linked,hold_request=hold_request,bad_pin=bad_pin)
        n.need(len(value['child_invocations'])==len(value['child_responses'])==1,'one actual nested wallet call required')
        child=value['child_invocations'][0];reply=value['child_responses'][0]
        n.need(child['kind']=='wallet' and child['command']==command,'nested wallet command differs')
        self.e['invocations'].append({k:v for k,v in child.items() if k not in ('kind','diagnostic_present')}|
            {'wallet_id':row['secret']['wallet_id']})
        self.e['responses'].append(reply);self.raw_responses.append(n.canonical(reply)+b'\n')
        if hold is not None:self.e['preproof_holds'].append(hold)
        self.collect_needles(row)
        if reply['status']=='refused':raise n.Invalid('actual lifecycle wallet refused')
        return reply

    def collect_needles(self,row):
        for item in self.plain(row)['obligations']:
            req=bytes.fromhex(item['private_request']);self.needles.append(req.hex().encode())
            self.needles.extend(req[552+i*32:584+i*32].hex().encode() for i in (0,1,4,5,14,15,17,18))

    def late(self):
        carol=next(row for row in self.wallets.values() if row['path'].parent.name=='carol-wallet')
        bob=next(row for row in self.wallets.values() if row['path'].parent.name=='bob-wallet' and row['path'].name=='wallet')
        incoming=bytes.fromhex(self.report['recovery']['receipt']['raw']);commitment=n.parse(incoming)[10]
        destination=json.loads((bob['workspace']/'wallet-cli.json').read_bytes())['wallet_pins']['recipient_key']
        extra=['--commitment',commitment,'--request',parent.payment.gate.field(91),'--destination',destination,
            '--payment',2,'--valid-until',32,'--payment-expiry',56]
        value,_=self.life_call(carol,'prepare',extra,hold_request=parent.payment.gate.field(91))
        n.need(value['status']!='refused','recipient native respend preparation refused');ident=value['view']['txid']
        private=self.io/'recipient-respend-wire'
        exported,_=self.life_call(carol,'export',['--txid',ident,'--output',private]);wire=cli.read_file(private,3560,private=True)
        worker=Worker(self.paths['worker'],self.report['inputs']['worker']['sha256'],cli.read_file(self.paths['kat'],3560))
        n.need(worker.verify(wire,self.report['genesis']['network']),'recipient native respend proof refused')
        audit=worker.audit();n.need(audit['call_count']==audit['retained_count']==audit['reaped_count'] and not audit['timeout_count'],'respend verifier not reaped')
        target=OUTPUT.with_name(OUTPUT.stem+'.recipient-respend.tx');n.need(not target.exists(),'fresh respend artifact required');target.write_bytes(wire)
        rejected,_=self.life_call(carol,'prepare',[parent.payment.gate.field(92) if x==parent.payment.gate.field(91) else x for x in extra])
        n.need(rejected['status']=='refused','recipient held input reused')
        self.collect_needles(carol)
        self.j['recipient_respend']={'wallet_id':carol['secret']['wallet_id'],'incoming_txid':n.txid(incoming),
            'incoming_commitment':commitment,'txid':ident,'wire_sha256':n.sha(wire),'wire_bytes':len(wire),
            'artifact':target.name,'native_audit':audit,'attempts':0,'completed':False,'chain_executed':False,
            'held_input_refused':True,'exported_exact':exported['view']['output_sha256']==n.sha(wire)}
        link=self.io/'refused-delivery-link';destination_file=self.io/'missing-delivery-target';link.symlink_to(destination_file)
        refused,_=self.life_call(bob,'deliver',['--txid',self.report['recovery']['txid'],'--output',link,'--output-index',10])
        packet=self.file(n.canonical({'witness':self.report['state_witness'],'signed_header':self.report['signed_header']}))
        bad,_=self.life_call(bob,'observe',['--packet',packet],bad_pin=True)
        n.need(refused['status']==bad['status']=='refused' and link.is_symlink() and not destination_file.exists(),'late refusal effects differ')
        self.j['late_refusals']={'delivery_symlink_refused':True,'symlink_unchanged':True,'target_absent':True,'wrong_genesis_refused':True}

    def close(self):
        try:
            if not self.report.get('error') and len(self.e['invocations'])==53:self.late()
        finally:super().close()

def run(args):
    global OUTPUT
    output=args.output.absolute();n.need(not output.exists(),'fresh journey output required');OUTPUT=output
    linked=output.with_name(output.stem+'.console.json');prior_network=parent.Network;prior_source=parent.payment.gate.source
    def source():
        value=prior_source()
        for name in EXTRA:
            raw=(ROOT/name).read_bytes();value['files'][name]={'bytes':len(raw),'sha256':n.sha(raw)}
        value['files']=dict(sorted(value['files'].items()));return value
    parent.Network=Network;parent.payment.gate.source=source
    try:params=argparse.Namespace(**vars(args));params.output=linked;code=parent.run(params)
    finally:parent.Network=prior_network;parent.payment.gate.source=prior_source
    outer=json.loads(linked.read_bytes());payment=json.loads((output.parent/outer['payment_report']).read_bytes())
    inner=json.loads((output.parent/payment['wallet_report']).read_bytes());j=inner.get('journey',{})
    calls=j.get('invocations',[]);responses=j.get('responses',[]);respend=j.get('recipient_respend',{});cancel=j.get('cancellation',{})
    children=[x for r in responses for x in r['child_invocations']]
    same=all(x['refusal_wallet_unchanged'] is True for x in calls if x['exit_code']==1)
    context=n.canonical(inner.get('genesis',{}))+b''.join(p.read_bytes().hex().encode() for p in
        (output.parent/(payment['wallet_report']+'.artifacts')).glob('*.tx'))
    needles=[x for x in (ACTIVE.needles if ACTIVE else []) if x and x not in context]
    material=n.canonical(j)+b''.join(ACTIVE.jraw if ACTIVE else [])
    checks=[code==0,tuple(x['command'] for x in calls)==EXPECTED and tuple(x['linked_wallet_ordinal'] for x in calls)==LINKED and
        {i for i,x in enumerate(calls,1) if x['exit_code']==1}==REFUSALS,
        len(calls)==len(responses)==35 and len(children)==34 and all(c['kind']=='wallet' for c in children),
        {i for i,x in enumerate(calls,1) if x['private_render_checked']}==PREPARES,
        cancel.get('wallet_unchanged') is True and cancel.get('wallet_child_started') is False and cancel.get('proxy_requests_after')==0,
        len(j.get('preproof_holds',[]))==3 and len(inner['wallet_cli']['preproof_holds'])==2,
        len(responses)>13 and responses[8]['view'].get('commitment')==responses[13]['view'].get('commitment') and
            responses[13]['view'].get('txid')==inner.get('recovery',{}).get('txid'),
        len(responses)>23 and responses[21]['view'].get('state')=='private-opening-delivered' and
            responses[23]['view'].get('commitment')==respend.get('incoming_commitment'),
        respend.get('exported_exact') is True and respend.get('chain_executed') is False and respend.get('attempts')==0,
        respend.get('held_input_refused') is True and all(j.get('late_refusals',{}).values()) and len(j.get('late_refusals',{}))==4,
        same and all(x['proxy_requests_before']==x['proxy_requests_after'] for x in calls),
        not j.get('forced_cleanup') and all(x['process_reaped'] for x in calls+children) and all(not r['forced_cleanup'] for r in responses),
        all(x not in material for x in needles) and all(r['private_review_values_retained'] is False for r in responses),
        all(source()['files'][p]==outer['source']['files'][p] for p in EXTRA)]
    raw=b''.join(ACTIVE.jraw if ACTIVE else []);log=output.with_name(output.stem+'.journey.jsonl');n.need(not log.exists(),'fresh journey stream required');log.write_bytes(raw)
    result={'format':'1soft/protocol8-journey-gate/v1','status':'qualified-one-host-wallet-journey' if all(checks) else 'failed',
        'source':outer['source'],'console_report':linked.name,'console_report_sha256':n.sha(linked.read_bytes()),'journey':j,
        'logs':{'journey':{'name':log.name,'bytes':len(raw),'sha256':n.sha(raw)}},'claims':CLAIMS,
        'checks':[{'id':name,'passed':bool(ok)} for name,ok in zip(CHECKS,checks)]}
    output.write_bytes(n.canonical(result)+b'\n');return 0 if all(checks) else 1

if __name__=='__main__':
    p=argparse.ArgumentParser(description=__doc__)
    for name in ('engine','worker','helper','fixture','prover','kat','output'):p.add_argument('--'+name,type=Path,required=True)
    raise SystemExit(run(p.parse_args()))
