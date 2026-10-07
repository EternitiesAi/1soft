#!/usr/bin/env python3
"""Actual read-only guide and inventory profiling within the four-validator journey."""
import argparse,json,os,subprocess,sys,time
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
sys.path[:0]=[str(ROOT/'src'),str(ROOT/'scripts'),str(ROOT/'tools/payment-console/src')]
import protocol8_transfer as n
import protocol8_wallet_cli as cli
from protocol8_wallet import FORMAT as WALLET_FORMAT
import run_protocol8_journey as journey
import run_protocol8_wallet_cli as old
import payment_console as console

ACTIVE=None
EXTRA=('scripts/run_protocol8_guide.py','scripts/profile_protocol8_inventory.py',
    'tools/release/check_protocol8_guide.py','tests/test_protocol8_guide.py','tests/test_protocol8_inventory_profile.py')
CASES=('empty-observed','received-input','received-input-repeat','missing-txid','wrong-genesis',
    'prepared-original','exact-observed','recipient-imported','conflict-observed','recipient-prepared')

class Network(journey.Network):
    def __init__(self,*args):
        super().__init__(*args)
        global ACTIVE;ACTIVE=self
        self.g={'calls':[],'responses':[],'profile':None,'profile_call':None,'forced_cleanup':[]}
        self.report['guide']=self.g;self.guide_raw=[]
    def inventory(self,row):
        p=self.plain(row)
        return {'format':WALLET_FORMAT,'wallet_id':row['secret']['wallet_id'],
            'recipient_key':json.loads((row['workspace']/'wallet-cli.json').read_bytes())['wallet_pins']['recipient_key'],
            'revision':p['revision'],'as_of_height':p['observations'][-1]['witness']['height'] if p['observations'] else None,
            'notes':[r['commitment'] for r in p['notes']],
            'obligations':[{'input':r['input'],'request':r['request'],'txid':n.txid(bytes.fromhex(r['raw'])) if r['raw'] else None,
                'attempts':r['attempts'],'completed':r['result'] is not None} for r in p['obligations']],
            'freshness_established':False,'automatic_retry':False}
    def files(self,row):
        # Never retain private paths or file contents. Assert byte identity in
        # controlled fixture memory; only the boolean result leaves this runner.
        return {str(p):p.read_bytes() for root in (row['workspace'],row['path'].parent,self.io)
            for p in root.rglob('*') if p.is_file() and not p.is_symlink()}
    def child(self,cmd):
        started=time.monotonic();proc=subprocess.Popen(cmd,stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,stderr=subprocess.PIPE,start_new_session=True)
        birth=old.process_identity(proc.pid);n.need(birth is not None,'guide child birth unavailable')
        try:raw,err=proc.communicate(timeout=480)
        finally:
            if proc.poll() is None:self.g['forced_cleanup'].extend(old.abort_owned_tree(proc))
        n.need(not err and 0<len(raw)<=1024**2,'guide child output bound')
        return raw,{'pid':proc.pid,'start_ticks':birth[0],'exit_code':proc.returncode,
            'process_reaped':proc.poll() is not None,'elapsed_seconds':round(time.monotonic()-started,6)}
    def guide_call(self,row,case,*,commitment=None,txid=None,bad_pin=False,refusal=False):
        receipt=self.io/('guide-receipt-'+str(len(self.g['calls'])))
        before=self.files(row);plain_before=self.plain(row);expected=self.inventory(row)
        wallet_before=n.sha(row['path'].read_bytes());requests=len(self.p['proxy_requests'])
        cmd=[sys.executable,'-B',str(ROOT/'scripts/protocol8_console.py'),'--workspace',str(row['workspace']),
            '--credentials',str(row['credentials']),'--genesis-sha256','ef'*32 if bad_pin else self.genesis_sha256,
            '--receipt',str(receipt),'guide']
        if commitment is not None:cmd+=['--commitment',commitment]
        if txid is not None:cmd+=['--txid',txid]
        text,call=self.child(cmd);raw=cli.read_file(receipt,1024**2,private=True);value=json.loads(raw)
        n.need(raw==n.canonical(value)+b'\n' and (value['pid'],value['start_ticks'])==(call['pid'],call['start_ticks']),
            'guide outer identity differs')
        n.need(call['exit_code']==(1 if refusal else 0) and (value['status']=='refused')==refusal,'guide refusal differs')
        after=self.files(row);after.pop(str(receipt))
        n.need(before==after and plain_before==self.plain(row) and requests==len(self.p['proxy_requests']),
            'read-only guide changed wallet/configuration/journal/output or made request')
        if not refusal:
            n.need(value['child_responses'][0]['inventory']==expected,'actual guide inventory differs from fixture custody')
            wanted=console.guide_view(expected,row['secret']['wallet_id'],self.genesis_sha256,commitment=commitment,txid=txid)
            n.need(value['view']==wanted and text==console.render(wanted).encode(),'actual guide rendering differs')
        self.g['calls'].append({**call,'case':case,'lifecycle_ordinal':len(self.j['invocations']),
            'selection':{'commitment':commitment,'txid':txid},'bad_genesis':bad_pin,'expected_refusal':refusal,
            'script_sha256':n.sha((ROOT/'scripts/protocol8_console.py').read_bytes()),
            'receipt_bytes':len(raw),'receipt_sha256':n.sha(raw),'stdout_bytes':len(text),'stdout_sha256':n.sha(text),
            'stdout':text.decode(),'expected_inventory':expected,'wallet_sha256_before':wallet_before,
            'wallet_sha256_after':n.sha(row['path'].read_bytes()),'private_fixture_state_unchanged':True,
            'configuration_journal_output_bytes_unchanged':True,'proxy_requests_before':requests,
            'proxy_requests_after':len(self.p['proxy_requests'])})
        self.g['responses'].append(value);self.guide_raw.append(raw)
    def profile_call(self,row):
        before=self.files(row);plain_before=self.plain(row);requests=len(self.p['proxy_requests']);expected=self.inventory(row)
        cmd=[sys.executable,'-B',str(ROOT/'scripts/profile_protocol8_inventory.py'),'--workspace',str(row['workspace']),
            '--credentials',str(row['credentials']),'--genesis-sha256',self.genesis_sha256]
        raw,call=self.child(cmd);value=json.loads(raw)
        n.need(raw==n.canonical(value)+b'\n' and call['exit_code']==0 and value['status']=='measured-authenticated-inventory',
            'actual inventory host profile refused')
        child=value['wallet_receipt']
        n.need((child['pid'],child['start_ticks'])==(call['pid'],call['start_ticks']) and child['inventory']==expected,
            'profiled wallet inventory identity differs')
        n.need(before==self.files(row) and plain_before==self.plain(row) and requests==len(self.p['proxy_requests']),
            'read-only profile changed fixture or made request')
        self.g['profile']=value;self.g['profile_call']={**call,'script_sha256':n.sha((ROOT/'scripts/profile_protocol8_inventory.py').read_bytes()),
            'stdout_bytes':len(raw),'stdout_sha256':n.sha(raw),'expected_inventory':expected,
            'private_fixture_state_unchanged':True,'configuration_journal_output_bytes_unchanged':True,
            'proxy_requests_before':requests,'proxy_requests_after':len(self.p['proxy_requests'])}
    def life_call(self,row,command,extra,**kwargs):
        result=super().life_call(row,command,extra,**kwargs);ordinal=len(self.j['invocations']);inv=self.inventory(row)
        if ordinal==1:self.guide_call(row,'empty-observed')
        if ordinal==9:
            commitment=inv['notes'][-1]
            self.guide_call(row,'received-input',commitment=commitment)
            self.guide_call(row,'received-input-repeat',commitment=commitment)
            self.guide_call(row,'missing-txid',txid='98'*32,refusal=True)
            self.guide_call(row,'wrong-genesis',bad_pin=True,refusal=True)
            self.profile_call(row)
        if ordinal in (14,21,26,31):
            case={14:'prepared-original',21:'exact-observed',26:'conflict-observed',31:'recipient-prepared'}[ordinal]
            self.guide_call(row,case,txid=next(r['txid'] for r in reversed(inv['obligations']) if r['txid'] is not None))
        if ordinal==24:self.guide_call(row,'recipient-imported',commitment=inv['notes'][-1])
        return result

def run(args):
    output=args.output.absolute();n.need(not output.exists(),'fresh guide output required')
    linked=output.with_name(output.stem+'.journey.json')
    prior_network=journey.Network;prior_source=journey.parent.payment.gate.source
    def source():
        value=prior_source()
        for name in EXTRA:
            b=(ROOT/name).read_bytes();value['files'][name]={'bytes':len(b),'sha256':n.sha(b)}
        value['files']=dict(sorted(value['files'].items()));return value
    journey.Network=Network;journey.parent.payment.gate.source=source
    try:
        params=argparse.Namespace(**vars(args));params.output=linked;code=journey.run(params)
    finally:journey.Network=prior_network;journey.parent.payment.gate.source=prior_source
    outer=json.loads(linked.read_bytes());g=ACTIVE.g if ACTIVE else {}
    stream=b''.join(ACTIVE.guide_raw if ACTIVE else [])
    log=output.with_name(output.stem+'.guide.jsonl');n.need(not log.exists(),'fresh guide stream required');log.write_bytes(stream)
    result={'format':'1soft/protocol8-guide-gate/v1','status':'candidate' if code==0 else 'failed',
        'source':outer['source'],'journey_report':linked.name,'journey_report_sha256':n.sha(linked.read_bytes()),
        'guide':g,'logs':{'guide':{'name':log.name,'bytes':len(stream),'sha256':n.sha(stream)}},
        'claims':{'actual_read_only_guide':True,'synthetic_funds':True,'one_trusted_host':True,
            'automatic_retry':False,'freshness_established':False,'production_ready':False,
            'performance_improvement_established':False,'profile_overhead_assessed':False,'private_payloads_retained':False}}
    output.write_bytes(n.canonical(result)+b'\n')
    if code==0:
        sys.path.insert(0,str(ROOT/'tools/release'))
        from check_protocol8_guide import check
        check(output,candidate=True);result['status']='qualified-one-host-wallet-guide'
        output.write_bytes(n.canonical(result)+b'\n')
    return code

if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__)
    for name in ('engine','worker','helper','fixture','prover','kat','output'):parser.add_argument('--'+name,type=Path,required=True)
    raise SystemExit(run(parser.parse_args()))
