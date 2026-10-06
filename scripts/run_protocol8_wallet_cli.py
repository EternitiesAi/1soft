#!/usr/bin/env python3
"""Exercise protected wallet commands through the unchanged actual wallet journey."""
import argparse,copy,fcntl,json,os,signal,subprocess,sys,time
from pathlib import Path
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
ROOT=Path(__file__).resolve().parents[1];sys.path.insert(0,str(ROOT/'src'))
import protocol8_transfer as n
import protocol8_wallet_cli as cli
import protocol8_wallet as core
import run_protocol8_wallet as wallet_gate
from run_devnet import wait_until

CHECKS=('inherited_actual_wallet_gate','four_cli_native_initializations','four_read_only_doctors',
    'bad_pin_no_creation','duplicate_configuration_owner_refused','actual_cli_methods_used',
    'durable_holds_observed_before_proof','early_private_delivery_refused','output_overwrite_refused',
    'all_cli_processes_reaped','cli_native_processes_reaped','private_material_absent','source_unchanged')
ACTIVE=None
# Frozen caller order, derived from the unchanged wallet journey plus this
# adapter's explicit init/doctor/hold/export/delivery checks. No extra dispatch.
EXPECTED_COMMANDS=(
    'init','init','doctor','doctor','observe',
    'import-note','import-note','import-note','import-note','import-note',
    'init','doctor','observe','import-note','import-note','inventory','inventory','inventory','import-note',
    'init','doctor','observe','import-note','prepare','deliver','export','export','prepare','export','prepare',
    'inventory','reconcile','reconcile','mark-attempt','inventory','reconcile','observe','reconcile',
    'inventory','reconcile','inventory','mark-attempt','deliver','init','doctor','observe','import-note',
    'inventory','export','observe','reconcile','inventory','observe','observe','import-note','import-note','inventory')
EXPECTED_REFUSALS={1,4,6,7,8,9,10,14,25,27,30,42,53,54,55,56}

def process_identity(pid):
    try:
        fields=Path(f'/proc/{pid}/stat').read_text().rsplit(')',1)[1].split()
        return int(fields[19]),fields[0]
    except (FileNotFoundError,ProcessLookupError):return None

def abort_owned_tree(proc):
    """Failure cleanup only: native workers own separate process groups.

    Snapshot descendants through this live fixture's actual parent links. Never
    signal by process name or a bare PID that might have been reused.
    """
    owned={};pending=[proc.pid]
    while pending:
        pid=pending.pop();identity=process_identity(pid)
        if identity is None or pid in owned:continue
        n.need(len(owned)<32,'owned CLI descendant bound')
        owned[pid]=identity
        try:pending.extend(int(x) for x in Path(f'/proc/{pid}/task/{pid}/children').read_text().split())
        except (FileNotFoundError,ProcessLookupError):pass
    for pid,identity in reversed(list(owned.items())):
        live=process_identity(pid)
        if live is not None and live[0]==identity[0]:
            try:os.kill(pid,signal.SIGKILL)
            except ProcessLookupError:pass
    proc.communicate()
    def stopped():
        for pid,identity in owned.items():
            live=process_identity(pid)
            if live is not None and live[0]==identity[0] and live[1]!='Z':return False
        return True
    wait_until(stopped,10)
    return [{'pid':pid,'start_ticks':identity[0],'stopped':True,
             'native_reaped_by_cli':False,'scope':'forced cleanup of proven fixture ancestry; failed run only'} for pid,identity in owned.items()]

class Network(wallet_gate.Network):
    def __init__(self,paths,output,report):
        super().__init__(paths,output,report)
        global ACTIVE;ACTIVE=self
        self.io=self.runtime/'wallet-cli-inputs';self.io.mkdir(mode=0o700)
        self.configs=self.runtime/'wallet-cli-configs';self.configs.mkdir(mode=0o700)
        self.wallets={};self.needles=[];self.raw_responses=[]
        self.e={'initializations':[],'doctors':[],'invocations':[],'responses':[],
            'preproof_holds':[],'bad_pin_refused':False,'duplicate_owner_refused':False,
            'early_delivery_refused':False,'output_overwrite_refused':False,'forced_cleanup':[]}
        report['wallet_cli']=self.e
    def file(self,raw):
        p=self.io/str(len(list(self.io.iterdir())))
        cli.write_new(p,raw);return p
    def plain(self,row):
        envelope=json.loads(row['path'].read_bytes());h=envelope['header']
        raw=AESGCM(bytes.fromhex(row['secret']['key'])).decrypt(bytes.fromhex(h['nonce']),bytes.fromhex(envelope['ciphertext']),core.AAD+n.canonical(h))
        return json.loads(raw)
    def call(self,row,command,extra=(),*,bad_pin=False,hold_request=None):
        args=[sys.executable,'-B',str(ROOT/'scripts/protocol8_wallet.py'),'--workspace',str(row['workspace']),
            '--genesis-sha256','ef'*32 if bad_pin else self.genesis_sha256,'--credentials',str(row['credentials']),command,*map(str,extra)]
        started=time.monotonic();proc=subprocess.Popen(args,stdout=subprocess.PIPE,stderr=subprocess.PIPE,start_new_session=True)
        ticks=int(Path(f'/proc/{proc.pid}/stat').read_text().rsplit(')',1)[1].split()[19]);raw=err=b''
        try:
            if hold_request is not None:
                def held():
                    n.need(proc.poll() is None,'CLI exited before the held obligation was observed')
                    p=self.plain(row);item=next((x for x in p['obligations'] if x['request']==hold_request),None)
                    return item and item['raw'] is None and item['attempts']==0
                wait_until(held,180)
                self.e['preproof_holds'].append({'request':hold_request,'pid':proc.pid,'start_ticks':ticks,
                    'encrypted_file_sha256':n.sha(row['path'].read_bytes()),'wire_absent':True,'attempts':0})
            raw,err=proc.communicate(timeout=480)
        finally:
            if proc.poll() is None:self.e['forced_cleanup'].extend(abort_owned_tree(proc))
            self.e['invocations'].append({'command':command,'wallet_id':row['secret']['wallet_id'],'pid':proc.pid,
                'start_ticks':ticks,'exit_code':proc.returncode,'process_reaped':proc.poll() is not None,
                'elapsed_seconds':round(time.monotonic()-started,6),'script_sha256':n.sha((ROOT/'scripts/protocol8_wallet.py').read_bytes())})
        n.need(not err and len(raw)<=384*1024,'CLI diagnostics or reply bound')
        value=json.loads(raw);n.need(raw==n.canonical(value)+b'\n' and value['pid']==proc.pid and value['start_ticks']==ticks,'CLI process response identity differs')
        self.e['invocations'][-1].update(stdout_bytes=len(raw),stdout_sha256=n.sha(raw))
        n.need(proc.returncode==(1 if value['status']=='refused' else 0),'CLI response exit status differs')
        self.raw_responses.append(raw);self.e['responses'].append(value)
        if row['path'].exists():
            p=self.plain(row)
            for item in p['obligations']:
                req=bytes.fromhex(item['private_request']);self.needles.append(req.hex().encode())
                self.needles.extend(req[552+i*32:584+i*32].hex().encode() for i in (0,1,4,5,14,15,17,18))
        if value['status']=='refused':raise n.Invalid('actual wallet CLI refused')
        return value

class Wallet:
    """Test caller adapter: every wallet method invokes the actual CLI process."""
    def __init__(self,path,*,key,wallet_id,recipient_secret,controller,create=False):
        self.h=ACTIVE;self.path=Path(path);secret={'key':key.hex(),'wallet_id':wallet_id,'recipient_secret':recipient_secret}
        if create:
            n.need(self.path not in self.h.wallets,'fresh fixture wallet mapping')
            row={'path':self.path,'secret':secret,'workspace':self.h.configs/str(len(self.h.wallets)),
                'credentials':self.h.file(n.canonical(secret))}
            extra=['--genesis',self.h.genesis_path,'--kat',self.h.paths['kat'],'--worker',controller.worker.binary,
                '--helper',self.h.report['wallet_cli_inputs']['helper'],'--helper-sha256',self.h.report['inputs']['helper']['sha256'],
                '--prover',self.h.report['wallet_cli_inputs']['prover'],'--prover-sha256',self.h.report['inputs']['prover']['sha256'],'--wallet',self.path]
            if not self.h.e['bad_pin_refused']:
                try:self.h.call(row,'init',extra,bad_pin=True)
                except n.Invalid:pass
                else:raise AssertionError('bad external pin accepted')
                self.h.e['bad_pin_refused']=not row['workspace'].exists() and not self.path.exists()
            result=self.h.call(row,'init',extra);self.h.e['initializations'].append(result);self.h.wallets[self.path]=row
            before=self.path.read_bytes();config={p.name:p.read_bytes() for p in row['workspace'].iterdir()}
            result=self.h.call(row,'doctor');n.need(before==self.path.read_bytes() and config=={p.name:p.read_bytes() for p in row['workspace'].iterdir()},'doctor mutated bytes')
            self.h.e['doctors'].append({'files_unchanged':True,**result})
            if not self.h.e['duplicate_owner_refused']:
                fd=os.open(row['workspace']/'wallet-cli.lock',os.O_RDONLY)
                try:
                    fcntl.flock(fd,fcntl.LOCK_EX|fcntl.LOCK_NB)
                    try:self.h.call(row,'doctor')
                    except n.Invalid:self.h.e['duplicate_owner_refused']=True
                    else:raise AssertionError('duplicate configuration owner accepted')
                finally:os.close(fd)
        else:
            row=self.h.wallets[self.path];n.need(secret==row['secret'],'fixture reopen credentials differ')
            self.h.call(row,'inventory')
        self.row=self.h.wallets[self.path]
        self.h.needles.extend(secret[k].encode() for k in ('key','recipient_secret'))
    def call(self,command,*extra):return self.h.call(self.row,command,extra)
    def observe(self,witness,signed_header):
        p=self.h.file(n.canonical({'witness':witness,'signed_header':signed_header}))
        return self.call('observe','--packet',p)['certificate']
    def import_note(self,o,*,raw=None,output=10,genesis=False):
        p=self.h.file(n.canonical(o));extra=['--opening',p,'--output-index',output]
        extra+=['--genesis-note'] if genesis else ['--wire',self.h.file(raw)]
        return self.call('import-note',*extra)['commitment']
    def inventory(self):return self.call('inventory')['inventory']
    def prepare(self,prover,commitment,**kw):
        extra=['--commitment',commitment]
        for name,value in kw.items():extra+=['--'+name.replace('_','-'),value]
        old=self.h.plain(self.row)
        held=any(x['input']==commitment or x['request']==kw['request'] for x in old['obligations'])
        result=self.h.call(self.row,'prepare',extra,hold_request=None if held else kw['request'])
        # The inherited gate counts actual private proof calls. Merge the measured
        # CLI prover receipt into that same counter; no call is fabricated/replayed.
        audit=result['native_audits']['prover'];n.need(audit['call_count']==1 and audit['calls'][0]['operation']=='prove','one actual CLI proof required')
        prover.runs.extend(copy.deepcopy(audit['calls']));prover.call_count+=audit['call_count'];prover.reaped_count+=audit['reaped_count'];prover.timeout_count+=audit['timeout_count']
        if not self.h.e['early_delivery_refused']:
            before=self.path.read_bytes();out=self.h.io/'early-private-delivery'
            try:self.call('deliver','--txid',result['txid'],'--output',out)
            except n.Invalid:self.h.e['early_delivery_refused']=not out.exists() and before==self.path.read_bytes()
            else:raise AssertionError('private delivery before certified execution')
        return result['txid']
    def export(self,ident):
        out=self.h.io/('wire-'+str(len(self.h.e['invocations'])))
        result=self.call('export','--txid',ident,'--output',out);raw=out.read_bytes()
        n.need(result['bytes']==len(raw) and result['sha256']==n.sha(raw),'exact exported wire receipt differs')
        if not self.h.e['output_overwrite_refused']:
            before=self.path.read_bytes()
            try:self.call('export','--txid',ident,'--output',out)
            except n.Invalid:self.h.e['output_overwrite_refused']=out.read_bytes()==raw and self.path.read_bytes()==before
            else:raise AssertionError('existing output overwritten')
        return raw
    def mark_attempt(self,ident):self.call('mark-attempt','--txid',ident)
    def reconcile(self,ident):return self.call('reconcile','--txid',ident)['result']
    def output_opening(self,ident,output=10):
        out=self.h.io/('opening-'+str(len(self.h.e['invocations'])))
        result=self.call('deliver','--txid',ident,'--output-index',output,'--output',out);raw=out.read_bytes()
        n.need(result['bytes']==len(raw) and result['sha256']==n.sha(raw),'private delivery receipt differs')
        return json.loads(raw)

def run(args):
    output=args.output.absolute();n.need(not output.exists(),'fresh CLI report required')
    inner=output.with_name(output.stem+'.wallet.json');original_network=wallet_gate.Network;original_wallet=wallet_gate.RecipientWallet
    class ConfiguredNetwork(Network):
        def __init__(self,*kw):
            super().__init__(*kw);self.report['wallet_cli_inputs']={name:str(getattr(args,name)) for name in ('helper','prover')}
    wallet_gate.Network=ConfiguredNetwork;wallet_gate.RecipientWallet=Wallet
    try:
        params=argparse.Namespace(**vars(args));params.output=inner;code=wallet_gate.run(params)
    finally:wallet_gate.Network=original_network;wallet_gate.RecipientWallet=original_wallet
    r=json.loads(inner.read_bytes());e=r.get('wallet_cli',{});responses=e.get('responses',[])
    public=n.canonical(r);needles=ACTIVE.needles if ACTIVE else []
    # Public small fixture/context fields are not secrets. Private random requests
    # and secret primitives must be absent from all serialized receipts and logs.
    public_context=n.canonical(r.get('genesis',{}))+b''.join(p.read_bytes().hex().encode() for p in inner.with_name(inner.name+'.artifacts').glob('*.tx'))
    filtered=[x for x in needles if x and x not in public_context]
    artifacts=inner.with_name(inner.name+'.artifacts')
    public_material=public+b''.join(p.read_bytes() for p in artifacts.iterdir() if p.is_file())
    private_absent=all(x not in public_material for x in filtered)
    methods={x['command'] for x in e.get('invocations',[])}
    native_audits=[a for x in responses for a in x['native_audits'].values()]
    checks=[code==0,len(e.get('initializations',[]))==4 and all(x['status']=='initialized' and x['native_startup']['valid_proof_verified'] and x['native_startup']['corrupt_proof_refused'] for x in e.get('initializations',[])),
        len(e.get('doctors',[]))==4 and all(x['files_unchanged'] and not x['native_executed'] and not x['encrypted_store_authenticated'] for x in e.get('doctors',[])),
        e.get('bad_pin_refused') is True,e.get('duplicate_owner_refused') is True,
        tuple(x['command'] for x in e.get('invocations',[]))==EXPECTED_COMMANDS and
            {i for i,x in enumerate(e.get('invocations',[]),1) if x['exit_code']==1}==EXPECTED_REFUSALS,
        len(e.get('preproof_holds',[]))==2 and all(x['wire_absent'] and x['attempts']==0 for x in e.get('preproof_holds',[])),
        e.get('early_delivery_refused') is True,e.get('output_overwrite_refused') is True,
        bool(e.get('invocations')) and not e.get('forced_cleanup') and len(e['invocations'])==len(responses) and
            all(x['process_reaped'] and x['exit_code'] in (0,1) for x in e['invocations']),
        bool(native_audits) and all(a['call_count']==a['reaped_count'] and a['timeout_count']==0 and len(a['calls'])==a['retained_count']<=512 for a in native_audits),
        private_absent,wallet_gate.source()==r['source']]
    log=output.with_name(output.stem+'.cli.jsonl');n.need(not log.exists(),'fresh raw CLI log required')
    log.write_bytes(b''.join(ACTIVE.raw_responses if ACTIVE else []))
    result={'format':'1soft/protocol8-wallet-cli-gate/v1','status':'failed','source':r['source'],
        'cli_log':log.name,'cli_log_sha256':n.sha(log.read_bytes()),'cli_log_bytes':log.stat().st_size,
        'wallet_report':inner.name,'wallet_report_sha256':n.sha(inner.read_bytes()),'wallet_cli':e,
        'checks':[{'id':name,'passed':bool(ok)} for name,ok in zip(CHECKS,checks)],
        'claims':{'actual_wallet_cli':True,'one_trusted_host':True,'synthetic_funds':True,'broadcast_by_cli':False,
            'automatic_retry':False,'freshness_established':False,'production_ready':False,'public_network':False,
            'production_key_management':False,'local_rollback_resistance':False}}
    if all(checks):result['status']='qualified-one-host-wallet-cli'
    output.write_bytes(n.canonical(result)+b'\n');return 0 if all(checks) else 1

if __name__=='__main__':
    p=argparse.ArgumentParser(description=__doc__)
    for name in ('engine','worker','helper','fixture','prover','kat','output'):p.add_argument('--'+name,type=Path,required=True)
    raise SystemExit(run(p.parse_args()))
