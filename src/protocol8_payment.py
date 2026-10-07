"""One explicit loopback P8 submission; wallet authority survives uncertain IO.

Public transport metadata has domain-separated HMAC authentication. It is not a
second monetary journal, a freshness source, a retry policy or rollback defense.
"""
from __future__ import annotations
import base64, hashlib, hmac, http.client, json, os, re, signal
from pathlib import Path
import protocol8_transfer as n
import protocol8_wallet_cli as c

FORMAT='1soft/protocol8-payment-caller/v1'
JOURNAL='1soft/protocol8-payment-journal/v1'
KEY_DOMAIN=b'1soft/P8-payment-journal/key/v1\0'
MAC_DOMAIN=b'1soft/P8-payment-journal/mac/v1\0'
MAX_JOURNAL=8192
MAX_REPLY=8192
TOTAL_RPC_SECONDS=20
PHASES={'prepared','attempt-marked','admission-accepted','admission-refused','unknown'}

def endpoint_port(value):
    c.require(type(value) is str,'explicit loopback endpoint required')
    match=re.fullmatch(r'http://127\.0\.0\.1:([1-9][0-9]{0,4})',value)
    c.require(match is not None and int(match[1])<=65535,'canonical literal loopback endpoint required')
    return int(match[1])

def runtime_sha():
    files=c.runtime_files()
    files['scripts/protocol8_payment.py']=c.sha(c.read_file(c.ROOT/'scripts/protocol8_payment.py',1024**2))
    return c.sha(c.canonical(files))

def unique_pairs(pairs):
    value={}
    for key,item in pairs:
        c.require(key not in value,'duplicate RPC field');value[key]=item
    return value

def invalid_constant(value):raise ValueError('nonfinite RPC number')
def timed_out(signum,frame):raise TimeoutError('local RPC deadline')

def dispatch(endpoint,wire):
    """Exactly one request, no proxy/DNS/redirect/retry; acknowledgment only."""
    port=endpoint_port(endpoint);connection=http.client.HTTPConnection('127.0.0.1',port,timeout=15)
    unknown={'outcome':'unknown','admission_code':None}
    armed=False;previous=None
    try:
        # This synchronous Linux CLI owns its main-thread alarm. A socket timeout
        # alone can be extended by trickled headers/body. Do not replace an alarm
        # belonging to an embedding caller; that unsupported use remains unknown.
        c.require(signal.getitimer(signal.ITIMER_REAL)==(0.0,0.0),'existing RPC alarm owner')
        previous=signal.signal(signal.SIGALRM,timed_out)
        signal.setitimer(signal.ITIMER_REAL,TOTAL_RPC_SECONDS);armed=True
        body=c.canonical({'jsonrpc':'2.0','id':1,'method':'broadcast_tx_sync',
            'params':{'tx':base64.b64encode(wire).decode('ascii')}})
        connection.request('POST','/',body=body,headers={'Content-Type':'application/json','Connection':'close'})
        response=connection.getresponse();raw=response.read(MAX_REPLY+1)
        if response.status!=200 or len(raw)>MAX_REPLY:return unknown
        value=json.loads(raw,object_pairs_hook=unique_pairs,parse_constant=invalid_constant)
        c.require(type(value) is dict and set(value)=={'jsonrpc','id','result'} and value['jsonrpc']=='2.0' and
            type(value['id']) is int and value['id']==1,'closed RPC result required')
        result=value['result']
        c.require(type(result) is dict and set(result)=={'code','data','log','codespace','hash'},'closed admission result required')
        code=result['code'];c.require(type(code) is int and 0<=code<2**32,'admission code required')
        for field in ('data','log','codespace','hash'):c.require(type(result[field]) is str,'RPC text field required')
        c.require(re.fullmatch('[0-9a-fA-F]{64}',result['hash']) is not None and
            result['hash'].lower()==hashlib.sha256(wire).hexdigest(),'RPC wire identity differs')
        # Raw node diagnostics/data never enter the public command or journal.
        return {'outcome':'admission-accepted' if code==0 else 'admission-refused','admission_code':code}
    except Exception:return unknown
    finally:
        if armed:signal.setitimer(signal.ITIMER_REAL,0);signal.signal(signal.SIGALRM,previous)
        connection.close()

def journal_key(secret):return hmac.digest(bytes.fromhex(secret['key']),KEY_DOMAIN,'sha256')
def tag(record,key):return hmac.digest(key,MAC_DOMAIN+c.canonical(record),'sha256').hex()

def save(path,record,key,*,initial=False):
    raw=c.canonical({'record':record,'hmac_sha256':tag(record,key)})
    c.require(len(raw)<=MAX_JOURNAL,'journal bound')
    if initial:
        # Atomic creation fsyncs both the new file and its directory before mark.
        c.private_output(path,raw);return
    c.read_file(path,MAX_JOURNAL,private=True)
    stage=path.with_name('.'+path.name+'.p8-stage-'+os.urandom(16).hex())
    try:
        c.write_new(stage,raw);os.replace(stage,path);c.sync_dir(path.parent)
    finally:
        if stage.exists():stage.unlink()

def base_record(args,root,config,wire):
    return {'format':JOURNAL,'journal_path':str(c.absolute(args.journal)),
        'workspace':str(root),'wallet_id':config['wallet_id'],
        'wallet_manifest_sha256':c.sha(c.read_file(root/'wallet-cli.json',32768,private=True)),
        'genesis_sha256':args.genesis_sha256,'runtime_sha256':runtime_sha(),'endpoint':args.endpoint,
        'txid':args.txid,'wire_sha256':c.sha(wire),'wire_bytes':len(wire)}

def load_journal(path,base,key):
    value=c.closed_json(c.read_file(path,MAX_JOURNAL,private=True),MAX_JOURNAL)
    c.require(type(value) is dict and set(value)=={'record','hmac_sha256'},'closed journal required')
    record=value['record'];c.pin(value['hmac_sha256'])
    c.require(type(record) is dict and set(record)==set(base)|{'phase','admission_code'},'closed journal record required')
    c.require(hmac.compare_digest(value['hmac_sha256'],tag(record,key)),'journal authentication differs')
    c.require(all(record[k]==v for k,v in base.items()),'journal identity differs')
    c.require(type(record['wire_bytes']) is int and record['phase'] in PHASES,'journal phase/size differs')
    phase=record['phase'];code=record['admission_code']
    c.require((phase in ('prepared','attempt-marked','unknown') and code is None) or
        (phase=='admission-accepted' and type(code) is int and code==0) or
        (phase=='admission-refused' and type(code) is int and 0<code<2**32),'journal admission shape differs')
    return record

def obligation(wallet,ident):
    rows=[x for x in wallet.inventory()['obligations'] if x['txid']==ident]
    c.require(len(rows)==1 and type(rows[0]['attempts']) is int and rows[0]['attempts'] in (0,1),'wallet attempt authority required')
    return rows[0]

def state(record,row):
    phase=record['phase']
    if phase=='prepared':return 'prepared-not-attempted' if row['attempts']==0 else 'attempt-record-incomplete'
    c.require(row['attempts']==1,'journal cannot replace wallet attempt authority')
    return phase if phase in ('admission-accepted','admission-refused') else 'attempted-outcome-unknown'

def operate(args,trace):
    endpoint_port(args.endpoint);c.pin(args.txid)
    path=c.parents(args.journal);c.directory(path.parent,private=True)
    if args.command=='submit':c.require(not path.exists() and not path.is_symlink(),'submit requires a new journal; never resume or resend')
    with c.locked(args.workspace) as root:
        raw,k,config,secret=c.load(root,args);trace['_wallet_id']=config['wallet_id']
        wallet,prover=c.native(raw,k,config,secret,trace)
        c.require(wallet.pins==config['wallet_pins'],'authenticated wallet pins differ')
        wire=wallet.export(args.txid)
        c.require(len(wire)==3560 and n.txid(wire)==args.txid,'exact wallet wire required')
        base=base_record(args,root,config,wire);key=journal_key(secret)
        if args.command=='submit':
            row=obligation(wallet,args.txid)
            c.require(row['attempts']==0 and row['completed'] is False,'original already attempted or completed; reconcile only')
            record={**base,'phase':'prepared','admission_code':None};save(path,record,key,initial=True)
            wallet.mark_attempt(args.txid)
            record['phase']='attempt-marked';save(path,record,key)
            trace['_transport_attempts']=1
            observed=dispatch(args.endpoint,wire)
            record.update(phase=observed['outcome'],admission_code=observed['admission_code']);save(path,record,key)
        else:record=load_journal(path,base,key)
        result=None
        if args.command=='reconcile':
            if args.packet is not None:
                packet=c.packet(args.packet);wallet.observe(packet['witness'],packet['signed_header'])
            result=wallet.reconcile(args.txid)
            c.require(result['status'] in ('executed-exact','conflict-held','unresolved-held'),'wallet resolution required')
        row=obligation(wallet,args.txid)
        return {'status':'payment-reconciled' if result is not None else 'payment-submission-recorded' if args.command=='submit' else 'payment-status',
            'txid':args.txid,'wallet_id':config['wallet_id'],'submission_state':state(record,row),
            'journal_sha256':c.sha(c.read_file(path,MAX_JOURNAL,private=True)),
            'transport':{'outcome':record['phase'],'admission_code':record['admission_code']},
            'wallet_attempts':row['attempts'],'wallet_completed':row['completed'],'result':result,
            'execution_confirmed':result is not None and result['status']=='executed-exact',
            'reconciliation_required':result is None or result['status']!='executed-exact'}

def execute(args):
    trace={};exit_code=0
    try:result=operate(args,trace)
    except Exception as exc:
        result={'status':'refused','error_type':type(exc).__name__,
            'reason':'payment command refused; reconcile original obligation; private details suppressed',
            'execution_confirmed':False,'reconciliation_required':True};exit_code=1
    wallet_id=trace.pop('_wallet_id',None);attempts=trace.pop('_transport_attempts',0)
    return {'format':FORMAT,'command':args.command,**result,'genesis_sha256':args.genesis_sha256,
        'wallet_id':wallet_id,'runtime_sha256':runtime_sha(),'pid':os.getpid(),
        'start_ticks':int(Path('/proc/self/stat').read_text().rsplit(')',1)[1].split()[19]),
        'native_audits':{name:obj.audit() for name,obj in trace.items()},'transport_attempts':attempts,
        'automatic_retry':False,'freshness_established':False,'production_ready':False,'public_network':False},exit_code
