"""Local terminal orchestration; protected wallet/payment CLIs retain authority."""
from __future__ import annotations
import json, os, subprocess, sys, tempfile, time
from pathlib import Path
import protocol8_wallet_cli as c
import protocol8_payment as p
from run_protocol8_wallet_cli import process_identity, abort_owned_tree

ROOT=Path(__file__).resolve().parents[3]
FORMAT='1soft/protocol8-payment-console/v1'
MAX_REPLY=384*1024
LIFECYCLE=('observe','import-note','prepare','export','deliver')
STATE_TEXT={
    'prepared-not-attempted':'Prepared locally. No submission attempt is recorded.',
    'attempt-record-incomplete':'The wallet recorded its attempt; the caller record is incomplete. Do not submit again.',
    'attempted-outcome-unknown':'Submission outcome unknown. Reconcile the original journal; retry is disabled.',
    'admission-accepted':'The node admitted the transaction. Execution is not confirmed.',
    'admission-refused':'The node refused admission. The original obligation remains held.',
    'unresolved-held':'Signed state does not establish execution. The original obligation remains held.',
    'executed-exact':'Signed AS-OF state confirms this exact retained transaction.',
    'conflict-held':'A certified conflicting spend exists. The original obligation remains held.',
    'refused':'Command refused. Preserve the original obligation and reconcile; private diagnostics are suppressed.',
    'cancelled':'Submission cancelled before the payment caller started.',
    'preparation-cancelled':'Preparation cancelled before the protected wallet child started.'}

def runtime_sha():
    files=c.runtime_files()
    for name in ('scripts/protocol8_payment.py','scripts/protocol8_console.py','tools/payment-console/src/payment_console.py'):
        files[name]=c.sha(c.read_file(ROOT/name,1024**2))
    return c.sha(c.canonical(dict(sorted(files.items()))))

def operational_reply(raw):
    # Operational receipts contain measured finite elapsed_seconds floats.
    # Consensus/private intent JSON continues to use the integer-only decoder.
    c.require(type(raw) is bytes and 0<len(raw)<=MAX_REPLY and raw.endswith(b'\n'),'one bounded canonical response required')
    value=json.loads(raw[:-1])
    c.require(type(value) is dict and raw==c.canonical(value)+b'\n','canonical operational receipt required')
    return value

class Runner:
    def __init__(self,args):self.args=args;self.calls=[];self.responses=[];self.forced=[]
    def run(self,kind,command,extra=()):
        args=self.args;script=ROOT/('scripts/protocol8_'+kind+'.py')
        script_sha=c.sha(c.read_file(script,1024**2))
        cmd=[sys.executable,'-B',str(script),'--workspace',str(args.workspace),
            '--genesis-sha256',args.genesis_sha256,'--credentials',str(args.credentials)]
        if kind=='payment':cmd+=['--endpoint',args.endpoint,'--journal',str(args.journal),'--txid',args.txid]
        cmd += [command,*map(str,extra)]
        started=time.monotonic();proc=None;identity=None;raw=b'';diagnostic=b''
        with tempfile.TemporaryFile() as out,tempfile.TemporaryFile() as err:
            try:
                proc=subprocess.Popen(cmd,stdout=out,stderr=err,start_new_session=True)
                identity=process_identity(proc.pid);c.require(identity is not None,'child birth unavailable')
                proc.communicate(timeout=480)
            finally:
                if proc is not None:
                    if proc.poll() is None:self.forced.extend(abort_owned_tree(proc))
                    out.seek(0);err.seek(0);raw=out.read(MAX_REPLY+1);diagnostic=err.read(257)
                    self.calls.append({'kind':kind,'command':command,'pid':proc.pid,
                        'start_ticks':identity[0] if identity else None,'exit_code':proc.returncode,
                        'process_reaped':proc.poll() is not None,'elapsed_seconds':round(time.monotonic()-started,6),
                        'script_sha256':script_sha,'stdout_bytes':len(raw),'stdout_sha256':c.sha(raw),
                        'diagnostic_present':bool(diagnostic)})
        c.require(not diagnostic and 0<len(raw)<=MAX_REPLY,'bounded canonical child response required')
        value=operational_reply(raw)
        c.require(type(value.get('pid')) is int and type(value.get('start_ticks')) is int and
            (value['pid'],value['start_ticks'])==(proc.pid,identity[0]),'child identity differs')
        c.require(value.get('format')==(c.FORMAT if kind=='wallet' else p.FORMAT) and
            value.get('command')==command and value.get('genesis_sha256')==args.genesis_sha256,'child command/pin differs')
        expected=c.sha(c.canonical(c.runtime_files())) if kind=='wallet' else p.runtime_sha()
        c.require(value.get('runtime_sha256')==expected and all(value.get(k) is False
            for k in ('automatic_retry','freshness_established','production_ready')),'child runtime/claims differ')
        c.require(proc.returncode==(1 if value.get('status')=='refused' else 0),'child exit differs')
        self.responses.append(value)
        return value

def need_success(value):c.require(value['status']!='refused','protected child refused')

def review(args,runner):
    with tempfile.TemporaryDirectory(prefix='1soft-console-review-') as name:
        root=Path(name);c.directory(root,private=True);path=root/'intent.json'
        reply=runner.run('wallet','review',['--txid',args.txid,'--output',path]);need_success(reply)
        raw=c.read_file(path,8192,private=True)
        c.require(reply['status']=='private-intent-reviewed' and reply['txid']==args.txid and
            reply['bytes']==len(raw) and reply['sha256']==c.sha(raw) and reply['private_file_created'] is True and
            reply['review_commitment_scheme']==c.REVIEW_SCHEME,'private review bytes differ')
        v=c.closed_json(raw,8192)
        keys={'format','wallet_id','txid','wire_sha256','wire_bytes','destination','payment','payment_expiry',
            'fee','valid_from','valid_until','attempts','completed','as_of_height','wallet_genesis_sha256','genesis_sha256','runtime_sha256','private_review_blind'}
        c.require(type(v) is dict and set(v)==keys and v['format']==c.REVIEW_FORMAT,'closed review required')
        for key in ('wallet_id','txid','wire_sha256','destination','wallet_genesis_sha256','genesis_sha256','runtime_sha256','private_review_blind'):c.pin(v[key])
        c.require(v['private_review_blind']!='00'*32 and v['wallet_genesis_sha256']==args.genesis_sha256,'private review blind/genesis differs')
        c.require(v['wallet_id']==reply['wallet_id'] and v['txid']==args.txid and v['genesis_sha256']==args.genesis_sha256 and
            v['runtime_sha256']==reply['runtime_sha256'],'private review identity differs')
        c.require(type(v['wire_bytes']) is int and v['wire_bytes']==3560 and type(v['completed']) is bool and
            type(v['attempts']) is int and v['attempts'] in (0,1),'review state differs')
        for key in ('payment','payment_expiry','fee','valid_from','valid_until','as_of_height'):
            c.require(type(v[key]) is int and 0<v[key]<2**64,'review numeric field differs')
        c.require(v['valid_from']<v['valid_until'],'review validity differs')
        return v,reply['sha256']

def public_review(v,digest):
    return {key:v[key] for key in ('wallet_id','txid','wire_sha256','wire_bytes','fee','valid_from','valid_until',
        'attempts','completed','as_of_height')} | {'review_sha256':digest,'review_commitment_scheme':c.REVIEW_SCHEME,'private_intent_omitted':True}

def review_text(v):
    return ('1soft | Review prepared payment\n'
        'Transaction: '+v['txid']+'\nWire SHA256: '+v['wire_sha256']+'\n'
        'Recipient: '+v['destination']+'\nAmount: '+str(v['payment'])+' atomic units\n'
        'Fee: '+str(v['fee'])+' atomic units\nPayment expiry: '+str(v['payment_expiry'])+' (protocol height)\n'
        'Validity: '+str(v['valid_from'])+' through '+str(v['valid_until'])+' (protocol heights)\n'
        'Wallet attempts: '+str(v['attempts'])+' | certified completion: '+str(v['completed']).lower()+'\n'
        'Observed AS-OF height: '+str(v['as_of_height'])+' | current network validity is not established\n')

def payment_view(value):
    need_success(value)
    result=value['result'];state=result['status'] if result is not None else value['submission_state']
    c.require(state in STATE_TEXT,'known payment state required')
    view={'state':state,'message':STATE_TEXT[state],'txid':value['txid'],'submission_state':value['submission_state'],
        'attempts':value['wallet_attempts'],'wallet_completed':value['wallet_completed'],'can_submit':False,
        'execution_confirmed':value['execution_confirmed'],'freshness_established':False}
    if result is not None:
        view['as_of_height']=result.get('state_height',result.get('as_of_height'))
        if 'app_hash' in result:view['app_hash']=result['app_hash']
    return view

def render(view):
    lines=['1soft | '+view['state'],view['message']]
    for key,label in (('txid','Transaction'),('submission_state','Submission record'),('attempts','Wallet attempts'),
        ('as_of_height','Signed AS-OF height'),('app_hash','AppHash'),('commitment','Note commitment'),
        ('output_sha256','Private file SHA256'),('output_bytes','Private file bytes')):
        if key in view:lines.append(label+': '+str(view[key]))
    lines+=['Automatic retry: disabled','Scope: local development; current network freshness is not established']
    return '\n'.join(lines)+'\n'

def fresh_journal(args):
    path=c.parents(args.journal);c.directory(path.parent,private=True)
    c.require(not path.exists() and not path.is_symlink(),'existing journal; reconcile only')

def lifecycle(args,runner,stream,input_stream):
    command=args.command;extra=[]
    if command=='observe':extra=['--packet',args.packet]
    elif command=='import-note':
        extra=['--opening',args.opening,'--output-index',args.output_index]
        extra+=['--genesis-note'] if args.genesis_note else ['--wire',args.wire]
    elif command=='prepare':
        for key in ('commitment','request','destination'):c.pin(getattr(args,key))
        for key in ('payment','valid_until','payment_expiry'):
            v=getattr(args,key);c.require(type(v) is int and 0<v<2**64,'bounded preparation integer required')
        stream.write('1soft | Prepare a payment\nInput commitment: '+args.commitment+'\n'
            'Recipient: '+args.destination+'\nAmount: '+str(args.payment)+' atomic units\n'
            'Payment expiry: '+str(args.payment_expiry)+' (protocol height)\n'
            'Validity ends at: '+str(args.valid_until)+' (protocol height)\n'
            'Preparation retains a held original transaction. It does not submit.\n')
        token='PREPARE '+args.commitment
        stream.write('Type '+token+' to prepare, or press Enter to cancel:\n');stream.flush()
        if input_stream.readline(100).rstrip('\r\n')!=token:
            return {'state':'preparation-cancelled','message':STATE_TEXT['preparation-cancelled'],
                'can_submit':False,'confirmation':'cancelled','wallet_child_started':False,
                'payment_child_started':False,'prepared_not_sent':True}
        for key in ('commitment','request','destination','payment','valid_until','payment_expiry'):
            extra+=['--'+key.replace('_','-'),getattr(args,key)]
    elif command in ('export','deliver'):
        c.pin(args.txid);extra=['--txid',args.txid,'--output',args.output]
        if command=='deliver':extra+=['--output-index',args.output_index]
    else:raise ValueError('unsupported lifecycle command')
    value=runner.run('wallet',command,extra);need_success(value);c.pin(value['wallet_id'])
    expected={'observe':'signed-state-observed','import-note':'note-imported',
        'prepare':'original-wire-retained','export':'exact-wire-exported','deliver':'private-opening-delivered'}
    c.require(value['status']==expected[command],'wallet lifecycle status differs')
    view={'state':value['status'],'wallet_id':value['wallet_id'],'can_submit':False,
        'payment_child_started':False,'opening_values_omitted':True}
    if command=='observe':
        cert=value['certificate'];height=cert['state_height'];c.pin(cert['app_hash'])
        c.require(type(height) is int and height>0 and cert['header_height']==height+1 and
            cert['genesis_sha256']==args.genesis_sha256,'signed observation context differs')
        view.update(message='Signed AS-OF state authenticated. Current network freshness is not established.',
            as_of_height=height,app_hash=cert['app_hash'])
    elif command=='import-note':
        c.pin(value['commitment']);view.update(commitment=value['commitment'],
            message='Recipient-controlled note imported from the explicit source. No balance is inferred.')
    elif command=='prepare':
        c.pin(value['txid']);view.update(state='prepared-not-attempted',message=STATE_TEXT['prepared-not-attempted'],
            txid=value['txid'],commitment=args.commitment,confirmation='exact-input-commitment',prepared_not_sent=True)
    else:
        c.require(value['txid']==args.txid and value['private_file_created'] is True,'private output identity differs')
        limit=3560 if command=='export' else 1024
        raw=c.read_file(args.output,limit,private=True)
        c.require(type(value['bytes']) is int and value['bytes']==len(raw) and value['sha256']==c.sha(raw),'private output bytes differ')
        if command=='export':c.require(len(raw)==3560 and c.n.txid(raw)==args.txid,'exported original wire differs')
        else:c.opening(c.closed_json(raw,1024))
        view.update(txid=args.txid,output_sha256=value['sha256'],output_bytes=len(raw),private_file_created=True,
            message='Exact retained wire exported to the explicit private file.' if command=='export' else
                'Selected opening saved to the explicit private file after certified exact execution. No delivery is sent.')
    return view

def operate(args,runner,stream,input_stream):
    c.pin(args.genesis_sha256);c.absolute(args.workspace);c.absolute(args.credentials)
    if args.command in LIFECYCLE:return lifecycle(args,runner,stream,input_stream)
    if args.command in ('inventory','doctor'):
        value=runner.run('wallet',args.command);need_success(value)
        if args.command=='doctor':return {'state':'configuration-valid','message':'Configuration checked. Encrypted wallet authentication was not performed.','can_submit':False}
        inv=value['inventory'];rows=inv['obligations']
        stream.write('1soft | Authenticated wallet\nObserved AS-OF height: '+str(inv['as_of_height'])+'\n')
        stream.write('Note commitments: '+str(len(inv['notes']))+' (values remain private)\n')
        for row in rows:stream.write('Payment: '+str(row['txid'] or 'proof pending')+' | attempts '+str(row['attempts'])+' | certified completion '+str(row['completed']).lower()+'\n')
        return {'state':'authenticated-inventory','message':'Authenticated wallet inventory. No balance or current-network freshness claim.',
            'can_submit':False,'inventory':inv}
    c.pin(args.txid);p.endpoint_port(args.endpoint)
    if args.command in ('review','submit'):
        if args.command=='submit':fresh_journal(args)
        v,digest=review(args,runner)
        projection=public_review(v,digest)
        ready=v['attempts']==0 and v['completed'] is False and not args.journal.exists() and not args.journal.is_symlink()
        if args.command=='submit':c.require(ready,'original attempted/completed; reconcile only')
        stream.write(review_text(v));stream.flush()
        if args.command=='review':return {'state':'reviewed','message':'Private original intent reviewed. Submission requires a separate explicit confirmation.',
            'can_submit':ready,'review':projection}
        token='SUBMIT '+args.txid+' '+v['wire_sha256']
        stream.write('Endpoint: '+args.endpoint+'\nA lost reply stays unknown; it cannot be resent automatically.\nType '+token+' to submit once, or press Enter to cancel:\n');stream.flush()
        line=input_stream.readline(220)
        if line.rstrip('\r\n')!=token:return {'state':'cancelled','message':STATE_TEXT['cancelled'],'can_submit':False,
            'review':projection,'confirmation':'cancelled','payment_child_started':False}
        current,current_digest=review(args,runner);c.require(current==v and current_digest==digest,'review changed; refresh explicitly')
        fresh_journal(args)
        value=runner.run('payment','submit');view=payment_view(value)
        c.require(value['wallet_id']==v['wallet_id'] and value['txid']==v['txid'],'submitted identity differs')
        return {**view,'review':projection,'confirmation':'exact-txid-and-wire','review_revalidated':True,'payment_child_started':True}
    extra=['--packet',args.packet] if args.command=='reconcile' and args.packet is not None else []
    return payment_view(runner.run('payment',args.command,extra))

def execute(args,stream=sys.stdout,input_stream=sys.stdin):
    runner=Runner(args);code=0;receipt_ready=False
    try:
        if args.receipt is not None:
            target=c.parents(args.receipt);c.directory(target.parent,private=True)
            workspace=c.absolute(args.workspace)
            c.require(workspace not in target.parents and target!=workspace and target!=c.absolute(args.credentials) and
                target!=getattr(args,'journal',None) and
                (getattr(args,'output',None) is None or target!=c.absolute(args.output)) and
                not target.exists() and not target.is_symlink(),'fresh separate receipt required')
            receipt_ready=True
        view=operate(args,runner,stream,input_stream)
    except (Exception,KeyboardInterrupt):
        view={'state':'refused','message':STATE_TEXT['refused'],'can_submit':False};code=1
    stream.write(render(view));stream.flush()
    receipt={'format':FORMAT,'command':args.command,'status':'refused' if code else 'console-completed',
        'pid':os.getpid(),'start_ticks':process_identity(os.getpid())[0],'genesis_sha256':args.genesis_sha256,
        'runtime_sha256':runtime_sha(),'view':view,'child_invocations':runner.calls,'child_responses':runner.responses,
        'forced_cleanup':runner.forced,'automatic_retry':False,'freshness_established':False,'production_ready':False,
        'private_review_values_retained':False}
    if args.receipt is not None and receipt_ready:
        try:c.private_output(args.receipt,c.canonical(receipt)+b'\n')
        except Exception:
            stream.write('Public receipt could not be saved. Preserve the original obligation; do not resend.\n');code=1
    return receipt,code
