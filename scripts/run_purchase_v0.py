#!/usr/bin/env python3
"""PURCHASE-V0, the 1soft half (Eternities Network PURCHASE-V0.md), on four validators of one host.

A fresh P9 ledger and two wallets (buyer, provider). The Network half (eternities-network scripts/purchase-v0.ts)
runs a real eID issuer and a work contract priced in 1soft; it hands over the contract's intent through an
exchange directory. Here the buyer binds one payment to that intent (request = the intent's digest in the field),
a separate buyer process submits it once through a receiver that discards the reply and is killed, a fresh
process recovers the exact execution from signed history, a wallet-less process verifies it publicly, and the
evidence goes back to settle the contract. Synthetic funds and keys; not production readiness."""
import argparse, base64, hashlib, http.server, json, os, signal, subprocess, sys, threading, time
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1];sys.path.insert(0,str(ROOT/'src'))
import protocol8_transfer as n
from protocol8_worker import Worker
from protocol9_consensus import GENESIS_FORMAT, bootstrap_digest, genesis_document
from protocol9_certificate import export_history, verify_history
from protocol9_notes import NoteController, Prover
from protocol9_history_wallet import RecipientWallet
from protocol9_payment import send_once
from run_protocol9_engine import Network, source
from run_protocol8_engine import field
from run_protocol5_engine import ENGINE_SHA256
from run_devnet import rpc, wait_until

UNIT='1soft:DEV';INTENT='eternities/purchase-intent/v0';SETTLEMENT='eternities/onesoft-settlement/v0'
PAYER=ROOT/'scripts/purchase_v0_payer.py'
CHECKS=('source_clean','engine_identity','four_validators_initialized','signed_initial_history','hello_written',
    'request_matches_network','intent_names_this_ledger','payment_bound_to_intent','buyer_killed_after_single_forward',
    'second_payment_refused','cold_buyer_recovered_exact','public_verifier_executed_exact','provider_holds_received_note',
    'evidence_returned','network_settled','cold_retry_refused','native_processes_reaped','workers_stopped','source_unchanged')

def request_of(intent):
    """sha256 of the Network's canonical JSON (sorted keys, no spaces, utf-8), big-endian, reduced into the field,
    32 bytes little-endian: the same rule as eternities-network src/onesoft.ts onesoftRequest."""
    body=json.dumps(intent,sort_keys=True,separators=(',',':'),ensure_ascii=False).encode('utf-8')
    r=int.from_bytes(hashlib.sha256(body).digest(),'big')%n.MODULUS;n.need(r!=0,'purchase zero request')
    return r.to_bytes(32,'little').hex()

def run(args):
    output=args.output.absolute();ex=args.exchange.absolute()
    n.need(not output.exists() and not output.with_name(output.name+'.artifacts').exists(),'fresh purchase receipt')
    n.need(ex.is_dir() and not any(ex.iterdir()),'empty exchange directory')
    before=source();report={'format':'1soft/purchase-v0/v0','status':'failed','source':before,'checks':[],'inputs':{},'native_processes':[],
        'claims':{'synthetic_funds':True,'one_host_four_validators':True,'independent_operators':False,'public_network':False,
        'production_custody':False,'shared_treasury':False,'freshness':False,'external_review':False}}
    network=None;workers=[];private=[];server=None;thread=None
    def check(name,ok,evidence=None):
        report['checks'].append({'id':name,'passed':bool(ok),'evidence':evidence or {}})
        print('PURCHASE_CHECK '+name+' '+str(bool(ok)),flush=True);n.need(ok,'purchase gate failed: '+name)
    def put(name,value):
        tmp=ex/(name+'.tmp');tmp.write_bytes(n.canonical(value)+b'\n');os.chmod(tmp,0o600);tmp.rename(ex/name)
    def take(name,seconds):
        until=time.monotonic()+seconds
        while not (ex/name).exists():
            n.need(not (ex/'network-failed.json').exists(),'network half failed');n.need(time.monotonic()<until,'timed out waiting for '+name);time.sleep(0.5)
        return json.loads((ex/name).read_bytes())
    def fixture(op,bootstrap):
        n.need(n.sha(args.fixture.read_bytes())==report['inputs']['fixture']['sha256'],'P9 fixture identity changed')
        fd=os.open(args.fixture,os.O_RDONLY|os.O_NOFOLLOW);child=None;out=b'';ticks=None
        try:
            child=subprocess.Popen(['/proc/self/fd/'+str(fd),op],stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=subprocess.PIPE,env={},pass_fds=(fd,),start_new_session=True)
            ticks=Path('/proc/'+str(child.pid)+'/stat').read_text().rsplit(')',1)[1].split()[19]
            out,err=child.communicate(bootstrap,timeout=45)
            n.need(child.returncode==0 and not err and len(out)<=1160,'P9 fixture output');return out
        finally:
            if child:
                try:os.killpg(child.pid,signal.SIGKILL)
                except ProcessLookupError:pass
                child.communicate();report['native_processes'].append({'operation':op,'pid':child.pid,'start_ticks':ticks,
                    'binary_sha256':report['inputs']['fixture']['sha256'],'exit_code':child.returncode,'output_bytes':len(out),'process_reaped':child.poll() is not None})
            os.close(fd)
    def observation(label):
        held=network.hold_sources_without_quorum();witness=export_history(network.runtime/'app0/state.sqlite')
        n.need(witness['height']==held['height'] and witness['app_hash']==held['app_hash'],'P9 history export checkpoint race')
        network.start_engine(2);network.start_engine(3)
        wait_until(lambda:network.height(0)>=witness['height']+1,120)
        signed=rpc(network.http[0],'commit',{'height':str(witness['height']+1)})['signed_header']
        network.hold_sources_without_quorum()
        cert,ledger=verify_history(witness,signed,raw,w)
        report.setdefault('observations',[]).append({'label':label,'height':witness['height'],'app_hash':witness['app_hash']})
        return witness,signed,ledger
    def resume_and_wait(count):
        network.start_engine(2);network.start_engine(3)
        wait_until(lambda:all(network.direct_state(i)['checkpoint']['accepted_count']==count for i in range(4)),240)
    def payer(mode,extra,secret_row=None,keep=False):
        command=[sys.executable,'-B',str(PAYER),mode,'--genesis',str(fixtures/'genesis.json'),'--genesis-sha256',n.sha(raw),
            '--kat',str(fixtures/'kat.tx'),'--worker',str(args.worker),'--worker-sha256',g['worker_sha256'],'--txid',ident,*extra]
        child=subprocess.Popen(command,stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=subprocess.PIPE,start_new_session=True)
        child.stdin.write(n.canonical(secret_row) if secret_row else b'');child.stdin.close()
        line=[];reader=threading.Thread(target=lambda:line.append(child.stdout.readline()),daemon=True);reader.start();reader.join(300)
        if keep:
            os.killpg(child.pid,signal.SIGKILL)
        else:
            try:child.wait(300)
            except subprocess.TimeoutExpired:os.killpg(child.pid,signal.SIGKILL)
        child.wait();child.stdout.close();err=child.stderr.read();child.stderr.close()
        report['native_processes'].append({'operation':'payer-'+mode,'pid':child.pid,'exit_code':child.returncode,'killed':keep,
            'stderr_bytes':len(err),'process_reaped':child.poll() is not None,'script_sha256':n.sha(PAYER.read_bytes())})
        n.need(line and line[0],'payer '+mode+' gave no result');return json.loads(line[0]),child.returncode
    ident=None
    try:
        check('source_clean',before['clean'])
        for name in ('engine','worker','helper','fixture','prover'):
            path=getattr(args,name);n.need(path.is_file() and not path.is_symlink() and 0<path.stat().st_size<=64*1024**2,'P9 binary input')
            report['inputs'][name]={'sha256':n.sha(path.read_bytes()),'bytes':path.stat().st_size}
        check('engine_identity',report['inputs']['engine']['sha256']==ENGINE_SHA256 and subprocess.check_output([str(args.engine),'version'],text=True).strip()=='0.38.25')
        seed=Worker(args.worker,report['inputs']['worker']['sha256'],args.kat.read_bytes());workers.append(seed)
        network=Network({'engine':args.engine,'worker':args.worker},output,report)
        vals=sorted([{'public_key':base64.b64decode(v['pub_key']['value'],validate=True).hex(),'power':int(v['power'])} for v in network.engine_genesis['validators']],key=lambda v:v['public_key'])
        g={'format':GENESIS_FORMAT,'protocol_version':9,'chain_id':network.chain_id,'profile_sha256':n.PROFILE_SHA256,
            'worker_sha256':seed.sha256,'kat_sha256':seed.kat_sha256,'validators':vals,'pool_id':os.urandom(32).hex(),
            'network':field(1),'asset':field(2),'mission':field(3),'fee':1,'notes':[]}
        bootstrap=bytes.fromhex(bootstrap_digest(g));g['network']=seed.network_domain(bootstrap)
        note=fixture('genesis-note',bootstrap);g['notes']=[{'kind':'p8-recipient-v1','commitment':note.hex()}]
        controller=NoteController(args.helper,report['inputs']['helper']['sha256'],g=g,worker=seed)
        prover=Prover(args.prover,report['inputs']['prover']['sha256'],g=g,worker=seed);private.extend((controller,prover))
        request=bytearray(fixture('first',bootstrap))
        try:first=prover.produce(bytes(request))
        finally:request[:]=bytes(len(request))
        g['kat_sha256']=n.sha(first);raw=n.canonical(g);w=Worker(args.worker,g['worker_sha256'],first);workers.append(w)
        genesis_document(raw,w);controller.worker=w;prover.worker=w
        fixtures=network.runtime/'public-proofs';fixtures.mkdir(mode=0o700);network.paths.update(fixtures=fixtures,kat=fixtures/'kat.tx')
        (fixtures/'genesis.json').write_bytes(raw);(fixtures/'kat.tx').write_bytes(first)
        network.install_genesis(raw,w);network.start_sources();wait_until(lambda:all(network.direct_state(i)['height']>=1 for i in range(4)),120)
        check('four_validators_initialized',all(network.direct_state(i)['genesis']==g for i in range(4)))
        initial,signed,_=observation('initial');check('signed_initial_history',initial['checkpoint']['accepted_count']==0)
        homes=network.runtime/'wallets';homes.mkdir(mode=0o700)
        keys={'buyer':os.urandom(32),'provider':os.urandom(32)};ids={name:os.urandom(32).hex() for name in keys}
        secrets={'buyer':field(31),'provider':field(41)}
        wallets={name:RecipientWallet(homes/name,key=keys[name],wallet_id=ids[name],recipient_secret=secrets[name],controller=controller,create=True) for name in keys}
        buyer,provider=wallets['buyer'],wallets['provider']
        for wallet in wallets.values():wallet.observe(initial,signed)
        buyer.import_note(note.hex(),{'origin':field(111),'value':1000,'expiry':100000,'note_secret':field(32),'blind':field(33)},genesis=True)
        row={'path':str(homes/'buyer'),'key':keys['buyer'].hex(),'wallet_id':ids['buyer'],'recipient_secret':secrets['buyer']}
        put('hello.json',{'genesis_sha256':n.sha(raw),'buyer_recipient_key':buyer.recipient_key,'provider_recipient_key':provider.recipient_key})
        check('hello_written',True,{'genesis_sha256':n.sha(raw)})

        got=take('intent.json',args.wait);intent=got['intent'];req=request_of(intent)
        check('request_matches_network',req==got['request'],{'request':req})
        amount=intent.get('amount')
        check('intent_names_this_ledger',intent.get('v')==INTENT and intent.get('unit')==UNIT and intent.get('genesis_sha256')==n.sha(raw) and
            intent.get('provider_recipient_key')==provider.recipient_key and type(amount) is int and 0<amount<1000-g['fee'],{'amount':amount,'contract_id':intent.get('contract_id')})
        ident=buyer.prepare(prover,note.hex(),request=req,destination=provider.recipient_key,payment=amount,valid_until=100000,payment_expiry=100000)
        wire=buyer.export(ident);(fixtures/'purchase.tx').write_bytes(wire)
        check('payment_bound_to_intent',n.parse(wire)[6]==req and buyer.inventory()['obligations'][0]['attempts']==0,{'txid':ident})

        forwarded=[];forward_errors=[]
        class DropReply(http.server.BaseHTTPRequestHandler):
            def log_message(self,*args):pass
            def do_POST(self):
                try:
                    length=int(self.headers.get('Content-Length','0'));n.need(0<length<8192,'bounded drop proxy')
                    value=json.loads(self.rfile.read(length));sent=base64.b64decode(value['params']['tx'],validate=True)
                    n.need(sent==wire,'drop proxy exact original wire');forwarded.append(n.txid(sent))
                    admitted=network.broadcast(0,sent);n.need(int(admitted['code'])==0,'drop proxy admission')
                except Exception as exc:forward_errors.append(type(exc).__name__)
                finally:self.close_connection=True;self.connection.close()
        server=http.server.HTTPServer(('127.0.0.1',0),DropReply);thread=threading.Thread(target=server.serve_forever,daemon=True);thread.start()
        helper=['--helper',str(args.helper),'--helper-sha256',report['inputs']['helper']['sha256']]
        sent,code=payer('send',[*helper,'--endpoint','http://127.0.0.1:'+str(server.server_port)],row,keep=True)
        server.shutdown();server.server_close();thread.join(5);server=None
        check('buyer_killed_after_single_forward',sent.get('result',{}).get('outcome')=='unknown' and forwarded==[ident] and not forward_errors and code==-signal.SIGKILL,
            {'caller':sent.get('result'),'forwards':len(forwarded),'exit_code':code})
        refused=[]
        try:send_once(buyer,ident,'http://127.0.0.1:'+str(network.http[0]));raise AssertionError('second send accepted')
        except n.Invalid:refused.append('send')
        try:buyer.prepare(prover,note.hex(),request=req,destination=provider.recipient_key,payment=amount,valid_until=100000,payment_expiry=100000);raise AssertionError('second prepare accepted')
        except n.Invalid:refused.append('prepare')
        check('second_payment_refused',refused==['send','prepare'] and buyer.reconcile(ident)['status']=='unresolved-held')

        resume_and_wait(1);executed,signed,_=observation('purchase-executed')
        (fixtures/'witness.json').write_bytes(n.canonical(executed));(fixtures/'header.json').write_bytes(n.canonical(signed))
        observed=['--witness',str(fixtures/'witness.json'),'--header',str(fixtures/'header.json')]
        rec,code=payer('recover',[*helper,*observed],row)
        check('cold_buyer_recovered_exact',code==0 and rec.get('result',{}).get('status')=='executed-exact' and rec['result']['txid']==ident,{'result':rec.get('result')})
        ver,code=payer('verify',[*observed,'--wire',str(fixtures/'purchase.tx'),'--request',req])
        (fixtures/'verify-report.json').write_bytes(n.canonical(ver))
        check('public_verifier_executed_exact',code==0 and ver.get('status')=='executed-exact',{'state_height':ver.get('state_height')})
        provider.observe(executed,signed);out_note=n.parse(wire)[10]
        provider.import_note(out_note,buyer.output_opening(ident),raw=wire)
        check('provider_holds_received_note',provider.inventory()['notes']==[out_note])
        app=str(executed['app_hash']).lower()
        evidence={'format':SETTLEMENT,'intent':intent,'request':req,'txid':ident,'state_height':int(executed['height']),'app_hash':app,
            'verifier':{'tool':'1soft scripts/purchase_v0_payer.py verify','status':ver['status'],'report_sha256':n.sha(n.canonical(ver)),'worker_sha256':g['worker_sha256']}}
        put('evidence.json',{'settlement':evidence})
        check('evidence_returned',True,{'txid':ident,'state_height':evidence['state_height']})
        settled=take('settled.json',args.wait)
        check('network_settled',settled.get('contract_id')==intent['contract_id'],settled)
        again,code=payer('send',[*helper,'--endpoint','http://127.0.0.1:'+str(network.http[0])],row)
        check('cold_retry_refused',code==1 and again.get('status')=='refused' and all(r['attempts']==1 for r in buyer.inventory()['obligations']))
        report['payment']={'txid':ident,'request':req,'wire_sha256':n.sha(wire),'amount':amount,'genesis_sha256':n.sha(raw),'evidence':evidence}
        report['worker_audits']=[{'node':i,**network.worker_audit(i)} for i in range(4)]+[{'node':'wallet-'+str(i),**x.audit()} for i,x in enumerate(workers)]
        report['private_process_audits']=[item.audit() for item in private]
        audits=report['worker_audits']+report['private_process_audits']
        check('native_processes_reaped',all(a['call_count']==a['reaped_count'] and a['timeout_count']==0 for a in audits) and all(r['process_reaped'] for r in report['native_processes']))
    except Exception as exc:
        report['error']={'type':type(exc).__name__,'message':str(exc)}
        try:put('onesoft-failed.json',report['error'])
        except Exception:pass
    finally:
        if server:server.shutdown();server.server_close()
        if thread:thread.join(5)
        if network:
            try:network.close();check('workers_stopped',all(type(p.get('exit_code')) is int for p in report['processes']))
            except Exception as exc:report['cleanup_error']={'type':type(exc).__name__,'message':str(exc)}
        report['checks'].append({'id':'source_unchanged','passed':source()==before,'evidence':{}})
        if tuple(c['id'] for c in report['checks'])==CHECKS and all(c['passed'] for c in report['checks']) and not report.get('cleanup_error'):report['status']='qualified-one-host-purchase-v0'
        output.write_bytes(n.canonical(report)+b'\n')
    return 0 if report['status']=='qualified-one-host-purchase-v0' else 1

if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__)
    for name in ('engine','worker','helper','fixture','prover','kat','output','exchange'):parser.add_argument('--'+name,type=Path,required=True)
    parser.add_argument('--wait',type=float,default=2700)
    raise SystemExit(run(parser.parse_args()))
