"""Disposable one-host synthetic demo. Never a public node or custody launcher."""
from __future__ import annotations
import argparse,base64,copy,http.client,json,os,signal,socket,subprocess,sys,threading,time
from http.server import BaseHTTPRequestHandler,HTTPServer
from pathlib import Path
ROOT=Path(__file__).resolve().parents[3]
sys.path[:0]=[str(ROOT/'src'),str(ROOT/'scripts'),str(ROOT/'tools/release')]
import protocol8_transfer as n
import protocol8_wallet_cli as cli
import run_protocol8_wallet_cli as gate
from protocol8_worker import Worker
from protocol8_notes import NoteController
from protocol8_consensus import bootstrap_digest,GENESIS_FORMAT,PROFILE_SHA256,genesis_document
from protocol8_certificate import verify_state
from run_protocol8_engine import field
from run_protocol5_engine import ENGINE_SHA256,_hold_transaction_height
from run_devnet import rpc,wait_until
from check_protocol8_native import batch_startup
from wallet_app import Service,Server

def source():
    value=gate.wallet_gate.source()
    paths=list((ROOT/'tools/p8-wallet').rglob('*'))+[ROOT/'tools/release/check_protocol8_native.py']
    for p in paths:
        if p.is_file() and '__pycache__' not in p.parts:
            raw=p.read_bytes();value['files'][p.relative_to(ROOT).as_posix()]={'bytes':len(raw),'sha256':n.sha(raw)}
    value['files']=dict(sorted(value['files'].items()));return value

class LostReply:
    """One independently bounded forward/drop transport per disposable wallet."""
    def __init__(self,owner,role,row,journal):
        self.owner=owner;self.role=role;self.row=row;self.journal=journal;self.requests=[];self.error=None
        proxy=self
        class Handler(BaseHTTPRequestHandler):
            def log_message(self,*args):pass
            def setup(self):super().setup();self.connection.settimeout(5)
            def do_POST(self):
                connection=None
                try:
                    n.need(self.path=='/' and self.headers.get_all('Content-Type',[])==['application/json'] and not self.headers.get('Transfer-Encoding'),'exact local proxy request')
                    lengths=self.headers.get_all('Content-Length',[])
                    n.need(len(lengths)==1 and lengths[0].isascii() and lengths[0].isdecimal(),'proxy length')
                    size=int(lengths[0]);n.need(0<size<=8192,'proxy body bound')
                    raw=self.rfile.read(size);n.need(len(raw)==size,'proxy complete body')
                    value=json.loads(raw);wire=base64.b64decode(value['params']['tx'],validate=True)
                    n.need(value=={'jsonrpc':'2.0','id':1,'method':'broadcast_tx_sync','params':{'tx':base64.b64encode(wire).decode()}},'exact RPC required')
                    plain=owner.net.plain(row);items=[x for x in plain['obligations'] if x['raw']==wire.hex()]
                    n.need(len(items)==1 and items[0]['attempts']==1,'original durable attempt before I/O')
                    record=json.loads(cli.read_file(journal,16384,private=True))['record']
                    n.need(record['phase']=='attempt-marked' and record['txid']==n.txid(wire),'journal original before I/O')
                    n.need(not proxy.requests and not proxy.error,'one forward budget; never retry')
                    # Reserve before I/O, so an upstream failure cannot reopen the budget.
                    proxy.requests.append({'txid':n.txid(wire),'wire_sha256':n.sha(wire),'wire_bytes':len(wire),
                        'wallet_attempts_before_io':1,'journal_phase_before_io':'attempt-marked',
                        'forward_count':1,'reply_forwarded':False})
                    connection=http.client.HTTPConnection('127.0.0.1',owner.net.http[0],timeout=90)
                    connection.request('POST','/',body=raw,headers={'Content-Type':'application/json'})
                    response=connection.getresponse();reply=response.read(8193)
                    n.need(response.status==200 and len(reply)<=8192,'actual node reply bound')
                    result=json.loads(reply)['result']
                    n.need(type(result['code']) is int and result['code']==0 and result['hash'].lower()==n.sha(wire),'actual node admission differs')
                    proxy.requests[-1].update(node_admission_code=0,node_wire_hash=result['hash'].lower(),upstream_reply_sha256=n.sha(reply))
                except Exception as exc:proxy.error=type(exc).__name__
                finally:
                    if connection:connection.close()
                    self.close_connection=True
                    try:self.connection.shutdown(socket.SHUT_RDWR)
                    except OSError:pass
        self.server=HTTPServer(('127.0.0.1',0),Handler);self.server.timeout=5
        self.endpoint='http://127.0.0.1:'+str(self.server.server_port)
        self.thread=threading.Thread(target=self.server.serve_forever,name='1soft-demo-proxy-'+role);self.thread.start()
    def close(self):
        self.server.shutdown();self.server.server_close();self.thread.join(10)
        n.need(not self.thread.is_alive(),'owned proxy stopped')
        return {'role':self.role,'requests':self.requests,'error_type':self.error,'stopped':True}

class AuditedService(Service):
    def __init__(self,owner,role,*args,**kwargs):self.owner=owner;self.role=role;super().__init__(*args,**kwargs)
    def invoke(self,command,extra,confirmation):
        row=self.owner.wallets[self.role];before=n.sha(row['path'].read_bytes())
        value=super().invoke(command,extra,confirmation)
        after=n.sha(row['path'].read_bytes())
        # Public console receipt deliberately omits private original review.
        public={k:copy.deepcopy(v) for k,v in value.items() if k!='private_display'}
        public.update(role=self.role,wallet_sha256_before=before,wallet_sha256_after=after,
            private_display_retained=False)
        self.owner.report['browser_actions'].append(public)
        if value['status']=='refused':n.need(before==after,'refused UI action changed wallet')
        return value

class Demo:
    def __init__(self,args):
        self.args=args;self.output=args.output.absolute();self.net=None;self.proxies={};self.servers={};self.threads={}
        self.wallets={};self.controllers=[];self.workers=[];self.receive=None;self.settled={};self.closed=False
        n.need(not self.output.exists() and not self.output.with_name(self.output.name+'.artifacts').exists(),'fresh demo evidence required')
        self.report={'format':'1soft/protocol8-browser-alpha/v1','status':'in-progress','source':source(),
            'inputs':{},'native_processes':[],'browser_actions':[],'signed_packets':[],
            'claims':{'one_trusted_host':True,'synthetic_funds':True,'actual_browser_required':True,
              'automatic_retry':False,'freshness_established':False,'production_ready':False,
              'public_network':False,'independent_operators':False,'production_custody':False},'checks':[]}
    def invoke(self,name,op,raw):
        path=getattr(self.args,name);n.need(n.sha(path.read_bytes())==self.report['inputs'][name]['sha256'],'native fixture binary changed')
        proc=subprocess.Popen([str(path),*([op] if op else [])],stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=subprocess.PIPE,env={},start_new_session=True)
        birth=gate.process_identity(proc.pid);n.need(birth is not None,'fixture native birth')
        try:
            out,err=proc.communicate(raw,timeout=180)
            n.need(proc.returncode==0 and not err and len(out)<=4096,'actual fixture/prover output')
            return out
        finally:
            if proc.poll() is None:gate.abort_owned_tree(proc)
            self.report['native_processes'].append({'binary':name,'operation':op or 'prove',
              'pid':proc.pid,'start_ticks':birth[0],'binary_sha256':self.report['inputs'][name]['sha256'],
              'exit_code':proc.returncode,'process_reaped':proc.poll() is not None})
    def setup(self):
        n.need(self.report['source']['clean'],'committed clean source required for disposable demo')
        for name in ('engine','worker','helper','fixture','prover'):
            p=getattr(self.args,name);n.need(p.is_file() and not p.is_symlink(),'actual native binary required')
            # Cargo may hard-link its release artifact. The protected CLI
            # requires a separately owned single-link executable, without
            # changing any trust rule. Refuse before starting validators.
            data=cli.read_file(p,(64 if name=='engine' else 32)*1024**2,executable=True)
            self.report['inputs'][name]={'bytes':len(data),'sha256':n.sha(data)}
        n.need(self.report['inputs']['engine']['sha256']==ENGINE_SHA256 and subprocess.check_output([str(self.args.engine),'version'],text=True).strip()=='0.38.25','frozen actual engine')
        preliminary=Worker(self.args.worker,self.report['inputs']['worker']['sha256'],self.args.kat.read_bytes());self.workers.append(preliminary)
        self.net=gate.Network({'engine':self.args.engine,'worker':self.args.worker},self.output,self.report)
        validators=sorted([{'public_key':base64.b64decode(v['pub_key']['value'],validate=True).hex(),'power':int(v['power'])}
            for v in self.net.engine_genesis['validators']],key=lambda v:v['public_key'])
        g={'format':GENESIS_FORMAT,'protocol_version':8,'chain_id':self.net.chain_id,'profile_sha256':PROFILE_SHA256,
          'worker_sha256':self.report['inputs']['worker']['sha256'],'kat_sha256':preliminary.kat_sha256,
          'validators':validators,'pool_id':os.urandom(32).hex(),'asset':field(2),'mission':field(3),'fee':1,'network':field(1),'notes':[]}
        bootstrap=bytes.fromhex(bootstrap_digest(g));domain=preliminary.network_domain(bootstrap)
        request=self.invoke('fixture','first',bootstrap);first=self.invoke('prover',None,request)
        note=self.invoke('fixture','genesis-note',bootstrap)
        g.update(network=domain,notes=[{'kind':'p8-recipient-v1','commitment':note.hex()}],kat_sha256=n.sha(first));raw=n.canonical(g)
        fixtures=self.net.runtime/'proof-fixtures';fixtures.mkdir(mode=0o700);self.net.paths['fixtures']=fixtures
        cli.write_new(fixtures/'first.tx',first);cli.write_new(fixtures/'genesis.json',raw);self.net.paths['kat']=fixtures/'first.tx'
        w=Worker(self.args.worker,g['worker_sha256'],first);self.workers.append(w)
        n.need(genesis_document(raw,w)==g and w.verify(first,domain),'fresh native receive KAT/domain')
        self.controller=NoteController(self.args.helper,self.report['inputs']['helper']['sha256'],expected_genesis=raw,worker=w);self.controllers.append(self.controller)
        original={'origin':field(111),'value':20,'expiry':64,'note_secret':field(32),'blind':field(33)}
        req,origin=self.controller.construct(original,field(31),[note.hex()],request=field(21),valid_from=2,valid_until=32,
          fee=1,destination=self.controller.key(field(41)),payment=12,payment_expiry=60,payment_secret=field(42),payment_blind=field(43),change_secret=field(34),change_blind=field(35))
        n.need(req[136:552]==first[8:424],'exact native opening origin')
        opening={'origin':origin,'value':12,'expiry':60,'note_secret':field(42),'blind':field(43)}
        self.net.needles.extend([request.hex().encode(),req.hex().encode()])
        self.net.needles.extend(field(v).encode() for v in (31,32,33,34,35,41,42,43,51))
        self.report.update(genesis=g,genesis_sha256=n.sha(raw),wallet_cli_inputs={'helper':str(self.args.helper),'prover':str(self.args.prover)})
        self.raw=raw;self.net.install_genesis(raw,w);self.net.start_sources();_hold_transaction_height(self.net)
        self.net.stage_without_quorum([first]);wait_until(lambda:self.count(1),180)
        self.receive=self.packet('receive',self.net.hold_sources_without_quorum())
        self.receive_opening=self.net.file(n.canonical(opening))
        for role,secret in (('bob',41),('carol',51)):
            root=self.net.runtime/(role+'-private');root.mkdir(mode=0o700)
            wallet=gate.Wallet(root/'wallet',key=os.urandom(32),wallet_id=os.urandom(32).hex(),recipient_secret=field(secret),controller=self.controller,create=True)
            self.wallets[role]=wallet.row
        for role,row in self.wallets.items():
            journal=row['path'].parent/'payment-journal'
            proxy=LostReply(self,role,row,journal);self.proxies[role]=proxy
            service=AuditedService(self,role,row['workspace'],row['credentials'],self.net.genesis_sha256,
              proxy.endpoint,journal,demo_inputs=lambda role=role:self.context(role))
            server=Server(service);self.servers[role]=server
            thread=threading.Thread(target=server.serve_forever,kwargs={'poll_interval':0.1},name='1soft-demo-wallet-'+role)
            self.threads[role]=thread;thread.start()
        n.need(len({s.origin for s in self.servers.values()})==2 and len({s.service.token for s in self.servers.values()})==2,'independent local sessions')
        self.report['wallet_servers']={r:{'origin':s.origin,'session_token_retained':False,'loopback_only':True} for r,s in self.servers.items()}
        return {'event':'ready','wallets':{r:s.origin for r,s in self.servers.items()},'synthetic_funds':True}
    def count(self,k):
        rows=[self.net.direct_state(i) for i in range(4)]
        return rows if all(len(r['state']['ledger']['receipts'])==k for r in rows) else None
    def packet(self,label,witness):
        self.net.start_engine(2);self.net.start_engine(3)
        wait_until(lambda:self.net.height(0)>=witness['height']+1,180)
        header=rpc(self.net.http[0],'commit',{'height':str(witness['height']+1)})['signed_header']
        verify_state(witness,header,self.raw,self.workers[-1]);self.net.hold_sources_without_quorum()
        value={'witness':witness,'signed_header':header};path=self.net.file(n.canonical(value))
        public=self.net.paths['fixtures']/(label+'-signed.json');cli.write_new(public,n.canonical(value))
        self.report['signed_packets'].append({'phase':label,'bytes':public.stat().st_size,'sha256':n.sha(public.read_bytes()),'witness':witness,'signed_header':header})
        return path
    def context(self,role):
        other='carol' if role=='bob' else 'bob';row=self.wallets[role]
        if role=='bob':packet=self.receive;opening=self.receive_opening;wire=self.net.paths['fixtures']/'first.tx'
        else:
            packet=self.settled.get('bob',self.receive)
            opening=self.wallets['bob']['path'].parent/'recipient-opening'
            wire=self.wallets['bob']['path'].parent/'exact-wire'
        recovery=self.settled.get(role,packet)
        return {'format':'1soft/synthetic-demo-inputs/v1',
          'output_paths':{'export':str(row['path'].parent/'exact-wire'),'deliver':str(row['path'].parent/'recipient-opening')},'forms':{
          'observe-form':{'packet':str(packet)},'import-form':{'opening':str(opening),'source':'received','wire':str(wire),'output_index':'10'},
          'prepare-form':{'destination':json.loads((self.wallets[other]['workspace']/'wallet-cli.json').read_bytes())['wallet_pins']['recipient_key'],
             'payment':'4' if role=='bob' else '2','valid_until':'48','payment_expiry':'56'},
          'recover-form':{'packet':str(recovery)},'output-form':{'output':str(row['path'].parent/'exact-wire'),'kind':'export','output_index':'10'}},
          'message':'Disposable '+role+' wallet. Inputs only: authenticate state, import and review explicitly. After an unknown send, use the terminal settle command, then load inputs and reconcile. Nothing was sent.'}
    def settle(self,role):
        n.need(role in self.wallets and role not in self.settled,'one explicit settlement per role')
        proxy=self.proxies[role];n.need(len(proxy.requests)==1 and proxy.error is None and proxy.requests[0].get('node_admission_code')==0,'actual one-request lost reply required')
        row=self.wallets[role];plain=self.net.plain(row)
        item=next(x for x in plain['obligations'] if x['raw'] and n.txid(bytes.fromhex(x['raw']))==proxy.requests[0]['txid'])
        wire=bytes.fromhex(item['raw']);n.need(item['attempts']==1,'one durable original attempt')
        wait_until(lambda:all(wire in self.net.mempool_transactions(i) for i in (0,1)),30)
        self.net.start_engine(2);self.net.start_engine(3)
        count=2 if role=='bob' else 3;rows=wait_until(lambda:self.count(count),180)
        state=self.net.hold_sources_without_quorum()
        n.need(all(n.canonical(x)==n.canonical(state) for x in rows) and state['state']['ledger']['receipts'][-1]['txid']==n.txid(wire),'four actual validators execute exact original')
        cli.write_new(self.net.paths['fixtures']/(role+'-spend.tx'),wire)
        self.settled[role]=self.packet(role+'-executed',state)
        return {'event':'settled','role':role,'txid':n.txid(wire),'as_of_height':state['height'],'four_validator_agreement':True}
    def delivery_path(self,role):return str(self.wallets[role]['path'].parent/'recipient-opening')
    def finish(self,browser=None):
        errors=[]
        for role,server in self.servers.items():
            try:
                server.shutdown();server.server_close();self.threads[role].join(10)
                n.need(not self.threads[role].is_alive(),'owned foreground wallet stopped')
            except Exception as exc:errors.append(type(exc).__name__)
        self.report['proxies']=[]
        for p in self.proxies.values():
            try:self.report['proxies'].append(p.close())
            except Exception as exc:errors.append(type(exc).__name__)
        if self.net:
            try:
                self.report['worker_audits']=[{'node':i,**self.net.worker_audit(i)} for i in range(4)]+[{'node':'host-'+str(i),**w.audit()} for i,w in enumerate(self.workers)]
                self.report['helper_audits']=[c.audit() for c in self.controllers]
                self.net.close()
            except Exception as exc:errors.append(type(exc).__name__)
        self.report['cleanup_errors']=errors;self.report['source_unchanged']=source()==self.report['source']
        if browser:self.report['browser']=browser
        self.closed=True
        try:
            self.validate()
            self.report['status']='qualified-one-host-synthetic-browser-alpha'
        except Exception as exc:
            self.report['status']='failed' if browser or 'failure_type' in self.report else 'stopped-unqualified-interactive-demo'
            self.report['qualification_error_type']=type(exc).__name__
        self.output.write_bytes(n.canonical(self.report)+b'\n')
        return {'event':'finished','status':self.report['status'],'evidence':self.output.name}
    def validate(self):
        n.need(not self.report['cleanup_errors'] and self.report['source_unchanged'],'owned cleanup/source unchanged')
        n.need(set(self.settled)=={'bob','carol'} and len(self.report['signed_packets'])==3,'two actual settled payments')
        n.need(all(len(p['requests'])==1 and p['error_type'] is None and p['stopped'] for p in self.report['proxies']),'two independent one-request proxies')
        n.need(self.report.get('browser',{}).get('status')=='passed-actual-browser-flow','real browser result required')
        actions=self.report['browser_actions']
        for role in ('bob','carol'):
            rows=[a for a in actions if a['role']==role]
            n.need(sum(a['command']=='submit' and a['status']!='refused' for a in rows)==1,'one actual UI submit per role')
            n.need(any(a['command']=='submit' and a['status']=='refused' for a in rows),'repeat protected submit refused')
            n.need(any(a['command']=='reconcile' and a['console_receipt']['view']['state']=='executed-exact' for a in rows),'signed exact recovery through browser')
        for a in actions:
            n.need(a['process']['process_reaped'] is True and a['private_display_retained'] is False,'console reaped/private display omitted')
        audits=[]
        def collect(value):
            if isinstance(value,dict):
                if 'native_audits' in value:
                    for kind,audit in value['native_audits'].items():
                        if kind=='worker':batch_startup(audit)
                        audits.append(audit)
                for v in value.values():collect(v)
            elif isinstance(value,list):
                for v in value:collect(v)
        collect(actions);collect(self.report['wallet_cli']['responses'])
        audits+=self.report['worker_audits']+self.report['helper_audits']
        for a in self.report['worker_audits']:batch_startup(a)
        n.need(all(a['call_count']==a['reaped_count']==a['retained_count']==len(a['calls']) and a['timeout_count']==0 for a in audits),'all actual native audits reaped')
        n.need(all(p['exit_code'] is not None for p in self.report['processes']),'all owned validator/application exits')
        material=n.canonical(self.report)+b''.join(p.read_bytes() for p in self.output.with_name(self.output.name+'.artifacts').iterdir())
        needles=[v for v in self.net.needles if v and v not in n.canonical(self.report['genesis']) and v not in (self.net.paths.get('kat',Path('/missing')).name.encode())]
        # Small public context integers are explicitly excluded, as in the prior fixture.
        public=b''.join(bytes.fromhex(r['raw']).hex().encode() for p in self.report['signed_packets'] for r in p['witness']['state']['ledger']['receipts'])
        n.need(all(v not in material for v in needles if v not in public),'known synthetic secret absent from public evidence')
        self.report['checks']=[{'id':k,'passed':True} for k in ('fresh_native_four_validators','actual_browser_two_wallet_flow','two_lost_reply_one_attempts',
            'two_signed_exact_recoveries','recipient_received_funds_used','duplicate_submit_refused_without_io','native_children_reaped','owned_servers_nodes_stopped','known_private_material_absent','source_unchanged')]

def parser():
    p=argparse.ArgumentParser(description=__doc__)
    for name in ('engine','worker','helper','fixture','prover','kat','output'):p.add_argument('--'+name,type=Path,required=True)
    p.add_argument('--automated',action='store_true');return p

def main():
    args=parser().parse_args();demo=Demo(args)
    try:
        value=demo.setup();print('ALPHA_EVENT '+json.dumps(value),flush=True)
        if not args.automated:
            print('Open the two local wallet addresses. In each: load demo inputs, authenticate signed state, import, authenticate wallet, prepare and review. Type the displayed confirmations yourself. Send once. Terminal commands: settle bob, settle carol, finish. All funds/keys disposable.',flush=True)
        for line in sys.stdin:
            if args.automated:
                command=json.loads(line);n.need(set(command)<= {'command','role','browser'},'closed fixture IPC')
            else:
                parts=line.strip().split();command={'command':parts[0] if parts else '',**({'role':parts[1]} if len(parts)==2 else {})}
            if command['command']=='settle':value=demo.settle(command['role'])
            elif command['command']=='delivery':value={'event':'delivery','role':command['role'],'output':demo.delivery_path(command['role'])}
            elif command['command']=='finish':
                print('ALPHA_EVENT '+json.dumps(demo.finish(command.get('browser'))),flush=True);return 0 if demo.report['status'].startswith('qualified') else 1
            else:raise ValueError('explicit fixture command required')
            print('ALPHA_EVENT '+json.dumps(value),flush=True)
    except KeyboardInterrupt:pass
    except Exception as exc:
        demo.report['failure_type']=type(exc).__name__;print('ALPHA_EVENT '+json.dumps({'event':'failed','error_type':type(exc).__name__}),flush=True)
        return 1
    finally:
        if not demo.closed:demo.finish()
    return 1

if __name__=='__main__':raise SystemExit(main())
