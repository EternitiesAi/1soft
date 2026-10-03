#!/usr/bin/env python3
"""Qualify fresh P4 state sync with a pinned real CometBFT on loopback only.

All original wires, keys, homes, databases, policies and stdout stay in a new
private POSIX directory. The separate public directory receives a deliberate
digest projection. Engine execution requires a clean, fully pinned checkout.
"""
from __future__ import annotations
import argparse
import base64
import hashlib
import io
import json
import os
from pathlib import Path
import socket
import sqlite3
import subprocess
import sys
import threading
import time
import uuid

ROOT=Path(__file__).resolve().parents[1]
sys.path[:0]=[str(ROOT/'src'),str(ROOT/'scripts'),str(ROOT/'tools/release'),
             str(ROOT/'tools/protocol4-client/src'),str(ROOT/'tools/validator-transition/src')]
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives import serialization
from abci_wire import read_frame,write_frame
from check_release import source_identity,require
from check_protocol4_state_sync import (PIN,ENGINE_SHA256,CHECK_IDS,CRASH_IDS,validate_core,artifact_manifest)
from commit_verifier import encode,load_json,header_hash,block_id
from native_core import public,address,digest
from protocol4_application import Protocol4Application
from protocol4_abci_wire import Request,Response
from p4_evidence import FORMAT as EVIDENCE_FORMAT,POLICY_FORMAT,verify_evidence
from registry_rules_core import GENESIS_FORMAT
from validator_sets_core import canonical_roster
from run_protocol4_engine import payment,app_query
from run_devnet import free_ports,patch_toml,rpc,wait_until
from run_state_sync import _sanitize_log
from serve_abci_state_sync_crash import read_event,write_event,directory
from serve_abci_p4_state_sync_test import birth,write_private

MAX_LOG=1024*1024

def output_paths(private,public):
    paths=[Path(os.path.abspath(p)) for p in (private,public)]
    for p in paths:
        require(not p.is_relative_to(ROOT) and not p.exists(),'new output outside checkout required')
        for parent in (p,*p.parents):
            require(not parent.is_symlink(),'aliased output refused')
    require(paths[0]!=paths[1] and not paths[0].is_relative_to(paths[1])
            and not paths[1].is_relative_to(paths[0]),'separate private/public outputs required')
    return tuple(paths)

def engine_preflight(engine,expected_sha256):
    binary=Path(engine)
    require(type(expected_sha256) is str and len(expected_sha256)==64
            and all(c in '0123456789abcdef' for c in expected_sha256),'invalid external engine pin')
    if not binary.is_file():return {'status':'unassessed','reason':'pinned engine absent'}
    require(not binary.is_symlink(),'aliased engine refused')
    sha=hashlib.sha256(binary.read_bytes()).hexdigest()
    if sha!=expected_sha256:return {'status':'failed','reason':'engine differs from external pin','engine_sha256':sha}
    version=subprocess.check_output([str(binary),'version'],text=True,timeout=10).strip().lstrip('v')
    require(version==PIN,'engine version differs from pin')
    return {'status':'ready','engine_sha256':sha,'engine_version':version}

def public_projection(value):
    source=value.get('source',{})
    return {'schema':'1soft-protocol4-state-sync-public-v1','status':value['status'],
            'profile':value['profile'],'run_id':value.get('run_id'),
            'source_commit':source.get('commit'),'source_tree':source.get('tree'),
            'source_id':source.get('source_id'),'engine_sha256':value.get('engine_sha256'),
            'qualified_check_ids':[c['id'] for c in value.get('checks',[]) if c.get('passed') is True]
                if value['status']=='passed' else [],
            'semantic_validation':value.get('semantic_validation') if value['status']=='passed' else None,
            'private_result_sha256':hashlib.sha256(encode(value)).hexdigest(),
            'failure_type':value.get('failure_type'),'log_digests':[
                {k:x[k] for k in ('name','bytes','sha256','truncated')} for x in value.get('logs',[])],
            'proof_origin':'target checkpoint plus independently verified source signed block history',
            'target_standalone_genesis_history_read':'unassessed',
            'independent_operators':False,'public_network_ready':False,'real_funds_ready':False}

class Capture:
    def __init__(self,stream,path):
        self.path=path;self.count=0;self.truncated=False;self.stream=stream
        self.failure=None;self.completed=False;self.closed=False;self.fsynced=False
        self.thread=threading.Thread(target=self.drain,daemon=True);self.thread.start()
    def drain(self):
        try:
            with self.path.open('xb') as out:
                read=self.stream.read1 if isinstance(self.stream,io.BufferedReader) else self.stream.read
                while True:
                    raw=read(8192)
                    if not raw:break
                    available=max(0,MAX_LOG-self.count)
                    kept=raw[:available]
                    require(out.write(kept)==len(kept),'partial stdout write')
                    self.count+=len(kept)
                    if len(raw)>available:self.truncated=True
                out.flush();os.fsync(out.fileno());self.fsynced=True
            self.closed=True;self.completed=True
        except BaseException as exc:
            self.failure=type(exc).__name__+': '+str(exc)
    def finish(self):
        self.thread.join(timeout=5)
        try:self.stream.close()
        except BaseException as exc:self.failure=type(exc).__name__+': '+str(exc)
        require(not self.thread.is_alive() and self.failure is None and self.completed
                and self.closed and self.fsynced,'log read/write/fsync/close incomplete')
        raw=self.path.read_bytes()
        require(len(raw)==self.count,'captured stdout byte count differs')
        return {'name':self.path.name,'bytes':len(raw),'sha256':hashlib.sha256(raw).hexdigest(),
                'truncated':self.truncated,'complete':True,'closed':True,'fsynced':True,'capture_error':None}

class Owned:
    def __init__(self,root):
        self.root=root;self.entries=[];self.logs=[];self.stop_seconds=8
        self.cleanup={'complete':False,'rescue_actions':[],'errors':[],'owned_survivors':[]}
    def start(self,name,argv):
        process=subprocess.Popen(argv,stdout=subprocess.PIPE,stderr=subprocess.STDOUT,start_new_session=True)
        role='engine' if name.startswith('engine') else (
            'crash-supervisor' if name=='app4' and 'final-apply-crash' in argv else 'app')
        item={'name':name,'process':process,'pid':process.pid,'birth':birth(process.pid),
              'argv':argv,'role':role,'spawned_at_ns':time.time_ns(),
              'stop_requested':False,'termination_signal':None,'rescue_used':False,
              'cleanup_error':None,'capture':Capture(process.stdout,self.root/(name+'.log'))}
        self.entries.append(item)
        write_private(self.root/('process-'+name+'-started.json'),encode({
            k:item[k] for k in ('name','pid','birth','role','argv','spawned_at_ns')}))
        return item
    def record(self,item):
        return {**{k:item[k] for k in ('name','pid','birth','role','argv','spawned_at_ns',
                   'stop_requested','termination_signal','rescue_used','cleanup_error')},
                'returncode':item['process'].returncode,'alive_after':item['process'].poll() is None}
    def stop(self,item):
        process=item['process']
        if process.poll() is None:
            require(birth(process.pid)==item['birth'],'owned process PID was reused')
            item['stop_requested']=True;item['termination_signal']=15
            process.terminate()
            try:process.wait(timeout=self.stop_seconds)
            except subprocess.TimeoutExpired:
                item['rescue_used']=True
                self.cleanup['rescue_actions'].append({'name':item['name'],'pid':item['pid'],
                    'birth':item['birth'],'signal':9,'reason':'TERM timeout'})
                process.kill();process.wait(timeout=5)
        outcome=self.record(item)
        path=self.root/('process-'+item['name']+'-exit.json')
        if not path.exists():write_private(path,encode(outcome))
        allowed=(0,-15) if item['role']=='engine' else (0,)
        require(item['stop_requested'] and not item['rescue_used'] and process.returncode in allowed,
                'unexpected exit or internal rescue: '+item['name'])
        return process.returncode
    def records(self):
        return [self.record(x) for x in self.entries]
    def finish(self):
        for item in reversed(self.entries):
            try:self.stop(item)
            except Exception as exc:
                item['cleanup_error']=type(exc).__name__+': '+str(exc)
                self.cleanup['errors'].append({'name':item['name'],'error':item['cleanup_error']})
        for item in self.entries:
            try:self.logs.append(item['capture'].finish())
            except Exception as exc:self.cleanup['errors'].append({
                'name':item['name'],'error':'log '+type(exc).__name__+': '+str(exc),
                'capture_failure':item['capture'].failure})
        self.cleanup['owned_survivors']=[{'name':x['name'],'pid':x['pid'],'birth':x['birth']}
            for x in self.entries if x['process'].poll() is None]
        self.cleanup['complete']=not (self.cleanup['errors'] or self.cleanup['rescue_actions']
                                      or self.cleanup['owned_survivors'])
        require(self.cleanup['complete'],'owned cleanup, outcomes or log drain failed')
        return self.records()

def local_query(sock,path):
    req=Request();req.query.path=path
    with socket.socket(socket.AF_UNIX,socket.SOCK_STREAM) as connection:
        connection.settimeout(5);connection.connect(str(sock))
        with connection.makefile('rwb',buffering=0) as stream:
            write_frame(stream,req);raw=read_frame(stream)
            require(raw is not None,'P4 ABCI query closed')
            return Response.FromString(raw).query

def database(path):
    with sqlite3.connect(Path(path).absolute().as_uri()+'?mode=ro',uri=True) as db:
        db.execute('BEGIN')
        row=db.execute('SELECT genesis,height,app_hash,state FROM committed WHERE id=1').fetchone()
        require(row is not None,'P4 checkpoint missing')
        state={'genesis':load_json(row[0].encode()),'height':row[1],'app_hash':row[2],
               **load_json(row[3].encode())}
        history=[{'height':h,'txs':load_json(t.encode())}
                 for h,t in db.execute('SELECT height,txs FROM history ORDER BY height')]
        first=db.execute('SELECT min(height) FROM blocks').fetchone()[0]
        marker=db.execute('SELECT height,app_hash FROM snapshot_marker WHERE id=1').fetchone()
    return state,history,first,None if marker is None else {'height':marker[0],'app_hash':marker[1]}

def checkpoint_evidence(state,history,port,genesis_bytes,policy):
    """Target checkpoint + SOURCE engine packets; never fabricate target blocks."""
    g=load_json(genesis_bytes)['app_state'];h=state['height']
    require(1<=h<=512 and len(history)==h,'bounded target checkpoint/history required')
    final=wait_until(lambda:rpc(port,'commit',{'height':str(h+1)})['signed_header'],20)
    headers=[];source_history=[]
    with Protocol4Application(':memory:',expected_genesis=g) as app:
        app.init_chain(g['chain_id'],g,g['validator_registry']['validators'])
        for height in range(1,h+1):
            signed=rpc(port,'commit',{'height':str(height)})['signed_header']
            incoming=rpc(port,'block',{'height':str(height)})
            block=incoming['block']
            require(header_hash(block['header'])==header_hash(signed['header']) and
                    block_id(incoming['block_id']).SerializeToString()==
                    block_id(signed['commit']['block_id']).SerializeToString(),'source block/commit differs')
            wires=[] if block['data']['txs'] is None else block['data']['txs']
            txs=[base64.b64decode(w,validate=True) for w in wires]
            after,result=app._execute(txs,height)
            headers.append({'signed_header':signed,'validators':after['registry']['active_validators'],
                            'next_validators':after['registry']['next_validators']})
            source_history.append({'height':height,'txs':wires})
            app.state,app.height,app.app_hash=after,height,result['app_hash']
        require(history==source_history,'target durable replay inputs differ from source signed block history')
        rebuilt={'genesis':g,'height':h,'app_hash':app.app_hash,**app.state}
        require(rebuilt==state,'source reconstructed checkpoint differs from actual target state')
        ahead,_=app.rules.transition(app.state['registry'],[],h+1)
        headers.append({'signed_header':final,'validators':ahead['active_validators'],
                        'next_validators':ahead['next_validators']})
    evidence={'schema':1,'format':EVIDENCE_FORMAT,'state':state,'history':source_history,'headers':headers}
    verify_evidence(evidence,genesis_bytes,policy,now_ns=time.time_ns())
    return evidence,rebuilt

def observe_node(binary,home,index,root,label):
    """Observe immutable identity; private key values are never parsed or printed."""
    meta=home.stat()
    node_id=subprocess.check_output([binary,'show-node-id','--home',str(home)],text=True,timeout=10).strip()
    pub=load_json(subprocess.check_output([binary,'show-validator','--home',str(home)],timeout=10))
    value={'index':index,'node_id':node_id,'validator_public_key':base64.b64decode(pub['value'],validate=True).hex(),
        'home_path':str(home.absolute()),'home_device':meta.st_dev,'home_inode':meta.st_ino,
        'node_key_sha256':hashlib.sha256((home/'config/node_key.json').read_bytes()).hexdigest(),
        'validator_key_sha256':hashlib.sha256((home/'config/priv_validator_key.json').read_bytes()).hexdigest()}
    write_private(root/('node-'+str(index)+'-'+label+'.json'),encode(value))
    return value

def earlier_checkpoint(original,height,genesis_bytes,policy):
    require(type(height) is int and 1<=height<original['state']['height'],'strictly older checkpoint required')
    g=load_json(genesis_bytes)['app_state']
    with Protocol4Application(':memory:',expected_genesis=g) as app:
        app.init_chain(g['chain_id'],g,g['validator_registry']['validators'])
        for row in original['history'][:height]:
            after,result=app._execute([base64.b64decode(x,validate=True) for x in row['txs']],row['height'])
            app.state,app.height,app.app_hash=after,row['height'],result['app_hash']
        state={'genesis':g,'height':height,'app_hash':app.app_hash,**app.state}
    evidence={'schema':1,'format':EVIDENCE_FORMAT,'state':state,
        'history':original['history'][:height],'headers':original['headers'][:height+1]}
    verify_evidence(evidence,genesis_bytes,policy,now_ns=time.time_ns())
    return evidence

def canonical_older_offer(evidence,genesis_bytes,policy,*,now_ns):
    """Direct ABCI rollback probe from authenticated replay, not an engine offer."""
    verify_evidence(evidence,genesis_bytes,policy,now_ns=now_ns)
    state=evidence['state'];g=state['genesis']
    with Protocol4Application(':memory:',expected_genesis=g) as app:
        app.init_chain(g['chain_id'],g,g['validator_registry']['validators'])
        for row in evidence['history']:
            after,result=app._execute([base64.b64decode(x,validate=True) for x in row['txs']],row['height'])
            app.state,app.height,app.app_hash=after,row['height'],result['app_hash']
            app.db.execute('INSERT INTO history(height,txs) VALUES(?,?)',(row['height'],encode(row['txs']).decode()))
        require({'genesis':g,'height':app.height,'app_hash':app.app_hash,**app.state}==state,
                'older snapshot replay differs')
        desc=app.state_sync.list()[0]
        chunks=[app.state_sync.load(desc['height'],2,i) for i in range(desc['chunks'])]
        request=Request();q=request.offer_snapshot
        q.snapshot.height=desc['height'];q.snapshot.format=2;q.snapshot.chunks=desc['chunks']
        q.snapshot.hash=desc['hash'];q.snapshot.metadata=desc['metadata']
        q.app_hash=bytes.fromhex(state['app_hash'])
    return request,chunks

def read_checkpoint_event(control,name):
    item=read_event(control,name)
    if item is None:return None
    raw=(control/item['record_file']).read_bytes()
    require(hashlib.sha256(raw).hexdigest()==item['record_sha256'],'install record bytes differ')
    return item,load_json(raw,max_bytes=16*1024*1024)

def transfer_trace(controls,install,crash,*,lost_only=False):
    selected=[];chunks={};offer=None;listed=False
    for control in controls:
        offered_height=None
        for reqfile in sorted(control.glob('request-*.bin')):
            raw=reqfile.read_bytes();request=Request.FromString(raw);method=request.WhichOneof('value')
            responsefile=control/reqfile.name.replace('request-','response-')
            answer_raw=responsefile.read_bytes() if responsefile.exists() else None
            answer=None if answer_raw is None else Response.FromString(answer_raw)
            wanted=False
            if method=='list_snapshots' and answer is not None:
                wanted=any(s.height==install['height'] and s.format==2 for s in answer.list_snapshots.snapshots)
                listed|=wanted
            elif method=='offer_snapshot':
                q=request.offer_snapshot
                if answer is not None and answer.offer_snapshot.result==1:offered_height=q.snapshot.height
                wanted=q.snapshot.height==install['height'] and q.snapshot.format==2
                if wanted and answer is not None and answer.offer_snapshot.result==1:
                    offer=q
            elif method=='load_snapshot_chunk':
                q=request.load_snapshot_chunk
                wanted=q.height==install['height'] and q.format==2
                if wanted and answer is not None:chunks[q.chunk]=bytes(answer.load_snapshot_chunk.chunk)
            elif method=='apply_snapshot_chunk':
                q=request.apply_snapshot_chunk
                wanted=control==controls[-1] and offered_height==install['height'] and (answer is None or answer.apply_snapshot_chunk.result==1)
            if wanted:selected.append({'request':base64.b64encode(raw).decode(),
                'response':None if answer_raw is None else base64.b64encode(answer_raw).decode()})
            if wanted and lost_only and method=='apply_snapshot_chunk' and answer is None:break
    require(listed and offer is not None,'actual snapshot listing/offer missing')
    return {'format':2,'height':install['height'],'offered_app_hash':offer.app_hash.hex(),
            'hash':offer.snapshot.hash.hex(),'metadata':base64.b64encode(offer.snapshot.metadata).decode(),
            'chunks':[base64.b64encode(chunks[i]).decode() for i in range(offer.snapshot.chunks)],
            'methods':sorted({'list_snapshots','offer_snapshot','load_snapshot_chunk','apply_snapshot_chunk'}),
            'trace':selected}

def state_sync_configuration(policy,ports):
    require(type(ports) is list and len(ports)==2 and all(type(x) is int and 1<=x<=65535 for x in ports),
            'two finite loopback RPC ports required')
    return {'statesync.enable':True,'statesync.rpc_servers':','.join(
            'http://127.0.0.1:'+str(x) for x in ports),
        'statesync.trust_height':policy['anchor_height'],'statesync.trust_hash':policy['anchor_hash'].upper(),
        'statesync.trust_period':'1h0m0s','statesync.discovery_time':'5s',
        'statesync.chunk_request_timeout':'5s','statesync.chunk_fetchers':2,'statesync.max_snapshot_chunks':64}

def run(engine,private_output,public_output,expected_sha256=ENGINE_SHA256,profile='basic'):
    require(os.name=='posix' and profile in ('basic','final-apply-crash'),'POSIX and known P4 profile required')
    private,public_out=output_paths(private_output,public_output);os.umask(0o077)
    source=source_identity(ROOT)
    preflight=engine_preflight(engine,expected_sha256)
    private.mkdir(parents=True,mode=0o700);directory(private);public_out.mkdir(parents=True,mode=0o700)
    run_id=uuid.uuid4().hex();binary=str(Path(engine).absolute())
    report={'schema':'1soft-protocol4-state-sync-v1','status':'unassessed','profile':profile,
        'run_id':run_id,'source':source,'source_dirty_before':False,'source_dirty_after':None,
        'public_network':False,'real_funds':False,'checks':[],'processes':[],'logs':[],
        'proof_origin':'target checkpoint plus source signed block history',
        'target_standalone_genesis_history_read':'unassessed',**preflight}
    def save():
        raw=encode(report);tmp=private/'result.next'
        tmp.write_bytes(raw);tmp.replace(private/'result.json')
        public_raw=encode(public_projection(report));tmp=public_out/'result.next'
        tmp.write_bytes(public_raw);tmp.replace(public_out/'result.json')
    if preflight['status']!='ready':save();return report
    report['status']='running';save();owned=Owned(private)
    print('P4 gate '+profile+' started with source '+source['commit']+'; original artifacts private.',flush=True)
    homes=private/'nodes';apps={};engines={};controls={};databases={};sockets={};initial_control=None
    try:
        with (private/'testnet.log').open('xb') as setup_log:
            subprocess.run([binary,'testnet','--v','4','--n','1','--o',str(homes),'--initial-height','1'],
                           check=True,stdout=setup_log,stderr=subprocess.STDOUT,timeout=40)
        for path in homes.rglob('*'):path.chmod(0o700 if path.is_dir() else 0o600)
        chain='one-p4-sync-'+os.urandom(8).hex()
        rootgen=load_json((homes/'node0/config/genesis.json').read_bytes())
        initial=rootgen['validators'];require(len(initial)==4,'exactly four source validators required')
        for row in initial:row['power']='10'
        roster=canonical_roster([{'public_key':base64.b64decode(row['pub_key']['value']).hex(),'power':10}
                                 for row in initial])
        admins=[Ed25519PrivateKey.generate() for _ in range(4)]
        payers=[Ed25519PrivateKey.generate() for _ in range(2)]
        registry={'schema':1,'format':GENESIS_FORMAT,'mode':'development-only','chain_id':chain,
            'validators':roster,'administrators':{'format':'threshold-ed25519-v1',
            'public_keys':sorted(public(k) for k in admins),'threshold':3},'minimum_delay_blocks':2,
            'cooldown_blocks':1,'minimum_validators':4,'maximum_power_bps':3333}
        genesis={'chain_id':chain,'asset':'DEV','fee':1,'protocol_version':4,
            'allocations':[{'public_key':public(payers[0]),'units':1000000},
                           {'public_key':public(payers[1]),'units':0}], 'validator_registry':registry}
        gbytes=encode(genesis);gsha=hashlib.sha256(gbytes).hexdigest()
        gfile=private/'protocol4-genesis.json';write_private(gfile,gbytes)
        for i,key in enumerate([*payers,*admins]):
            write_private(private/('fixture-private-key-'+str(i)+'.bin'),key.private_bytes(
                serialization.Encoding.Raw,serialization.PrivateFormat.Raw,serialization.NoEncryption()))
        rootgen.update(chain_id=chain,initial_height='1',app_state=genesis,validators=initial)
        rootgen['consensus_params']['block'].update(max_bytes='1048576',max_gas='-1')
        engine_genesis=encode(rootgen);write_private(private/'engine-genesis.json',engine_genesis)
        ports=free_ports(10);p2p,http=ports[:5],ports[5:]
        report['nodes']=[observe_node(binary,homes/('node'+str(i)),i,private,'initial') for i in range(5)]
        ids=[n['node_id'] for n in report['nodes']]
        for i in range(5):
            home=homes/('node'+str(i));(home/'config/genesis.json').write_bytes(engine_genesis)
            appdir=private/('app'+str(i));appdir.mkdir(mode=0o700)
            sockets[i]=appdir/'a.sock';databases[i]=appdir/'state.sqlite'
            controls[i]=private/('control'+str(i));controls[i].mkdir(mode=0o700)
            config=home/'config/config.toml'
            config.write_text(patch_toml(config.read_text(),{
                'proxy_app':'unix://'+str(sockets[i]),'abci':'socket',
                'rpc.laddr':'tcp://127.0.0.1:'+str(http[i]),'rpc.unsafe':False,'rpc.grpc_laddr':'',
                'p2p.laddr':'tcp://127.0.0.1:'+str(p2p[i]),'p2p.external_address':'','p2p.seeds':'',
                'p2p.persistent_peers':','.join(ids[j]+'@127.0.0.1:'+str(p2p[j]) for j in range(5) if j!=i),
                'p2p.addr_book_strict':False,'p2p.allow_duplicate_ip':True,'p2p.pex':False,
                'consensus.timeout_commit':'1s','mempool.max_tx_bytes':65536,
                'instrumentation.prometheus':False}))
        def start_app(i,control=None,mode='observe',suffix=''):
            if control is not None:controls[i]=control
            apps[i]=owned.start('app'+str(i)+suffix,[sys.executable,
                str(ROOT/'scripts/serve_abci_p4_state_sync_test.py'),'--genesis',str(gfile),
                '--genesis-sha256',gsha,'--database',str(databases[i]),'--socket',str(sockets[i]),
                '--control-dir',str(controls[i]),'--run-id',run_id,'--mode',mode,'--wait-seconds','150'])
            phase='pause' if mode=='final-apply-crash' else 'normal'
            return wait_until(lambda:read_event(controls[i],phase+'-ready.json'),15)
        def start_engine(i,suffix=''):
            engines[i]=owned.start('engine'+str(i)+suffix,[binary,'start','--home',str(homes/('node'+str(i)))])
        def height(i):
            require(engines[i]['process'].poll() is None,'owned engine stopped unexpectedly')
            return int(rpc(http[i],'status')['sync_info']['latest_block_height'])
        for i in range(4):start_app(i)
        for i in range(4):start_engine(i)
        wait_until(lambda:all(height(i)>=3 for i in range(4)),70)
        pre=payment(genesis,payers[0],address(public(payers[1])),nonce=0,units=7,valid_until=512)
        def submit(wire):
            admission=rpc(http[0],'broadcast_tx_sync',{'tx':base64.b64encode(wire).decode()})
            require(int(admission['code'])==0,'original signed payment admission failed')
            return wait_until(lambda:rpc(http[0],'tx',{'hash':base64.b64encode(hashlib.sha256(wire).digest()).decode()}),30)
        pre_receipt=submit(pre);require(int(pre_receipt['tx_result']['code'])==0,'pre-snapshot payment failed')
        pre_state,pre_history,_,_=database(databases[0])
        trust_height=pre_state['height']-1
        trust_header=rpc(http[0],'commit',{'height':str(trust_height)})['signed_header']['header']
        policy={'schema':1,'format':POLICY_FORMAT,
            'genesis_sha256':hashlib.sha256(engine_genesis).hexdigest(),
            'anchor_height':trust_height,'anchor_hash':header_hash(trust_header).hex(),
            'anchor_time':trust_header['time'],'trust_period_seconds':3600,
            'max_clock_drift_seconds':5,'expected_block_version':11}
        pre_target,_=checkpoint_evidence(pre_state,pre_history,http[0],engine_genesis,policy)
        checked_at=time.time_ns()
        verify_evidence(pre_target,engine_genesis,policy,now_ns=checked_at)
        write_private(private/'pre-target-evidence.json',encode(pre_target))
        pinned_at=time.time_ns();write_private(private/'read-policy.json',encode(policy))
        inventory=[p.relative_to(homes/'node4').as_posix() for p in (homes/'node4').rglob('*') if p.is_file()]
        require(not databases[4].exists() and not any('blockstore' in p or 'state.db' in p for p in inventory),
                'target already started or has engine state')
        target_config=homes/'node4/config/config.toml'
        target_config.write_text(patch_toml(target_config.read_text(),state_sync_configuration(policy,http[:2])))
        report['trust_pin']={'policy':policy,'engine_genesis_sha256':hashlib.sha256(engine_genesis).hexdigest(),
            'native_genesis_sha256':gsha,'pinned_at_ns':pinned_at,
            'pre_target':{'evidence':pre_target,'checked_at_ns':checked_at},
            'target_never_started':True,'target_initial_inventory':inventory,
            'source_pids':[engines[i]['pid'] for i in range(4)],
            'sources':[{'index':i,'engine_pid':engines[i]['pid'],'engine_birth':engines[i]['birth'],
                'app_pid':apps[i]['pid'],'app_birth':apps[i]['birth'],'observed_height':height(i)}
                for i in range(4)]}
        write_private(private/'trust-pin.json',encode(report['trust_pin']))
        print('Before target launch: engine genesis '+report['trust_pin']['engine_genesis_sha256']+
              '; native genesis '+gsha+'; policy '+hashlib.sha256(encode(policy)).hexdigest()+
              '; trust height '+str(trust_height)+' hash '+policy['anchor_hash'],flush=True)
        start_app(4,mode='final-apply-crash' if profile=='final-apply-crash' else 'observe')
        report['trust_pin']['target_started_at_ns']=apps[4]['spawned_at_ns']
        initial_control=controls[4];start_engine(4)
        installed_item,install=wait_until(lambda:read_checkpoint_event(initial_control,'installed.json'),90)
        report['install']=install
        initial_install=install
        if profile=='final-apply-crash':
            killed=wait_until(lambda:read_event(initial_control,'killed.json'),15)
            owned.stop(engines[4]);write_event(initial_control,'resume.json',{'schema':1,'run_id':run_id,'resume':True})
            wait_until(lambda:read_event(initial_control,'recovery-ready.json'),15)
            _,restart_checkpoint=read_checkpoint_event(initial_control,'restart-audited.json')
            initial_state={'genesis':genesis,'height':initial_install['height'],
                           'app_hash':initial_install['app_hash'],**initial_install['state']}
            initial_evidence,_=checkpoint_evidence(initial_state,initial_install['history'],http[0],engine_genesis,policy)
            older=earlier_checkpoint(initial_evidence,initial_install['height']-1,engine_genesis,policy)
            oldreq,oldchunks=canonical_older_offer(older,engine_genesis,policy,now_ns=time.time_ns())
            write_private(private/'older-checkpoint-evidence.json',encode(older))
            write_private(private/'rollback-offer-request.bin',oldreq.SerializeToString(deterministic=True))
            for index,raw_chunk in enumerate(oldchunks):
                write_private(private/('rollback-chunk-'+str(index)+'.bin'),raw_chunk)
            with socket.socket(socket.AF_UNIX,socket.SOCK_STREAM) as c:
                c.settimeout(5);c.connect(str(sockets[4]))
                with c.makefile('rwb',buffering=0) as stream:
                    write_frame(stream,oldreq);answer_raw=read_frame(stream)
                    require(answer_raw is not None,'rollback offer reply missing')
                    answer=Response.FromString(answer_raw)
            write_private(private/'rollback-offer-response.bin',answer_raw)
            rollback=answer.offer_snapshot.result;require(rollback==3,'coherent checkpoint rollback offer not refused')
            rollback_probe={'kind':'manual-direct-ABCI-coherent-older-checkpoint','evidence':older,
                'request':base64.b64encode(oldreq.SerializeToString(deterministic=True)).decode(),
                'response':base64.b64encode(answer_raw).decode(),
                'chunks':[base64.b64encode(x).decode() for x in oldchunks]}
            from serve_abci_p4_state_sync_test import checkpoint as durable_checkpoint
            rollback_after=durable_checkpoint(databases[4])
            start_engine(4,'-recovery')
            recovered_item,recovered=wait_until(lambda:read_checkpoint_event(initial_control,'recovered.json'),90)
            require(recovered['height']>=initial_install['height'],'recovery rolled checkpoint backward')
            report['crash']={'killed':{**killed,'install':initial_install},'initial_install':initial_install,
                'initial_evidence':initial_evidence,'recovered':recovered,
                'restart_checkpoint':restart_checkpoint,'rollback_after':rollback_after,
                'rollback_offer_result':rollback,'rollback_probe':rollback_probe,'recovery_kind':'same' if
                    recovered['height']==initial_install['height'] else 'newer',
                'ready':read_event(initial_control,'pause-ready.json'),
                'identity_before':report['nodes'][4],
                'identity_after':observe_node(binary,homes/'node4',4,private,'crash-restarted')}
            install=recovered;report['install']=install
        snapshot_state={'genesis':genesis,'height':install['height'],'app_hash':install['app_hash'],**install['state']}
        snapshot_evidence,_=checkpoint_evidence(snapshot_state,install['history'],http[0],engine_genesis,policy)
        report['snapshot_evidence']=snapshot_evidence
        wait_until(lambda:height(4)>install['height'],60)
        report['unavailable_responses']=[]
        for h in range(1,install['height']+1):
            absent=local_query(sockets[4],'/block/'+str(h))
            report['unavailable_responses'].append({'height':h,'code':absent.code,'log':absent.log})
            require(absent.code==1 and absent.log=='protocol-4 response unavailable',
                    'target fabricated historical response or query failed for another reason')
        report['snapshot_response_code']=report['unavailable_responses'][-1]['code']
        post=payment(genesis,payers[0],address(public(payers[1])),nonce=1,units=5,valid_until=512)
        post_receipt=submit(post);post_height=int(post_receipt['height'])
        require(int(post_receipt['tx_result']['code'])==0 and post_height>install['height'],'post-snapshot payment failed')
        wait_until(lambda:height(4)>=post_height+1,60)
        owned.stop(engines[4])
        before,old_history,_,_=database(databases[4]);old_pid=apps[4]['pid'];old_birth=apps[4]['birth']
        restart_identity_before=observe_node(binary,homes/'node4',4,private,'ordinary-before')
        db_before=databases[4].stat()
        restart_evidence,_=checkpoint_evidence(before,old_history,http[0],engine_genesis,policy)
        owned.stop(apps[4])
        restart_control=private/'control4-restart';restart_control.mkdir(mode=0o700)
        start_app(4,control=restart_control,suffix='-restart')
        after=load_json(local_query(sockets[4],'/state').value)
        restart_identity_after=observe_node(binary,homes/'node4',4,private,'ordinary-after')
        db_after=databases[4].stat()
        require(before==after,'same DB restart changed current composite state')
        report['target_restart']={'database_before':str(databases[4]),'database_after':str(databases[4]),
            'home_before':str(homes/'node4'),'home_after':str(homes/'node4'),
            'before':before,'after':after,'old_pid':old_pid,'new_pid':apps[4]['pid'],
            'old_birth':old_birth,'new_birth':apps[4]['birth'],
            'identity_before':restart_identity_before,'identity_after':restart_identity_after,
            'database_device_before':db_before.st_dev,'database_device_after':db_after.st_dev,
            'database_inode_before':db_before.st_ino,'database_inode_after':db_after.st_ino,
            'evidence':restart_evidence}
        start_engine(4,'-restart')
        wait_until(lambda:height(4)>=before['height']+2,60)
        owned.stop(engines[4])
        target_state,target_history,first,marker=database(databases[4])
        actual=load_json(local_query(sockets[4],'/state').value)
        require(actual==target_state,'actual ABCI state differs from durable current checkpoint')
        final_evidence,source_at_target=checkpoint_evidence(target_state,target_history,http[0],engine_genesis,policy)
        report.update(final_evidence=final_evidence,target_final_state=actual,
            source_final_state=source_at_target,target_final_history=target_history,
            source_final_history=final_evidence['history'],first_target_block=first,final_marker=marker,
            evidence_origin={'state':'target-ABCI-query','headers':'source-engine-RPC',
                             'history':'source-blocks-with-target-durable-equality'},
            payments={'pre':base64.b64encode(pre).decode(),'post':base64.b64encode(post).decode()},
            snapshot_transfer=transfer_trace([controls[i] for i in range(4)]+[initial_control],install,
                                            profile=='final-apply-crash'))
        if profile=='final-apply-crash':
            report['crash']['initial_transfer']=transfer_trace(
                [controls[i] for i in range(4)]+[initial_control],initial_install,True,lost_only=True)
        report['status']='completed-awaiting-external-validation';save()
    except Exception as exc:
        report.update(status='failed',failure_type=type(exc).__name__,reason=str(exc))
    finally:
        try:
            try:owned.finish()
            finally:
                report['processes']=owned.records();report['logs']=owned.logs
                report['service_cleanup']=owned.cleanup
            # Supervisor children are also owned, and their observed birth/exit is retained.
            for control in dict.fromkeys([*controls.values(),initial_control] if initial_control is not None else controls.values()):
                for name in ('pause-ready.json','recovery-ready.json'):
                    ready=read_event(control,name)
                    if ready is None:continue
                    alive=False
                    try:alive=birth(ready['pid'])==ready['birth']
                    except FileNotFoundError:pass
                    exit_item=read_event(control,'killed.json' if name=='pause-ready.json' else 'recovery-exit.json')
                    require(exit_item is not None,'supervised child actual exit receipt missing')
                    report['processes'].append({'name':name,'pid':ready['pid'],'birth':ready['birth'],
                        'role':'final-apply-pause-child' if name=='pause-ready.json' else 'recovery-child',
                        'alive_after':alive,**{k:exit_item[k] for k in ('returncode','stop_requested',
                            'termination_signal','rescue_used','cleanup_error')}})
            current=source_identity(ROOT);require(current==source,'tracked source changed during scenario')
            require(hashlib.sha256(Path(binary).read_bytes()).hexdigest()==expected_sha256,
                    'engine bytes changed during scenario')
            report['engine_sync']={'log_names':[x['name'] for x in report['logs'] if x['name'].startswith('engine4')],
                'original_log':''.join((private/x['name']).read_bytes().decode('utf-8',errors='replace')
                                      for x in report['logs'] if x['name'].startswith('engine4'))}
            report['artifacts']=artifact_manifest(private)
            report['source_dirty_after']=False
            if report['status']=='completed-awaiting-external-validation':
                report['checks']=[{'id':x,'passed':True} for x in CHECK_IDS+
                                  (CRASH_IDS if profile=='final-apply-crash' else ())]
                report['semantic_validation']=validate_core(report,profile,source,expected_sha256,
                    engine_genesis,policy,now_ns=time.time_ns())
        except Exception as exc:
            report.update(status='failed',failure_type=type(exc).__name__,reason=str(exc))
        for item in report.get('logs',[]):
            public_raw=encode({'schema':'1soft-private-log-public-digest-v1',
                **{k:item[k] for k in ('name','bytes','sha256','truncated')},
                'content':'original bounded stdout/stderr retained privately'})
            write_private(public_out/item['name'],public_raw)
        save()
    print('P4 gate '+profile+' finished: '+report['status']+'.',flush=True)
    return report

def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--engine',type=Path,required=True);p.add_argument('--engine-sha256',required=True)
    p.add_argument('--private-output',type=Path,required=True);p.add_argument('--public-output',type=Path,required=True)
    p.add_argument('--profile',choices=('basic','final-apply-crash'),default='basic')
    a=p.parse_args()
    result=run(a.engine,a.private_output,a.public_output,a.engine_sha256,a.profile)
    return 0 if result['status']=='completed-awaiting-external-validation' else 2
if __name__=='__main__':raise SystemExit(main())
