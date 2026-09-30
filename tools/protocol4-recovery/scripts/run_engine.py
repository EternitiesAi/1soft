#!/usr/bin/env python3
"""Opt-in genuine local CometBFT P4 recovery test. No engine download or deployment.

Six nodes for bootstrap, five for lost-Commit response. Every node/key is a fresh
local fixture; output never includes node homes or private keys. Existing P1-P3
and P4 qualification remain required at any later release revision.
"""
from __future__ import annotations
import argparse
import base64
from datetime import datetime,timezone
import hashlib
import json
import os
import re
from pathlib import Path
import signal
import stat
import subprocess
import sys
import tempfile
import threading
import time
import uuid

ROOT=Path(__file__).resolve().parents[3]
ADDON=Path(__file__).resolve().parents[1]
sys.path[:0]=[str(ROOT/'src'),str(ROOT/'scripts'),str(ROOT/'tools/release'),
              str(ROOT/'tools/validator-transition/src'),str(ADDON/'src')]
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from check_release import source_identity
from commit_verifier import encode,header_hash
from native_core import NativeLedger,public,address,canonical,sign,digest
from registry_rules_core import RegistryRules,GENESIS_FORMAT
from validator_sets_core import canonical_roster
from run_devnet import free_ports,patch_toml,rpc
from run_state_sync import _sanitize_log
from recovery_checks import (need,hex64,read_json,write_new,checkpoint,verify_boundary,
    remove_dead_socket,verify_payment_rows,verify_replayed_anchor,sha)
from acceptance import PROFILES,validate

PIN='0.38.25'
LOG_CAP=2*1024*1024

class Child:
    def __init__(self,argv,log,runtime=None):
        self.runtime=runtime
        self.log=log;self.buffer=bytearray();self.bytes=0;self.error=None;self.record=None
        self.p=subprocess.Popen(argv,stdout=subprocess.PIPE,stderr=subprocess.STDOUT,start_new_session=True)
        def read():
            try:
                while data:=self.p.stdout.read(65536):
                    left=max(0,LOG_CAP-len(self.buffer));self.buffer.extend(data[:left]);self.bytes+=len(data)
            except OSError:self.error='log capture failed'
            finally:self.p.stdout.close()
        self.thread=threading.Thread(target=read,daemon=True);self.thread.start()
    def stop(self):
        if self.record is not None:return self.record
        # start_new_session gives this fixture its own group, including children
        # that retain stdout after the direct child exits. Never signal a name.
        def signal_group(sig):
            try:os.killpg(self.p.pid,sig)
            except ProcessLookupError:pass
        signal_group(signal.SIGTERM)
        try:self.p.wait(8)
        except subprocess.TimeoutExpired:signal_group(signal.SIGKILL);self.p.wait(5)
        self.thread.join(2)
        signal_group(signal.SIGKILL)  # Also stop descendants that closed stdout.
        if self.thread.is_alive():self.thread.join(5)
        need(not self.thread.is_alive() and self.error is None,'incomplete process log')
        raw=sanitize(bytes(self.buffer),self.runtime);self.log.write_bytes(raw);self.log.chmod(0o600)
        self.record={'path':self.log.name,'sha256':sha(raw),'bytes':len(raw),'observed_bytes':self.bytes,
                     'truncated':self.bytes>LOG_CAP,'pid':self.p.pid,'returncode':self.p.returncode,
                     'owned_process_group_stopped':True}
        return self.record

def sanitize(raw,runtime=None):
    raw=_sanitize_log(raw)
    return raw.replace(os.fsencode(runtime),b'[private-runtime]') if runtime is not None else raw

def rpc_height(value):
    need(type(value) is str and re.fullmatch(r'0|[1-9][0-9]{0,2}',value) is not None,
         'invalid bounded RPC height')
    return int(value)

def live_height(engine,port):
    need(engine.p.poll() is None,'owned engine process exited')
    return rpc_height(rpc(port,'status')['sync_info']['latest_block_height'])

def wait(fn,seconds=40):
    deadline=time.monotonic()+seconds;last=None
    while time.monotonic()<deadline:
        try:
            result=fn()
            if result:return result
        except (OSError,KeyError,RuntimeError) as exc:last=type(exc).__name__
        time.sleep(.12)
    raise TimeoutError('bounded local acceptance wait expired'+(' ('+last+')' if last else ''))

def query(port,path):
    value=rpc(port,'abci_query',{'path':path,'prove':False})['response']
    need(type(value['code']) is int and value['code']==0,'P4 query rejected')
    return json.loads(base64.b64decode(value['value'],validate=True))

def make_payment(g,key,recipient,nonce,units):
    ledger=NativeLedger(':memory:',g)
    try:return canonical(sign(key,ledger.body(address(public(key)),nonce,
                {'type':'transfer','to':recipient,'units':units},valid_until=450)))
    finally:ledger.close()

def submit(port,raw):
    result=rpc(port,'broadcast_tx_commit',{'tx':base64.b64encode(raw).decode()})
    need(all(type(result[k]['code']) is int and result[k]['code']==0 for k in ('check_tx','tx_result')),
         'test transaction not committed')
    height=rpc_height(result['height']);need(height>0,'transaction has no committed height')
    return height

def run(engine,engine_hash,output,profile):
    hex64(engine_hash);need(profile in PROFILES,'unknown acceptance profile')
    need(os.name=='posix','POSIX local acceptance requires Unix sockets and SIGKILL')
    output=Path(os.path.abspath(output));need(not output.is_relative_to(ROOT),'evidence must be outside checkout')
    for parent in (output.parent,*output.parent.parents):need(not parent.is_symlink(),'symlink output ancestor')
    source=source_identity(ROOT)
    output.mkdir(mode=0o700,exist_ok=False)
    run_id=uuid.uuid4().hex
    report={'schema':1,'profile':profile,'run_id':run_id,'source':{'commit':source['commit'],
        'tree':source['tree'],'source_id':source['source_id']},'status':'unassessed','engine_required':PIN,
        'checks':[],'public_network':False,'real_funds':False,'independent_operators':False,
        'release_status':'blocked','consensus_executed':False}
    write_new(output/'source.json',source);write_new(output/'started.json',report)
    binary=Path(engine).resolve();children=[];apps={};engines={};temp_handle=None
    if not binary.is_file():
        report['reason']='Pinned CometBFT executable unavailable; zero engine processes started.'
        write_new(output/'result.json',report);return report
    def checked(name,ok):
        report['checks'].append({'name':name,'passed':bool(ok)})
        need(ok,'acceptance check failed: '+name)
    def child(args,label):
        c=Child(args,output/(label+'.log'),runtime);children.append(c);return c
    def stop(c):
        record=c.stop();need(not record['truncated'],'captured process output truncated')
    try:
        actual=sha(binary.read_bytes());need(actual==engine_hash,'binary digest differs from explicit pin')
        version=subprocess.check_output([str(binary),'version'],text=True,timeout=10).strip().lstrip('v')
        need(version==PIN,'wrong CometBFT version');report.update(engine_sha256=actual,engine_version=version)
        temp_handle=tempfile.TemporaryDirectory(prefix='p4-engine-recovery-')
        name=temp_handle.name
        runtime=Path(name);homes=runtime/'nodes';count=6 if profile==PROFILES[0] else 5
        setup=subprocess.run([str(binary),'testnet','--v','4','--n',str(count-4),'--o',str(homes),
                              '--initial-height','1'],capture_output=True,timeout=30)
        setup_log=sanitize(setup.stdout+setup.stderr,runtime)
        (output/'engine-setup.log').write_bytes(setup_log[:LOG_CAP])
        (output/'engine-setup.log').chmod(0o600)
        report['setup_log']={'path':'engine-setup.log','sha256':sha(setup_log[:LOG_CAP]),'bytes':min(len(setup_log),LOG_CAP),'truncated':len(setup_log)>LOG_CAP}
        need(len(setup_log)<=LOG_CAP,'engine setup log truncated')
        need(setup.returncode==0,'disposable engine setup failed')
        for path in homes.rglob('*'):path.chmod(0o700 if path.is_dir() else 0o600)
        public_gen=json.loads((homes/'node0/config/genesis.json').read_bytes())
        original=public_gen['validators'];need(len(original)==4,'wrong genesis validator count')
        for row in original:row['power']='10'
        public_keys=[base64.b64decode(row['pub_key']['value'],validate=True).hex() for row in original]
        # Read only the PUBLIC field from our freshly generated fifth fixture key file.
        newcomer=json.loads((homes/'node4/config/priv_validator_key.json').read_bytes())['pub_key']
        old=canonical_roster([{'public_key':key,'power':10} for key in public_keys])
        after=canonical_roster([{'public_key':key,'power':p} for key,p in zip(
            public_keys[1:]+[base64.b64decode(newcomer['value'],validate=True).hex()],(12,10,10,9))])
        chain='1soft-p4-recovery-'+run_id[:12]
        admins=[Ed25519PrivateKey.generate() for _ in range(4)];payers=[Ed25519PrivateKey.generate() for _ in range(2)]
        registry={'schema':1,'format':GENESIS_FORMAT,'mode':'development-only','chain_id':chain,'validators':old,
            'administrators':{'format':'threshold-ed25519-v1','public_keys':sorted(public(k) for k in admins),'threshold':3},
            'minimum_delay_blocks':2,'cooldown_blocks':1,'minimum_validators':4,'maximum_power_bps':3333}
        g={'protocol_version':4,'chain_id':chain,'asset':'DEV','fee':1,'validator_registry':registry,
           'allocations':[{'public_key':public(k),'units':100000} for k in payers]}
        public_gen.update(chain_id=chain,initial_height='1',validators=original,app_state=g)
        public_gen['consensus_params']['block'].update(max_bytes='1048576',max_gas='-1')
        write_new(output/'engine-genesis.json',public_gen);gfile=runtime/'genesis.json';gfile.write_bytes(encode(g))
        report['genesis_sha256']=digest(g)
        ports=free_ports(count*2);p2p,http=ports[:count],ports[count:]
        ids=[subprocess.check_output([str(binary),'show-node-id','--home',str(homes/f'node{i}')],text=True,timeout=8).strip() for i in range(count)]
        for i in range(count):
            home=homes/f'node{i}';(home/'config/genesis.json').write_bytes(encode(public_gen))
            appdir=runtime/f'app{i}';appdir.mkdir(mode=0o700)
            config=home/'config/config.toml'
            config.write_text(patch_toml(config.read_text(),{'proxy_app':f'unix://{appdir}/app.sock','abci':'socket',
                'rpc.laddr':f'tcp://127.0.0.1:{http[i]}','rpc.unsafe':False,
                'p2p.laddr':f'tcp://127.0.0.1:{p2p[i]}','p2p.persistent_peers':','.join(
                   f'{ids[j]}@127.0.0.1:{p2p[j]}' for j in range(5) if j!=i),
                'p2p.addr_book_strict':False,'p2p.allow_duplicate_ip':True,'p2p.pex':False,
                'consensus.timeout_commit':'500ms','mempool.max_tx_bytes':65536}))
        def db(i):return runtime/f'app{i}/state.sqlite'
        def socket(i):return runtime/f'app{i}/app.sock'
        def start_app(i,crash=False,snapshot=False,phase='initial'):
            argv=[sys.executable,str(ADDON/'scripts/serve_probe.py'),'--db',str(db(i)),'--socket',str(socket(i)),
                  '--genesis',str(gfile),'--boundary',str(runtime/f'app{i}/boundary-{phase}.json'),'--run-id',run_id]
            if crash:argv+=['--kill-emission']
            if snapshot:argv+=['--snapshot-notice',str(runtime/f'app{i}/snapshot.json'),
                               '--snapshot-release',str(runtime/f'app{i}/release.json')]
            apps[i]=child(argv,f'app{i}-{phase}')
            wait(lambda:socket(i).exists() and apps[i].p.poll() is None,10)
        def start_engine(i,phase='initial'):
            engines[i]=child([str(binary),'start','--home',str(homes/f'node{i}')],f'engine{i}-{phase}')
        def height(i):return live_height(engines[i],http[i])
        for i in range(5):
            start_app(i,crash=profile==PROFILES[1] and i==2);start_engine(i)
        report['consensus_executed']=True
        wait(lambda:all(height(i)>=2 for i in range(5)),40)
        initial=rpc(http[1],'commit',{'height':'1'})['signed_header']
        report['initial_header_hash']=header_hash(initial['header']).hex()
        wires=[make_payment(g,payers[0],address(public(payers[1])),0,37)]
        submit(http[1],wires[0])
        rules=RegistryRules(registry,bound_genesis_sha256=digest(g))
        reg=query(http[1],'/registry-state');emission=reg['height']+12
        need(emission<400,'test too close to bounded history end')
        body=rules.body(reg,{'kind':'schedule','emitted_height':emission,'target_validators':after},
                        valid_from=reg['height']+1,valid_until=emission-2)
        action=encode({'body':body,'approvals':sorted([{'public_key':public(k),
            'signature':k.sign(rules.signing_bytes(body)).hex()} for k in admins[:3]],key=lambda v:v['public_key'])})
        submit(http[1],action)
        evidence={'genesis':g,'emitted_height':emission}
        if profile==PROFILES[1]:
            dead=apps[2].p
            wait(lambda:dead.poll() is not None,40)
            observation=read_json(runtime/'app2/boundary-initial.json');saved=checkpoint(db(2),g)
            verify_boundary(observation,saved,run_id=run_id,pid=dead.pid,height=emission,returncode=dead.returncode)
            checked('durable-commit-before-lost-reply',True)
            stop(engines[2]);before_inode=db(2).stat().st_ino
            remove_dead_socket(socket(2),observation,dead)
            start_app(2,phase='restarted');start_engine(2,phase='restarted')
            wait(lambda:height(2)>=emission+3,45)
            record=checkpoint(db(2),g)
            r=query(http[2],f'/block/{emission}')
            preserved=sha(__import__('protocol4_abci_wire').encode_finalization(r))
            liveid=subprocess.check_output([str(binary),'show-node-id','--home',str(homes/'node2')],text=True,timeout=8).strip()
            crash={'observation':observation,'checkpoint':saved,'pid':dead.pid,'returncode':dead.returncode,
                   'restarted_pid':apps[2].p.pid,'same_database_inode':db(2).stat().st_ino==before_inode,
                   'same_engine_identity':liveid==ids[2],'saved_response_after_recovery':preserved}
            checked('same-store-restart',crash['same_database_inode'] and crash['same_engine_identity'] and
                    crash['restarted_pid']!=crash['pid'])
            evidence['crash']=crash
        wait(lambda:query(http[1],'/registry-state')['epoch']==1 and height(4)>=emission+3,40)
        stop(engines[0]);stop(apps[0])  # Removed validator no longer needed.
        wires.append(make_payment(g,payers[0],address(public(payers[1])),1,53))
        post_height=submit(http[1],wires[1]);checked('post-transition-payment',post_height>=emission+2)
        target=5 if profile==PROFILES[0] else 2
        if profile==PROFILES[0]:
            trust_height=max(1,height(1)-1);trust_header=rpc(http[1],'commit',{'height':str(trust_height)})['signed_header']
            config=homes/'node5/config/config.toml'
            config.write_text(patch_toml(config.read_text(),{'statesync.enable':True,
                'statesync.rpc_servers':f'http://127.0.0.1:{http[1]},http://127.0.0.1:{http[3]}',
                'statesync.trust_height':trust_height,'statesync.trust_hash':header_hash(trust_header['header']).hex().upper(),
                'statesync.trust_period':'1h0m0s','statesync.discovery_time':'5s',
                'statesync.chunk_request_timeout':'5s','statesync.chunk_fetchers':2,'statesync.max_snapshot_chunks':64}))
            need(not db(5).exists(),'observer database must start absent')
            start_app(5,snapshot=True);start_engine(5)
            notice=runtime/'app5/snapshot.json'
            def installed():
                need(engines[5].p.poll() is None and apps[5].p.poll() is None,
                     'observer process exited before snapshot installation')
                return notice.exists()
            wait(installed,75)
            boot=checkpoint(db(5),g);obs=read_json(notice)
            checked('untouched-format2-bootstrap',boot['local_block_count']==0 and boot['latest_block'] is None and
                    boot['snapshot_marker']=={'height':boot['height'],'app_hash':boot['app_hash']} and boot['height']>=emission+2)
            evidence.update(bootstrap_checkpoint=boot,bootstrap_observation=obs)
            write_new(output/'bootstrap-observation.json',obs);write_new(output/'bootstrap-checkpoint.json',boot)
            write_new(runtime/'app5/release.json',{'run_id':run_id})
            wait(lambda:height(5)>=boot['height'],45)
            missing=[];unavailable=[]
            for h in range(1,boot['height']+1):
                response=rpc(http[5],'abci_query',{'path':f'/block/{h}','prove':False})['response']
                need(type(response['code']) is int and response['code']==1 and
                     response['log']=='protocol-4 response unavailable' and response['value']=='',
                     'historical block query did not report unavailable response')
                missing.append(h);unavailable.append({'height':h,'code':response['code'],'log':response['log'],'value':response['value']})
            evidence['unavailable_blocks']=missing;evidence['unavailable_block_responses']=unavailable
            checked('no-imported-block-evidence',True)
            wires.append(make_payment(g,payers[0],address(public(payers[1])),2,71))
            final_payment_height=submit(http[1],wires[-1]);checked('post-snapshot-payment',final_payment_height>boot['height'])
        else:final_payment_height=post_height
        wait(lambda:height(target)>=final_payment_height+1,45)
        def matching():
            left=checkpoint(db(1),g);right=checkpoint(db(target),g)
            return (left,right) if all(left[k]==right[k] for k in ('height','app_hash','state','history')) else None
        left,right=wait(matching,30)
        checked('matching-source-and-target',True);verify_payment_rows(left['state'],wires);checked('ordered-payments',True)
        final_h=left['height'];wait(lambda:height(1)>final_h,15)
        signed=[rpc(http[1],'commit',{'height':str(h)})['signed_header'] for h in range(1,final_h+2)]
        now=time.time_ns();anchor=verify_replayed_anchor(g,left['history'],left['state'],signed,
                                                        report['initial_header_hash'],now)
        evidence.update(final_checkpoint=left,target_checkpoint=right,signed_headers=signed,
                        verified_anchor=anchor,payment_wires=[base64.b64encode(w).decode() for w in wires])
        if profile==PROFILES[1]:
            from recovery_checks import verify_block_records
            emissions=verify_block_records(right,g,1)
            evidence['crash']['emission_heights']=emissions
            checked('no-duplicate-emission',emissions==[emission])
        report.update(status='passed',observed_at_ns=now,evidence=evidence)
        checked('dynamic-signed-anchor',True)
        report['verification']=validate(report,source=report['source'],engine_hash=engine_hash)
        # Shut down while fixture homes still exist; no process survives cleanup.
        for c in reversed(children):stop(c)
        need(source_identity(ROOT)==source,'source changed during engine acceptance')
        need(sha(binary.read_bytes())==engine_hash,'engine binary changed during acceptance')
    except BaseException as exc:
        message=sanitize(str(exc).encode(),temp_handle.name if temp_handle else None)[:4096].decode(errors='replace')
        report.update(status='failed',error_type=type(exc).__name__,error_message=message)
        report.pop('verification',None)
    finally:
        records=[]
        for c in reversed(children):
            try:records.append(c.stop())
            except BaseException:report.update(status='failed',log_capture_failed=True)
        report['process_logs']=list(reversed(records))
        if temp_handle is not None:
            try:temp_handle.cleanup()
            except OSError:report.update(status='failed',runtime_cleanup_failed=True)
        if any(r['truncated'] for r in records):report.update(status='failed',log_truncated=True)
        if report['status']!='passed':report.pop('verification',None)
        write_new(output/'result.json',report)
    return report

def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--cometbft',type=Path,required=True);p.add_argument('--engine-sha256',required=True)
    p.add_argument('--output',type=Path,required=True);p.add_argument('--profile',choices=PROFILES,required=True)
    a=p.parse_args();r=run(a.cometbft,a.engine_sha256,a.output,a.profile)
    print(json.dumps({k:v for k,v in r.items() if k!='evidence'},indent=2))
    return 0 if r['status']=='passed' else 2

if __name__=='__main__':raise SystemExit(main())
