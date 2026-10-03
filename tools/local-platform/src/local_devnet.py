"""Exclusive private four-validator development lifecycle; no public provisioning."""
import base64
import fcntl
import hashlib
import http.client
import os
from pathlib import Path
import stat
import subprocess
import sys
import time

from block_application import encode, restore
from commit_verifier import load_json
from native_core import address, canonical, digest, public, sign
from offline_signer import create_vault, _load_vault, _password
from registry_rules_core import GENESIS_FORMAT
from validator_sets_core import canonical_roster
from commit_verifier import header_hash
from p4_evidence import need, integer, hash_text, policy_checked, p4_genesis
from p4_read_store import private_path
from development_profile import DURABLE_PROFILE,max_height_for
from p4_incremental_evidence import policy_v2_checked
from validator_witness import nanos
from p4_delivery import collect_evidence
from platform_service import PlatformService
from run_devnet import free_ports, patch_toml

ROOT=Path(__file__).resolve().parents[3]
PIN='0.38.25'
PIN_SHA='218628da07bed5d27e178d38d0bef9ecf46f21b214c8e9fea402fd215fccc024'
FORMAT='1soft/local-development-workspace/v1'
MAX_LOG=5*1024*1024


def read_private(path,maximum=2*1024*1024):
    p=private_path(path);need(p.is_file(),'private file is missing')
    need(p.stat().st_size<=maximum,'private file exceeds bound')
    fd=os.open(p,os.O_RDONLY|os.O_NOFOLLOW)
    with os.fdopen(fd,'rb') as file:
        data=file.read(maximum+1)
    need(len(data)<=maximum,'private file exceeds bound');return data


def private_new(path,data):
    p=private_path(path);need(type(data) is bytes,'exact file bytes required')
    fd=os.open(p,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
    with os.fdopen(fd,'wb') as file:file.write(data);file.flush();os.fsync(file.fileno())
    fd=os.open(p.parent,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
    try:os.fsync(fd)
    finally:os.close(fd)


class WorkspaceLock:
    def __init__(self,root):self.root=Path(root).absolute();self.fd=None
    def __enter__(self):
        p=private_path(self.root/'owner.lock');need(p.is_file(),'workspace owner lock missing')
        self.fd=os.open(p,os.O_RDWR|os.O_NOFOLLOW)
        try:fcntl.flock(self.fd,fcntl.LOCK_EX|fcntl.LOCK_NB)
        except BlockingIOError:
            os.close(self.fd);self.fd=None;raise ValueError('workspace already has a live owner') from None
        return self
    def __exit__(self,*_):
        if self.fd is not None:os.close(self.fd);self.fd=None


def verify_engine(engine,expected_sha256=PIN_SHA):
    hash_text(expected_sha256);need(expected_sha256==PIN_SHA,'engine pin is not the release pin')
    binary=Path(engine).absolute();need(binary.is_file() and not binary.is_symlink(),'pinned engine absent')
    need(binary.stat().st_size<=256*1024*1024,'engine exceeds bound')
    h=hashlib.sha256()
    with binary.open('rb') as file:
        while block:=file.read(1024*1024):h.update(block)
    need(h.hexdigest()==expected_sha256,'engine differs from release SHA256 pin')
    result=subprocess.run([str(binary),'version'],capture_output=True,timeout=10,check=True)
    need(result.stdout.strip().decode('ascii').lstrip('v')==PIN,'engine version differs')
    return binary


def rpc(port,method,params=None):
    integer(port,1,65535);payload=encode({'jsonrpc':'2.0','id':1,'method':method,'params':params or {}})
    conn=http.client.HTTPConnection('127.0.0.1',port,timeout=8)
    try:
        conn.request('POST','/',payload,{'Content-Type':'application/json'})
        response=conn.getresponse();raw=response.read(8*1024*1024+1)
        need(response.status==200 and len(raw)<=8*1024*1024,'local node response unavailable')
        value=load_json(raw,max_bytes=8*1024*1024)
        need('error' not in value and value.get('id')==1,'local node operation unavailable')
        return value['result']
    finally:conn.close()


def wait(predicate,seconds=30):
    deadline=time.monotonic()+seconds
    while time.monotonic()<deadline:
        try:
            value=predicate()
            if value:return value
        except (OSError,ValueError,KeyError):pass
        time.sleep(.15)
    raise ValueError('local node operation did not become available in time')


def immutable_names():
    names={'app-genesis.json','engine-genesis.json',*[n+'.pem' for n in
           ('owner','merchant','raven','atlas','admin0','admin1','admin2','admin3')]}
    for i in range(4):
        names.update(f'nodes/node{i}/config/'+n for n in
                     ('config.toml','genesis.json','node_key.json','priv_validator_key.json'))
    return names


def initialize(workspace,engine,expected_sha256=PIN_SHA,*,password,profile=None):
    need(profile is None or type(profile) is str and profile==DURABLE_PROFILE,
         'unknown explicit development profile')
    binary=verify_engine(engine,expected_sha256);_password(password)
    root=Path(workspace).absolute()
    need(not root.is_relative_to(ROOT),'development workspace must be outside source')
    need(os.name=='posix' and len(os.fsencode(root/'app0/a.sock'))<100,'private POSIX workspace path required, at most 85 bytes')
    need(not root.exists() and not root.is_symlink(),'workspace exists; no overwrite or reset')
    root.mkdir(mode=0o700,parents=False,exist_ok=False);private_path(root/'owner.lock')
    private_new(root/'owner.lock',b'')
    keys={name:create_vault(root/(name+'.pem'),password) for name in
          ('owner','merchant','raven','atlas','admin0','admin1','admin2','admin3')}
    nodes=root/'nodes'
    subprocess.run([str(binary),'testnet','--v','4','--n','0','--o',str(nodes)],
                   check=True,capture_output=True,timeout=40,umask=0o077)
    nodes.chmod(0o700)
    for p in nodes.rglob('*'):p.chmod(0o700 if p.is_dir() else 0o600)
    engine_genesis=load_json(read_private(nodes/'node0/config/genesis.json'))
    initial=engine_genesis['validators'];need(len(initial)==4,'exactly four initial validators required')
    for row in initial:row['power']='10'
    roster=canonical_roster([{'public_key':base64.b64decode(row['pub_key']['value'],validate=True).hex(),
                             'power':10} for row in initial])
    chain='1soft-dev-'+os.urandom(6).hex();payer=address(keys['owner']);merchant=address(keys['merchant'])
    registry={'schema':1,'format':GENESIS_FORMAT,'mode':'development-only','chain_id':chain,
        'validators':roster,'administrators':{'format':'threshold-ed25519-v1',
        'public_keys':sorted(keys['admin'+str(i)] for i in range(4)),'threshold':3},
        'minimum_delay_blocks':2,'cooldown_blocks':1,'minimum_validators':4,'maximum_power_bps':3333}
    genesis={'chain_id':chain,'asset':'DEV','fee':2,'protocol_version':4,
        'allocations':[{'public_key':keys['owner'],'units':1000},{'public_key':keys['merchant'],'units':0}],
        'validator_registry':registry}
    if profile is not None:genesis['development_profile']=profile
    private_new(root/'app-genesis.json',encode(genesis))
    engine_genesis.update(chain_id=chain,initial_height='1',app_state=genesis,validators=initial)
    engine_genesis['consensus_params']['block'].update(max_bytes='1048576',max_gas='-1')
    full=encode(engine_genesis);private_new(root/'engine-genesis.json',full)
    ports=free_ports(8);p2p=ports[:4];http=ports[4:]
    ids=[subprocess.check_output([str(binary),'show-node-id','--home',str(nodes/f'node{i}')],timeout=10).decode().strip() for i in range(4)]
    for i in range(4):
        app=root/f'app{i}';app.mkdir(mode=0o700);sock=app/'a.sock';home=nodes/f'node{i}'
        (home/'config/genesis.json').write_bytes(full)
        conf=home/'config/config.toml'
        conf.write_text(patch_toml(read_private(conf).decode(),{
            'proxy_app':f'unix://{sock}','abci':'socket','rpc.laddr':f'tcp://127.0.0.1:{http[i]}','rpc.unsafe':False,
            'p2p.laddr':f'tcp://127.0.0.1:{p2p[i]}','p2p.persistent_peers':','.join(f'{ids[j]}@127.0.0.1:{p2p[j]}' for j in range(4) if j!=i),
            'p2p.addr_book_strict':False,'p2p.allow_duplicate_ip':True,'p2p.pex':False,
            'consensus.timeout_commit':'4s','mempool.max_tx_bytes':65536}))
    roles={n:dict(payer=payer,grant_id='' if n=='owner' else n,vault=n+'.pem') for n in ('owner','raven','atlas')}
    config={'schema':1,'format':FORMAT,'chain_id':chain,'genesis_sha256':hashlib.sha256(full).hexdigest(),
        'native_sha256':hashlib.sha256(encode(genesis)).hexdigest(),'engine_sha256':PIN_SHA,
        'ports':ports,'endpoint':f'http://127.0.0.1:{http[0]}/','roles':roles,'merchant':merchant,
        'files':{n:hashlib.sha256(read_private(root/n)).hexdigest() for n in sorted(immutable_names())}}
    private_new(root/'workspace.json',encode(config))
    return config


def load_configuration(workspace):
    root=Path(workspace).absolute();raw=read_private(root/'workspace.json');q=load_json(raw)
    need(type(q) is dict and set(q)=={'schema','format','chain_id','genesis_sha256','native_sha256',
        'engine_sha256','ports','endpoint','roles','merchant','files'} and q['schema']==1 and type(q['schema']) is int and
        q['format']==FORMAT and encode(q)==raw,'workspace configuration differs')
    need(q['engine_sha256']==PIN_SHA and type(q['ports']) is list and len(q['ports'])==8 and
         len(set(q['ports']))==8,'workspace engine/ports differ')
    for port in q['ports']:integer(port,1,65535)
    need(q['endpoint']==f'http://127.0.0.1:{q["ports"][4]}/','workspace endpoint differs')
    need(type(q['files']) is dict and set(q['files'])==immutable_names(),'workspace immutable file list differs')
    for name,value in q['files'].items():
        hash_text(value);need(hashlib.sha256(read_private(root/name)).hexdigest()==value,'workspace immutable file changed')
    g,_=p4_genesis(read_private(root/'engine-genesis.json'),q['genesis_sha256'])
    need(g['asset']=='DEV' and g['chain_id']==q['chain_id'] and g['fee']==2 and g['protocol_version']==4,
         'development genesis required')
    need(read_private(root/'app-genesis.json')==encode(g) and
         hashlib.sha256(encode(g)).hexdigest()==q['native_sha256'],'native genesis differs')
    expected_payer=address(g['allocations'][0]['public_key'])
    need(q['merchant']==address(g['allocations'][1]['public_key']) and
         q['roles']=={n:dict(payer=expected_payer,grant_id='' if n=='owner' else n,vault=n+'.pem') for n in ('owner','raven','atlas')},
         'fixed development account roles differ')
    return q


class LocalNetwork:
    def __init__(self,workspace,engine,*,clock=time.time_ns):
        self.root=Path(workspace).absolute();self.config=load_configuration(self.root)
        self.binary=verify_engine(engine);self.clock=clock
        self.lock=None;self.apps=[];self.engines=[];self.handles=[];self.stopped=False;self._alpha_store=None
        self.alpha=load_json(read_private(self.root/'app-genesis.json')).get('development_profile')==DURABLE_PROFILE
    def _log(self,name):
        p=private_path(self.root/name)
        need(not p.exists() or p.stat().st_size<=MAX_LOG,'node log capacity reached')
        fd=os.open(p,os.O_WRONLY|os.O_APPEND|os.O_CREAT|os.O_NOFOLLOW,0o600)
        handle=os.fdopen(fd,'ab');self.handles.append(handle);return handle
    def start(self):
        need(self.lock is None and not self.stopped,'network lifecycle already used')
        self.lock=WorkspaceLock(self.root);self.lock.__enter__()
        try:
            for i in range(4):
                app=self.root/f'app{i}';private_path(app/'state.sqlite')
                need(not (app/'a.sock').exists() and not (app/'a.sock').is_symlink(),
                     'ABCI socket already exists; inspect its owner, no replacement')
                log=self._log(f'app{i}.log')
                self.apps.append(subprocess.Popen([sys.executable,str(ROOT/'tools/local-platform/scripts/serve_app.py'),
                    '--genesis',str(self.root/'app-genesis.json'),'--genesis-sha256',self.config['native_sha256'],
                    '--database',str(app/'state.sqlite'),'--socket',str(app/'a.sock')],stdout=log,stderr=log,
                    pass_fds=(self.lock.fd,),umask=0o077,
                    env={**os.environ,'PYTHONPATH':'','PYTHONDONTWRITEBYTECODE':'1'}))
                wait(lambda:(app/'a.sock').exists(),15)
            for i in range(4):
                log=self._log(f'engine{i}.log')
                self.engines.append(subprocess.Popen([str(self.binary),'start','--home',str(self.root/f'nodes/node{i}')],
                    stdout=log,stderr=log,pass_fds=(self.lock.fd,),umask=0o077))
            wait(lambda:all(self.height(i)>=1 for i in range(4)),80)
            return self
        except BaseException:self.stop();raise
    def height(self,i=0):
        self.health();return int(rpc(self.config['ports'][4+i],'status')['sync_info']['latest_block_height'])
    def health(self):
        need(all(p.poll() is None for p in self.apps+self.engines),'owned node process exited; data preserved')
        need(all(not p.exists() or p.stat().st_size<=MAX_LOG for p in
                 [self.root/f'{kind}{i}.log' for kind in ('app','engine') for i in range(4)]),
                 'node log capacity reached; stop and preserve data')
    def policy(self):
        q=(policy_v2_checked if self.alpha else policy_checked)(load_json(read_private(self.root/'policy.json')))
        need(q['genesis_sha256']==self.config['genesis_sha256'],'workspace policy belongs to another genesis')
        return q
    def service(self,**kw):
        if self.alpha:
            from p4_incremental_store import P4IncrementalStore
            from p4_alpha_platform_service import AlphaPlatformService
            genesis=read_private(self.root/'engine-genesis.json');policy=self.policy()
            if self._alpha_store is None:
                self._alpha_store=P4IncrementalStore(self.root/'ledger.sqlite',genesis,policy,
                    create=kw.get('create',False),clock=self.clock)
            return AlphaPlatformService(self.root,genesis,policy,self.config['endpoint'],
                self.config['roles'],clock=self.clock,store=self._alpha_store,**kw)
        return PlatformService(self.root,read_private(self.root/'engine-genesis.json'),self.policy(),
                               self.config['endpoint'],self.config['roles'],clock=self.clock,**kw)
    def ready(self):
        p=self.root/'READY.json'
        if not p.exists():return False
        q=load_json(read_private(p));need(q=={'schema':1,'format':'1soft/local-development-ready/v1',
            'workspace_sha256':hashlib.sha256(read_private(self.root/'workspace.json')).hexdigest(),
            'policy_sha256':hashlib.sha256(read_private(self.root/'policy.json')).hexdigest()},'workspace readiness pins differ')
        self.policy();return True
    def bootstrap(self,*,password):
        need(self.lock is not None and not self.stopped,'network is not owned')
        if self.ready():return {'status':'original_workspace_retained','trust_renewed':False}
        need(not any((self.root/(n+'.sqlite')).exists() for n in ('wallet','delivery','ledger','requests','receipts')),
             'partially initialized journals retained; no repair or recreation')
        _password(password);genesis=load_json(read_private(self.root/'app-genesis.json'))
        key=_load_vault(self.root/'owner.pem',password)
        need(public(key)==genesis['allocations'][0]['public_key'],'development owner vault differs')
        expiry=4096 if self.alpha else 500
        recipient=self.config['merchant'];port=self.config['ports'][4];ops=[{
            'type':'budget_create','id':'studio','cap':100,'expires':expiry,'recipients':[recipient]}]
        for name in ('raven','atlas'):
            pk=public(_load_vault(self.root/(name+'.pem'),password))
            ops.append({'type':'grant','id':name,'public_key':pk,'cap':100,'expires':expiry,
                        'recipients':[recipient],'budget_id':'studio'})
        # This setup exists only before the canonical financial journal. Each
        # original setup wire/claim is retained; uncertain claims are not resent.
        for nonce,op in enumerate(ops):
            wire_path=self.root/f'setup-{nonce}.json';claim=self.root/f'setup-{nonce}.claim'
            if wire_path.exists():wire=read_private(wire_path,32768)
            else:
                ledger=restore(genesis,genesis_native(port))
                try:wire=canonical(sign(key,ledger.body(self.config['roles']['owner']['payer'],nonce,op,valid_until=100)))
                finally:ledger.close()
                private_new(wire_path,wire)
            packet=load_json(wire,max_bytes=32768)
            need(canonical(packet)==wire and packet['body']['op']==op and packet['body']['nonce']==nonce and
                 packet['body']['genesis_hash']==digest(genesis) and packet['body']['sender']==address(public(key)) and
                 packet==sign(key,packet['body']),'saved setup wire differs')
            txhash=base64.b64encode(hashlib.sha256(wire).digest()).decode()
            if not claim.exists():
                private_new(claim,hashlib.sha256(wire).hexdigest().encode())
                admission=rpc(port,'broadcast_tx_sync',{'tx':base64.b64encode(wire).decode()})
                need(type(admission['code']) is int and admission['code']==0,'development setup admission refused')
            else:need(read_private(claim)==hashlib.sha256(wire).hexdigest().encode(),'saved setup claim differs')
            result=wait(lambda:rpc(port,'tx',{'hash':txhash}),30)
            need(type(result['tx_result']['code']) is int and result['tx_result']['code']==0 and
                 base64.b64decode(result['tx'],validate=True)==wire,'exact development setup execution unavailable')
        key=None
        policy_path=self.root/'policy.json'
        if not policy_path.exists():
            first=rpc(port,'commit',{'height':'1'})['signed_header']['header']
            policy={'schema':1,'format':'1soft/protocol4-read-policy/v1','genesis_sha256':self.config['genesis_sha256'],
                'anchor_height':1,'anchor_hash':header_hash(first).hex(),'anchor_time':first['time'],
                'trust_period_seconds':3600,'max_clock_drift_seconds':5,'expected_block_version':11}
            if self.alpha:
                policy.update(schema=2,format='1soft/protocol4-read-policy/v2',checkpoint_progression=True,
                    absolute_not_after_ns=nanos(policy['anchor_time'])+86400*10**9)
            private_new(policy_path,encode((policy_v2_checked if self.alpha else policy_checked)(policy)))
        if self.alpha:
            with self.service(create=True) as svc:
                svc.refresh(expected_tip=None);svc.sync(expected_revision=None)
        else:
            proof=collect_evidence(self.config['endpoint'],read_private(self.root/'engine-genesis.json'),self.policy(),self.clock())['evidence']
            with self.service(create=True) as svc:
                svc.import_checkpoint(proof,expected_tip=None);svc.sync(expected_revision=None)
        private_new(self.root/'READY.json',encode({'schema':1,'format':'1soft/local-development-ready/v1',
            'workspace_sha256':hashlib.sha256(read_private(self.root/'workspace.json')).hexdigest(),
            'policy_sha256':hashlib.sha256(read_private(policy_path)).hexdigest()}))
        return {'status':'development_workspace_ready','validator_count':4,'trust_renewed':False}
    def stop(self):
        # Popen handles, never a process-name kill or an inferred external PID.
        errors=[]
        for p in [*reversed(self.engines),*reversed(self.apps)]:
            if p.poll() is None:
                p.terminate()
                try:p.wait(timeout=10)
                except subprocess.TimeoutExpired:
                    p.kill();p.wait(timeout=10);errors.append('owned process required kill; inspect retained socket before restart')
        for h in self.handles:h.close()
        self.handles=[]
        if self._alpha_store is not None:self._alpha_store.close();self._alpha_store=None
        if self.lock is not None:self.lock.__exit__();self.lock=None
        self.stopped=True
        return {'status':'owned_processes_stopped','data_preserved':True,'warnings':errors}
    def __enter__(self):return self.start()
    def __exit__(self,*_):self.stop()


def genesis_native(port):
    response=rpc(port,'abci_query',{'path':'/state','prove':False})['response']
    need(type(response['code']) is int and response['code']==0,'development application state unavailable')
    return load_json(base64.b64decode(response['value'],validate=True),max_bytes=4*1024*1024)['native']
