"""Protected local commands around the unchanged encrypted P8 recipient wallet.

External credentials and private outputs are owner-only files. No dispatcher,
key generation, reproof, repair, migration or public endpoint.
"""
from __future__ import annotations
from contextlib import contextmanager
import fcntl, os, stat
from pathlib import Path

import protocol8_transfer as n
from protocol8_consensus import canonical, closed_json, genesis_shape, genesis_document, bootstrap_digest
from protocol8_notes import NoteController, opening
from protocol8_prover import Prover
from protocol8_wallet import RecipientWallet, MAX_FILE, ENVELOPE, REVIEW_FORMAT, REVIEW_SCHEME
from protocol8_worker import Worker
from protocol8_operator import absolute, parents, directory, read_file, write_new, pin, sha, require

ROOT=Path(__file__).resolve().parents[1]
FORMAT='1soft/protocol8-wallet-cli/v1'
MEMBERS={'wallet-cli.json','genesis.json','kat.tx','wallet-cli.lock'}
MAX_PACKET=4*1024**2

def runtime_files():
    paths=sorted([*ROOT.glob('src/*.py'),ROOT/'scripts/protocol8_wallet.py',
                  ROOT/'scripts/protocol8_worker_exec.py',ROOT/'scripts/protocol8_private_exec.py'])
    return {p.relative_to(ROOT).as_posix():sha(read_file(p,1024**2)) for p in paths}

def credentials(path):
    p=absolute(path);directory(p.parent,private=True)
    raw=read_file(p,1024,private=True);v=closed_json(raw,1024)
    require(type(v) is dict and set(v)=={'key','wallet_id','recipient_secret'},'closed external credentials required')
    for k in v:pin(v[k])
    require(any(bytes.fromhex(v['key'])) and v['wallet_id']!=n.ZERO,'nonzero external key and wallet ID required')
    n.field(v['recipient_secret']);require(v['recipient_secret']!=n.ZERO,'nonzero recipient secret required')
    return raw,v

def inputs(genesis,genesis_sha256,kat,worker,helper,helper_sha256,prover,prover_sha256,credential_path,wallet_path):
    raw=read_file(genesis,16384);require(sha(raw)==pin(genesis_sha256),'external genesis pin differs')
    g=genesis_shape(raw);k=read_file(kat,3560)
    require(len(k)==3560 and sha(k)==g['kat_sha256'],'KAT pin differs')
    paths={name:absolute(path) for name,path in (('worker',worker),('helper',helper),('prover',prover))}
    pins={'worker':g['worker_sha256'],'helper':pin(helper_sha256),'prover':pin(prover_sha256)}
    for name,p in paths.items():require(sha(read_file(p,32*1024**2,executable=True))==pins[name],'native binary pin differs')
    cr,v=credentials(credential_path);wp=absolute(wallet_path);directory(wp.parent,private=True)
    require(wp not in (absolute(credential_path),*(paths.values())),'wallet path collides with input')
    config={'format':FORMAT,'genesis_sha256':genesis_sha256,'profile_sha256':g['profile_sha256'],
        'kat_sha256':g['kat_sha256'],'binaries':{name:{'path':str(paths[name]),'sha256':pins[name]} for name in paths},
        'credentials_path':str(absolute(credential_path)),'credentials_sha256':sha(cr),
        'wallet_path':str(wp),'wallet_id':v['wallet_id'],'runtime_files':runtime_files()}
    return raw,k,config,v

def native(raw,k,config,secret,trace):
    b=config['binaries'];worker=Worker(b['worker']['path'],b['worker']['sha256'],k);trace['worker']=worker
    genesis_document(raw,worker)
    helper=NoteController(b['helper']['path'],b['helper']['sha256'],expected_genesis=raw,worker=worker);trace['helper']=helper
    prover=Prover(b['prover']['path'],b['prover']['sha256'],expected_genesis=raw,worker=worker);trace['prover']=prover
    wallet=RecipientWallet(config['wallet_path'],key=bytes.fromhex(secret['key']),wallet_id=secret['wallet_id'],
        recipient_secret=secret['recipient_secret'],controller=helper,create=trace.pop('create',False))
    return wallet,prover

def initialize(args,trace):
    target=parents(args.workspace);directory(target.parent)
    require(not target.exists() and not target.is_symlink(),'init requires a new configuration workspace')
    raw,k,config,v=inputs(args.genesis,args.genesis_sha256,args.kat,args.worker,args.helper,args.helper_sha256,
        args.prover,args.prover_sha256,args.credentials,args.wallet)
    wp=Path(config['wallet_path'])
    require(not wp.exists() and not wp.is_symlink() and not Path(str(wp)+'.lock').exists(), 'init requires a fresh wallet target')
    require(target!=wp.parent and target not in wp.parents,'separate existing private wallet directory required')
    # Native validation happens before creation. Reuse these measured objects for
    # the actual wallet creation; do not expose the private credentials.
    b=config['binaries'];w=Worker(b['worker']['path'],b['worker']['sha256'],k);trace['worker']=w
    genesis_document(raw,w)
    h=NoteController(b['helper']['path'],b['helper']['sha256'],expected_genesis=raw,worker=w);trace['helper']=h
    p=Prover(b['prover']['path'],b['prover']['sha256'],expected_genesis=raw,worker=w);trace['prover']=p
    recipient=h.key(v['recipient_secret'])
    target.mkdir(mode=0o700)
    write_new(target/'genesis.json',raw);write_new(target/'kat.tx',k);write_new(target/'wallet-cli.lock',b'')
    wallet=RecipientWallet(wp,key=bytes.fromhex(v['key']),wallet_id=v['wallet_id'],recipient_secret=v['recipient_secret'],controller=h,create=True)
    require(wallet.recipient_key==recipient,'recipient identity differs')
    config['wallet_pins']=wallet.pins
    write_new(target/'wallet-cli.json',canonical(config));sync_dir(target)
    return {'status':'initialized','wallet_id':v['wallet_id'],'recipient_key':recipient,
        'encrypted_wallet_created':True,'native_startup':w.startup}

def sync_dir(path):
    fd=os.open(path,os.O_RDONLY|os.O_DIRECTORY)
    try:os.fsync(fd)
    finally:os.close(fd)

@contextmanager
def locked(workspace):
    root=directory(workspace,private=True)
    require({p.name for p in root.iterdir()}==MEMBERS,'incomplete or unknown configuration membership')
    read_file(root/'wallet-cli.lock',0,private=True)
    fd=os.open(root/'wallet-cli.lock',os.O_RDONLY|os.O_NOFOLLOW)
    try:
        opened=os.fstat(fd);live=(root/'wallet-cli.lock').lstat()
        require((opened.st_dev,opened.st_ino)==(live.st_dev,live.st_ino),'configuration lock replaced')
        try:fcntl.flock(fd,fcntl.LOCK_EX|fcntl.LOCK_NB)
        except BlockingIOError:raise ValueError('wallet configuration busy') from None
        yield root
    finally:os.close(fd)

def load(root,args):
    stored=closed_json(read_file(root/'wallet-cli.json',32768,private=True),32768)
    require(type(stored) is dict and set(stored)=={'format','genesis_sha256','profile_sha256','kat_sha256',
        'binaries','credentials_path','credentials_sha256','wallet_path','wallet_id','runtime_files','wallet_pins'},'closed wallet manifest required')
    require(type(stored['binaries']) is dict and set(stored['binaries'])=={'worker','helper','prover'},'closed binary membership required')
    for b in stored['binaries'].values():require(type(b) is dict and set(b)=={'path','sha256'},'closed binary pin required')
    require(str(absolute(args.credentials))==stored['credentials_path'],'external credential source differs')
    b=stored['binaries'];raw,k,actual,v=inputs(root/'genesis.json',args.genesis_sha256,root/'kat.tx',b['worker']['path'],
        b['helper']['path'],b['helper']['sha256'],b['prover']['path'],b['prover']['sha256'],args.credentials,stored['wallet_path'])
    g=genesis_shape(raw);pins=stored['wallet_pins']
    require(type(pins) is dict,'closed wallet pins required')
    expected={'format':ENVELOPE,'wallet_id':v['wallet_id'],'recipient_key':pins.get('recipient_key'),
        'genesis_sha256':sha(canonical(g)),'bootstrap_sha256':bootstrap_digest(g),'profile_sha256':n.PROFILE_SHA256,
        'parameter_sha256':n.PROFILE['parameter_sha256'],'verifying_key_sha256':n.PROFILE['verifying_key_sha256'],
        'worker_sha256':g['worker_sha256'],'kat_sha256':g['kat_sha256'],'controller_sha256':b['helper']['sha256']}
    n.field(expected['recipient_key']);require(expected['recipient_key']!=n.ZERO and pins==expected,'wallet identity/profile pins differ')
    actual['wallet_pins']=pins;require(actual==stored,'manifest/runtime pins differ; no automatic upgrade')
    wp=Path(stored['wallet_path']);read_file(wp,MAX_FILE,private=True);read_file(Path(str(wp)+'.lock'),0,private=True)
    for suffix in ('-wal','-shm','-journal'):require(not Path(str(wp)+suffix).exists() and not Path(str(wp)+suffix).is_symlink(),'plaintext wallet sidecar refused')
    envelope=closed_json(read_file(wp,MAX_FILE,private=True),MAX_FILE)
    require(type(envelope) is dict and set(envelope)=={'header','ciphertext'},'closed encrypted envelope required')
    header=envelope['header'];pins=stored['wallet_pins']
    require(type(pins) is dict and pins.get('format')==ENVELOPE and type(header) is dict and
        set(header)==set(pins)|{'revision','nonce'} and all(header[x]==y for x,y in pins.items()),'stored envelope pins differ')
    return raw,k,stored,v

def packet(path):
    v=closed_json(read_file(path,MAX_PACKET,private=True),MAX_PACKET)
    require(type(v) is dict and set(v)=={'witness','signed_header'},'closed signed-state packet required')
    return v

def private_output(path,raw):
    p=parents(path);directory(p.parent,private=True)
    require(not p.exists() and not p.is_symlink(),'output already exists; never overwrite')
    stage=p.with_name('.'+p.name+'.stage-'+os.urandom(16).hex())
    try:
        write_new(stage,raw);os.link(stage,p);stage.unlink();sync_dir(p.parent)
    finally:
        if stage.exists():stage.unlink()
    return {'bytes':len(raw),'sha256':sha(raw),'private_file_created':True}

def operate(args,trace):
    if args.command=='init':return initialize(args,trace)
    with locked(args.workspace) as root:
        raw,k,config,v=load(root,args)
        trace['_wallet_id']=config['wallet_id']
        if args.command=='doctor':return {'status':'configuration-valid','native_executed':False,
            'encrypted_store_authenticated':False,'wallet_id':config['wallet_id'],'wallet_present':True}
        wallet,prover=native(raw,k,config,v,trace)
        require(wallet.pins==config['wallet_pins'],'authenticated wallet pins differ')
        c=args.command
        if c=='inventory':return {'status':'authenticated-inventory','inventory':wallet.inventory()}
        if c=='observe':
            p=packet(args.packet);cert=wallet.observe(p['witness'],p['signed_header'])
            return {'status':'signed-state-observed','certificate':cert}
        if c=='import-note':
            o=closed_json(read_file(args.opening,1024,private=True),1024);opening(o)
            wire=None if args.genesis_note else read_file(args.wire,3560,private=True)
            return {'status':'note-imported','commitment':wallet.import_note(o,raw=wire,output=args.output_index,genesis=args.genesis_note)}
        if c=='prepare':return {'status':'original-wire-retained','txid':wallet.prepare(prover,args.commitment,
            request=args.request,destination=args.destination,payment=args.payment,valid_until=args.valid_until,payment_expiry=args.payment_expiry)}
        if c=='mark-attempt':wallet.mark_attempt(args.txid);return {'status':'attempt-marked','txid':args.txid,'attempts':1}
        if c=='reconcile':return {'status':'original-reconciled','result':wallet.reconcile(args.txid)}
        if c=='export':return {'status':'exact-wire-exported','txid':args.txid,**private_output(args.output,wallet.export(args.txid))}
        if c=='review':
            view={**wallet.review_intent(args.txid),'genesis_sha256':args.genesis_sha256,
                'runtime_sha256':sha(canonical(runtime_files()))}
            return {'status':'private-intent-reviewed','txid':args.txid,'review_commitment_scheme':REVIEW_SCHEME,**private_output(args.output,canonical(view))}
        if c=='deliver':return {'status':'private-opening-delivered','txid':args.txid,
            **private_output(args.output,canonical(wallet.output_opening(args.txid,args.output_index)))}
        raise ValueError('unsupported wallet command')

def execute(args):
    trace={};result=None;exit_code=0
    try:result=operate(args,trace)
    except Exception as exc:
        # Never echo malformed private JSON, credentials, native diagnostics or
        # arbitrary exception strings into a public command log.
        result={'status':'refused','error_type':type(exc).__name__,'reason':'wallet command refused; private input details suppressed'};exit_code=1
    wallet_id=result.get('wallet_id',trace.pop('_wallet_id',None))
    trace.pop('_wallet_id',None)
    audits={name:obj.audit() for name,obj in trace.items()}
    return {'format':FORMAT,'command':args.command,**result,'genesis_sha256':args.genesis_sha256,
        'wallet_id':wallet_id,
        'runtime_sha256':sha(canonical(runtime_files())),'pid':os.getpid(),
        'start_ticks':int(Path('/proc/self/stat').read_text().rsplit(')',1)[1].split()[19]),
        'native_audits':audits,'broadcast_calls':0,'automatic_retry':False,'freshness_established':False,
        'production_ready':False},exit_code
