"""Native serialized owner treasury laboratory; no P7 consensus qualification."""
from __future__ import annotations
from collections import OrderedDict
import copy,hashlib,json,os,re,signal,stat,subprocess,sys,tempfile
from pathlib import Path
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey,Ed25519PublicKey

PROFILE_PATH=Path(__file__).resolve().parents[1]/'PROFILE_V1.json'
PROFILE=json.loads(PROFILE_PATH.read_bytes());PROFILE_SHA256=hashlib.sha256(PROFILE_PATH.read_bytes()).hexdigest()
FIELD_MODULUS=0x40000000000000000000000000000000224698fc094cf91b992d30ed00000001
ZERO='00'*32;MAX_U64=2**64-1;MAX_HEIGHT=64;MAX_HISTORY=64;MAX_BYTES=262144
PAYMENT_MAGIC=b'1SOTPY01';COMMAND_MAGIC=b'1SOWNR01'
COMMAND_DOMAIN=b'1soft/owner-treasury-lab/owner-command/v1\0'
TX_DOMAIN=b'1soft/owner-treasury-lab/transaction/v1\0'
T_KEYS={'genesis','asset','mission','parent_id','epoch','owner_key','owner_epoch','owner_sequence','parent','grants','fee','notes'}
RUNTIME_KEYS={'fees','nullifiers','authority_nullifiers','anchors'}
BODY_KEYS={'format','profile_sha256','genesis_sha256','chain_id','owner_key','owner_epoch','next_sequence','context_root','kind','grant_id','generation','old_commitment','height','new_generation','new_commitment','new_agent_key'}
LOGS={0:'',1:'malformed owner treasury transaction',2:'current owner treasury authority differs',3:'execution height differs',4:'value anchor differs',5:'replay or duplicate',6:'invalid owner treasury proof',7:'owner treasury capacity exceeded',8:'owner signature refused'}
class Unavailable(ValueError):pass
def need(condition,message):
    if not condition:raise ValueError(message)
def digest(raw):return hashlib.sha256(raw).hexdigest()
def canonical(v):return json.dumps(v,sort_keys=True,separators=(',',':'),allow_nan=False).encode()
def hexbytes(v,n):
    need(type(v) is str and re.fullmatch('[0-9a-f]{'+str(n*2)+'}',v) is not None,'canonical hex bytes required')
    return bytes.fromhex(v)
def field(v):
    raw=hexbytes(v,32);need(int.from_bytes(raw,'little')<FIELD_MODULUS,'canonical field required');return raw
def number(v):need(type(v) is int and 0<=v<=MAX_U64,'canonical u64 required');return v
def integer(v):return number(int.from_bytes(field(v),'little'))
def numfield(v):return number(v).to_bytes(32,'little').hex()
def closed_json(raw,bound):
    need(type(raw) is bytes and len(raw)<=bound,'bounded canonical JSON required')
    v=json.loads(raw);need(canonical(v)==raw,'closed canonical JSON bytes required');return v
def parse(raw):
    need(type(raw) is bytes and len(raw)==4168 and raw[:8]==PAYMENT_MAGIC,'exact owner treasury payment envelope required')
    p=[raw[8+i*32:8+(i+1)*32].hex() for i in range(30)]
    for v in p:field(v)
    need(integer(p[0])==2 and all(p[i]!=ZERO for i in list(range(19))+list(range(20,24))+[26,27,28,29]),'owner payment version/nonzero fields')
    for i in [14,15,16,17,25,26,28]:integer(p[i])
    need(integer(p[15])<integer(p[16]) and p[22]!=p[23],'owner payment interval/outputs');return p
def packet(raw):
    need(type(raw) is bytes and raw[:8]==COMMAND_MAGIC,'owner command envelope required')
    v=closed_json(raw[8:],2048);need(type(v) is dict and set(v)=={'body','signature'},'closed owner packet required')
    b=v['body'];need(type(b) is dict and set(b)==BODY_KEYS and b['format']=='1soft/owner-treasury-command/v1','closed owner body required')
    for k in ('profile_sha256','genesis_sha256','owner_key'):hexbytes(b[k],32)
    for k in ('context_root','grant_id','old_commitment','new_commitment','new_agent_key'):field(b[k])
    for k in ('owner_epoch','next_sequence','generation','height','new_generation'):number(b[k])
    need(type(b['chain_id']) is str and re.fullmatch('[a-zA-Z0-9_-]{1,50}',b['chain_id']) is not None and b['kind'] in ('enroll','revoke','rotate'),'owner command domain/kind')
    need(b['owner_epoch']>0 and b['next_sequence']>0 and 1<=b['height']<=MAX_HEIGHT and b['grant_id']!=ZERO and b['owner_key']!=ZERO,'owner command zero/height')
    hexbytes(v['signature'],64);return v
def txid(raw):
    if raw[:8]==PAYMENT_MAGIC:parse(raw)
    else:packet(raw)
    return digest(TX_DOMAIN+raw)

class Native:
    """Measured inode and bounded real subprocess; no unavailable-proof fallback."""
    def __init__(self,binary,sha256,kat):
        self.binary=Path(binary).absolute();hexbytes(sha256,32);self.sha256=sha256;self.kat_sha256=digest(kat);self.cache=OrderedDict()
        parse(kat)
        need(self.verify(kat),'actual owner proof KAT refused')
        bad=bytearray(kat);bad[-1]^=1;need(not self.verify(bytes(bad)),'corrupt owner proof KAT accepted')
        ids=json.loads(self.call('identities',b''));need(type(ids) is dict and set(ids)=={'parameter_sha256','verifying_key_sha256'} and all(ids[k]==PROFILE[k] for k in ids),'native owner profile identity differs')
        self.startup={'binary_sha256':sha256,'kat_sha256':self.kat_sha256,'profile_sha256':PROFILE_SHA256,**ids,'valid_proof_verified':True,'corrupt_proof_refused':True}
    def _open(self):
        try:
            fd=os.open(self.binary,os.O_RDONLY|os.O_NOFOLLOW)
            m=os.fstat(fd);need(stat.S_ISREG(m.st_mode) and m.st_uid==os.getuid() and not m.st_mode&0o022 and m.st_mode&0o100 and m.st_size<=16*1024*1024,'unsafe owner native binary')
            with os.fdopen(os.dup(fd),'rb') as f:need(hashlib.file_digest(f,'sha256').hexdigest()==self.sha256,'owner native binary identity differs')
            return fd
        except BaseException as exc:
            if 'fd' in locals():os.close(fd)
            if isinstance(exc,Unavailable):raise
            raise Unavailable('owner native executable unavailable or identity differs') from exc
    def call(self,op,raw):
        need(op in ('verify','context-root','note-root','owner-key','identities') and type(raw) is bytes and len(raw)<=8192,'native request bound')
        try:fd=self._open()
        except Unavailable:raise
        except (OSError,ValueError) as exc:raise Unavailable('owner native executable unavailable or identity differs') from exc
        try:
            with tempfile.TemporaryFile() as out,tempfile.TemporaryFile() as err:
                p=subprocess.Popen([sys.executable,'-I','-B',str(Path(__file__).with_name('native_exec.py')),str(fd),op],stdin=subprocess.PIPE,stdout=out,stderr=err,pass_fds=(fd,),env={},start_new_session=True)
                try:p.communicate(raw,timeout=45)
                except subprocess.TimeoutExpired:
                    try:os.killpg(p.pid,signal.SIGKILL)
                    except ProcessLookupError:pass
                    finally:p.communicate()
                    raise Unavailable('native wall deadline') from None
                out.seek(0);err.seek(0);reply=out.read(257);error=err.read(257)
                if op=='verify' and p.returncode==1 and reply==b'' and error==b'Error: "proof"\n':return b'INVALID\n'
                if p.returncode or error or len(reply)>256:raise Unavailable('native subprocess failure or malformed response')
                return reply
        finally:os.close(fd)
    def verify(self,raw):
        parse(raw);fd=self._open();os.close(fd)
        if raw in self.cache:return True
        reply=self.call('verify',raw)
        if reply==b'INVALID\n':return False
        need(reply==b'verified\n','native verifier response differs');self.cache[raw]=True
        if len(self.cache)>8:self.cache.popitem(last=False)
        return True
    def field_call(self,op,raw):
        result=self.call(op,raw)
        try:
            need(len(result)==32,'native field response bound');field(result.hex())
        except ValueError as exc:raise Unavailable('native field response malformed') from exc
        return result.hex()
    def owner_key(self,key):return self.field_call('owner-key',hexbytes(key,32))
    def context_root(self,t):
        validate_treasury(t,runtime=RUNTIME_KEYS<=set(t))
        f=[t[k] for k in ('genesis','asset','mission','parent_id')]+[numfield(t['epoch']),numfield(t['owner_epoch']),numfield(t['owner_sequence']),self.owner_key(t['owner_key']),t['parent'],numfield(t['fee'])]
        for g in t['grants']:f.extend([g['id'],numfield(g['generation']),g['commitment'],g['agent_key']])
        return self.field_call('context-root',b''.join(field(v) for v in f))
    def note_root(self,notes):
        need(type(notes) is list and len(notes)<=16,'native note bound');return self.field_call('note-root',b''.join(field(v) for v in notes))

def validate_treasury(t,runtime=False):
    need(type(t) is dict and set(t)==T_KEYS|(RUNTIME_KEYS if runtime else set()),'closed owner treasury required')
    for k in ('genesis','asset','mission','parent_id','parent'):field(t[k]);need(t[k]!=ZERO,'owner treasury nonzero field')
    hexbytes(t['owner_key'],32);need(t['owner_key']!=ZERO,'owner key zero')
    for k in ('epoch','owner_epoch','owner_sequence','fee'):number(t[k])
    need(t['epoch']>0 and t['owner_epoch']>0 and t['fee']>0,'owner treasury nonzero integer')
    gs=t['grants'];need(type(gs) is list and len(gs)==2,'two owner grant slots')
    for g in gs:
        need(type(g) is dict and set(g)=={'id','generation','commitment','agent_key'},'closed owner grant')
        for k in ('id','commitment','agent_key'):field(g[k])
        number(g['generation']);need(g['id']!=ZERO,'stable nonzero grant ID')
        need((g['generation']==0 and g['commitment']==g['agent_key']==ZERO) or (g['generation']>0 and g['agent_key']!=ZERO),'owner grant generation/key invariant')
    need(gs[0]['id']!=gs[1]['id'],'distinct stable grants')
    need(type(t['notes']) is list and 1<=len(t['notes'])<=16 and len(set(t['notes']))==len(t['notes']),'bounded distinct initial notes')
    for v in t['notes']:field(v);need(v!=ZERO,'nonzero notes')
    if runtime:
        number(t['fees'])
        for k in ('nullifiers','authority_nullifiers','anchors'):
            need(type(t[k]) is list and len(t[k])<=32 and len(set(t[k]))==len(t[k]),'bounded distinct owner history keys')
            for v in t[k]:field(v);need(v!=ZERO,'nonzero history key')
def genesis(t,*,chain_id,worker):
    validate_treasury(t);need(isinstance(worker,Native),'actual owner native worker required')
    g={'format':'1soft/owner-treasury-lab/genesis/v1','chain_id':chain_id,'profile_sha256':PROFILE_SHA256,'worker_sha256':worker.sha256,'kat_sha256':worker.kat_sha256,'treasury':copy.deepcopy(t)}
    validate_genesis(g);return g
def validate_genesis(g):
    need(type(g) is dict and set(g)=={'format','chain_id','profile_sha256','worker_sha256','kat_sha256','treasury'} and g['format']=='1soft/owner-treasury-lab/genesis/v1' and g['profile_sha256']==PROFILE_SHA256,'fresh closed owner lab genesis')
    need(type(g['chain_id']) is str and re.fullmatch('[a-zA-Z0-9_-]{1,50}',g['chain_id']) is not None,'owner lab chain identity')
    for k in ('worker_sha256','kat_sha256'):hexbytes(g[k],32);need(g[k]!=ZERO,'owner lab worker pins')
    validate_treasury(g['treasury'])
def pins(g,w):validate_genesis(g);need(isinstance(w,Native) and w.sha256==g['worker_sha256'] and w.kat_sha256==g['kat_sha256'],'owner genesis/worker pins differ')
def initial_state(g,w):
    pins(g,w);t=copy.deepcopy(g['treasury']);t.update(fees=0,nullifiers=[],authority_nullifiers=[],anchors=[w.note_root(t['notes'])]);return {'version':1,'treasury':t,'receipts':[],'blocks':[]}
def result(code,data=''):return {'code':code,'log':LOGS[code],'data':data}
def _owner_check(g,t,b,height,w):
    need(all(b[k]==g[k] for k in ('profile_sha256','chain_id')) and b['genesis_sha256']==digest(canonical(g)) and b['owner_key']==t['owner_key'] and b['owner_epoch']==t['owner_epoch'],'owner command domain/key differs')
    need(t['owner_sequence']<MAX_U64 and b['next_sequence']==t['owner_sequence']+1 and b['context_root']==w.context_root(t),'stale owner command sequence/context')
    need(b['height']==height,'owner command height differs')
    slot=next((i for i,v in enumerate(t['grants']) if v['id']==b['grant_id']),None);need(slot is not None,'owner grant ID')
    old=t['grants'][slot];need(b['generation']==old['generation'] and b['old_commitment']==old['commitment'],'owner grant generation/old commitment differs')
    if b['kind']=='revoke':need(old['generation']>0 and old['commitment']!=ZERO and b['new_generation']==old['generation'] and b['new_commitment']==ZERO and b['new_agent_key']==old['agent_key'],'owner revoke semantics')
    else:
        need(old['generation']<MAX_U64 and b['new_generation']==old['generation']+1 and b['new_commitment']!=ZERO and b['new_agent_key']!=ZERO,'owner activation semantics')
        need((b['kind']=='enroll' and old['generation']==0 and old['commitment']==ZERO) or (b['kind']=='rotate' and old['generation']>0),'owner enroll/rotate lifecycle differs')
    return slot
def command(g,s,*,kind,grant_id,height,new_commitment,new_agent_key,key,worker):
    pins(g,worker);t=s['treasury'];validate_treasury(t,runtime=True)
    need(isinstance(key,Ed25519PrivateKey) and key.public_key().public_bytes_raw().hex()==t['owner_key'],'owner signing key differs')
    old=next((v for v in t['grants'] if v['id']==grant_id),None);need(old is not None,'stable owner grant ID')
    b={'format':'1soft/owner-treasury-command/v1','profile_sha256':g['profile_sha256'],'genesis_sha256':digest(canonical(g)),'chain_id':g['chain_id'],'owner_key':t['owner_key'],'owner_epoch':t['owner_epoch'],
       'next_sequence':number(t['owner_sequence']+1),'context_root':worker.context_root(t),'kind':kind,'grant_id':grant_id,'generation':old['generation'],'old_commitment':old['commitment'],'height':height,
       'new_generation':old['generation'] if kind=='revoke' else number(old['generation']+1),'new_commitment':new_commitment,'new_agent_key':new_agent_key}
    raw=COMMAND_MAGIC+canonical({'body':b,'signature':key.sign(COMMAND_DOMAIN+canonical(b)).hex()});packet(raw);_owner_check(g,t,b,height,worker);return raw
def _owner(g,s,raw,height,index,w):
    try:v=packet(raw)
    except (ValueError,TypeError,KeyError):return result(1)
    b=v['body'];t=s['treasury']
    try:slot=_owner_check(g,t,b,height,w)
    except Unavailable:raise
    except ValueError:return result(2)
    try:Ed25519PublicKey.from_public_bytes(hexbytes(t['owner_key'],32)).verify(hexbytes(v['signature'],64),COMMAND_DOMAIN+canonical(b))
    except InvalidSignature:return result(8)
    if len(s['receipts'])>=32:return result(7)
    before=w.context_root(t);old=t['grants'][slot];old['generation']=b['new_generation'];old['commitment']=b['new_commitment']
    old['agent_key']=b['new_agent_key']
    t['owner_sequence']=b['next_sequence'];ident=txid(raw)
    s['receipts'].append({'kind':'owner','txid':ident,'raw':raw.hex(),'raw_sha256':digest(raw),'body':copy.deepcopy(b),'height':height,'tx_index':index,'authority_root_before':before,'authority_root_after':w.context_root(t)})
    return result(0,ident)
def _payment(g,s,raw,h,index,w):
    try:p=parse(raw)
    except ValueError:return result(1)
    t=s['treasury'];ident=txid(raw)
    if not integer(p[15])<=h<integer(p[16]):return result(3)
    if any(p[i]!=t[k] for i,k in [(1,'genesis'),(2,'asset'),(3,'mission'),(5,'parent_id'),(7,'parent')]) or integer(p[14])!=t['epoch'] or integer(p[17])!=t['fee'] or integer(p[25])!=t['owner_sequence'] or p[27]!=w.owner_key(t['owner_key']) or integer(p[28])!=t['owner_epoch'] or p[4]!=w.context_root(t):return result(2)
    slot=next((i for i,v in enumerate(t['grants']) if v['id']==p[6] and v['generation']==integer(p[26]) and v['commitment']==p[8] and v['commitment']!=ZERO and v['agent_key']==p[29]),None)
    if slot is None:return result(2)
    if p[20] not in t['anchors']:return result(4)
    if p[21] in t['nullifiers'] or p[11]==p[12] or any(p[i] in t['authority_nullifiers'] for i in (11,12)) or any(r['txid']==ident or (r['kind']=='payment' and r['statement'][18]==p[18]) for r in s['receipts']) or any(p[i] in t['notes'] for i in (22,23)):return result(5)
    if len(t['notes'])+2>16 or len(s['receipts'])>=32 or t['fees']+t['fee']>MAX_U64:return result(7)
    if not w.verify(raw):return result(6)
    before=w.context_root(t);anchor=t['anchors'][-1];position=len(t['notes']);t['parent']=p[9];t['grants'][slot]['commitment']=p[10]
    t['notes'].extend(p[22:24]);t['nullifiers'].append(p[21]);t['authority_nullifiers'].extend(p[11:13]);t['fees']+=t['fee'];after=w.note_root(t['notes']);t['anchors'].append(after)
    s['receipts'].append({'kind':'payment','txid':ident,'raw':raw.hex(),'raw_sha256':digest(raw),'statement':p,'height':h,'tx_index':index,'fee':t['fee'],'note_root_before':anchor,'note_root_after':after,'authority_root_before':before,'authority_root_after':w.context_root(t),'merchant_position':position,'change_position':position+1})
    return result(0,ident)
def _execute(g,state,txs,height,w):
    need(type(state) is dict and set(state)=={'version','treasury','receipts','blocks'} and state['version']==1 and type(state['blocks']) is list,'owner state shape')
    need(type(height) is int and height==len(state['blocks'])+1 and 1<=height<=MAX_HEIGHT,'owner sequential height')
    need(type(txs) is list and len(txs)<=2 and all(type(r) is bytes and len(r)<=8192 for r in txs),'owner block bounds')
    need(sum(len(b['transactions']) for b in state['blocks'])+len(txs)<=MAX_HISTORY,'owner history capacity')
    s=copy.deepcopy(state);validate_treasury(s['treasury'],runtime=True)
    results=[(_owner(g,s,r,height,i,w) if r[:8]==COMMAND_MAGIC else _payment(g,s,r,height,i,w)) for i,r in enumerate(txs)]
    s['blocks'].append({'height':height,'transactions':[r.hex() for r in txs],'results':results});need(len(canonical(s))<=MAX_BYTES,'owner state byte capacity');return s,results
def execute_block(g,state,txs,height,w):
    pins(g,w);replay(g,state,len(state['blocks']),w);return _execute(g,state,txs,height,w)
def replay(g,state,height,w):
    pins(g,w);need(type(state) is dict and set(state)=={'version','treasury','receipts','blocks'} and type(state['blocks']) is list and type(height) is int and 0<=height<=MAX_HEIGHT and len(state['blocks'])==height,'owner replay shape')
    actual=initial_state(g,w)
    for h,b in enumerate(state['blocks'],1):
        need(type(b) is dict and set(b)=={'height','transactions','results'} and b['height']==h and type(b['transactions']) is list and len(b['transactions'])<=2,'owner history block shape')
        txs=[]
        for v in b['transactions']:
            need(type(v) is str and len(v)<=16384 and re.fullmatch('[0-9a-f]*',v) is not None and len(v)%2==0,'canonical owner history wire');txs.append(bytes.fromhex(v))
        actual,_=_execute(g,actual,txs,h,w)
    need(canonical(actual)==canonical(state),'owner replayed state/receipts differ');return actual
def application_hash(g,height,state):
    need(type(height) is int and 0<=height<=MAX_HEIGHT and len(canonical(state))<=MAX_BYTES,'owner hash bound')
    return digest(b'1soft/owner-treasury-lab/apphash/v1\0'+canonical({'genesis_sha256':digest(canonical(g)),'height':height,'state':state}))
