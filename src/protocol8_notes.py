"""Measured private P8 construction. Destination is a public key commitment."""
from __future__ import annotations
import hashlib, os, signal, stat, subprocess, sys, tempfile, time
from pathlib import Path
import protocol8_transfer as n
from protocol8_consensus import bootstrap_digest, genesis_document

REQUEST_BYTES=1160
OPENING_KEYS={'origin','value','expiry','note_secret','blind'}
def num(v):return n.u64(v).to_bytes(32,'little').hex()
def opening(o):
    n.need(type(o) is dict and set(o)==OPENING_KEYS,'P8 closed private opening')
    for key in ('origin','note_secret','blind'):
        n.field(o[key]);n.need(o[key]!=n.ZERO,'P8 nonzero opening')
    for key in ('value','expiry'):n.need(n.u64(o[key])>0,'P8 positive opening integer')
    return o
def statement(request,g):
    n.need(type(request) is bytes and len(request)==REQUEST_BYTES,'P8 exact private request')
    prefix=(b'1SRCP008'+bytes.fromhex(n.PROFILE_SHA256)+bytes.fromhex(n.PROFILE['parameter_sha256'])+
            bytes.fromhex(n.PROFILE['verifying_key_sha256'])+bytes.fromhex(bootstrap_digest(g)))
    n.need(request[:136]==prefix,'P8 private request pins')
    fs=[request[i:i+32].hex() for i in range(136,1160,32)]
    for v in fs:n.field(v)
    p,w=fs[:13],fs[13:]
    for i in (2,3,6,12,13,16):n.integer(w[i])
    n.need(n.integer(w[6])<16,'P8 position bound')
    # Syntax only; the zero proof is never admitted or verified.
    n.parse(b'1SRCT008'+b''.join(n.field(v) for v in p)+bytes(3136))
    n.need(p[1:4]==[g['network'],g['asset'],g['mission']],'P8 request context')
    return p,w

class PrivateProcess:
    def __init__(self,binary,sha256):
        n.need(os.name=='posix','P8 private workers require trusted POSIX host')
        self.binary=Path(binary).absolute();self.sha256=sha256;self.runs=[]
        self.call_count=self.reaped_count=self.timeout_count=0
        n.need(type(sha256) is str and len(sha256)==64 and all(c in '0123456789abcdef' for c in sha256),'P8 private binary pin')
        fd=self._open();os.close(fd)
    def _open(self):
        fd=None
        try:
            fd=os.open(self.binary,os.O_RDONLY|os.O_NOFOLLOW);s=os.fstat(fd)
            n.need(stat.S_ISREG(s.st_mode) and s.st_uid==os.getuid() and not s.st_mode&0o022 and s.st_mode&0o100 and 0<s.st_size<=32*1024**2,'P8 unsafe private worker')
            with os.fdopen(os.dup(fd),'rb') as f:actual=hashlib.file_digest(f,'sha256').hexdigest()
            n.need(actual==self.sha256,'P8 private worker changed')
            return fd
        except Exception:
            if fd is not None:os.close(fd)
            raise n.Unavailable('P8 private worker cannot be opened') from None
    def call(self,op,raw,bound):
        n.need(op in ('key','inspect-note','construct','prove') and type(raw) is bytes and len(raw)<=1160,'P8 private operation bound')
        n.need(bound=={'key':32,'inspect-note':258,'construct':1192,'prove':3560}[op],'P8 private reply bound')
        fd=self._open();child=None;started=time.monotonic();ticks=None;timed_out=False
        try:
            with tempfile.TemporaryFile() as out,tempfile.TemporaryFile() as err:
                launcher=Path(__file__).resolve().parents[1]/'scripts/protocol8_private_exec.py'
                child=subprocess.Popen([sys.executable,'-I','-B',str(launcher),str(fd),op],stdin=subprocess.PIPE,
                    stdout=out,stderr=err,pass_fds=(fd,),env={},start_new_session=True)
                ticks=Path('/proc/'+str(child.pid)+'/stat').read_text().rsplit(')',1)[1].split()[19]
                try:child.communicate(raw,timeout=320 if op=='prove' else 35)
                except subprocess.TimeoutExpired:timed_out=True;raise n.Unavailable('P8 private worker deadline') from None
                finally:
                    try:os.killpg(child.pid,signal.SIGKILL)
                    except ProcessLookupError:pass
                    child.communicate();out.seek(0);err.seek(0)
                    reply=out.read(bound+1);diagnostic=err.read(257)
                    self.call_count+=1;self.reaped_count+=int(child.poll() is not None);self.timeout_count+=int(timed_out)
                    self.runs.append({'operation':op,'pid':child.pid,'start_ticks':ticks,'exit_code':child.returncode,
                        'binary_sha256':self.sha256,'input_bytes':len(raw),'output_bytes':len(reply),
                        'process_reaped':child.poll() is not None,'timed_out':timed_out,'elapsed_seconds':round(time.monotonic()-started,6)})
                    if len(self.runs)>512:self.runs.pop(0)
                if child.returncode or diagnostic or len(reply)!=bound:raise n.Unavailable('P8 private worker failed or malformed output')
                return reply
        except OSError:raise n.Unavailable('P8 private worker launch failed') from None
        finally:
            if child is not None and child.poll() is None:
                try:os.killpg(child.pid,signal.SIGKILL)
                except ProcessLookupError:pass
                child.communicate()
            os.close(fd)
    def audit(self):
        return {'call_count':self.call_count,'reaped_count':self.reaped_count,'timeout_count':self.timeout_count,
                'retained_count':len(self.runs),'retention_limit':512,'calls':list(self.runs)}

class NoteController(PrivateProcess):
    def __init__(self,binary,sha256,*,expected_genesis,worker):
        super().__init__(binary,sha256);self.g=genesis_document(expected_genesis,worker);self.worker=worker
    def key(self,secret):
        n.field(secret);n.need(secret!=n.ZERO,'P8 nonzero recipient secret')
        out=self.call('key',n.field(secret),32).hex();n.field(out);n.need(out!=n.ZERO,'P8 nonzero recipient key');return out
    def base(self,o,secret,notes):
        opening(o);n.field(secret);n.need(secret!=n.ZERO,'P8 nonzero recipient secret')
        root=self.worker.root(notes)
        raw=bytes.fromhex(bootstrap_digest(self.g))+b''.join(n.field(v) for v in
            (self.g['asset'],self.g['mission'],o['origin'],num(o['value']),num(o['expiry']),o['note_secret'],o['blind'],secret))
        return raw+bytes([len(notes)])+b''.join(n.field(v) for v in notes),root
    def inspect(self,o,secret,notes):
        raw,root=self.base(o,secret,notes);out=self.call('inspect-note',raw,258)
        fs=[out[i:i+32].hex() for i in range(0,128,32)];path=[out[i:i+32].hex() for i in range(130,258,32)]
        for v in fs+path:n.field(v)
        position=int.from_bytes(out[128:130],'little')
        n.need(position<len(notes) and fs[0]==notes[position] and fs[1]==self.key(secret) and fs[3]==root,'P8 native note/path mismatch')
        return dict(commitment=fs[0],recipient_key=fs[1],nullifier=fs[2],root=fs[3],position=position,path=path)
    def construct(self,o,secret,notes,*,request,valid_from,valid_until,fee,destination,payment,payment_expiry,payment_secret,payment_blind,change_secret,change_blind):
        projection=self.inspect(o,secret,notes);base,_=self.base(o,secret,notes)
        vs=[request,num(valid_from),num(valid_until),num(fee),destination,num(payment),num(payment_expiry),payment_secret,payment_blind,change_secret,change_blind]
        for v in vs:n.field(v);n.need(v!=n.ZERO,'P8 nonzero preparation field')
        out=self.call('construct',base+b''.join(n.field(v) for v in vs),1192)
        req,origin=out[:1160],out[1160:].hex();p,w=statement(req,self.g);n.field(origin);n.need(origin!=n.ZERO,'P8 nonzero successor origin')
        expected=[secret,o['origin'],num(o['value']),num(o['expiry']),o['note_secret'],o['blind'],num(projection['position']),*projection['path'],destination,num(payment),num(payment_expiry),payment_secret,payment_blind,num(o['value']-payment-fee),change_secret,change_blind]
        n.need(w==expected and p[4:10]==[projection['root'],projection['nullifier'],request,num(valid_from),num(valid_until),num(fee)],'P8 constructed request differs from intent')
        return req,origin
