"""Measured private P7 note derivation; supplies openings, never authority."""
from __future__ import annotations
import hashlib,os,signal,stat,subprocess,sys,threading
from pathlib import Path
from protocol7_treasury import PROFILE,PROFILE_SHA256,ZERO,Unavailable,bootstrap_digest,field,genesis_document,hexbytes,integer,numfield
from protocol7_prover import MAGIC,WITNESS_U64

def request_bytes(public,witness,g):
    if type(public) not in (list,tuple) or len(public)!=30 or type(witness) not in (list,tuple) or len(witness)!=31:
        raise ValueError('P7 note input count')
    for value in (*public,*witness):field(value)
    for i in WITNESS_U64:integer(witness[i])
    if integer(witness[15])>=16:raise ValueError('P7 note position')
    return (MAGIC+hexbytes(PROFILE_SHA256,32)+hexbytes(PROFILE['parameter_sha256'],32)
            +hexbytes(PROFILE['verifying_key_sha256'],32)+hexbytes(bootstrap_digest(g),32)
            +b''.join(field(v) for v in (*public,*witness)))

class NoteController:
    def __init__(self,binary,sha256,*,expected_genesis,worker):
        if os.name!='posix':raise ValueError('P7 notes require trusted POSIX host')
        self.binary=Path(binary).absolute();self.sha256=sha256;hexbytes(sha256,32)
        self.raw_genesis=expected_genesis;self.g=genesis_document(expected_genesis,worker);self.worker=worker
        self.runs=[];fd=self._open();os.close(fd)
    def _open(self):
        fd=None
        try:
            fd=os.open(self.binary,os.O_RDONLY|os.O_NOFOLLOW);s=os.fstat(fd)
            if not stat.S_ISREG(s.st_mode) or s.st_uid!=os.getuid() or s.st_mode&0o022 or not s.st_mode&0o100 or not 0<s.st_size<=16*1024*1024:
                raise Unavailable('unsafe P7 note controller')
            with os.fdopen(os.dup(fd),'rb') as f:observed=hashlib.file_digest(f,'sha256').hexdigest()
            if observed!=self.sha256:raise Unavailable('P7 note controller identity differs')
            return fd
        except BaseException as exc:
            if fd is not None:os.close(fd)
            if not isinstance(exc,Exception):raise
            raise Unavailable('P7 note controller cannot be opened') from None
    def call(self,op,raw):
        if op not in ('derive','construct','merchant') or type(raw) is not bytes or len(raw)>2602:
            raise ValueError('P7 note controller input bound')
        bound={'derive':256,'construct':2088,'merchant':32}[op];fd=self._open();child=None;threads=[];replies={}
        def read(name,stream,limit):
            try:replies[name]=stream.read(limit+1)
            except Exception:replies[name]=None
        try:
            launcher=Path(__file__).resolve().parents[1]/'scripts/protocol7_note_exec.py'
            child=subprocess.Popen([sys.executable,'-I','-B',str(launcher),str(fd),op],
                stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=subprocess.PIPE,
                pass_fds=(fd,),env={},start_new_session=True)
            ticks=int(Path('/proc/'+str(child.pid)+'/stat').read_text().rsplit(')',1)[1].split()[19])
            for name,stream,limit in (('out',child.stdout,bound),('err',child.stderr,256)):
                t=threading.Thread(target=read,args=(name,stream,limit),daemon=True);t.start();threads.append(t)
            child.stdin.write(raw);child.stdin.close()
            try:child.wait(timeout=30)
            except subprocess.TimeoutExpired:raise Unavailable('P7 note controller wall deadline') from None
            for t in threads:t.join(timeout=1)
            if any(t.is_alive() for t in threads) or child.returncode or replies.get('err')!=b'' or type(replies.get('out')) is not bytes or len(replies['out'])!=bound:
                raise Unavailable('P7 note controller failed or malformed output')
            self.runs.append({'operation':op,'pid':child.pid,'start_ticks':ticks,'exit_code':child.returncode,
                              'binary_sha256':self.sha256,'request_bytes':len(raw),'response_bytes':bound})
            if len(self.runs)>128:self.runs.pop(0)
            return replies['out']
        except OSError:raise Unavailable('P7 note controller launch failed') from None
        finally:
            if child is not None:
                # A failed child may have exited while a descendant kept a pipe
                # open. Stop the owned session before closing reader streams.
                try:os.killpg(child.pid,signal.SIGKILL)
                except ProcessLookupError:pass
                child.wait()
                for t in threads:t.join(timeout=1)
                for stream in (child.stdin,child.stdout,child.stderr):
                    if stream is not None and not stream.closed:stream.close()
                for t in threads:t.join(timeout=1)
            os.close(fd)
    def derive(self,public,opening,notes,position):
        if type(opening) is not dict or set(opening)!={'agent_secret','value','expiry','note_secret','blind'}:
            raise ValueError('P7 closed change opening required')
        if type(notes) is not list or not 1<=len(notes)<=16 or type(position) is not int or not 0<=position<len(notes):
            raise ValueError('P7 authenticated note position')
        w=[ZERO]*31
        for i,key in ((11,'agent_secret'),(18,'note_secret'),(19,'blind')):
            field(opening[key])
            if opening[key]==ZERO:raise ValueError('P7 nonzero private opening required')
            w[i]=opening[key]
        w[15]=numfield(position);w[16]=numfield(opening['value']);w[17]=numfield(opening['expiry'])
        raw=self.call('derive',request_bytes(public,w,self.g)+len(notes).to_bytes(2,'little')+b''.join(field(v) for v in notes))
        result=[raw[i*32:(i+1)*32].hex() for i in range(8)]
        for value in result:field(value)
        if result[0]!=notes[position] or result[1]!=public[29] or result[3]!=self.worker.note_root(notes):
            raise Unavailable('P7 derived note/path differs')
        return {'commitment':result[0],'agent_key':result[1],'nullifier':result[2],'root':result[3],'path':result[4:]}
    def construct(self,public,witness):
        raw=self.call('construct',request_bytes(public,witness,self.g))
        if raw[:136]!=request_bytes(public,witness,self.g)[:136]:raise Unavailable('P7 constructed request identity differs')
        p=[raw[136+i*32:168+i*32].hex() for i in range(30)]
        w=[raw[1096+i*32:1128+i*32].hex() for i in range(31)]
        from protocol7_prover import canonical_inputs
        p,w=canonical_inputs(p,w)
        if tuple(witness)!=w or any(p[i]!=public[i] for i in (0,1,2,3,4,5,6,7,8,14,15,16,17,18,20,25,26,27,28,29)):
            raise Unavailable('P7 constructed request differs from intent')
        return p,w

    def merchant_commitment(self,public,opening):
        """Native domain604 projection; explicit disclosure, not execution authority."""
        from protocol7_treasury import integer,parse,PAYMENT_MAGIC
        if type(public) not in (list,tuple) or len(public)!=30:
            raise ValueError('P7 exact merchant public statement required')
        # The envelope parser checks canonical public integers and interval. The
        # zero proof suffix here is syntax only, never passed to a verifier.
        p=parse(PAYMENT_MAGIC+b''.join(field(v) for v in public)+bytes(3200))
        if type(opening) is not dict or set(opening)!={'recipient','payment','payment_blind','payment_expiry','payment_note_secret'}:
            raise ValueError('P7 closed merchant opening required')
        w=[ZERO]*31
        for slot,key in ((12,'recipient'),(14,'payment_blind'),(30,'payment_note_secret')):
            field(opening[key])
            if opening[key]==ZERO:raise ValueError('P7 nonzero merchant opening required')
            w[slot]=opening[key]
        w[13]=numfield(opening['payment']);w[29]=numfield(opening['payment_expiry'])
        if opening['payment']==0 or opening['payment_expiry']<integer(p[16]):
            raise ValueError('P7 merchant amount/expiry refused')
        full=request_bytes(p,w,self.g)
        raw=full[:1096]+b''.join(field(w[i]) for i in (12,13,14,29,30))
        commitment=self.call('merchant',raw).hex();field(commitment)
        return commitment
