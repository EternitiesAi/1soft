"""Pinned verifier-only subprocess. Resource bounded; trusted host, no seccomp claim."""
from __future__ import annotations
from collections import OrderedDict
import hashlib, os, signal, stat, subprocess, sys, tempfile
from pathlib import Path
from protocol6_treasury import field,parse

class Unavailable(RuntimeError):pass
class Worker:
    def __init__(self,binary,sha256,kat):
        self.binary=Path(binary).absolute();self.sha256=sha256
        self.kat_sha256=hashlib.sha256(kat).hexdigest();self.cache=OrderedDict()
        parse(kat)
        if not self.verify(kat):raise Unavailable('P6 verifier known-answer proof refused')
        bad=bytearray(kat);bad[-1]^=1
        if self.verify(bytes(bad)):raise Unavailable('P6 verifier corrupt known-answer proof accepted')
        self.startup={'binary_sha256':self.sha256,'kat_sha256':self.kat_sha256,'valid_proof_verified':True,'corrupt_proof_refused':True,
            'profile_sha256':'4e12c9a2eafd2d4f3e82106ba1128e1fc6301b24b871d30714eb0ca3b93115bd',
            'parameter_sha256':'1cb278fe4d9cf5325e5cbc710d863c0deca3e961e1b8f6c8736890c43345c461',
            'verifying_key_sha256':'1cc94283b32da0e1cbc055986ed2a375a33a899957a6421d5def8d7d056f5408'}
    def _open(self):
        try:
            fd=os.open(self.binary,os.O_RDONLY|os.O_NOFOLLOW)
            mode=os.fstat(fd)
            if not stat.S_ISREG(mode.st_mode) or mode.st_uid!=os.getuid() or mode.st_mode&0o022 or not mode.st_mode&0o100 or mode.st_size>16*1024*1024:
                raise Unavailable('unsafe P6 bridge executable')
            with os.fdopen(os.dup(fd),'rb') as f:observed=hashlib.file_digest(f,'sha256').hexdigest()
            if observed!=self.sha256:raise Unavailable('P6 bridge binary identity differs')
            return fd
        except BaseException as exc:
            if 'fd' in locals():os.close(fd)
            if isinstance(exc,Unavailable):raise
            raise Unavailable('P6 bridge cannot be opened') from exc
    def call(self,op,raw):
        if op not in ('verify','context-root','note-root') or type(raw) is not bytes or len(raw)>4096:raise ValueError('P6 bridge request bound')
        fd=self._open()
        try:
            launcher=Path(__file__).resolve().parents[1]/'scripts/protocol6_worker_exec.py'
            with tempfile.TemporaryFile() as out,tempfile.TemporaryFile() as err:
                try:
                    p=subprocess.Popen([sys.executable,'-I','-B',str(launcher),str(fd),op],stdin=subprocess.PIPE,stdout=out,stderr=err,
                        pass_fds=(fd,),env={},start_new_session=True)
                    try:p.communicate(raw,timeout=45)
                    except subprocess.TimeoutExpired:
                        try:os.killpg(p.pid,signal.SIGKILL)
                        except ProcessLookupError:pass
                        finally:p.communicate()
                        raise Unavailable('P6 bridge wall deadline') from None
                    out.seek(0);err.seek(0);reply=out.read(257);error=err.read(257)
                    if p.returncode or error or len(reply)>256:raise Unavailable('P6 bridge failed or malformed diagnostics')
                    return reply
                except OSError as exc:raise Unavailable('P6 bridge launcher failure') from exc
        finally:os.close(fd)
    def verify(self,raw):
        parse(raw)
        # Even cached proofs require the exact measured executable to remain available.
        fd=self._open();os.close(fd)
        if raw in self.cache:return True
        reply=self.call('verify',raw)
        if reply==b'INVALID\n':return False
        if reply!=b'OK\n':raise Unavailable('P6 verifier response differs')
        self.cache[raw]=True
        if len(self.cache)>8:self.cache.popitem(last=False)
        return True
    def context_root(self,t):
        names=('genesis','asset','mission','parent_id')
        f=[t[k] for k in names]+[t['epoch'].to_bytes(32,'little').hex(),t['parent']]
        for pair in t['grants']:f.extend(pair)
        reply=self.call('context-root',b''.join(field(v) for v in f))
        if len(reply)!=32:raise Unavailable('P6 context response differs')
        field(reply.hex());return reply.hex()
    def note_root(self,notes):
        if type(notes) is not list or len(notes)>16:raise ValueError('P6 note root bound')
        reply=self.call('note-root',b''.join(field(v) for v in notes))
        if len(reply)!=32:raise Unavailable('P6 tree response differs')
        field(reply.hex());return reply.hex()
