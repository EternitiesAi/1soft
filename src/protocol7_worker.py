"""Pinned verifier-only subprocess. Resource bounded; trusted host, no seccomp claim."""
from __future__ import annotations
from collections import OrderedDict
import hashlib, os, signal, stat, subprocess, sys, tempfile
from pathlib import Path
from protocol7_treasury import field,parse,hexbytes,validate_treasury,RUNTIME_KEYS,numfield,PROFILE,PROFILE_SHA256,Unavailable

class Worker:
    def __init__(self,binary,sha256,kat):
        self.binary=Path(binary).absolute();hexbytes(sha256,32);self.sha256=sha256
        self.kat_sha256=hashlib.sha256(kat).hexdigest();self.cache=OrderedDict()
        self.kat_statement=parse(kat)
        if not self.verify(kat):raise Unavailable('P7 verifier known-answer proof refused')
        bad=bytearray(kat);bad[-1]^=1
        if self.verify(bytes(bad)):raise Unavailable('P7 verifier corrupt known-answer proof accepted')
        import json
        try:ids=json.loads(self.call('identities',b''))
        except (ValueError,TypeError) as exc:raise Unavailable('P7 malformed profile identity') from exc
        if type(ids) is not dict or set(ids)!={'parameter_sha256','verifying_key_sha256'} or any(ids[k]!=PROFILE[k] for k in ids):raise Unavailable('P7 profile identity differs')
        self.startup={'binary_sha256':self.sha256,'kat_sha256':self.kat_sha256,'profile_sha256':PROFILE_SHA256,**ids,'valid_proof_verified':True,'corrupt_proof_refused':True,'verifier_only':True}
    def _open(self):
        try:
            fd=os.open(self.binary,os.O_RDONLY|os.O_NOFOLLOW)
            mode=os.fstat(fd)
            if not stat.S_ISREG(mode.st_mode) or mode.st_uid!=os.getuid() or mode.st_mode&0o022 or not mode.st_mode&0o100 or mode.st_size>16*1024*1024:
                raise Unavailable('unsafe P7 bridge executable')
            with os.fdopen(os.dup(fd),'rb') as f:observed=hashlib.file_digest(f,'sha256').hexdigest()
            if observed!=self.sha256:raise Unavailable('P7 bridge binary identity differs')
            return fd
        except BaseException as exc:
            if 'fd' in locals():os.close(fd)
            if isinstance(exc,Unavailable):raise
            raise Unavailable('P7 bridge cannot be opened') from exc
    def call(self,op,raw):
        if op not in ('verify','context-root','note-root','owner-key','network-domain','identities') or type(raw) is not bytes or len(raw)>8192:raise ValueError('P7 bridge request bound')
        fd=self._open()
        try:
            launcher=Path(__file__).resolve().parents[1]/'scripts/protocol7_worker_exec.py'
            with tempfile.TemporaryFile() as out,tempfile.TemporaryFile() as err:
                try:
                    p=subprocess.Popen([sys.executable,'-I','-B',str(launcher),str(fd),op],stdin=subprocess.PIPE,stdout=out,stderr=err,
                        pass_fds=(fd,),env={},start_new_session=True)
                    try:p.communicate(raw,timeout=45)
                    except subprocess.TimeoutExpired:
                        try:os.killpg(p.pid,signal.SIGKILL)
                        except ProcessLookupError:pass
                        finally:p.communicate()
                        raise Unavailable('P7 bridge wall deadline') from None
                    out.seek(0);err.seek(0);reply=out.read(257);error=err.read(257)
                    if p.returncode or error or len(reply)>256:raise Unavailable('P7 bridge failed or malformed diagnostics')
                    return reply
                except OSError as exc:raise Unavailable('P7 bridge launcher failure') from exc
        finally:os.close(fd)
    def verify(self,raw):
        parse(raw)
        # Even cached proofs require the exact measured executable to remain available.
        fd=self._open();os.close(fd)
        if raw in self.cache:return True
        reply=self.call('verify',raw)
        if reply==b'INVALID\n':return False
        if reply!=b'OK\n':raise Unavailable('P7 verifier response differs')
        self.cache[raw]=True
        if len(self.cache)>8:self.cache.popitem(last=False)
        return True
    def field_call(self,op,raw):
        reply=self.call(op,raw)
        try:
            if len(reply)!=32:raise ValueError('field response bound')
            field(reply.hex())
        except ValueError as exc:raise Unavailable('P7 malformed native field response') from exc
        return reply.hex()
    def owner_key(self,key):return self.field_call('owner-key',hexbytes(key,32))
    def network_domain(self,digest):
        if type(digest) is not bytes or len(digest)!=32:raise ValueError('P7 bootstrap digest bound')
        return self.field_call('network-domain',digest)
    def context_root(self,t):
        validate_treasury(t,runtime=RUNTIME_KEYS<=set(t))
        f=[t[k] for k in ('genesis','asset','mission','parent_id')]+[numfield(t['epoch']),numfield(t['owner_epoch']),numfield(t['owner_sequence']),self.owner_key(t['owner_key']),t['parent'],numfield(t['fee'])]
        for g in t['grants']:f.extend([g['id'],numfield(g['generation']),g['commitment'],g['agent_key']])
        return self.field_call('context-root',b''.join(field(v) for v in f))
    def note_root(self,notes):
        if type(notes) is not list or len(notes)>16:raise ValueError('P7 note root bound')
        return self.field_call('note-root',b''.join(field(v) for v in notes))
