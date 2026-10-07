"""Measured P8 verifier-only subprocess with bounded positive-proof caching.

Resource limits and an inode pin support one trusted POSIX host. No seccomp,
hostile-host isolation, custody or private proving claim is made.
"""
from __future__ import annotations
from collections import OrderedDict, deque
import hashlib
import json
import os
import signal
import stat
import subprocess
import sys
import tempfile
import time
from pathlib import Path
import protocol8_transfer as native

def _closed_object(pairs):
    if len(pairs) != len(dict(pairs)):
        raise ValueError('duplicate native response field')
    return dict(pairs)

class Worker:
    def __init__(self, binary, expected_sha256, kat, *, startup_mode='batch'):
        self.binary = Path(binary).absolute()
        native.need(type(expected_sha256) is str and len(expected_sha256) == 64 and
                    all(c in '0123456789abcdef' for c in expected_sha256), 'P8 binary digest')
        self.sha256 = expected_sha256
        self.identity = {'sha256': expected_sha256, 'bytes': self.binary.stat().st_size}
        self.kat_sha256 = hashlib.sha256(kat).hexdigest()
        self.kat_statement = native.parse(kat)
        self.cache = OrderedDict()
        self.calls = deque(maxlen=512)
        self.call_count = self.reaped_count = self.timeout_count = 0
        native.need(startup_mode in ('batch', 'legacy'), 'P8 explicit startup mode')
        # Legacy is an explicit development comparison, never an automatic
        # fallback when a pinned binary refuses the new startup operation.
        if startup_mode == 'legacy':
            if not self.verify(kat, self.kat_statement[1]):
                raise native.Unavailable('P8 known-answer proof refused')
            bad = bytearray(kat); bad[-1] ^= 1
            if self.verify(bytes(bad), self.kat_statement[1]):
                raise native.Unavailable('P8 corrupt known-answer proof accepted')
        try:
            if startup_mode == 'legacy':
                ids = json.loads(self.call('identities', b''), object_pairs_hook=_closed_object)
            else:
                value = json.loads(self.call('startup', native.field(self.kat_statement[1]) + kat), object_pairs_hook=_closed_object)
                native.need(type(value) is dict and set(value) == {'valid', 'corrupt',
                    'parameter_sha256', 'verifying_key_sha256'}, 'P8 closed startup response')
                native.need(value['valid'] is True and value['corrupt'] is False,
                    'P8 startup known-answer checks refused')
                ids = {k: value[k] for k in ('parameter_sha256', 'verifying_key_sha256')}
        except (ValueError, TypeError) as e:
            raise native.Unavailable('P8 malformed profile identity') from e
        expected = {k: native.PROFILE[k] for k in ('parameter_sha256', 'verifying_key_sha256')}
        if type(ids) is not dict or ids != expected:
            raise native.Unavailable('P8 native profile identity differs')
        if startup_mode == 'batch':
            self.cache[kat] = True
            self.calls[-1]['startup_checks'] = {'valid_proof_verified': True,
                'corrupt_proof_refused': True, **ids}
        self.startup = {'binary_sha256': expected_sha256, 'kat_sha256': self.kat_sha256,
                        'profile_sha256': native.PROFILE_SHA256, **ids,
                        'valid_proof_verified': True, 'corrupt_proof_refused': True,
                        'verifier_only': True}

    def _open(self):
        fd = None
        try:
            fd = os.open(self.binary, os.O_RDONLY | os.O_NOFOLLOW)
            mode = os.fstat(fd)
            if (not stat.S_ISREG(mode.st_mode) or mode.st_uid != os.getuid() or
                    mode.st_mode & 0o022 or not mode.st_mode & 0o100 or
                    not 0 < mode.st_size <= 16 * 1024**2):
                raise native.Unavailable('P8 unsafe bridge inode')
            with os.fdopen(os.dup(fd), 'rb') as f:
                observed = hashlib.file_digest(f, 'sha256').hexdigest()
            if observed != self.sha256:
                raise native.Unavailable('P8 bridge binary identity differs')
            return fd
        except BaseException as e:
            if fd is not None: os.close(fd)
            if isinstance(e, native.Unavailable): raise
            raise native.Unavailable('P8 bridge cannot be opened') from e

    def guard(self):
        fd = self._open(); os.close(fd)

    def call(self, op, raw):
        native.need(op in ('verify', 'note-root', 'network-domain', 'identities', 'startup') and
                    type(raw) is bytes and len(raw) <= 4096, 'P8 bounded bridge request')
        fd = self._open()
        process = None
        ticks = None
        started = time.monotonic()
        timed_out = False
        try:
            launcher = Path(__file__).resolve().parents[1] / 'scripts/protocol8_worker_exec.py'
            with tempfile.TemporaryFile() as out, tempfile.TemporaryFile() as err:
                process = subprocess.Popen([sys.executable, '-I', '-B', str(launcher), str(fd), op],
                    stdin=subprocess.PIPE, stdout=out, stderr=err, pass_fds=(fd,), env={},
                    start_new_session=True)
                try:
                    ticks = Path(f'/proc/{process.pid}/stat').read_text().rsplit(')', 1)[1].split()[19]
                    process.communicate(raw, timeout=45)
                except subprocess.TimeoutExpired:
                    timed_out = True
                    try: os.killpg(process.pid, signal.SIGKILL)
                    except ProcessLookupError: pass
                    process.communicate()
                    raise native.Unavailable('P8 bridge wall deadline') from None
                finally:
                    if process.poll() is None:
                        os.killpg(process.pid, signal.SIGKILL); process.communicate()
                    out.seek(0); err.seek(0)
                    reply, error = out.read(257), err.read(257)
                    self.call_count += 1
                    self.reaped_count += int(process.poll() is not None)
                    self.timeout_count += int(timed_out)
                    self.calls.append({'operation': op, 'pid': process.pid, 'start_ticks': ticks,
                        'binary_sha256': self.sha256, 'exit_code': process.returncode,
                        'input_bytes': len(raw), 'output_bytes': len(reply),
                        'timed_out': timed_out, 'process_reaped': process.poll() is not None,
                        'elapsed_seconds': round(time.monotonic() - started, 6)})
                if process.returncode or error or len(reply) > 256:
                    raise native.Unavailable('P8 bridge failed or diagnostics differ')
                return reply
        except OSError as e:
            raise native.Unavailable('P8 bridge launcher failure') from e
        finally:
            os.close(fd)

    def audit(self):
        return {'call_count': self.call_count, 'reaped_count': self.reaped_count,
                'timeout_count': self.timeout_count, 'retained_count': len(self.calls),
                'retention_limit': 512, 'calls': list(self.calls)}

    def verify(self, raw, network):
        p = native.parse(raw)
        native.field(network)
        self.guard()  # Cached success never hides a missing or changed executable.
        if network != p[1]: return False
        if raw in self.cache:
            self.cache.move_to_end(raw)
            return True
        reply = self.call('verify', native.field(network) + raw)
        if reply == b'INVALID\n': return False
        if reply != b'OK\n': raise native.Unavailable('P8 closed verification response')
        self.cache[raw] = True
        if len(self.cache) > 16: self.cache.popitem(last=False)
        return True

    def field_call(self, op, raw):
        reply = self.call(op, raw)
        if len(reply) != 32: raise native.Unavailable('P8 native field response bound')
        native.field(reply.hex())
        return reply.hex()

    def network_domain(self, bootstrap):
        native.need(type(bootstrap) is bytes and len(bootstrap) == 32, 'P8 bootstrap digest')
        return self.field_call('network-domain', bootstrap)

    def root(self, notes):
        native.need(type(notes) is list and 1 <= len(notes) <= 16, 'P8 bounded notes')
        for n in notes: native.field(n); native.need(n != native.ZERO, 'P8 nonzero note')
        native.need(len(set(notes)) == len(notes), 'P8 duplicate note')
        return self.field_call('note-root', b''.join(native.field(n) for n in notes))
