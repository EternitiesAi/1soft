"""Measured, bounded POSIX development proving; no submission, signing or custody."""
from __future__ import annotations
import hashlib, os, signal, stat, subprocess, sys, tempfile
from pathlib import Path
from protocol7_treasury import (
    PROFILE, PROFILE_SHA256, PAYMENT_MAGIC, Unavailable, bootstrap_digest,
    field, genesis_document, hexbytes, integer, parse,
)

MAGIC = b'1SOPRV01'
PUBLIC_COUNT = 30
WITNESS_COUNT = 31
REQUEST_BYTES = 2088
TRANSACTION_BYTES = 4168
WALL_SECONDS = 320
WITNESS_U64 = (0, 1, 2, 5, 6, 7, 10, 13, 15, 16, 17, 24, 26, 29)

def canonical_inputs(public, witness):
    if type(public) not in (list, tuple) or len(public) != PUBLIC_COUNT:
        raise ValueError('P7 public input count')
    if type(witness) not in (list, tuple) or len(witness) != WITNESS_COUNT:
        raise ValueError('P7 private input count')
    p, w = tuple(public), tuple(witness)
    for value in (*p, *w):
        field(value)
    for i in WITNESS_U64:
        integer(w[i])
    if integer(w[15]) >= 16:
        raise ValueError('P7 private note position')
    # Structural statement checks only. A zero proof is never verified or admitted.
    parse(PAYMENT_MAGIC + b''.join(field(v) for v in p) + bytes(3200))
    return p, w

class Prover:
    """Separate request worker. Current spending authority is enforced by the journal."""
    def __init__(self, binary, sha256, *, expected_genesis, worker):
        if os.name != 'posix':
            raise ValueError('P7 proving requires trusted POSIX host')
        self.binary = Path(binary).absolute()
        self.sha256 = sha256
        hexbytes(sha256, 32)
        self.raw_genesis = expected_genesis
        self.g = genesis_document(expected_genesis, worker)
        self.worker = worker
        fd = self._open()
        os.close(fd)

    def _open(self):
        fd = None
        try:
            fd = os.open(self.binary, os.O_RDONLY | os.O_NOFOLLOW)
            s = os.fstat(fd)
            if (not stat.S_ISREG(s.st_mode) or s.st_uid != os.getuid()
                    or s.st_mode & 0o022 or not s.st_mode & 0o100
                    or not 0 < s.st_size <= 32 * 1024 * 1024):
                raise Unavailable('unsafe P7 prover executable')
            with os.fdopen(os.dup(fd), 'rb') as source:
                observed = hashlib.file_digest(source, 'sha256').hexdigest()
            if observed != self.sha256:
                raise Unavailable('P7 prover binary identity differs')
            return fd
        except BaseException as exc:
            if fd is not None:
                os.close(fd)
            if isinstance(exc, Unavailable):
                raise
            raise Unavailable('P7 prover cannot be opened') from None

    def produce(self, public, witness):
        p, w = canonical_inputs(public, witness)
        genesis_document(self.raw_genesis, self.worker)
        if p[1] != self.g['treasury']['genesis']:
            raise ValueError('P7 prover network domain differs')
        request = (MAGIC + hexbytes(PROFILE_SHA256, 32)
                   + hexbytes(PROFILE['parameter_sha256'], 32)
                   + hexbytes(PROFILE['verifying_key_sha256'], 32)
                   + hexbytes(bootstrap_digest(self.g), 32)
                   + b''.join(field(v) for v in (*p, *w)))
        assert len(request) == REQUEST_BYTES
        fd = self._open()
        child = None
        try:
            launcher = Path(__file__).resolve().parents[1] / 'scripts/protocol7_prover_exec.py'
            # Child limits bound these files; never retain or print private request bytes.
            with tempfile.TemporaryFile() as out, tempfile.TemporaryFile() as err:
                child = subprocess.Popen(
                    [sys.executable, '-I', '-B', str(launcher), str(fd)],
                    stdin=subprocess.PIPE, stdout=out, stderr=err,
                    pass_fds=(fd,), env={}, start_new_session=True)
                # Read while the child is blocked on input; refuse an unrecordable lifecycle.
                start_ticks = int(Path('/proc/'+str(child.pid)+'/stat').read_text().rsplit(')',1)[1].split()[19])
                try:
                    child.communicate(request, timeout=WALL_SECONDS)
                except subprocess.TimeoutExpired:
                    try:
                        os.killpg(child.pid, signal.SIGKILL)
                    except ProcessLookupError:
                        pass
                    finally:
                        child.communicate()
                    raise Unavailable('P7 prover wall deadline') from None
                out.seek(0)
                err.seek(0)
                raw, diagnostics = out.read(TRANSACTION_BYTES + 1), err.read(257)
                if child.returncode or diagnostics or len(raw) != TRANSACTION_BYTES:
                    raise Unavailable('P7 prover failed or malformed output')
        except OSError:
            raise Unavailable('P7 prover launcher failure') from None
        finally:
            if child is not None:
                if child.poll() is None:
                    try:os.killpg(child.pid,signal.SIGKILL)
                    except ProcessLookupError:pass
                child.wait()
            os.close(fd)
        if tuple(parse(raw)) != p or not self.worker.verify(raw):
            raise Unavailable('P7 prover returned a different statement or invalid proof')
        self.last_run = {'pid':child.pid,'start_ticks':start_ticks,'exit_code':child.returncode,
                         'binary_sha256':self.sha256,'request_bytes':REQUEST_BYTES,
                         'response_bytes':len(raw)}
        # Public prefix only. Do not create an offline guessing target for private openings.
        self.request_binding = {
            'profile_sha256':PROFILE_SHA256,
            'parameter_sha256':PROFILE['parameter_sha256'],
            'verifying_key_sha256':PROFILE['verifying_key_sha256'],
            'bootstrap_sha256':bootstrap_digest(self.g),
            'public_prefix_sha256':hashlib.sha256(request[:1096]).hexdigest(),
            'private_openings_retained':False,
        }
        return raw
