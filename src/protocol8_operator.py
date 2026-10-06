"""Protected P8 recovery application workspace on one trusted Linux host.

No engine provisioning, signing, wallet, network trust selection or repair.
Doctor reads configuration/inodes only. Audit explicitly opens the existing
store and runs native replay; SQLite may update its local WAL bookkeeping.
"""
from __future__ import annotations
from contextlib import contextmanager
import fcntl
import hashlib
import os
from pathlib import Path
import re
import signal
import stat
import threading

from protocol8_consensus import canonical, closed_json, genesis_shape, genesis_document, StateError
from protocol8_worker import Worker
from protocol8_recovery import RecoveryApplication
from protocol8_recovery_abci import Request, Response, dispatch
from abci_server import Server

ROOT = Path(__file__).resolve().parents[1]
FORMAT = '1soft/protocol8-recovery-operator/v1'
ENGINE_SHA256 = '218628da07bed5d27e178d38d0bef9ecf46f21b214c8e9fea402fd215fccc024'
ENGINE_VERSION = '0.38.25'
FILES = {'operator.json', 'genesis.json', 'kat.tx', 'operator.lock',
         'state.sqlite', 'state.sqlite.lock', 'state.sqlite-wal', 'state.sqlite-shm', 'a.sock'}
REQUIRED = {'operator.json', 'genesis.json', 'kat.tx', 'operator.lock'}
MAX_CONFIG = 32768

class OperatorError(ValueError):
    pass

def require(ok, message):
    if not ok:
        raise OperatorError(message)

def absolute(path):
    p = Path(path)
    require(p.is_absolute() and '..' not in p.parts and '.' not in p.parts,
            'absolute normalized Linux paths required')
    return p

def parents(path):
    require(os.name == 'posix' and Path('/proc/self/fd').is_dir(), 'Linux/WSL required')
    p = absolute(path)
    for parent in reversed(p.parents):
        s = parent.lstat()
        require(stat.S_ISDIR(s.st_mode) and s.st_uid in (0, os.getuid()), 'unsafe path ancestor')
        # A sticky system temp directory is allowed above an owner-only workspace.
        require(not s.st_mode & 0o022 or (s.st_uid == 0 and s.st_mode & stat.S_ISVTX),
                'writable path ancestor')
    return p

def directory(path, *, private=False):
    p = parents(path)
    s = p.lstat()
    require(stat.S_ISDIR(s.st_mode) and s.st_uid == os.getuid() and
            not s.st_mode & 0o022, 'owned directory required')
    if private:
        require(stat.S_IMODE(s.st_mode) == 0o700, 'workspace mode must be 0700')
    return p

def read_file(path, bound, *, private=False, executable=False):
    p = parents(path)
    fd = os.open(p, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    try:
        s = os.fstat(fd)
        require(stat.S_ISREG(s.st_mode) and s.st_uid == os.getuid() and
                s.st_nlink == 1 and not s.st_mode & 0o022 and 0 <= s.st_size <= bound,
                'unsafe, linked or oversized file')
        if private:
            require(stat.S_IMODE(s.st_mode) == 0o600, 'workspace file mode must be 0600')
        if executable:
            require(s.st_mode & stat.S_IXUSR and s.st_size > 0, 'owned executable required')
        with os.fdopen(os.dup(fd), 'rb') as stream:
            raw = stream.read(bound + 1)
        require(len(raw) == s.st_size and len(raw) <= bound, 'file changed or exceeds bound')
        return raw
    finally:
        os.close(fd)

def sha(raw):
    return hashlib.sha256(raw).hexdigest()

def pin(value):
    require(type(value) is str and re.fullmatch('[0-9a-f]{64}', value) is not None,
            'external genesis SHA256 required')
    return value

def runtime_files():
    paths = sorted([*ROOT.glob('src/*.py'), ROOT/'scripts/protocol8_worker_exec.py',
                    ROOT/'scripts/protocol8_operator.py'])
    return {str(p.relative_to(ROOT)): sha(read_file(p, 1024*1024)) for p in paths}

def inputs(genesis, genesis_sha256, kat, worker, engine):
    expected = pin(genesis_sha256)
    raw = read_file(genesis, 16384)
    require(sha(raw) == expected, 'external genesis pin differs')
    g = genesis_shape(raw)
    k = read_file(kat, 3560)
    require(len(k) == 3560 and sha(k) == g['kat_sha256'], 'KAT pin differs')
    w = absolute(worker); e = absolute(engine)
    require(sha(read_file(w, 16*1024**2, executable=True)) == g['worker_sha256'], 'worker pin differs')
    require(sha(read_file(e, 64*1024**2, executable=True)) == ENGINE_SHA256, 'pinned engine differs')
    return raw, k, {'format': FORMAT, 'genesis_sha256': expected,
        'profile_sha256': g['profile_sha256'], 'worker_sha256': g['worker_sha256'],
        'kat_sha256': g['kat_sha256'], 'worker': str(w), 'engine': str(e),
        'engine_sha256': ENGINE_SHA256, 'engine_version': ENGINE_VERSION,
        'runtime_files': runtime_files()}

def write_new(path, raw):
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    try:
        with os.fdopen(os.dup(fd), 'wb') as stream:
            stream.write(raw); stream.flush(); os.fsync(stream.fileno())
    finally:
        os.close(fd)

def initialize(workspace, genesis, genesis_sha256, kat, worker, engine):
    target = parents(workspace)
    directory(target.parent)
    require(not target.exists() and not target.is_symlink(), 'init requires a new workspace')
    require(len(os.fsencode(target/'a.sock')) <= 107, 'Unix socket path too long')
    raw, k, config = inputs(genesis, genesis_sha256, kat, worker, engine)
    verifier = Worker(worker, config['worker_sha256'], k)
    genesis_document(raw, verifier)  # Actual proof/network validation before writing.
    target.mkdir(mode=0o700)
    # Interrupted creation is retained and refused; never repair or overwrite it.
    write_new(target/'genesis.json', raw)
    write_new(target/'kat.tx', k)
    write_new(target/'operator.lock', b'')
    write_new(target/'operator.json', canonical(config))
    fd = os.open(target, os.O_RDONLY | os.O_DIRECTORY)
    try: os.fsync(fd)
    finally: os.close(fd)
    return {'status': 'initialized', 'scope': 'private-application-workspace-only',
            'genesis_sha256': config['genesis_sha256'], 'database_created': False,
            'native_startup': verifier.startup, 'worker_audit': verifier.audit(),
            'engine_executed': False, 'consensus_verified': False}

@contextmanager
def locked(workspace):
    root = directory(workspace, private=True)
    read_file(root/'operator.lock', 0, private=True)
    fd = os.open(root/'operator.lock', os.O_RDONLY | os.O_NOFOLLOW)
    try:
        try: fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError: raise OperatorError('workspace busy; no duplicate owner') from None
        yield root
    finally:
        os.close(fd)

def load(root, genesis_sha256):
    names = {p.name for p in root.iterdir()}
    require(REQUIRED <= names <= FILES, 'incomplete or unknown workspace membership')
    for name in names:
        require(name != 'a.sock', 'existing socket refused; owner diagnosis required')
        bound = MAX_CONFIG if name == 'operator.json' else (16384 if name == 'genesis.json' else
                3560 if name == 'kat.tx' else 16*1024**2)
        read_file(root/name, bound, private=True)
    raw = read_file(root/'operator.json', MAX_CONFIG, private=True)
    config = closed_json(raw, MAX_CONFIG)
    require(type(config) is dict and set(config) == {'format','genesis_sha256','profile_sha256',
        'worker_sha256','kat_sha256','worker','engine','engine_sha256','engine_version','runtime_files'},
        'closed operator manifest required')
    g, k, actual = inputs(root/'genesis.json', genesis_sha256, root/'kat.tx',
                          config['worker'], config['engine'])
    require(config == actual, 'manifest/runtime pins differ; no automatic upgrade')
    require(len(os.fsencode(root/'a.sock')) <= 107, 'Unix socket path too long')
    return g, k, config

def doctor(workspace, genesis_sha256):
    with locked(workspace) as root:
        _, _, config = load(root, genesis_sha256)
        return {'status': 'configuration-valid', 'scope': 'read-only-inode-and-pin-inspection',
            'pins': {k:v for k,v in config.items() if k != 'runtime_files'},
            'runtime_file_count': len(config['runtime_files']),
            'database_present': (root/'state.sqlite').exists(), 'store_replay_verified': False,
            'native_executed': False, 'engine_executed': False, 'consensus_verified': False}

def audit(workspace, genesis_sha256):
    with locked(workspace) as root:
        raw, k, config = load(root, genesis_sha256)
        require((root/'state.sqlite').is_file(), 'audit requires an existing store')
        worker = Worker(config['worker'], config['worker_sha256'], k)
        with RecoveryApplication(root/'state.sqlite', worker, expected_genesis=raw) as app:
            marker = app.db.execute('SELECT height,app_hash,payload_sha256 FROM p8_snapshot_origin WHERE id=1').fetchone()
            heights = [r[0] for r in app.db.execute('SELECT height FROM p8_blocks ORDER BY height')]
            return {'status': 'local-store-replayed', 'height': app.height, 'app_hash': app.app_hash,
                'initialized': app.state is not None, 'origin_marker': marker,
                'real_response_heights': heights, 'worker_audit': worker.audit(),
                'consensus_verified': False, 'freshness_established': False,
                'effect': 'existing store opened; SQLite WAL bookkeeping may change'}

def serve(workspace, genesis_sha256, emit):
    with locked(workspace) as root:
        raw, k, config = load(root, genesis_sha256)
        worker = Worker(config['worker'], config['worker_sha256'], k)
        with RecoveryApplication(root/'state.sqlite', worker, expected_genesis=raw) as app:
            with Server(str(root/'a.sock'), app, request_type=Request, response_type=Response,
                        dispatcher=dispatch) as server:
                previous = {s: signal.getsignal(s) for s in (signal.SIGINT, signal.SIGTERM)}
                stopping = threading.Event()
                def stop(_signal, _frame):
                    if not stopping.is_set():
                        stopping.set(); server.closing.set()
                        threading.Thread(target=server.shutdown, daemon=True).start()
                try:
                    for s in previous: signal.signal(s, stop)
                    emit({'status': 'serving-private-application', 'pid': os.getpid(),
                        'genesis_sha256': config['genesis_sha256'], 'worker_sha256': config['worker_sha256'],
                        'runtime_sha256': sha(canonical(config['runtime_files'])),
                        'engine_started': False, 'consensus_verified': False})
                    server.serve_forever(poll_interval=0.1)
                finally:
                    for s, handler in previous.items(): signal.signal(s, handler)
            require(not server.failed.is_set(), 'application server failed closed')
            emit({'status': 'application-stopped', 'height': app.height, 'app_hash': app.app_hash,
                  'socket_removed': not (root/'a.sock').exists(), 'worker_audit': worker.audit(),
                  'engine_started': False, 'consensus_verified': False})
