#!/usr/bin/env python3
"""Disposable test application: observe final snapshot install, SIGKILL, recover.

Only the acceptance runner starts this entry point. The ordinary node entry point
has no crash option. No native source, wire message, signature or authority changes.
The killed process leaves its socket; its parent may remove only the recorded inode
AFTER wait() establishes this child's termination. No arbitrary reset/delete API.
"""
from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import signal
import stat
import sys
import uuid

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'src'))
from abci_server import Server
from block_application import BlockApplication
from commit_verifier import encode, load_json

PHASES = ('crash', 'recovery')


def private_path(path):
    p = Path(os.path.abspath(path))
    for ancestor in (p.parent, *p.parent.parents):
        if ancestor.is_symlink():
            raise ValueError('test observation ancestor is aliased')
    info = p.parent.stat()
    if not stat.S_ISDIR(info.st_mode) or info.st_uid != os.geteuid() or info.st_mode & 0o077:
        raise ValueError('private owned test directory required')
    return p


def write_once(path, value):
    p = private_path(path)
    raw = encode(value) + b'\n'
    if len(raw) > 8192:
        raise ValueError('test observation exceeds limit')
    temp = p.with_name('.install-observation-' + uuid.uuid4().hex)
    fd = os.open(temp, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    try:
        with os.fdopen(fd, 'wb') as stream:
            stream.write(raw); stream.flush(); os.fsync(stream.fileno())
        # Link atomically publishes the complete new file and refuses overwrite.
        os.link(temp, p, follow_symlinks=False)
    finally:
        temp.unlink(missing_ok=True)
    fd = os.open(p.parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def read_observation(path):
    p = private_path(path)
    if not p.exists() and not p.is_symlink():
        return None
    fd = os.open(p, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(fd, 'rb') as stream:
        info = os.fstat(stream.fileno())
        if (not stat.S_ISREG(info.st_mode) or info.st_uid != os.geteuid() or
                info.st_nlink != 1 or info.st_mode & 0o077 or info.st_size > 8192):
            raise ValueError('unsafe test observation')
        raw = stream.read(8193)
    value = load_json(raw, max_bytes=8192)
    if type(value) is not dict:
        raise ValueError('invalid test observation')
    return value


def remove_crashed_socket(path, identity):
    """Caller must first reap its child. Only remove the exact captured socket."""
    p = private_path(path)
    info = p.lstat()
    if (type(identity) is not dict or set(identity) != {'device', 'inode'} or
            type(identity['device']) is not int or type(identity['inode']) is not int or
            not stat.S_ISSOCK(info.st_mode) or info.st_uid != os.geteuid() or
            (info.st_dev, info.st_ino) != (identity['device'], identity['inode'])):
        raise ValueError('crashed socket identity differs; no removal performed')
    p.unlink()


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--db', type=Path, required=True)
    parser.add_argument('--socket', type=Path, required=True)
    parser.add_argument('--genesis', type=Path, required=True)
    parser.add_argument('--phase', choices=PHASES, required=True)
    parser.add_argument('--observation', type=Path, required=True)
    parser.add_argument('--run-id', required=True)
    parser.add_argument('--block-history-keep', type=int)
    args = parser.parse_args(argv)
    if (os.name != 'posix' or len(args.run_id) != 32 or
            any(c not in '0123456789abcdef' for c in args.run_id)):
        raise ValueError('POSIX and an exact acceptance run ID are required')
    observation = private_path(args.observation)
    if observation.exists() or observation.is_symlink():
        raise ValueError('test observation must be new')
    # Keep instrumentation output separate from all database/socket/input paths.
    reserved = {Path(os.path.abspath(p)) for p in (args.db, args.socket, args.genesis)}
    reserved |= {Path(str(Path(os.path.abspath(args.db))) + suffix)
                 for suffix in ('-wal', '-shm', '-journal', '.lock')}
    if observation in reserved:
        raise ValueError('observation aliases an application path')
    genesis = json.loads(args.genesis.read_bytes())
    app = BlockApplication(args.db, expected_genesis=genesis,
                           block_history_keep=args.block_history_keep)
    original = app.state_sync._install
    server = None
    try:
        server = Server(str(args.socket), app)
        identity = {'device': args.socket.stat().st_dev, 'inode': server.owned_inode}

        def observed_install(payload, checked, *, checkpoint_recovery=False):
            original(payload, checked, checkpoint_recovery=checkpoint_recovery)
            # _install returned after the SQLite commit; Apply has not returned.
            row = app.db.execute('SELECT height,app_hash FROM committed WHERE id=1').fetchone()
            mark = app.db.execute('SELECT height,app_hash FROM state_sync_marker WHERE id=1').fetchone()
            count = app.db.execute('SELECT count(*) FROM blocks').fetchone()[0]
            if (app.db.in_transaction or row != mark or
                    row != (payload['height'], payload['app_hash']) or count != 0):
                raise RuntimeError('install boundary does not describe one snapshot checkpoint')
            if (args.phase == 'crash' and checkpoint_recovery) or (args.phase == 'recovery' and not checkpoint_recovery):
                raise RuntimeError('unexpected install path at prebound crash/recovery gate')
            write_once(observation, {
                'schema': 1, 'run_id': args.run_id, 'pid': os.getpid(),
                'phase': 'after-durable-install-before-apply-return',
                'mode': args.phase, 'height': row[0], 'app_hash': row[1],
                'checkpoint_recovery': checkpoint_recovery, 'block_rows': count,
                'socket': identity,
            })
            if args.phase == 'crash':
                os.kill(os.getpid(), signal.SIGKILL)
                raise RuntimeError('SIGKILL unexpectedly returned')

        app.state_sync._install = observed_install
        def stop(*_):
            raise KeyboardInterrupt
        signal.signal(signal.SIGTERM, stop); signal.signal(signal.SIGINT, stop)
        print(json.dumps({'status': 'ready', 'phase': args.phase, 'run_id': args.run_id}), flush=True)
        try:
            server.serve_forever(poll_interval=.05)
        except KeyboardInterrupt:
            pass
        return 2 if server.failed.is_set() else 0
    finally:
        if server is not None:
            server.server_close()
        app.close()


if __name__ == '__main__':
    raise SystemExit(main())
