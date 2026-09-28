#!/usr/bin/env python3
"""Test-only ABCI supervisor for the final state-sync Apply crash window.

The first child is SIGKILLed immediately after StateSyncManager._install commits
its durable checkpoint and before ApplySnapshotChunk can return. The supervisor
then waits for an explicit local resume marker and starts a second child that
records successful checkpoint-recovery installation before replying normally.
Never use this script as a validator application outside acceptance testing.
"""
from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import signal
import stat
import subprocess
import sys
import time

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'src'))
from abci_server import Server
from block_application import BlockApplication

KILL_SIGNAL = signal.SIGKILL
WAIT_SECONDS = 45


def _private_file(path: Path, *, must_exist=False):
    path = Path(os.path.abspath(path))
    parent = path.parent
    mode = parent.stat()
    if not stat.S_ISDIR(mode.st_mode) or mode.st_uid != os.getuid() or stat.S_IMODE(mode.st_mode) & 0o077:
        raise ValueError('status directory must be private and owned')
    if path.exists() or path.is_symlink():
        info = path.lstat()
        if not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid() or info.st_nlink != 1 or stat.S_IMODE(info.st_mode) & 0o077:
            raise ValueError('unsafe status file')
    elif must_exist:
        raise ValueError('resume marker missing')
    return path


def _write_new(path: Path, value: dict):
    path = _private_file(path)
    raw = (json.dumps(value, sort_keys=True, separators=(',', ':')) + '\n').encode()
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, 'wb') as f:
        f.write(raw); f.flush(); os.fsync(f.fileno())


def _unlink_owned_socket(path: Path):
    path = Path(path)
    info = path.lstat()
    if not stat.S_ISSOCK(info.st_mode) or info.st_uid != os.getuid():
        raise ValueError('crashed child did not leave its owned Unix socket')
    path.unlink()


def _child(args, phase):
    genesis = json.loads(Path(args.genesis).read_text())
    app = BlockApplication(args.db, expected_genesis=genesis,
                           block_history_keep=args.block_history_keep)
    original = app.state_sync._install
    def instrumented(payload, checked, *, checkpoint_recovery=False):
        original(payload, checked, checkpoint_recovery=checkpoint_recovery)
        if phase == 'crash':
            # SQLite FULL commit has returned and in-memory install completed;
            # no ApplySnapshotChunk response has been constructed yet.
            os.kill(os.getpid(), KILL_SIGNAL)
        if checkpoint_recovery:
            _write_new(Path(args.recovered), {
                'schema': 1, 'phase': 'checkpoint-recovery-install',
                'height': payload['height'], 'app_hash': payload['app_hash'],
                'checkpoint_recovery': True,
            })
    app.state_sync._install = instrumented
    server = None
    try:
        server = Server(args.socket, app)
        server.serve_forever(poll_interval=.05)
        return 2 if server.failed.is_set() else 0
    finally:
        if server is not None: server.server_close()
        app.close()


def _command(args, phase):
    command = [sys.executable, str(Path(__file__).resolve()), '--child-phase', phase,
               '--db', args.db, '--socket', args.socket, '--genesis', args.genesis,
               '--status', args.status, '--resume', args.resume, '--recovered', args.recovered]
    if args.block_history_keep is not None:
        command += ['--block-history-keep', str(args.block_history_keep)]
    return command


def _supervise(args):
    for p in (Path(args.status), Path(args.resume), Path(args.recovered)):
        _private_file(p)
        if p.exists(): raise ValueError('crash acceptance marker already exists')
    child = subprocess.Popen(_command(args, 'crash'))
    current = [child]
    def stop(*_):
        proc = current[0]
        if proc.poll() is None:
            proc.terminate()
    signal.signal(signal.SIGTERM, stop); signal.signal(signal.SIGINT, stop)
    code = child.wait()
    if code != -KILL_SIGNAL:
        return 71
    _unlink_owned_socket(Path(args.socket))
    _write_new(Path(args.status), {'schema': 1, 'phase': 'killed-after-durable-install',
                                    'signal': 'SIGKILL', 'exit_code': code})
    deadline = time.monotonic() + WAIT_SECONDS
    while time.monotonic() < deadline:
        if Path(args.resume).exists():
            _private_file(Path(args.resume), must_exist=True)
            break
        time.sleep(.05)
    else:
        return 72
    child = subprocess.Popen(_command(args, 'recovery'))
    current[0] = child
    return child.wait()


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--db', required=True); p.add_argument('--socket', required=True)
    p.add_argument('--genesis', required=True); p.add_argument('--status', required=True)
    p.add_argument('--resume', required=True); p.add_argument('--recovered', required=True)
    p.add_argument('--block-history-keep', type=int, default=None)
    p.add_argument('--child-phase', choices=('crash', 'recovery'), help=argparse.SUPPRESS)
    args = p.parse_args()
    return _child(args, args.child_phase) if args.child_phase else _supervise(args)

if __name__ == '__main__':
    raise SystemExit(main())
