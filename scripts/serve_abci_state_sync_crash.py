#!/usr/bin/env python3
"""TEST ONLY: interrupt this disposable application's final snapshot Apply.

The child runs the unchanged native app. Its install wrapper pauses after the
SQLite commit, before Apply can reply. This supervisor kills that exact child,
records the observed exit/checkpoint, and requires explicit local resumption.
Do not use this executable as a production application or validator service.
"""
from __future__ import annotations
import argparse
import json
import os
from pathlib import Path
import signal
import sqlite3
import stat
import subprocess
import sys
import time

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT/'src'))
from abci_server import Server
from block_application import BlockApplication
from commit_verifier import load_json


def need(ok, message):
    if not ok: raise ValueError(message)


def directory(path):
    p = Path(os.path.abspath(path))
    for parent in (p, *p.parents):
        need(not parent.is_symlink(), 'symlinked control directory refused')
    m = p.stat()
    need(stat.S_ISDIR(m.st_mode) and m.st_uid == os.getuid() and not stat.S_IMODE(m.st_mode)&0o077,
         'private owned control directory required')
    return p


def write_event(root, name, data):
    root = directory(root)
    raw = json.dumps(data, sort_keys=True, separators=(',', ':'), allow_nan=False).encode()+b'\n'
    need(len(raw) <= 4096, 'event too large')
    fd = os.open(root/name, os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, 'wb') as f:
        f.write(raw); f.flush(); os.fsync(f.fileno())
    fd = os.open(root, os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
    try: os.fsync(fd)
    finally: os.close(fd)


def read_event(root, name):
    root = directory(root); p = root/name
    try:
        fd = os.open(p, os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK)
    except FileNotFoundError: return None
    with os.fdopen(fd, 'rb') as f:
        m = os.fstat(f.fileno())
        need(stat.S_ISREG(m.st_mode) and m.st_uid == os.getuid() and m.st_nlink == 1
             and not stat.S_IMODE(m.st_mode)&0o077 and m.st_size <= 4096, 'unsafe event file')
        raw = f.read(4097)
    need(len(raw) <= 4096, 'event too large')
    # A read racing an incomplete write must not count as a completed observation.
    if not raw.endswith(b'\n'): return None
    data = load_json(raw, max_bytes=4096)
    need(type(data) is dict, 'event must be object')
    return data


def checkpoint(path):
    with sqlite3.connect(Path(path).absolute().as_uri()+'?mode=ro', uri=True) as db:
        row = db.execute('SELECT height,app_hash FROM committed WHERE id=1').fetchone()
        mark = db.execute('SELECT height,app_hash FROM state_sync_marker WHERE id=1').fetchone()
        count = db.execute('SELECT count(*) FROM blocks').fetchone()[0]
    need(row is not None and row == mark and count == 0, 'snapshot-only checkpoint not intact')
    return {'height':row[0], 'app_hash':row[1], 'local_block_rows':count}


def remove_exact_socket(path, identity):
    p = Path(path); m = p.lstat()
    need(stat.S_ISSOCK(m.st_mode) and m.st_uid == os.getuid() and
         (m.st_dev,m.st_ino)==(identity['device'],identity['inode']), 'crashed socket identity differs')
    p.unlink()


def _child(a):
    control = directory(a.control_dir)
    app = BlockApplication(a.db, expected_genesis=json.loads(Path(a.genesis).read_bytes()),
                           block_history_keep=a.block_history_keep)
    original = app.state_sync._install
    def install(payload, checked, *, checkpoint_recovery=False):
        original(payload, checked, checkpoint_recovery=checkpoint_recovery)
        event = {'schema':1, 'run_id':a.run_id, 'pid':os.getpid(),
                 'height':app.height,'app_hash':app.app_hash,
                 'checkpoint_recovery':checkpoint_recovery, 'transaction_active':app.db.in_transaction}
        if a.child_phase == 'pause':
            write_event(control, 'installed.json', event)
            # Supervisor sends SIGKILL; this call never returns a final Apply reply.
            while True: time.sleep(.05)
        need(checkpoint_recovery is True, 'recovery child was not recovering installed checkpoint')
        write_event(control, 'recovered.json', event)
    app.state_sync._install = install
    server = None
    def stopping(*_): raise KeyboardInterrupt
    signal.signal(signal.SIGTERM, stopping); signal.signal(signal.SIGINT, stopping)
    try:
        server = Server(a.socket, app)
        m = Path(a.socket).lstat()
        write_event(control, a.child_phase+'-ready.json', {'schema':1,'run_id':a.run_id,
                    'pid':os.getpid(),'device':m.st_dev,'inode':m.st_ino})
        try: server.serve_forever(poll_interval=.05)
        except KeyboardInterrupt: pass
        return 2 if server.failed.is_set() else 0
    finally:
        if server: server.server_close()
        app.close()


def supervise(a):
    control = directory(a.control_dir)
    need(not list(control.iterdir()), 'control directory must be empty')
    stopped = [False]; child = None
    def stop(*_): stopped[0] = True
    signal.signal(signal.SIGTERM, stop); signal.signal(signal.SIGINT, stop)
    def spawn(phase):
        cmd = [sys.executable,str(Path(__file__).resolve()),'--child-phase',phase,
               '--db',a.db,'--socket',a.socket,'--genesis',a.genesis,
               '--control-dir',str(control),'--run-id',a.run_id,'--wait-seconds',str(a.wait_seconds)]
        # The recovery launch intentionally omits retention: reuse the saved policy.
        if phase == 'pause' and a.block_history_keep is not None:
            cmd += ['--block-history-keep',str(a.block_history_keep)]
        return subprocess.Popen(cmd)
    def wait_event(name):
        deadline = time.monotonic()+a.wait_seconds
        while not stopped[0] and time.monotonic()<deadline:
            value = read_event(control,name)
            if value is not None:
                need(value.get('run_id') == a.run_id, 'event belongs to another run')
                return value
            need(child.poll() is None, 'application exited before required event')
            time.sleep(.02)
        raise TimeoutError('required event unavailable or interrupted')
    try:
        child = spawn('pause')
        ready = wait_event('pause-ready.json')
        installed = wait_event('installed.json')
        need(ready['pid'] == installed['pid'] == child.pid and child.poll() is None,
             'install observation belongs to a different child')
        need(installed.get('transaction_active') is False and installed.get('checkpoint_recovery') is False,
             'wrong initial install boundary')
        child.kill(); code = child.wait(timeout=5)
        need(code == -signal.SIGKILL, 'not a SIGKILL exit')
        snap = checkpoint(a.db)
        need((snap['height'],snap['app_hash'])==(installed['height'],installed['app_hash']),
             'durable checkpoint differs from paused install')
        remove_exact_socket(a.socket,ready)
        write_event(control,'killed.json', {'schema':1,'run_id':a.run_id,'pid':child.pid,
                    'signal':'SIGKILL','returncode':code,'install':installed,'checkpoint':snap})
        # No child exists while paused for the runner to stop/restart the engine.
        deadline=time.monotonic()+a.wait_seconds
        while not stopped[0] and time.monotonic()<deadline:
            resume=read_event(control,'resume.json')
            if resume is not None:
                need(resume == {'schema':1,'run_id':a.run_id,'resume':True}, 'invalid resume event')
                break
            time.sleep(.02)
        else: raise TimeoutError('explicit resumption was not supplied')
        child = spawn('recovery')
        while not stopped[0]:
            code=child.poll()
            if code is not None: return code
            time.sleep(.05)
        return 0
    finally:
        if child is not None and child.poll() is None:
            child.terminate()
            try: child.wait(timeout=3)
            except subprocess.TimeoutExpired: child.kill(); child.wait(timeout=3)


def main():
    p=argparse.ArgumentParser(description=__doc__)
    for name in ('db','socket','genesis','control-dir','run-id'):p.add_argument('--'+name,required=True)
    p.add_argument('--block-history-keep',type=int,default=None)
    p.add_argument('--wait-seconds',type=int,default=100)
    p.add_argument('--child-phase',choices=('pause','recovery'),help=argparse.SUPPRESS)
    a=p.parse_args()
    need(os.name=='posix' and 2<=a.wait_seconds<=180,'POSIX and bounded wait required')
    need(len(a.run_id)==32 and all(c in '0123456789abcdef' for c in a.run_id),'invalid run ID')
    try: return _child(a) if a.child_phase else supervise(a)
    except (OSError,ValueError,TimeoutError):
        print('Snapshot crash acceptance interrupted or refused; no recovery pass inferred.',file=sys.stderr)
        return 2

if __name__=='__main__':raise SystemExit(main())
