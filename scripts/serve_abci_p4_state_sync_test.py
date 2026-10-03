#!/usr/bin/env python3
"""TEST ONLY: observe real P4 snapshots or kill final Apply after SQLite COMMIT.

This is a disposable loopback gate instrument, never a validator service.
The production application and dispatcher remain unchanged. Original P4 snapshot
ABCI packets and the durable composite checkpoint stay in the private control dir.
"""
from __future__ import annotations
import argparse
import base64
import hashlib
import os
from pathlib import Path
import signal
import sqlite3
import subprocess
import sys
import threading
import time

ROOT=Path(__file__).resolve().parents[1]
sys.path[:0]=[str(ROOT/'src'),str(ROOT/'scripts')]
from abci_server import Server
from commit_verifier import encode,load_json
from protocol4_application import Protocol4Application
from protocol4_abci_wire import Request,Response
from protocol4_abci_server import dispatch
from serve_abci_state_sync_crash import directory,write_event,read_event,remove_exact_socket,need

SNAPSHOT_METHODS={'list_snapshots','offer_snapshot','load_snapshot_chunk','apply_snapshot_chunk'}
MAX_TRACE_BYTES=64*1024*1024
MAX_TRACE_PACKETS=2048

def birth(pid):
    return Path('/proc').joinpath(str(pid),'stat').read_text().rsplit(')',1)[1].split()[19]

def write_private(path,raw):
    fd=os.open(path,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
    with os.fdopen(fd,'wb') as stream:
        stream.write(raw);stream.flush();os.fsync(stream.fileno())

def checkpoint(path,*,pid=None,checkpoint_recovery=False):
    with sqlite3.connect(Path(path).absolute().as_uri()+'?mode=ro',uri=True) as db:
        db.execute('BEGIN')
        committed=db.execute('SELECT genesis,height,app_hash,state FROM committed WHERE id=1').fetchone()
        marker=db.execute('SELECT height,app_hash FROM snapshot_marker WHERE id=1').fetchone()
        blocks=db.execute('SELECT count(*) FROM blocks').fetchone()[0]
        history=[{'height':h,'txs':load_json(t.encode())}
                 for h,t in db.execute('SELECT height,txs FROM history ORDER BY height')]
    need(committed is not None and marker==(committed[1],committed[2]) and blocks==0,
         'snapshot-only composite checkpoint not intact')
    genesis=load_json(committed[0].encode());state=load_json(committed[3].encode())
    with Protocol4Application(':memory:',expected_genesis=genesis) as app:
        app._audit_state(genesis,state,committed[1],committed[2])
        app._audit_history(genesis,state,committed[1],committed[2],history,strict_txs=True)
    db_identity=Path(path).stat()
    return {'database_device':db_identity.st_dev,'database_inode':db_identity.st_ino,'height':committed[1],'app_hash':committed[2],'genesis':genesis,'state':state,
            'history':history,'marker':{'height':marker[0],'app_hash':marker[1]},
            'block_rows':blocks,'transaction_active':False,'pid':pid,
            'checkpoint_recovery':checkpoint_recovery}

class Trace:
    def __init__(self,control):
        self.control=control;self.lock=threading.Lock()
        requests=list(control.glob('request-*.bin'))
        self.count=max([int(p.stem.split('-')[1]) for p in requests],default=0)
        self.bytes=sum(p.stat().st_size for p in control.glob('*-*.bin'))
    def save(self,kind,index,raw):
        with self.lock:
            need(self.bytes+len(raw)<=MAX_TRACE_BYTES,'snapshot wire trace exceeds private bound')
            write_private(self.control/(kind+'-'+str(index).zfill(5)+'.bin'),raw)
            self.bytes+=len(raw)
    def call(self,app,request):
        method=request.WhichOneof('value')
        if method not in SNAPSHOT_METHODS:return dispatch(app,request)
        with self.lock:
            self.count+=1;index=self.count
            need(index<=MAX_TRACE_PACKETS,'snapshot wire packet count exceeds bound')
        self.save('request',index,request.SerializeToString(deterministic=True))
        answer=dispatch(app,request)
        self.save('response',index,answer.SerializeToString(deterministic=True))
        return answer

def child(a):
    control=directory(a.control_dir);raw=Path(a.genesis).read_bytes()
    need(hashlib.sha256(raw).hexdigest()==a.genesis_sha256,'P4 genesis bytes differ from pin')
    app=Protocol4Application(a.database,expected_genesis=load_json(raw,max_bytes=131072))
    if a.child_phase=='recovery':
        reopened=checkpoint(a.database,pid=os.getpid())
        raw_checkpoint=encode(reopened)
        write_private(control/'restart-checkpoint.json',raw_checkpoint)
        write_event(control,'restart-audited.json',{'schema':1,'run_id':a.run_id,'pid':os.getpid(),
            'birth':birth(os.getpid()),'record_file':'restart-checkpoint.json',
            'record_sha256':hashlib.sha256(raw_checkpoint).hexdigest()})
    trace=Trace(control);original=app.state_sync._install
    def install(payload,checkpoint_recovery):
        original(payload,checkpoint_recovery)
        need(not app.db.in_transaction,'snapshot transaction not committed')
        record=checkpoint(a.database,pid=os.getpid(),checkpoint_recovery=checkpoint_recovery)
        socket_identity=Path(a.socket).stat()
        record.update(run_id=a.run_id,birth=birth(os.getpid()),
            socket_device=socket_identity.st_dev,socket_inode=socket_identity.st_ino)
        name='checkpoint-'+a.child_phase+'.json';record_raw=encode(record)
        write_private(control/name,record_raw)
        item={'schema':1,'run_id':a.run_id,'pid':os.getpid(),'birth':birth(os.getpid()),
              'height':app.height,'app_hash':app.app_hash,'transaction_active':False,
              'checkpoint_recovery':checkpoint_recovery,'record_file':name,
              'record_sha256':hashlib.sha256(record_raw).hexdigest()}
        event_name='recovered.json' if a.child_phase=='recovery' else 'installed.json'
        write_event(control,event_name,item)
        if a.child_phase=='pause':
            while True:time.sleep(.02)  # Supervisor SIGKILL; final Apply cannot reply.
        if a.child_phase=='recovery':need(checkpoint_recovery is True,'checkpoint reoffer missing')
    app.state_sync._install=install
    def stopping(*_):raise KeyboardInterrupt
    signal.signal(signal.SIGTERM,stopping);signal.signal(signal.SIGINT,stopping)
    server=None
    try:
        server=Server(a.socket,app,request_type=Request,response_type=Response,dispatcher=trace.call)
        m=Path(a.socket).lstat()
        write_event(control,a.child_phase+'-ready.json',{'schema':1,'run_id':a.run_id,
            'pid':os.getpid(),'birth':birth(os.getpid()),'device':m.st_dev,'inode':m.st_ino,
            'database':str(Path(a.database).absolute()),'socket':str(Path(a.socket).absolute())})
        print('P4 test observer ready; snapshot wires retained privately.',flush=True)
        try:server.serve_forever(poll_interval=.05)
        except KeyboardInterrupt:pass
        return 2 if server.failed.is_set() else 0
    finally:
        if server:server.server_close()
        app.close()

def supervise(a):
    control=directory(a.control_dir);need(not list(control.iterdir()),'control directory must be empty')
    stopped=[False];owned=None;owned_phase=None;owned_birth=None
    def stopping(*_):stopped[0]=True
    signal.signal(signal.SIGTERM,stopping);signal.signal(signal.SIGINT,stopping)
    def launch(phase):
        return subprocess.Popen([sys.executable,str(Path(__file__).resolve()),'--child-phase',phase,
            '--mode','final-apply-crash','--database',a.database,'--socket',a.socket,
            '--genesis',a.genesis,'--genesis-sha256',a.genesis_sha256,
            '--control-dir',str(control),'--run-id',a.run_id,'--wait-seconds',str(a.wait_seconds)])
    def wait(name):
        end=time.monotonic()+a.wait_seconds
        while not stopped[0] and time.monotonic()<end:
            item=read_event(control,name)
            if item:
                need(item.get('run_id')==a.run_id,'event run identity differs');return item
            need(owned.poll() is None,'owned application exited before boundary');time.sleep(.02)
        raise TimeoutError('P4 snapshot boundary missing or interrupted')
    try:
        owned=launch('pause');owned_phase='pause';owned_birth=birth(owned.pid);ready=wait('pause-ready.json');installed=wait('installed.json')
        need(installed['pid']==ready['pid']==owned.pid and
             installed['birth']==ready['birth']==birth(owned.pid) and
             installed['checkpoint_recovery'] is False and installed['transaction_active'] is False,
             'initial install child or boundary differs')
        owned.kill();code=owned.wait(timeout=5)
        need(code==-signal.SIGKILL,'final Apply child did not exit SIGKILL')
        saved=checkpoint(a.database,pid=owned.pid)
        need((saved['height'],saved['app_hash'])==(installed['height'],installed['app_hash']),
             'SIGKILL checkpoint differs')
        remove_exact_socket(a.socket,ready)
        write_event(control,'killed.json',{'schema':1,'run_id':a.run_id,'pid':owned.pid,
            'birth':ready['birth'],'returncode':code,'signal':'SIGKILL','install':installed,
            'height':saved['height'],'app_hash':saved['app_hash'],'stop_requested':True,
            'termination_signal':9,'rescue_used':False,'cleanup_error':None})
        end=time.monotonic()+a.wait_seconds
        while not stopped[0] and time.monotonic()<end:
            resume=read_event(control,'resume.json')
            if resume:
                need(resume=={'schema':1,'run_id':a.run_id,'resume':True},'resume event differs');break
            time.sleep(.02)
        else:raise TimeoutError('explicit P4 resumption missing')
        owned=launch('recovery');owned_phase='recovery';owned_birth=birth(owned.pid)
        while not stopped[0]:
            code=owned.poll()
            if code is not None:return code
            time.sleep(.05)
        return 0
    finally:
        stop_requested=False;rescue_used=False;cleanup_error=None;termination_signal=None
        try:
            if owned and owned.poll() is None:
                need(birth(owned.pid)==owned_birth,'child PID birth changed before cleanup')
                stop_requested=True;termination_signal=15;owned.terminate()
                try:owned.wait(timeout=3)
                except subprocess.TimeoutExpired:
                    rescue_used=True;owned.kill();owned.wait(timeout=3)
        except Exception as exc:
            cleanup_error=type(exc).__name__+': '+str(exc)
            raise
        finally:
            if owned and owned_phase=='recovery':
                write_event(control,'recovery-exit.json',{'schema':1,'run_id':a.run_id,
                    'pid':owned.pid,'birth':owned_birth,'returncode':owned.returncode,
                    'stop_requested':stop_requested,'termination_signal':termination_signal,
                    'rescue_used':rescue_used,'cleanup_error':cleanup_error})
        need(not rescue_used and cleanup_error is None and
             (owned_phase!='recovery' or (stop_requested and owned.returncode==0)),
             'supervised child unexpected exit or cleanup rescue')

def main():
    p=argparse.ArgumentParser(description=__doc__)
    for name in ('genesis','genesis-sha256','database','socket','control-dir','run-id'):
        p.add_argument('--'+name,required=True)
    p.add_argument('--mode',choices=('observe','final-apply-crash'),default='observe')
    p.add_argument('--wait-seconds',type=int,default=150)
    p.add_argument('--child-phase',choices=('normal','pause','recovery'),help=argparse.SUPPRESS)
    a=p.parse_args();os.umask(0o077)
    need(os.name=='posix' and 2<=a.wait_seconds<=180,'POSIX and bounded wait required')
    need(len(a.run_id)==32 and all(c in '0123456789abcdef' for c in a.run_id),'invalid run ID')
    try:
        if a.child_phase:return child(a)
        if a.mode=='final-apply-crash':return supervise(a)
        a.child_phase='normal';return child(a)
    except (OSError,ValueError,TimeoutError):
        print('P4 snapshot observation refused or interrupted; no pass inferred.',file=sys.stderr)
        return 2
if __name__=='__main__':raise SystemExit(main())
