"""Real private P4 socket/process checks; no engine consensus claim."""
import hashlib
import json
import os
from pathlib import Path
import signal
import socket
import subprocess
import sys
import tempfile
import time
import unittest

from abci_wire import read_frame, write_frame
from commit_verifier import encode
from native_core import NativeLedger,address,public,canonical,sign
from protocol4_application import Protocol4Application
from protocol4_fixture import fixture
from protocol4_abci_wire import Request,Response
from protocol4_abci_server import dispatch
from serve_abci_state_sync_crash import read_event,write_event

ROOT=Path(__file__).resolve().parents[1]

class Client:
    def __init__(self,path):self.path=path
    def __enter__(self):
        self.sock=socket.socket(socket.AF_UNIX);self.sock.settimeout(5);self.sock.connect(str(self.path))
        self.stream=self.sock.makefile('rwb',buffering=0);return self
    def __exit__(self,*args):self.stream.close();self.sock.close()
    def call(self,request):
        write_frame(self.stream,request);raw=read_frame(self.stream)
        if raw is None:raise ConnectionError('peer closed')
        return Response.FromString(raw)

def event(control,name,process):
    end=time.monotonic()+5
    while time.monotonic()<end:
        row=read_event(control,name)
        if row:return row
        if process.poll() is not None:raise AssertionError('P4 wrapper exited before '+name)
        time.sleep(.02)
    raise AssertionError('missing P4 boundary '+name)

class Protocol4StateSyncWrapperTests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory();self.root=Path(self.tmp.name);self.root.chmod(0o700)
        self.g,self.payers,_,_,_=fixture()
        self.source=Protocol4Application(':memory:',expected_genesis=self.g)
        self.source.init_chain(self.g['chain_id'],self.g,self.g['validator_registry']['validators'])
        ledger=NativeLedger(':memory:',self.g)
        try:wire=canonical(sign(self.payers[0],ledger.body(address(public(self.payers[0])),0,
            {'type':'transfer','to':address(public(self.payers[1])),'units':7},valid_until=20)))
        finally:ledger.close()
        for h in range(1,5):
            from validator_sets_core import ValidatorSet
            votes=[] if h==1 else [{'address':v.address.hex(),'power':v.power,'block_id_flag':2}
                for v in ValidatorSet.parse(self.g['validator_registry']['validators']).validators]
            self.source.finalize_block([wire] if h==1 else [],h,bytes([h])*32,
                bytes.fromhex(self.source.state['registry']['next_hash']),votes,b'wrapper-test:'+str(h).encode())
            self.source.commit()
        req=Request();req.list_snapshots.SetInParent()
        self.desc=dispatch(self.source,req).list_snapshots.snapshots[0]
        self.control=self.root/'control';self.control.mkdir(mode=0o700)
        self.gf=self.root/'genesis.json';self.gf.write_bytes(encode(self.g));self.gf.chmod(0o600)
        self.sock=self.root/'a.sock';self.db=self.root/'a.db';self.run_id=os.urandom(16).hex()
        self.process=None;self.log=None;self.engine_probe=None
    def tearDown(self):
        self.source.close()
        if self.process is not None and self.process.poll() is None:self.process.terminate()
        if self.process is not None:
            try:self.process.wait(timeout=3)
            except subprocess.TimeoutExpired:self.process.kill();self.process.wait(timeout=3)
        if self.engine_probe is not None:
            if self.engine_probe.poll() is None:self.engine_probe.terminate()
            self.engine_probe.wait(timeout=3)
        if self.log:self.log.close()
        self.tmp.cleanup()
    def start(self,mode):
        self.log=(self.root/'wrapper.log').open('wb')
        argv=[sys.executable,str(ROOT/'scripts/serve_abci_p4_state_sync_test.py'),
            '--genesis',str(self.gf),'--genesis-sha256',hashlib.sha256(self.gf.read_bytes()).hexdigest(),
            '--database',str(self.db),'--socket',str(self.sock),'--control-dir',str(self.control),
            '--run-id',self.run_id,'--mode',mode,'--wait-seconds','10']
        if self.engine_probe is not None:
            argv+=['--crash-engine-start-receipt',str(self.root/'engine-start.json')]
        self.process=subprocess.Popen(argv,stdout=self.log,stderr=self.log)
    def offer(self,client,desc=None,app_hash=None):
        req=Request();req.offer_snapshot.snapshot.CopyFrom(desc or self.desc)
        req.offer_snapshot.app_hash=app_hash or bytes.fromhex(self.source.app_hash)
        return client.call(req).offer_snapshot.result
    def apply(self,client):
        req=Request();req.apply_snapshot_chunk.index=0;req.apply_snapshot_chunk.sender='unit'
        req.apply_snapshot_chunk.chunk=self.source.load_snapshot_chunk(4,2,0)
        return client.call(req).apply_snapshot_chunk.result
    def test_observed_real_install_records_durable_composite_without_block_result(self):
        self.start('observe');event(self.control,'normal-ready.json',self.process)
        with Client(self.sock) as client:
            self.assertEqual(self.offer(client),1);self.assertEqual(self.apply(client),1)
            req=Request();req.query.path='/block/4';self.assertEqual(client.call(req).query.code,1)
        installed=event(self.control,'installed.json',self.process)
        record=json.loads((self.control/installed['record_file']).read_bytes())
        self.assertEqual(record['height'],4);self.assertEqual(record['state'],self.source.state)
        self.assertEqual(record['history'],self.source.history());self.assertEqual(record['block_rows'],0)
        self.assertFalse(record['transaction_active'])
        self.assertEqual(len(list(self.control.glob('request-*.bin'))),2)
        self.assertEqual(len(list(self.control.glob('response-*.bin'))),2)
    def test_actual_sigkill_then_same_checkpoint_reoffer_and_lower_height_refusal(self):
        from serve_abci_p4_state_sync_test import birth,write_private
        # A private ordinary Python process supplies only the real live-PID
        # observation boundary. This is not an engine or consensus substitute.
        self.engine_probe=subprocess.Popen([sys.executable,'-c','import time;time.sleep(20)'],
            stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
        engine_birth=birth(self.engine_probe.pid)
        write_private(self.root/'engine-start.json',encode({'name':'engine4','role':'engine',
            'pid':self.engine_probe.pid,'birth':engine_birth,'spawned_at_ns':time.time_ns()}))
        self.start('final-apply-crash');event(self.control,'pause-ready.json',self.process)
        with Client(self.sock) as client:
            self.assertEqual(self.offer(client),1)
            with self.assertRaises((ConnectionError,OSError)):self.apply(client)
        killed=event(self.control,'killed.json',self.process)
        self.assertEqual(killed['returncode'],-signal.SIGKILL)
        observed=killed['engine_before_kill']
        self.assertEqual((observed['pid'],observed['birth']),(self.engine_probe.pid,engine_birth))
        self.assertTrue(observed['alive'])
        self.assertLessEqual(observed['observed_at_ns'],killed['kill_requested_at_ns'])
        self.assertLessEqual(killed['kill_requested_at_ns'],killed['reaped_at_ns'])
        record=json.loads((self.control/killed['install']['record_file']).read_bytes())
        self.assertEqual(record['height'],4);self.assertEqual(record['state'],self.source.state)
        self.assertFalse(self.sock.exists())
        write_event(self.control,'resume.json',{'schema':1,'run_id':self.run_id,'resume':True})
        ready=event(self.control,'recovery-ready.json',self.process)
        self.assertNotEqual(ready['pid'],killed['pid'])
        with Client(self.sock) as client:
            # A valid earlier composite snapshot distinguishes rollback refusal
            # from malformed metadata rejection.
            import base64
            with Protocol4Application(':memory:',expected_genesis=self.g) as older:
                older.init_chain(self.g['chain_id'],self.g,self.g['validator_registry']['validators'])
                for row in self.source.history()[:3]:
                    state,result=older._execute([base64.b64decode(x) for x in row['txs']],row['height'])
                    older.state,older.height,older.app_hash=state,row['height'],result['app_hash']
                    older.db.execute('INSERT INTO history VALUES (?,?)',(row['height'],encode(row['txs']).decode()))
                req=Request();req.list_snapshots.SetInParent();lower=dispatch(older,req).list_snapshots.snapshots[0]
                self.assertEqual(json.loads(lower.metadata)['height'],lower.height)
                self.assertEqual(self.offer(client,lower,bytes.fromhex(older.app_hash)),3)
            self.assertEqual(self.offer(client),1);self.assertEqual(self.apply(client),1)
        recovered=event(self.control,'recovered.json',self.process)
        again=json.loads((self.control/recovered['record_file']).read_bytes())
        self.assertTrue(again['checkpoint_recovery'])
        self.assertEqual(again['state'],record['state']);self.assertEqual(again['history'],record['history'])


        self.process.terminate();self.process.wait(timeout=3)
        exit_event=read_event(self.control,'recovery-exit.json')
        self.assertIsNotNone(exit_event)
        self.assertEqual(exit_event['pid'],ready['pid'])
        self.assertEqual(exit_event['returncode'],0)
        self.assertTrue(exit_event['stop_requested'])
        self.assertEqual(exit_event['termination_signal'],15)
        self.assertFalse(exit_event['rescue_used'])
        self.assertIsNone(exit_event['cleanup_error'])

    def test_observe_wrapper_sigterm_reaps_zero_without_rescue(self):
        self.start('observe');event(self.control,'normal-ready.json',self.process)
        self.process.terminate();self.process.wait(timeout=3)
        self.assertEqual(self.process.returncode,0)


class Protocol4CrashEngineObservationTests(unittest.TestCase):
    def test_reaped_engine_pid_is_never_a_live_pre_kill_observation(self):
        from serve_abci_p4_state_sync_test import birth,write_private,observe_crash_engine
        with tempfile.TemporaryDirectory() as d:
            process=subprocess.Popen([sys.executable,'-c','import time;time.sleep(.1)'],
                stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
            row={'name':'engine4','role':'engine','pid':process.pid,'birth':birth(process.pid),
                 'spawned_at_ns':time.time_ns()}
            process.wait(timeout=3);path=Path(d)/'start.json';write_private(path,encode(row))
            with self.assertRaises((OSError,ValueError)):observe_crash_engine(path)
