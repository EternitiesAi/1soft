"""Recovery harness regressions using disposable local processes and databases."""
import copy
import json
import os
from pathlib import Path
import sqlite3
import sys
import tempfile
import time
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from block_application import encode
from protocol4_abci_server import dispatch
from protocol4_abci_wire import Request, encode_finalization
from protocol4_application import Protocol4Application
from recovery_checks import checkpoint, verify_block_records
from recovery_fixture import model
from acceptance import validate, PROFILES
from test_acceptance import crash_report, bootstrap_report, SOURCE, ENGINE
import run_engine
import serve_probe


class StoredBlockTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):cls.c=model()
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory();self.path=Path(self.tmp.name)/'state.sqlite'
        g=self.c['genesis'];app=Protocol4Application(self.path,expected_genesis=g)
        app.init_chain(g['chain_id'],g,g['validator_registry']['validators'])
        for q in self.c['requests']:dispatch(app,Request.FromString(q));app.commit()
        app.close()
    def tearDown(self):self.tmp.cleanup()
    def test_missing_non_tip_block_is_rejected(self):
        with sqlite3.connect(self.path) as db:db.execute('DELETE FROM blocks WHERE height=3')
        with self.assertRaisesRegex(ValueError,'coverage'):checkpoint(self.path,self.c['genesis'])
    def test_non_tip_emission_matches_replay_even_when_response_encoding_matches(self):
        with sqlite3.connect(self.path) as db:
            result=json.loads(db.execute('SELECT result FROM blocks WHERE height=4').fetchone()[0])
            result['validator_updates']=[]
            db.execute('UPDATE blocks SET result=?,response=? WHERE height=4',
                       (encode(result).decode(),encode_finalization(result)))
        with self.assertRaisesRegex(ValueError,'independently replayed'):checkpoint(self.path,self.c['genesis'])
    def test_normal_node_cannot_claim_a_snapshot_origin_after_losing_first_block(self):
        with sqlite3.connect(self.path) as db:db.execute('DELETE FROM blocks WHERE height=1')
        saved=checkpoint(self.path,self.c['genesis'])
        with self.assertRaisesRegex(ValueError,'coverage'):verify_block_records(saved,self.c['genesis'],1)
    def test_full_stored_responses_bind_exactly_one_replayed_emission(self):
        saved=checkpoint(self.path,self.c['genesis'])
        self.assertEqual(verify_block_records(saved,self.c['genesis'],1),[4])
        self.assertEqual([r['height'] for r in saved['local_blocks']],list(range(1,11)))


class ReportIntegrityTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):cls.crash=crash_report();cls.boot=bootstrap_report()
    def test_claimed_emission_list_cannot_hide_a_missing_stored_response(self):
        r=copy.deepcopy(self.crash);r['evidence']['target_checkpoint']['local_blocks'].pop(2)
        r['evidence']['target_checkpoint']['local_block_count']-=1
        with self.assertRaisesRegex(ValueError,'coverage'):validate(r,source=SOURCE,engine_hash=ENGINE)
    def test_unavailability_must_be_specific_not_any_query_failure(self):
        r=copy.deepcopy(self.boot);r['evidence']['unavailable_block_responses'][0]['log']='unknown query path'
        with self.assertRaisesRegex(ValueError,'other than'):validate(r,source=SOURCE,engine_hash=ENGINE)
    def test_boolean_unavailability_code_is_refused(self):
        r=copy.deepcopy(self.boot);r['evidence']['unavailable_block_responses'][0]['code']=True
        with self.assertRaises(ValueError):validate(r,source=SOURCE,engine_hash=ENGINE)
    def test_unavailability_must_cover_each_snapshot_height(self):
        r=copy.deepcopy(self.boot);r['evidence']['unavailable_block_responses'].pop()
        with self.assertRaises(ValueError):validate(r,source=SOURCE,engine_hash=ENGINE)


class DriverIntegrityTests(unittest.TestCase):
    def test_non_integer_rpc_codes_cannot_be_success(self):
        for name in ('check_tx','tx_result'):
            for code in (False,True,'0',0.0,None):
                value={'check_tx':{'code':0},'tx_result':{'code':0},'height':'8'}
                value[name]['code']=code
                with self.subTest(name=name,code=code),patch.object(run_engine,'rpc',return_value=value):
                    with self.assertRaises(ValueError):run_engine.submit(1,b'fixture')
    def test_canonical_successful_rpc_response_is_accepted(self):
        with patch.object(run_engine,'rpc',return_value={'check_tx':{'code':0},'tx_result':{'code':0},'height':'8'}):
            self.assertEqual(run_engine.submit(1,b'fixture'),8)
    def test_rpc_height_cannot_be_bool_float_or_noncanonical(self):
        for height in (True,False,8,8.0,'08','8.0','-1','1000',''):
            with self.subTest(height=height),self.assertRaises(ValueError):run_engine.rpc_height(height)
    def test_dead_owned_engine_is_rejected_before_rpc(self):
        child=SimpleNamespace(p=SimpleNamespace(poll=lambda:2))
        with patch.object(run_engine,'rpc',side_effect=AssertionError('no RPC')):
            with self.assertRaisesRegex(ValueError,'exited'):run_engine.live_height(child,1)
    def test_stale_snapshot_release_is_refused_before_opening_database(self):
        with tempfile.TemporaryDirectory() as name:
            root=Path(name);release=root/'release.json';release.write_text('{}')
            args=SimpleNamespace(kill_height=0,kill_emission=False,run_id='a'*32,
                boundary=root/'boundary.json',snapshot_notice=root/'notice.json',snapshot_release=release)
            with self.assertRaisesRegex(ValueError,'old observation'):serve_probe.run(args)
    def test_interruption_writes_failed_report_and_cleans_runtime(self):
        with tempfile.TemporaryDirectory() as name:
            root=Path(name);source=root/'src';source.mkdir();binary=root/'engine';binary.write_bytes(b'fixture')
            engine_hash=run_engine.sha(b'fixture')
            with patch.object(run_engine,'ROOT',source),patch.object(run_engine,'source_identity',return_value=SOURCE),\
                 patch.object(run_engine.subprocess,'check_output',return_value='0.38.25'),\
                 patch.object(run_engine.subprocess,'run',side_effect=KeyboardInterrupt('interrupted')):
                report=run_engine.run(binary,engine_hash,root/'evidence',PROFILES[0])
            self.assertEqual(report['status'],'failed');self.assertEqual(report['error_type'],'KeyboardInterrupt')
            self.assertNotIn('verification',report)
            self.assertEqual(json.loads((root/'evidence/result.json').read_text())['status'],'failed')
    def test_owned_descendant_does_not_survive_leader_exit(self):
        with tempfile.TemporaryDirectory() as name:
            root=Path(name);pidfile=root/'child.pid'
            grandchild=("import os,signal,time;from pathlib import Path;"
                "signal.signal(signal.SIGTERM,signal.SIG_IGN);"
                f"Path({str(pidfile)!r}).write_text(str(os.getpid()));"
                "print('descendant ready',flush=True);time.sleep(60)")
            leader=f'import subprocess,sys;subprocess.Popen([sys.executable,"-c",{grandchild!r}])'
            child=run_engine.Child([sys.executable,'-c',leader],root/'process.log',root)
            try:
                deadline=time.monotonic()+5
                while not pidfile.exists():
                    self.assertLess(time.monotonic(),deadline);time.sleep(.02)
                child.p.wait(5);descendant=int(pidfile.read_text());record=child.stop()
                self.assertTrue(record['owned_process_group_stopped']);self.assertFalse(child.thread.is_alive())
                stat=Path(f'/proc/{descendant}/stat')
                if stat.exists():self.assertEqual(stat.read_text().split()[2],'Z')
                self.assertIn(b'descendant ready',(root/'process.log').read_bytes())
            finally:child.stop()
    def test_private_runtime_prefix_is_redacted(self):
        self.assertEqual(run_engine.sanitize(b'open /tmp/private-123/app1/state.sqlite',Path('/tmp/private-123')),
                         b'open [private-runtime]/app1/state.sqlite')


if __name__=='__main__':unittest.main()
