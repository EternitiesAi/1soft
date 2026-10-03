"""Bounded runner boundary tests; real engine scenarios are separate gates."""
import hashlib
from pathlib import Path
import tempfile
import unittest
from run_protocol4_state_sync import engine_preflight, output_paths, public_projection

class Protocol4StateSyncRunnerTests(unittest.TestCase):
    def test_missing_engine_is_unassessed_without_launch(self):
        with tempfile.TemporaryDirectory() as d:
            report=engine_preflight(Path(d)/'absent','a'*64)
            self.assertEqual(report['status'],'unassessed')
            self.assertEqual(report['reason'],'pinned engine absent')
    def test_changed_engine_bytes_fail_before_execution(self):
        with tempfile.TemporaryDirectory() as d:
            engine=Path(d)/'engine';engine.write_text('must never be executed')
            report=engine_preflight(engine,'a'*64)
            self.assertEqual(report['status'],'failed')
            self.assertEqual(report['engine_sha256'],hashlib.sha256(engine.read_bytes()).hexdigest())
    def test_existing_output_is_preserved_and_refused(self):
        with tempfile.TemporaryDirectory() as d:
            old=Path(d)/'existing';old.mkdir();(old/'valuable').write_text('preserve')
            with self.assertRaises(ValueError):output_paths(old,Path(d)/'public')
            self.assertEqual((old/'valuable').read_text(),'preserve')
    def test_checkout_output_or_aliased_private_parent_refused(self):
        from run_protocol4_state_sync import ROOT
        with self.assertRaises(ValueError):output_paths(ROOT/'generated',Path('/tmp/public-new'))
        with tempfile.TemporaryDirectory() as d:
            parent=Path(d)/'original';parent.mkdir();link=Path(d)/'alias';link.symlink_to(parent,target_is_directory=True)
            with self.assertRaises(ValueError):output_paths(link/'private',Path(d)/'public')
    def test_public_projection_does_not_copy_full_private_proofs_or_paths(self):
        result={'schema':'1soft-protocol4-state-sync-v1','status':'failed','profile':'basic',
                'source':{'commit':'a'*40,'tree':'b'*40,'source_id':'c'*64},
                'engine_sha256':'d'*64,'checks':[],'private_key':'NEVER EXPORT',
                'reason':'private /home/fixture and signing wire','payments':{'pre':'SECRET'},
                'final_evidence':{'native':'SECRET'},'private_output':'/private/path'}
        public=public_projection(result)
        self.assertEqual(public['status'],'failed');self.assertEqual(public['qualified_check_ids'],[])
        self.assertNotIn('SECRET',str(public));self.assertNotIn('NEVER EXPORT',str(public))
        self.assertNotIn('/private',str(public));self.assertNotIn('/home',str(public))


    def test_written_comet38_state_sync_config_meets_discovery_floor_and_exact_trust(self):
        import tomllib
        from run_devnet import patch_toml
        from run_protocol4_state_sync import state_sync_configuration
        raw='[statesync]\nenable=false\nrpc_servers=""\ntrust_height=0\ntrust_hash=""\ntrust_period="168h0m0s"\ndiscovery_time="15s"\nchunk_request_timeout="10s"\nchunk_fetchers=4\nmax_snapshot_chunks=64\n'
        config=tomllib.loads(patch_toml(raw,state_sync_configuration(
            {'anchor_height':11,'anchor_hash':'ab'*32},[1111,2222])))['statesync']
        # Official pinned Config.ValidateBasic rejects every nonzero duration below 5s.
        self.assertGreaterEqual(int(config['discovery_time'][:-1]),5)
        self.assertEqual(config['trust_height'],11)
        self.assertEqual(config['trust_hash'],'AB'*32)
        self.assertEqual(config['rpc_servers'],'http://127.0.0.1:1111,http://127.0.0.1:2222')

class Protocol4CaptureOutcomeTests(unittest.TestCase):
    def test_read_failure_after_partial_bytes_is_not_a_complete_log(self):
        import io
        from run_protocol4_state_sync import Capture
        class Broken(io.BytesIO):
            def read(self,n=-1):
                if self.tell():raise OSError('controlled read fault')
                return super().read(n)
        with tempfile.TemporaryDirectory() as d:
            capture=Capture(Broken(b'partial stdout'),Path(d)/'read.log')
            with self.assertRaises(ValueError):capture.finish()
    def test_write_failure_is_not_a_complete_log(self):
        import io
        from unittest.mock import patch
        from run_protocol4_state_sync import Capture
        with tempfile.TemporaryDirectory() as d:
            path=Path(d)/'write.log';original_open=Path.open
            class Writer:
                def __enter__(self):self.stream=original_open(path,'xb');return self
                def write(self,raw):raise OSError('controlled disk write fault')
                def __exit__(self,*a):self.stream.close()
            with patch.object(Path,'open',return_value=Writer()):
                capture=Capture(io.BytesIO(b'original stdout'),path)
                capture.thread.join(timeout=2)
            with self.assertRaises(ValueError):capture.finish()
    def test_fsync_failure_is_not_a_complete_log(self):
        import io
        from unittest.mock import patch
        from run_protocol4_state_sync import Capture
        with tempfile.TemporaryDirectory() as d, patch('run_protocol4_state_sync.os.fsync',side_effect=OSError('controlled fsync fault')):
            capture=Capture(io.BytesIO(b'original stdout'),Path(d)/'sync.log')
            with self.assertRaises(ValueError):capture.finish()


class Protocol4OwnedOutcomeTests(unittest.TestCase):
    def test_unexpected_nonzero_exit_is_rejected_after_actual_reap(self):
        import sys
        from run_protocol4_state_sync import Owned
        with tempfile.TemporaryDirectory() as d:
            owned=Owned(Path(d));item=owned.start('engine0',[sys.executable,'-c',
                "print('actual child stdout',flush=True);raise SystemExit(7)"])
            item['process'].wait(timeout=3)
            with self.assertRaises(ValueError):owned.finish()
            self.assertEqual(item['process'].returncode,7)
    def test_rescue_sigkill_is_retained_but_never_qualified(self):
        import sys,time
        from run_protocol4_state_sync import Owned
        with tempfile.TemporaryDirectory() as d:
            owned=Owned(Path(d));item=owned.start('engine0',[sys.executable,'-c',
                "import signal,time;signal.signal(signal.SIGTERM,signal.SIG_IGN);print('ready',flush=True);time.sleep(20)"])
            end=time.monotonic()+3
            while (not (Path(d)/'engine0.log').exists() or not (Path(d)/'engine0.log').stat().st_size) and time.monotonic()<end:
                time.sleep(.01)
            owned.stop_seconds=.05
            with self.assertRaises(ValueError):owned.finish()
            self.assertEqual(item['process'].returncode,-9)
    def test_requested_sigterm_for_actual_owned_engine_role_is_explicit(self):
        import sys
        from run_protocol4_state_sync import Owned
        with tempfile.TemporaryDirectory() as d:
            owned=Owned(Path(d));item=owned.start('engine0',[sys.executable,'-c',
                "import time;print('ready',flush=True);time.sleep(20)"])
            owned.stop(item);records=owned.finish()
            self.assertEqual(records[0]['role'],'engine')
            self.assertTrue(records[0]['stop_requested'])
            self.assertEqual(records[0]['termination_signal'],15)
            self.assertFalse(records[0]['rescue_used'])

class Protocol4RunnerSetupCallerTests(unittest.TestCase):
    def test_actual_missing_engine_caller_retains_well_formed_unassessed_result(self):
        import json
        from run_protocol4_state_sync import run
        # Exercise real setup and clean source pinning. The genuinely absent
        # engine cannot execute; unassessed is the only acceptable outcome.
        with tempfile.TemporaryDirectory() as d:
            private=Path(d)/'private';public=Path(d)/'public'
            result=run(Path(d)/'absent-cometbft',private,public,'a'*64,'basic')
            self.assertEqual(result['status'],'unassessed')
            self.assertEqual(result['reason'],'pinned engine absent')
            self.assertRegex(result['run_id'],r'^[0-9a-f]{32}$')
            self.assertEqual(result['processes'],[])
            self.assertEqual(json.loads((private/'result.json').read_bytes()),result)
            projection=json.loads((public/'result.json').read_bytes())
            self.assertEqual(projection['status'],'unassessed')
            self.assertEqual(projection['qualified_check_ids'],[])


class Protocol4ControlledEngineExitTests(unittest.TestCase):
    # Actual private Python processes exercise lifecycle bookkeeping only.
    # Their diagnostic is an explicitly controlled test fixture, not CometBFT.
    def exercise(self,name):
        import os,signal,subprocess,sys,time
        from run_protocol4_state_sync import Owned
        from serve_abci_p4_state_sync_test import birth
        from serve_abci_state_sync_crash import write_event
        with tempfile.TemporaryDirectory() as d:
            root=Path(d);control=root/'control4';control.mkdir(mode=0o700)
            trigger=root/'trigger'
            diagnostic='consensus connection terminated. Did the application crash? Please restart CometBFT module=proxy err="read message: EOF"'
            command="import pathlib,time; p=pathlib.Path("+repr(str(trigger))+"); "+                "\nwhile not p.exists(): time.sleep(.01)\nprint("+repr(diagnostic)+",flush=True)"
            owned=Owned(root);engine=owned.start(name,[sys.executable,'-c',command])
            pause=subprocess.Popen([sys.executable,'-c','import time;time.sleep(20)'],
                                   stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
            try:
                child_birth=birth(pause.pid);run_id='f'*32
                initial={'pid':pause.pid,'birth':child_birth,'run_id':run_id,
                         'checkpoint_recovery':False,'transaction_active':False}
                before={k:engine[k] for k in ('name','pid','birth','spawned_at_ns')}
                before.update(alive=True,observed_at_ns=time.time_ns())
                kill_requested=time.time_ns();pause.kill();code=pause.wait(timeout=3);reaped=time.time_ns()
                killed={'schema':1,'run_id':run_id,'pid':pause.pid,'birth':child_birth,
                        'returncode':code,'signal':'SIGKILL','stop_requested':True,
                        'termination_signal':9,'rescue_used':False,'cleanup_error':None,
                        'engine_before_kill':before,'kill_requested_at_ns':kill_requested,
                        'reaped_at_ns':reaped}
                write_event(control,'killed.json',killed)
                engine['controlled_application_kill']={'profile':'final-apply-crash','run_id':run_id,
                    'killed':killed,'initial':initial,'event_file':control/'killed.json',
                    'socket_path':str(root/'app4/a.sock')}
                trigger.write_text('actual child kill has completed')
                engine['process'].wait(timeout=3)
                if name=='engine4':
                    # Previous source genuinely rejects this reaped rc0 outcome.
                    self.assertEqual(owned.stop(engine),0)
                    row=owned.finish()[0]
                    self.assertFalse(row['stop_requested']);self.assertIsNone(row['termination_signal'])
                    self.assertEqual(row['causal_exit']['kind'],'controlled-final-apply-application-kill')
                    self.assertEqual(row['causal_exit']['child_pid'],pause.pid)
                    self.assertTrue(owned.cleanup['complete'])
                else:
                    with self.assertRaises(ValueError):owned.stop(engine)
                    with self.assertRaises(ValueError):owned.finish()
            finally:
                if pause.poll() is None:pause.kill();pause.wait(timeout=3)
                if engine['process'].poll() is None or not engine['capture'].completed:
                    try:owned.finish()
                    except ValueError:pass
    def test_identified_target_clean_selfexit_after_actual_child_sigkill_is_truthful(self):
        self.exercise('engine4')
    def test_identical_cause_cannot_authorize_source_engine_selfexit(self):
        self.exercise('engine0')
    def test_target_clean_selfexit_without_child_kill_is_refused(self):
        import sys
        from run_protocol4_state_sync import Owned
        with tempfile.TemporaryDirectory() as d:
            owned=Owned(Path(d));engine=owned.start('engine4',[sys.executable,'-c',"print('unrelated clean exit',flush=True)"])
            engine['process'].wait(timeout=3)
            with self.assertRaises(ValueError):owned.finish()


class Protocol4FailurePreservationTests(unittest.TestCase):
    def test_cleanup_failure_cannot_overwrite_original_scenario_cause(self):
        from run_protocol4_state_sync import record_failure
        report={'status':'running'}
        record_failure(report,ValueError('first engine outcome'),'scenario')
        record_failure(report,OSError('later cleanup fault'),'cleanup-or-validation')
        self.assertEqual(report['reason'],'first engine outcome')
        self.assertEqual(report['failure_type'],'ValueError')
        self.assertEqual([x['reason'] for x in report['failures']],
                         ['first engine outcome','later cleanup fault'])
