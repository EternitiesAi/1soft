"""Real disposable application SIGKILL/reopen; synthetic headers, not consensus."""
import copy
import hashlib
import json
import os
from pathlib import Path
import socket
import sqlite3
import subprocess
import sys
import tempfile
import time
import unittest

from abci_wire import Client
from block_application import BlockApplication, encode
from certificate_fixture import validators, make_header, make_commit
from run_state_sync import build_case, ExecutionLogBundle, run
from serve_abci_state_sync_crash import read_observation, write_once, remove_crashed_socket
from state_sync_acceptance import (checkpoint, validate_probe, validate_recovery, validate_history,
    verify_marker_commitment, validate_payment_continuation)

ROOT = Path(__file__).resolve().parents[1]
RUN_ID = 'a'*32


def sample(compact=False):
    case = build_case('fault-check-fixture', 3 if compact else 1, state_commitment='smt-v1' if compact else None)
    app = BlockApplication(':memory:', expected_genesis=case['genesis'])
    app.init_chain(case['genesis']['chain_id'], case['genesis'])
    app.finalize_block([case['pre_snapshot_tx']],1,b'a'*32); app.commit()
    return case, app


def history(height=6, bootstrap=2):
    return {'scope':'local_application_block_results', 'application_height':height,
        'availability':{'keep_blocks':2,'bootstrap_height':bootstrap,'pruned_through':height-2,
            'retained_from':height-1,'retained_through':height,'retained_count':2,'within_configured_window':True},
        'native_receipts_pruned':False,'native_receipt_count':2,'cometbft_retain_height':0,
        'engine_history_pruning_requested':False,'historical_transaction_absence_proven':False,
        'total_storage_bounded':False}


def event(mode='crash'):
    return {'schema':1,'run_id':RUN_ID,'pid':101 if mode=='crash' else 102,
        'phase':'after-durable-install-before-apply-return','mode':mode,'height':2,'app_hash':'b'*64,
        'checkpoint_recovery':mode=='recovery','block_rows':0,'socket':{'device':1,'inode':234}}


class EvidenceTests(unittest.TestCase):
    def test_exact_probe_accepted(self):
        validate_probe(event(), mode='crash',run_id=RUN_ID,expected_pid=101)
    def test_wrong_process_and_run_refused(self):
        for args in ({'expected_pid':999,'run_id':RUN_ID},{'expected_pid':101,'run_id':'f'*32}):
            with self.assertRaises(ValueError): validate_probe(event(),mode='crash',**args)
    def test_probe_numeric_booleans_refused(self):
        for field in ('schema','pid','height','block_rows'):
            e=event();e[field]=True if field!='block_rows' else False
            with self.subTest(field=field),self.assertRaises(ValueError):validate_probe(e,mode='crash',run_id=RUN_ID)
    def test_probe_wrong_phase_refused(self):
        e=event();e['phase']='before-install'
        with self.assertRaises(ValueError):validate_probe(e,mode='crash',run_id=RUN_ID)
    def test_probe_cannot_claim_ordinary_fresh_install_as_recovery(self):
        e=event('recovery');e['checkpoint_recovery']=False
        with self.assertRaises(ValueError):validate_probe(e,mode='recovery',run_id=RUN_ID)
    def test_history_healthy_windows(self):
        for bootstrap in (0,2):validate_history(history(6,bootstrap),final_height=6,bootstrap=bootstrap,keep=2,receipt_count=2)
    def test_retention_booleans_are_not_numeric_evidence(self):
        for key in ('keep_blocks','bootstrap_height','pruned_through','retained_from','retained_through','retained_count'):
            h=history();h['availability'][key]=False
            with self.subTest(key=key),self.assertRaises(ValueError):validate_history(h,final_height=6,bootstrap=2,keep=2,receipt_count=2)
    def test_native_receipt_loss_or_engine_pruning_refused(self):
        for key,value in [('native_receipt_count',1),('native_receipts_pruned',True),('engine_history_pruning_requested',True),('historical_transaction_absence_proven',True),('cometbft_retain_height',2)]:
            h=history();h[key]=value
            with self.subTest(key=key),self.assertRaises(ValueError):validate_history(h,final_height=6,bootstrap=2,keep=2,receipt_count=2)
    def test_signed_snapshot_anchor_checks_quorum_not_rpc_label(self):
        c,a=sample()
        try:
            engine,trust,keys=validators(c['genesis']);mark={'height':1,'app_hash':a.app_hash}
            sh=make_commit(make_header(trust,2,a.app_hash,previous={'hash':'a'*64,'parts':{'total':1,'hash':'b'*64}}),trust,keys)
            self.assertEqual(verify_marker_commitment(mark,sh,encode(engine))['header_height'],2)
            sh['commit']['signatures'][0]['signature']='AA=='
            with self.assertRaises(ValueError):verify_marker_commitment(mark,sh,encode(engine))
        finally:a.close()
    def test_unsigned_wrong_height_and_app_hash_refused(self):
        c,a=sample()
        try:
            engine,trust,keys=validators(c['genesis']);mark={'height':1,'app_hash':a.app_hash}
            for height,apphash in ((1,a.app_hash),(2,'f'*64)):
                sh=make_commit(make_header(trust,height,apphash,previous=None if height == 1 else {'hash':'a'*64,'parts':{'total':1,'hash':'b'*64}}),trust,keys)
                with self.assertRaises(ValueError):verify_marker_commitment(mark,sh,encode(engine))
        finally:a.close()
    def test_exact_post_snapshot_payment_not_merely_two_receipts(self):
        c,a=sample()
        try:
            mark={'height':1,'app_hash':a.app_hash}
            a.finalize_block([c['post_snapshot_tx']],2,b'b'*32);a.commit()
            state=json.loads(a.query('/state')['value'])
            self.assertEqual(len(validate_payment_continuation(state,mark,c['pre_snapshot_tx'],c['post_snapshot_tx'])),2)
            with self.assertRaises(ValueError):validate_payment_continuation(state,mark,c['post_snapshot_tx'],c['pre_snapshot_tx'])
        finally:a.close()


class FileAndRunnerTests(unittest.TestCase):
    def setUp(self):self.tmp=tempfile.TemporaryDirectory();self.root=Path(self.tmp.name)
    def tearDown(self):self.tmp.cleanup()
    def test_missing_observation_is_unknown(self):self.assertIsNone(read_observation(self.root/'missing'))
    def test_observation_never_overwrites(self):
        p=self.root/'observation';write_once(p,event());before=p.read_bytes()
        with self.assertRaises(FileExistsError):write_once(p,{'other':True})
        self.assertEqual(p.read_bytes(),before)
    def test_symlink_and_hardlink_observations_refused(self):
        p=self.root/'observation';write_once(p,event());alias=self.root/'alias';alias.symlink_to(p)
        with self.assertRaises((OSError,ValueError)):read_observation(alias)
        alias.unlink();os.link(p,alias)
        with self.assertRaises(ValueError):read_observation(p)
    def test_large_observation_refused(self):
        p=self.root/'too-large';p.write_bytes(b'x'*8193);p.chmod(0o600)
        with self.assertRaises(ValueError):read_observation(p)
    def test_socket_removal_requires_exact_inode(self):
        path=self.root/'socket';s=socket.socket(socket.AF_UNIX);s.bind(str(path));info=path.stat()
        try:
            with self.assertRaises(ValueError):remove_crashed_socket(path,{'device':info.st_dev,'inode':info.st_ino+1})
            self.assertTrue(path.exists());remove_crashed_socket(path,{'device':info.st_dev,'inode':info.st_ino})
            self.assertFalse(path.exists())
        finally:s.close()
    def test_socket_cleanup_never_removes_regular_file(self):
        path=self.root/'socket';path.write_text('preserve');info=path.stat()
        with self.assertRaises(ValueError):remove_crashed_socket(path,{'device':info.st_dev,'inode':info.st_ino})
        self.assertEqual(path.read_text(),'preserve')
    def test_missing_engine_stays_unassessed_with_explicit_modes(self):
        for keep,crash in ((2,False),(None,True)):
            r=run(str(self.root/'absent'),self.root/f'{keep}-{crash}.json',1,block_history_keep=keep,final_apply_crash=crash)
            self.assertEqual(r['status'],'unassessed');self.assertEqual(r['checks'],[])
            self.assertFalse(r['final_apply_recovery_verified']);self.assertIs(r['final_apply_crash'],crash)
    def test_invalid_and_combined_modes_refused_before_output(self):
        for keep,crash in ((True,False),(3,False),(2,True),(None,1)):
            with self.assertRaises(ValueError):run('missing',self.root/'no.json',1,block_history_keep=keep,final_apply_crash=crash)
        self.assertFalse((self.root/'no.json').exists())
    def test_restart_output_is_separate_and_bounded(self):
        b=ExecutionLogBundle(self.root/'report.json',max_log_bytes=256)
        p=b.start('target',4,'app',[sys.executable,'-c','print("initial")']);p.wait(timeout=5)
        p=b.restart('target',4,'app',[sys.executable,'-c','print("restart")']);p.wait(timeout=5)
        with self.assertRaises(ValueError):b.restart('target',4,'app',[])
        b.finish('passed');m=json.loads(b.manifest_path.read_bytes())
        self.assertEqual(m['log_files'],11)
        self.assertEqual((b.log_dir/'target-node4-app.log').read_text().strip(),'initial')
        self.assertEqual((b.log_dir/'target-node4-app-restart1.log').read_text().strip(),'restart')


class ProcessCrashTests(unittest.TestCase):
    def exercise(self,compact):
        case,source=sample(compact);proc=None
        with tempfile.TemporaryDirectory(prefix='1s-') as d:
            root=Path(d);g=root/'genesis.json';g.write_bytes(encode(case['genesis']))
            db=root/'app.sqlite';sock=root/'app.sock';crashfile=root/'crash.json';recoveryfile=root/'recovery.json'
            def start(phase,observation):
                return subprocess.Popen([sys.executable,str(ROOT/'scripts/serve_abci_state_sync_crash.py'),
                    '--db',str(db),'--socket',str(sock),'--genesis',str(g),'--phase',phase,
                    '--observation',str(observation),'--run-id',RUN_ID],stdout=subprocess.PIPE,stderr=subprocess.PIPE)
            def wait_socket():
                deadline=time.monotonic()+8
                while time.monotonic()<deadline and not sock.exists():
                    self.assertIsNone(proc.poll());time.sleep(.02)
                self.assertTrue(sock.exists())
            def apply(peer,desc):
                self.assertEqual(peer.call('offer_snapshot',snapshot=desc,app_hash=bytes.fromhex(source.app_hash)).result,1)
                for i in range(desc['chunks']):
                    result=peer.call('apply_snapshot_chunk',index=i,chunk=source.load_snapshot_chunk(source.height,1,i),sender='local-fixture')
                    self.assertEqual(result.result,1)
            try:
                proc=start('crash',crashfile);wait_socket();desc=source.list_snapshots()[0]
                with Client(str(sock)) as client:
                    with self.assertRaises((ConnectionError,OSError,EOFError)):apply(client,desc)
                self.assertEqual(proc.wait(timeout=8),-9);proc.communicate(timeout=3)
                crashed=read_observation(crashfile);validate_probe(crashed,mode='crash',run_id=RUN_ID,expected_pid=proc.pid)
                durable=checkpoint(db);self.assertEqual(durable['marker']['app_hash'],source.app_hash)
                self.assertEqual(durable['native_receipts'],1)
                remove_crashed_socket(sock,crashed['socket'])
                # Same DB; do not delete, reset, re-sign or replace any source state.
                proc=start('recovery',recoveryfile);wait_socket()
                with Client(str(sock)) as client:
                    apply(client,desc)
                    recovered=read_observation(recoveryfile)
                    validate_probe(recovered,mode='recovery',run_id=RUN_ID,expected_pid=proc.pid)
                    self.assertEqual(client.call('info').last_block_height,1)
                    out=source.finalize_block([case['post_snapshot_tx']],2,b'b'*32);source.commit()
                    response=client.call('finalize_block',txs=[case['post_snapshot_tx']],height=2,hash=b'b'*32)
                    self.assertEqual(response.app_hash.hex(),out['app_hash']);client.call('commit')
                    self.assertEqual(json.loads(client.call('query',path='/state').value),json.loads(source.query('/state')['value']))
                    self.assertNotEqual(client.call('check_tx',tx=case['pre_snapshot_tx']).code,0)
                saved={'crash':crashed,'exit_code':-9,'durable':durable,'recovery':recovered,
                       'same_node_home':True,'engine_restarted':True,'recovery_retention_flag':None}
                # No actual engine here: matrix-only fields above are synthetic,
                # while the application PID/kill/restore/payment observations ran.
                validate_recovery(saved,{'height':1,'app_hash':crashed['app_hash']},2,RUN_ID)
                with self.assertRaises(ValueError):checkpoint(db)  # Ordinary execution is not snapshot-only.
                print('APPLICATION_CRASH_RESULT='+json.dumps({'compact':compact,'killed_exit':-9,
                    'snapshot_height':1,'post_payment_height':2,'post_payment_app_hash':source.app_hash,
                    'consensus_executed':False,'actual_sigkill':True}),flush=True)
            finally:
                source.close()
                if proc is not None:
                    if proc.poll() is None:proc.terminate()
                    try:proc.communicate(timeout=8)
                    except subprocess.TimeoutExpired:proc.kill();proc.communicate(timeout=5)
    def test_flat_actual_sigkill_reopen_and_post_snapshot_payment(self):self.exercise(False)
    def test_smt_actual_sigkill_reopen_and_post_snapshot_payment(self):self.exercise(True)


if __name__=='__main__':unittest.main()
