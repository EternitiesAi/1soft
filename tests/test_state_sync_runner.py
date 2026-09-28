import base64
from contextlib import redirect_stdout
import io
import json
import os
from pathlib import Path
import subprocess
import time
import sqlite3
import sys
import tempfile
import unittest

from native_core import NativeLedger, parse_wire
from block_application import BlockApplication
from abci_wire import Client
from run_devnet import patch_toml
from run_state_sync import (
    ExecutionLogBundle, build_case, committed, marker, min_block_height, private_json,
    receipt_history_contains, run, verify_compact_proof_response,
)
from state_tree import make_witness


class StateSyncRunnerTests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory();self.root=Path(self.tmp.name)
    def tearDown(self):self.tmp.cleanup()

    def test_missing_engine_is_unassessed_not_simulated(self):
        output=self.root/'report.json'
        report=run(str(self.root/'definitely-missing-cometbft'),output,1)
        self.assertEqual(report['status'],'unassessed')
        self.assertFalse(report['state_sync_verified'])
        self.assertFalse(report['continued_execution_verified'])
        saved=json.loads(output.read_text());self.assertEqual(saved['checks'],[])
        self.assertEqual(saved['source_provenance']['runner_relative_path'],'scripts/run_state_sync.py')

    def test_protocol_and_compact_mode_are_explicit(self):
        with self.assertRaises(ValueError):build_case('x',2)
        with self.assertRaises(ValueError):build_case('x',1,state_commitment='smt-v1')
        case=build_case('x',3,state_commitment='smt-v1')
        self.assertEqual(case['genesis']['protocol_version'],3)
        self.assertEqual(case['genesis']['state_commitment'],'smt-v1')

    def test_pre_and_post_snapshot_transactions_execute_in_order(self):
        for version,commitment in ((1,None),(3,'smt-v1')):
            with self.subTest(version=version):
                case=build_case('chain-'+str(version),version,state_commitment=commitment)
                ledger=NativeLedger(':memory:',case['genesis'])
                try:
                    first=ledger.apply(parse_wire(case['pre_snapshot_tx']),height=1)
                    second=ledger.apply(parse_wire(case['post_snapshot_tx']),height=2)
                    self.assertNotEqual(first['txid'],second['txid'])
                    owner=ledger._account(case['owner']);merchant=ledger._account(case['merchant'])
                    self.assertEqual(owner['nonce'],2);self.assertEqual(merchant['balance'],188)
                finally:ledger.close()

    def test_state_sync_config_patch_is_bounded_and_parseable(self):
        source='''[statesync]\nenable = false\nrpc_servers = ""\ntrust_height = 0\ntrust_hash = ""\ntrust_period = "168h0m0s"\ndiscovery_time = "15s"\nchunk_request_timeout = "10s"\nchunk_fetchers = "4"\nmax_snapshot_chunks = 100000\n'''
        result=patch_toml(source,{
            'statesync.enable':True,
            'statesync.rpc_servers':'http://127.0.0.1:1,http://127.0.0.1:2',
            'statesync.trust_height':7,
            'statesync.trust_hash':'ab'*32,
            'statesync.trust_period':'168h0m0s',
            'statesync.discovery_time':'5s',
            'statesync.chunk_request_timeout':'5s',
            'statesync.chunk_fetchers':2,
            'statesync.max_snapshot_chunks':64})
        self.assertIn('rpc_servers = "http://127.0.0.1:1,http://127.0.0.1:2"',result)
        self.assertIn('max_snapshot_chunks = 64',result)

    def test_marker_and_committed_helpers_distinguish_snapshot_from_blocks(self):
        path=self.root/'app.sqlite';db=sqlite3.connect(path)
        db.executescript('''CREATE TABLE committed(id INTEGER PRIMARY KEY,genesis TEXT,height INTEGER,app_hash TEXT,state TEXT);
            CREATE TABLE blocks(height INTEGER PRIMARY KEY,block_hash TEXT,tx_digest TEXT,app_hash TEXT,results TEXT);
            CREATE TABLE state_sync_marker(id INTEGER PRIMARY KEY,height INTEGER,app_hash TEXT);''')
        db.execute('INSERT INTO committed VALUES (1,?,?,?,?)',('{}',9,'aa',json.dumps({'x':1})))
        db.execute('INSERT INTO state_sync_marker VALUES (1,?,?)',(7,'bb'))
        db.execute('INSERT INTO blocks VALUES (?,?,?,?,?)',(8,'h','t','c','[]'))
        db.commit();db.close();path.chmod(0o600)
        self.assertEqual(marker(path),{'height':7,'app_hash':'bb'})
        self.assertEqual(committed(path)['height'],9)
        self.assertEqual(min_block_height(path),8)


    def test_failed_runner_child_keeps_bounded_sanitized_source_and_target_logs(self):
        bundle=ExecutionLogBundle(self.root/'result.json',max_log_bytes=160)
        self.assertEqual(len([p for p in bundle.log_dir.glob('*.log') if p.name != 'runner.log']),10)
        try:
            process=bundle.start('source',0,'engine',[
                sys.executable,'-c',
                'import sys; print(\"startup private_key=do-not-retain\"); '
                'print(\'"priv_key":{"type":"ed25519","value":"object-secret"}\'); '
                'print(\'x\'*4000); sys.exit(7)'])
            self.assertEqual(process.wait(timeout=10),7)
        finally:
            bundle.finish(status='failed')
        names={p.name for p in bundle.log_dir.glob('*.log')}
        self.assertEqual(len([name for name in names if name != 'runner.log']),10)
        log=(bundle.log_dir/'source-node0-engine.log').read_text()
        self.assertIn('startup',log)
        self.assertNotIn('do-not-retain',log)
        self.assertNotIn('object-secret',log)
        self.assertLessEqual((bundle.log_dir/'source-node0-engine.log').stat().st_size,160)
        manifest=json.loads(bundle.manifest_path.read_text())
        self.assertEqual(manifest['status'],'failed')
        entry=next(row for row in manifest['logs'] if row['path']=='source-node0-engine.log')
        self.assertTrue(entry['truncated'])
        self.assertEqual(entry['max_bytes'],160)
        self.assertFalse(any('priv_validator_key.json' in p.name for p in bundle.log_dir.iterdir()))

    def test_runner_failure_preserves_process_log_bundle_and_setup_diagnostics(self):
        engine=self.root/'fake-cometbft'
        engine.write_text("""#!/usr/bin/env python3
import sys
if sys.argv[1:] == ['version']:
    print('v0.38.25')
    raise SystemExit(0)
if len(sys.argv) > 1 and sys.argv[1] == 'testnet':
    print('synthetic testnet setup failure', file=sys.stderr)
    raise SystemExit(9)
raise SystemExit(8)
""")
        engine.chmod(0o700)
        output=self.root/'failed-run.json'
        with redirect_stdout(io.StringIO()):
            report=run(str(engine),output,1)
        self.assertEqual(report['status'],'failed')
        self.assertEqual(report['execution_logs']['log_files'],10)
        logs=report['execution_logs']['manifest']
        manifest=json.loads((output.parent/logs).read_text())
        self.assertEqual(manifest['status'],'failed')
        self.assertEqual(manifest['log_files'],10)
        self.assertIn('synthetic testnet setup failure',
                      (output.parent/'failed-run.json.logs'/'runner.log').read_text())
        self.assertEqual(len([path for path in (output.parent/'failed-run.json.logs').glob('*.log')
                              if path.name != 'runner.log']),10)

    def test_retention_and_crash_modes_are_explicit_even_when_engine_is_missing(self):
        output=self.root/'retained.json'
        report=run(str(self.root/'missing'),output,3,state_commitment='smt-v1',
                   block_history_keep=2,final_apply_crash=True)
        self.assertEqual(report['status'],'unassessed')
        self.assertEqual(report['block_history_keep'],2)
        self.assertTrue(report['final_apply_crash'])
        self.assertFalse(report['final_apply_recovery_verified'])
        for bad in (True,1,1.0,'2',1000001):
            with self.subTest(bad=bad):
                with self.assertRaises(ValueError):
                    run(str(self.root/'missing'),self.root/f'bad-{bad}.json',1,block_history_keep=bad)

    def test_extra_restart_log_is_bounded_and_manifested_separately(self):
        bundle=ExecutionLogBundle(self.root/'restart.json',max_log_bytes=256)
        first=bundle.start('target',4,'engine',[sys.executable,'-c','print("first")'])
        self.assertEqual(first.wait(timeout=5),0)
        second=bundle.start_extra('target',4,'engine','restart1',[sys.executable,'-c','print("restart")'])
        self.assertEqual(second.wait(timeout=5),0)
        bundle.finish('passed')
        manifest=json.loads(bundle.manifest_path.read_text())
        rows=[r for r in manifest['logs'] if r['role']=='target' and r['node']==4 and r['process']=='engine']
        self.assertEqual({r['phase'] for r in rows},{'initial','restart1'})
        self.assertEqual(manifest['log_files'],11)

    def test_final_apply_supervisor_sigkills_then_recovers_exact_checkpoint(self):
        case=build_case('final-apply-local-test',1)
        source=BlockApplication(':memory:',expected_genesis=case['genesis'])
        source.init_chain(case['genesis']['chain_id'],case['genesis'])
        result=source.finalize_block([case['pre_snapshot_tx']],1,b'a'*32)
        self.assertEqual(result['tx_results'][0]['code'],0);source.commit()
        desc=source.list_snapshots()[0]
        private=self.root/'crash-app';private.mkdir(mode=0o700)
        genesis=private/'genesis.json';genesis.write_text(json.dumps(case['genesis']))
        socket=private/'a.sock';db=private/'app.sqlite';status=private/'killed.json';resume=private/'resume';recovered=private/'recovered.json'
        proc=subprocess.Popen([sys.executable,str(Path(__file__).resolve().parents[1]/'scripts/serve_abci_state_sync_crash.py'),
            '--db',str(db),'--socket',str(socket),'--genesis',str(genesis),
            '--status',str(status),'--resume',str(resume),'--recovered',str(recovered)],
            stdout=subprocess.PIPE,stderr=subprocess.STDOUT)
        try:
            deadline=time.monotonic()+5
            while time.monotonic()<deadline and not socket.exists():
                self.assertIsNone(proc.poll());time.sleep(.02)
            self.assertTrue(socket.exists())
            with Client(str(socket)) as peer:
                offered=peer.call('offer_snapshot',snapshot=desc,app_hash=bytes.fromhex(source.app_hash))
                self.assertEqual(offered.result,1)
                for i in range(desc['chunks']-1):
                    self.assertEqual(peer.call('apply_snapshot_chunk',index=i,chunk=source.load_snapshot_chunk(1,1,i),sender='fixture').result,1)
                with self.assertRaises((ConnectionError,OSError,EOFError,ValueError)):
                    peer.call('apply_snapshot_chunk',index=desc['chunks']-1,chunk=source.load_snapshot_chunk(1,1,desc['chunks']-1),sender='fixture')
            deadline=time.monotonic()+5
            while time.monotonic()<deadline and private_json(status) is None:time.sleep(.02)
            self.assertEqual(private_json(status),{'schema':1,'phase':'killed-after-durable-install','signal':'SIGKILL','exit_code':-9})
            self.assertEqual(marker(db),{'height':1,'app_hash':source.app_hash})
            self.assertIsNone(min_block_height(db))
            resume.write_text('resume\n');resume.chmod(0o600)
            deadline=time.monotonic()+5
            while time.monotonic()<deadline and not socket.exists():time.sleep(.02)
            self.assertTrue(socket.exists());time.sleep(.05)
            with Client(str(socket)) as peer:
                offered=peer.call('offer_snapshot',snapshot=desc,app_hash=bytes.fromhex(source.app_hash))
                self.assertEqual(offered.result,1)
                for i in range(desc['chunks']):
                    self.assertEqual(peer.call('apply_snapshot_chunk',index=i,chunk=source.load_snapshot_chunk(1,1,i),sender='fixture').result,1)
                info=peer.call('info');self.assertEqual(info.last_block_height,1)
            deadline=time.monotonic()+5
            while time.monotonic()<deadline and private_json(recovered) is None:time.sleep(.02)
            self.assertEqual(private_json(recovered),{'schema':1,'phase':'checkpoint-recovery-install',
                'height':1,'app_hash':source.app_hash,'checkpoint_recovery':True})
        finally:
            source.close()
            if proc.poll() is None:proc.terminate()
            try:proc.communicate(timeout=5)
            except subprocess.TimeoutExpired:proc.kill();proc.communicate(timeout=5)


    def test_post_snapshot_receipt_gate_requires_exact_transaction_id(self):
        state={'native':{'receipts':[['older-txid',1,'','{}',''],['other-txid',2,'','{}','']]}}
        self.assertFalse(receipt_history_contains(state,'post-snapshot-txid'))
        state['native']['receipts'][1][0]='post-snapshot-txid'
        self.assertTrue(receipt_history_contains(state,'post-snapshot-txid'))

    def test_compact_proof_gate_verifies_decoded_proof_and_bound_state(self):
        case=build_case('runner-proof-test',3,state_commitment='smt-v1')
        owner=case['owner']
        native={'meta':[],'accounts':[[owner,case['genesis']['allocations'][0]['public_key'],0,0,123]],
                'grants':[],'receipts':[],'budgets':[],'grant_budgets':[]}
        witness=make_witness(case['genesis'],3,native,[('accounts',owner)])
        state={'genesis':case['genesis'],'height':3,'app_hash':witness['app_hash'],'native':native}
        response={'code':0,'height':'3',
                  'value':base64.b64encode(json.dumps(witness).encode()).decode()}
        result=verify_compact_proof_response(response,state,'accounts',owner)
        self.assertEqual(result['record'],native['accounts'][0])
        empty={'code':0,'height':'3','value':''}
        with self.assertRaises((ValueError,KeyError,TypeError)):
            verify_compact_proof_response(empty,state,'accounts',owner)
        malformed={'code':0,'height':'3','value':base64.b64encode(b'{').decode()}
        with self.assertRaises((ValueError,KeyError,TypeError)):
            verify_compact_proof_response(malformed,state,'accounts',owner)
        wrong_height={**response,'height':'4'}
        with self.assertRaises((ValueError,KeyError,TypeError)):
            verify_compact_proof_response(wrong_height,state,'accounts',owner)

if __name__=='__main__':unittest.main()
