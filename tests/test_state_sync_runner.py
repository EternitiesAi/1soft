import json
from pathlib import Path
import sqlite3
import tempfile
import unittest

from native_core import NativeLedger, parse_wire
from run_devnet import patch_toml
from run_state_sync import build_case, committed, marker, min_block_height, run


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


if __name__=='__main__':unittest.main()
