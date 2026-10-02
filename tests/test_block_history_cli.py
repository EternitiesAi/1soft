"""Actual private ABCI process and CLI, not a CometBFT network."""
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import time
import unittest
from abci_wire import Client
from block_application import encode
from test_block_history import fixture

ROOT=Path(__file__).resolve().parents[1]

class HistoryCliTests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory();self.root=Path(self.tmp.name)
        self.g,*_=fixture();(self.root/'genesis.json').write_bytes(encode(self.g));self.proc=None
    def tearDown(self):
        if self.proc is not None:
            self.proc.terminate()
            try:self.proc.communicate(timeout=5)
            except subprocess.TimeoutExpired:self.proc.kill();self.proc.communicate(timeout=5)
        self.tmp.cleanup()
    def command(self, keep=None):
        args=[sys.executable,str(ROOT/'scripts/serve_abci.py'),'--db',str(self.root/'app.sqlite'),
              '--socket',str(self.root/'app.sock'),'--genesis',str(self.root/'genesis.json')]
        if keep is not None:args+=['--block-history-keep',str(keep)]
        return args
    def start(self, keep=None):
        self.proc=subprocess.Popen(self.command(keep),stdout=subprocess.PIPE,stderr=subprocess.PIPE,
                                    env={**os.environ,'PYTHONPATH':str(ROOT/'src')})
        deadline=time.monotonic()+5
        while time.monotonic()<deadline:
            if self.proc.poll() is not None:
                out,err=self.proc.communicate();self.fail(err.decode()+out.decode())
            if (self.root/'app.sock').exists():return
            time.sleep(.02)
        self.fail('private ABCI socket did not start')
    def drive(self,peer,start=1,end=8):
        for h in range(start,end+1):
            peer.call('finalize_block',txs=[],height=h,hash=hashlib.sha256(str(h).encode()).digest())
            self.assertEqual(peer.call('commit').retain_height,0)
    def test_cli_applies_retention_over_real_private_abci(self):
        self.start(3)
        with Client(str(self.root/'app.sock')) as c:
            c.call('init_chain',chain_id=self.g['chain_id'],app_state_bytes=encode(self.g),initial_height=1)
            self.drive(c)
            h=json.loads(c.call('query',path='/history').value)
            self.assertEqual(h['availability']['retained_count'],3)
            q=c.call('query',path='/block/1');self.assertEqual(q.code,2)
            self.assertFalse(json.loads(q.value)['historical_transaction_absence_proven'])
            self.assertEqual(c.call('info').last_block_height,8)
    def test_cli_restart_without_flag_reuses_saved_policy(self):
        self.start(3)
        with Client(str(self.root/'app.sock')) as c:
            c.call('init_chain',chain_id=self.g['chain_id'],app_state_bytes=encode(self.g),initial_height=1)
            self.drive(c)
        self.proc.terminate();self.proc.communicate(timeout=5);self.proc=None
        self.start()
        with Client(str(self.root/'app.sock')) as c:
            self.drive(c,9,12);h=json.loads(c.call('query',path='/history').value)
            self.assertEqual(h['availability']['keep_blocks'],3)
            self.assertEqual(h['availability']['retained_count'],3)
            self.assertEqual(h['application_height'],12)
    def test_cli_invalid_keep_refused_before_database_creation(self):
        p=subprocess.run(self.command(1),capture_output=True,timeout=5)
        self.assertNotEqual(p.returncode,0);self.assertFalse((self.root/'app.sqlite').exists())
    def test_cli_default_does_not_prune(self):
        self.start()
        with Client(str(self.root/'app.sock')) as c:
            c.call('init_chain',chain_id=self.g['chain_id'],app_state_bytes=encode(self.g),initial_height=1)
            self.drive(c);h=json.loads(c.call('query',path='/history').value)
            self.assertIsNone(h['availability']['keep_blocks'])
            self.assertEqual(h['availability']['retained_count'],8)
    def test_cli_readonly_request_cannot_change_retention(self):
        self.start(3)
        with Client(str(self.root/'app.sock')) as c:
            c.call('init_chain',chain_id=self.g['chain_id'],app_state_bytes=encode(self.g),initial_height=1)
            self.drive(c)
            self.assertNotEqual(c.call('query',path='/history',data=b'{"keep_blocks":0}').code,0)
            h=json.loads(c.call('query',path='/history').value)
            self.assertEqual(h['availability']['keep_blocks'],3)

if __name__=='__main__':unittest.main()
