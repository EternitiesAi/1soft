"""Actual CLI uses an existing verified store; bad input creates no new store."""
import json,os,subprocess,sys,tempfile,unittest
from pathlib import Path
from p4_fixture import build,bundle
from p4_read_store import P4ReadStore,write_new
from block_application import encode
ROOT=Path(__file__).resolve().parents[1]
class CliTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):cls.c=build()
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory();self.root=Path(self.tmp.name)
        write_new(self.root/'genesis.json',self.c['genesis']);write_new(self.root/'policy.json',encode(self.c['policy']))
        self.path=self.root/'read.sqlite'
        with P4ReadStore(self.path,self.c['genesis'],self.c['policy'],create=True,clock=lambda:self.c['now_ns']) as s:s.import_evidence(bundle(self.c),expected_tip=None)
    def tearDown(self):self.tmp.cleanup()
    def run_cli(self,*args,path=None):
        return subprocess.run([sys.executable,str(ROOT/'scripts/p4_explorer.py'),'--genesis',str(self.root/'genesis.json'),'--policy',str(self.root/'policy.json'),'--store',str(path or self.path),*args],capture_output=True,text=True,timeout=10)
    def test_inspect_replays_real_store_and_returns_projected_balance(self):
        before=self.path.read_bytes();p=self.run_cli('inspect');self.assertEqual(p.returncode,0,p.stderr)
        v=json.loads(p.stdout);self.assertEqual(v['checkpoint']['state_height'],'16');self.assertEqual(self.path.read_bytes(),before)
        self.assertNotIn('history',v);self.assertFalse(v['spending_authority'])
    def test_missing_store_is_not_initialized(self):
        path=self.root/'missing.sqlite';p=self.run_cli('inspect',path=path)
        self.assertEqual(p.returncode,2);self.assertFalse(path.exists());self.assertNotIn('lab_',p.stderr)
    def test_bad_genesis_pin_refuses_without_mutation(self):
        (self.root/'genesis.json').write_bytes(b'{}');before=self.path.read_bytes();p=self.run_cli('inspect')
        self.assertEqual(p.returncode,2);self.assertEqual(self.path.read_bytes(),before)
    def test_no_sync_send_or_historical_clock_command(self):
        for args in [('sync',),('send',),('inspect','--now','0')]:
            p=self.run_cli(*args);self.assertEqual(p.returncode,2)
