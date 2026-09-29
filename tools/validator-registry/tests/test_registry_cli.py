import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from commit_verifier import encode
from registry_fixture import fixture,schedule
from registry_rules import initial_state,sha

HERE=Path(__file__).resolve().parents[1]

class RegistryCliTests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory();self.root=Path(self.temp.name)
        self.g,self.admins,_,self.target=fixture();self.raw=schedule(self.g,initial_state(self.g),self.admins[:2],self.target)
        (self.root/'g.json').write_bytes(encode(self.g));(self.root/'commands.json').write_bytes(encode([self.raw.hex()]))
    def tearDown(self):self.temp.cleanup()
    def call(self,*args,store='registry.sqlite'):
        return subprocess.run([sys.executable,str(HERE/'scripts/registry.py'),'--genesis',str(self.root/'g.json'),
            '--store',str(self.root/store),*map(str,args)],capture_output=True,text=True,timeout=10,
            env={**os.environ,'PYTHONPATH':''})
    def test_real_cli_init_block_inspect_and_export(self):
        self.assertEqual(self.call('init').returncode,0)
        r=self.call('block','--height','1','--block-hash',sha(b'1'),'--transactions',self.root/'commands.json')
        self.assertEqual(r.returncode,0,r.stderr)
        r=self.call('inspect');self.assertEqual(json.loads(r.stdout)['result']['nonce'],1)
        r=self.call('export','--output',self.root/'snapshot.json');self.assertEqual(r.returncode,0,r.stderr)
    def test_missing_store_not_initialized_by_read(self):
        self.assertEqual(self.call('inspect').returncode,2);self.assertFalse((self.root/'registry.sqlite').exists())
    def test_draft_does_not_authorize_or_reserve(self):
        self.call('init');op={'type':'schedule','emission_height':3,'validators':self.target}
        (self.root/'op.json').write_bytes(encode(op))
        r=self.call('draft','--operation',self.root/'op.json','--valid-from','1','--valid-until','10','--output',self.root/'unsigned.json')
        self.assertEqual(r.returncode,0,r.stderr);self.assertFalse(json.loads(r.stdout)['result']['administrative_authorization'])
        self.assertEqual(json.loads(self.call('inspect').stdout)['result']['nonce'],0)
    def test_restore_requires_explicit_hash_and_fresh_store(self):
        self.call('init');self.call('block','--height','1','--block-hash',sha(b'1'),'--transactions',self.root/'commands.json')
        r=self.call('export','--output',self.root/'snapshot.json');h=json.loads(r.stdout)['result']['app_hash']
        self.call('init',store='fresh.sqlite')
        r=self.call('restore','--snapshot',self.root/'snapshot.json','--expected-hash',h,store='fresh.sqlite')
        self.assertEqual(r.returncode,0,r.stderr);self.assertEqual(json.loads(r.stdout)['result']['height'],1)
    def test_existing_export_refused_without_overwrite(self):
        self.call('init');p=self.root/'old.json';p.write_text('preserve')
        self.assertEqual(self.call('export','--output',p).returncode,2);self.assertEqual(p.read_text(),'preserve')
    def test_no_wallet_or_broadcast_commands(self):
        for command in ('sign','send','broadcast','unlock'):
            self.assertNotEqual(self.call(command).returncode,0)
    def test_fixture_demo_runs_complete_lifecycle_and_replicas(self):
        r=subprocess.run([sys.executable,str(HERE/'scripts/demo.py'),'--output',str(self.root/'demo')],
            capture_output=True,text=True,timeout=15,env={**os.environ,'PYTHONPATH':''})
        self.assertEqual(r.returncode,0,r.stderr);out=json.loads(r.stdout)
        self.assertEqual(out['emitted_heights'],[3,10]);self.assertEqual(out['active_heights'],[5,12])
        self.assertTrue(out['restored_replicas_match']);self.assertFalse(out['consensus_executed'])

if __name__=='__main__':unittest.main()
