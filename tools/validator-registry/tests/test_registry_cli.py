import base64
import json
import hashlib
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from registry_fixture import fixture,authorize
from registry_rules import RegistryRules
from registry_application import RegistryApplication
from commit_verifier import encode

ROOT=Path(__file__).resolve().parents[1]

class RegistryCliTests(unittest.TestCase):
    def setUp(self):
        self.g,self.admins,self.vals,self.target=fixture();self.tmp=tempfile.TemporaryDirectory();self.root=Path(self.tmp.name)
        self.raw=encode(self.g);self.pin=hashlib.sha256(self.raw).hexdigest();self.path=self.root/'registry.sqlite'
        (self.root/'genesis.json').write_bytes(self.raw);(self.root/'target.json').write_bytes(encode(self.target))
    def tearDown(self):self.tmp.cleanup()
    def call(self,*args,database=None,pin=None):
        return subprocess.run([sys.executable,str(ROOT/'scripts/registry.py'),'--genesis',str(self.root/'genesis.json'),
            '--genesis-sha256',pin or self.pin,'--database',str(database or self.path),*map(str,args)],
            env={**os.environ,'PYTHONPATH':''},capture_output=True,text=True,timeout=10)
    def block(self,h,txs=()):
        p=self.root/f'block{h}.json';p.write_bytes(encode({'height':h,'block_hash':hashlib.sha256(str(h).encode()).hexdigest(),
                    'transactions':[base64.b64encode(raw).decode() for raw in txs]}));return p
    def test_full_draft_approval_apply_export_restore_workflow(self):
        p=self.call('init');self.assertEqual(p.returncode,0,p.stderr)
        draft=self.root/'draft.json'
        p=self.call('draft-schedule','--target',self.root/'target.json','--emit-height',4,'--valid-from',1,'--valid-until',2,'--output',draft)
        self.assertEqual(p.returncode,0,p.stderr);body=json.loads(draft.read_bytes())['body'];self.assertFalse(json.loads(draft.read_bytes())['signed'])
        rules=RegistryRules(self.g);raw=authorize(rules,body,self.admins[:3]);tx=self.root/'action.json';tx.write_bytes(raw)
        p=self.call('check','--transaction',tx);self.assertEqual(p.returncode,0,p.stderr)
        for h in range(1,8):
            p=self.call('apply-block','--block',self.block(h,[raw] if h==1 else []));self.assertEqual(p.returncode,0,p.stderr)
        p=self.call('inspect');result=json.loads(p.stdout);self.assertEqual(result['registry_state']['epoch'],1)
        snapshot=self.root/'snapshot.json';self.assertEqual(self.call('export','--output',snapshot).returncode,0)
        p=self.call('restore','--snapshot',snapshot,'--expected-app-hash',result['info']['app_hash'],
                    '--expected-height',7,database=self.root/'restored.sqlite');self.assertEqual(p.returncode,0,p.stderr)
        self.assertEqual(json.loads(p.stdout)['app_hash'],result['info']['app_hash'])
    def test_existing_store_not_overwritten(self):
        self.call('init');p=self.call('init');self.assertEqual(p.returncode,2)
    def test_wrong_genesis_pin_cannot_create_store(self):
        p=self.call('init',pin='f'*64);self.assertEqual(p.returncode,2);self.assertFalse(self.path.exists())
    def test_missing_store_inspection_not_zero_balance(self):
        p=self.call('inspect');self.assertEqual(p.returncode,2);self.assertFalse(self.path.exists())
    def test_rejected_action_reports_failure_even_if_empty_block_commits(self):
        self.call('init');p=self.call('apply-block','--block',self.block(1,[b'{}']))
        self.assertEqual(p.returncode,2);self.assertEqual(json.loads(p.stdout)['tx_results'][0]['code'],1)
        info=json.loads(self.call('inspect').stdout);self.assertEqual(info['registry_state']['height'],1);self.assertEqual(info['registry_state']['sequence'],0)
    def test_commit_result_can_be_retrieved_without_reexecuting(self):
        self.call('init');p=self.call('apply-block','--block',self.block(1));r=json.loads(p.stdout)
        again=self.call('committed-result','--height',1);self.assertEqual(json.loads(again.stdout),r)
        rejected=self.call('apply-block','--block',self.root/'block1.json');self.assertEqual(rejected.returncode,2)
    def test_draft_output_refuses_overwrite(self):
        self.call('init');out=self.root/'draft.json';out.write_text('keep')
        p=self.call('draft-schedule','--target',self.root/'target.json','--emit-height',4,'--valid-from',1,'--valid-until',2,'--output',out)
        self.assertEqual(p.returncode,2);self.assertEqual(out.read_text(),'keep')
    def test_no_sign_or_broadcast_command(self):
        for name in ('sign','broadcast','activate-mainnet'):
            self.assertNotEqual(self.call(name).returncode,0)
        self.assertFalse(self.path.exists())

if __name__=='__main__':unittest.main()
