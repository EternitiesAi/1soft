import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

from block_application import encode
from p4_fixture import build,bundle

ROOT=Path(__file__).resolve().parents[1]

class CLITests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):cls.c=build()
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory();self.root=Path(self.temp.name)
        for name,raw in [('genesis.json',self.c['genesis']),('policy.json',encode(self.c['policy'])),
                         ('evidence.json',encode(bundle(self.c))),('after.json',self.c['wires']['after'])]:
            (self.root/name).write_bytes(raw)
        self.path=self.root/'read.sqlite'
    def tearDown(self):self.temp.cleanup()
    def call(self,*args):
        return subprocess.run([sys.executable,str(ROOT/'scripts/p4_read.py'),'--genesis',str(self.root/'genesis.json'),
            '--policy',str(self.root/'policy.json'),*map(str,args)],capture_output=True,text=True,timeout=10)
    def initialize(self):
        p=self.call('init','--store',self.path);self.assertEqual(p.returncode,0,p.stderr)
        p=self.call('import','--store',self.path,'--expected-tip','empty','--evidence',self.root/'evidence.json')
        self.assertEqual(p.returncode,0,p.stderr);return json.loads(p.stdout)
    def test_complete_init_import_account_receipt_inspect_and_export_workflow(self):
        report=self.initialize()
        p=self.call('inspect','--store',self.path);self.assertEqual(p.returncode,0,p.stderr)
        self.assertEqual(json.loads(p.stdout)['registry_epoch'],2)
        p=self.call('account','--store',self.path,'--account',self.c['payer']);self.assertEqual(p.returncode,0,p.stderr)
        self.assertEqual(json.loads(p.stdout)['account']['recorded_balance'],'874')
        p=self.call('receipt','--store',self.path,'--transaction',self.root/'after.json','--payer',self.c['payer'])
        self.assertEqual(p.returncode,0,p.stderr);self.assertEqual(json.loads(p.stdout)['receipt']['height'],7)
        out=self.root/'export.json'
        p=self.call('export','--store',self.path,'--evidence-id',report['evidence_id'],'--output',out)
        self.assertEqual(p.returncode,0,p.stderr);self.assertEqual(out.read_bytes(),encode(bundle(self.c)))
    def test_standalone_verification_creates_no_database(self):
        p=self.call('verify','--evidence',self.root/'evidence.json');self.assertEqual(p.returncode,0,p.stderr)
        self.assertEqual(json.loads(p.stdout)['state_height'],16);self.assertFalse(self.path.exists())
    def test_missing_read_store_not_created_by_inspect(self):
        p=self.call('inspect','--store',self.path);self.assertEqual(p.returncode,2);self.assertFalse(self.path.exists())
    def test_existing_export_not_overwritten(self):
        r=self.initialize();out=self.root/'out.json';out.write_text('preserve')
        p=self.call('export','--store',self.path,'--evidence-id',r['evidence_id'],'--output',out)
        self.assertEqual(p.returncode,2);self.assertEqual(out.read_text(),'preserve')
    def test_wrong_payer_cli_refused(self):
        self.initialize()
        p=self.call('receipt','--store',self.path,'--transaction',self.root/'after.json','--payer',self.c['merchant'])
        self.assertEqual(p.returncode,2)
    def test_bad_input_not_echoed_as_diagnostic(self):
        (self.root/'evidence.json').write_text('{"secret":"unsafe-value"}')
        p=self.call('verify','--evidence',self.root/'evidence.json')
        self.assertEqual(p.returncode,2);self.assertNotIn('unsafe-value',p.stderr);self.assertNotIn(str(self.root),p.stderr)
    def test_no_sign_send_or_policy_renew_command(self):
        for name in ('sign','send','renew'):
            p=self.call(name);self.assertNotEqual(p.returncode,0)
        self.assertFalse(self.path.exists())
    def test_unknown_account_remains_unavailable_without_balance(self):
        self.initialize();p=self.call('account','--store',self.path,'--account','unknown')
        self.assertEqual(p.returncode,2);self.assertIsNone(json.loads(p.stdout)['account'])


if __name__=='__main__':unittest.main()
