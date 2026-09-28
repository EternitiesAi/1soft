import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from commit_verifier import encode
from fixture_explorer import scenario,bundle,pin

ROOT=Path(__file__).resolve().parents[1]

class CLITests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):cls.c=scenario(blocks=8)
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory();self.root=Path(self.tmp.name)
        (self.root/'g.json').write_bytes(self.c['genesis']);(self.root/'e.json').write_bytes(encode(bundle(self.c)))
    def tearDown(self):self.tmp.cleanup()
    def call(self,*args):
        return subprocess.run([sys.executable,str(ROOT/'scripts/explorer.py'),'--genesis',str(self.root/'g.json'),
            '--genesis-sha256',self.c['genesis_sha256'],'--index',str(self.root/'index.sqlite'),*map(str,args)],
            capture_output=True,text=True,timeout=10)
    def import_(self):
        return self.call('import','--evidence',self.root/'e.json','--initial-header-hash',pin(self.c))
    def test_init_import_inspect_export_real_cli(self):
        self.assertEqual(self.call('init').returncode,0)
        p=self.import_();self.assertEqual(p.returncode,0,p.stderr)
        p=self.call('inspect');self.assertEqual(p.returncode,0,p.stderr);self.assertEqual(json.loads(p.stdout)['state_height'],8)
        out=self.root/'view.html';p=self.call('export','--output',out);self.assertEqual(p.returncode,0,p.stderr)
        self.assertIn('1soft Explorer',out.read_text());self.assertIn('block_inclusion_verified',out.read_text())
    def test_missing_index_not_created_by_inspect(self):
        p=self.call('inspect');self.assertEqual(p.returncode,2);self.assertFalse((self.root/'index.sqlite').exists())
    def test_empty_index_inspection_refuses_not_zero_balance(self):
        self.call('init');p=self.call('inspect');self.assertEqual(p.returncode,2);self.assertEqual(p.stdout,'')
    def test_export_does_not_overwrite_existing_file(self):
        self.call('init');self.import_();out=self.root/'view.html';out.write_text('preserve')
        p=self.call('export','--output',out);self.assertEqual(p.returncode,2);self.assertEqual(out.read_text(),'preserve')
    def test_bad_evidence_does_not_get_rendered_or_echoed(self):
        self.call('init');(self.root/'e.json').write_text('{"untrusted":"secret-payload"}')
        p=self.import_();self.assertEqual(p.returncode,2);self.assertNotIn('secret-payload',p.stderr)
        self.assertNotIn(str(self.root),p.stderr)
    def test_demo_is_repeatable_and_refuses_existing_directory(self):
        out=self.root/'demo'
        p=subprocess.run([sys.executable,str(ROOT/'scripts/demo.py'),'--output',str(out)],capture_output=True,text=True,timeout=10)
        self.assertEqual(p.returncode,0,p.stderr)
        result=json.loads((out/'result.json').read_bytes());self.assertFalse(result['consensus_executed'])
        self.assertEqual(result['reopened_import']['state_height'],24)
        self.assertFalse(result['private_key_files_created'])
        p=subprocess.run([sys.executable,str(ROOT/'scripts/demo.py'),'--output',str(out)],capture_output=True,text=True,timeout=5)
        self.assertNotEqual(p.returncode,0)
    def test_no_sign_or_submit_commands(self):
        p=self.call('sign');self.assertNotEqual(p.returncode,0)
        self.assertFalse((self.root/'index.sqlite').exists())

if __name__=='__main__':unittest.main()
