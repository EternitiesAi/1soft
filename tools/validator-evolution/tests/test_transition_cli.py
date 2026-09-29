from datetime import datetime,timezone,timedelta
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from commit_verifier import encode
from transition_fixture import fixture

ROOT=Path(__file__).resolve().parents[1]

class CliTests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory();self.root=Path(self.tmp.name)
        self.f=fixture(start=datetime.now(timezone.utc)-timedelta(seconds=30))
        for name,value in [('genesis',self.f['genesis']),('policy',encode(self.f['policy'])),
                           ('anchor',encode(self.f['steps'][0])),('batch',encode(self.f['steps'][1:]))]:
            (self.root/name).write_bytes(value)
    def tearDown(self):self.tmp.cleanup()
    def call(self,command,*extra):
        args=[sys.executable,str(ROOT/'scripts/validators.py'),command]
        if command!='preview':args+=['--genesis',str(self.root/'genesis'),'--policy',str(self.root/'policy'),'--store',str(self.root/'store.sqlite')]
        return subprocess.run(args+list(map(str,extra)),capture_output=True,text=True,timeout=10,env={**os.environ,'PYTHONPATH':''})
    def test_init_advance_inspect_export(self):
        r=self.call('init','--anchor',self.root/'anchor');self.assertEqual(r.returncode,0,r.stderr)
        r=self.call('advance','--steps',self.root/'batch','--expected-tip-hash',self.f['policy']['initial_header_hash'])
        self.assertEqual(r.returncode,0,r.stderr);self.assertEqual(json.loads(r.stdout)['height'],10)
        r=self.call('inspect');self.assertEqual(json.loads(r.stdout)['observed_set_changes'],3)
        r=self.call('export','--output',self.root/'export.json');self.assertEqual(r.returncode,0,r.stderr)
        self.assertEqual(json.loads((self.root/'export.json').read_bytes()),self.f['steps'])
    def test_missing_store_does_not_create(self):
        r=self.call('inspect');self.assertEqual(r.returncode,2);self.assertFalse((self.root/'store.sqlite').exists())
    def test_preview_has_no_side_effects(self):
        (self.root/'next.json').write_bytes(encode(self.f['steps'][0]['validators']))
        (self.root/'changes.json').write_bytes(encode(self.f['plans'][0]['updates']))
        r=self.call('preview','--next-set',self.root/'next.json','--changes',self.root/'changes.json','--finalize-height',2)
        self.assertEqual(r.returncode,0,r.stderr);j=json.loads(r.stdout)
        self.assertEqual(j['active_validator_height'],4);self.assertFalse(j['activation_scheduled'])
        self.assertFalse((self.root/'store.sqlite').exists())
    def test_export_refuses_overwrite(self):
        self.call('init','--anchor',self.root/'anchor');out=self.root/'export.json';out.write_text('keep')
        self.assertEqual(self.call('export','--output',out).returncode,2);self.assertEqual(out.read_text(),'keep')
    def test_diagnostics_omit_payload_and_private_path(self):
        (self.root/'policy').write_text('{"private":"do-not-echo"}')
        r=self.call('init','--anchor',self.root/'anchor');self.assertEqual(r.returncode,2)
        self.assertNotIn('do-not-echo',r.stderr);self.assertNotIn(str(self.root),r.stderr)
    def test_no_sign_or_update_command(self):
        self.assertNotEqual(self.call('submit').returncode,0)
        self.assertFalse((self.root/'store.sqlite').exists())
    def test_demo_both_commitment_modes(self):
        r=subprocess.run([sys.executable,str(ROOT/'scripts/demo.py'),'--output',str(self.root/'demo')],capture_output=True,text=True,timeout=15)
        self.assertEqual(r.returncode,0,r.stderr);j=json.loads((self.root/'demo/result.json').read_bytes())
        self.assertEqual(len(j['reports']),2);self.assertFalse(j['activation_scheduled'])
        self.assertTrue(all(x['states'][-1]['observed_set_changes']==3 for x in j['reports']))
