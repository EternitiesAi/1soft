import copy
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from commit_verifier import encode
from validator_sets import document_id
from validator_witness import start_witness, extend_witness, verify_witness
from transition_io import write_new, read_json
from transition_fixture import scenario

ROOT=Path(__file__).resolve().parents[1]

class FileAndCliTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):cls.c=scenario()
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory();self.root=Path(self.tmp.name)
        for name,data in (('genesis',self.c['genesis']),('policy',encode(self.c['policy'])),
                          ('entry',encode(self.c['entries'][0])),('entries',encode(self.c['entries'][1:])),
                          ('old',encode(self.c['old'])),('new',encode(self.c['new']))):
            (self.root/(name+'.json')).write_bytes(data)
    def tearDown(self):self.tmp.cleanup()
    def call(self,*args):
        return subprocess.run([sys.executable,str(ROOT/'scripts/transitions.py'),
            '--genesis',str(self.root/'genesis.json'),'--policy',str(self.root/'policy.json'),*map(str,args)],
            capture_output=True,text=True,timeout=10,env={**os.environ,'PYTHONPATH':''})
    def test_actual_cli_draft_start_extend_reopen_and_audit(self):
        draft=self.root/'draft.json';old=self.root/'start.json';new=self.root/'continued.json'
        p=self.call('draft','--current-set',self.root/'old.json','--new-set',self.root/'new.json',
            '--expected-current-hash',self.c['sets']['old'].hash,'--emitted-height','3','--output',draft)
        self.assertEqual(p.returncode,0,p.stderr);self.assertFalse(json.loads(p.stdout)['activation_performed'])
        p=self.call('start','--entry',self.root/'entry.json','--output',old)
        self.assertEqual(p.returncode,0,p.stderr);before=old.read_bytes()
        parent=json.loads(p.stdout)['witness_sha256']
        p=self.call('extend','--witness',old,'--entries',self.root/'entries.json',
            '--expected-parent-sha256',parent,'--output',new)
        self.assertEqual(p.returncode,0,p.stderr);self.assertEqual(old.read_bytes(),before)
        p=self.call('verify','--witness',new);self.assertEqual(p.returncode,0,p.stderr)
        self.assertEqual(json.loads(p.stdout)['final_height'],12)
        p=self.call('audit','--witness',new,'--draft',draft);self.assertEqual(p.returncode,0,p.stderr)
        self.assertFalse(json.loads(p.stdout)['governance_authorization_established'])
    def test_existing_output_never_replaced(self):
        out=self.root/'unchanged';out.write_text('preserve')
        p=self.call('start','--entry',self.root/'entry.json','--output',out)
        self.assertEqual(p.returncode,2);self.assertEqual(out.read_text(),'preserve')
    def test_wrong_parent_writes_no_new_proof(self):
        out=self.root/'first';self.call('start','--entry',self.root/'entry.json','--output',out)
        p=self.call('extend','--witness',out,'--entries',self.root/'entries.json',
            '--expected-parent-sha256','0'*64,'--output',self.root/'bad')
        self.assertEqual(p.returncode,2);self.assertFalse((self.root/'bad').exists())
    def test_output_files_are_private(self):
        path=self.root/'proof.json';write_new(path,{'x':1})
        self.assertEqual(path.stat().st_mode&0o777,0o600)
    def test_symlink_target_refused(self):
        saved=self.root/'keep';saved.write_text('same');alias=self.root/'alias';alias.symlink_to(saved)
        with self.assertRaises(OSError):write_new(alias,{'x':1})
        self.assertEqual(saved.read_text(),'same')
    def test_symlink_parent_refused(self):
        p=self.root/'alias';p.symlink_to(self.root,target_is_directory=True)
        with self.assertRaises(ValueError):write_new(p/'bad',{})
    def test_duplicate_json_fields_refused(self):
        p=self.root/'bad';p.write_text('{"schema":1,"schema":1}')
        with self.assertRaises(ValueError):read_json(p)
    def test_truncated_proof_not_complete(self):
        p=self.root/'bad';p.write_bytes(b'{"entries":[')
        r=self.call('verify','--witness',p);self.assertEqual(r.returncode,2)
    def test_bad_input_diagnostics_do_not_echo_payload(self):
        p=self.root/'bad';p.write_text('{"private":"DO-NOT-ECHO"}')
        r=self.call('verify','--witness',p);self.assertEqual(r.returncode,2)
        self.assertNotIn('DO-NOT-ECHO',r.stderr);self.assertNotIn(str(self.root),r.stderr)
    def test_demo_saved_proof_is_immediately_readable_by_real_clock_cli(self):
        out=self.root/'demo'
        p=subprocess.run([sys.executable,str(ROOT/'scripts/demo.py'),'--output',str(out)],
                          capture_output=True,text=True,timeout=10)
        self.assertEqual(p.returncode,0,p.stderr)
        p=subprocess.run([sys.executable,str(ROOT/'scripts/transitions.py'),'--genesis',str(out/'genesis.json'),
                          '--policy',str(out/'policy.json'),'verify','--witness',str(out/'active-witness.json')],
                          capture_output=True,text=True,timeout=10)
        self.assertEqual(p.returncode,0,p.stderr)
    def test_no_activate_or_sign_command(self):
        for command in ('activate','sign','broadcast'):
            with self.subTest(command=command):self.assertNotEqual(self.call(command).returncode,0)
    def test_proof_file_reopen_uses_original_external_policy(self):
        first=start_witness(self.c['entries'][0],self.c['genesis'],self.c['policy'],now_ns=self.c['now_ns'])
        path=self.root/'first';write_new(path,first)
        again=read_json(path)
        result=extend_witness(again,self.c['entries'][1:],self.c['genesis'],self.c['policy'],
            expected_parent_sha256=document_id(first),now_ns=self.c['now_ns'])
        write_new(self.root/'second',result)
        self.assertEqual(verify_witness(read_json(self.root/'second'),self.c['genesis'],self.c['policy'],now_ns=self.c['now_ns'])['final_height'],12)
    def test_expired_policy_does_not_destroy_proof_file(self):
        out=self.root/'first';self.call('start','--entry',self.root/'entry.json','--output',out);before=out.read_bytes()
        p={**self.c['policy'],'trust_period_seconds':1};(self.root/'policy.json').write_bytes(encode(p))
        result=self.call('verify','--witness',out);self.assertEqual(result.returncode,2)
        self.assertEqual(out.read_bytes(),before)

if __name__=='__main__':unittest.main()
