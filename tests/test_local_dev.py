"""Local runner controls, not additional blockchain consensus tests."""
import hashlib
import io
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch
ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/'scripts'))
import local_dev


class LocalRunnerTests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory();self.root=Path(self.tmp.name)
    def tearDown(self):self.tmp.cleanup()
    def manifest(self):
        entries=[]
        for path in sorted(local_dev.CORE_FILES | {'src/not-published.py'}):
            data=b''
            if path in local_dev.CORE_FILES:
                p=self.root/path;p.parent.mkdir(parents=True,exist_ok=True);p.write_bytes(data)
            entries.append({'path':path,'sha256':hashlib.sha256(data).hexdigest(),'bytes':0})
        (self.root/'SOURCE_MANIFEST.json').write_text(json.dumps({'schema':1,'project':'1soft','scope':'required-source-files','files':entries}))
    def test_core_subset_explicitly_reports_incomplete_full_checkout(self):
        self.manifest();r=local_dev.check_source(self.root,'core')
        self.assertEqual(r['status'],'passed');self.assertEqual(r['complete_source_status'],'failed')
    def test_full_gate_remains_failed(self):
        self.manifest();self.assertEqual(local_dev.check_source(self.root,'full')['status'],'failed')
    def test_missing_core_file_rejected(self):
        self.manifest();(self.root/'scripts/wallet.py').unlink()
        self.assertEqual(local_dev.check_source(self.root,'core')['status'],'failed')
    def test_modified_core_file_rejected(self):
        self.manifest();(self.root/'src/native_core.py').write_text('changed')
        self.assertEqual(local_dev.check_source(self.root,'core')['status'],'failed')
    def test_manifest_cannot_omit_core_requirement(self):
        self.manifest();p=self.root/'SOURCE_MANIFEST.json';m=json.loads(p.read_text());m['files']=m['files'][1:];p.write_text(json.dumps(m))
        with self.assertRaises(ValueError):local_dev.check_source(self.root,'core')
    def test_real_child_pass(self):
        r=local_dev.run_step([sys.executable,'-c','print("ok")'],self.root,self.root,'pass')
        self.assertEqual(r['status'],'passed');self.assertEqual((self.root/'pass.log').read_text(),'ok\n')
    def test_real_child_failure(self):
        r=local_dev.run_step([sys.executable,'-c','raise SystemExit(3)'],self.root,self.root,'fail')
        self.assertEqual(r['status'],'failed');self.assertEqual(r['returncode'],3)
    def test_missing_command_unassessed(self):
        r=local_dev.run_step(['/this-command-does-not-exist'],self.root,self.root,'missing')
        self.assertEqual(r['status'],'unassessed')
    def test_real_timeout_stops_child(self):
        r=local_dev.run_step([sys.executable,'-c','import time;time.sleep(30)'],self.root,self.root,'timeout',timeout=1)
        self.assertEqual(r['status'],'failed');self.assertIn('timed out',r['reason'])
    def test_log_never_overwritten(self):
        (self.root/'same.log').write_text('old')
        with self.assertRaises(FileExistsError):local_dev.run_step([sys.executable,'-c','pass'],self.root,self.root,'same')
        self.assertEqual((self.root/'same.log').read_text(),'old')
    def test_existing_output_directory_refused(self):
        with patch('sys.stdout',new_callable=io.StringIO),patch('local_dev.ROOT',self.root):
            code=local_dev.main(['test','--output',str(self.root)])
        self.assertEqual(code,1)
    def test_engine_build_needs_explicit_download_consent(self):
        out=self.root/'evidence'
        with patch('sys.stdout',new_callable=io.StringIO),patch('local_dev.ROOT',self.root),patch('local_dev.run_step') as child:
            self.assertEqual(local_dev.main(['build-engine','--output',str(out)]),2)
            child.assert_not_called()
        self.assertFalse(json.loads((out/'result.json').read_text())['consensus_verified'])
    def test_missing_engine_is_not_mocked(self):
        self.manifest();(self.root/'src/not-published.py').write_bytes(b'')
        with patch('sys.stdout',new_callable=io.StringIO),patch('local_dev.ROOT',self.root),patch('local_dev.run_step') as child:
            code=local_dev.main(['network','--output',str(self.root/'evidence')]);child.assert_not_called()
        self.assertEqual(code,2)
    def test_zero_test_core_subset_fails(self):
        self.manifest()
        with patch('sys.stdout',new_callable=io.StringIO),patch('local_dev.ROOT',self.root):
            code=local_dev.main(['test','--scope','core','--output',str(self.root/'evidence')])
        self.assertEqual(code,1)
    def test_doctor_does_not_execute_engine(self):
        with patch('local_dev.run_step',side_effect=AssertionError('no processes')):
            self.assertFalse(local_dev.inspect(self.root,None)['engine_executed'])



    def test_pass_label_cannot_hide_failed_check(self):
        self.assertFalse(local_dev.gate_passed({'status':'passed','checks':[{'passed':False}]}))
    def test_empty_checks_not_pass(self):
        self.assertFalse(local_dev.gate_passed({'status':'passed','checks':[]}))
    def test_truthy_nonboolean_check_not_pass(self):
        self.assertFalse(local_dev.gate_passed({'status':'passed','checks':[{'passed':'true'}]}))
    def test_unassessed_not_pass(self):
        self.assertFalse(local_dev.gate_passed({'status':'unassessed','checks':[{'passed':True}]}))
    def test_consistent_pass_report(self):
        self.assertTrue(local_dev.gate_passed({'status':'passed','checks':[{'passed':True}]}))

if __name__=='__main__':unittest.main()
