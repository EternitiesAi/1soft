"""Checkout and test-runner regressions; no network, money or production keys."""
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'scripts'))
from verify_checkout import CheckoutError, verify_checkout


class CheckoutTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        (self.root/'src').mkdir()
        (self.root/'src/example.py').write_bytes(b'VALUE = 1\n')
        self.manifest = {'schema': 1, 'project': '1soft', 'scope': 'required-source-files',
            'files': [{'path': 'src/example.py', 'sha256': hashlib.sha256(b'VALUE = 1\n').hexdigest(), 'bytes': 10}]}
        self.write()
    def tearDown(self):
        self.tmp.cleanup()
    def write(self):
        (self.root/'SOURCE_MANIFEST.json').write_text(json.dumps(self.manifest))
    def test_complete_checkout(self):
        result=verify_checkout(self.root)
        self.assertEqual(result['status'],'passed');self.assertEqual(result['matched'],1)
        self.assertIs(result['consensus_verified'],False)
    def test_missing_file(self):
        (self.root/'src/example.py').unlink()
        self.assertEqual(verify_checkout(self.root)['status'],'failed')
    def test_same_size_corruption(self):
        (self.root/'src/example.py').write_text('VALUE = 2\n')
        self.assertEqual(verify_checkout(self.root)['status'],'failed')
    def test_shortened_file(self):
        (self.root/'src/example.py').write_text('')
        self.assertEqual(verify_checkout(self.root)['status'],'failed')
    def test_empty_manifest(self):
        self.manifest['files']=[];self.write()
        with self.assertRaises(CheckoutError):verify_checkout(self.root)
    def test_duplicate_entry(self):
        self.manifest['files']*=2;self.write()
        with self.assertRaises(CheckoutError):verify_checkout(self.root)
    def test_wrong_project(self):
        self.manifest['project']='other';self.write()
        with self.assertRaises(CheckoutError):verify_checkout(self.root)
    def test_boolean_schema(self):
        self.manifest['schema']=True;self.write()
        with self.assertRaises(CheckoutError):verify_checkout(self.root)
    def test_bad_digest(self):
        self.manifest['files'][0]['sha256']='not a digest';self.write()
        with self.assertRaises(CheckoutError):verify_checkout(self.root)
    def test_boolean_size(self):
        self.manifest['files'][0]['bytes']=True;self.write()
        with self.assertRaises(CheckoutError):verify_checkout(self.root)
    def test_unknown_fields(self):
        self.manifest['extra']='ignored?';self.write()
        with self.assertRaises(CheckoutError):verify_checkout(self.root)
    def test_duplicate_json_field(self):
        (self.root/'SOURCE_MANIFEST.json').write_text('{"schema":1,"schema":1}')
        with self.assertRaises(CheckoutError):verify_checkout(self.root)
    def test_path_traversal(self):
        self.manifest['files'][0]['path']='../outside.py';self.write()
        with self.assertRaises(CheckoutError):verify_checkout(self.root)
    def test_absolute_path(self):
        self.manifest['files'][0]['path']='/tmp/outside.py';self.write()
        with self.assertRaises(CheckoutError):verify_checkout(self.root)
    def test_windows_drive(self):
        self.manifest['files'][0]['path']='C:/outside.py';self.write()
        with self.assertRaises(CheckoutError):verify_checkout(self.root)
    def test_backslash_path(self):
        self.manifest['files'][0]['path']='src\\example.py';self.write()
        with self.assertRaises(CheckoutError):verify_checkout(self.root)
    def test_git_metadata_path(self):
        self.manifest['files'][0]['path']='.git/config';self.write()
        with self.assertRaises(CheckoutError):verify_checkout(self.root)
    def test_dot_path_segment(self):
        self.manifest['files'][0]['path']='src/./example.py';self.write()
        with self.assertRaises(CheckoutError):verify_checkout(self.root)
    def test_self_reference(self):
        self.manifest['files'][0]['path']='SOURCE_MANIFEST.json';self.write()
        with self.assertRaises(CheckoutError):verify_checkout(self.root)
    @unittest.skipUnless(os.name=='posix','POSIX symbolic link test')
    def test_symlinked_file(self):
        p=self.root/'src/example.py';p.rename(self.root/'target.py');p.symlink_to(self.root/'target.py')
        self.assertEqual(verify_checkout(self.root)['status'],'failed')
    @unittest.skipUnless(os.name=='posix','POSIX symbolic link test')
    def test_symlinked_parent(self):
        p=self.root/'src';p.rename(self.root/'other');p.symlink_to(self.root/'other',target_is_directory=True)
        self.assertEqual(verify_checkout(self.root)['status'],'failed')
    def test_directory_instead_of_file(self):
        p=self.root/'src/example.py';p.unlink();p.mkdir()
        self.assertEqual(verify_checkout(self.root)['status'],'failed')
    def test_missing_manifest(self):
        (self.root/'SOURCE_MANIFEST.json').unlink()
        with self.assertRaises(CheckoutError):verify_checkout(self.root)
    def test_report_lists_all_missing_files(self):
        self.manifest['files'].append({**self.manifest['files'][0], 'path':'src/missing.py'})
        self.write();(self.root/'src/example.py').unlink()
        self.assertEqual(len(verify_checkout(self.root)['errors']),2)


class RunnerTests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory();self.root=Path(self.tmp.name)
        (self.root/'src').mkdir();(self.root/'tests').mkdir()
        (self.root/'src/example.py').write_text('VALUE = 1\n')
    def tearDown(self):self.tmp.cleanup()
    def launch(self, code=None, alter=None):
        if code is not None:(self.root/'tests/test_example.py').write_text(code)
        entries=[]
        for p in sorted(self.root.rglob('*.py')):
            data=p.read_bytes();entries.append({'path':p.relative_to(self.root).as_posix(),
                'bytes':len(data),'sha256':hashlib.sha256(data).hexdigest()})
        (self.root/'SOURCE_MANIFEST.json').write_text(json.dumps({'schema':1,'project':'1soft',
            'scope':'required-source-files','files':entries}))
        if alter:alter(self.root)
        return subprocess.run([sys.executable,str(ROOT/'scripts/run_tests.py'),'--root',str(self.root)],
            capture_output=True,text=True,timeout=15)
    def test_zero_tests_is_failure(self):
        result=self.launch();self.assertEqual(result.returncode,2);self.assertIn('zero tests discovered',result.stderr)
    def test_passing_suite(self):
        result=self.launch('import unittest\nclass T(unittest.TestCase):\n def test_ok(self): self.assertTrue(True)\n')
        self.assertEqual(result.returncode,0,result.stderr);self.assertIn('"consensus_verified": false',result.stderr)
    def test_all_skipped_is_failure(self):
        result=self.launch('import unittest\nclass T(unittest.TestCase):\n @unittest.skip("not executed")\n def test_no(self): pass\n')
        self.assertEqual(result.returncode,1,result.stderr)
    def test_test_failure_is_failure(self):
        result=self.launch('import unittest\nclass T(unittest.TestCase):\n def test_bad(self): self.fail("expected")\n')
        self.assertEqual(result.returncode,1)
    def test_import_error_is_failure(self):
        result=self.launch('raise ImportError("expected")\n');self.assertEqual(result.returncode,1)
    def test_missing_source_is_failure(self):
        result=self.launch('import unittest\n',lambda r:(r/'src/example.py').unlink())
        self.assertEqual(result.returncode,2);self.assertIn('missing file',result.stderr)
    def test_corrupt_test_not_executed(self):
        result=self.launch('raise RuntimeError("should not run")\n',lambda r:(r/'tests/test_example.py').write_text('print("tampered")\n'))
        self.assertEqual(result.returncode,2);self.assertNotIn('tampered',result.stdout)
    def test_child_process_inherits_source_path(self):
        code = 'import unittest,subprocess,sys\nclass T(unittest.TestCase):\n def test_child(self):\n  p=subprocess.run([sys.executable,"-c","import example; assert example.VALUE == 1"],capture_output=True)\n  self.assertEqual(p.returncode,0,p.stderr)\n'
        result=self.launch(code);self.assertEqual(result.returncode,0,result.stderr)
    def test_runner_changes_to_checkout_directory(self):
        code = 'import unittest,pathlib\nclass T(unittest.TestCase):\n def test_cwd(self): self.assertTrue(pathlib.Path("SOURCE_MANIFEST.json").is_file())\n'
        result=self.launch(code);self.assertEqual(result.returncode,0,result.stderr)
