"""Main CLI routing and readonly prerequisite diagnostics, using real child CLIs."""
from pathlib import Path
import json
import os
import shutil
import subprocess
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[3]
CLI = ROOT/'tools/local-platform/scripts/1soft.py'
PIN = '218628da07bed5d27e178d38d0bef9ecf46f21b214c8e9fea402fd215fccc024'

class CurrentEntrypointTests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory(prefix='1soft-entrypoint-test-')
        self.base=Path(self.tmp.name); self.base.chmod(0o700)
        self.root=self.base/'checkout'; self.root.mkdir()
        self.cli=self.root/'tools/local-platform/scripts/1soft.py'
        self.cli.parent.mkdir(parents=True)
        shutil.copyfile(CLI,self.cli)
        preflight=ROOT/'tools/local-platform/src/platform_preflight.py'
        if preflight.exists():
            target=self.root/'tools/local-platform/src/platform_preflight.py'
            target.parent.mkdir(parents=True); shutil.copyfile(preflight,target)
        shutil.copyfile(ROOT/'requirements.txt',self.root/'requirements.txt')
        release=self.root/'tools/release'; release.mkdir(parents=True)
        # Replace only the expensive external checker boundary. The real CLI
        # selects/executes this child; no full-suite or consensus pass is claimed.
        (release/'check_current.py').write_text('''import argparse,json,os
from pathlib import Path
p=argparse.ArgumentParser();p.add_argument('--output',type=Path,required=True)
p.add_argument('--timeout',type=int,default=600);a=p.parse_args()
if a.output.exists(): raise SystemExit(3)
a.output.mkdir();(a.output/'route.json').write_text(json.dumps({
'checker':'current-fixture','timeout':a.timeout,'pythonpath':os.environ.get('PYTHONPATH')}))
raise SystemExit(int(os.environ.get('ENTRYPOINT_TEST_RETURN','0')))
''')
    def tearDown(self): self.tmp.cleanup()
    def launch(self,*args,no_site=False,env_extra=None):
        env=os.environ.copy();env.pop('PYTHONHOME',None);env.pop('PYTHONPATH',None)
        env['PYTHONDONTWRITEBYTECODE']='1'
        if env_extra:env.update(env_extra)
        command=[sys.executable,'-B']+(['-S'] if no_site else [])+[str(self.cli),*map(str,args)]
        return subprocess.run(command,cwd=self.base,env=env,stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=30)
    def diagnostic(self,*args,no_site=False):
        result=self.launch('doctor',*args,no_site=no_site)
        self.assertNotIn(b'Traceback',result.stderr)
        return result,json.loads(result.stdout)
    def test_help_works_without_application_modules_or_site_packages(self):
        result=self.launch('--help',no_site=True)
        self.assertEqual(0,result.returncode,result.stderr)
        self.assertIn(b'doctor',result.stdout);self.assertIn(b'check',result.stdout)
    def test_check_routes_current_checker_and_clears_inherited_import_path(self):
        output=self.base/'evidence'
        result=self.launch('check','--output',output,'--timeout','47',
            env_extra={'PYTHONPATH':'/untrusted-unused-import-path'})
        self.assertEqual(0,result.returncode,result.stderr)
        record=json.loads((output/'route.json').read_text())
        self.assertEqual('current-fixture',record['checker'])
        self.assertEqual(47,record['timeout']);self.assertIsNone(record['pythonpath'])
        self.assertFalse((self.root/'src').exists())
    def test_current_checker_failure_exit_is_not_converted_into_success(self):
        output=self.base/'failed-evidence'
        result=self.launch('check','--output',output,env_extra={'ENTRYPOINT_TEST_RETURN':'7'})
        self.assertEqual(7,result.returncode,result.stderr)
        self.assertTrue((output/'route.json').is_file())
    def test_current_checker_preserves_existing_output(self):
        output=self.base/'existing';output.mkdir();(output/'valuable').write_bytes(b'save')
        result=self.launch('check','--output',output)
        self.assertEqual(3,result.returncode,result.stderr)
        self.assertEqual(b'save',(output/'valuable').read_bytes())
        self.assertEqual(['valuable'],[p.name for p in output.iterdir()])
    def test_doctor_reports_missing_dependencies_without_importing_application(self):
        result,report=self.diagnostic(no_site=True)
        self.assertEqual(1,result.returncode)
        self.assertEqual('needs_attention',report['status'])
        self.assertFalse(report['production_qualified'])
        self.assertTrue(all(x['status']=='missing' for x in report['dependencies']))
        self.assertEqual('not_provided',report['engine']['status'])
        self.assertFalse((self.root/'src').exists())
    def test_doctor_never_executes_a_wrong_engine_or_creates_workspace(self):
        marker=self.base/'engine-executed';engine=self.base/'fake-engine'
        engine.write_text('#!/bin/sh\ntouch "'+str(marker)+'"\n');engine.chmod(0o700)
        before=engine.read_bytes()
        result,report=self.diagnostic('--engine',engine)
        self.assertEqual(1,result.returncode)
        self.assertEqual('hash_mismatch',report['engine']['status'])
        self.assertFalse(marker.exists());self.assertEqual(before,engine.read_bytes())
        self.assertEqual(PIN,report['engine']['expected_sha256'])
        self.assertFalse(report['network_started']);self.assertFalse(report['files_modified'])
    def test_doctor_distinguishes_missing_and_aliased_engine(self):
        result,report=self.diagnostic('--engine',self.base/'missing')
        self.assertEqual(1,result.returncode);self.assertEqual('missing',report['engine']['status'])
        target=self.base/'target';target.write_bytes(b'not engine');target.chmod(0o700)
        alias=self.base/'alias';alias.symlink_to(target)
        result,report=self.diagnostic('--engine',alias)
        self.assertEqual(1,result.returncode);self.assertEqual('unsafe_file',report['engine']['status'])
    def test_doctor_refuses_non_regular_engine_without_blocking_on_fifo(self):
        fifo=self.base/'fifo';os.mkfifo(fifo)
        result,report=self.diagnostic('--engine',fifo)
        self.assertEqual(1,result.returncode);self.assertEqual('unsafe_file',report['engine']['status'])
    def test_doctor_reports_wrong_dependency_pin_as_mismatch(self):
        (self.root/'requirements.txt').write_text('cryptography==0.0.0\n')
        result,report=self.diagnostic()
        self.assertEqual(1,result.returncode)
        self.assertEqual('mismatch',report['dependencies'][0]['status'])
    def test_doctor_rejects_unrecognized_requirement_syntax(self):
        (self.root/'requirements.txt').write_text('cryptography>=46\n')
        result,report=self.diagnostic()
        self.assertEqual(1,result.returncode)
        self.assertEqual('invalid_pins',report['dependency_pin_status'])
    def test_doctor_refuses_hardlinked_engine_without_hashing_or_execution(self):
        target=self.base/'target';target.write_bytes(b'not engine');target.chmod(0o700)
        alias=self.base/'hardlink';os.link(target,alias)
        result,report=self.diagnostic('--engine',alias)
        self.assertEqual(1,result.returncode);self.assertEqual('unsafe_file',report['engine']['status'])
        self.assertNotIn('observed_sha256',report['engine'])
    def test_doctor_refuses_oversized_engine_without_reading_it(self):
        engine=self.base/'oversized'
        with engine.open('wb') as f:f.truncate(256*1024*1024+1)
        engine.chmod(0o700)
        result,report=self.diagnostic('--engine',engine)
        self.assertEqual(1,result.returncode);self.assertEqual('unsafe_file',report['engine']['status'])
        self.assertNotIn('observed_sha256',report['engine'])
    def test_doctor_rejects_duplicate_normalized_pins(self):
        (self.root/'requirements.txt').write_text('cryptography==46.0.4\nCryptography==46.0.4\n')
        result,report=self.diagnostic()
        self.assertEqual(1,result.returncode)
        self.assertEqual('invalid_pins',report['dependency_pin_status'])
    def test_dependency_pin_reader_is_bounded_before_parsing(self):
        import importlib.util
        from unittest.mock import patch
        helper=self.root/'tools/local-platform/src/platform_preflight.py'
        spec=importlib.util.spec_from_file_location('entrypoint_preflight_under_test',helper)
        module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module)
        reads=[]
        class BoundedRead:
            def __enter__(self):return self
            def __exit__(self,*args):return False
            def read(self,limit=-1):
                reads.append(limit)
                if limit<0:raise AssertionError('pin reader attempted an unbounded read')
                return b'#'+b'x'*65536
        with patch.object(Path,'open',return_value=BoundedRead()):
            state,records=module.dependency_checks(self.root)
        self.assertEqual('invalid_pins',state);self.assertEqual([],records)
        self.assertEqual([65537],reads)
    def test_help_does_not_create_diagnostic_or_runtime_files(self):
        before={p.relative_to(self.base) for p in self.base.rglob('*')}
        result=self.launch('doctor','--help',no_site=True)
        self.assertEqual(0,result.returncode,result.stderr)
        self.assertEqual(before,{p.relative_to(self.base) for p in self.base.rglob('*')})

if __name__=='__main__':unittest.main()
