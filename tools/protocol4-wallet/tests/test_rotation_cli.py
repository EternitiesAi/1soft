"""Actual command flows with encrypted disposable vaults and owned terminals."""
import fcntl
import importlib.util
import json
import os
from pathlib import Path
import pty
import select
import subprocess
import sys
import termios
import time
import unittest
import warnings
import io
from contextlib import redirect_stderr, redirect_stdout
from unittest.mock import patch
import test_rotation as fixtures
from wallet_fixture import PASSWORD


class RotationCliTests(unittest.TestCase):
    setUp=fixtures.RotationTests.setUp
    prepare=fixtures.RotationTests.prepare
    accept=fixtures.RotationTests.accept
    approve=fixtures.RotationTests.approve

    def cli(self,args,terminal=False):
        script=Path(__file__).resolve().parents[1]/'scripts/p4_rotation_cli.py'
        self.assertTrue(script.exists(),'explicit rotation CLI missing')
        g=self.root/'genesis.json';p=self.root/'policy.json'
        g.write_bytes(self.c.genesis);p.write_text(json.dumps(self.c.policy))
        command=[sys.executable,'-B',str(script),'--genesis',str(g),'--policy',str(p),'--wallet',str(self.wp),*args]
        if not terminal:return subprocess.run(command,input=b'',capture_output=True,timeout=15)
        master,slave=pty.openpty();proc=None
        try:
            def own():
                os.setsid();fcntl.ioctl(0,termios.TIOCSCTTY,0)
            proc=subprocess.Popen(command,stdin=slave,stdout=slave,stderr=slave,preexec_fn=own)
            os.close(slave);slave=None;output=bytearray();sent=False;deadline=time.monotonic()+15
            while time.monotonic()<deadline:
                if select.select([master],[],[],.1)[0]:
                    try:chunk=os.read(master,65536)
                    except OSError:break
                    if not chunk:break
                    output.extend(chunk)
                    if b'Vault password:' in output and not sent:
                        os.write(master,PASSWORD+b'\n');sent=True
                if proc.poll() is not None:
                    while select.select([master],[],[],.1)[0]:
                        try:chunk=os.read(master,65536)
                        except OSError:break
                        if not chunk:break
                        output.extend(chunk)
                    break
            if proc.poll() is None:proc.kill()
            code=proc.wait(timeout=5);self.assertNotIn(PASSWORD,output)
            return subprocess.CompletedProcess(command,code,bytes(output),b'')
        finally:
            if proc is not None and proc.poll() is None:proc.kill();proc.wait(timeout=5)
            os.close(master)
            if slave is not None:os.close(slave)

    def review_file(self,q):
        path=self.root/'review.json';path.write_text(json.dumps(q['review']));path.chmod(0o600);return path

    def test_nonterminal_has_no_secret_fallback_or_reservation(self):
        q=self.prepare();path=self.review_file(q);output=self.root/'accepted.json'
        r=self.cli(['accept','--review',str(path),'--confirmation',q['confirmation'],'--vault',str(self.vault),'--output',str(output)])
        self.assertNotEqual(r.returncode,0);self.assertIn(b'terminal',r.stderr.lower())
        self.assertFalse(output.exists());self.assertEqual(self.w.status()['pending_debit_units'],'0')

    def test_actual_terminal_prepare_accept_approve_and_exact_recover(self):
        review=self.root/'prepared.json';accepted=self.root/'accepted.json';wire=self.root/'wire.json'
        r=self.cli(['prepare','--payer',self.c.payer,'--new-public-key',fixtures.public(self.new),'--valid-until','30','--output',str(review)])
        self.assertEqual(r.returncode,0,r.stderr.decode());q=json.loads(r.stdout)
        r=self.cli(['accept','--review',str(review),'--confirmation',q['confirmation'],'--vault',str(self.vault),'--output',str(accepted)],True)
        self.assertEqual(r.returncode,0,r.stdout.decode());a=json.loads(accepted.read_bytes())
        from p4_evidence import content_id
        did=content_id(a)
        r=self.cli(['approve','--review',str(accepted),'--confirmation',did,'--vault',str(self.root/'owner.pem'),'--output',str(wire)],True)
        self.assertEqual(r.returncode,0,r.stdout.decode());self.assertIn(did.encode(),r.stdout)
        self.c.now=time.time_ns()  # Child CLI uses the real clock; do not regress it.
        self.assertEqual(self.w.status()['pending_debit_units'],'2')
        self.assertEqual(wire.stat().st_mode&0o777,0o600)
        recovered=self.root/'recovered.json'
        r=self.cli(['recover','--decision-id',did,'--payer',self.c.payer,'--output',str(recovered)])
        self.assertEqual(r.returncode,0,r.stderr.decode());self.assertEqual(wire.read_bytes(),recovered.read_bytes())

    def test_existing_and_database_sidecar_outputs_refused_before_approval(self):
        q=self.accept();path=self.review_file(q);output=self.root/'wire.json';output.write_bytes(b'preserve');output.chmod(0o600)
        for target in (output,Path(str(self.wp)+'-journal'),self.vault,path):
            r=self.cli(['approve','--review',str(path),'--confirmation',q['confirmation'],'--vault',str(self.root/'owner.pem'),'--output',str(target)])
            self.assertNotEqual(r.returncode,0)
            self.assertNotIn(b'terminal',r.stderr.lower())
        self.assertEqual(output.read_bytes(),b'preserve');self.assertEqual(self.w.status()['decisions'],[])

    def module(self):
        script=Path(__file__).resolve().parents[1]/'scripts/p4_rotation_cli.py'
        spec=importlib.util.spec_from_file_location('rotation_cli_fixture',script)
        cli=importlib.util.module_from_spec(spec);spec.loader.exec_module(cli);return cli

    def test_echo_control_failure_refuses_password_fallback(self):
        cli=self.module()
        def unavailable(*args,**kw):
            warnings.warn('echo cannot be disabled',cli.getpass.GetPassWarning)
            self.fail('echoed fallback reached')
        with patch.object(cli.sys.stdin,'isatty',return_value=True),patch.object(cli.sys.stderr,'isatty',return_value=True),patch.object(cli.getpass,'getpass',side_effect=unavailable):
            with self.assertRaisesRegex(ValueError,'echo'):cli.password()

    def test_lost_output_after_commit_retains_decision_and_explicit_recovery_marker(self):
        cli=self.module();q=self.accept();path=self.review_file(q)
        g=self.root/'genesis.json';p=self.root/'policy.json'
        g.write_bytes(self.c.genesis);p.write_text(json.dumps(self.c.policy));output=self.root/'lost-wire.json'
        argv=['rotation','--genesis',str(g),'--policy',str(p),'--wallet',str(self.wp),
              'approve','--review',str(path),'--confirmation',q['confirmation'],
              '--vault',str(self.root/'owner.pem'),'--output',str(output)]
        err=io.StringIO()
        with patch.object(cli.sys,'argv',argv),patch.object(cli,'password',return_value=PASSWORD),patch.object(cli,'publish_new',side_effect=OSError('injected post-commit output loss')),redirect_stderr(err),redirect_stdout(io.StringIO()):
            self.assertEqual(cli.main(),2)
        self.c.now=time.time_ns()
        self.assertIn(q['confirmation'],err.getvalue());self.assertIn('Recover',err.getvalue())
        self.assertEqual(self.w.status()['pending_debit_units'],'2');self.assertFalse(output.exists())
        wire=self.w.recover(q['confirmation'],payer=self.c.payer)
        self.assertEqual(json.loads(wire)['body'],q['review']['body'])
        with self.assertRaises(ValueError):self.approve(q)


if __name__=='__main__':unittest.main()
