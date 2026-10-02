"""Actual CLI processes/PTY; only public disposable test keys and native units."""
import contextlib
import io
import json
import os
from pathlib import Path
import pty
import select
import subprocess
import sys
import tempfile
import time
import unittest
from unittest.mock import patch

from block_application import encode
from native_core import canonical
from p4_wallet import P4Wallet
from wallet_fixture import Chain,PASSWORD

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/'scripts'))
from p4_wallet_cli import main

class WalletCliTests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory();self.root=Path(self.tmp.name);self.c=Chain(self.root)
        self.path=self.root/'wallet.sqlite'
        (self.root/'genesis.json').write_bytes(self.c.genesis)
        (self.root/'policy.json').write_bytes(encode(self.c.policy))
        (self.root/'evidence.json').write_bytes(encode(self.c.evidence()))
    def tearDown(self):self.c.close();self.tmp.cleanup()
    def args(self,*args):
        return ['--genesis',str(self.root/'genesis.json'),'--policy',str(self.root/'policy.json'),
                '--wallet',str(self.path),*map(str,args)]
    def cli(self,*args):
        return subprocess.run([sys.executable,str(ROOT/'scripts/p4_wallet_cli.py'),*self.args(*args)],
                              capture_output=True,text=True,timeout=10)
    def ready(self):
        p=self.cli('init');self.assertEqual(p.returncode,0,p.stderr)
        p=self.cli('sync','--evidence',self.root/'evidence.json','--expected-revision','empty')
        self.assertEqual(p.returncode,0,p.stderr)
    def prepared(self):
        self.ready();out=self.root/'review.json'
        p=self.cli('prepare','--payer',self.c.payer,'--to',self.c.merchant,'--units','58',
            '--valid-until','30','--grant','raven','--output',out)
        self.assertEqual(p.returncode,0,p.stderr)
        return json.loads(out.read_bytes())
    def approval_args(self,q,output=None):
        return ['approve','--review',self.root/'review.json','--confirmation',q['confirmation'],
                '--vault',self.root/'raven.pem','--output',output or self.root/'signed.json']
    def terminal_approve(self,q):
        master,slave=pty.openpty()
        process=subprocess.Popen([sys.executable,str(ROOT/'scripts/p4_wallet_cli.py'),
                                  *self.args(*self.approval_args(q))],stdin=slave,stdout=slave,stderr=slave,
                                  start_new_session=True)
        os.close(slave);data=bytearray();sent=False;deadline=time.monotonic()+10
        try:
            while time.monotonic()<deadline:
                ready,_,_=select.select([master],[],[],.05)
                if ready:
                    try:chunk=os.read(master,8192)
                    except OSError:break
                    if not chunk:break
                    data.extend(chunk)
                if not sent and b'Vault passphrase:' in data:
                    os.write(master,PASSWORD+b'\n');sent=True
                if process.poll() is not None and not ready:break
            self.assertTrue(sent,'terminal did not request passphrase')
            code=process.wait(timeout=2)
            self.assertEqual(code,0,data.decode(errors='replace'))
        finally:
            if process.poll() is None:process.kill();process.wait(timeout=2)
            os.close(master)
        return bytes(data)
    def test_actual_terminal_sign_recover_and_status(self):
        q=self.prepared();before=json.loads(self.cli('status').stdout)
        self.assertEqual(before['pending_debit_units'],'0')
        output=self.terminal_approve(q)
        self.assertNotIn(PASSWORD,output)
        self.assertIn(q['confirmation'].encode(),output)
        raw=(self.root/'signed.json').read_bytes()
        self.assertEqual(json.loads(raw)['body'],q['review']['body'])
        self.assertEqual(json.loads(self.cli('status').stdout)['pending_debit_units'],'60')
        (self.root/'raven.pem').unlink()
        p=self.cli('recover','--decision-id',q['confirmation'],'--payer',self.c.payer,
                   '--grant','raven','--output',self.root/'recovered.json')
        self.assertEqual(p.returncode,0,p.stderr)
        self.assertEqual((self.root/'recovered.json').read_bytes(),raw)
    def test_cli_resolves_native_source_with_cleared_pythonpath(self):
        p=subprocess.run([sys.executable,str(ROOT/'scripts/p4_wallet_cli.py'),*self.args('init')],
            env={**os.environ,'PYTHONPATH':''},cwd=self.root,capture_output=True,text=True,timeout=10)
        self.assertEqual(p.returncode,0,p.stderr)
        self.assertEqual(json.loads(p.stdout)['status'],'empty-p4-wallet-created')

    def test_nonterminal_passphrase_fallback_refused(self):
        q=self.prepared();p=self.cli(*self.approval_args(q))
        self.assertEqual(p.returncode,2);self.assertNotIn('Vault passphrase',p.stderr)
        self.assertEqual(json.loads(self.cli('status').stdout)['pending_debit_units'],'0')
    def test_no_password_or_network_command_flags(self):
        self.assertEqual(self.cli('send').returncode,2)
        self.assertEqual(self.cli('init','--password','not-a-real-secret').returncode,2)
        self.assertFalse(self.path.exists())
    def test_output_collision_refused_before_passphrase_or_signature(self):
        q=self.prepared();out=self.root/'signed.json';out.write_bytes(b'preserve')
        with patch('p4_wallet_cli.getpass.getpass',side_effect=AssertionError('must not prompt')):
            with contextlib.redirect_stderr(io.StringIO()):
                self.assertEqual(main(self.args(*self.approval_args(q))),2)
        self.assertEqual(out.read_bytes(),b'preserve')
        self.assertEqual(json.loads(self.cli('status').stdout)['pending_debit_units'],'0')
    def test_output_failure_after_commit_retains_recoverable_signature(self):
        q=self.prepared();err=io.StringIO()
        with patch('p4_wallet_cli.getpass.getpass',return_value=PASSWORD.decode()),\
             patch('p4_wallet_cli.sys.stdin.isatty',return_value=True),\
             patch('p4_wallet_cli.write_new',side_effect=OSError('fixture output failure')),\
             contextlib.redirect_stderr(err):
            code=main(self.args(*self.approval_args(q)))
        self.assertEqual(code,2);self.assertIn('Durable decision: '+q['confirmation'],err.getvalue())
        self.assertIn('remains journaled',err.getvalue());self.assertNotIn(PASSWORD.decode(),err.getvalue())
        p=self.cli('recover','--decision-id',q['confirmation'],'--payer',self.c.payer,
                   '--grant','raven','--output',self.root/'recovered.json')
        self.assertEqual(p.returncode,0,p.stderr)
        self.assertEqual(json.loads(self.cli('status').stdout)['pending_debit_units'],'60')
    def test_missing_wallet_is_not_created_for_status(self):
        p=self.cli('status');self.assertEqual(p.returncode,2);self.assertFalse(self.path.exists())
    def test_empty_wallet_not_reported_as_zero_balance(self):
        self.assertEqual(self.cli('init').returncode,0)
        p=self.cli('status');self.assertEqual(p.returncode,2);self.assertEqual(p.stdout,'')
    def test_read_review_output_never_creates_a_hold(self):
        q=self.prepared();self.assertFalse(q['reserved'])
        self.assertEqual((self.root/'review.json').stat().st_mode&0o777,0o600)
        self.assertEqual(json.loads(self.cli('status').stdout)['pending_debit_units'],'0')
    def test_bad_amount_has_no_effect(self):
        self.ready()
        p=self.cli('prepare','--payer',self.c.payer,'--to',self.c.merchant,'--units','1.5',
                   '--valid-until','30','--output',self.root/'bad.json')
        self.assertEqual(p.returncode,2);self.assertFalse((self.root/'bad.json').exists())
    def test_untrusted_input_not_echoed_by_error_diagnostic(self):
        self.ready();(self.root/'evidence.json').write_text('{"secret":"fixture-private-text"}')
        p=self.cli('sync','--evidence',self.root/'evidence.json','--expected-revision','bad')
        self.assertEqual(p.returncode,2);self.assertNotIn('fixture-private-text',p.stderr)
        self.assertNotIn(str(self.root),p.stderr)

if __name__=='__main__':unittest.main()
