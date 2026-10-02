"""PTY command flows using disposable journals, never production custody."""
import json
import fcntl
import os
from pathlib import Path
import pty
import select
import subprocess
import sys
import time
import termios
import unittest
import importlib.util
import warnings
import io
import sqlite3
from contextlib import redirect_stderr
from unittest.mock import patch

import test_custody as helpers
BACKUP_PASSWORD = helpers.BACKUP_PASSWORD


class CustodyCliTests(helpers.CustodyTests):
    # Use setup helpers without inheriting/duplicating the core test inventory.
    __unittest_skip__ = False

    def cli(self, command, *, terminal=False):
        path = Path(__file__).resolve().parents[1]/'scripts/p4_custody_cli.py'
        self.assertTrue(path.exists(), 'custody command-line feature is missing')
        genesis, policy = self.root/'genesis.json', self.root/'policy.json'
        genesis.write_bytes(self.c.genesis); policy.write_text(json.dumps(self.c.policy))
        args = [sys.executable, '-B', str(path), '--genesis', str(genesis), '--policy', str(policy), *command]
        if not terminal:
            return subprocess.run(args, input=b'', capture_output=True, timeout=15)
        master, slave = pty.openpty()
        proc = None
        try:
            def own_terminal():
                os.setsid()
                fcntl.ioctl(0, termios.TIOCSCTTY, 0)
            proc = subprocess.Popen(args, stdin=slave, stdout=slave, stderr=slave,
                                    preexec_fn=own_terminal)
            os.close(slave); slave = None
            output = bytearray(); sent = set(); deadline = time.monotonic()+15
            prompts = (b'Backup passphrase:', b'Repeat backup passphrase:')
            while time.monotonic() < deadline:
                if select.select([master], [], [], .1)[0]:
                    try: chunk = os.read(master, 65536)
                    except OSError: break
                    if not chunk: break
                    output.extend(chunk)
                    for prompt in prompts:
                        if prompt in output and prompt not in sent:
                            os.write(master, BACKUP_PASSWORD+b'\n'); sent.add(prompt)
                if proc.poll() is not None:
                    # Drain any remaining result before reading the artifact.
                    while select.select([master], [], [], .1)[0]:
                        try: chunk = os.read(master, 65536)
                        except OSError: break
                        if not chunk: break
                        output.extend(chunk)
                    break
            if proc.poll() is None: proc.kill()
            code = proc.wait(timeout=5)
            self.assertNotIn(BACKUP_PASSWORD, bytes(output))
            return subprocess.CompletedProcess(args, code, bytes(output), b'')
        finally:
            if proc is not None and proc.poll() is None: proc.kill(); proc.wait(timeout=5)
            os.close(master)
            if slave is not None: os.close(slave)

    def backup_args(self):
        return ['backup', '--wallet', str(self.wp), '--delivery', str(self.dp),
                '--endpoint', self.d.endpoint, '--output', str(self.bp)]

    def test_nonterminal_backup_has_no_password_fallback_or_artifact(self):
        result = self.cli(self.backup_args())
        self.assertNotEqual(result.returncode, 0)
        self.assertIn(b'terminal', result.stderr.lower())
        self.assertFalse(self.bp.exists())

    def test_terminal_without_echo_control_refuses_before_password_fallback(self):
        path = Path(__file__).resolve().parents[1]/'scripts/p4_custody_cli.py'
        spec = importlib.util.spec_from_file_location('custody_cli_fixture', path)
        cli = importlib.util.module_from_spec(spec); spec.loader.exec_module(cli)
        def echo_unavailable(*args, **kwargs):
            warnings.warn('fixture terminal cannot hide input', cli.getpass.GetPassWarning)
            self.fail('echoed password fallback was reached')
        for confirm in (False, True):
            with patch.object(cli.sys.stdin, 'isatty', return_value=True), \
                 patch.object(cli.sys.stderr, 'isatty', return_value=True), \
                 patch.object(cli.getpass, 'getpass', side_effect=echo_unavailable):
                with self.assertRaisesRegex(ValueError, 'echo'):
                    cli.password(confirm=confirm)

    def test_eof_and_database_busy_are_controlled_refusals(self):
        path = Path(__file__).resolve().parents[1]/'scripts/p4_custody_cli.py'
        spec = importlib.util.spec_from_file_location('custody_cli_error_fixture', path)
        cli = importlib.util.module_from_spec(spec); spec.loader.exec_module(cli)
        genesis, policy = self.root/'genesis.json', self.root/'policy.json'
        genesis.write_bytes(self.c.genesis); policy.write_text(json.dumps(self.c.policy))
        argv = ['custody', '--genesis', str(genesis), '--policy', str(policy), *self.backup_args()]
        for failure in (EOFError('input ended'), sqlite3.OperationalError('database is locked')):
            stderr = io.StringIO()
            with patch.object(cli.sys, 'argv', argv), \
                 patch.object(cli, 'password', side_effect=failure), redirect_stderr(stderr):
                self.assertEqual(cli.main(), 2)
            self.assertIn('Recovery refused', stderr.getvalue())
            self.assertNotIn('Traceback', stderr.getvalue())
            self.assertFalse(self.bp.exists())

    def test_real_terminal_backup_restore_and_wire_export(self):
        before = self.rows()
        result = self.cli(self.backup_args(), terminal=True)
        self.assertEqual(result.returncode, 0, result.stdout.decode())
        result = self.cli(['restore', '--backup', str(self.bp), '--output', str(self.ap)], terminal=True)
        self.assertEqual(result.returncode, 0, result.stdout.decode())
        result = self.cli(['status', '--archive', str(self.ap)])
        self.assertEqual(result.returncode, 0, result.stderr.decode())
        self.assertEqual(json.loads(result.stdout)['pending_debit_units'], '100')
        wire = self.root/'recovered.json'
        result = self.cli(['recover', '--archive', str(self.ap), '--decision-id', self.raven,
                           '--payer', self.c.payer, '--grant', 'raven', '--output', str(wire)])
        self.assertEqual(result.returncode, 0, result.stderr.decode())
        self.assertEqual(wire.read_bytes(), self.w.recover(self.raven, **self.select()))
        self.assertEqual(self.rows(), before)

    def test_wrong_role_existing_output_and_archive_sidecar_exports_are_refused(self):
        with self.roundtrip(): pass
        output = self.root/'wire.json'
        args = ['recover', '--archive', str(self.ap), '--decision-id', self.raven,
                '--payer', self.c.payer, '--grant', 'atlas', '--output', str(output)]
        result = self.cli(args)
        self.assertNotEqual(result.returncode, 0)
        self.assertFalse(output.exists())
        args[args.index('atlas')] = 'raven'
        output.write_bytes(b'preserve existing export'); output.chmod(0o600)
        result = self.cli(args)
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(output.read_bytes(), b'preserve existing export')
        sidecar = Path(str(self.ap)+'-journal')
        args[-1] = str(sidecar)
        result = self.cli(args)
        self.assertNotEqual(result.returncode, 0)
        self.assertFalse(sidecar.exists())


# Unittest treats inherited test methods as new test IDs. Keep this class's
# command-specific inventory independent of the core behavior suite.
for _name in vars(helpers.CustodyTests):
    if _name.startswith('test_') and _name not in vars(CustodyCliTests):
        setattr(CustodyCliTests, _name, None)

if __name__ == '__main__': unittest.main()
