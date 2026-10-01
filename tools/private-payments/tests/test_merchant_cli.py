"""Actual CLI processes: parser/file guards run before engine or financial work.

Successful engine-backed CLI callers belong to the independently scheduled actual
validator profile. These tests never initialize/start engines or unlock keys.
"""
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

from local_devnet import private_new, read_private

ROOT = Path(__file__).resolve().parents[3]
CLI = ROOT / 'tools/private-payments/scripts/1soft_merchant.py'


class MerchantCLITests(unittest.TestCase):
    def setUp(self):
        self.assertTrue(CLI.is_file(), 'explicit merchant CLI is missing')
        self.tmp = tempfile.TemporaryDirectory(); self.root = Path(self.tmp.name); self.root.chmod(0o700)
        self.addCleanup(self.tmp.cleanup)

    def run_cli(self, *args):
        return subprocess.run([sys.executable, str(CLI), *map(str, args)],
            capture_output=True, timeout=10, env={**os.environ, 'PYTHONDONTWRITEBYTECODE': '1'})

    def context(self): return ['--workspace', self.root / 'not-initialized', '--engine', self.root / 'absent-engine']

    def assert_refused(self, result, secret=None):
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(result.stdout, b'')
        self.assertLess(len(result.stderr), 512)
        if secret is not None: self.assertNotIn(secret.encode(), result.stderr)

    def test_help_exposes_only_explicit_local_merchant_operations(self):
        result = self.run_cli('--help')
        self.assertEqual(result.returncode, 0)
        for command in ('init-book', 'add-quote', 'inspect', 'export-quote', 'enroll-wire', 'serve'):
            self.assertIn(command.encode(), result.stdout)
        self.assertFalse((self.root / 'merchant.sqlite').exists())

    def test_unknown_password_or_book_arguments_are_rejected_without_reflection(self):
        sentinel = 'SYNTHETIC_SECRET_NOT_A_REAL_PASSWORD'
        for option in ('--password', '--book', '--submit'):
            with self.subTest(option=option):
                self.assert_refused(self.run_cli('init-book', *self.context(), option, sentinel), sentinel)

    def test_public_resource_confirmation_is_mandatory_and_wrong_hash_precedes_engine(self):
        resource = self.root / 'public'; private_new(resource, b'Explicit public data')
        args = ['add-quote', *self.context(), '--recipient-index', '0', '--origin', 'http://127.0.0.1:18947',
            '--resource-path', '/public/one', '--amount-units', '7', '--resource', resource,
            '--expires-ns', '1000000000000000000']
        self.assert_refused(self.run_cli(*args))
        self.assert_refused(self.run_cli(*args, '--public-resource-confirmation', '0' * 64))
        self.assertEqual(read_private(resource), b'Explicit public data')
        self.assertFalse((self.root / 'not-initialized').exists())

    def test_export_never_overwrites_an_existing_file_even_with_absent_engine(self):
        out = self.root / 'retained'; private_new(out, b'original private material')
        result = self.run_cli('export-quote', *self.context(), '--quote-id', 'a' * 64,
            '--required-out', out, '--expectation-out', self.root / 'other')
        self.assert_refused(result)
        self.assertEqual(read_private(out), b'original private material')
        self.assertFalse((self.root / 'other').exists())

    def test_serve_bounds_and_session_no_overwrite_precede_any_server_binding(self):
        session = self.root / 'session'; private_new(session, b'original session')
        for seconds in ('0', '301', '1'):
            self.assert_refused(self.run_cli('serve', *self.context(), '--quote-id', 'a' * 64,
                '--session-file', session, '--seconds', seconds))
        self.assertEqual(read_private(session), b'original session')

    def test_enrollment_wrong_original_wire_confirmation_cannot_create_workspace(self):
        wire = self.root / 'wire'; evidence = self.root / 'evidence'
        private_new(wire, b'{"public":"wire"}'); private_new(evidence, b'{"schema":1}')
        result = self.run_cli('enroll-wire', *self.context(), '--quote-id', 'a' * 64,
            '--payer', 'lab_' + 'b' * 64, '--wire', wire, '--evidence', evidence,
            '--wire-confirmation', '0' * 64)
        self.assert_refused(result); self.assertFalse((self.root / 'not-initialized').exists())

    def test_nonprivate_public_input_is_refused_without_echoing_content(self):
        resource = self.root / 'public'; private_new(resource, b'SYNTHETIC_PRIVATE_CONTENT_SENTINEL')
        resource.chmod(0o644)
        result = self.run_cli('add-quote', *self.context(), '--recipient-index', '0',
            '--origin', 'http://127.0.0.1:18947', '--resource-path', '/public/one',
            '--amount-units', '7', '--resource', resource, '--expires-ns', '1000000000000000000',
            '--public-resource-confirmation', '0' * 64)
        self.assert_refused(result, 'SYNTHETIC_PRIVATE_CONTENT_SENTINEL')


if __name__ == '__main__': unittest.main()
