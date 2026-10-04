"""Actual private storage/subprocess boundaries and real synthetic P4 callers.

The terminal driver exercises real getpass with a disposable dedicated invoice
key. Wallet caller tests replace only the interactive password boundary; they
use real encrypted payment keys, journals, RPC and capsule replay. Synthetic
committee signatures are fixtures, not observed consensus.
"""
from dataclasses import asdict, replace
import importlib.util
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import time
import unittest
from unittest.mock import patch

from block_application import encode
from commit_verifier import load_json
from invoice_book import initialize_invoice_storage, open_invoice_storage
from local_devnet import ROOT, private_new
from payment_x402 import NativePaymentExpectation, make_payment_required
from private_cli_acceptance import invoke
import test_private_payment_desk as desk_fixture
from wallet_fixture import PASSWORD

INVOICE_PASSWORD = desk_fixture.INVOICE_PASSWORD
PRIVATE_DATA = desk_fixture.PRIVATE_DATA

SCRIPT = ROOT / 'tools/private-payments/scripts/1soft_private.py'
CLI = None
if SCRIPT.is_file():
    spec = importlib.util.spec_from_file_location('private_cli_test_entry', SCRIPT)
    CLI = importlib.util.module_from_spec(spec); spec.loader.exec_module(CLI)


class StandaloneCliTests(unittest.TestCase):
    def setUp(self):
        self.assertIsNotNone(CLI, 'private payment CLI is missing')
        self.tmp = tempfile.TemporaryDirectory(); self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name); self.root.chmod(0o700)
        self.genesis = 'c' * 64; self.storage = self.root / 'invoices'
        self.expected = NativePaymentExpectation('https://merchant.example',
            'https://merchant.example/report', '1soft:cli-local', '1soft:DEV',
            self.genesis, 'lab_'+'a'*64, '12')
        now = time.time_ns()
        self.header = make_payment_required(self.expected, created_ns=now-10**9,
            expires_ns=now+600*10**9, quote_nonce='d'*64)
        self.required = self.root / 'required.txt'; private_new(self.required, self.header.encode('ascii'))
        self.expectation = self.root / 'expectation.json'; private_new(self.expectation, encode(asdict(self.expected)))

    def base(self): return ['--invoices', str(self.storage), '--genesis-sha256', self.genesis]

    def retained(self):
        initialize_invoice_storage(self.storage, self.genesis, password=INVOICE_PASSWORD)
        with open_invoice_storage(self.storage, self.genesis) as book:
            return book.retain(required_header=self.header, expectation=self.expected,
                content=PRIVATE_DATA, password=INVOICE_PASSWORD)['request_id']

    def run_plain(self, command, args):
        return subprocess.run([sys.executable, '-B', str(SCRIPT), command, *args],
            stdin=subprocess.DEVNULL, capture_output=True, timeout=10,
            env={**os.environ, 'PYTHONPATH': '', 'PYTHONDONTWRITEBYTECODE': '1'}, cwd=ROOT)

    def test_actual_init_two_tty_prompts_and_inspection_disclose_no_private_data(self):
        result = invoke('init-invoices', self.base(), password=INVOICE_PASSWORD)
        self.assertEqual(2, result['password_prompts'])
        self.assertEqual('dedicated_invoice_storage_initialized', result['value']['status'])
        inspected = invoke('inspect', self.base())
        self.assertEqual([], inspected['value']['invoices'])
        self.assertEqual(0, inspected['password_prompts'])
        self.assertFalse(inspected['value']['spending_authority'])
        self.assertNotIn(INVOICE_PASSWORD, encode(result))

    def test_check_quote_is_standalone_unsigned_and_uses_independent_expectation(self):
        args = ['--required', str(self.required), '--expectation', str(self.expectation)]
        checked = invoke('check-quote', args)['value']
        self.assertFalse(checked['spending_authority'])
        self.assertFalse(self.storage.exists())
        bad = self.root / 'changed.json'; private_new(bad, encode(asdict(replace(self.expected, amount_units='13'))))
        self.assertNotEqual(0, self.run_plain('check-quote', ['--required', str(self.required), '--expectation', str(bad)]).returncode)

    def test_exact_header_and_duplicate_or_oversize_expectation_are_refused(self):
        changed = self.root / 'newline.txt'; private_new(changed, self.header.encode()+b'\n')
        duplicate = self.root / 'duplicate.json'; private_new(duplicate, b'{"amount_units":"12","amount_units":"12"}')
        huge = self.root / 'huge.json'; private_new(huge, b' '*4097)
        for required, expected in ((changed, self.expectation), (self.required, duplicate), (self.required, huge)):
            self.assertNotEqual(0, self.run_plain('check-quote', ['--required', str(required), '--expectation', str(expected)]).returncode)

    def test_open_explicit_new_file_only_and_encrypted_export_never_unlocks(self):
        rid = self.retained(); plain = self.root / 'opened.json'; encrypted = self.root / 'exported.json'
        opened = invoke('open-invoice', [*self.base(), '--request-id', rid, '--output', str(plain)], password=INVOICE_PASSWORD)
        self.assertEqual(PRIVATE_DATA, load_json(plain.read_bytes(), max_bytes=65536))
        self.assertEqual(0o600, plain.stat().st_mode & 0o777)
        for value in PRIVATE_DATA.values(): self.assertNotIn(value.encode(), encode(opened))
        self.assertEqual(1, opened['password_prompts'])
        exported = invoke('export-invoice', [*self.base(), '--request-id', rid, '--output', str(encrypted)])
        self.assertEqual(0, exported['password_prompts'])
        self.assertNotIn(PRIVATE_DATA['content'].encode(), encrypted.read_bytes())
        before = plain.read_bytes()
        refused = self.run_plain('open-invoice', [*self.base(), '--request-id', rid, '--output', str(plain)])
        self.assertNotEqual(0, refused.returncode); self.assertNotIn(b'password: ', refused.stderr)
        self.assertEqual(before, plain.read_bytes())

    def test_missing_tty_and_password_argument_are_generic_and_never_echo_secret(self):
        refused = self.run_plain('init-invoices', self.base())
        self.assertNotEqual(0, refused.returncode); self.assertFalse(self.storage.exists())
        forbidden = self.run_plain('init-invoices', [*self.base(), '--password', INVOICE_PASSWORD.decode()])
        self.assertNotEqual(0, forbidden.returncode)
        self.assertNotIn(INVOICE_PASSWORD, forbidden.stdout + forbidden.stderr)
        self.assertNotIn(b'Traceback', forbidden.stderr)

    def test_private_input_ownership_and_links_are_refused(self):
        self.required.chmod(0o644)
        self.assertNotEqual(0, self.run_plain('check-quote', ['--required', str(self.required), '--expectation', str(self.expectation)]).returncode)
        self.required.chmod(0o600); linked = self.root / 'linked'; linked.symlink_to(self.required)
        self.assertNotEqual(0, self.run_plain('check-quote', ['--required', str(linked), '--expectation', str(self.expectation)]).returncode)
        hardlink = self.root / 'hardlink'; os.link(self.required, hardlink)
        self.assertNotEqual(0, self.run_plain('check-quote', ['--required', str(hardlink), '--expectation', str(self.expectation)]).returncode)

    def test_damaged_private_storage_returns_generic_failure_without_repair(self):
        self.retained(); database = self.storage / 'invoices.sqlite'; broken = b'invalid private database fixture'
        database.write_bytes(broken)
        refused = self.run_plain('inspect', self.base())
        self.assertNotEqual(0, refused.returncode)
        self.assertNotIn(b'Traceback', refused.stderr)
        self.assertNotIn(broken, refused.stderr)
        self.assertEqual(broken, database.read_bytes())


class WalletCliTests(unittest.TestCase):
    def setUp(self):
        self.assertIsNotNone(CLI, 'private payment CLI is missing')
        self.fixture = desk_fixture.PrivateDeskTests(); self.fixture.setUp(); self.addCleanup(self.fixture.doCleanups)
        self.desk = self.fixture.desk; self.root = self.fixture.root

    def args(self, command, rid=None, **options):
        values = [command, '--workspace', str(self.fixture.workspace), '--engine', '/not-executed',
                  '--invoices', str(self.fixture.storage)]
        if rid: values += ['--request-id', rid]
        for key, value in options.items(): values += ['--'+key.replace('_', '-'), str(value)]
        return CLI.parser().parse_args(values)

    def execute(self, args, password=None):
        if password is None: return CLI.wallet_operation(args, self.desk)
        # Only the interactive boundary is substituted. Desk, encrypted keys,
        # journal and cryptographic receipt verification remain real.
        with patch.object(CLI, 'password', return_value=password):
            return CLI.wallet_operation(args, self.desk)

    def prepared(self, rid):
        output = self.root / 'approval.json'
        result = self.execute(self.args('prepare', rid, role='raven', valid_until=30, output=output))
        return output, load_json(output.read_bytes(), max_bytes=65536), result

    def test_real_import_and_unsigned_native_plus_terms_review(self):
        required = self.root / 'offer'; expectation = self.root / 'expected'; content = self.root / 'content'
        private_new(required, self.fixture.header.encode()); private_new(expectation, encode(asdict(self.fixture.expected)))
        private_new(content, encode(PRIVATE_DATA))
        result = self.execute(self.args('import-invoice', required=required, expectation=expectation, content=content), INVOICE_PASSWORD)
        rid = result['request_id']; _, wrapper, result = self.prepared(rid)
        self.assertEqual(rid, wrapper['request_id']); self.assertEqual('raven', wrapper['role'])
        self.assertEqual('14', wrapper['prepared']['review']['debit_units'])
        self.assertEqual(self.fixture.expected.resource_url, wrapper['prepared']['terms']['resource_url'])
        self.assertIsNone(self.fixture.service.book.selected(rid)['decision_id'])
        self.assertEqual('0', self.fixture.service.state()['wallet']['pending_debit_units'])
        self.assertEqual([], self.fixture.fx.submissions)

    def test_both_confirmations_required_and_original_recovery_never_resigns(self):
        rid = self.fixture.imported(); path, wrapper, _ = self.prepared(rid); p = wrapper['prepared']
        bad = self.args('approve', rid, role='raven', review=path, confirmation=p['confirmation'], terms_confirmation='0'*64)
        with patch.object(CLI, 'password', side_effect=AssertionError('password boundary reached')):
            with self.assertRaises(ValueError): self.execute(bad)
        self.assertEqual('0', self.fixture.service.state()['wallet']['pending_debit_units'])
        approved = self.execute(self.args('approve', rid, role='raven', review=path,
            confirmation=p['confirmation'], terms_confirmation=p['terms_confirmation']), PASSWORD)
        self.assertFalse(approved['broadcast']); self.assertEqual('14', self.fixture.service.state()['wallet']['pending_debit_units'])
        output = self.root / 'wire'; self.execute(self.args('recover', rid, output=output))
        self.assertEqual(self.desk.recover(rid), output.read_bytes())
        self.assertEqual([], self.fixture.fx.submissions)

    def test_changed_review_wrapper_cannot_unlock_payment_key_or_overwrite_output(self):
        rid = self.fixture.imported(); path, wrapper, _ = self.prepared(rid); p = wrapper['prepared']
        wrapper['role'] = 'atlas'; path.write_bytes(encode(wrapper))
        args = self.args('approve', rid, role='raven', review=path, confirmation=p['confirmation'], terms_confirmation=p['terms_confirmation'])
        with patch.object(CLI, 'password', side_effect=AssertionError('password boundary reached')):
            with self.assertRaises(ValueError): self.execute(args)
        with self.assertRaises(ValueError): self.execute(self.args('prepare', rid, role='raven', valid_until=30, output=path))
        self.assertEqual('0', self.fixture.service.state()['wallet']['pending_debit_units'])

    def test_submission_receipt_export_and_explicit_revision_reconciliation(self):
        rid = self.fixture.imported(); self.fixture.sign(rid)
        output = self.root / 'submission'; self.execute(self.args('submission-review', rid, output=output))
        wrapper = load_json(output.read_bytes(), max_bytes=65536); p = wrapper['prepared']
        with self.assertRaises(ValueError): self.execute(self.args('submit', rid, review=output, confirmation='0'*64))
        self.assertEqual([], self.fixture.fx.submissions)
        self.execute(self.args('submit', rid, review=output, confirmation=p['confirmation']))
        self.execute(self.args('collect', rid)); saved = self.execute(self.args('retain-receipt', rid))
        capsule = self.root / 'capsule'; self.execute(self.args('export-receipt', rid, capsule_id=saved['capsule_id'], output=capsule))
        header = self.root / 'signature'; self.execute(self.args('payment-header', rid, capsule_id=saved['capsule_id'], output=header))
        self.assertEqual(self.fixture.service.capsule(rid, saved['capsule_id']), capsule.read_bytes())
        self.assertTrue(load_json(header.read_bytes(), max_bytes=65536)['full_public_ledger_disclosed'])
        self.assertEqual('14', self.fixture.service.state()['wallet']['pending_debit_units'])
        with self.assertRaises(ValueError): self.execute(self.args('reconcile', rid, expected_revision='0'*64))
        self.assertEqual('14', self.fixture.service.state()['wallet']['pending_debit_units'])
        revision = self.fixture.service.state()['wallet']['revision']
        self.execute(self.args('reconcile', rid, expected_revision=revision))
        self.assertEqual('0', self.fixture.service.state()['wallet']['pending_debit_units'])
        self.assertEqual(1, len(self.fixture.fx.submissions))

    def test_unknown_attempt_cannot_resubmit_and_recovery_keeps_hold(self):
        rid = self.fixture.imported(); self.fixture.sign(rid); self.fixture.fx.mode = 'admit_only'
        output = self.root / 'submission'; self.execute(self.args('submission-review', rid, output=output))
        p = load_json(output.read_bytes(), max_bytes=65536)['prepared']
        self.execute(self.args('submit', rid, review=output, confirmation=p['confirmation']))
        self.assertEqual('unavailable', self.execute(self.args('collect', rid))['status'])
        with self.assertRaises(ValueError): self.execute(self.args('submit', rid, review=output, confirmation=p['confirmation']))
        wire = self.root / 'recovered'; self.execute(self.args('recover', rid, output=wire))
        self.assertEqual('14', self.fixture.service.state()['wallet']['pending_debit_units'])
        self.assertEqual(1, len(self.fixture.fx.submissions))


    def test_workspace_dispatch_uses_version_factory_without_lifecycle(self):
        from contextlib import nullcontext
        rid = self.fixture.imported()
        fixture = self.fixture
        class Network:
            config = {'genesis_sha256': fixture.service.policy['genesis_sha256']}
            clock = fixture.service.clock
            def close_read_store(inner): pass  # Legacy fixture owns no alpha store.
            def ready(inner): return True
            def service(inner): return nullcontext(fixture.service)
            def start(inner): raise AssertionError('payer started engines')
            def bootstrap(inner, **kw): raise AssertionError('payer bootstrapped')
            def stop(inner): raise AssertionError('payer stopped engines')
        args = self.args('prepare', rid, role='raven', valid_until=30, output=self.root/'dispatched-review')
        with patch.object(CLI, 'network_for_workspace', return_value=Network()) as factory:
            result = CLI.execute(args)
        factory.assert_called_once_with(args.workspace, args.engine)
        self.assertEqual(rid, result['request_id']); self.assertFalse(result['signed'])
        self.assertEqual('0', fixture.service.state()['wallet']['pending_debit_units'])

    def test_unready_dispatched_workspace_refuses_before_invoice_unlock_or_service(self):
        from types import SimpleNamespace
        args = self.args('recover', 'a'*64, output=self.root/'not-created')
        network = SimpleNamespace(ready=lambda: False, close_read_store=lambda: None,
            service=lambda: (_ for _ in ()).throw(AssertionError('service reached')))
        with patch.object(CLI, 'network_for_workspace', return_value=network), \
             patch.object(CLI, 'open_invoice_storage', side_effect=AssertionError('invoice store reached')):
            with self.assertRaises(ValueError): CLI.execute(args)
        self.assertFalse(args.output.exists())


if __name__ == '__main__': unittest.main()
