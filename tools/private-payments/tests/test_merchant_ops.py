"""Real merchant storage/P4 execution with a test-only trusted network context.

Only the source/engine/workspace validation boundary is substituted. Deterministic
P4 quorum signatures are SYNTHETIC; no engine or consensus runs in this suite.
"""
import copy
import fcntl
from dataclasses import asdict
import hashlib
import http.client
import json
import os
from pathlib import Path
import socket
import subprocess
import sys
import tempfile
import threading
import time
import unittest
from unittest.mock import patch

from block_application import encode
from local_devnet import private_new, read_private
from merchant_book import MerchantBook, MAX_RESOURCE_BYTES
from p4_fixture import build, bundle
from payment_x402 import make_payment_required

try:
    import merchant_ops
except ImportError:
    merchant_ops = None


class SyntheticNetworkContext:
    """Test-only stand-in for independently validated engine/workspace context."""
    def __init__(self, root, case):
        self.root = root; self.now = case['now_ns']; self.clock = lambda: self.now
        self.config = {'genesis_sha256': case['policy']['genesis_sha256'],
            'merchant': case['merchant'], 'merchant_recipients': [case['merchant'], case['payer']]}
        self._policy = copy.deepcopy(case['policy']); self.is_ready = True
        private_new(root / 'engine-genesis.json', case['genesis'])
        private_new(root / 'workspace.json', encode(self.config))
    def ready(self): return self.is_ready
    def policy(self): return copy.deepcopy(self._policy)


class MerchantOpsTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls): cls.case = build(rejected=True)

    def setUp(self):
        self.assertIsNotNone(merchant_ops, 'bounded merchant operator module is missing')
        self.tmp = tempfile.TemporaryDirectory(); self.root = Path(self.tmp.name); self.root.chmod(0o700)
        self.addCleanup(self.tmp.cleanup)
        self.network = SyntheticNetworkContext(self.root, self.case)
        self.boundary = patch.object(merchant_ops, 'MerchantNetwork', SyntheticNetworkContext)
        self.boundary.start(); self.addCleanup(self.boundary.stop)
        self.ops = merchant_ops.MerchantOps(self.network)
        self.ops.init_book()

    def add(self, index=0, path='/public/one', **kwargs):
        values = dict(recipient_index=index, merchant_origin='http://127.0.0.1:18947',
            resource_path=path, amount_units='38', resource=b'Explicit PUBLIC report.\n',
            expires_ns=self.network.now + 60 * 10**9, mime_type='text/plain')
        values.update(kwargs)
        return self.ops.add_quote(**values)

    def book(self):
        return MerchantBook(self.root / 'merchant.sqlite', self.case['genesis'], self.case['policy'],
            clock=self.network.clock)

    def test_explicit_indices_create_distinct_immutable_assignments_in_one_book(self):
        one = self.add(); two = self.add(1, '/public/two')
        self.assertNotEqual(one['quote_sha256'], two['quote_sha256'])
        rows = self.ops.inspect()['quotes']
        self.assertEqual([r['expectation']['recipient'] for r in rows],
            [self.case['merchant'], self.case['payer']])
        self.assertEqual(len(rows), 2)
        self.assertTrue((self.root / 'merchant.sqlite').is_file())
        self.assertFalse((self.root / 'wallet.sqlite').exists())
        with self.assertRaises((ValueError, FileExistsError)): self.ops.init_book()

    def test_expired_recipient_is_never_reused_and_pool_exhaustion_cannot_evict(self):
        first = self.add(); self.add(1, '/public/two')
        self.network.now += 61 * 10**9
        for index in (0, 1, 2, -1, True):
            with self.subTest(index=index):
                with self.assertRaises(ValueError): self.add(index, '/public/replacement')
        self.assertEqual(len(self.ops.inspect()['quotes']), 2)
        self.assertEqual(self.ops.inspect()['quotes'][0]['quote_sha256'], first['quote_sha256'])

    def test_duplicate_path_rejection_does_not_burn_an_unassigned_recipient(self):
        self.add()
        with self.assertRaises(ValueError): self.add(1)
        second = self.add(1, '/public/two')
        self.assertEqual(len(self.ops.inspect()['quotes']), 2)
        self.assertEqual(second['status'], 'quote_retained')

    def test_concurrent_operators_cannot_assign_one_exact_route_to_two_recipients(self):
        barrier = threading.Barrier(2); results = []; failures = []
        original = MerchantBook.add_quote
        def overlap(book, *args, **kwargs):
            try: barrier.wait(timeout=0.3)
            except threading.BrokenBarrierError: pass
            return original(book, *args, **kwargs)
        def add(index):
            try: results.append(self.add(index))
            except BaseException as exc: failures.append(exc)
        with patch.object(MerchantBook, 'add_quote', overlap):
            threads = [threading.Thread(target=add, args=(i,)) for i in (0, 1)]
            for thread in threads: thread.start()
            for thread in threads: thread.join(timeout=7)
        self.assertTrue(all(not thread.is_alive() for thread in threads))
        self.assertEqual(len(results), 1)
        self.assertEqual(len(failures), 1); self.assertIsInstance(failures[0], ValueError)
        self.assertEqual(len(self.ops.inspect()['quotes']), 1)
        remaining = 1 - results[0]['recipient_index']
        self.add(remaining, '/public/two')
        self.assertEqual(len(self.ops.inspect()['quotes']), 2)

    def test_resource_bounds_amount_and_literal_loopback_are_checked_before_retention(self):
        bad = [dict(resource=b''), dict(resource=b'x' * (MAX_RESOURCE_BYTES + 1)),
            dict(amount_units='038'), dict(amount_units='0'), dict(merchant_origin='http://localhost:18947'),
            dict(merchant_origin='http://127.0.0.1:18947/'), dict(resource_path='//elsewhere.example/x'),
            dict(resource_path='/public/a#fragment'), dict(resource_path='/public/one?')]
        for values in bad:
            with self.subTest(fields=list(values)):
                with self.assertRaises(ValueError): self.add(**values)
        self.assertEqual(self.ops.inspect()['quotes'], [])

    def test_changed_independent_context_or_unready_runtime_cannot_append(self):
        self.network.is_ready = False
        with self.assertRaises(ValueError): self.add()
        self.network.is_ready = True
        self.network.config['merchant_recipients'].reverse()
        with self.assertRaises(ValueError): self.add()
        self.network.config['merchant_recipients'].reverse()
        self.assertEqual(self.ops.inspect()['quotes'], [])

    def test_changed_disk_configuration_cannot_use_an_old_network_object(self):
        changed = dict(self.network.config, merchant_recipients=list(reversed(self.network.config['merchant_recipients'])))
        (self.root / 'workspace.json').write_bytes(encode(changed))
        with self.assertRaises(ValueError): self.add()
        with self.book() as book: self.assertEqual(book.entries(), [])

    def test_foreign_quote_inserted_into_canonical_book_is_rejected_by_operator(self):
        first = self.add()
        with self.book() as book: selected = book.selected(first['quote_sha256'])
        from dataclasses import replace
        foreign = replace(selected['expectation'], network='1soft:foreign')
        # Same recipient is already assigned, so use the second fixture account.
        foreign = replace(foreign, recipient=self.case['payer'], resource_url=foreign.merchant_origin + '/foreign')
        required = make_payment_required(foreign, created_ns=self.network.now,
            expires_ns=self.network.now + 60 * 10**9, quote_nonce='f' * 64)
        with self.book() as book: book.add_quote(required, foreign, resource=b'Public foreign')
        with self.assertRaises(ValueError): self.ops.inspect()

    def test_export_retrieves_original_header_and_expectation_into_exclusive_private_files(self):
        qid = self.add()['quote_sha256']; required = self.root / 'offer'; expected = self.root / 'expectation'
        self.ops.export_quote(qid, required_out=required, expectation_out=expected)
        with self.book() as book: selected = book.selected(qid)
        self.assertEqual(read_private(required), selected['required_header'].encode('ascii'))
        self.assertEqual(json.loads(read_private(expected)), asdict(selected['expectation']))
        self.assertEqual(required.stat().st_mode & 0o777, 0o600)
        original = read_private(required)
        with self.assertRaises(ValueError):
            self.ops.export_quote(qid, required_out=required, expectation_out=self.root / 'new-expectation')
        self.assertEqual(read_private(required), original)
        self.assertFalse((self.root / 'new-expectation').exists())

    def test_partial_export_failure_preserves_quote_and_later_export_recovers_it(self):
        qid = self.add()['quote_sha256']; calls = 0
        def fail_second(path, raw):
            nonlocal calls
            calls += 1
            if calls == 2: raise OSError('synthetic output failure')
            private_new(path, raw)
        with patch.object(merchant_ops, 'private_new', fail_second):
            with self.assertRaises(OSError):
                self.ops.export_quote(qid, required_out=self.root / 'partial', expectation_out=self.root / 'failed')
        self.ops.export_quote(qid, required_out=self.root / 'recovered', expectation_out=self.root / 'recovered-e')
        self.assertEqual(read_private(self.root / 'partial'), read_private(self.root / 'recovered'))
        self.assertEqual(len(self.ops.inspect()['quotes']), 1)

    def test_owned_lock_denies_export_without_outputs_and_readonly_inspection_still_works(self):
        qid = self.add()['quote_sha256']
        fd = os.open(self.root / 'merchant-ops.lock', os.O_RDWR)
        try:
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            with self.assertRaises(ValueError):
                self.ops.export_quote(qid, required_out=self.root / 'locked-r', expectation_out=self.root / 'locked-e')
            self.assertFalse((self.root / 'locked-r').exists()); self.assertFalse((self.root / 'locked-e').exists())
            self.assertEqual(len(self.ops.inspect()['quotes']), 1)
        finally: os.close(fd)
        self.ops.export_quote(qid, required_out=self.root / 'unlocked-r', expectation_out=self.root / 'unlocked-e')
        self.assertTrue((self.root / 'unlocked-r').is_file())

    def test_operator_crash_releases_lock_without_reset_or_recipient_reuse(self):
        first = self.add()['quote_sha256']
        program = ('import fcntl,os,sys;fd=os.open(sys.argv[1],os.O_RDWR);'
            'fcntl.flock(fd,fcntl.LOCK_EX|fcntl.LOCK_NB);print("locked",flush=True);os._exit(0)')
        child = subprocess.run([sys.executable, '-c', program, str(self.root / 'merchant-ops.lock')],
            capture_output=True, timeout=5)
        self.assertEqual(child.returncode, 0); self.assertEqual(child.stdout, b'locked\n')
        self.add(1, '/public/two')
        with self.assertRaises(ValueError): self.add(0, '/public/reused')
        self.assertEqual(self.ops.inspect()['quotes'][0]['quote_sha256'], first)

    def test_enrollment_requires_exact_payer_wire_and_verified_evidence(self):
        qid = self.add()['quote_sha256']; wire = self.case['wires']['after']
        for payer, raw, evidence in ((self.case['merchant'], wire, bundle(self.case, 6)),
                (self.case['payer'], wire[:-1] + b' ', bundle(self.case, 6)),
                (self.case['payer'], wire, {'schema': 1})):
            with self.assertRaises(ValueError): self.ops.enroll_wire(qid, payer=payer, wire=raw, evidence=evidence)
        result = self.ops.enroll_wire(qid, payer=self.case['payer'], wire=wire, evidence=bundle(self.case, 6))
        self.assertEqual(result['status'], 'wire_enrolled')
        self.assertFalse(result['wallet_reservations_changed'])
        with self.book() as book: self.assertIsNone(book.selected(qid)['fulfillment'])

    def test_bounded_serve_writes_private_independent_session_and_fixed_routes_without_secret_stdout(self):
        with socket.socket() as sock:
            sock.bind(('127.0.0.1', 0)); port = sock.getsockname()[1]
        origin = 'http://127.0.0.1:' + str(port)
        ids = tuple(self.add(i, '/public/' + str(i), merchant_origin=origin)['quote_sha256'] for i in (0, 1))
        session = self.root / 'session'; results = []; failures = []
        def serve():
            try: results.append(self.ops.serve(ids, session_file=session, seconds=1))
            except BaseException as exc: failures.append(exc)
        thread = threading.Thread(target=serve); thread.start()
        try:
            deadline = time.monotonic() + 3
            while not session.exists() and thread.is_alive() and time.monotonic() < deadline: time.sleep(0.01)
            self.assertTrue(session.exists()); data = json.loads(read_private(session))
            self.assertEqual(len(data['session_token']), 64); self.assertEqual(data['origin'], origin)
            connection = http.client.HTTPConnection('127.0.0.1', port, timeout=3)
            try:
                connection.request('GET', '/public/1', headers={'X-1soft-Merchant-Session': data['session_token']})
                response = connection.getresponse(); self.assertEqual(response.status, 402); response.read()
            finally: connection.close()
        finally: thread.join(timeout=7)
        self.assertFalse(thread.is_alive()); self.assertEqual(failures, [])
        self.assertNotIn(data['session_token'], json.dumps(results))
        self.assertEqual(session.stat().st_mode & 0o777, 0o600)
        self.assertEqual(len(self.ops.inspect()['quotes']), 2)

    def test_invalid_serve_bounds_or_existing_session_file_never_replace_content(self):
        qid = self.add()['quote_sha256']; target = self.root / 'session'
        private_new(target, b'original private bytes')
        for seconds in (0, 301, True, 1):
            with self.assertRaises(ValueError): self.ops.serve((qid,), session_file=target, seconds=seconds)
        self.assertEqual(read_private(target), b'original private bytes')


if __name__ == '__main__': unittest.main()
