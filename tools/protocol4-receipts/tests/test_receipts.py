"""Actual local P4 replay with synthetic committee signatures, not consensus."""
import base64
import copy
from concurrent.futures import ThreadPoolExecutor
import hashlib
import json
import os
from pathlib import Path
import shutil
import sqlite3
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

from commit_verifier import encode, load_json
from native_core import canonical
from p4_evidence import MAX_EVIDENCE_BYTES, nanos
from p4_fixture import build, bundle
from p4_receipt_capsule import (FORMAT, MAX_CAPSULE_BYTES, MAX_DEPTH,
    encode_capsule, make_capsule, parse_capsule, sha256, verify_capsule)
from p4_receipt_archive import P4ReceiptArchive, write_new

ROOT = Path(__file__).resolve().parents[1]
CLI = ROOT / 'scripts/p4_receipts.py'


class CapsuleTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.case = build(rejected=True)
        cls.evidence = bundle(cls.case)
        cls.wire = cls.case['wires']['after']
        cls.capsule = make_capsule(cls.evidence, cls.case['genesis'], cls.case['policy'],
                                  cls.wire, payer=cls.case['payer'], now_ns=cls.case['now_ns'])

    def verify(self, value=None, **kwargs):
        return verify_capsule(self.capsule if value is None else value,
            self.case['genesis'], self.case['policy'], now_ns=self.case['now_ns'], **kwargs)

    def changed(self): return copy.deepcopy(self.capsule)

    def test_positive_exact_payment_after_validator_replacement(self):
        report = self.verify(expected_payer=self.case['payer'], expected_wire_sha256=sha256(self.wire))
        self.assertEqual(report['status'], 'verified-p4-payment-receipt')
        self.assertEqual((report['asset'], report['unit'], report['amount_units'], report['fee_units'], report['total_debit_units']),
                         ('DEV', 'native-atomic-units', '38', '2', '40'))
        self.assertEqual((report['receipt_height'], report['state_height'], report['header_height'], report['registry_epoch']),
                         (7, 16, 17, 2))
        self.assertEqual(canonical(report['transaction']), self.wire)
        self.assertEqual(report['binding']['wire_sha256'], sha256(self.wire))
        for flag in ('latest_network_state_established', 'spending_authority', 'automatic_resend',
                     'wallet_reservations_changed', 'historical_absence_proven', 'external_settlement_verified'):
            self.assertIs(report[flag], False)

    def test_export_is_deterministic_and_has_no_embedded_time_or_policy(self):
        newer = make_capsule(self.evidence, self.case['genesis'], self.case['policy'], self.wire,
                            payer=self.case['payer'], now_ns=self.case['now_ns'] + 1)
        self.assertEqual(encode_capsule(newer), encode_capsule(self.capsule))
        self.assertEqual(self.verify(encode_capsule(self.capsule))['capsule_id'], sha256(encode_capsule(self.capsule)))
        self.assertNotIn('policy', self.capsule); self.assertNotIn('checked_at_ns', self.capsule)
        self.assertNotIn('private_key', encode_capsule(self.capsule).decode())

    def test_metadata_cannot_claim_positive_or_current_authority(self):
        for key, value in (('status', 'paid'), ('latest_network_state_established', True),
                           ('spending_authority', True), ('checked_at_ns', self.case['now_ns']),
                           ('policy', self.case['policy']), ('private_key', 'secret')):
            c = self.changed(); c[key] = value
            with self.subTest(key=key), self.assertRaises(ValueError): self.verify(c)

    def test_every_binding_is_recomputed(self):
        for key in self.capsule['binding']:
            c = self.changed(); value = c['binding'][key]
            c['binding'][key] = value + 1 if type(value) is int else '0' * 64
            with self.subTest(key=key), self.assertRaises(ValueError): self.verify(c)

    def test_binding_unknown_fields_bool_height_and_versions_refused(self):
        for edit in (lambda c: c['binding'].update(extra=True), lambda c: c['binding'].update(height=True),
                     lambda c: c.update(schema=True), lambda c: c.update(schema=2), lambda c: c.update(format='other')):
            c = self.changed(); edit(c)
            with self.assertRaises(ValueError): self.verify(c)

    def test_caller_payer_and_wire_expectations_are_enforced(self):
        with self.assertRaises(ValueError): self.verify(expected_payer=self.case['merchant'])
        with self.assertRaises(ValueError): self.verify(expected_wire_sha256='0' * 64)
        with self.assertRaises(ValueError): self.verify(expected_wire_sha256='A' * 64)

    def test_external_genesis_policy_and_time_are_mandatory(self):
        with self.assertRaises(TypeError): verify_capsule(self.capsule, self.case['genesis'], self.case['policy'])
        with self.assertRaises(ValueError): verify_capsule(self.capsule, None, self.case['policy'], now_ns=self.case['now_ns'])
        with self.assertRaises(ValueError): verify_capsule(self.capsule, self.case['genesis'] + b' ', self.case['policy'], now_ns=self.case['now_ns'])
        p = copy.deepcopy(self.case['policy']); p['anchor_hash'] = '0' * 64
        c = self.changed(); c['policy_id'] = sha256(encode(p))
        with self.assertRaises(ValueError): verify_capsule(c, self.case['genesis'], p, now_ns=self.case['now_ns'])

    def test_policy_reference_cannot_renew_or_select_trust(self):
        p = copy.deepcopy(self.case['policy']); p['trust_period_seconds'] += 1
        with self.assertRaises(ValueError): verify_capsule(self.capsule, self.case['genesis'], p, now_ns=self.case['now_ns'])
        c = self.changed(); c['genesis_sha256'] = '0' * 64
        with self.assertRaises(ValueError): self.verify(c)

    def test_exact_fixed_deadline_stays_enforced(self):
        expiry = nanos(self.case['policy']['anchor_time']) + self.case['policy']['trust_period_seconds'] * 10**9
        with self.assertRaises(ValueError): verify_capsule(self.capsule, self.case['genesis'], self.case['policy'], now_ns=expiry)
        with self.assertRaises(ValueError): make_capsule(self.evidence, self.case['genesis'], self.case['policy'], self.wire,
                                                       payer=self.case['payer'], now_ns=expiry)

    def test_unavailable_payment_never_exports(self):
        with self.assertRaises(ValueError): make_capsule(bundle(self.case, 3), self.case['genesis'], self.case['policy'],
            self.wire, payer=self.case['payer'], now_ns=self.case['now_ns'])

    def test_rejected_replay_is_not_second_positive_execution(self):
        self.assertEqual(self.verify()['binding']['height'], 7)
        c = self.changed(); c['binding']['height'] = 8; c['binding']['index'] = 0
        with self.assertRaises(ValueError): self.verify(c)

    def test_native_management_receipts_are_not_payments(self):
        wire = base64.b64decode(self.evidence['history'][0]['txs'][0])
        with self.assertRaises(ValueError): make_capsule(self.evidence, self.case['genesis'], self.case['policy'],
            wire, payer=self.case['payer'], now_ns=self.case['now_ns'])

    def test_wire_payer_signature_and_encoding_tamper_refused(self):
        c = self.changed(); c['payer'] = self.case['merchant']
        with self.assertRaises(ValueError): self.verify(c)
        packet = load_json(self.wire); packet['signature'] = '0' * 128
        c = self.changed(); c['wire'] = base64.b64encode(canonical(packet)).decode()
        with self.assertRaises(ValueError): self.verify(c)
        c = self.changed(); c['wire'] = base64.b64encode(self.wire + b' ').decode()
        with self.assertRaises(ValueError): self.verify(c)
        c = self.changed(); c['wire'] += '='
        with self.assertRaises(ValueError): self.verify(c)

    def test_full_evidence_history_headers_state_and_signer_are_reverified(self):
        changes = [lambda e: e['history'][6].update(txs=[]),
                   lambda e: e['headers'][-1]['signed_header']['header'].update(app_hash='00' * 32),
                   lambda e: e['state']['native']['accounts'][0].__setitem__(4, 1)]
        for edit in changes:
            c = self.changed(); edit(c['evidence'])
            with self.assertRaises(ValueError): self.verify(c)
        c = self.changed(); row = c['evidence']['state']['native']['receipts'][0]
        record = load_json(row[3].encode()); record['signer_public_key'] = '0' * 64
        row[3] = canonical(record).decode()
        with self.assertRaises(ValueError): self.verify(c)

    def test_unknown_evidence_secret_fields_refused(self):
        c = self.changed(); c['evidence']['secret'] = 'do-not-export'
        with self.assertRaises(ValueError): self.verify(c)

    def test_duplicate_trailing_noncanonical_and_deep_json_refused(self):
        raw = encode_capsule(self.capsule)
        for bad in (b'{"schema":1,' + raw[1:], raw + b'null', b' ' + raw,
                    b'[' * (MAX_DEPTH + 1) + b'0' + b']' * (MAX_DEPTH + 1), raw[:-1]):
            with self.assertRaises(ValueError): parse_capsule(bad)
        # Delimiters in quoted strings must not be counted as JSON structure.
        c = self.changed(); c['format'] = '[' * 200
        with self.assertRaisesRegex(ValueError, 'unsupported'): parse_capsule(c)

    def test_capsule_and_nested_evidence_size_caps(self):
        with self.assertRaises(ValueError): parse_capsule(b' ' * (MAX_CAPSULE_BYTES + 1))
        c = self.changed(); c['evidence']['oversized'] = 'x' * (MAX_EVIDENCE_BYTES + 1)
        with self.assertRaises(ValueError): parse_capsule(c)


class ArchiveTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        if not hasattr(CapsuleTests, 'case'): CapsuleTests.setUpClass()
        cls.case = CapsuleTests.case
        cls.first = CapsuleTests.capsule
        cls.second = make_capsule(CapsuleTests.evidence, cls.case['genesis'], cls.case['policy'],
            cls.case['wires']['raven'], payer=cls.case['payer'], now_ns=cls.case['now_ns'])

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(dir=ROOT, prefix='test-private-')
        self.path = Path(self.tmp.name) / 'archive.sqlite'
        self.now = self.case['now_ns']

    def tearDown(self): self.tmp.cleanup()

    def open(self, **kwargs):
        return P4ReceiptArchive(self.path, self.case['genesis'], self.case['policy'], now_ns=self.now, **kwargs)

    def test_exclusive_init_roundtrip_content_addressed_reopen(self):
        with self.open(create=True) as archive:
            report = archive.put(self.first, now_ns=self.now)
            self.assertEqual(report['status'], 'stored')
            self.assertEqual(report['capsule_id'], sha256(encode_capsule(self.first)))
        with self.assertRaises(FileExistsError): self.open(create=True)
        with self.open(read_only=True) as archive:
            restored = archive.get(report['capsule_id'], now_ns=self.now,
                                   expected_wire_sha256=self.first['binding']['wire_sha256'])
            self.assertEqual(encode_capsule(restored), encode_capsule(self.first))
            self.assertFalse(archive.inspect(report['capsule_id'], now_ns=self.now)['spending_authority'])
        self.assertEqual(self.path.stat().st_mode & 0o777, 0o600)

    def test_replay_duplicate_is_noop_and_clock_cannot_regress(self):
        with self.open(create=True) as archive:
            first = archive.put(self.first, now_ns=self.now + 10)
            self.assertEqual(archive.put(self.first, now_ns=self.now + 11)['status'], 'already_stored')
            self.assertEqual(archive.db.execute('SELECT count(*) FROM capsules').fetchone()[0], 1)
            with self.assertRaises(ValueError): archive.put(self.first, now_ns=self.now + 9)
            with self.assertRaises(ValueError): archive.get(first['capsule_id'], now_ns=self.now + 9)

    def test_capacity_refuses_without_evicting(self):
        with self.open(create=True, max_records=1) as archive:
            receipt = archive.put(self.first, now_ns=self.now)
            with self.assertRaises(ValueError): archive.put(self.second, now_ns=self.now)
            self.assertEqual(archive.get(receipt['capsule_id'], now_ns=self.now), self.first)
            self.assertEqual(archive.db.execute('SELECT count(*) FROM capsules').fetchone()[0], 1)

    def test_byte_capacity_and_hard_capacity_configuration(self):
        with self.open(create=True, max_bytes=len(encode_capsule(self.first))) as archive:
            archive.put(self.first, now_ns=self.now)
            with self.assertRaises(ValueError): archive.put(self.second, now_ns=self.now)
        for options in ({'max_records': 33}, {'max_bytes': 64 * 1024 * 1024 + 1}, {'max_records': True}):
            with self.assertRaises(ValueError): self.open(**options)

    def test_failed_atomic_insert_leaves_catalogue_and_clock_unchanged(self):
        with self.open(create=True) as archive:
            before = list(archive.db.iterdump())
            with patch('p4_receipt_archive.check_clock', side_effect=[self.now + 100, ValueError('after insert')]):
                with self.assertRaises(ValueError): archive.put(self.first, now_ns=self.now + 1)
            self.assertEqual(list(archive.db.iterdump()), before)

    def test_read_only_get_does_not_write_clock_or_config(self):
        with self.open(create=True) as archive: receipt = archive.put(self.first, now_ns=self.now)
        before = self.path.read_bytes()
        with self.open(read_only=True) as archive:
            old = archive.db.execute('SELECT * FROM config').fetchall()
            archive.get(receipt['capsule_id'], now_ns=self.now + 10)
            archive.inspect(receipt['capsule_id'], now_ns=self.now + 11)
            self.assertEqual(archive.db.execute('SELECT * FROM config').fetchall(), old)
            with self.assertRaises(ValueError): archive.put(self.first, now_ns=self.now + 12)
        self.assertEqual(self.path.read_bytes(), before)

    def test_missing_archive_or_capsule_is_unknown_not_nonpayment(self):
        with self.assertRaises(ValueError): self.open()
        with self.open(create=True) as archive:
            with self.assertRaisesRegex(ValueError, 'outcome unknown'): archive.get('0' * 64, now_ns=self.now)

    def test_external_policy_mismatch_expiry_and_uninitialized_files_refused(self):
        with self.open(create=True): pass
        p = copy.deepcopy(self.case['policy']); p['trust_period_seconds'] += 1
        with self.assertRaises(ValueError): P4ReceiptArchive(self.path, self.case['genesis'], p, now_ns=self.now)
        expiry = nanos(self.case['policy']['anchor_time']) + self.case['policy']['trust_period_seconds'] * 10**9
        with self.assertRaises(ValueError): P4ReceiptArchive(self.path, self.case['genesis'], self.case['policy'], now_ns=expiry)
        empty = Path(self.tmp.name) / 'empty.sqlite'; empty.touch(mode=0o600)
        with self.assertRaises(ValueError): P4ReceiptArchive(empty, self.case['genesis'], self.case['policy'], now_ns=self.now)
        self.assertEqual(empty.read_bytes(), b'')

    def test_payload_and_index_tamper_refused_after_reopen(self):
        with self.open(create=True) as archive:
            receipt = archive.put(self.first, now_ns=self.now)
            archive.db.execute('UPDATE capsules SET native_txid=?', ('0' * 64,))
            with self.assertRaises(ValueError): archive.get(receipt['capsule_id'], now_ns=self.now)
            archive.db.execute('UPDATE capsules SET payload=?', (b'{}',))
        with self.assertRaises(ValueError): self.open(read_only=True)

    def test_private_parent_symlink_hardlink_and_sidecar_refused(self):
        parent = Path(self.tmp.name); parent.chmod(0o755)
        with self.assertRaises(ValueError): self.open(create=True)
        parent.chmod(0o700)
        target = parent / 'target'; target.touch(mode=0o600)
        self.path.symlink_to(target)
        with self.assertRaises(ValueError): self.open(create=True)
        self.path.unlink()
        os.link(target, self.path)
        with self.assertRaises(ValueError): self.open()
        self.path.unlink()
        sidecar = Path(str(self.path) + '-wal'); sidecar.symlink_to(target)
        with self.assertRaises(ValueError): self.open(create=True)

    def test_exclusive_output_never_overwrites(self):
        output = Path(self.tmp.name) / 'capsule.json'; raw = encode_capsule(self.first)
        write_new(output, raw)
        with self.assertRaises(FileExistsError): write_new(output, raw)
        self.assertEqual(output.read_bytes(), raw)
        self.assertEqual(output.stat().st_mode & 0o777, 0o600)

    def test_two_writers_share_content_addressed_atomic_catalogue(self):
        with self.open(create=True): pass
        def put(_):
            with self.open() as archive: return archive.put(self.first, now_ns=self.now)['status']
        with ThreadPoolExecutor(max_workers=2) as pool: statuses = list(pool.map(put, range(2)))
        self.assertEqual(sorted(statuses), ['already_stored', 'stored'])
        with self.open() as archive:
            self.assertEqual(archive.db.execute('SELECT count(*) FROM capsules').fetchone()[0], 1)


class ConsumerTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(dir=ROOT, prefix='test-consumer-')
        self.path = Path(self.tmp.name)

    def tearDown(self): self.tmp.cleanup()

    def cli(self, *args):
        return subprocess.run([sys.executable, str(CLI), '--genesis', str(self.path/'genesis.json'),
            '--policy', str(self.path/'policy.json'), *args], capture_output=True, text=True,
            timeout=30, env={**os.environ, 'PYTHONPATH': '', 'PYTHONDONTWRITEBYTECODE': '1'})

    def test_cli_export_verify_and_archive_roundtrip_with_clean_import_environment(self):
        case = CapsuleTests.case
        for name, raw in [('genesis.json', case['genesis']), ('policy.json', encode(case['policy'])),
                          ('evidence.json', encode(CapsuleTests.evidence)), ('wire.json', CapsuleTests.wire)]:
            (self.path/name).write_bytes(raw)
        result = self.cli('export', '--evidence', str(self.path/'evidence.json'), '--transaction', str(self.path/'wire.json'),
                          '--payer', case['payer'], '--output', str(self.path/'capsule.json'))
        self.assertEqual(result.returncode, 0, result.stderr)
        report = json.loads(result.stdout)
        self.assertFalse(report['spending_authority']); self.assertFalse(report['latest_network_state_established'])
        result = self.cli('verify', '--capsule', str(self.path/'capsule.json'), '--expected-wire-sha256', sha256(CapsuleTests.wire))
        self.assertEqual(result.returncode, 0, result.stderr)
        archive = str(self.path/'archive.sqlite')
        self.assertEqual(self.cli('archive-init', '--archive', archive).returncode, 0)
        result = self.cli('archive-put', '--archive', archive, '--capsule', str(self.path/'capsule.json'))
        self.assertEqual(result.returncode, 0, result.stderr); capsule_id = json.loads(result.stdout)['capsule_id']
        result = self.cli('archive-get', '--archive', archive, '--capsule-id', capsule_id, '--output', str(self.path/'reopened.json'))
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual((self.path/'reopened.json').read_bytes(), (self.path/'capsule.json').read_bytes())
        self.assertEqual(self.cli('export', '--evidence', str(self.path/'evidence.json'), '--transaction', str(self.path/'wire.json'),
                                 '--payer', case['payer'], '--output', str(self.path/'capsule.json')).returncode, 2)

    def test_cli_failure_has_no_payload_or_secret_and_no_historical_override(self):
        case = CapsuleTests.case
        (self.path/'genesis.json').write_bytes(case['genesis']); (self.path/'policy.json').write_bytes(encode(case['policy']))
        (self.path/'bad.json').write_bytes(b'{"private_key":"secret-do-not-log"}')
        result = self.cli('verify', '--capsule', str(self.path/'bad.json'))
        self.assertEqual(result.returncode, 2); self.assertNotIn('secret-do-not-log', result.stderr + result.stdout)
        self.assertEqual(self.cli('verify', '--capsule', str(self.path/'bad.json'), '--now-ns', str(case['now_ns'])).returncode, 2)

    def test_delivery_export_reopens_without_wallet_delivery_or_private_key_files(self):
        # Existing caller APIs only; no submission or reconciliation is performed.
        from delivery_fixture import Fixture
        source = self.path/'source'; source.mkdir(mode=0o700)
        fixture = Fixture(source)
        try:
            decision = fixture.sign(); selected = fixture.selection()
            wire = fixture.wallet.recover(decision, **selected)
            outcome = fixture.chain.block([wire]); self.assertEqual(outcome['tx_results'][0]['code'], 0)
            fixture.publish()
            before = fixture.wallet.status(); fixture.delivery.import_receipt(decision, fixture.proof, **selected)
            evidence = fixture.delivery.export_receipt(decision, **selected)
            capsule = make_capsule(evidence, fixture.chain.genesis, fixture.chain.policy, wire,
                                   payer=selected['payer'], now_ns=fixture.chain.clock())
            self.assertEqual(fixture.wallet.status(), before)
            self.assertEqual(fixture.submissions, [])
            genesis, policy, now = fixture.chain.genesis, fixture.chain.policy, fixture.chain.clock()
            private_markers = [p.read_bytes()[:40] for p in source.glob('*.pem')]
            raw = encode_capsule(capsule); write_new(self.path/'portable.json', raw)
            for marker in private_markers: self.assertNotIn(marker, raw)
        finally:
            fixture.close()
        shutil.rmtree(source)  # Only this test's owned disposable fixture directory.
        self.assertFalse(source.exists())
        report = verify_capsule((self.path/'portable.json').read_bytes(), genesis, policy, now_ns=now,
                                expected_payer=selected['payer'], expected_wire_sha256=sha256(wire))
        self.assertEqual(report['amount_units'], '58'); self.assertFalse(report['wallet_reservations_changed'])
        with P4ReceiptArchive(self.path/'receipt.sqlite', genesis, policy, now_ns=now, create=True) as archive:
            identity = archive.put(capsule, now_ns=now)['capsule_id']
        with P4ReceiptArchive(self.path/'receipt.sqlite', genesis, policy, now_ns=now, read_only=True) as archive:
            self.assertEqual(archive.get(identity, now_ns=now), capsule)
