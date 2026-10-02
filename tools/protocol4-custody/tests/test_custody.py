"""Real journal/native rules with synthetic committee fixtures; no engines."""
import copy
from concurrent.futures import ThreadPoolExecutor
import hashlib
import json
import os
from pathlib import Path
import sqlite3
import sys
import tempfile
import threading
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[3]
sys.path[:0] = [str(ROOT/'src'), str(ROOT/'tools/validator-transition/src')]
for name in ('protocol4-client', 'protocol4-wallet', 'protocol4-delivery', 'protocol4-custody'):
    sys.path[:0] = [str(ROOT/'tools'/name/'src'), str(ROOT/'tools'/name/'tests')]
from block_application import encode
from p4_wallet import P4Wallet
from p4_delivery import P4Delivery
from wallet_fixture import Chain, PASSWORD

BACKUP_PASSWORD = b'public backup fixture passphrase'


class CustodyTests(unittest.TestCase):
    def setUp(self):
        try:
            import p4_custody
        except ModuleNotFoundError as exc:
            self.fail('custody recovery feature is missing: '+str(exc))
        self.api = p4_custody
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.c = Chain(self.root)
        self.addCleanup(self.c.close)
        self.wp, self.dp = self.root/'wallet.sqlite', self.root/'delivery.sqlite'
        self.w = P4Wallet(self.wp, self.c.genesis, self.c.policy, create=True, clock=self.c.clock)
        self.addCleanup(self.w.close)
        self.w.sync(self.c.evidence(), expected_revision=None)
        self.d = P4Delivery(self.wp, self.dp, self.c.genesis, self.c.policy,
                            'http://127.0.0.1:26657/', create=True, clock=self.c.clock)
        self.addCleanup(self.d.close)
        self.raven = self.sign('raven', 58)
        self.atlas = self.sign('atlas', 38)
        self.bp, self.ap = self.root/'backup.json', self.root/'recovery.sqlite'

    def sign(self, role, units):
        q = self.w.prepare(payer=self.c.payer, recipient=self.c.merchant,
                           units=units, grant_id=role, valid_until=30)
        return self.w.approve(q['review'], q['confirmation'],
            vault=self.root/(role+'.pem'), password=PASSWORD)['decision_id']

    def select(self, role='raven'):
        return dict(payer=self.c.payer, grant_id=role)

    def claim(self):
        q = self.d.prepare(self.raven, **self.select())
        # Real send commits its claim; only the external I/O boundary is faulted.
        with patch('p4_delivery.submit_once', side_effect=RuntimeError('injected I/O loss')):
            with self.assertRaises(RuntimeError):
                self.d.send(q['review'], q['confirmation'])

    def rows(self):
        return [tuple(self.w.db.iterdump()), tuple(self.d.db.iterdump())]

    def roundtrip(self):
        self.api.backup(self.d, self.bp, BACKUP_PASSWORD)
        self.api.restore_backup(self.bp, self.ap, self.c.genesis, self.c.policy, BACKUP_PASSWORD)
        return self.api.RecoveryArchive(self.ap, self.c.genesis, self.c.policy)

    def test_preserves_original_wires_and_fee_inclusive_shared_holds(self):
        wire = self.w.recover(self.raven, **self.select())
        with self.roundtrip() as a:
            view = a.inspect()
            self.assertEqual(view['pending_debit_units'], '100')
            self.assertEqual(view['budgets'][0]['pending_debit_units'], '100')
            self.assertEqual(a.recover(self.raven, **self.select()), wire)
            self.assertFalse(view['old_device_fenced'])
            self.assertFalse(view['latestness_established'])
            self.assertFalse(view['signing_enabled'])
            self.assertFalse(view['dispatch_enabled'])

    def test_consumed_claim_without_response_remains_unresolved(self):
        self.claim()
        with self.roundtrip() as a:
            row = next(r for r in a.inspect()['decisions'] if r['id'] == self.raven)
            self.assertTrue(row['attempt_recorded'])
            self.assertEqual(row['transport_observation'], 'unresolved')
            self.assertFalse(row['safe_to_resend'])
            self.assertEqual(a.inspect()['pending_debit_units'], '100')

    def test_collected_receipt_does_not_silently_reconcile_wallet(self):
        wire = self.w.recover(self.raven, **self.select())
        self.c.block([wire])
        evidence = self.c.evidence()
        self.d.import_receipt(self.raven, evidence, **self.select())
        with self.roundtrip() as a:
            row = next(r for r in a.inspect()['decisions'] if r['id'] == self.raven)
            self.assertEqual(row['wallet_receipt_status'], 'unavailable')
            self.assertEqual(row['delivery_receipt_status'], 'verified_historical_receipt')
            self.assertEqual(a.inspect()['pending_debit_units'], '100')
            self.assertEqual(a.export_receipt(self.raven, **self.select()), evidence)

    def test_backup_restore_and_inspection_preserve_every_source_row(self):
        self.claim()
        before = self.rows()
        with self.roundtrip() as a:
            a.inspect()
            a.recover(self.raven, **self.select())
        self.assertEqual(self.rows(), before)

    def test_expired_policy_preserves_holds_and_keyless_original_recovery(self):
        self.c.now += 7200*10**9
        for path in self.root.glob('*.pem'):
            path.unlink()
        with self.roundtrip() as a:
            self.assertEqual(a.inspect()['pending_debit_units'], '100')
            self.assertEqual(a.recover(self.raven, **self.select()),
                             self.w.recover(self.raven, **self.select()))

    def test_wrong_payer_or_role_cannot_export_another_original(self):
        with self.roundtrip() as a:
            for selection in (dict(payer=self.c.merchant, grant_id='raven'),
                              dict(payer=self.c.payer, grant_id='atlas')):
                with self.assertRaises(ValueError): a.recover(self.raven, **selection)

    def test_wrong_password_creates_no_restore_output(self):
        self.api.backup(self.d, self.bp, BACKUP_PASSWORD)
        with self.assertRaises(ValueError):
            self.api.restore_backup(self.bp, self.ap, self.c.genesis, self.c.policy,
                                     b'wrong long fixture passphrase')
        self.assertFalse(self.ap.exists())

    def test_authenticated_ciphertext_corruption_creates_no_output(self):
        self.api.backup(self.d, self.bp, BACKUP_PASSWORD)
        raw = json.loads(self.bp.read_bytes())
        raw['ciphertext'] = ('A' if raw['ciphertext'][0] != 'A' else 'B') + raw['ciphertext'][1:]
        self.bp.write_bytes(encode(raw))
        with self.assertRaises(ValueError):
            self.api.restore_backup(self.bp, self.ap, self.c.genesis, self.c.policy, BACKUP_PASSWORD)
        self.assertFalse(self.ap.exists())

    def test_kdf_resource_inflation_is_rejected_before_derivation(self):
        self.api.backup(self.d, self.bp, BACKUP_PASSWORD)
        raw = json.loads(self.bp.read_bytes())
        raw['header']['kdf']['n'] = 2**40
        self.bp.write_bytes(encode(raw))
        with self.assertRaises(ValueError):
            self.api.restore_backup(self.bp, self.ap, self.c.genesis, self.c.policy, BACKUP_PASSWORD)
        self.assertFalse(self.ap.exists())

    def test_valid_password_does_not_authorize_altered_signed_decision(self):
        snapshot = self.api.capture(self.d)
        row = snapshot['wallet']['decisions'][0]
        decision = json.loads(bytes.fromhex(row[3]['hex']))
        decision['review']['debit_units'] = '1'
        row[3] = {'hex': encode(decision).hex()}
        self.bp.write_bytes(self.api._seal(snapshot, BACKUP_PASSWORD))
        self.bp.chmod(0o600)
        with self.assertRaises(ValueError):
            self.api.restore_backup(self.bp, self.ap, self.c.genesis, self.c.policy, BACKUP_PASSWORD)
        self.assertFalse(self.ap.exists())

    def test_external_policy_cannot_be_replaced_by_backup_contents(self):
        self.api.backup(self.d, self.bp, BACKUP_PASSWORD)
        changed = copy.deepcopy(self.c.policy)
        changed['trust_period_seconds'] += 1
        with self.assertRaises(ValueError):
            self.api.restore_backup(self.bp, self.ap, self.c.genesis, changed, BACKUP_PASSWORD)
        self.assertFalse(self.ap.exists())

    def test_recovery_archive_cannot_be_opened_by_active_wallet_or_delivery(self):
        with self.roundtrip(): pass
        with self.assertRaises(ValueError): P4Wallet(self.ap, self.c.genesis, self.c.policy)
        with self.assertRaises(ValueError):
            P4Delivery(self.ap, self.root/'not-created.sqlite', self.c.genesis,
                       self.c.policy, 'http://127.0.0.1:26657/', create=True)
        self.assertFalse((self.root/'not-created.sqlite').exists())
        with self.assertRaises(ValueError):
            P4Delivery(self.wp, self.ap, self.c.genesis, self.c.policy,
                       'http://127.0.0.1:26657/')

    def test_backup_never_occupies_any_source_database_sidecar(self):
        before = self.rows()
        for source in (self.wp, self.dp):
            for suffix in ('', '-wal', '-shm', '-journal'):
                target = Path(str(source)+suffix)
                existed = target.exists()
                with self.assertRaises(ValueError):
                    self.api.backup(self.d, target, BACKUP_PASSWORD)
                self.assertEqual(target.exists(), existed)
        self.assertEqual(self.rows(), before)

    def test_restore_cannot_occupy_backup_sidecar(self):
        self.api.backup(self.d, self.bp, BACKUP_PASSWORD)
        target = Path(str(self.bp)+'-journal')
        with self.assertRaises(ValueError):
            self.api.restore_backup(self.bp, target, self.c.genesis, self.c.policy, BACKUP_PASSWORD)
        self.assertFalse(target.exists())

    def test_stale_backup_does_not_establish_latestness_or_unpaid_absence(self):
        # Only this disposable fixture starts from a valid shorter prefix.
        self.w.db.execute('DELETE FROM decisions WHERE decision_id=?', (self.atlas,))
        self.api.backup(self.d, self.bp, BACKUP_PASSWORD)
        newer = self.sign('atlas', 38)
        self.api.restore_backup(self.bp, self.ap, self.c.genesis, self.c.policy, BACKUP_PASSWORD)
        with self.api.RecoveryArchive(self.ap, self.c.genesis, self.c.policy) as archive:
            view = archive.inspect()
            self.assertEqual(view['pending_debit_units'], '60')
            self.assertFalse(view['latestness_established'])
            self.assertFalse(view['current_spending_authority'])
            self.assertFalse(view['old_device_fenced'])
            with self.assertRaises(ValueError): archive.recover(newer, **self.select('atlas'))
            with self.assertRaisesRegex(ValueError, 'unknown'):
                archive.export_receipt(self.raven, **self.select())
        self.assertEqual(self.w.status()['pending_debit_units'], '100')

    def test_authenticated_metadata_tampering_creates_no_archive(self):
        self.api.backup(self.d, self.bp, BACKUP_PASSWORD)
        original = json.loads(self.bp.read_bytes())
        for field in ('salt', 'nonce'):
            envelope = copy.deepcopy(original)
            value = envelope['header'][field]
            envelope['header'][field] = ('0' if value[0] != '0' else '1')+value[1:]
            self.bp.write_bytes(encode(envelope))
            with self.assertRaisesRegex(ValueError, 'authenticate'):
                self.api.restore_backup(self.bp, self.ap, self.c.genesis, self.c.policy, BACKUP_PASSWORD)
            self.assertFalse(self.ap.exists())

    def test_symlink_and_hardlink_inputs_and_outputs_are_refused(self):
        self.api.backup(self.d, self.bp, BACKUP_PASSWORD)
        link = self.root/'alias.json'
        link.symlink_to(self.bp)
        with self.assertRaises((ValueError, OSError)):
            self.api.restore_backup(link, self.ap, self.c.genesis, self.c.policy, BACKUP_PASSWORD)
        link.unlink(); os.link(self.bp, link)
        with self.assertRaises(ValueError):
            self.api.restore_backup(link, self.ap, self.c.genesis, self.c.policy, BACKUP_PASSWORD)
        link.unlink()
        for kind in ('symlink', 'hardlink'):
            if kind == 'symlink': self.ap.symlink_to(self.bp)
            else: os.link(self.bp, self.ap)
            with self.assertRaises(ValueError):
                self.api.restore_backup(self.bp, self.ap, self.c.genesis, self.c.policy, BACKUP_PASSWORD)
            self.ap.unlink()
        self.assertFalse(self.ap.exists())

    def test_prepublication_fsync_failure_leaves_no_output_or_temp(self):
        before = self.rows()
        with patch('p4_custody.os.fsync', side_effect=OSError('injected fsync failure')):
            with self.assertRaises(OSError): self.api.backup(self.d, self.bp, BACKUP_PASSWORD)
        self.assertFalse(self.bp.exists())
        self.assertEqual(list(self.root.glob('.1soft-recovery-*.tmp')), [])
        self.assertEqual(self.rows(), before)

    def test_directory_fsync_failure_reports_published_output_as_uncertain(self):
        before = self.rows()
        original = os.fsync
        def fail_directory(fd):
            import stat
            if stat.S_ISDIR(os.fstat(fd).st_mode): raise OSError('injected directory fsync loss')
            return original(fd)
        with patch('p4_custody.os.fsync', side_effect=fail_directory):
            with self.assertRaisesRegex(OSError, 'published.*unconfirmed'):
                self.api.backup(self.d, self.bp, BACKUP_PASSWORD)
        self.assertTrue(self.bp.exists())
        self.api.restore_backup(self.bp, self.ap, self.c.genesis, self.c.policy, BACKUP_PASSWORD)
        with self.api.RecoveryArchive(self.ap, self.c.genesis, self.c.policy) as archive:
            self.assertEqual(archive.inspect()['pending_debit_units'], '100')
        self.assertEqual(self.rows(), before)

    def test_complete_payload_bound_refuses_without_evicting_source_rows(self):
        before = self.rows()
        # Lower the configured cap to exercise the exact production cap path
        # without generating an unrelated multi-megabyte committee fixture.
        with patch('p4_custody.MAX_JOURNAL_BYTES', 1):
            with self.assertRaises(ValueError):
                self.api.backup(self.d, self.bp, BACKUP_PASSWORD, format_version=1)
        self.assertFalse(self.bp.exists())
        self.assertEqual(self.rows(), before)

    def test_existing_backup_and_restore_targets_are_never_overwritten(self):
        self.api.backup(self.d, self.bp, BACKUP_PASSWORD)
        original = self.bp.read_bytes()
        with self.assertRaises((ValueError, FileExistsError)):
            self.api.backup(self.d, self.bp, BACKUP_PASSWORD)
        self.assertEqual(self.bp.read_bytes(), original)
        self.ap.write_bytes(b'precious existing file'); self.ap.chmod(0o600)
        with self.assertRaises((ValueError, FileExistsError)):
            self.api.restore_backup(self.bp, self.ap, self.c.genesis, self.c.policy, BACKUP_PASSWORD)
        self.assertEqual(self.ap.read_bytes(), b'precious existing file')

    def test_restore_sidecar_alias_is_refused_without_overwrite(self):
        self.api.backup(self.d, self.bp, BACKUP_PASSWORD)
        sidecar = Path(str(self.ap)+'-wal')
        sidecar.write_bytes(b'existing sidecar'); sidecar.chmod(0o600)
        with self.assertRaises(ValueError):
            self.api.restore_backup(self.bp, self.ap, self.c.genesis, self.c.policy, BACKUP_PASSWORD)
        self.assertFalse(self.ap.exists())
        self.assertEqual(sidecar.read_bytes(), b'existing sidecar')

    def test_different_backups_of_same_journal_have_distinct_encryption(self):
        self.api.backup(self.d, self.bp, BACKUP_PASSWORD)
        other = self.root/'other.json'
        self.api.backup(self.d, other, BACKUP_PASSWORD)
        self.assertNotEqual(self.bp.read_bytes(), other.read_bytes())

    def test_capture_with_concurrent_writer_is_complete_before_or_after(self):
        # Remove only this fixture's latest unsigned-for-network decision to set
        # up a valid one-decision prefix, then approve it on a separate connection.
        self.w.db.execute('DELETE FROM decisions WHERE decision_id=?', (self.atlas,))
        q = self.w.prepare(payer=self.c.payer, recipient=self.c.merchant,
                           units=38, grant_id='atlas', valid_until=30)
        start, attempting = threading.Event(), threading.Event()
        def approve():
            with P4Wallet(self.wp, self.c.genesis, self.c.policy, clock=self.c.clock) as wallet:
                start.wait(5)
                wallet.db.set_trace_callback(lambda sql: attempting.set() if sql == 'BEGIN IMMEDIATE' else None)
                return wallet.approve(q['review'], q['confirmation'],
                    vault=self.root/'atlas.pem', password=PASSWORD)
        with ThreadPoolExecutor(max_workers=1) as pool:
            future = pool.submit(approve)
            original = self.api._rows
            def capture_rows(db, schema):
                if db is self.d.wallet.db:
                    start.set()
                    self.assertTrue(attempting.wait(5), 'writer did not reach the existing wallet lock')
                    self.assertFalse(future.done(), 'writer bypassed the capture lock')
                return original(db, schema)
            with patch('p4_custody._rows', side_effect=capture_rows):
                self.api.backup(self.d, self.bp, BACKUP_PASSWORD)
            future.result(timeout=10)
        self.api.restore_backup(self.bp, self.ap, self.c.genesis, self.c.policy, BACKUP_PASSWORD)
        with self.api.RecoveryArchive(self.ap, self.c.genesis, self.c.policy) as a:
            view = a.inspect()
            self.assertEqual((len(view['decisions']), view['pending_debit_units']), (1, '60'))
        self.assertEqual(self.w.status()['pending_debit_units'], '100')


if __name__ == '__main__': unittest.main()
