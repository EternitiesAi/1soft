"""Versioned complete recovery backups; real local journals, public test keys."""
import hashlib
import json
import os
from pathlib import Path
import struct
import unittest
from unittest.mock import patch
from contextlib import closing

import test_custody as helpers
BACKUP_PASSWORD = helpers.BACKUP_PASSWORD


class BackupFormatTests(unittest.TestCase):
    setUp = helpers.CustodyTests.setUp
    sign = helpers.CustodyTests.sign
    select = helpers.CustodyTests.select
    claim = helpers.CustodyTests.claim
    rows = helpers.CustodyTests.rows
    def test_explicit_v2_roundtrip_preserves_original_provenance(self):
        self.claim()
        before = self.rows()
        try:
            result = self.api.backup(self.d, self.bp, BACKUP_PASSWORD, format_version=2)
        except TypeError as exc:
            self.fail('explicit v2 backup is unavailable: '+str(exc))
        self.assertEqual(result['backup_format_version'], 2)
        self.api.restore_backup(self.bp, self.ap, self.c.genesis, self.c.policy, BACKUP_PASSWORD)
        with self.api.RecoveryArchive(self.ap, self.c.genesis, self.c.policy) as archive:
            view = archive.inspect()
            self.assertEqual(view['pending_debit_units'], '100')
            self.assertEqual(archive.recover(self.raven, **self.select()), self.w.recover(self.raven, **self.select()))
            row = next(d for d in view['decisions'] if d['id'] == self.raven)
            self.assertEqual(row['transport_observation'], 'unresolved')
            self.assertFalse(view['signing_enabled'])
            self.assertFalse(view['trust_policy_renewed'])
        self.assertEqual(self.rows(), before)

    def test_default_small_backup_remains_v1_and_unsupported_selection_refuses(self):
        self.api.backup(self.d, self.bp, BACKUP_PASSWORD)
        self.assertEqual(json.loads(self.bp.read_bytes())['header']['schema'], 1)
        for version in (0, 4, True, '2'):
            with self.subTest(version=version), self.assertRaises(ValueError):
                self.api.backup(self.d, self.root/'invalid', BACKUP_PASSWORD, format_version=version)
        self.assertFalse((self.root/'invalid').exists())

    def test_auto_falls_back_if_complete_legacy_plaintext_exceeds_codec_bound(self):
        # Exercise the separate legacy encoding cap; source admission is unchanged.
        with patch('p4_custody.MAX_PLAINTEXT_BYTES',1):
            with self.assertRaises(ValueError):
                self.api.backup(self.d,self.root/'legacy',BACKUP_PASSWORD,format_version=1)
            result=self.api.backup(self.d,self.bp,BACKUP_PASSWORD)
        self.assertEqual(result['backup_format_version'],2)
        self.assertFalse((self.root/'legacy').exists())

    def test_v2_wrong_password_damage_truncation_and_append_refuse_publication(self):
        self.api.backup(self.d, self.bp, BACKUP_PASSWORD, format_version=2)
        raw = self.bp.read_bytes()
        with self.assertRaises(ValueError):
            self.api.restore_backup(self.bp, self.ap, self.c.genesis, self.c.policy, b'wrong fixture password')
        damaged = bytearray(raw); damaged[len(raw)//2] ^= 1
        for candidate in (bytes(damaged), raw[:-1], raw+b'x'):
            self.bp.write_bytes(candidate)
            with self.subTest(size=len(candidate)), self.assertRaises(ValueError):
                self.api.restore_backup(self.bp, self.ap, self.c.genesis, self.c.policy, BACKUP_PASSWORD)
            self.assertFalse(self.ap.exists())

    def test_v2_mixed_backup_frame_is_not_authenticated(self):
        self.api.backup(self.d,self.bp,BACKUP_PASSWORD,format_version=2)
        other=self.root/'other.backup'
        self.api.backup(self.d,other,BACKUP_PASSWORD,format_version=2)
        a,b=self.bp.read_bytes(),other.read_bytes()
        self.assertNotEqual(a,b)
        end=14+int.from_bytes(a[10:14],'big');other_end=14+int.from_bytes(b[10:14],'big')
        n=int.from_bytes(a[end+1:end+5],'big');m=int.from_bytes(b[other_end+1:other_end+5],'big')
        self.bp.write_bytes(a[:end]+b[other_end:other_end+5+m]+a[end+5+n:])
        with self.assertRaises(ValueError):
            self.api.restore_backup(self.bp,self.ap,self.c.genesis,self.c.policy,BACKUP_PASSWORD)
        self.assertFalse(self.ap.exists())

    def test_v2_inflated_kdf_and_unsupported_version_refuse_before_derivation(self):
        import p4_custody_stream as stream
        self.api.backup(self.d,self.bp,BACKUP_PASSWORD,format_version=2)
        raw=self.bp.read_bytes();end=14+int.from_bytes(raw[10:14],'big')
        original=json.loads(raw[14:end])
        for field in ('schema','kdf','chunk_bytes','nonce_prefix'):
            h=json.loads(json.dumps(original))
            if field=='kdf': h[field]['n']=2**30
            elif field=='nonce_prefix':h[field]='Z'*16
            else:h[field]=3
            encoded=helpers.encode(h)
            self.bp.write_bytes(raw[:10]+struct.pack('>I',len(encoded))+encoded+raw[end:])
            with patch('p4_custody_stream.Scrypt',side_effect=AssertionError('KDF must not run')):
                with self.subTest(field=field),self.assertRaises(ValueError):
                    self.api.restore_backup(self.bp,self.ap,self.c.genesis,self.c.policy,BACKUP_PASSWORD)
            self.assertFalse(self.ap.exists())

    def test_v2_authenticated_altered_signed_wire_still_fails_original_auditor(self):
        import p4_custody_stream as stream
        before=self.rows()
        with stream.capture_pair(self.d) as pair:
            db=pair[0];raw=db.execute('SELECT payload FROM decisions WHERE decision_id=?',(self.raven,)).fetchone()[0]
            decision=json.loads(raw);packet=json.loads(bytes.fromhex(decision['wire_hex']))
            packet['signature']='0'*128;decision['wire_hex']=helpers.encode(packet).hex()
            db.execute('UPDATE decisions SET payload=? WHERE decision_id=?',(helpers.encode(decision),self.raven))
            self.bp.write_bytes(b''.join(stream.sealed_parts(pair,BACKUP_PASSWORD,{})));self.bp.chmod(0o600)
        with self.assertRaises(ValueError):
            self.api.restore_backup(self.bp,self.ap,self.c.genesis,self.c.policy,BACKUP_PASSWORD)
        self.assertFalse(self.ap.exists());self.assertEqual(self.rows(),before)

    def test_v2_expired_clock_does_not_renew_original_policy(self):
        self.claim();self.c.now+=7200*10**9
        self.api.backup(self.d,self.bp,BACKUP_PASSWORD,format_version=2)
        self.api.restore_backup(self.bp,self.ap,self.c.genesis,self.c.policy,BACKUP_PASSWORD)
        with self.api.RecoveryArchive(self.ap,self.c.genesis,self.c.policy) as archive:
            view=archive.inspect()
            self.assertEqual(view['pending_debit_units'],'100')
            self.assertFalse(view['trust_policy_renewed'])
        changed=dict(self.c.policy);changed['trust_period_seconds']=7200
        with self.assertRaises(ValueError):self.api.RecoveryArchive(self.ap,self.c.genesis,changed)

    def test_v2_archive_corruption_and_unknown_version_are_refused(self):
        import sqlite3
        self.api.backup(self.d,self.bp,BACKUP_PASSWORD,format_version=2)
        self.api.restore_backup(self.bp,self.ap,self.c.genesis,self.c.policy,BACKUP_PASSWORD)
        raw=self.ap.read_bytes()
        with closing(sqlite3.connect(self.ap)) as db:
            db.execute('UPDATE recovery SET version=3');db.commit()
        with self.assertRaises(ValueError):self.api.RecoveryArchive(self.ap,self.c.genesis,self.c.policy)
        self.ap.write_bytes(raw)
        with closing(sqlite3.connect(self.ap)) as db:
            payload=db.execute('SELECT payload FROM chunks WHERE seq=1').fetchone()[0]
            db.execute('UPDATE chunks SET payload=? WHERE seq=1',(payload[:-1]+b'x',))
            db.commit()
        with self.assertRaises(ValueError):self.api.RecoveryArchive(self.ap,self.c.genesis,self.c.policy)

    def test_v2_fsync_failure_and_sidecar_alias_leave_source_and_outputs_intact(self):
        before=self.rows()
        with patch('p4_custody.os.fsync',side_effect=OSError('fixture fsync failure')):
            with self.assertRaises(OSError):self.api.backup(self.d,self.bp,BACKUP_PASSWORD,format_version=2)
        self.assertFalse(self.bp.exists());self.assertEqual(list(self.root.glob('.1soft-recovery-*.tmp')),[])
        for source in (self.wp,self.dp):
            with self.assertRaises(ValueError):
                self.api.backup(self.d,Path(str(source)+'-journal'),BACKUP_PASSWORD,format_version=2)
        self.assertEqual(self.rows(),before)


if __name__ == '__main__': unittest.main()
