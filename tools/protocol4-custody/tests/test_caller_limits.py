"""Caller ceilings tighten the exact audited captured pair, never live preflight."""
from contextlib import contextmanager
import io
import unittest
from unittest.mock import patch

import test_custody as helpers
import p4_custody_stream as stream


class CallerLimitTests(unittest.TestCase):
    setUp = helpers.CustodyTests.setUp
    sign = helpers.CustodyTests.sign
    select = helpers.CustodyTests.select
    rows = helpers.CustodyTests.rows

    def test_explicit_three_accepts_exact_captured_blob_ceiling(self):
        with stream.capture_pair(self.d) as pair:
            size = sum(db.execute(f'SELECT coalesce(sum(length({col})),0) FROM {table}').fetchone()[0]
                       for db, table, col in ((pair[0],'config','policy'),(pair[0],'observations','payload'),
                       (pair[0],'decisions','payload'),(pair[1],'attempts','review'),
                       (pair[1],'responses','payload'),(pair[1],'receipts','payload')))
        before = self.rows()
        result = self.api.backup(self.d,self.bp,helpers.BACKUP_PASSWORD,format_version=3,
                                 max_capture_blob_bytes=size,max_backup_bytes=16*1024*1024)
        self.assertEqual(3,result['backup_format_version'])
        self.assertEqual(before,self.rows())

    def test_captured_blob_limit_refuses_before_sealing_and_no_live_preflight(self):
        with patch('p4_custody_stream.blob_size',side_effect=AssertionError('live preflight')):
            with patch('p4_custody_compressed.sealed_parts',side_effect=AssertionError('KDF reached')):
                with self.assertRaisesRegex(ValueError,'captured'):
                    self.api.backup(self.d,self.bp,helpers.BACKUP_PASSWORD,format_version=3,
                                    max_capture_blob_bytes=1)
        self.assertFalse(self.bp.exists())

    def test_physical_ceiling_cleans_partial_and_keeps_existing_output(self):
        with self.assertRaisesRegex(ValueError,'bounded output'):
            self.api.backup(self.d,self.bp,helpers.BACKUP_PASSWORD,format_version=3,max_backup_bytes=1)
        self.assertFalse(self.bp.exists())
        self.assertFalse(list(self.root.glob('.1soft-recovery-*')))
        self.bp.write_bytes(b'existing');self.bp.chmod(0o600)
        with self.assertRaises(ValueError):
            self.api.backup(self.d,self.bp,helpers.BACKUP_PASSWORD,format_version=3,max_backup_bytes=1)
        self.assertEqual(b'existing',self.bp.read_bytes())

    def test_limits_require_explicit_three_and_exact_positive_bounded_ints(self):
        import p4_custody_compressed as compressed
        for field,bound in (('max_capture_blob_bytes',stream.MAX_PAIR_BYTES),
                            ('max_backup_bytes',compressed.MAX_BACKUP_BYTES)):
            for value in (True,False,0,-1,1.0,'1',bound+1):
                with self.subTest(field=field,value=value):
                    with patch('p4_custody.separate_paths',side_effect=AssertionError('artifact paths reached')):
                        with self.assertRaises(ValueError):
                            self.api.backup(self.d,self.bp,helpers.BACKUP_PASSWORD,format_version=3,**{field:value})
                    self.assertFalse(self.bp.exists())
            for version in (None,1,2):
                with self.subTest(field=field,version=version):
                    with self.assertRaises(ValueError):
                        self.api.backup(self.d,self.bp,helpers.BACKUP_PASSWORD,format_version=version,**{field:bound})

    def test_live_growth_after_capture_cannot_change_caller_limit_or_encrypted_pair(self):
        import p4_custody_compressed as compressed
        size=stream.blob_size(self.d);original_capture=stream.capture_pair
        @contextmanager
        def growing_source(delivery):
            with original_capture(delivery) as pair:
                review=self.w.prepare(payer=self.c.payer,recipient=self.c.merchant,units=1,
                                      grant_id='',valid_until=30)
                self.w.approve(review['review'],review['confirmation'],
                    vault=self.root/'owner.pem',password=helpers.PASSWORD)
                self.assertGreater(stream.blob_size(self.d),size)
                yield pair
        with patch('p4_custody_stream.capture_pair',growing_source):
            self.api.backup(self.d,self.bp,helpers.BACKUP_PASSWORD,format_version=3,max_capture_blob_bytes=size)
        _,manifest=compressed.unseal(io.BytesIO(self.bp.read_bytes()),helpers.BACKUP_PASSWORD)
        self.assertEqual(2,manifest['row_counts'][2])
        self.assertEqual(3,self.w.db.execute('SELECT count(*) FROM decisions').fetchone()[0])
        self.assertEqual(size,sum(manifest['blob_bytes']))

    def test_cipher_limit_accepts_exact_size_and_refuses_one_byte_less(self):
        with patch('p4_custody_stream.time.time_ns',return_value=self.c.now):
            self.api.backup(self.d,self.bp,helpers.BACKUP_PASSWORD,format_version=3)
            size=self.bp.stat().st_size
            exact=self.root/'exact.p4b3';short=self.root/'short.p4b3'
            self.api.backup(self.d,exact,helpers.BACKUP_PASSWORD,format_version=3,max_backup_bytes=size)
            self.assertEqual(size,exact.stat().st_size)
            with self.assertRaisesRegex(ValueError,'bounded output'):
                self.api.backup(self.d,short,helpers.BACKUP_PASSWORD,format_version=3,max_backup_bytes=size-1)
            self.assertFalse(short.exists());self.assertFalse(list(self.root.glob('.1soft-recovery-*')))

    def test_explicit_none_is_not_a_supplied_integer_ceiling(self):
        for field in ('max_capture_blob_bytes','max_backup_bytes'):
            with self.subTest(field=field):
                output=self.root/(field+'.p4b3')
                with self.assertRaisesRegex(ValueError,'ceiling'):
                    self.api.backup(self.d,output,helpers.BACKUP_PASSWORD,format_version=3,**{field:None})
                self.assertFalse(output.exists())


if __name__=='__main__':unittest.main()
