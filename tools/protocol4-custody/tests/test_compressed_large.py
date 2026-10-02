"""One real admitted multi-frame journal; no padding, SQL growth or cap changes."""
import hashlib
from pathlib import Path
import secrets
import struct
import unittest

import test_large as large_helpers
import p4_custody as api
import p4_custody_stream as stream


class LargeCompressedBackupTests(unittest.TestCase):
    def test_admitted_multiframe_baseline_and_data_order_omission_refusals(self):
        root = Path('/home/xnuonux')/('1soft-compressed-multiframe-'+secrets.token_hex(8))
        c,w,d,ids,receipt,total = large_helpers.make_large(root)
        try:
            before = large_helpers.table_rows(w,d)
            backup, archive = root/'compressed.backup', root/'recovery.sqlite'
            password = large_helpers.helpers.BACKUP_PASSWORD
            result = api.backup(d,backup,password,format_version=3)
            self.assertEqual(result['backup_format_version'],3)
            api.restore_backup(backup,archive,c.genesis,c.policy,password)
            with api.RecoveryArchive(archive,c.genesis,c.policy) as recovered:
                view = recovered.inspect(); self.assertEqual(view['pending_debit_units'],'40')
                atlas = next(row for row in view['decisions'] if row['id']==ids['atlas'])
                self.assertTrue(atlas['attempt_recorded'])
                self.assertEqual(atlas['transport_observation'],'unresolved')
                self.assertFalse(atlas['safe_to_resend'])
                for role in ('raven','atlas'):
                    selected = dict(payer=c.payer,grant_id=role)
                    self.assertTrue(recovered.recover(ids[role],**selected)==w.recover(ids[role],**selected),
                                    'original '+role+' wire differs')
                self.assertTrue(large_helpers.helpers.encode(recovered.export_receipt(
                    ids['raven'],payer=c.payer,grant_id='raven'))==large_helpers.helpers.encode(receipt),
                    'retained Raven receipt differs')
                with stream.stream_pair(recovered._chunks) as pair:
                    for source,table,_,_ in stream.TABLES:
                        name = ('wallet_config' if source==0 else 'delivery_config') if table=='config' else table
                        self.assertTrue(tuple(pair[source].execute('SELECT * FROM '+table+' ORDER BY 1'))==before[name],
                                        'retained table differs: '+name)
                self.assertFalse(view['signing_enabled']); self.assertFalse(view['dispatch_enabled'])
            raw = backup.read_bytes(); start = 14+int.from_bytes(raw[10:14],'big')
            frames = []; offset = start
            while offset<len(raw):
                kind,codec,size,n = struct.unpack('>cBII',raw[offset:offset+10])
                frames.append(raw[offset:offset+10+n]); offset += 10+n
            self.assertGreaterEqual(len(frames)-1,2,'real admitted baseline lacks multiple D frames')
            self.assertTrue(all(frame[:1]==b'D' for frame in frames[:-1]))
            self.assertEqual(frames[-1][:1],b'F')
            cases = {
                'swap_data': [frames[1],frames[0],*frames[2:]],
                'duplicate_data': [frames[0],*frames],
                'omit_first_data': frames[1:],
                'omit_last_data': [*frames[:-2],frames[-1]],
                'omit_final_manifest': frames[:-1],
            }
            damaged = root/'damaged.backup'
            for name, sequence in cases.items():
                with self.subTest(refusal=name):
                    damaged.write_bytes(raw[:start]+b''.join(sequence)); damaged.chmod(0o600)
                    target = root/(name+'.sqlite')
                    with self.assertRaises(ValueError):
                        api.restore_backup(damaged,target,c.genesis,c.policy,password)
                    self.assertFalse(target.exists(),'malformed backup published '+name)
            self.assertTrue(large_helpers.table_rows(w,d)==before,'source rows changed')
            self.assertLess(sum(path.stat().st_size for path in root.iterdir() if path.is_file()),512*1024*1024)
        finally:
            d.close(); w.close(); c.close()
        # Keep this new exclusive private fixture for evidence; never remove old fixtures.


if __name__=='__main__': unittest.main()
