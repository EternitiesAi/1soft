"""An admitted real journal above the legacy bound, without padding or cap patches."""
import hashlib
import json
import os
from pathlib import Path
import secrets
import unittest
from unittest.mock import patch

import test_custody as helpers
from block_application import encode


def table_rows(w, d):
    return {name: tuple(db.execute('SELECT * FROM '+table+' ORDER BY 1'))
            for db, name, table in ((w.db,'wallet_config','config'),
                (w.db,'observations','observations'), (w.db,'decisions','decisions'),
                (d.db,'delivery_config','config'), (d.db,'attempts','attempts'),
                (d.db,'responses','responses'), (d.db,'receipts','receipts'))}


def make_large(root):
    root.mkdir(mode=0o700, parents=False, exist_ok=False)
    with patch('wallet_fixture.time.time', return_value=1800000000):
        c = helpers.Chain(root, balance=10000)
    w = helpers.P4Wallet(root/'wallet.sqlite', c.genesis, c.policy, create=True, clock=c.clock)
    d = helpers.P4Delivery(root/'wallet.sqlite', root/'delivery.sqlite', c.genesis,
                           c.policy, 'http://127.0.0.1:26657/', create=True, clock=c.clock)
    ids = {}
    try:
        w.sync(c.evidence(), expected_revision=None)
        for role, units in (('raven',58), ('atlas',38)):
            c.now += 1
            q = w.prepare(payer=c.payer, recipient=c.merchant, units=units,
                          grant_id=role, valid_until=30)
            ids[role] = w.approve(q['review'], q['confirmation'], vault=root/(role+'.pem'),
                                  password=helpers.PASSWORD)['decision_id']
        selection = dict(payer=c.payer, grant_id='atlas')
        q = d.prepare(ids['atlas'], **selection)
        with patch('p4_delivery.submit_once', side_effect=RuntimeError('fixture I/O loss')):
            try: d.send(q['review'], q['confirmation'])
            except RuntimeError: pass
            else: raise AssertionError('claimed attempt did not stop at the I/O boundary')
        wire = w.recover(ids['raven'], payer=c.payer, grant_id='raven')
        assert c.block([wire])['tx_results'][0]['code'] == 0
        receipt = c.evidence(); c.now = (1800000000+c.app.height)*10**9
        d.import_receipt(ids['raven'], receipt, payer=c.payer, grant_id='raven')
        w.sync(receipt, expected_revision=w.status()['revision'])
        nonce = 3
        total = 0
        for _ in range(30):
            txs = [c.owner_wire({'type':'transfer','to':c.merchant,'units':1}, nonce=nonce+i)
                   for i in range(8)]
            nonce += 8
            result = c.block(txs)
            assert all(r['code']==0 for r in result['tx_results'])
            evidence = c.evidence(); c.now = (1800000000+c.app.height)*10**9
            w.sync(evidence, expected_revision=w.status()['revision'])
            rows = table_rows(w,d)
            total = sum(len(cell) for rs in rows.values() for row in rs for cell in row
                        if type(cell) is bytes)
            if total > 7*1024*1024: break
        assert total > 7*1024*1024, 'bounded real fixture failed to cross the legacy limit'
        status = w.status()
        assert status['pending_debit_units'] == '40'
        d.wallet._load(historical=True)
        return c, w, d, ids, receipt, total
    except BaseException:
        d.close(); w.close(); c.close(); raise


class LargeBackupTests(unittest.TestCase):
    def test_admitted_large_pair_automatically_roundtrips_without_eviction_or_activation(self):
        import p4_custody as api
        root = Path('/home/xnuonux')/('1soft-backup-scale-fixture-'+secrets.token_hex(8))
        c, w, d, ids, receipt, total = make_large(root)
        try:
            before = table_rows(w,d)
            backup, archive = root/'large.backup', root/'recovery.sqlite'
            with self.assertRaises(ValueError):
                api.capture(d)
            try: result = api.backup(d, backup, helpers.BACKUP_PASSWORD)
            except ValueError as exc: self.fail('admitted large pair still cannot be backed up: '+str(exc))
            self.assertEqual(result['backup_format_version'], 2)
            api.restore_backup(backup, archive, c.genesis, c.policy, helpers.BACKUP_PASSWORD)
            with api.RecoveryArchive(archive, c.genesis, c.policy) as recovered:
                view = recovered.inspect()
                self.assertEqual(view['pending_debit_units'], '40')
                atlas = next(x for x in view['decisions'] if x['id']==ids['atlas'])
                self.assertEqual(atlas['transport_observation'], 'unresolved')
                self.assertFalse(atlas['safe_to_resend'])
                self.assertFalse(view['old_device_fenced'])
                self.assertFalse(view['latestness_established'])
                self.assertFalse(view['signing_enabled'])
                self.assertFalse(view['trust_policy_renewed'])
                for role in ('raven','atlas'):
                    select = dict(payer=c.payer, grant_id=role)
                    self.assertEqual(recovered.recover(ids[role], **select), w.recover(ids[role], **select))
                self.assertEqual(encode(recovered.export_receipt(ids['raven'], payer=c.payer,
                                                              grant_id='raven')), encode(receipt))
                # Inspect decoded database bytes, independently of the manifest.
                from p4_custody_stream import stream_pair
                with stream_pair(recovered._chunks) as pair:
                    class Holder: pass
                    a,b = Holder(),Holder(); a.db,b.db=pair[0],pair[1]
                    self.assertEqual(table_rows(a,b), before)
            self.assertEqual(table_rows(w,d), before)
            with self.assertRaises(ValueError): helpers.P4Wallet(archive, c.genesis, c.policy)
            # These are actual distinct data frames; implicit positions form AAD.
            raw = backup.read_bytes(); end=14+int.from_bytes(raw[10:14],'big')
            header=raw[:end]; frames=[]
            while end<len(raw):
                n=int.from_bytes(raw[end+1:end+5],'big');frames.append(raw[end:end+5+n]);end+=5+n
            self.assertGreater(len(frames),3)
            variants=(frames[1:2]+frames[0:1]+frames[2:],frames[:1]+frames[:1]+frames[1:],
                      frames[:1]+frames[2:],frames[:-2]+frames[-1:])
            damaged=root/'damaged.backup'; damaged_archive=root/'damaged-recovery.sqlite'
            for variant in variants:
                damaged.write_bytes(header+b''.join(variant));damaged.chmod(0o600)
                with self.assertRaises(ValueError):
                    api.restore_backup(damaged,damaged_archive,c.genesis,c.policy,helpers.BACKUP_PASSWORD)
                self.assertFalse(damaged_archive.exists())
            report = {'scope':'real native rules; synthetic public keys; no engine/network/funds',
                'fixture_path':str(root), 'journal_blob_bytes':total,
                'observations':len(before['observations']), 'state_height':view['state_height'],
                'decisions':len(before['decisions']), 'attempts':len(before['attempts']),
                'receipts':len(before['receipts']), 'backup_bytes':backup.stat().st_size,
                'archive_bytes':archive.stat().st_size, 'backup_sha256':hashlib.sha256(backup.read_bytes()).hexdigest(),
                'original_rows_preserved':True, 'archive_rows_equal':True,
                'pending_debit_units':'40', 'automatic_activation':False}
            (root/'qualification.json').write_bytes(encode(report)); os.chmod(root/'qualification.json',0o600)
            print('LARGE_JOURNAL_RECEIPT '+json.dumps(report,sort_keys=True),flush=True)
        finally: d.close(); w.close(); c.close()


if __name__ == '__main__': unittest.main()
