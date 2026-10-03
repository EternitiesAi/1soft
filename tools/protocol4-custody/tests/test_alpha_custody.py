"""Alpha encrypted/inert custody with actual original financial fixture behavior.

Synthetic public keys and owned temporary paths only; no production custody claim.
"""
import copy
import hashlib
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from block_application import encode
from commit_verifier import load_json
from p4_evidence import content_id
from alpha_wallet_fixture import PASSWORD
from test_alpha_wallet import AlphaWalletCase
from p4_alpha_delivery import P4AlphaDelivery
from p4_alpha_custody import (backup,restore_backup,RecoveryArchive,receipt_reference,
    make_receipt,verify_receipt,_seal,_unseal,MAGIC,MAX_HISTORY_BYTES)


class AlphaCustodyTests(AlphaWalletCase):
    def setUp(self):
        super().setUp()
        self.delivery=P4AlphaDelivery(self.root/'wallet.sqlite',self.root/'delivery.sqlite',
            self.c.genesis,self.c.policy,'http://127.0.0.1:26657/',self.store,
            create=True,clock=self.c.clock)
        self.backup_path=self.root/'history.p4alpha'
        self.archive_path=self.root/'history.p4alpha-inert'

    def tearDown(self):
        if hasattr(self,'delivery'):self.delivery.close()
        super().tearDown()

    def create_backup(self):
        return backup(self.delivery,self.backup_path,PASSWORD)

    def restore(self,path=None):
        return restore_backup(self.backup_path,self.archive_path if path is None else path,
                              self.c.genesis,self.c.policy,PASSWORD)

    def original_rows(self):
        return {label:{name:db.execute('SELECT * FROM '+name+' ORDER BY 1').fetchall()
                for name in names} for label,db,names in [
            ('wallet',self.w.db,['config','observations','decisions']),
            ('delivery',self.delivery.db,['config','attempts','responses','receipts']),
            ('history',self.store.db,['config','headers','blocks','checkpoints'])]}

    def recorded(self):
        result,wire=self.sign()
        self.c.block([wire]);view=self.append()
        self.delivery.import_receipt(result['decision_id'],view['checkpoint']['id'],
                                     payer=self.c.payer,grant_id='raven')
        return result,wire,view

    def test_encrypted_complete_readonly_capture_and_inert_fee_inclusive_recovery(self):
        result,wire=self.sign();before=self.original_rows()
        receipt=self.create_backup()
        self.assertEqual(self.original_rows(),before)
        self.assertTrue(self.backup_path.read_bytes().startswith(MAGIC))
        self.assertEqual(hashlib.sha256(self.backup_path.read_bytes()).hexdigest(),receipt['backup_sha256'])
        self.assertNotIn(wire,self.backup_path.read_bytes())
        restored=self.restore()
        self.assertFalse(restored['signing_enabled'])
        with RecoveryArchive(self.archive_path,self.c.genesis,self.c.policy) as archive:
            view=archive.inspect()
            self.assertEqual(view['pending_debit_units'],'60')
            self.assertFalse(view['current_spending_authority'])
            self.assertEqual(archive.recover(result['decision_id'],payer=self.c.payer,grant_id='raven'),wire)
            for forbidden in ('approve','prepare','sign','send','sync','collect','activate','wallet','delivery','db'):
                self.assertFalse(hasattr(archive,forbidden),forbidden)

    def test_expired_recovery_retains_exact_wire_and_hold_without_new_authority(self):
        result,wire=self.sign()
        expired=self.c.policy['absolute_not_after_ns']
        with self.assertRaises(ValueError):self.store.current(expired)
        # Synthetic host expiry covers export, restore and inspect; none grants authority.
        with patch('p4_alpha_custody.time.time_ns',return_value=expired):
            self.create_backup();self.restore()
            with RecoveryArchive(self.archive_path,self.c.genesis,self.c.policy) as archive:
                self.assertEqual(archive.recover(result['decision_id'],payer=self.c.payer,grant_id='raven'),wire)
                self.assertEqual(archive.inspect()['pending_debit_units'],'60')
                self.assertFalse(archive.inspect()['trust_policy_renewed'])

    def test_lost_reply_attempt_survives_and_is_never_permission_to_resend(self):
        result,wire=self.sign()
        q=self.delivery.prepare(result['decision_id'],payer=self.c.payer,grant_id='raven')
        with patch('p4_delivery.submit_once',side_effect=RuntimeError('controlled lost reply')):
            with self.assertRaises(RuntimeError):self.delivery.send(q['review'],q['confirmation'])
        self.create_backup();self.restore()
        with RecoveryArchive(self.archive_path,self.c.genesis,self.c.policy) as archive:
            row=archive.inspect()['decisions'][0]
            self.assertTrue(row['attempt_recorded'])
            self.assertEqual(row['transport_observation'],'unresolved')
            self.assertFalse(row['safe_to_resend'])
            self.assertEqual(archive.recover(result['decision_id'],payer=self.c.payer,grant_id='raven'),wire)

    def test_original_positive_receipt_and_unreconciled_hold_survive_recovery(self):
        result,wire,_=self.recorded();self.create_backup();self.restore()
        with RecoveryArchive(self.archive_path,self.c.genesis,self.c.policy) as archive:
            view=archive.inspect()
            self.assertEqual(view['pending_debit_units'],'60')
            self.assertEqual(view['decisions'][0]['delivery_receipt_status'],'verified_historical_receipt')
            capsule=archive.export_receipt(result['decision_id'],payer=self.c.payer,grant_id='raven')
        receipt=verify_receipt(capsule,self.c.genesis,self.c.policy,payer=self.c.payer,
                               wire_sha256=hashlib.sha256(wire).hexdigest())
        self.assertEqual(receipt['status'],'verified-historical-alpha-receipt')
        self.assertFalse(receipt['current_spending_authority'])

    def test_portable_receipt_prefix_and_identity_are_stable_after_progress(self):
        result,wire,view=self.recorded()
        ref=receipt_reference(self.delivery,result['decision_id'],payer=self.c.payer,grant_id='raven')
        raw=make_receipt(self.delivery,result['decision_id'],payer=self.c.payer,grant_id='raven')
        self.assertEqual(ref['checkpoint_id'],view['checkpoint']['id'])
        self.append();self.append()
        self.assertEqual(receipt_reference(self.delivery,result['decision_id'],payer=self.c.payer,grant_id='raven'),ref)
        self.assertEqual(make_receipt(self.delivery,result['decision_id'],payer=self.c.payer,grant_id='raven'),raw)
        packet=load_json(raw,max_bytes=128*1024*1024)
        self.assertEqual(packet['capsule_id'],content_id(ref))
        self.assertEqual(len(packet['history']['history']),view['checkpoint']['height'])
        self.assertEqual(len(packet['history']['headers']),view['checkpoint']['height']+1)
        self.assertEqual(verify_receipt(raw,self.c.genesis,self.c.policy,payer=self.c.payer,
                         wire_sha256=hashlib.sha256(wire).hexdigest())['capsule_id'],content_id(ref))

    def test_wrong_password_corrupt_ciphertext_and_inflated_kdf_refuse_before_output(self):
        self.sign();self.create_backup()
        with self.assertRaises(ValueError):
            restore_backup(self.backup_path,self.archive_path,self.c.genesis,self.c.policy,b'wrong long password')
        self.assertFalse(self.archive_path.exists())
        original=self.backup_path.read_bytes()
        envelope=load_json(original[len(MAGIC):],max_bytes=180*1024*1024)
        changed=copy.deepcopy(envelope);changed['header']['kdf']['n']*=2
        self.backup_path.write_bytes(MAGIC+encode(changed))
        with patch('p4_alpha_custody.Scrypt',side_effect=AssertionError('inflation must refuse before KDF')):
            with self.assertRaises(ValueError):self.restore()
        self.assertFalse(self.archive_path.exists())
        changed=copy.deepcopy(envelope)
        text=changed['ciphertext'];changed['ciphertext']=('A' if text[0]!='A' else 'B')+text[1:]
        self.backup_path.write_bytes(MAGIC+encode(changed))
        with self.assertRaises(ValueError):self.restore()
        self.assertFalse(self.archive_path.exists())

    def test_external_pins_and_legacy_formats_are_refused(self):
        self.sign();self.create_backup()
        with self.assertRaises(ValueError):
            restore_backup(self.backup_path,self.archive_path,self.c.genesis,
                           {**self.c.policy,'anchor_hash':'b'*64},PASSWORD)
        self.assertFalse(self.archive_path.exists())
        self.backup_path.write_bytes(b'1SOFTP4B3\n{}')
        with self.assertRaises(ValueError):self.restore()

    def test_coherently_rehashed_wrong_fee_review_is_not_a_valid_recovery(self):
        self.sign();self.create_backup()
        snapshot=_unseal(self.backup_path.read_bytes(),PASSWORD)
        row=snapshot['wallet']['decisions'][0]
        decision=load_json(bytes.fromhex(row[3]['hex']),max_bytes=32768)
        decision['review']['debit_units']='58'
        decision['id']=content_id(decision['review'])
        row[1]=decision['id'];row[3]={'hex':encode(decision).hex()}
        self.backup_path.write_bytes(_seal(snapshot,PASSWORD))
        with self.assertRaises(ValueError):self.restore()
        self.assertFalse(self.archive_path.exists())

    def test_missing_original_block_or_future_capture_refuses_partial_recovery(self):
        self.sign();self.create_backup()
        snapshot=_unseal(self.backup_path.read_bytes(),PASSWORD)
        for mutation in ('history','future'):
            changed=copy.deepcopy(snapshot)
            if mutation=='history':changed['history']['history'][0]['txs']=[]
            else:changed['captured_ns']=__import__('time').time_ns()+86400*10**9
            self.backup_path.write_bytes(_seal(changed,PASSWORD))
            with self.subTest(mutation=mutation),self.assertRaises(ValueError):self.restore()
            self.assertFalse(self.archive_path.exists())

    def test_output_database_alias_existing_output_and_sidecar_are_never_overwritten(self):
        self.sign();before=self.original_rows()
        with self.assertRaises(ValueError):backup(self.delivery,self.w.path,PASSWORD)
        self.assertEqual(self.original_rows(),before)
        self.create_backup();original=self.backup_path.read_bytes()
        with self.assertRaises(ValueError):self.create_backup()
        self.assertEqual(self.backup_path.read_bytes(),original)
        sidecar=Path(str(self.archive_path)+'-wal');sidecar.write_bytes(b'owned sentinel');sidecar.chmod(0o600)
        with self.assertRaises(ValueError):self.restore()
        self.assertEqual(sidecar.read_bytes(),b'owned sentinel')
        self.assertFalse(self.archive_path.exists())

    def test_fsync_before_publication_refuses_without_touching_sources(self):
        self.sign();before=self.original_rows()
        with patch('p4_alpha_custody.os.fsync',side_effect=OSError('controlled file fsync failure')):
            with self.assertRaises(OSError):self.create_backup()
        self.assertFalse(self.backup_path.exists())
        self.assertEqual(self.original_rows(),before)

    def test_directory_fsync_failure_keeps_complete_uncertain_output_and_refuses_retry(self):
        self.sign()
        import os,stat
        original=os.fsync
        def fail_directory(fd):
            if stat.S_ISDIR(os.fstat(fd).st_mode):raise OSError('controlled directory fsync failure')
            return original(fd)
        with patch('p4_alpha_custody.os.fsync',side_effect=fail_directory):
            with self.assertRaisesRegex(OSError,'published'):self.create_backup()
        self.assertTrue(self.backup_path.exists())
        _unseal(self.backup_path.read_bytes(),PASSWORD)
        with self.assertRaises(ValueError):self.create_backup()

    def test_missing_positive_receipt_never_becomes_absence_proof(self):
        result,_=self.sign()
        with self.assertRaises(ValueError):
            receipt_reference(self.delivery,result['decision_id'],payer=self.c.payer,grant_id='raven')
        self.create_backup();self.restore()
        with RecoveryArchive(self.archive_path,self.c.genesis,self.c.policy) as archive:
            with self.assertRaises(ValueError):
                archive.export_receipt(result['decision_id'],payer=self.c.payer,grant_id='raven')
            self.assertEqual(archive.inspect()['pending_debit_units'],'60')

    def test_wrong_receipt_wire_payer_or_altered_signed_history_is_refused(self):
        result,wire,_=self.recorded()
        raw=make_receipt(self.delivery,result['decision_id'],payer=self.c.payer,grant_id='raven')
        for payer,wirehash in [(self.c.merchant,hashlib.sha256(wire).hexdigest()),(self.c.payer,'a'*64)]:
            with self.assertRaises(ValueError):
                verify_receipt(raw,self.c.genesis,self.c.policy,payer=payer,wire_sha256=wirehash)
        packet=load_json(raw,max_bytes=128*1024*1024)
        packet['history']['headers'][0]['signed_header']['commit']['signatures'][0]['signature']='AA=='
        with self.assertRaises(ValueError):
            verify_receipt(encode(packet),self.c.genesis,self.c.policy,payer=self.c.payer,
                           wire_sha256=hashlib.sha256(wire).hexdigest())

    def test_plain_history_ceiling_refuses_without_creating_backup(self):
        self.sign()
        with patch('p4_alpha_custody.MAX_HISTORY_BYTES',32):
            with self.assertRaises(ValueError):self.create_backup()
        self.assertFalse(self.backup_path.exists())


    def test_wrong_live_source_application_id_cannot_be_repaired_by_backup_reconstruction(self):
        self.sign()
        self.w.db.execute('PRAGMA application_id=0x31503457')
        with self.assertRaises(ValueError):self.create_backup()
        self.assertFalse(self.backup_path.exists())

    def test_exact_original_wire_selection_refuses_wrong_recovery_role(self):
        result,_=self.sign();self.create_backup();self.restore()
        with RecoveryArchive(self.archive_path,self.c.genesis,self.c.policy) as archive:
            with self.assertRaises(ValueError):
                archive.recover(result['decision_id'],payer=self.c.payer,grant_id='atlas')
            with self.assertRaises(ValueError):
                archive.recover(result['decision_id'],payer=self.c.merchant,grant_id='raven')

    def test_noncanonical_envelope_unknown_tables_and_closed_archive_refuse(self):
        self.sign();self.create_backup()
        original=self.backup_path.read_bytes()
        self.backup_path.write_bytes(original+b'\n')
        with self.assertRaises(ValueError):self.restore()
        self.assertFalse(self.archive_path.exists())
        snapshot=_unseal(original,PASSWORD)
        snapshot['wallet']['unknown']=[]
        self.backup_path.write_bytes(_seal(snapshot,PASSWORD))
        with self.assertRaises(ValueError):self.restore()
        self.assertFalse(self.archive_path.exists())
        self.backup_path.write_bytes(original);self.restore()
        archive=RecoveryArchive(self.archive_path,self.c.genesis,self.c.policy)
        archive.close()
        with self.assertRaises(ValueError):archive.inspect()

    def test_complete_backup_beyond_64_observations_retains_history_once(self):
        # Start this disposable fixture in the past so its 65 added headers remain
        # before the actual capture clock. This is a unit fixture, not an engine run.
        import time
        fixture=AlphaWalletCase()
        with patch('alpha_wallet_fixture.time.time',return_value=time.time()-150):
            fixture.setUp()
        try:
            result,wire=fixture.sign()
            for _ in range(65):fixture.sync()
            with P4AlphaDelivery(fixture.w.path,fixture.root/'delivery.sqlite',
                    fixture.c.genesis,fixture.c.policy,'http://127.0.0.1:26657/',
                    fixture.store,create=True,clock=fixture.c.clock) as delivery:
                encrypted=fixture.root/'complete.p4alpha';inert=fixture.root/'complete.inert'
                backup(delivery,encrypted,PASSWORD)
                snapshot=_unseal(encrypted.read_bytes(),PASSWORD)
                self.assertEqual(len(snapshot['wallet']['observations']),66)
                self.assertEqual(len(snapshot['history']['history']),fixture.height)
                self.assertEqual(len(snapshot['history']['headers']),fixture.height+1)
                self.assertEqual(len(snapshot['history']['checkpoints']),66)
                for row in snapshot['wallet']['observations']:
                    reference=load_json(bytes.fromhex(row[4]['hex']),max_bytes=2048)
                    self.assertEqual(set(reference),{'schema','format','checkpoint_id','store_id','height'})
                restore_backup(encrypted,inert,fixture.c.genesis,fixture.c.policy,PASSWORD)
                with RecoveryArchive(inert,fixture.c.genesis,fixture.c.policy) as archive:
                    self.assertEqual(archive.inspect()['pending_debit_units'],'60')
                    self.assertEqual(archive.recover(result['decision_id'],payer=fixture.c.payer,grant_id='raven'),wire)
        finally:fixture.tearDown()

if __name__=='__main__':unittest.main()
