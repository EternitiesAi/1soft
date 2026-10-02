"""Native key rotation, canonical reservations and authenticated proof fixtures."""
import copy
from pathlib import Path
import tempfile
import unittest
from concurrent.futures import ThreadPoolExecutor
from unittest.mock import patch
from cryptography.hazmat.primitives import serialization as ser
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from block_application import restore
from native_core import canonical, public, sign, accept_account_key
from p4_evidence import content_id
from p4_wallet import P4Wallet
from p4_delivery import P4Delivery
from wallet_fixture import Chain, PASSWORD


class RotationTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(); self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name); self.c = Chain(self.root); self.addCleanup(self.c.close)
        self.wp = self.root/'wallet.sqlite'; self.dp = self.root/'delivery.sqlite'
        self.w = P4Wallet(self.wp,self.c.genesis,self.c.policy,create=True,clock=self.c.clock)
        self.addCleanup(self.w.close); self.w.sync(self.c.evidence(),expected_revision=None)
        self.new = Ed25519PrivateKey.from_private_bytes(b'\xa2'*32)
        self.vault = self.root/'incoming.pem'
        self.vault.write_bytes(self.new.private_bytes(ser.Encoding.PEM,ser.PrivateFormat.PKCS8,
                              ser.BestAvailableEncryption(PASSWORD))); self.vault.chmod(0o600)
        self.d = P4Delivery(self.wp,self.dp,self.c.genesis,self.c.policy,
                           'http://127.0.0.1:26657/',create=True,clock=self.c.clock)
        self.addCleanup(self.d.close)

    def prepare(self):
        return self.w.prepare_rotation(payer=self.c.payer,new_public_key=public(self.new),valid_until=30)

    def accept(self,q=None):
        q = q or self.prepare()
        return self.w.accept_rotation(q['review'],q['confirmation'],incoming_vault=self.vault,password=PASSWORD)

    def approve(self,q=None):
        q = q or self.accept()
        return self.w.approve_rotation(q['review'],q['confirmation'],owner_vault=self.root/'owner.pem',password=PASSWORD)

    def payment(self,role='raven',units=58):
        q=self.w.prepare(payer=self.c.payer,recipient=self.c.merchant,units=units,grant_id=role,valid_until=30)
        return self.w.approve(q['review'],q['confirmation'],vault=self.root/((role or 'owner')+'.pem'),password=PASSWORD)

    def sync(self):
        self.w.sync(self.c.evidence(),expected_revision=self.w.status()['revision'])

    def test_prepare_and_incoming_consent_never_reserve_or_owner_sign(self):
        before=list(self.w.db.iterdump()); q=self.prepare(); a=self.accept(q)
        self.assertFalse(q['reserved']); self.assertFalse(a['owner_signed'])
        self.assertEqual(self.w.status()['pending_debit_units'],'0')
        self.assertEqual(list(self.w.db.iterdump()),before)
        self.assertEqual(a['review']['body']['nonce'],3)
        self.assertEqual(a['review']['body']['grant_id'],'')
        self.assertEqual(len(a['review']['body']['op']['acceptance']),128)

    def test_owner_approval_reserves_only_fee_and_original_wire_survives_reopen(self):
        r=self.approve(); self.assertEqual(self.w.status()['pending_debit_units'],'2')
        self.assertFalse(r['broadcast'])
        self.assertEqual(self.w.recover(r['decision_id'],payer=self.c.payer),canonical(r['transaction']))
        with P4Wallet(self.wp,self.c.genesis,self.c.policy,clock=self.c.clock) as other:
            self.assertEqual(other.status()['decisions'][0]['status'],'pending')

    def test_stale_consent_is_refused_before_old_owner_unlock(self):
        q=self.accept(); self.payment()
        with patch('p4_wallet._load_vault',side_effect=AssertionError('must not unlock')):
            with self.assertRaises(ValueError): self.approve(q)
        self.assertEqual(self.w.status()['pending_debit_units'],'60')

    def test_pending_rotation_quiesces_all_payer_payments_and_original_dispatch(self):
        payment=self.payment(); rotation=self.approve()
        for role in ('','raven','atlas'):
            with self.subTest(role=role),self.assertRaisesRegex(ValueError,'rotation'):
                self.w.prepare(payer=self.c.payer,recipient=self.c.merchant,units=1,grant_id=role,valid_until=30)
        with self.assertRaisesRegex(ValueError,'rotation'):
            self.d.prepare(payment['decision_id'],payer=self.c.payer,grant_id='raven')
        q=self.d.prepare(rotation['decision_id'],payer=self.c.payer)
        self.assertEqual(q['review']['debit_units'],'2')
        self.assertEqual(self.w.status()['pending_debit_units'],'62')

    def test_positive_rotation_preserves_unknown_payment_hold_and_retires_old_keys(self):
        payment=self.payment(); rotation=self.approve()
        self.c.block([canonical(rotation['transaction'])]); evidence=self.c.evidence()
        report=self.w.rotation_status(rotation['decision_id'],payer=self.c.payer,evidence=evidence)
        self.assertTrue(report['old_owner_retired_at_checkpoint'])
        self.assertTrue(report['replacement_owner_active_at_checkpoint'])
        self.assertEqual(report['receipt_epoch_before'],0); self.assertEqual(report['receipt_epoch_after'],1)
        self.assertFalse(report['physical_device_fenced']); self.assertFalse(report['latest_state_guaranteed'])
        self.w.sync(evidence,expected_revision=self.w.status()['revision'])
        self.assertEqual(self.w.status()['pending_debit_units'],'60')
        self.assertEqual(self.w.recover(payment['decision_id'],payer=self.c.payer,grant_id='raven'),canonical(payment['transaction']))
        with self.assertRaises(ValueError):
            self.w.prepare(payer=self.c.payer,recipient=self.c.merchant,units=1,grant_id='atlas',valid_until=30)
        q=self.w.prepare(payer=self.c.payer,recipient=self.c.merchant,units=1,valid_until=30)
        self.assertEqual(q['review']['signer_public_key'],public(self.new))
        with self.assertRaises(ValueError):
            self.w.approve(q['review'],q['confirmation'],vault=self.root/'owner.pem',password=PASSWORD)
        r=self.w.approve(q['review'],q['confirmation'],vault=self.vault,password=PASSWORD)
        ledger=restore(self.c.g,evidence['state']['native'])
        try:
            b=ledger.body(self.c.payer,4,{'type':'transfer','to':self.c.merchant,'units':1},valid_until=30)
            with self.assertRaises(ValueError): ledger.apply(sign(self.c.owner,b),height=evidence['state']['height']+1)
            with self.assertRaises(ValueError): ledger.apply(payment['transaction'],height=evidence['state']['height']+1)
            ledger.apply(r['transaction'],height=evidence['state']['height']+1)
        finally: ledger.close()

    def test_absent_receipt_and_expiry_never_fence_or_release_holds(self):
        r=self.approve(); self.c.block()
        report=self.w.rotation_status(r['decision_id'],payer=self.c.payer,evidence=self.c.evidence())
        self.assertEqual(report['status'],'rotation-unobserved')
        self.assertFalse(report['old_owner_retired_at_checkpoint'])
        self.assertEqual(self.w.status()['pending_debit_units'],'2')

    def test_transfer_approval_cannot_implicitly_approve_administration(self):
        q=self.accept()
        with patch('p4_wallet._load_vault',side_effect=AssertionError('must not unlock')):
            with self.assertRaises(ValueError):
                self.w.approve(q['review'],q['confirmation'],vault=self.root/'owner.pem',password=PASSWORD)

    def test_rotation_refuses_unresolved_owner_nonce_even_with_spare_balance(self):
        self.payment('',1)
        with self.assertRaisesRegex(ValueError,'unresolved'): self.prepare()

    def test_wrong_incoming_or_owner_vault_never_creates_a_decision(self):
        q=self.prepare()
        with self.assertRaisesRegex(ValueError,'incoming key'):
            self.w.accept_rotation(q['review'],q['confirmation'],incoming_vault=self.root/'owner.pem',password=PASSWORD)
        a=self.accept(q)
        with self.assertRaisesRegex(ValueError,'reviewed owner'):
            self.w.approve_rotation(a['review'],a['confirmation'],owner_vault=self.vault,password=PASSWORD)
        self.assertEqual(self.w.status()['decisions'],[])

    def test_all_intent_mutations_fail_before_old_owner_unlock_even_when_rehashed(self):
        original=self.accept()
        changes=(('nonce',4),('valid_until',29),('max_fee',3),('chain_id','other'),
                 ('genesis_hash','0'*64),('sender',self.c.merchant),('grant_id','raven'))
        for field,value in changes:
            q=copy.deepcopy(original); q['review']['body'][field]=value
            q['confirmation']=content_id(q['review'])
            with self.subTest(field=field),patch('p4_wallet._load_vault',side_effect=AssertionError('must not unlock')):
                with self.assertRaises(ValueError):self.approve(q)
        self.assertEqual(self.w.status()['decisions'],[])

    def test_forged_cached_authority_and_unknown_fields_fail_before_unlock(self):
        for field,value in (('payer_epoch',1),('debit_units','0'),('affected_grants',[]),
                            ('signer_public_key',public(self.new)),('approved',True),('format','other')):
            q=self.accept(); q['review'][field]=value; q['confirmation']=content_id(q['review'])
            with self.subTest(field=field),patch('p4_wallet._load_vault',side_effect=AssertionError('must not unlock')):
                with self.assertRaises(ValueError):self.approve(q)

    def test_missing_consent_and_changed_consent_refused_before_owner_unlock(self):
        for acceptance in ('','0'*128):
            q=self.accept();q['review']['body']['op']['acceptance']=acceptance
            q['confirmation']=content_id(q['review'])
            with self.subTest(acceptance=bool(acceptance)),patch('p4_wallet._load_vault',side_effect=AssertionError('must not unlock')):
                with self.assertRaises(ValueError):self.approve(q)

    def test_changed_checkpoint_invalidates_incoming_consent_before_unlock(self):
        q=self.prepare();self.c.block();self.sync()
        with patch('p4_wallet._load_vault',side_effect=AssertionError('must not unlock')):
            with self.assertRaises(ValueError):self.accept(q)

    def test_clock_expiry_during_vault_access_cannot_commit_rotation(self):
        from offline_signer import _load_vault
        q=self.accept()
        def delayed(v,p):
            key=_load_vault(v,p);self.c.now+=4000*10**9;return key
        with patch('p4_wallet._load_vault',side_effect=delayed):
            with self.assertRaises(ValueError):self.approve(q)
        self.assertEqual(self.w.db.execute('SELECT count(*) FROM decisions').fetchone()[0],0)

    def test_two_concurrent_owner_approvals_commit_only_one_original_wire(self):
        q=self.accept()
        def run(_):
            with P4Wallet(self.wp,self.c.genesis,self.c.policy,clock=self.c.clock) as wallet:
                try:
                    return wallet.approve_rotation(q['review'],q['confirmation'],owner_vault=self.root/'owner.pem',password=PASSWORD)['status']
                except ValueError:return 'refused'
        with ThreadPoolExecutor(max_workers=2) as executor: outcomes=list(executor.map(run,range(2)))
        self.assertEqual(sorted(outcomes),['refused','signed_and_reserved'])
        self.assertEqual(self.w.status()['pending_debit_units'],'2')
        self.assertEqual(len(self.w.status()['decisions']),1)

    def test_same_or_existing_account_key_and_malformed_pubkey_refused(self):
        for key in (public(self.c.owner),public(self.c.merchant_key),'A'*64,'0'*63,True):
            with self.subTest(key=key),self.assertRaises(ValueError):
                self.w.prepare_rotation(payer=self.c.payer,new_public_key=key,valid_until=30)

    def test_exact_rotation_delivery_claim_is_consumed_before_failed_io(self):
        r=self.approve();q=self.d.prepare(r['decision_id'],payer=self.c.payer)
        with patch('p4_delivery.submit_once',side_effect=RuntimeError('injected loss')):
            with self.assertRaises(RuntimeError):self.d.send(q['review'],q['confirmation'])
        self.assertEqual(self.w.status()['pending_debit_units'],'2')
        with self.assertRaises(ValueError):self.d.prepare(r['decision_id'],payer=self.c.payer)
        self.assertEqual(self.w.recover(r['decision_id'],payer=self.c.payer),canonical(r['transaction']))

    def test_recovery_archive_retains_rotation_hold_and_consumed_payment_claim(self):
        from p4_custody import backup,restore_backup,RecoveryArchive
        payment=self.payment();q=self.d.prepare(payment['decision_id'],payer=self.c.payer,grant_id='raven')
        with patch('p4_delivery.submit_once',side_effect=RuntimeError('injected loss')):
            with self.assertRaises(RuntimeError):self.d.send(q['review'],q['confirmation'])
        r=self.approve();bp=self.root/'backup';ap=self.root/'archive'
        backup(self.d,bp,b'public backup fixture passphrase')
        restore_backup(bp,ap,self.c.genesis,self.c.policy,b'public backup fixture passphrase')
        with RecoveryArchive(ap,self.c.genesis,self.c.policy) as a:
            view=a.inspect();self.assertEqual(view['pending_debit_units'],'62')
            self.assertFalse(view['signing_enabled']);self.assertFalse(view['dispatch_enabled'])
            self.assertFalse(view['old_device_fenced'])
            self.assertEqual(a.recover(r['decision_id'],payer=self.c.payer),canonical(r['transaction']))

    def test_later_rotation_back_to_old_key_is_not_permanent_old_owner_fencing(self):
        r=self.approve();self.c.block([canonical(r['transaction'])])
        ledger=restore(self.c.g,self.c.app.state['native'])
        try:
            body=ledger.body(self.c.payer,4,{'type':'rotate_key','public_key':public(self.c.owner),'acceptance':''},valid_until=30)
            packet=sign(self.new,accept_account_key(self.c.owner,body))
        finally:ledger.close()
        self.c.block([canonical(packet)]);report=self.w.rotation_status(r['decision_id'],payer=self.c.payer,evidence=self.c.evidence())
        self.assertEqual(report['status'],'rotation-recorded')
        self.assertEqual(report['receipt_epoch_after'],1);self.assertEqual(report['checkpoint_epoch'],2)
        self.assertFalse(report['old_owner_retired_at_checkpoint'])
        self.assertFalse(report['replacement_owner_active_at_checkpoint'])
        self.assertTrue(report['original_grants_retired_at_checkpoint'])
        self.assertFalse(report['physical_device_fenced'])

    def test_conflicting_or_regressing_or_mutated_evidence_never_reports_fencing(self):
        r=self.approve();self.c.block([canonical(r['transaction'])]);e=self.c.evidence()
        bad=copy.deepcopy(e);bad['state']['native']['accounts'][1][1]='0'*64
        for proof in (bad,{'status':'confirmed'},copy.deepcopy(e)|{'history':[]}):
            with self.subTest(proof=proof.get('status','packet')),self.assertRaises((ValueError,KeyError)):
                self.w.rotation_status(r['decision_id'],payer=self.c.payer,evidence=proof)

    def test_saved_rotation_audit_rejects_rehashed_corrupted_origin(self):
        from block_application import encode
        self.approve();seq,_,at,raw=self.w.db.execute('SELECT * FROM decisions').fetchone()
        import json
        d=json.loads(raw);d['review']['payer_epoch']=1;d['id']=content_id(d['review'])
        self.w.db.execute('UPDATE decisions SET decision_id=?,payload=? WHERE seq=?',(d['id'],encode(d),seq))
        with self.assertRaises(ValueError):self.w.status()

    def test_malformed_rotation_reviews_have_controlled_refusal_before_key_access(self):
        values=([],None,True,'review',{'format':'1soft/p4-key-rotation-review/v1'},
                {'format':'1soft/p4-key-rotation-review/v1','body':None})
        for value in values:
            for method,vault_arg in ((self.w.accept_rotation,'incoming_vault'),(self.w.approve_rotation,'owner_vault')):
                with self.subTest(value=value,method=method.__name__),patch('p4_wallet._load_vault',side_effect=AssertionError('must not unlock')):
                    with self.assertRaises(ValueError):
                        method(value,content_id(value),**{vault_arg:self.vault},password=PASSWORD)


if __name__=='__main__': unittest.main()
