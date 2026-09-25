"""Protocol-v2 native account lifecycle. All keys and units are disposable.

The acceptance encoder here is deliberately constructed independently of the
production helper, so two implementations must agree on the signed intention.
"""
import copy
import hashlib
import json
import sqlite3
import tempfile
import threading
import unittest
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from native_core import (NativeLedger, Reject, MAX_UNITS, FEE_ACCOUNT, DOMAIN,
                         canonical, digest, address, public, sign)
from block_application import snapshot

KEYS = [Ed25519PrivateKey.from_private_bytes(bytes([i])*32) for i in range(11, 21)]
IDS = [address(public(k)) for k in KEYS]
CONSENT_DOMAIN = b'ETERNITIES/ACCOUNT-KEY-CONSENT/v2\x00'


def genesis_v2():
    return {'protocol_version': 2, 'chain_id': 'eternities-lifecycle-tests-v2',
            'asset': 'DEV', 'fee': 2, 'allocations': [
                {'public_key': public(KEYS[0]), 'units': 1000},
                {'public_key': public(KEYS[1]), 'units': 0},
                {'public_key': public(KEYS[2]), 'units': 200}]}


def independently_accept(key, body):
    accepted = copy.deepcopy(body)
    payload = copy.deepcopy(body)
    payload['op'].pop('acceptance')
    accepted['op']['acceptance'] = key.sign(CONSENT_DOMAIN + canonical(payload)).hex()
    return accepted


class AccountLifecycleTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.path = Path(self.tmp.name)/'ledger.sqlite'
        self.g = genesis_v2()
        self.db = NativeLedger(self.path, self.g)
        self.a, self.m, self.b = IDS[:3]

    def tearDown(self):
        self.db.close()
        self.tmp.cleanup()

    def body(self, op, nonce=0, sender=None, **kw):
        return self.db.body(sender or self.a, nonce, op, **kw)

    def opening(self, nonce=0, units=100, key=None, sender=None, **kw):
        key = key or KEYS[3]
        body = self.body({'type':'open_account', 'public_key':public(key),
                          'units':units, 'acceptance':''}, nonce, sender, **kw)
        return independently_accept(key, body)

    def rotating(self, nonce=0, key=None, sender=None, **kw):
        key = key or KEYS[4]
        body = self.body({'type':'rotate_key', 'public_key':public(key),
                          'acceptance':''}, nonce, sender, **kw)
        return independently_accept(key, body)

    def apply(self, body, key=None, height=1):
        return self.db.apply(sign(key or KEYS[0], body), height=height)

    def denied(self, body, key=None, height=1, message=None):
        before = snapshot(self.db)
        if message:
            with self.assertRaisesRegex(Reject, message): self.apply(body, key, height)
        else:
            with self.assertRaises(Reject): self.apply(body, key, height)
        self.assertEqual(snapshot(self.db), before, 'rejection must not change balances, keys, nonces or receipts')
        self.assertTrue(self.db.verify_receipts())

    def grant(self, nonce=0, label='raven', sender=None, key=None, agent=None, cap=80):
        return self.apply(self.body({'type':'grant','id':label,
            'public_key':public(agent or KEYS[5]),'cap':cap,'expires':100,
            'recipients':[self.m]},nonce,sender), key)

    def test_open_funds_new_account_without_minting(self):
        receipt = self.apply(self.opening())
        self.assertEqual(self.db.balance(IDS[3]), 100)
        self.assertEqual(self.db.balance(self.a), 898)
        self.assertEqual(self.db.balance(FEE_ACCOUNT), 2)
        self.assertEqual(sum(r['balance'] for r in self.db.state()['accounts']), 1200)
        self.assertEqual(self.db._account(IDS[3])['nonce'], 0)
        self.assertEqual(receipt['envelope']['body']['version'], 2)
        self.assertTrue(self.db.verify_receipts())

    def test_new_account_can_spend_in_same_height(self):
        self.apply(self.opening())
        self.apply(self.body({'type':'transfer','to':self.m,'units':20},sender=IDS[3]),KEYS[3])
        self.assertEqual(self.db.balance(IDS[3]),78)
        self.assertEqual(self.db.balance(self.m),20)

    def test_new_account_can_receive_later_payment(self):
        self.apply(self.opening())
        self.apply(self.body({'type':'transfer','to':IDS[3],'units':50},nonce=1))
        self.assertEqual(self.db.balance(IDS[3]),150)

    def test_open_requires_new_key_acceptance(self):
        for sig in ['', '0'*128, True, 12, 'f'*126, 'G'*128, '0'*130]:
            with self.subTest(sig=sig):
                b=self.opening();b['op']['acceptance']=sig;self.denied(b)

    def test_open_wrong_recipient_signature(self):
        b=self.opening(); b=independently_accept(KEYS[6],b);self.denied(b)

    def test_open_wrong_sponsor_signature(self): self.denied(self.opening(),KEYS[3])

    def test_acceptance_is_bound_to_all_intent_fields(self):
        for field,value in [('nonce',1),('valid_until',999),('max_fee',3),('sender',self.b)]:
            with self.subTest(field=field):
                b=self.opening();b[field]=value
                if field=='nonce':
                    self.apply(self.body({'type':'transfer','to':self.m,'units':1}))
                    self.denied(b,message='acceptance')
                    self.db.close();self.path.unlink();self.db=NativeLedger(self.path,self.g)
                else:self.denied(b,KEYS[2] if field=='sender' else KEYS[0],message='acceptance')

    def test_acceptance_binds_initial_funding(self):
        b=self.opening();b['op']['units']=101;self.denied(b,message='acceptance')

    def test_acceptance_binds_new_public_key(self):
        b=self.opening();b['op']['public_key']=public(KEYS[6]);self.denied(b,message='acceptance')

    def test_acceptance_binds_action(self):
        b=self.opening();b['op'].pop('units');b['op']['type']='rotate_key';self.denied(b,message='acceptance')

    def test_transaction_domain_signature_cannot_be_key_acceptance(self):
        b=self.opening(); payload=copy.deepcopy(b);payload['op'].pop('acceptance')
        b['op']['acceptance']=KEYS[3].sign(DOMAIN+canonical(payload)).hex()
        self.denied(b,message='acceptance')

    def test_acceptance_rejected_on_different_genesis(self):
        b=self.opening(); self.db.close();self.path.unlink()
        g=genesis_v2();g['fee']=3;self.db=NativeLedger(self.path,g)
        b['genesis_hash']=digest(g);b['max_fee']=3;self.denied(b,message='acceptance')

    def test_acceptance_rejected_on_different_chain(self):
        b=self.opening();self.db.close();self.path.unlink()
        g=genesis_v2();g['chain_id']='other-lifecycle';self.db=NativeLedger(self.path,g)
        b['chain_id']=g['chain_id'];b['genesis_hash']=digest(g);self.denied(b,message='acceptance')

    def test_duplicate_open_does_not_reset_existing_balance(self):
        self.apply(self.opening());self.denied(self.opening(nonce=1))
        self.assertEqual(self.db.balance(IDS[3]),100)

    def test_open_existing_genesis_account_rejected(self): self.denied(self.opening(key=KEYS[1]))

    def test_open_zero_negative_or_noninteger_funding_rejected(self):
        for value in [0,-1,True,1.5,'100',MAX_UNITS+1]:
            with self.subTest(value=value):self.denied(self.opening(units=value))

    def test_open_includes_fee_in_affordability(self): self.denied(self.opening(units=999))

    def test_open_insufficient_funds_leaves_no_account(self):
        self.denied(self.opening(units=999))
        with self.assertRaises(Reject):self.db.balance(IDS[3])

    def test_open_overflow_rejected(self): self.denied(self.opening(units=MAX_UNITS))

    def test_open_expired_intention(self): self.denied(self.opening(valid_until=0))

    def test_open_fee_above_consent(self): self.denied(self.opening(max_fee=1))

    def test_open_unknown_fields_rejected(self):
        b=self.opening();b['op']['display_name']='Raven';self.denied(b)

    def test_open_missing_fields_rejected(self):
        for field in ['public_key','units','acceptance']:
            b=self.opening();b['op'].pop(field);self.denied(b)

    def test_open_invalid_public_key_rejected(self):
        for value in [True,23,'','f'*62,'G'*64]:
            b=self.opening();b['op']['public_key']=value;self.denied(b)

    def test_delegate_cannot_open_account(self):
        self.grant();self.denied(self.opening(grant_id='raven'),KEYS[5])

    def test_open_retry_historical_only_no_double_funding(self):
        b=self.opening();r=self.apply(b);self.assertEqual(self.apply(b,height=2000),r)
        self.assertEqual(self.db.balance(IDS[3]),100)

    def test_rotate_keeps_stable_account_and_fences_grants(self):
        self.grant();r=self.apply(self.rotating(nonce=1))
        account=self.db._account(self.a)
        self.assertEqual((account['id'],account['public_key'],account['epoch'],account['nonce'],account['balance']),
                         (self.a,public(KEYS[4]),1,2,996))
        self.denied(self.body({'type':'transfer','to':self.m,'units':1},grant_id='raven'),KEYS[5])
        self.assertEqual(r['signer_public_key'],public(KEYS[0]))

    def test_old_owner_key_cannot_authorize_new_transaction(self):
        self.apply(self.rotating());self.denied(self.body({'type':'transfer','to':self.m,'units':10},nonce=1),KEYS[0])

    def test_new_key_can_spend_from_stable_original_id(self):
        self.apply(self.rotating())
        self.apply(self.body({'type':'transfer','to':self.m,'units':10},nonce=1),KEYS[4])
        self.assertEqual(self.db.balance(self.a),986)
        with self.assertRaises(Reject):self.db.balance(IDS[4])

    def test_pending_old_key_intent_cannot_survive_rotation(self):
        pending=self.body({'type':'transfer','to':self.m,'units':10},nonce=1)
        envelope=sign(KEYS[0],pending);self.apply(self.rotating())
        before=snapshot(self.db)
        with self.assertRaises(Reject):self.db.apply(envelope,height=2)
        self.assertEqual(before,snapshot(self.db))

    def test_rotate_cannot_take_over_without_current_owner(self): self.denied(self.rotating(),KEYS[4])

    def test_rotate_requires_new_key_possession(self):
        b=self.rotating();b=independently_accept(KEYS[6],b);self.denied(b,message='acceptance')

    def test_rotate_missing_acceptance(self):
        b=self.rotating();b['op'].pop('acceptance');self.denied(b)

    def test_rotate_empty_acceptance(self):
        b=self.rotating();b['op']['acceptance']='';self.denied(b)

    def test_rotate_same_key_rejected(self):self.denied(self.rotating(key=KEYS[0]))

    def test_rotate_to_other_accounts_active_key_rejected(self):self.denied(self.rotating(key=KEYS[1]))

    def test_delegated_key_cannot_rotate_owner(self):
        self.grant();self.denied(self.rotating(grant_id='raven'),KEYS[5])

    def test_rotate_fee_failure_rolls_back_key_and_epoch(self):
        self.apply(self.body({'type':'transfer','to':self.m,'units':997}))
        self.denied(self.rotating(nonce=1));self.assertEqual(self.db._account(self.a)['epoch'],0)

    def test_rotate_does_not_reset_nonce(self):
        self.apply(self.body({'type':'transfer','to':self.m,'units':1}))
        self.apply(self.rotating(nonce=1));self.assertEqual(self.db._account(self.a)['nonce'],2)
        self.denied(self.body({'type':'transfer','to':self.m,'units':1},nonce=0),KEYS[4])

    def test_new_grant_after_rotation_requires_explicit_budget(self):
        self.grant();self.apply(self.rotating(nonce=1))
        self.grant(nonce=2,label='raven-new',key=KEYS[4],cap=12)
        self.apply(self.body({'type':'transfer','to':self.m,'units':10},grant_id='raven-new'),KEYS[5])
        self.denied(self.body({'type':'transfer','to':self.m,'units':1},nonce=1,grant_id='raven-new'),KEYS[5])

    def test_rotation_does_not_refill_old_grant(self):
        self.grant(cap=50)
        self.apply(self.body({'type':'transfer','to':self.m,'units':10},grant_id='raven'),KEYS[5])
        before=[dict(r) for r in self.db.db.execute('SELECT * FROM grants')]
        self.apply(self.rotating(nonce=1))
        after=[dict(r) for r in self.db.db.execute('SELECT * FROM grants')]
        self.assertEqual(before,after)
        self.denied(self.body({'type':'transfer','to':self.m,'units':1},nonce=1,grant_id='raven'),KEYS[5])

    def test_rotate_historical_retry_does_not_change_key_back(self):
        b=self.rotating();r=self.apply(b)
        self.apply(self.rotating(nonce=1,key=KEYS[6]),KEYS[4])
        self.assertEqual(self.apply(b),r)
        self.assertEqual(self.db._account(self.a)['public_key'],public(KEYS[6]))

    def test_rotate_epoch_overflow_rejected(self):
        self.db.db.execute('UPDATE accounts SET epoch=? WHERE id=?',(MAX_UNITS,self.a))
        before=snapshot(self.db)
        with self.assertRaises(Reject):self.apply(self.rotating())
        self.assertEqual(before,snapshot(self.db))

    def test_rotate_acceptance_not_reusable_for_later_nonce(self):
        b=self.rotating();self.apply(self.body({'type':'transfer','to':self.m,'units':1}))
        b['nonce']=1;self.denied(b,message='acceptance')

    def test_rotate_unknown_fields(self):
        b=self.rotating();b['op']['keep_old_grants']=True;self.denied(b)

    def test_open_cannot_duplicate_active_rotated_key(self):
        self.apply(self.rotating())
        self.denied(self.opening(sender=self.b,key=KEYS[4]),KEYS[2])

    def test_two_owners_can_use_same_grant_label(self):
        self.grant(label='raven')
        try:self.grant(sender=self.b,key=KEYS[2],label='raven')
        except Reject as exc:self.fail('different owners must be able to use the same label: '+str(exc))
        self.apply(self.body({'type':'transfer','to':self.m,'units':10},grant_id='raven'),KEYS[5])
        self.apply(self.body({'type':'transfer','to':self.m,'units':11},sender=self.b,grant_id='raven'),KEYS[5])
        self.assertEqual(self.db.balance(self.m),21)
        self.assertEqual(len(self.db.state()['grants']),2)

    def test_namespaced_revoke_does_not_revoke_other_owner(self):
        self.grant();self.grant(sender=self.b,key=KEYS[2])
        self.apply(self.body({'type':'revoke','id':'raven'},nonce=1))
        self.denied(self.body({'type':'transfer','to':self.m,'units':1},grant_id='raven'),KEYS[5])
        self.apply(self.body({'type':'transfer','to':self.m,'units':1},sender=self.b,grant_id='raven'),KEYS[5])

    def test_duplicate_grant_label_same_owner_still_rejected(self):
        self.grant()
        body=self.body({'type':'grant','id':'raven','public_key':public(KEYS[5]),
            'cap':90,'expires':100,'recipients':[self.m]},nonce=1)
        self.denied(body)

    def test_revoked_label_cannot_silently_reset_budget(self):
        self.grant();self.apply(self.body({'type':'revoke','id':'raven'},nonce=1))
        body=self.body({'type':'grant','id':'raven','public_key':public(KEYS[5]),
            'cap':90,'expires':100,'recipients':[self.m]},nonce=2)
        self.denied(body)

    def test_namespace_injection_cannot_select_other_owner(self):
        self.grant();self.grant(sender=self.b,key=KEYS[2])
        b=self.body({'type':'transfer','to':self.m,'units':1},grant_id=self.b+'::raven')
        self.denied(b,KEYS[5])

    def test_restart_preserves_rotated_identity_and_receipts(self):
        self.apply(self.opening());self.apply(self.rotating(nonce=1))
        before=snapshot(self.db);self.db.close();self.db=NativeLedger(self.path,self.g)
        self.assertEqual(snapshot(self.db),before);self.assertTrue(self.db.verify_receipts())
        self.apply(self.body({'type':'transfer','to':self.m,'units':1},nonce=2),KEYS[4])

    def test_replay_on_independent_database(self):
        other=NativeLedger(':memory:',self.g)
        try:
            for body,key in [(self.opening(),KEYS[0]),(self.rotating(nonce=1),KEYS[0]),
                (self.body({'type':'transfer','to':self.m,'units':7},nonce=2),KEYS[4])]:
                env=sign(key,body)
                self.assertEqual(self.db.apply(env,height=1),other.apply(env,height=1))
            self.assertEqual(snapshot(self.db),snapshot(other))
        finally:other.close()

    def test_concurrent_sponsors_cannot_fund_duplicate_identity(self):
        first=self.opening(units=100)
        second=self.opening(units=100,sender=self.b)
        barrier=threading.Barrier(2)
        def worker(pair):
            body,key=pair;db=NativeLedger(self.path,self.g)
            try:
                barrier.wait(timeout=5)
                try:db.apply(sign(key,body),height=1);return 'accepted'
                except Reject:return 'rejected'
            finally:db.close()
        with ThreadPoolExecutor(max_workers=2) as ex:
            result=list(ex.map(worker,[(first,KEYS[0]),(second,KEYS[2])]))
        self.assertEqual(sorted(result),['accepted','rejected'])
        self.assertEqual(self.db.balance(IDS[3]),100)
        self.assertEqual(self.db.balance(FEE_ACCOUNT),2)
        self.assertTrue(self.db.verify_receipts())

    def test_helper_matches_independent_signature(self):
        from native_core import accept_account_key
        body=self.rotating();body['op']['acceptance']=''
        before=copy.deepcopy(body)
        self.assertEqual(accept_account_key(KEYS[4],body),independently_accept(KEYS[4],body))
        self.assertEqual(body,before)

    def test_helper_rejects_wrong_new_key(self):
        from native_core import accept_account_key
        with self.assertRaises(Reject):accept_account_key(KEYS[6],self.rotating())


class ProtocolVersionTests(unittest.TestCase):
    def test_legacy_genesis_retains_v1(self):
        g=genesis_v2();g.pop('protocol_version');db=NativeLedger(':memory:',g)
        try:self.assertEqual(db.body(IDS[0],0,{'type':'fence'})['version'],1)
        finally:db.close()

    def test_explicit_v1_retains_v1(self):
        g=genesis_v2();g['protocol_version']=1;db=NativeLedger(':memory:',g)
        try:self.assertEqual(db.body(IDS[0],0,{'type':'fence'})['version'],1)
        finally:db.close()

    def test_invalid_protocol_versions(self):
        for version in [True,False,0,4,'2',2.0,None]:
            with self.subTest(version=version):
                g=genesis_v2();g['protocol_version']=version
                with self.assertRaises(Reject):NativeLedger(':memory:',g)

    def test_v1_rejects_v2_operations_even_with_valid_signatures(self):
        g=genesis_v2();g.pop('protocol_version');db=NativeLedger(':memory:',g)
        try:
            for op in [{'type':'open_account','public_key':public(KEYS[3]),'units':10,'acceptance':'0'*128},
                       {'type':'rotate_key','public_key':public(KEYS[4]),'acceptance':'0'*128}]:
                b=db.body(IDS[0],0,op);before=snapshot(db)
                with self.assertRaises(Reject):db.apply(sign(KEYS[0],b),height=1)
                self.assertEqual(before,snapshot(db))
        finally:db.close()

    def test_v2_rejects_v1_transaction_version(self):
        db=NativeLedger(':memory:',genesis_v2())
        try:
            b=db.body(IDS[0],0,{'type':'fence'});b['version']=1
            with self.assertRaises(Reject):db.apply(sign(KEYS[0],b),height=1)
        finally:db.close()

    def test_genesis_protocol_version_is_part_of_chain_binding(self):
        g=genesis_v2();v1=copy.deepcopy(g);v1['protocol_version']=1
        self.assertNotEqual(digest(g),digest(v1))

    def test_reopen_rejects_protocol_change(self):
        with tempfile.TemporaryDirectory() as d:
            path=Path(d)/'l.sqlite';g=genesis_v2();db=NativeLedger(path,g);db.close()
            g['protocol_version']=1
            with self.assertRaises(Reject):NativeLedger(path,g)
