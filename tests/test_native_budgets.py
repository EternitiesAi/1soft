"""Protocol 3 aggregate spending; actual signatures/SQLite, no validator consensus."""
import copy
import hashlib
import json
import os
from pathlib import Path
import random
import subprocess
import sys
import tempfile
import threading
import unittest
from concurrent.futures import ThreadPoolExecutor
from unittest.mock import patch
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from native_core import NativeLedger, Reject, address, public, sign, canonical, accept_account_key, FEE_ACCOUNT
from block_application import snapshot, restore, application_hash

ROOT = Path(__file__).resolve().parents[1]
KEYS = [Ed25519PrivateKey.from_private_bytes(bytes([i])*32) for i in range(71, 77)]
IDS = [address(public(k)) for k in KEYS]


def genesis(version=3):
    return {'chain_id':'1soft-shared-budget-dev','asset':'DEV','fee':2,'protocol_version':version,
        'allocations':[{'public_key':public(KEYS[i]),'units':10000 if i == 0 else (1000 if i == 4 else 0)} for i in (0,1,4)]}


def budget_op(label='project', cap=100, expires=90):
    return {'type':'budget_create','id':label,'cap':cap,'expires':expires,'recipients':[IDS[1]]}


def grant_op(label='raven', key=KEYS[2], budget='project', cap=100, expires=80):
    return {'type':'grant','id':label,'public_key':public(key),'cap':cap,'expires':expires,
            'recipients':[IDS[1]],'budget_id':budget}


class NativeBudgetTests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory();self.root=Path(self.tmp.name);self.path=self.root/'ledger.sqlite'
        self.g=genesis();self.l=NativeLedger(self.path,self.g)
    def tearDown(self):self.l.close();self.tmp.cleanup()
    def apply(self,op,key=KEYS[0],sender=IDS[0],height=1,grant='',nonce=None):
        if nonce is None:
            nonce=self.l._account(sender)['nonce'] if not grant else self.l.db.execute('SELECT nonce FROM grants WHERE id=?',(self.l.grant_storage_id(sender,grant),)).fetchone()[0]
        return self.l.apply(sign(key,self.l.body(sender,nonce,op,grant_id=grant)),height=height)
    def setup_budget(self,cap=100):
        self.apply(budget_op(cap=cap));self.apply(grant_op(cap=cap));self.apply(grant_op('atlas',KEYS[3],cap=cap))
    def spend(self,units,key=KEYS[2],grant='raven',height=2):
        return self.apply({'type':'transfer','to':IDS[1],'units':units},key,grant=grant,height=height)
    def denied(self,call):
        before=snapshot(self.l)
        with self.assertRaises(Reject):call()
        self.assertEqual(snapshot(self.l),before);self.assertTrue(self.l.verify_receipts())
    def test_every_v3_agent_grant_requires_budget(self):
        op=grant_op();del op['budget_id'];self.denied(lambda:self.apply(op))
    def test_unknown_budget_refuses_and_rolls_back_inserted_grant(self):
        self.denied(lambda:self.apply(grant_op()));self.assertEqual(self.l.state()['grants'],[])
    def test_two_distinct_keys_share_aggregate_and_fee_allowance(self):
        self.setup_budget();self.spend(58)
        self.denied(lambda:self.spend(39,KEYS[3],'atlas'))
        self.spend(38,KEYS[3],'atlas')
        self.assertEqual(self.l.state()['budgets'][0]['spent'],100)
        self.assertEqual(sorted(r['spent'] for r in self.l.state()['grants']),[40,60])
        self.assertEqual(self.l.balance(IDS[1]),96);self.assertEqual(self.l.balance(FEE_ACCOUNT),10)
        self.denied(lambda:self.spend(1))
    def test_aggregate_applies_even_when_each_grant_individually_fits(self):
        self.setup_budget();self.spend(60)
        self.denied(lambda:self.spend(40,KEYS[3],'atlas'))
    def test_individual_limit_still_enforced(self):
        self.apply(budget_op());self.apply(grant_op(cap=20));self.denied(lambda:self.spend(19))
    def test_grant_cannot_widen_parent_recipients(self):
        self.apply(budget_op());op=grant_op();op['recipients']=[IDS[4]];self.denied(lambda:self.apply(op))
    def test_grant_cannot_outlive_parent(self):
        self.apply(budget_op());self.denied(lambda:self.apply(grant_op(expires=91)))
    def test_grant_cannot_exceed_parent_cap(self):
        self.apply(budget_op());self.denied(lambda:self.apply(grant_op(cap=101)))
    def test_budget_expiry_blocks_all_grants(self):
        self.setup_budget();self.denied(lambda:self.spend(1,height=91))
    def test_revoking_budget_blocks_all_grants_without_resetting_spent(self):
        self.setup_budget();self.spend(10)
        self.apply({'type':'budget_revoke','id':'project'},height=2)
        self.denied(lambda:self.spend(1));self.denied(lambda:self.spend(1,KEYS[3],'atlas'))
        self.assertEqual(self.l.state()['budgets'][0]['spent'],12)
    def test_revoked_budget_cannot_accept_new_grant(self):
        self.setup_budget();self.apply({'type':'budget_revoke','id':'project'})
        self.denied(lambda:self.apply(grant_op('worker3',KEYS[5])))
    def test_revoked_grant_does_not_return_allowance(self):
        self.setup_budget();self.spend(58);self.apply({'type':'revoke','id':'raven'},height=2)
        self.denied(lambda:self.spend(39,KEYS[3],'atlas'));self.spend(38,KEYS[3],'atlas')
    def test_budget_name_cannot_be_reset_after_revoke(self):
        self.setup_budget();self.apply({'type':'budget_revoke','id':'project'})
        self.denied(lambda:self.apply(budget_op(cap=1000)))
    def test_grant_cannot_rebind_to_other_budget(self):
        self.setup_budget();self.apply(budget_op('another'))
        self.denied(lambda:self.apply(grant_op(budget='another')))
    def test_multiple_owners_can_use_same_labels(self):
        self.setup_budget();self.apply(budget_op(),KEYS[4],IDS[4]);self.apply(grant_op(),KEYS[4],IDS[4])
        self.assertEqual(len(self.l.state()['budgets']),2);self.assertEqual(len(self.l.state()['grants']),3)
    def test_owner_cannot_use_another_owners_pool(self):
        self.setup_budget();self.denied(lambda:self.apply(grant_op(),KEYS[4],IDS[4]))
    def test_agent_cannot_create_revoke_or_expand_budgets(self):
        self.setup_budget()
        for op in [budget_op('new'),{'type':'budget_revoke','id':'project'},grant_op('new')]:
            self.denied(lambda op=op:self.apply(op,KEYS[2],grant='raven'))
    def test_fence_invalidates_budget_and_grants_but_retains_spending(self):
        self.setup_budget();self.spend(10);self.apply({'type':'fence'},height=2)
        self.denied(lambda:self.spend(1));self.denied(lambda:self.apply(grant_op('new'),height=2))
        self.assertEqual(self.l.state()['budgets'][0]['spent'],12)
    def test_rotation_retains_history_and_invalidates_budget(self):
        self.setup_budget();self.spend(10)
        body=self.l.body(IDS[0],3,{'type':'rotate_key','public_key':public(KEYS[5]),'acceptance':''})
        self.l.apply(sign(KEYS[0],accept_account_key(KEYS[5],body)),height=2)
        self.denied(lambda:self.spend(1));self.assertEqual(self.l.state()['budgets'][0]['spent'],12)
        self.apply(budget_op('new-epoch'),KEYS[5],height=2)
    def test_direct_owner_spending_is_not_an_agent_budget(self):
        self.setup_budget();self.apply({'type':'transfer','to':IDS[1],'units':200})
        self.assertEqual(self.l.state()['budgets'][0]['spent'],0)
    def test_budget_is_not_a_balance_reservation(self):
        self.setup_budget();balance=self.l.balance(IDS[0]);self.apply({'type':'transfer','to':IDS[1],'units':balance-2})
        self.denied(lambda:self.spend(1))
    def test_replay_does_not_charge_pool_twice(self):
        self.setup_budget();body=self.l.body(IDS[0],0,{'type':'transfer','to':IDS[1],'units':10},grant_id='raven');env=sign(KEYS[2],body)
        first=self.l.apply(env,height=2);self.assertEqual(first,self.l.apply(env,height=3))
        self.assertEqual(self.l.state()['budgets'][0]['spent'],12)
    def test_budget_admin_cannot_mutate_when_fee_unpaid(self):
        self.apply({'type':'transfer','to':IDS[1],'units':9997})
        self.denied(lambda:self.apply(budget_op()))
    def test_invalid_pool_values_are_atomic_rejections(self):
        for name, values in [('cap',[True,False,0,-1,1.0,'10',2**53]),('expires',[True,-1,'90']),('id',['','../x']),('recipients',[[],[IDS[1],IDS[1]],[IDS[0]],[FEE_ACCOUNT],['unknown']])]:
            for value in values:
                with self.subTest(field=name,value=value):
                    op=budget_op();op[name]=value;self.denied(lambda op=op:self.apply(op))
    def test_extra_admin_fields_cannot_be_ignored(self):
        op=budget_op();op['rollover']=True;self.denied(lambda:self.apply(op))
    def test_legacy_versions_cannot_access_new_operations(self):
        for v in (1,2):
            l=NativeLedger(':memory:',genesis(v))
            try:
                with self.assertRaises(Reject):l.apply(sign(KEYS[0],l.body(IDS[0],0,budget_op())),height=1)
                self.assertNotIn('budgets',snapshot(l))
            finally:l.close()
    def test_v3_genesis_cannot_open_as_v2(self):
        self.setup_budget()
        with self.assertRaises(Reject):NativeLedger(self.path,genesis(2))
    def test_restart_keeps_shared_spending(self):
        self.setup_budget();self.spend(58);self.l.close();self.l=NativeLedger(self.path,self.g)
        self.denied(lambda:self.spend(39,KEYS[3],'atlas'));self.spend(38,KEYS[3],'atlas')
    def test_budget_state_participates_in_state_and_application_hashes(self):
        self.setup_budget();before=self.l.state_hash();s=snapshot(self.l);ah=application_hash(self.g,1,s)
        self.l.db.execute('UPDATE budgets SET revoked=1')
        self.assertNotEqual(before,self.l.state_hash());self.assertNotEqual(ah,application_hash(self.g,1,snapshot(self.l)))
    def test_missing_or_inconsistent_binding_rejected_on_restore(self):
        self.setup_budget();self.spend(10);s=snapshot(self.l)
        for mutate in [lambda x:x.pop('budgets'),lambda x:x['grant_budgets'].clear(),lambda x:x['budgets'][0].__setitem__(4,0)]:
            copy_state=copy.deepcopy(s);mutate(copy_state)
            with self.assertRaises(Reject):restore(self.g,copy_state)
    def test_deleted_grant_cannot_release_historical_spending(self):
        self.setup_budget();self.spend(10);s=snapshot(self.l);s['grants'].clear();s['grant_budgets'].clear()
        with self.assertRaises(Reject):restore(self.g,s)
    def test_capacity_limit_cannot_be_bypassed_by_new_labels(self):
        with patch('native_budgets.MAX_BUDGETS_PER_OWNER',1):
            self.apply(budget_op());self.denied(lambda:self.apply(budget_op('other')))
        with patch('native_budgets.MAX_GRANTS_PER_BUDGET',1):
            self.apply(grant_op());self.denied(lambda:self.apply(grant_op('atlas',KEYS[3])))
    def test_two_connections_cannot_race_separate_grants_past_budget(self):
        self.setup_budget();barrier=threading.Barrier(2)
        def worker(data):
            label,key=data;l=NativeLedger(self.path,self.g)
            try:
                env=sign(key,l.body(IDS[0],0,{'type':'transfer','to':IDS[1],'units':58},grant_id=label))
                barrier.wait(timeout=5)
                try:l.apply(env,height=2);return 'accepted'
                except Reject:return 'rejected'
            finally:l.close()
        with ThreadPoolExecutor(max_workers=2) as pool:r=list(pool.map(worker,[('raven',KEYS[2]),('atlas',KEYS[3])]))
        self.assertEqual(sorted(r),['accepted','rejected']);self.assertEqual(self.l.state()['budgets'][0]['spent'],60)
    def test_randomized_interleaving_matches_independent_integer_model(self):
        self.setup_budget(cap=1000);rng=random.Random(12871);spent=0
        for _ in range(150):
            who=rng.randrange(2);amount=rng.randrange(1,60);debit=amount+2
            if spent+debit<=1000:
                self.spend(amount,KEYS[2+who],('raven','atlas')[who]);spent+=debit
            else:self.denied(lambda:self.spend(amount,KEYS[2+who],('raven','atlas')[who]))
            self.assertEqual(self.l.state()['budgets'][0]['spent'],spent)
        self.assertLessEqual(spent,1000)
    def test_rejected_upgrade_does_not_add_v3_schema_to_legacy_database(self):
        import sqlite3
        path=self.root/'legacy.sqlite';legacy=NativeLedger(path,genesis(2));legacy.close()
        with self.assertRaises(Reject):NativeLedger(path,genesis(3))
        db=sqlite3.connect(path)
        try:
            tables={r[0] for r in db.execute("SELECT name FROM sqlite_master WHERE type='table'")}
            self.assertNotIn('budgets',tables);self.assertNotIn('grant_budgets',tables)
        finally:db.close()
    def test_legacy_vectors_are_byte_identical(self):
        for vector in json.loads((ROOT/'evidence/v012/legacy-vectors.json').read_text()):
            l=NativeLedger(':memory:',vector['genesis'])
            try:
                for record in vector['records']:
                    self.assertEqual(l.apply(record['envelope'],height=record['height']),record)
                self.assertEqual(snapshot(l),vector['native'])
                self.assertEqual(application_hash(vector['genesis'],3,snapshot(l)),vector['app_hash'])
            finally:l.close()

if __name__=='__main__':unittest.main()
