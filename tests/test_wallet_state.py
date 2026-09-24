"""Attested-state wallet tests with SYNTHETIC certificates, never validator voting."""
import copy
from concurrent.futures import ThreadPoolExecutor
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import threading
import unittest
from unittest.mock import patch

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from native_core import public,address,sign,Reject
from commit_verifier import encode,sha,VerificationError
from offline_signer import create_vault
from wallet_state import WalletState
from wallet_state_fixture import StateFixture,NOW,STAMP

PASS=b'disposable-wallet-state-test-password'

class WalletStateTests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory(); self.root=Path(self.temp.name)
        self.vault=self.root/'owner.pem'; self.pk=create_vault(self.vault,PASS)
        self.owner=address(self.pk); self.merchant=Ed25519PrivateKey.generate(); self.to=address(public(self.merchant))
        self.g={'chain_id':'1soft-checkpoint-dev','asset':'DEV','fee':2,'protocol_version':2,
            'allocations':[{'public_key':self.pk,'units':1000},{'public_key':public(self.merchant),'units':0}]}
        self.fixture=StateFixture(self.g); self.clock=[NOW]; self.path=self.root/'wallet.sqlite'
        self.wallet=self.open(); self.first=self.fixture.packet(); self.wallet.import_state(self.first)
    def tearDown(self):
        self.wallet.close(); self.fixture.close(); self.temp.cleanup()
    def open(self):return WalletState(self.path,self.fixture.raw,self.fixture.pin,clock=lambda:self.clock[0])
    def review(self,units=20,grant=''):
        return self.wallet.build_transfer(self.owner,self.to,units,valid_until=20,grant_id=grant)
    def approve(self,review=None,vault=None):
        r=review or self.review()
        return self.wallet.approve(r['body'],r['signer_public_key'],r['confirmation'],vault=vault or self.vault,password=PASS)
    def grant(self,label='raven',cap=100):
        path=self.root/(label+'.pem'); pk=create_vault(path,PASS)
        from offline_signer import approve_intent,review_intent
        owner=self.fixture.ledger._account(self.owner)
        body=self.fixture.ledger.body(self.owner,owner['nonce'],{'type':'grant','id':label,'public_key':pk,'cap':cap,
            'expires':40,'recipients':[self.to]})
        r=review_intent(self.g,body,self.pk)
        env=approve_intent(self.vault,PASS,self.g,body,self.pk,r['confirmation'])
        self.wallet.import_state(self.fixture.packet(execute=env))
        return path,pk
    def test_build_uses_attested_balance_nonce_and_key(self):
        r=self.review(); self.assertEqual((r['attested_balance_units'],r['body']['nonce'],r['signer_public_key']),(1000,0,self.pk))
        self.assertFalse(r['latest_network_state_established']);self.assertEqual(r['authority_verified_as_of_height'],0)
    def test_signed_envelope_is_accepted_by_native_ledger(self):
        envelope=self.approve(); self.fixture.ledger.apply(envelope,height=2)
        self.assertEqual(self.fixture.ledger.balance(self.to),20)
    def test_signing_does_not_change_node_or_claim_settlement(self):
        before=self.fixture.ledger.state_hash();self.approve()
        self.assertEqual(self.fixture.ledger.state_hash(),before);self.assertEqual(self.wallet.outbox()[0]['status'],'signed')
    def test_repeated_approval_returns_same_signature_without_unlocking(self):
        r=self.review(); env=self.approve(r)
        with patch('wallet_state.approve_intent',side_effect=AssertionError('not a new signing')):
            self.assertEqual(env,self.approve(r))
        self.assertEqual(len(self.wallet.outbox()),1)
    def test_competing_same_nonce_intention_refused(self):
        self.approve()
        with self.assertRaises(ValueError):self.review(21)
    def test_amount_changed_after_review_refused_before_unlock(self):
        r=self.review();r['body']['op']['units']=21
        with patch('wallet_state.approve_intent',side_effect=AssertionError('no unlock')):
            with self.assertRaises(ValueError):self.approve(r)
    def test_new_checkpoint_requires_new_review(self):
        r=self.review();self.wallet.import_state(self.fixture.packet())
        with self.assertRaises(ValueError):self.approve(r)
    def test_wrong_account_key_refused(self):
        r=self.review()
        with self.assertRaises(ValueError):self.wallet.review(r['body'],public(self.merchant))
    def test_wrong_nonce_refused(self):
        r=self.review();r['body']['nonce']=7
        with self.assertRaises(ValueError):self.wallet.review(r['body'],self.pk)
    def test_insufficient_balance_includes_fee(self):
        with self.assertRaises(ValueError):self.review(999)
    def test_unknown_recipient_refused(self):
        with self.assertRaises(ValueError):self.wallet.build_transfer(self.owner,'not-opened',1,valid_until=20)
    def test_too_soon_expiry_refused(self):
        with self.assertRaises(ValueError):self.wallet.build_transfer(self.owner,self.to,1,valid_until=1)
    def test_nontransfer_certified_signing_refused(self):
        b=self.fixture.ledger.body(self.owner,0,{'type':'fence'})
        with self.assertRaises(ValueError):self.wallet.review(b,self.pk)
    def test_agent_spend_uses_grant_signer(self):
        vault,pk=self.grant();r=self.review(20,'raven');self.assertEqual(r['signer_public_key'],pk)
        self.fixture.ledger.apply(self.approve(r,vault),height=3)
        self.assertEqual(self.fixture.ledger.balance(self.to),20)
    def test_agent_fee_included_in_cap(self):
        self.grant(cap=21)
        with self.assertRaises(ValueError):self.review(20,'raven')
    def test_revoked_agent_refused(self):
        self.grant();body=self.fixture.ledger.body(self.owner,1,{'type':'revoke','id':'raven'})
        from offline_signer import review_intent,approve_intent
        r=review_intent(self.g,body,self.pk);env=approve_intent(self.vault,PASS,self.g,body,self.pk,r['confirmation'])
        self.wallet.import_state(self.fixture.packet(execute=env))
        with self.assertRaises(ValueError):self.review(20,'raven')
    def test_shared_balance_across_distinct_grants(self):
        v1,_=self.grant('one',900);v2,_=self.grant('two',900)
        self.approve(self.review(700,'one'),v1)
        with self.assertRaises(ValueError):self.review(400,'two')
        self.approve(self.review(200,'two'),v2)
        self.assertEqual(sum(r['debit'] for r in self.wallet.outbox()),904)
    def test_pending_change_invalidates_other_review(self):
        v1,_=self.grant('one',900);v2,_=self.grant('two',900)
        r1=self.review(20,'one');r2=self.review(20,'two');self.approve(r1,v1)
        with self.assertRaises(ValueError):self.approve(r2,v2)
    def test_recorded_receipt_resolves_exact_intention(self):
        env=self.approve();self.wallet.import_state(self.fixture.packet(execute=env))
        self.assertEqual(self.wallet.outbox()[0]['status'],'recorded')
        r=self.review();self.assertEqual(r['body']['nonce'],1);self.assertEqual(r['attested_balance_units'],978)
    def test_no_receipt_does_not_release_hold(self):
        self.approve();self.wallet.import_state(self.fixture.packet())
        self.assertEqual(self.wallet.outbox()[0]['status'],'signed')
        with self.assertRaises(ValueError):self.review(21)
    def test_expiry_needs_signed_height_not_wallclock(self):
        r=self.wallet.build_transfer(self.owner,self.to,20,valid_until=2);self.approve(r)
        self.wallet.import_state(self.fixture.packet());self.wallet.import_state(self.fixture.packet())
        self.assertEqual(self.wallet.outbox()[0]['status'],'signed')
        self.wallet.import_state(self.fixture.packet())
        self.assertEqual(self.wallet.outbox()[0]['status'],'expired')
        self.review(21)
    def test_receipt_at_expiry_wins_over_release(self):
        r=self.wallet.build_transfer(self.owner,self.to,20,valid_until=2);env=self.approve(r)
        self.wallet.import_state(self.fixture.packet());self.wallet.import_state(self.fixture.packet(execute=env))
        self.wallet.import_state(self.fixture.packet());self.assertEqual(self.wallet.outbox()[0]['status'],'recorded')
    def test_restart_preserves_held_nonce_and_exact_envelope(self):
        r=self.review();env=self.approve(r);self.wallet.close();self.wallet=self.open()
        self.assertEqual(env,self.wallet.export(r['native_txid']))
        with self.assertRaises(ValueError):self.review(21)
    def test_wrong_anchor_after_restart_refused(self):
        other=copy.deepcopy(self.fixture.genesis);other['validators'][0]['power']='11';raw=encode(other)
        with self.assertRaises(ValueError):WalletState(self.path,raw,sha(raw).hex(),clock=lambda:NOW)
    def test_bad_genesis_pin_refused(self):
        with self.assertRaises(ValueError):WalletState(self.root/'bad.sqlite',self.fixture.raw,'0'*64)
    def test_state_hash_tamper_does_not_change_checkpoint(self):
        p=self.fixture.packet();p['state']['native']['accounts'][0][-1]+=10
        with self.assertRaises(ValueError):self.wallet.import_state(p)
        self.assertEqual(self.review()['state_height'],0)
    def test_signature_tamper_refused(self):
        p=self.fixture.packet();p['state_commit']['commit']['signatures'][0]['signature']='A'*88
        with self.assertRaises(ValueError):self.wallet.import_state(p)
    def test_same_height_conflict_refused(self):
        rival=StateFixture(self.g);p=rival.packet(stamp='2026-09-24T16:00:01Z');rival.close()
        with self.assertRaises(ValueError):self.wallet.import_state(p)
    def test_same_header_reimport_is_idempotent(self):
        self.wallet.import_state(self.first);self.assertEqual(self.review()['state_height'],0)
    def test_rollback_refused_after_restart(self):
        self.wallet.import_state(self.fixture.packet());self.wallet.close();self.wallet=self.open()
        with self.assertRaises(ValueError):self.wallet.import_state(self.first)
    def test_skipped_header_needs_signed_continuation(self):
        middle=self.fixture.packet();last=self.fixture.packet()
        with self.assertRaises(ValueError):self.wallet.import_state(last)
        self.wallet.import_state(last,continuation=[middle['state_commit']]);self.assertEqual(self.review()['state_height'],2)
    def test_wrong_intermediate_signature_refused(self):
        middle=self.fixture.packet();last=self.fixture.packet();middle['state_commit']['commit']['signatures'][0]['signature']='A'*88
        with self.assertRaises(ValueError):self.wallet.import_state(last,continuation=[middle['state_commit']])
    def test_signed_wrong_predecessor_rejected(self):
        wrong={'hash':'ab'*32,'parts':{'total':1,'hash':'cd'*32}}
        with self.assertRaises(ValueError):self.wallet.import_state(self.fixture.packet(previous=wrong))
    def test_future_certificate_rejected(self):
        p=self.fixture.packet(stamp='2026-09-24T16:00:31Z')
        with self.assertRaises(ValueError):self.wallet.import_state(p)
    def test_old_certificate_refused(self):
        self.clock[0]=NOW+301*10**9
        with self.assertRaises(ValueError):self.wallet.import_state(self.first)
    def test_clock_rechecked_at_sign(self):
        r=self.review();self.clock[0]=NOW+301*10**9
        with self.assertRaises(ValueError):self.approve(r)
        self.assertEqual(self.wallet.outbox(),[])
    def test_stale_checkpoint_still_exports_already_signed_envelope(self):
        r=self.review();env=self.approve(r);self.clock[0]+=999*10**9
        self.assertEqual(env,self.wallet.export(r['native_txid']))
    def test_even_valid_quorum_malformed_state_rejected(self):
        p=self.fixture.packet(mutate_state=lambda s:s['native']['accounts'].append(s['native']['accounts'][0]))
        with self.assertRaises((ValueError,__import__('sqlite3').IntegrityError)):self.wallet.import_state(p)
    def test_failed_unlock_creates_no_hold(self):
        r=self.review()
        with self.assertRaises(ValueError):self.wallet.approve(r['body'],self.pk,r['confirmation'],vault=self.vault,password=b'wrong-password-but-long')
        self.assertEqual(self.wallet.outbox(),[])
    def test_nonce_race_two_connections_only_one_signed(self):
        reviews=[self.review(20),self.review(21)];barrier=threading.Barrier(2)
        def worker(r):
            with self.open() as w:
                barrier.wait(timeout=5)
                try:w.approve(r['body'],self.pk,r['confirmation'],vault=self.vault,password=PASS);return 'signed'
                except ValueError:return 'rejected'
        with ThreadPoolExecutor(2) as pool:results=list(pool.map(worker,reviews))
        self.assertEqual(sorted(results),['rejected','signed']);self.assertEqual(len(self.wallet.outbox()),1)
    def test_corrupt_saved_witness_refused_before_signing(self):
        self.wallet.db.execute("UPDATE checkpoint SET witness='{}'")
        with self.assertRaises(ValueError):self.review()
    def test_workspace_symlink_refused(self):
        link=self.root/'linked.sqlite';link.symlink_to(self.path)
        with self.assertRaises(ValueError):WalletState(link,self.fixture.raw,self.fixture.pin)
    def test_nonprivate_workspace_refused(self):
        self.path.chmod(0o644)
        with self.assertRaises(ValueError):self.open()
    def test_export_unknown_refused(self):
        with self.assertRaises(ValueError):self.wallet.export('00'*32)

    def test_attested_supply_cannot_change_genesis_supply(self):
        def mutate(state):
            for row in state['native']['meta']:
                if row[0]=='supply':row[1]='1001'
            state['native']['accounts'][0][-1]+=1
        packet=self.fixture.packet(mutate_state=mutate)
        with self.assertRaises(ValueError):self.wallet.import_state(packet)

    def test_committed_signature_survives_process_exit_before_export(self):
        r=self.review()
        for name,data in [('genesis.json',self.fixture.raw),('review.json',encode(r))]:
            (self.root/name).write_bytes(data)
        code="""import json,os,sys
from pathlib import Path
from wallet_state import WalletState
r=Path(sys.argv[1]);view=json.loads((r/'review.json').read_text())
w=WalletState(r/'wallet.sqlite',(r/'genesis.json').read_bytes(),sys.argv[2],clock=lambda:int(sys.argv[3]))
w.approve(view['body'],view['signer_public_key'],view['confirmation'],vault=r/'owner.pem',password=b'disposable-wallet-state-test-password')
os._exit(0)
"""
        env=dict(os.environ,PYTHONPATH=str(Path(__file__).resolve().parents[1]/'src'))
        subprocess.run([sys.executable,'-c',code,str(self.root),self.fixture.pin,str(NOW)],env=env,check=True,timeout=10)
        self.wallet.close();self.wallet=self.open()
        self.assertEqual(self.wallet.outbox()[0]['status'],'signed')
        recovered=self.wallet.export(r['native_txid'])
        self.fixture.ledger.apply(recovered,height=2)
        self.assertEqual(self.fixture.ledger.balance(self.to),20)
        with self.assertRaises(ValueError):self.review(21)

if __name__=='__main__':unittest.main()
