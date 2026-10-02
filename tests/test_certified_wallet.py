"""Signed synthetic snapshots only; no live engine or production wallet claim."""
import copy
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import threading
import unittest
from concurrent.futures import ThreadPoolExecutor
from unittest.mock import patch

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from block_application import BlockApplication
from certified_wallet import CertifiedWallet, nanos
from commit_verifier import encode, header_hash
from native_core import NativeLedger, Reject, address, public, sign, canonical
from offline_signer import create_vault, _load_vault
from certificate_fixture import validators, make_header, make_commit, STAMP

PASSWORD = b'disposable-only-test-password-for-certificates'
NOW = nanos(STAMP) + 10_000_000_000
ROOT = Path(__file__).resolve().parents[1]


class CertifiedWalletTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        self.vault = self.root/'owner.pem'
        self.pk = create_vault(self.vault, PASSWORD)
        self.key = _load_vault(self.vault, PASSWORD)
        self.merchant = Ed25519PrivateKey.from_private_bytes(bytes([9])*32)
        self.owner = address(self.pk); self.recipient = address(public(self.merchant))
        self.g = {'chain_id':'1soft-certified-dev', 'asset':'DEV','fee':2,'protocol_version':2,
                  'allocations':[{'public_key':self.pk,'units':1000},
                                 {'public_key':public(self.merchant),'units':0}]}
        self.engine,self.trust,self.valkeys = validators(self.g)
        self.raw = encode(self.engine)
        self.policy = {'schema':1,'genesis_sha256':hashlib.sha256(self.raw).hexdigest(),
                       'trust_expires_utc':'2026-09-25T00:00:00Z',
                       'minimum_header_height':1,'maximum_age_seconds':300,'future_skew_seconds':5}
        self.clock_value = NOW
        self.app = BlockApplication(':memory:'); self.app.init_chain(self.g['chain_id'],self.g)
        self.ledger = NativeLedger(':memory:',self.g)
        self.witness = self.attest(0)
        self.body = self.ledger.body(self.owner,0,{'type':'transfer','to':self.recipient,'units':20})
        self.path = self.root/'decisions.sqlite'
        self.wallet = self.open_wallet()

    def tearDown(self):
        self.wallet.close();self.app.close();self.ledger.close();self.tmp.cleanup()

    def open_wallet(self, path=None):
        return CertifiedWallet(path or self.path, self.raw, self.policy, clock=lambda:self.clock_value)

    def attest(self, height, txs=(), *, previous=None, stamp=STAMP):
        if height > self.app.height:
            self.app.finalize_block(list(txs),height,bytes([height % 255])*32); self.app.commit()
        state=json.loads(self.app.query('/state')['value'])
        header=make_header(self.trust,height+1,state['app_hash'],previous=previous)
        header['time']=stamp
        if height and previous is None:
            header['last_block_id']={'hash':'12'*32,'parts':{'total':1,'hash':'13'*32}}
        return {'schema':1,'state':state,'state_commit':make_commit(header,self.trust,self.valkeys)}

    def reviewed(self, body=None, witness=None, pk=None, mode='sign'):
        return self.wallet.review(witness or self.witness,body or self.body,pk or self.pk,mode=mode)

    def approve(self, body=None, witness=None, pk=None, vault=None, mode='sign'):
        b=body or self.body;w=witness or self.witness;p=pk or self.pk
        review=self.reviewed(b,w,p,mode)
        return self.wallet.approve(w,b,p,review['confirmation'],vault or self.vault,PASSWORD,mode=mode)

    def test_authentication_and_scope(self):
        review=self.reviewed()
        self.assertTrue(review['authority_at_snapshot_verified'])
        self.assertFalse(review['latest_state_guaranteed'])
        self.assertEqual(review['account_balance_units'],1000)
        self.assertEqual(review['proposed_account_debit_units'],22)
        self.assertEqual(review['signed_power'],40)

    def test_sign_and_execute_on_unchanged_snapshot(self):
        result=self.approve();self.ledger.apply(result['result'],height=1)
        self.assertEqual(self.ledger.balance(self.recipient),20)
        self.assertEqual(result['status'],'signed-locally-not-broadcast')

    def test_review_never_unlocks(self):
        with patch('certified_wallet._load_vault',side_effect=AssertionError('no unlock')):
            self.reviewed()

    def test_wrong_genesis_file_pin(self):
        with self.assertRaises(ValueError):
            CertifiedWallet(self.root/'other.sqlite',self.raw+b' ',self.policy,clock=lambda:NOW)

    def test_policy_change_cannot_reuse_journal(self):
        policy={**self.policy,'maximum_age_seconds':600}
        with self.assertRaises(Reject):
            CertifiedWallet(self.path,self.raw,policy,clock=lambda:NOW)

    def test_wrong_validator_signature_before_unlock(self):
        witness=copy.deepcopy(self.witness)
        witness['state_commit']['commit']['signatures'][0]['signature']='AA=='
        with patch('certified_wallet._load_vault',side_effect=AssertionError('no unlock')):
            with self.assertRaises(ValueError):self.reviewed(witness=witness)

    def test_tampered_balance_rejected(self):
        witness=copy.deepcopy(self.witness)
        witness['state']['native']['accounts'][0][4]+=100
        with self.assertRaises(ValueError):self.reviewed(witness=witness)

    def test_stale_snapshot(self):
        self.clock_value=nanos(STAMP)+301_000_000_000
        with self.assertRaisesRegex(Reject,'too old'):self.reviewed()

    def test_future_snapshot(self):
        self.clock_value=nanos(STAMP)-6_000_000_000
        with self.assertRaisesRegex(Reject,'future'):self.reviewed()

    def test_expired_local_trust(self):
        self.clock_value=nanos(self.policy['trust_expires_utc'])
        with self.assertRaisesRegex(Reject,'policy expired'):self.reviewed()

    def test_time_rechecked_after_slow_unlock(self):
        review=self.reviewed()
        def unlock(*args):
            self.clock_value=nanos(STAMP)+301_000_000_000
            return self.key
        with patch('certified_wallet._load_vault',side_effect=unlock):
            with self.assertRaisesRegex(Reject,'too old'):
                self.wallet.approve(self.witness,self.body,self.pk,review['confirmation'],self.vault,PASSWORD)
        self.assertEqual(self.wallet.db.execute('SELECT count(*) FROM decisions').fetchone()[0],0)

    def test_clock_rollback(self):
        self.reviewed();self.clock_value-=1
        with self.assertRaisesRegex(Reject,'clock moved backwards'):self.reviewed()

    def test_owner_wrong_key_is_rejected_before_unlock(self):
        with patch('certified_wallet._load_vault',side_effect=AssertionError('no unlock')):
            with self.assertRaisesRegex(Reject,'controlling key'):self.reviewed(pk=public(self.merchant))

    def test_wrong_nonce(self):
        body={**self.body,'nonce':1}
        with self.assertRaisesRegex(Reject,'nonce'):self.reviewed(body)

    def test_insufficient_balance(self):
        body=copy.deepcopy(self.body);body['op']['units']=999
        with self.assertRaisesRegex(Reject,'insufficient'):self.reviewed(body)

    def test_unknown_recipient(self):
        body=copy.deepcopy(self.body);body['op']['to']='unknown'
        with self.assertRaisesRegex(Reject,'unknown account'):self.reviewed(body)

    def test_expired_intention(self):
        with self.assertRaisesRegex(Reject,'expired'):self.reviewed({**self.body,'valid_until':0})

    def test_changed_review_rejected_before_unlock(self):
        review=self.reviewed();body=copy.deepcopy(self.body);body['op']['units']=21
        with patch('certified_wallet._load_vault',side_effect=AssertionError('no unlock')):
            with self.assertRaisesRegex(Reject,'review changed'):
                self.wallet.approve(self.witness,body,self.pk,review['confirmation'],self.vault,PASSWORD)

    def test_older_certificate_after_newer_review(self):
        first=self.reviewed()
        newer=self.attest(1,previous=self.witness['state_commit']['commit']['block_id'])
        self.reviewed(witness=newer)
        with self.assertRaisesRegex(Reject,'rolls back'):self.reviewed()

    def test_same_height_conflicting_signed_header(self):
        self.reviewed();other=copy.deepcopy(self.witness)
        header=other['state_commit']['header'];header['consensus_hash']='55'*32
        other['state_commit']=make_commit(header,self.trust,self.valkeys)
        with self.assertRaisesRegex(Reject,'conflicting'):self.reviewed(witness=other)

    def test_adjacent_certificate_wrong_parent(self):
        self.reviewed();newer=self.attest(1)
        with self.assertRaisesRegex(Reject,'does not extend'):self.reviewed(witness=newer)

    def test_checkpoint_survives_restart(self):
        self.reviewed();newer=self.attest(1,previous=self.witness['state_commit']['commit']['block_id'])
        self.reviewed(witness=newer);self.wallet.close();self.wallet=self.open_wallet()
        with self.assertRaisesRegex(Reject,'rolls back'):self.reviewed()

    def test_one_authority_nonce_cannot_sign_twice(self):
        self.approve();other=copy.deepcopy(self.body);other['op']['units']=21
        with self.assertRaisesRegex(Reject,'already has'):self.reviewed(other)

    def test_identical_retry_requires_export(self):
        first=self.approve()
        with self.assertRaisesRegex(Reject,'export'):self.approve()
        self.assertEqual(self.wallet.export(first['decision_id'])['result'],first['result'])

    def test_export_survives_restart_without_key(self):
        result=self.approve();self.vault.unlink();self.wallet.close();self.wallet=self.open_wallet()
        self.assertEqual(self.wallet.export(result['decision_id'])['result'],result['result'])

    def test_export_after_policy_expiry(self):
        result=self.approve();self.wallet.close();self.clock_value=nanos(self.policy['trust_expires_utc'])+1
        self.wallet=self.open_wallet()
        self.assertEqual(self.wallet.export(result['decision_id'])['result'],result['result'])

    def test_corrupt_export_detected(self):
        result=self.approve();self.wallet.db.execute("UPDATE decisions SET result='{}'")
        with self.assertRaisesRegex(Reject,'integrity'):self.wallet.export(result['decision_id'])

    def test_concurrent_signers_cannot_sign_conflicting_nonce(self):
        review=self.reviewed();barrier=threading.Barrier(2)
        def worker(i):
            wallet=self.open_wallet()
            try:
                body=copy.deepcopy(self.body);body['op']['units']+=i
                own=wallet.review(self.witness,body,self.pk)
                barrier.wait(timeout=5)
                try:
                    wallet.approve(self.witness,body,self.pk,own['confirmation'],self.vault,PASSWORD)
                    return 'signed'
                except Reject:return 'rejected'
            finally:wallet.close()
        with ThreadPoolExecutor(2) as pool:
            result=list(pool.map(worker,(0,1)))
        self.assertEqual(sorted(result),['rejected','signed'])
        self.assertEqual(self.wallet.db.execute('SELECT count(*) FROM decisions').fetchone()[0],1)

    def test_state_can_change_after_review_and_still_reject_on_execution(self):
        result=self.approve()
        other=copy.deepcopy(self.body);other['op']['units']=1
        self.ledger.apply(sign(self.key,other),height=1)
        with self.assertRaisesRegex(Reject,'nonce'):self.ledger.apply(result['result'],height=2)

    def test_journal_symlink_refused(self):
        alias=self.root/'alias.sqlite';alias.symlink_to(self.path)
        with self.assertRaises(Reject):self.open_wallet(alias)

    def test_journal_permissions_refused(self):
        self.path.chmod(0o644)
        with self.assertRaises(Reject):self.open_wallet()

    def test_bad_skew_policy_refused(self):
        with self.assertRaises(Reject):
            CertifiedWallet(self.root/'bad.sqlite',self.raw,{**self.policy,'future_skew_seconds':31},clock=lambda:NOW)

    def test_boolean_policy_field_refused(self):
        with self.assertRaises(Reject):
            CertifiedWallet(self.root/'bad.sqlite',self.raw,{**self.policy,'minimum_header_height':True},clock=lambda:NOW)

    def test_verified_agent_allowance_includes_fees(self):
        vault=self.root/'agent.pem';pk=create_vault(vault,PASSWORD)
        grant=self.ledger.body(self.owner,0,{'type':'grant','id':'raven','public_key':pk,'cap':22,
                                          'expires':100,'recipients':[self.recipient]})
        witness=self.attest(1,[canonical(sign(self.key,grant))])
        body={**self.body,'grant_id':'raven'}
        review=self.reviewed(body,witness,pk)
        self.assertEqual(review['grant_remaining_units'],22)
        result=self.wallet.approve(witness,body,pk,review['confirmation'],vault,PASSWORD)
        self.assertEqual(result['result']['body']['grant_id'],'raven')

    def test_revoked_agent_blocked_at_certified_state(self):
        vault=self.root/'agent.pem';pk=create_vault(vault,PASSWORD)
        grant=self.ledger.body(self.owner,0,{'type':'grant','id':'raven','public_key':pk,'cap':100,
                                          'expires':100,'recipients':[self.recipient]})
        revoke=self.ledger.body(self.owner,1,{'type':'revoke','id':'raven'})
        witness=self.attest(1,[canonical(sign(self.key,grant)),canonical(sign(self.key,revoke))])
        with self.assertRaisesRegex(Reject,'inactive'):self.reviewed({**self.body,'grant_id':'raven'},witness,pk)

    def test_incoming_account_consent_and_sponsor_can_share_journal(self):
        vault=self.root/'incoming.pem';pk=create_vault(vault,PASSWORD)
        body=self.ledger.body(self.owner,0,{'type':'open_account','public_key':pk,'units':100,'acceptance':''})
        accepted=self.approve(body,pk=pk,vault=vault,mode='accept')['result']
        result=self.approve(accepted)
        self.ledger.apply(result['result'],height=1)
        self.assertEqual(self.ledger.balance(address(pk)),100)

    def test_key_rotation_and_old_key_rejection(self):
        vault=self.root/'incoming.pem';pk=create_vault(vault,PASSWORD)
        body=self.ledger.body(self.owner,0,{'type':'rotate_key','public_key':pk,'acceptance':''})
        accepted=self.approve(body,pk=pk,vault=vault,mode='accept')['result']
        rotation=self.approve(accepted)['result']
        witness=self.attest(1,[canonical(rotation)],previous=self.witness['state_commit']['commit']['block_id'])
        spend={**self.body,'nonce':1}
        with self.assertRaisesRegex(Reject,'controlling key'):self.reviewed(spend,witness,self.pk)
        new=self.approve(spend,witness,pk,vault)
        self.assertEqual(new['result']['body']['sender'],self.owner)

    def test_real_process_crash_after_journal_commit_export_recovers(self):
        for name,value in [('genesis',self.engine),('policy',self.policy),('witness',self.witness),('body',self.body)]:
            (self.root/(name+'.json')).write_bytes(encode(value))
        source='''import os,sys,json
from pathlib import Path
from certified_wallet import CertifiedWallet
p=Path(sys.argv[1]);read=lambda n:json.loads((p/(n+'.json')).read_bytes())
w=CertifiedWallet(p/'child.sqlite',(p/'genesis.json').read_bytes(),read('policy'),clock=lambda:int(sys.argv[2]))
r=w.review(read('witness'),read('body'),sys.argv[3])
w.approve(read('witness'),read('body'),sys.argv[3],r['confirmation'],p/'owner.pem',b'disposable-only-test-password-for-certificates')
os._exit(0)
'''
        subprocess.run([sys.executable,'-c',source,str(self.root),str(NOW),self.pk],check=True,timeout=15,
                       env={**os.environ,'PYTHONPATH':str(ROOT/'src')})
        wallet=self.open_wallet(self.root/'child.sqlite')
        try:
            decision=wallet.db.execute('SELECT id FROM decisions').fetchone()[0]
            exported=wallet.export(decision)
            self.ledger.apply(exported['result'],height=1)
            self.assertEqual(self.ledger.balance(self.recipient),20)
        finally:wallet.close()

    def test_old_key_after_rotation_rejected_before_unlock(self):
        vault=self.root/'replacement.pem';pk=create_vault(vault,PASSWORD)
        body=self.ledger.body(self.owner,0,{'type':'rotate_key','public_key':pk,'acceptance':''})
        accepted=self.approve(body,pk=pk,vault=vault,mode='accept')['result']
        rotation=self.approve(accepted)['result']
        witness=self.attest(1,[canonical(rotation)],previous=self.witness['state_commit']['commit']['block_id'])
        with patch('certified_wallet._load_vault',side_effect=AssertionError('no unlock')):
            with self.assertRaisesRegex(Reject,'controlling key'):
                self.reviewed({**self.body,'nonce':1},witness,self.pk)

    def test_insufficient_quorum_is_rejected(self):
        witness=copy.deepcopy(self.witness)
        witness['state_commit']=make_commit(witness['state_commit']['header'],self.trust,self.valkeys,flags=[2,2,1,1])
        with self.assertRaisesRegex(ValueError,'voting power'):self.reviewed(witness=witness)

    def test_bad_last_signature_not_ignored_after_quorum(self):
        witness=copy.deepcopy(self.witness)
        witness['state_commit']['commit']['signatures'][-1]['signature']='AA=='
        with self.assertRaises(ValueError):self.reviewed(witness=witness)

    def test_wrong_witness_shape(self):
        witness=copy.deepcopy(self.witness);witness['transactions']=[]
        with self.assertRaisesRegex(Reject,'invalid account witness'):self.reviewed(witness=witness)

    def test_native_height_cannot_exceed_certified_state(self):
        from block_application import application_hash
        witness=copy.deepcopy(self.witness)
        for row in witness['state']['native']['meta']:
            if row[0]=='height':row[1]='100'
        state=witness['state']
        state['app_hash']=application_hash(state['genesis'],state['height'],state['native'])
        header=witness['state_commit']['header'];header['app_hash']=state['app_hash'].upper()
        witness['state_commit']=make_commit(header,self.trust,self.valkeys)
        with self.assertRaisesRegex(Reject,'native height exceeds'):self.reviewed(witness=witness)

    def cli_arguments(self):
        from datetime import datetime, timedelta, timezone
        now=datetime.now(timezone.utc)
        stamp=now.isoformat(timespec='microseconds').replace('+00:00','Z')
        witness=self.attest(0,stamp=stamp)
        policy={**self.policy,'trust_expires_utc':(now+timedelta(hours=1)).isoformat().replace('+00:00','Z')}
        for name,value in [('genesis',self.engine),('policy',policy),('witness',witness),('body',self.body)]:
            (self.root/(name+'.json')).write_bytes(encode(value))
        args=['--genesis',str(self.root/'genesis.json'),'--policy',str(self.root/'policy.json'),
              '--journal',str(self.root/'cli.sqlite'),'--witness',str(self.root/'witness.json'),
              '--body',str(self.root/'body.json'),'--signer-public-key',self.pk]
        return args,policy,witness

    def test_cli_review_checks_certificate_without_password(self):
        args,policy,witness=self.cli_arguments()
        proc=subprocess.run([sys.executable,str(ROOT/'scripts/certified_wallet.py'),'review',*args],
            capture_output=True,text=True,timeout=10)
        self.assertEqual(proc.returncode,0,proc.stderr)
        result=json.loads(proc.stdout)
        self.assertTrue(result['authority_at_snapshot_verified'])
        self.assertFalse(result['latest_state_guaranteed'])

    def test_cli_cannot_sign_noninteractively(self):
        args,policy,witness=self.cli_arguments();out=self.root/'no-envelope.json'
        proc=subprocess.run([sys.executable,str(ROOT/'scripts/certified_wallet.py'),'sign',*args,
                '--vault',str(self.vault),'--output',str(out)],input='',capture_output=True,text=True,timeout=10)
        self.assertEqual(proc.returncode,2,proc.stderr);self.assertFalse(out.exists())

    def test_cli_real_terminal_sign_and_export_without_password(self):
        import test_offline_signer
        args,policy,witness=self.cli_arguments();out=self.root/'envelope.json'
        with_wallet=CertifiedWallet(self.root/'cli.sqlite',self.raw,policy)
        try:review=with_wallet.review(witness,self.body,self.pk)
        finally:with_wallet.close()
        code,output=test_offline_signer.SignerTests.tty_command(self,
            [sys.executable,str(ROOT/'scripts/certified_wallet.py'),'sign',*args,
             '--vault',str(self.vault),'--output',str(out)],
            [(b'Type the certified confirmation digest to approve:',review['confirmation'].encode()),
             (b'Vault passphrase:',PASSWORD)])
        self.assertEqual(code,0,output);self.assertNotIn(PASSWORD,output)
        envelope=json.loads(out.read_bytes());self.ledger.apply(envelope,height=1)
        self.vault.unlink()
        proc=subprocess.run([sys.executable,str(ROOT/'scripts/certified_wallet.py'),'export',
             '--genesis',str(self.root/'genesis.json'),'--policy',str(self.root/'policy.json'),
             '--journal',str(self.root/'cli.sqlite'),'--decision-id',review['confirmation']],
             capture_output=True,text=True,timeout=10)
        self.assertEqual(proc.returncode,0,proc.stderr)
        self.assertEqual(json.loads(proc.stdout)['result'],envelope)

    def test_cli_existing_output_recovers_committed_signature(self):
        import test_offline_signer
        args,policy,witness=self.cli_arguments();out=self.root/'occupied.json';out.write_bytes(b'preserve')
        with_wallet=CertifiedWallet(self.root/'cli.sqlite',self.raw,policy)
        try:review=with_wallet.review(witness,self.body,self.pk)
        finally:with_wallet.close()
        code,output=test_offline_signer.SignerTests.tty_command(self,
            [sys.executable,str(ROOT/'scripts/certified_wallet.py'),'sign',*args,
             '--vault',str(self.vault),'--output',str(out)],
            [(b'Type the certified confirmation digest to approve:',review['confirmation'].encode()),
             (b'Vault passphrase:',PASSWORD)])
        self.assertEqual(code,2,output);self.assertEqual(out.read_bytes(),b'preserve')
        with_wallet=CertifiedWallet(self.root/'cli.sqlite',self.raw,policy)
        try:exported=with_wallet.export(review['confirmation'])
        finally:with_wallet.close()
        self.ledger.apply(exported['result'],height=1)
        self.assertEqual(self.ledger.balance(self.recipient),20)

if __name__=='__main__':unittest.main()
