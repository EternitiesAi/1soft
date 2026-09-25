"""Pending native obligations using disposable keys and synthetic signed headers.

Executes the real native application and encrypted key operations. The committee
attestations are fixtures, not a newly executed CometBFT network or custody audit.
"""
import copy
import hashlib
import json
import os
from pathlib import Path
import sqlite3
import subprocess
import sys
import tempfile
import threading
import unittest
from concurrent.futures import ThreadPoolExecutor
from unittest.mock import patch

from cryptography.hazmat.primitives import serialization as ser
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from block_application import BlockApplication, restore
from certified_wallet import CertifiedWallet, DOMAIN as REVIEW_DOMAIN, nanos
from commit_verifier import encode
from native_core import NativeLedger, Reject, address, canonical, public, sign
from offline_signer import _load_vault
from certificate_fixture import validators, make_header, make_commit, STAMP

ROOT = Path(__file__).resolve().parents[1]
PASSWORD = b'public-test-passphrase-not-a-secret-1soft'
KEYS = [Ed25519PrivateKey.from_private_bytes(bytes([i])*32) for i in range(61,67)]
IDS = [address(public(key)) for key in KEYS]


class ObligationTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(); self.root = Path(self.tmp.name)
        self.g = {'chain_id': '1soft-pending-budget-test', 'asset': 'DEV', 'fee': 2,
                  'protocol_version': 3, 'allocations': [
                      {'public_key': public(KEYS[0]), 'units': 1000},
                      {'public_key': public(KEYS[1]), 'units': 0},
                      {'public_key': public(KEYS[5]), 'units': 500}]}
        self.model = NativeLedger(':memory:', self.g)
        self.app = BlockApplication(':memory:'); self.app.init_chain(self.g['chain_id'], self.g)
        self.engine, self.trust, self.valkeys = validators(self.g)
        self.raw = encode(self.engine); self.clock = nanos(STAMP)+10**9
        self.policy = {'schema': 1, 'genesis_sha256': hashlib.sha256(self.raw).hexdigest(),
                       'trust_expires_utc': '2030-01-01T00:00:00Z', 'minimum_header_height': 1,
                       'maximum_age_seconds': 300, 'future_skew_seconds': 5}
        self.path = self.root/'wallet.sqlite'; self.witnesses = []
        self.make_witness()
        ops = [{'type':'budget_create','id':'project','cap':100,'expires':100,'recipients':[IDS[1]]}]
        ops += [{'type':'grant','id':name,'public_key':public(KEYS[i]),'cap':100,'expires':100,
                 'recipients':[IDS[1]],'budget_id':'project'} for i,name in [(2,'raven'),(3,'atlas'),(4,'worker')]]
        self.advance([canonical(sign(KEYS[0], self.model.body(IDS[0], n, op))) for n,op in enumerate(ops)])
        self.wallet = self.open()
        for i,key in enumerate(KEYS):
            p = self.root/f'key{i}.pem'
            p.write_bytes(key.private_bytes(ser.Encoding.PEM, ser.PrivateFormat.PKCS8, ser.BestAvailableEncryption(PASSWORD)))
            p.chmod(0o600)
    def tearDown(self):
        self.wallet.close(); self.app.close(); self.model.close(); self.tmp.cleanup()
    def open(self, path=None):
        return CertifiedWallet(path or self.path, self.raw, self.policy, clock=lambda:self.clock)
    def make_witness(self):
        state = json.loads(self.app.query('/state')['value'])
        previous = self.witnesses[-1]['state_commit']['commit']['block_id'] if self.witnesses else None
        h = make_header(self.trust, self.app.height+1, state['app_hash'], previous=previous)
        h['version']['app'] = '3'
        self.witness = {'schema':1,'state':state,'state_commit':make_commit(h,self.trust,self.valkeys)}
        self.witnesses.append(self.witness)
        return self.witness
    def advance(self, txs=()):
        h = self.app.height+1
        result = self.app.finalize_block(list(txs), h, hashlib.sha256(str(h).encode()).digest())
        self.app.commit(); self.make_witness()
        return result
    def body(self, who=2, units=58, nonce=0, until=1000):
        grant = {2:'raven',3:'atlas',4:'worker'}.get(who,'')
        sender = IDS[5] if who == 5 else IDS[0]
        return self.model.body(sender, nonce, {'type':'transfer','to':IDS[1],'units':units},
                               grant_id=grant, valid_until=until)
    def review(self, who=2, units=58, nonce=0, until=1000, witness=None, wallet=None, **kwargs):
        return (wallet or self.wallet).review(witness or self.witness, self.body(who,units,nonce,until),public(KEYS[who]),**kwargs)
    def approve(self, who=2, units=58, nonce=0, until=1000, wallet=None):
        w = wallet or self.wallet; body = self.body(who,units,nonce,until)
        review = w.review(self.witness,body,public(KEYS[who]))
        return w.approve(self.witness,body,public(KEYS[who]),review['confirmation'],self.root/f'key{who}.pem',PASSWORD)
    def sync(self): return self.wallet.sync(self.witness)
    def pending_units(self): return sum(self.wallet.pending()['pending_budget_units'].values())
    def owner_operation(self, op):
        ledger = restore(self.g, self.witness['state']['native'])
        try:
            nonce = ledger._account(IDS[0])['nonce']
            return canonical(sign(KEYS[0], ledger.body(IDS[0],nonce,op)))
        finally: ledger.close()

    def test_pending_shared_budget_is_checked_before_unlock(self):
        self.approve()
        with patch('certified_wallet._load_vault', side_effect=AssertionError('must not unlock')):
            with self.assertRaisesRegex(Reject,'shared budget insufficient'):
                self.review(3,39)
    def test_prepared_review_is_not_a_reservation(self):
        self.review(); self.review(3,39)
        self.assertEqual(self.wallet.pending()['decision_count'],0)
    def test_signed_but_unbroadcast_consumes_allowance(self):
        self.approve(); view = self.review(3,38)
        self.assertEqual(view['shared_budget_remaining_units'],100)
        self.assertEqual(view['pending_shared_budget_debit_units'],60)
        self.assertEqual(view['shared_budget_available_after_pending_units'],40)
        self.assertEqual(view['pending_account_debit_units'],60)
        self.assertEqual(self.witness['state']['native']['budgets'][0][4],0)
    def test_fee_inclusive_boundary_two_pending_agents(self):
        self.approve(); self.approve(3,38)
        self.assertEqual(self.pending_units(),100)
        with self.assertRaisesRegex(Reject,'shared budget insufficient'): self.review(4,1)
    def test_owner_cannot_ignore_pending_agent_debits(self):
        self.advance([self.owner_operation({'type':'transfer','to':IDS[5],'units':916})])
        # Balance = 74 (1000 - 8 setup - 918 external debit); pending agent uses 60.
        self.approve()
        with self.assertRaisesRegex(Reject,'balance insufficient after pending'): self.review(0,13,nonce=5)
    def test_owner_pending_payment_counts_against_agent_balance(self):
        self.approve(0,950,nonce=4)
        with self.assertRaisesRegex(Reject,'balance insufficient after pending'): self.review()
    def test_separate_owner_does_not_charge_another_account(self):
        self.approve(5,450,nonce=0)
        view=self.review();self.assertEqual(view['pending_account_debit_units'],0)
        self.approve();self.assertEqual(self.pending_units(),60)
    def test_shared_budget_and_distinct_budgets_remain_distinct(self):
        create={'type':'budget_create','id':'other','cap':100,'expires':100,'recipients':[IDS[1]]}
        grant={'type':'grant','id':'other-worker','public_key':public(KEYS[4]),'cap':100,'expires':100,
               'recipients':[IDS[1]],'budget_id':'other'}
        self.advance([self.owner_operation(create)])
        self.advance([self.owner_operation(grant)])
        self.approve()
        body={**self.body(4,58),'grant_id':'other-worker'}
        r=self.wallet.review(self.witness,body,public(KEYS[4]))
        self.assertEqual(r['pending_shared_budget_debit_units'],0)
        self.wallet.approve(self.witness,body,public(KEYS[4]),r['confirmation'],self.root/'key4.pem',PASSWORD)
        self.assertEqual(sorted(self.wallet.pending()['pending_budget_units'].values()),[60,60])
    def test_review_changes_when_another_worker_signs(self):
        prior=self.review(3,38);self.approve()
        with patch('certified_wallet._load_vault',side_effect=AssertionError('must not unlock')):
            with self.assertRaisesRegex(Reject,'review changed'):
                self.wallet.approve(self.witness,self.body(3,38),public(KEYS[3]),prior['confirmation'],self.root/'key3.pem',PASSWORD)
    def test_review_changes_even_if_pending_on_other_account(self):
        prior=self.review();self.approve(5,5)
        with self.assertRaisesRegex(Reject,'review changed'):
            self.wallet.approve(self.witness,self.body(),public(KEYS[2]),prior['confirmation'],self.root/'key2.pem',PASSWORD)
    def test_two_writer_race_cannot_overbook_budget(self):
        barrier=threading.Barrier(2)
        def worker(who):
            w=self.open()
            try:
                body=self.body(who,58);r=w.review(self.witness,body,public(KEYS[who]))
                barrier.wait(timeout=8)
                try:
                    w.approve(self.witness,body,public(KEYS[who]),r['confirmation'],self.root/f'key{who}.pem',PASSWORD)
                    return 'signed'
                except Reject: return 'refused'
            finally: w.close()
        with ThreadPoolExecutor(max_workers=2) as pool: out=list(pool.map(worker,[2,3]))
        self.assertEqual(sorted(out),['refused','signed']);self.assertEqual(self.pending_units(),60)
    def test_pending_survives_reopen(self):
        self.approve();self.wallet.close();self.wallet=self.open()
        with self.assertRaisesRegex(Reject,'shared budget insufficient'): self.review(3,39)
    def test_independent_journal_is_not_falsely_claimed_coordinated(self):
        self.approve();other=self.open(self.root/'other.sqlite')
        try: self.approve(3,58,wallet=other)
        finally: other.close()
        self.assertEqual(self.pending_units(),60)
    def test_exact_receipt_removes_hold_without_refunding_native_spend(self):
        first=self.approve();self.approve(3,38)
        self.advance([canonical(first['result'])]);summary=self.sync()
        self.assertEqual(sum(summary['pending_budget_units'].values()),40)
        self.assertEqual(sorted(x['status'] for x in summary['decisions']),['pending','recorded'])
        self.assertEqual(self.witness['state']['native']['budgets'][0][4],60)
        with self.assertRaisesRegex(Reject,'shared budget insufficient'): self.review(4,1)
    def test_recorded_signature_still_exportable(self):
        first=self.approve();self.advance([canonical(first['result'])]);self.sync()
        self.assertEqual(self.wallet.export(first['decision_id'])['result'],first['result'])
    def test_native_nonce_advancement_alone_does_not_release_hold(self):
        self.approve()
        other=canonical(sign(KEYS[2],self.body(2,1)))
        self.advance([other]);summary=self.sync()
        self.assertEqual(summary['decisions'][0]['status'],'pending');self.assertEqual(self.pending_units(),60)
    def test_revocation_does_not_refund_an_unresolved_obligation(self):
        self.approve();self.advance([self.owner_operation({'type':'revoke','id':'raven'})]);self.sync()
        self.assertEqual(self.pending_units(),60)
        with self.assertRaisesRegex(Reject,'shared budget insufficient'): self.review(3,39)
    def test_authority_fence_does_not_release_pending_account_debit(self):
        self.approve();self.advance([self.owner_operation({'type':'fence'})]);summary=self.sync()
        self.assertEqual(summary['pending_account_units'][IDS[0]],60)
    def test_clock_passing_alone_does_not_expire_height_valid_payment(self):
        self.approve(until=2);self.clock+=90*10**9
        self.assertEqual(self.sync()['decisions'][0]['status'],'pending')
    def test_at_valid_until_height_hold_is_retained(self):
        self.approve(until=2);self.advance();self.sync();self.assertEqual(self.pending_units(),60)
    def test_beyond_expiry_absent_from_verified_full_state_retires_hold(self):
        self.approve(until=2);self.advance();self.sync();self.advance();summary=self.sync()
        self.assertEqual(summary['decisions'][0]['status'],'expired_absent');self.assertEqual(self.pending_units(),0)
    def test_expired_nonce_can_be_used_by_a_new_reviewed_intention(self):
        old=self.approve(until=2);self.advance();self.sync();self.advance();self.sync()
        new=self.approve(until=20)
        self.assertNotEqual(old['decision_id'],new['decision_id']);self.assertEqual(self.pending_units(),60)
        self.assertEqual(self.app.check_tx(canonical(new['result']))['code'],0)
    def test_recorded_receipt_wins_over_later_expiry(self):
        first=self.approve(until=2);self.advance([canonical(first['result'])]);self.sync();self.advance();summary=self.sync()
        self.assertEqual(summary['decisions'][0]['status'],'recorded')
    def test_certificate_gap_needs_signed_continuation(self):
        self.approve(until=2);self.advance();self.advance()
        with self.assertRaisesRegex(Reject,'missing signed header continuation'): self.sync()
        self.assertEqual(self.pending_units(),60)
    def test_valid_header_continuation_allows_expiry_reconciliation(self):
        self.approve(until=2);self.advance();middle=self.witness['state_commit'];self.advance()
        summary=self.wallet.sync(self.witness,continuation=[middle])
        self.assertEqual(summary['decisions'][0]['status'],'expired_absent')
    def test_forged_intermediate_header_does_not_release_hold(self):
        self.approve(until=2);self.advance();middle=copy.deepcopy(self.witness['state_commit']);self.advance()
        middle['commit']['signatures'][0]['signature']='AA=='
        with self.assertRaises(ValueError):self.wallet.sync(self.witness,continuation=[middle])
        self.assertEqual(self.pending_units(),60)
    def test_old_checkpoint_cannot_resurrect_released_balance(self):
        old=self.witness;first=self.approve();self.advance([canonical(first['result'])]);self.sync()
        with self.assertRaisesRegex(Reject,'rolls back'):self.wallet.sync(old)
    def test_untrusted_endpoint_paid_label_is_not_a_release(self):
        self.approve();false=copy.deepcopy(self.witness);false['status']='paid'
        with self.assertRaises(ValueError):self.wallet.sync(false)
        self.assertEqual(self.pending_units(),60)
    def test_corrupted_signed_result_is_rejected_before_unlock(self):
        self.approve();row=self.wallet.db.execute('SELECT id,result FROM decisions').fetchone()
        result=json.loads(row[1]);result['signature']='0'*128;wire=canonical(result)
        self.wallet.db.execute('UPDATE decisions SET result=?,result_hash=? WHERE id=?',(wire.decode(),hashlib.sha256(wire).hexdigest(),row[0]))
        with patch('certified_wallet._load_vault',side_effect=AssertionError('must not unlock')):
            with self.assertRaises(ValueError): self.review(3,38)
    def test_corrupted_debit_cannot_make_a_hold_smaller(self):
        self.approve();row=self.wallet.db.execute('SELECT id,review FROM decisions').fetchone()
        review=json.loads(row[1]);review['proposed_account_debit_units']=1
        material={k:v for k,v in review.items() if k!='confirmation'}
        ident=hashlib.sha256(REVIEW_DOMAIN+encode(material)).hexdigest();review['confirmation']=ident
        self.wallet.db.execute('UPDATE decisions SET id=?,review=? WHERE id=?',(ident,encode(review).decode(),row[0]))
        with self.assertRaisesRegex(Reject,'debit differs'): self.review(3,39)
    def test_saved_witness_corruption_is_not_hidden(self):
        self.approve();self.wallet.db.execute("UPDATE wallet_evidence SET witness='{}'")
        with self.assertRaisesRegex(Reject,'intact saved'):self.wallet.pending()
    def test_new_journal_without_state_does_not_report_available_funds(self):
        with self.assertRaisesRegex(Reject,'sync first'):self.wallet.pending()
    def test_failed_unlock_does_not_reserve_allowance(self):
        r=self.review()
        with self.assertRaises(Reject):
            self.wallet.approve(self.witness,self.body(),public(KEYS[2]),r['confirmation'],self.root/'key2.pem',b'incorrect-test-passphrase')
        self.assertEqual(self.wallet.pending()['decision_count'],0)
    def test_slow_unlock_expiry_does_not_commit_signature(self):
        r=self.review()
        def delayed(*args):self.clock+=301*10**9;return KEYS[2]
        with patch('certified_wallet._load_vault',side_effect=delayed):
            with self.assertRaisesRegex(Reject,'too old'):
                self.wallet.approve(self.witness,self.body(),public(KEYS[2]),r['confirmation'],self.root/'key2.pem',PASSWORD)
        self.assertEqual(self.wallet.pending()['decision_count'],0)
    def test_abort_at_decision_insert_rolls_back_signature_and_hold(self):
        r=self.review()
        self.wallet.db.execute("CREATE TRIGGER stop_decision BEFORE INSERT ON decisions BEGIN SELECT RAISE(ABORT,'fixture failure'); END")
        with self.assertRaises(sqlite3.IntegrityError):
            self.wallet.approve(self.witness,self.body(),public(KEYS[2]),r['confirmation'],self.root/'key2.pem',PASSWORD)
        self.assertEqual(self.wallet.pending()['decision_count'],0)
    def test_policy_expiry_keeps_export_and_historical_inspection(self):
        first=self.approve();self.clock=nanos(self.policy['trust_expires_utc'])
        self.assertEqual(self.wallet.export(first['decision_id'])['result'],first['result'])
        self.assertFalse(self.wallet.pending()['freshness_checked'])
        with self.assertRaisesRegex(Reject,'policy expired'):self.sync()
    def test_existing_pre_reservation_decision_is_not_forgotten(self):
        first=self.approve();row=self.wallet.db.execute('SELECT id,review FROM decisions').fetchone()
        review=json.loads(row[1])
        new_fields=['reservation_schema','local_obligations_digest','pending_account_debit_units',
                    'account_available_after_pending_units','pending_grant_debit_units',
                    'grant_available_after_pending_units','pending_shared_budget_debit_units',
                    'shared_budget_available_after_pending_units','reservation_scope']
        for key in new_fields:review.pop(key)
        ident=hashlib.sha256(REVIEW_DOMAIN+encode({k:v for k,v in review.items() if k!='confirmation'})).hexdigest()
        review['confirmation']=ident
        self.wallet.db.execute('UPDATE decisions SET id=?,review=? WHERE id=?',(ident,encode(review).decode(),row[0]))
        self.wallet.db.execute('DELETE FROM wallet_evidence');self.wallet.close();self.wallet=self.open()
        self.assertEqual(self.wallet.export(ident)['result'],first['result'])
        with self.assertRaisesRegex(Reject,'shared budget insufficient'):self.review(3,39)
    def test_legacy_outbox_database_is_not_silently_reused(self):
        p=self.root/'legacy.sqlite';db=sqlite3.connect(p);db.execute('CREATE TABLE outbox(value TEXT)');db.execute("INSERT INTO outbox VALUES ('preserve')");db.commit();db.close();p.chmod(0o600)
        with self.assertRaisesRegex(Reject,'different wallet'):self.open(p)
        db=sqlite3.connect(p)
        self.assertEqual(db.execute('SELECT value FROM outbox').fetchone()[0],'preserve')
        self.assertFalse(db.execute("SELECT name FROM sqlite_master WHERE name='decisions'").fetchone());db.close()
    def test_insufficient_existing_holds_never_silently_dropped(self):
        self.approve();self.advance([self.owner_operation({'type':'transfer','to':IDS[5],'units':950})]);summary=self.sync()
        self.assertEqual(summary['pending_account_units'][IDS[0]],60)
        with self.assertRaisesRegex(Reject,'balance insufficient after pending'):self.review(3,1)
    def test_decision_limit_refuses_before_unlock(self):
        self.approve()
        with patch('wallet_obligations.MAX_DECISIONS',1),patch('certified_wallet._load_vault',side_effect=AssertionError('must not unlock')):
            with self.assertRaisesRegex(Reject,'decision-count limit'):self.review(3,1)
    def test_process_exit_after_signature_commit_recovers_hold_and_original_bytes(self):
        for name,value in [('genesis',self.engine),('policy',self.policy),('witness',self.witness),('body',self.body())]:
            (self.root/f'{name}.json').write_bytes(encode(value))
        source='''import json,os,sys
from pathlib import Path
from certified_wallet import CertifiedWallet
p=Path(sys.argv[1]);read=lambda n:json.loads((p/(n+'.json')).read_bytes())
w=CertifiedWallet(p/'wallet.sqlite',(p/'genesis.json').read_bytes(),read('policy'),clock=lambda:int(sys.argv[2]))
r=w.review(read('witness'),read('body'),sys.argv[3]);w.approve(read('witness'),read('body'),sys.argv[3],r['confirmation'],p/'key2.pem',b'public-test-passphrase-not-a-secret-1soft')
os._exit(23)
'''
        p=subprocess.run([sys.executable,'-c',source,str(self.root),str(self.clock),public(KEYS[2])],
                         env={**os.environ,'PYTHONPATH':str(ROOT/'src')},capture_output=True,timeout=10)
        self.assertEqual(p.returncode,23,p.stderr)
        ident=self.wallet.pending()['decisions'][0]['decision_id'];self.assertEqual(self.pending_units(),60)
        env=self.wallet.export(ident)['result'];self.assertEqual(env,sign(KEYS[2],self.body()))
        with self.assertRaisesRegex(Reject,'shared budget insufficient'):self.review(3,39)
    def test_consent_is_not_charged_twice_with_sponsor_signature(self):
        pk=public(KEYS[4])
        body=self.model.body(IDS[0],4,{'type':'open_account','public_key':pk,'units':100,'acceptance':''})
        r=self.wallet.review(self.witness,body,pk,mode='accept')
        consent=self.wallet.approve(self.witness,body,pk,r['confirmation'],self.root/'key4.pem',PASSWORD,mode='accept')['result']
        self.assertEqual(self.wallet.pending()['pending_account_units'],{})
        r=self.wallet.review(self.witness,consent,public(KEYS[0]))
        self.wallet.approve(self.witness,consent,public(KEYS[0]),r['confirmation'],self.root/'key0.pem',PASSWORD)
        self.assertEqual(self.wallet.pending()['pending_account_units'][IDS[0]],102)
    def test_failed_new_proof_leaves_previous_reconciliation_unchanged(self):
        self.approve();before=self.wallet.pending();bad=copy.deepcopy(self.witness)
        bad['state_commit']['commit']['signatures'][0]['signature']='AA=='
        with self.assertRaises(ValueError):self.wallet.sync(bad)
        self.assertEqual(self.wallet.pending(),before)


class ObligationCliTests(unittest.TestCase):
    """Current-clock CLI checks over freshly signed fixture state, never live consensus."""
    def setUp(self):
        from datetime import datetime, timezone, timedelta
        self.case=ObligationTests();self.case.setUp();self.root=self.case.root
        c=self.case;now=datetime.now(timezone.utc)
        self.witness=copy.deepcopy(c.witness)
        h=self.witness['state_commit']['header'];h['time']=now.isoformat().replace('+00:00','Z')
        self.witness['state_commit']=make_commit(h,c.trust,c.valkeys)
        self.policy={**c.policy,'trust_expires_utc':(now+timedelta(hours=1)).isoformat().replace('+00:00','Z')}
        for name,value in [('genesis',c.engine),('policy',self.policy),('witness',self.witness),('body',c.body())]:
            (self.root/f'cli-{name}.json').write_bytes(encode(value))
        self.args=['--genesis',str(self.root/'cli-genesis.json'),'--policy',str(self.root/'cli-policy.json'),
                   '--journal',str(self.root/'cli.sqlite')]
    def tearDown(self):self.case.tearDown()
    def call(self,command,*extra):
        return subprocess.run([sys.executable,str(ROOT/'scripts/certified_wallet.py'),command,*self.args,*extra],
                              capture_output=True,text=True,timeout=15)
    def test_sync_cli_observes_state_without_signature(self):
        p=self.call('sync','--witness',str(self.root/'cli-witness.json'))
        self.assertEqual(p.returncode,0,p.stderr);out=json.loads(p.stdout)
        self.assertEqual(out['decision_count'],0);self.assertFalse(out['broadcast'])
    def test_pending_requires_a_saved_witness(self):
        p=self.call('pending');self.assertEqual(p.returncode,2);self.assertIn('sync first',p.stderr)
    def test_pending_cli_is_historical_and_no_password(self):
        self.call('sync','--witness',str(self.root/'cli-witness.json'))
        p=self.call('pending');self.assertEqual(p.returncode,0,p.stderr)
        self.assertFalse(json.loads(p.stdout)['freshness_checked'])
    def test_sync_rejects_provider_success_label(self):
        (self.root/'invalid.json').write_text('{"status":"paid"}')
        p=self.call('sync','--witness',str(self.root/'invalid.json'))
        self.assertEqual(p.returncode,2)
    def test_actual_terminal_sign_then_other_agent_review_refused(self):
        import test_offline_signer
        c=self.case;wallet=CertifiedWallet(self.root/'cli.sqlite',c.raw,self.policy)
        try:r=wallet.review(self.witness,c.body(),public(KEYS[2]))
        finally:wallet.close()
        out=self.root/'signed-cli.json'
        command=[sys.executable,str(ROOT/'scripts/certified_wallet.py'),'sign',*self.args,
                 '--witness',str(self.root/'cli-witness.json'),'--body',str(self.root/'cli-body.json'),
                 '--signer-public-key',public(KEYS[2]),'--vault',str(self.root/'key2.pem'),'--output',str(out)]
        code,printed=test_offline_signer.SignerTests.tty_command(self,command,
             [(b'Type the certified confirmation digest to approve:',r['confirmation'].encode()),
              (b'Vault passphrase:',PASSWORD)])
        self.assertEqual(code,0,printed);self.assertNotIn(PASSWORD,printed)
        self.assertEqual(c.app.check_tx(canonical(json.loads(out.read_bytes())))['code'],0)
        p=self.call('pending');self.assertEqual(p.returncode,0,p.stderr)
        self.assertEqual(sum(json.loads(p.stdout)['pending_budget_units'].values()),60)
        (self.root/'atlas.json').write_bytes(encode(c.body(3,39)))
        p=self.call('review','--witness',str(self.root/'cli-witness.json'),'--body',str(self.root/'atlas.json'),
                    '--signer-public-key',public(KEYS[3]))
        self.assertEqual(p.returncode,2);self.assertIn('shared budget insufficient',p.stderr)
        self.assertNotIn('Vault passphrase',p.stdout)
    def test_sync_does_not_require_body_signer_or_vault(self):
        p=self.call('sync','--witness',str(self.root/'cli-witness.json'))
        self.assertEqual(p.returncode,0,p.stderr)
        self.assertEqual(len(list(self.root.glob('*.pem'))),6)

if __name__=='__main__':unittest.main()
