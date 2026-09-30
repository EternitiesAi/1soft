"""Real P4 components, local RPC fixture, synthetic committee signatures."""
import hashlib
from pathlib import Path
import shutil
import tempfile
import unittest
from unittest.mock import patch

from delivery_fixture import Fixture
from wallet_fixture import PASSWORD
from block_application import encode
from commit_verifier import load_json
from payment_requests import new_request

try:
    from platform_service import PlatformService
except ImportError:
    PlatformService = None


class ServiceTests(unittest.TestCase):
    def setUp(self):
        self.assertIsNotNone(PlatformService, 'platform composition is missing')
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name); self.root.chmod(0o700)
        self.node = self.root/'fixture'; self.node.mkdir(mode=0o700)
        self.fx = Fixture(self.node, mode='normal')
        self.workspace = self.root/'platform'; self.workspace.mkdir(mode=0o700)
        for name in ('owner','raven','atlas'):
            shutil.copyfile(self.node/(name+'.pem'), self.workspace/(name+'.pem'))
            (self.workspace/(name+'.pem')).chmod(0o600)
        c = self.fx.chain
        self.roles = {name:dict(payer=c.payer,grant_id='' if name=='owner' else name,
                                vault=name+'.pem') for name in ('owner','raven','atlas')}
        self.service = self.open(create=True)
        self.service.import_checkpoint(self.fx.proof, expected_tip=None)
        self.service.sync(expected_revision=None)

    def tearDown(self):
        if hasattr(self,'service'): self.service.close()
        if hasattr(self,'fx'): self.fx.close()
        if hasattr(self,'tmp'): self.tmp.cleanup()

    def open(self,**kw):
        return PlatformService(self.workspace,self.fx.chain.genesis,self.fx.chain.policy,
            self.fx.url,self.roles,clock=self.fx.chain.clock,**kw)

    def request(self,units='58',note='Coffee'):
        c=self.fx.chain
        value=new_request(hashlib.sha256(c.genesis).hexdigest(),c.merchant,units,
                          created_ns=c.now,expires_ns=c.now+600*10**9,note=note)
        return self.service.add_request(value)['request_id']

    def sign(self,rid,role='raven'):
        p=self.service.prepare(rid,role,valid_until=30)
        return self.service.approve(rid,role,p['review'],p['confirmation'],password=PASSWORD)

    def send(self,rid):
        p=self.service.submission_review(rid)
        return self.service.submit(rid,p['review'],p['confirmation'])

    def test_preview_has_no_binding_or_key_access(self):
        rid=self.request()
        with patch('p4_wallet._load_vault',side_effect=AssertionError('key access')):
            p=self.service.prepare(rid,'raven',valid_until=30)
        self.assertEqual('60',p['review']['debit_units'])
        self.assertIsNone(self.service.book.selected(rid)['decision_id'])
        self.assertEqual('0',self.service.state()['wallet']['pending_debit_units'])

    def test_sign_is_durable_original_and_never_submits(self):
        rid=self.request(); result=self.sign(rid)
        self.assertEqual('signed_and_reserved',result['status'])
        self.assertEqual([],self.fx.submissions)
        self.assertEqual('60',self.service.state()['wallet']['pending_debit_units'])
        raw=self.service.recover(rid); self.service.close(); self.service=self.open()
        self.assertEqual(raw,self.service.recover(rid))
        p=self.service.book.selected(rid)['review']
        with patch('p4_wallet._load_vault',side_effect=AssertionError('resign')):
            again=self.service.approve(rid,'raven',p,result['decision_id'],password=b'ignored')
        self.assertEqual('original_signed_decision_retained',again['status'])
        self.assertEqual('60',self.service.state()['wallet']['pending_debit_units'])

    def test_binding_commits_before_vault_unlock(self):
        rid=self.request(); p=self.service.prepare(rid,'raven',valid_until=30)
        def refuse(*a,**k):
            self.assertEqual(p['confirmation'],self.service.book.selected(rid)['decision_id'])
            raise ValueError('unlock refused')
        with patch('p4_wallet._load_vault',side_effect=refuse):
            with self.assertRaises(ValueError):
                self.service.approve(rid,'raven',p['review'],p['confirmation'],password=PASSWORD)
        self.assertEqual('0',self.service.state()['wallet']['pending_debit_units'])
        self.assertEqual('review_bound_unsigned',self.service.state()['requests'][0]['stage'])
        self.sign(rid)

    def test_role_recipient_units_and_digest_changes_refused_before_key(self):
        rid=self.request(); p=self.service.prepare(rid,'raven',valid_until=30)
        with patch('p4_wallet._load_vault',side_effect=AssertionError('key access')):
            for role in ('owner','atlas','../../owner.pem'):
                with self.assertRaises(ValueError):
                    self.service.approve(rid,role,p['review'],p['confirmation'],password=PASSWORD)
            other=self.request('57','Different')
            with self.assertRaises(ValueError):
                self.service.approve(other,'raven',p['review'],p['confirmation'],password=PASSWORD)
            with self.assertRaises(ValueError):
                self.service.approve(rid,'raven',p['review'],'0'*64,password=PASSWORD)

    def test_stale_review_refuses_without_binding(self):
        rid=self.request(); p=self.service.prepare(rid,'raven',valid_until=30)
        self.fx.publish()
        tip=self.service.state()['ledger']['checkpoint']['evidence_id']
        self.service.import_checkpoint(self.fx.proof,expected_tip=tip)
        self.service.sync(expected_revision=self.service.state()['wallet']['revision'])
        with patch('p4_wallet._load_vault',side_effect=AssertionError('key access')):
            with self.assertRaises(ValueError):
                self.service.approve(rid,'raven',p['review'],p['confirmation'],password=PASSWORD)
        self.assertIsNone(self.service.book.selected(rid)['decision_id'])
        self.sign(rid)

    def test_agent_lanes_share_budget(self):
        a=self.request('58','Raven');self.sign(a)
        b=self.request('39','Atlas too much')
        with self.assertRaises(ValueError):self.service.prepare(b,'atlas',valid_until=30)
        c=self.request('38','Atlas exact');self.sign(c,'atlas')
        self.assertEqual('100',self.service.state()['wallet']['pending_debit_units'])
        self.assertEqual('0',self.service.state()['wallet']['budgets'][0]['uncommitted_units'])

    def test_get_state_does_not_collect_or_mutate_money(self):
        rid=self.request();self.sign(rid)
        before=self.service.wallet.db.execute('SELECT * FROM observations').fetchall()
        calls=list(self.fx.reads)
        for _ in range(2): self.service.state()
        self.assertEqual(calls,self.fx.reads)
        self.assertEqual(before,self.service.wallet.db.execute('SELECT * FROM observations').fetchall())

    def test_submission_collection_archive_and_reconcile_are_separate(self):
        rid=self.request();self.sign(rid);raw=self.service.recover(rid)
        sent=self.send(rid)
        self.assertFalse(sent['execution_proven'])
        self.assertEqual([raw],self.fx.submissions)
        self.assertEqual('60',self.service.state()['wallet']['pending_debit_units'])
        receipt=self.service.collect(rid)
        self.assertEqual('receipt_collected',receipt['status'])
        self.assertEqual('60',self.service.state()['wallet']['pending_debit_units'])
        archived=self.service.retain_receipt(rid)
        capsule=self.service.capsule(rid,archived['capsule_id'])
        self.assertEqual('1soft/protocol4-payment-capsule/v1',load_json(capsule)['format'])
        self.assertEqual('60',self.service.state()['wallet']['pending_debit_units'])
        rev=self.service.state()['wallet']['revision']
        self.service.reconcile(rid,expected_revision=rev)
        self.assertEqual('0',self.service.state()['wallet']['pending_debit_units'])
        self.assertEqual('recorded',self.service.state()['requests'][0]['stage'])
        self.assertEqual([raw],self.fx.submissions)
        self.service.reconcile(rid,expected_revision=self.service.state()['wallet']['revision'])
        with self.assertRaises(ValueError):self.service.submission_review(rid)

    def test_lost_http_response_can_collect_original_without_resend(self):
        self.fx.mode='drop';rid=self.request();self.sign(rid);self.send(rid)
        self.service.close();self.service=self.open()
        row=self.service.state()['requests'][0]
        self.assertTrue(row['delivery']['attempt_recorded'])
        with self.assertRaises(ValueError):self.service.submission_review(rid)
        self.service.collect(rid)
        self.service.reconcile(rid,expected_revision=self.service.state()['wallet']['revision'])
        self.assertEqual(1,len(self.fx.submissions))

    def test_admission_and_missing_receipt_preserve_hold(self):
        self.fx.mode='admit_only';rid=self.request();self.sign(rid);self.send(rid)
        self.assertEqual('unavailable',self.service.collect(rid)['status'])
        self.assertEqual('60',self.service.state()['wallet']['pending_debit_units'])
        with self.assertRaises(ValueError):self.service.retain_receipt(rid)
        with self.assertRaises(ValueError):self.service.submission_review(rid)

    def test_expiry_clears_current_money_but_original_recovery_survives(self):
        rid=self.request();self.sign(rid);raw=self.service.recover(rid)
        self.fx.chain.now+=3700*10**9
        state=self.service.state()
        self.assertIsNone(state['wallet']);self.assertIsNone(state['ledger'])
        self.assertFalse(state['current_evidence_available'])
        self.assertEqual(raw,self.service.recover(rid))
        self.assertEqual('signed_reserved',state['requests'][0]['stage'])
        with self.assertRaises(ValueError):self.service.submission_review(rid)

    def test_create_never_overwrites_existing_workspace_journals(self):
        raw=self.service.wallet.path.read_bytes()
        with self.assertRaises((ValueError,FileExistsError)): self.open(create=True)
        self.assertEqual(raw,self.service.wallet.path.read_bytes())

    def test_fixed_vault_map_refuses_paths_and_role_aliases(self):
        roles={**self.roles,'other':{**self.roles['raven']}}
        with self.assertRaises(ValueError):
            PlatformService(self.workspace,self.fx.chain.genesis,self.fx.chain.policy,
                            self.fx.url,roles,clock=self.fx.chain.clock)
        roles={k:dict(v) for k,v in self.roles.items()};roles['raven']['vault']='../fixture/raven.pem'
        with self.assertRaises(ValueError):
            PlatformService(self.workspace,self.fx.chain.genesis,self.fx.chain.policy,
                            self.fx.url,roles,clock=self.fx.chain.clock)

    def test_corrupt_request_and_decision_are_not_hidden_as_unpaid(self):
        rid=self.request();self.sign(rid)
        self.service.wallet.db.execute('UPDATE decisions SET payload=?',(b'{}',))
        with self.assertRaises(ValueError):self.service.state()


if __name__=='__main__':unittest.main()
