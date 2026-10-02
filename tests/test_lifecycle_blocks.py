"""New account operations exercised through block staging, not just the ledger."""
import copy
import hashlib
import json
import tempfile
import unittest
from pathlib import Path
from native_core import NativeLedger, Reject, canonical, sign, public, address, accept_account_key
from block_application import BlockApplication, transaction_id
from test_account_lifecycle import KEYS, IDS, genesis_v2, independently_accept


class LifecycleBlockTests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory();self.path=Path(self.tmp.name)/'app.sqlite'
        self.g=genesis_v2();self.app=BlockApplication(self.path,expected_genesis=self.g)
        self.app.init_chain(self.g['chain_id'],self.g)
        self.model=NativeLedger(':memory:',self.g)

    def tearDown(self):
        self.model.close();self.app.close();self.tmp.cleanup()

    def open(self):
        b=self.model.body(IDS[0],0,{'type':'open_account','public_key':public(KEYS[3]),'units':100,'acceptance':''})
        return canonical(sign(KEYS[0],independently_accept(KEYS[3],b)))

    def rotate(self):
        b=self.model.body(IDS[0],1,{'type':'rotate_key','public_key':public(KEYS[4]),'acceptance':''})
        return canonical(sign(KEYS[0],independently_accept(KEYS[4],b)))

    def finalize(self,txs,height=1):
        return self.app.finalize_block(txs,height,hashlib.sha256(str(height).encode()).digest())

    def state(self):return json.loads(self.app.query('/state')['value'])

    def test_info_exposes_genesis_pinned_version(self):self.assertEqual(self.app.info()['version'],2)

    def test_check_new_account_does_not_create_it(self):
        before=self.state();self.assertEqual(self.app.check_tx(self.open())['code'],0)
        self.assertEqual(self.state(),before)
        self.assertNotEqual(self.app.query('/account/'+IDS[3])['code'],0)

    def test_proposal_can_open_then_spend_without_mutating_commit(self):
        op=self.open()
        spend=canonical(sign(KEYS[3],self.model.body(IDS[3],0,{'type':'transfer','to':IDS[1],'units':10})))
        before=self.state()
        self.assertEqual(self.app.prepare_proposal([op,spend],1,1048576),[op,spend])
        self.assertTrue(self.app.process_proposal([op,spend],1))
        self.assertEqual(self.state(),before)

    def test_proposal_rejects_spend_before_account_exists(self):
        spend=canonical(sign(KEYS[3],self.model.body(IDS[3],0,{'type':'transfer','to':IDS[1],'units':10})))
        self.assertFalse(self.app.process_proposal([spend,self.open()],1))

    def test_finalized_account_invisible_until_commit(self):
        self.finalize([self.open()]);self.assertNotEqual(self.app.query('/account/'+IDS[3])['code'],0)
        self.app.commit();self.assertEqual(self.app.query('/account/'+IDS[3])['code'],0)
        self.assertEqual(json.loads(self.app.query('/account/'+IDS[3])['value'])['balance'],100)

    def test_finalized_rotation_invisible_until_commit(self):
        self.finalize([self.open()]);self.app.commit();self.finalize([self.rotate()],2)
        self.assertEqual(json.loads(self.app.query('/account/'+IDS[0])['value'])['public_key'],public(KEYS[0]))
        self.app.commit()
        self.assertEqual(json.loads(self.app.query('/account/'+IDS[0])['value'])['public_key'],public(KEYS[4]))

    def test_committed_open_replay_rejected_by_chain(self):
        self.finalize([self.open()]);self.app.commit();self.assertNotEqual(self.app.check_tx(self.open())['code'],0)

    def test_unknown_incoming_consent_deterministically_rejected(self):
        bad=json.loads(self.open());bad['body']['op']['acceptance']='0'*128
        bad=canonical(sign(KEYS[0],bad['body']))
        self.assertFalse(self.app.process_proposal([bad],1))
        final=self.finalize([bad]);self.assertNotEqual(final['tx_results'][0]['code'],0)
        self.app.commit();self.assertEqual(len(self.state()['native']['receipts']),0)

    def test_commit_fault_restores_old_key_and_replays(self):
        self.finalize([self.open()]);self.app.commit();before=self.state()
        result=self.finalize([self.rotate()],2)
        with self.assertRaises(RuntimeError):self.app.commit(fault='after_state')
        self.assertEqual(self.state(),before)
        self.app.close();self.app=BlockApplication(self.path,expected_genesis=self.g)
        self.assertEqual(self.app.info()['height'],1)
        self.assertEqual(self.finalize([self.rotate()],2),result);self.app.commit()
        self.assertEqual(self.app.info()['height'],2)

    def test_post_commit_restart_retains_new_key_and_receipt(self):
        self.finalize([self.open(),self.rotate()]);self.app.commit();before=self.state()
        self.app.close();self.app=BlockApplication(self.path,expected_genesis=self.g)
        self.assertEqual(self.state(),before)
        receipt=json.loads(self.app.query('/receipt/'+transaction_id(self.rotate()))['value'])
        self.assertEqual(receipt['signer_public_key'],public(KEYS[0]))
        self.assertEqual(receipt['envelope']['body']['op']['public_key'],public(KEYS[4]))

    def test_old_owner_key_rejected_after_rotation_commit(self):
        self.finalize([self.open(),self.rotate()]);self.app.commit()
        b=self.model.body(IDS[0],2,{'type':'transfer','to':IDS[1],'units':1})
        self.assertNotEqual(self.app.check_tx(canonical(sign(KEYS[0],b)))['code'],0)
        self.assertEqual(self.app.check_tx(canonical(sign(KEYS[4],b)))['code'],0)

    def test_cannot_reopen_with_changed_protocol(self):
        self.finalize([self.open()]);self.app.commit();self.app.close()
        g=copy.deepcopy(self.g);g['protocol_version']=1
        with self.assertRaises(Reject):BlockApplication(self.path,expected_genesis=g)
