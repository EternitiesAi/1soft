import hashlib
import json
import os
from pathlib import Path
import sqlite3
import subprocess
import sys
import tempfile
import unittest

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from native_core import NativeLedger, Reject, public, address, sign, canonical
from block_application import BlockApplication, application_hash, transaction_id, transaction_data_size, MAX_BLOCK_TXS, MAX_BLOCK_BYTES


def fixture():
    owner=Ed25519PrivateKey.from_private_bytes(bytes([1])*32)
    merchant=Ed25519PrivateKey.from_private_bytes(bytes([2])*32)
    agent=Ed25519PrivateKey.from_private_bytes(bytes([3])*32)
    genesis={'chain_id':'eternities-block-test-1','asset':'DEV','fee':100,
        'allocations':[{'public_key':public(owner),'units':100_000_000},
                       {'public_key':public(merchant),'units':0}]}
    return owner,merchant,agent,genesis


def signed(genesis, key, nonce=0, *, op=None, grant_id='', until=1000):
    ledger=NativeLedger(':memory:',genesis)
    owner,merchant,agent,_=fixture()
    body=ledger.body(address(public(owner)),nonce,
        op or {'type':'transfer','to':address(public(merchant)),'units':1_000_000},
        grant_id=grant_id,valid_until=until)
    ledger.close()
    return canonical(sign(key,body))


class BlockTests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory()
        self.path=Path(self.tmp.name)/'app.sqlite'
        self.owner,self.merchant,self.agent,self.genesis=fixture()
        self.app=BlockApplication(self.path,expected_genesis=self.genesis)
        self.app.init_chain(self.genesis['chain_id'],self.genesis)
        self.tx=signed(self.genesis,self.owner)

    def tearDown(self):
        self.app.close(); self.tmp.cleanup()

    def reopen(self):
        self.app.close()
        self.app=BlockApplication(self.path,expected_genesis=self.genesis)

    def block(self, txs=None, *, commit=True):
        h=self.app.height+1
        result=self.app.finalize_block([self.tx] if txs is None else txs,h,hashlib.sha256(str(h).encode()).digest())
        if commit:self.app.commit()
        return result

    def test_check_does_not_mutate(self):
        before=self.app.query('/state')['value']
        self.assertEqual(self.app.check_tx(self.tx)['code'],0)
        self.assertEqual(before,self.app.query('/state')['value'])

    def test_prepare_does_not_mutate(self):
        before=self.app.info()
        self.assertEqual(self.app.prepare_proposal([self.tx],1,MAX_BLOCK_BYTES),[self.tx])
        self.assertEqual(before,self.app.info())

    def test_prepare_filters_competing_nonce(self):
        other=signed(self.genesis,self.owner,op={'type':'transfer','to':address(public(self.merchant)),'units':2})
        self.assertEqual(self.app.prepare_proposal([self.tx,other],1,MAX_BLOCK_BYTES),[self.tx])

    def test_process_rejects_double_spend(self):
        self.assertFalse(self.app.process_proposal([self.tx,self.tx],1))
        self.assertEqual(self.app.height,0)

    def test_process_valid_no_mutation(self):
        before=self.app.query('/state')['value']
        self.assertTrue(self.app.process_proposal([self.tx],1))
        self.assertEqual(before,self.app.query('/state')['value'])

    def test_same_height_alternate_proposals_are_isolated(self):
        other=signed(self.genesis,self.owner,op={'type':'transfer','to':address(public(self.merchant)),'units':5})
        self.assertTrue(self.app.process_proposal([self.tx],1))
        self.assertTrue(self.app.process_proposal([other],1))
        self.assertEqual(self.app.check_tx(self.tx)['code'],0)

    def test_finalize_not_visible_before_commit(self):
        before=self.app.query('/state')['value']
        self.block(commit=False)
        self.assertEqual(before,self.app.query('/state')['value'])
        self.assertEqual(self.app.height,0)

    def test_finalize_is_not_durable(self):
        self.block(commit=False); self.reopen()
        self.assertEqual(self.app.height,0)
        self.assertEqual(self.app.check_tx(self.tx)['code'],0)

    def test_commit_is_durable(self):
        result=self.block(); self.reopen()
        self.assertEqual(self.app.height,1)
        self.assertEqual(self.app.app_hash,result['app_hash'])
        self.assertEqual(self.app.check_tx(self.tx)['code'],1)

    def test_committed_replay_rejected(self):
        self.block()
        self.assertIn('already executed',self.app.check_tx(self.tx)['log'])
        self.assertFalse(self.app.process_proposal([self.tx],2))

    def test_empty_block_advances_height_and_root(self):
        root=self.app.app_hash
        result=self.block([])
        self.assertNotEqual(root,result['app_hash'])
        self.assertEqual(self.app.height,1)
        self.reopen(); self.assertEqual(self.app.height,1)

    def test_bad_signature_filtered(self):
        invalid=signed(self.genesis,self.agent)
        self.assertEqual(self.app.check_tx(invalid)['code'],1)
        self.assertEqual(self.app.prepare_proposal([invalid,self.tx],1,MAX_BLOCK_BYTES),[self.tx])

    def test_expiry_uses_committed_block_height(self):
        tx=signed(self.genesis,self.owner,until=1)
        self.block([])
        self.assertEqual(self.app.check_tx(tx)['code'],1)

    def test_duplicate_json_rejected(self):
        self.assertEqual(self.app.check_tx(b'{"body":{},"body":{}}')['code'],1)

    def test_noncanonical_json_rejected(self):
        self.assertEqual(self.app.check_tx(b' '+self.tx)['code'],1)

    def test_oversized_tx_rejected(self):
        self.assertEqual(self.app.check_tx(b'x'*20000)['code'],1)

    def test_block_transaction_limit(self):
        self.assertFalse(self.app.process_proposal([b'']*(MAX_BLOCK_TXS+1),1))

    def test_prepare_respects_byte_budget(self):
        self.assertEqual(self.app.prepare_proposal([self.tx],1,len(self.tx)-1),[])
        self.assertEqual(self.app.prepare_proposal([self.tx],1,len(self.tx)),[])
        self.assertEqual(self.app.prepare_proposal([self.tx],1,transaction_data_size([self.tx])),[self.tx])

    def test_finalize_duplicate_call_stable(self):
        first=self.block(commit=False)
        second=self.block(commit=False)
        self.assertEqual(first,second)

    def test_conflicting_pending_block_rejected(self):
        self.block(commit=False)
        with self.assertRaises(Reject):self.app.finalize_block([],1,b'z'*32)

    def test_height_gap_rejected(self):
        self.assertFalse(self.app.process_proposal([self.tx],3))
        with self.assertRaises(Reject):self.app.finalize_block([],3,b'z'*32)

    def test_bad_block_hash_rejected(self):
        with self.assertRaises(Reject):self.app.finalize_block([],1,b'z')

    def test_defensive_finalize_invalid_transaction_no_spend(self):
        before=self.app.query('/account/'+address(public(self.owner)))['value']
        result=self.block([signed(self.genesis,self.agent)])
        self.assertEqual(result['tx_results'][0]['code'],1)
        self.assertEqual(before,self.app.query('/account/'+address(public(self.owner)))['value'])

    def test_rollback_state_and_block_after_state_fault(self):
        before=self.app.info(); self.block(commit=False)
        with self.assertRaises(RuntimeError):self.app.commit(fault='after_state')
        self.assertEqual(self.app.info(),before)
        self.assertEqual(self.app.db.execute('SELECT count(*) FROM blocks').fetchone()[0],0)
        self.app.commit(); self.assertEqual(self.app.height,1)

    def test_rollback_before_commit(self):
        self.block(commit=False)
        with self.assertRaises(RuntimeError):self.app.commit(fault='before_commit')
        self.reopen(); self.assertEqual(self.app.height,0)

    def test_no_pending_commit_no_op(self):
        self.assertEqual(self.app.commit(),self.app.info())
        self.block(); before=self.app.info(); self.assertEqual(self.app.commit(),before)

    def test_mismatched_genesis_rejected(self):
        bad=dict(self.genesis,asset='OTHER')
        with self.assertRaises(Reject):self.app.init_chain(bad['chain_id'],bad)

    def test_mismatched_engine_chain_rejected(self):
        with self.assertRaises(Reject):self.app.init_chain('other-chain',self.genesis)

    def test_nonstandard_initial_height_rejected(self):
        with self.assertRaises(Reject):self.app.init_chain(self.genesis['chain_id'],self.genesis,10)

    def test_receipt_set_is_in_application_hash(self):
        self.block(); original=self.app.app_hash
        state=json.loads(json.dumps(self.app.native)); state['receipts']=[]
        self.assertNotEqual(original,application_hash(self.genesis,self.app.height,state))

    def test_proofs_not_faked(self):
        self.assertEqual(self.app.query('/state',prove=True)['code'],1)

    def test_historical_queries_not_faked(self):
        self.block(); self.block([])
        self.assertEqual(self.app.query('/state',height=1)['code'],1)

    def test_receipt_query(self):
        self.block()
        r=self.app.query('/receipt/'+transaction_id(self.tx))
        self.assertEqual(r['code'],0)
        self.assertEqual(json.loads(r['value'])['height'],1)

    def test_supply_conserved(self):
        self.block()
        self.assertEqual(sum(r[4] for r in self.app.native['accounts']),100_000_000)

    def test_chain_fence_blocks_agent(self):
        grant={'type':'grant','id':'worker','public_key':public(self.agent),'cap':5_000_000,
               'expires':50,'recipients':[address(public(self.merchant))]}
        t1=signed(self.genesis,self.owner,op=grant)
        t2=signed(self.genesis,self.agent,grant_id='worker')
        self.block([t1,t2])
        self.block([signed(self.genesis,self.owner,1,op={'type':'fence'})])
        self.assertEqual(self.app.check_tx(signed(self.genesis,self.agent,1,grant_id='worker'))['code'],1)

    def test_replicated_state_deterministic(self):
        other=BlockApplication(':memory:')
        try:
            other.init_chain(self.genesis['chain_id'],self.genesis)
            a=self.block()
            b=other.finalize_block([self.tx],1,hashlib.sha256(b'1').digest());other.commit()
            self.assertEqual(a,b)
            self.assertEqual(self.app.query('/state')['value'],other.query('/state')['value'])
        finally:other.close()

    def test_store_tamper_detected(self):
        self.app.close()
        c=sqlite3.connect(self.path)
        c.execute("UPDATE committed SET app_hash=?",('0'*64,));c.commit();c.close()
        with self.assertRaises(Reject):BlockApplication(self.path)

    def test_second_process_cannot_own_store(self):
        code='from block_application import BlockApplication; import sys; BlockApplication(sys.argv[1])'
        result=subprocess.run([sys.executable,'-c',code,str(self.path)],capture_output=True,text=True)
        self.assertNotEqual(result.returncode,0)
        self.assertIn('already in use',result.stderr)

    def _kill_case(self, fault, expected_height):
        self.app.close()
        code='''
import json,sys
from block_application import BlockApplication
app=BlockApplication(sys.argv[1])
app.finalize_block([bytes.fromhex(sys.argv[2])],1,b'x'*32)
app.commit(fault=sys.argv[3])
'''
        result=subprocess.run([sys.executable,'-c',code,str(self.path),self.tx.hex(),fault])
        self.assertEqual(result.returncode,91 if fault=='exit_after_state' else 92)
        self.app=BlockApplication(self.path,expected_genesis=self.genesis)
        self.assertEqual(self.app.height,expected_height)
        self.assertEqual(self.app.check_tx(self.tx)['code'],int(expected_height>0))

    def test_process_exit_inside_commit_does_not_partial_commit(self):
        self._kill_case('exit_after_state',0)

    def test_process_exit_after_commit_recovers_new_height(self):
        self._kill_case('exit_after_commit',1)

if __name__=='__main__':unittest.main()
