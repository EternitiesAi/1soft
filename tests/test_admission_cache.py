"""Admission-local reuse and bounded proposal selection; no validator simulation."""
import copy
from concurrent.futures import ThreadPoolExecutor
import hashlib
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from admission_cache import AdmissionCache, AdmissionLimits
from block_application import BlockApplication, MAX_BLOCK_BYTES
from execution_snapshot import ExecutionSnapshotFault
from native_core import NativeLedger, Reject, canonical, public, sign, accept_account_key
from test_execution_snapshot import raw
from test_native_budgets import KEYS, IDS, genesis
from test_budget_integration import setup_transactions, payment

class CacheTests(unittest.TestCase):
    def setUp(self):
        self.c = AdmissionCache(AdmissionLimits(3, 150, 100))
        self.c.bind('1'*64,0,'2'*64)
    def answer(self,text='bad'):return {'code':1,'log':text,'data':''}
    def test_exact_key_and_copy_of_result(self):
        self.c.put(b'tx',self.answer());a=self.c.get(b'tx');a['code']=0
        self.assertEqual(self.c.get(b'tx'),self.answer())
    def test_empty_bytes_key_not_miss(self):
        self.c.put(b'',self.answer());self.assertIsNotNone(self.c.get(b''))
    def test_different_signature_bytes_are_different_keys(self):
        self.c.put(b'body-sigA',self.answer());self.assertIsNone(self.c.get(b'body-sigB'))
    def test_exact_same_checkpoint_preserves_entries(self):
        self.c.put(b'x',self.answer());self.c.bind('1'*64,0,'2'*64);self.assertIsNotNone(self.c.get(b'x'))
    def test_every_checkpoint_dimension_invalidates(self):
        for point in (('1'*64,1,'2'*64),('3'*64,0,'2'*64),('1'*64,0,'4'*64)):
            self.c.bind('1'*64,0,'2'*64);self.c.put(b'x',self.answer())
            self.c.bind(*point);self.assertIsNone(self.c.get(b'x'))
    def test_count_ceiling_and_lru(self):
        for b in (b'a',b'b',b'c'):self.c.put(b,self.answer())
        self.c.get(b'a');self.c.put(b'd',self.answer())
        self.assertIsNone(self.c.get(b'b'));self.assertIsNotNone(self.c.get(b'a'))
        self.assertEqual(self.c.stats()['entries'],3)
    def test_payload_byte_bound(self):
        for i in range(10):self.c.put(bytes([i])*60,self.answer())
        self.assertLessEqual(self.c.stats()['retained_payload_bytes'],150)
        self.assertEqual(self.c.stats()['entries'],2)
    def test_per_entry_skip_keeps_existing(self):
        self.c.put(b'a',self.answer());self.c.put(b'x'*101,self.answer())
        self.assertIsNotNone(self.c.get(b'a'));self.assertEqual(self.c.stats()['oversize_not_cached'],1)
    def test_overall_byte_limit_smaller_than_entry_limit(self):
        c=AdmissionCache(AdmissionLimits(10,10,100));c.bind('1'*64,0,'2'*64)
        c.put(b'x'*11,self.answer());self.assertEqual(c.stats()['entries'],0)
    def test_replacement_adjusts_weight(self):
        self.c.put(b'a',self.answer());n=self.c.stats()['retained_payload_bytes']
        self.c.put(b'a',self.answer());self.assertEqual(n,self.c.stats()['retained_payload_bytes'])
    def test_clear_requires_explicit_new_checkpoint(self):
        self.c.put(b'a',self.answer());self.c.clear()
        self.assertEqual(self.c.stats()['retained_payload_bytes'],0)
        with self.assertRaises(RuntimeError):self.c.get(b'a')
    def test_bad_limits_refused(self):
        for kw in ({'max_entries':True},{'max_entries':0},{'max_entries':4097},
                   {'max_payload_bytes':0},{'max_entry_bytes':None}):
            with self.subTest(kw=kw),self.assertRaises(ValueError):AdmissionLimits(**kw)
    def test_invalid_results_not_retained(self):
        for answer in ({'code':True,'log':'','data':''},{'code':2,'log':'','data':''},
                       {'code':0,'log':'','data':'wrong'},{'code':1,'log':'','data':'extra'},
                       {'code':1,'log':'bad','data':'','extra':1}):
            with self.subTest(answer=answer),self.assertRaises(ValueError):self.c.put(b'a',answer)
        self.assertEqual(self.c.stats()['entries'],0)
    def test_invalid_checkpoint_refused(self):
        for p in (('1'*64,True,'2'*64),('1'*64,-1,'2'*64),('bad',1,'2'*64)):
            with self.assertRaises(ValueError):self.c.bind(*p)
    def test_accounting_under_thousands_of_distinct_inputs(self):
        for i in range(2000):
            self.c.put(i.to_bytes(4,'big'),self.answer('x'*(i%90)))
            self.assertLessEqual(self.c.stats()['entries'],3)
            self.assertLessEqual(self.c.stats()['retained_payload_bytes'],150)
    def test_success_and_negative_outcomes_not_mixed(self):
        good={'code':0,'log':'','data':'a'*64};self.c.put(b'valid',good);self.c.put(b'bad',self.answer())
        self.assertEqual(self.c.get(b'valid'),good);self.assertEqual(self.c.get(b'bad'),self.answer())

class AdmissionIntegrationTests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory();self.path=Path(self.tmp.name)/'state.sqlite'
        self.g=genesis();self.app=BlockApplication(self.path)
        self.app.init_chain(self.g['chain_id'],self.g)
    def tearDown(self):self.app.close();self.tmp.cleanup()
    def block(self,txs):
        self.app.finalize_block(txs,self.app.height+1,hashlib.sha256(str(self.app.height).encode()).digest())
        self.app.commit()
    def test_repeat_reuses_completed_validation_no_extra_database_copy(self):
        tx=raw(self.g)
        with patch.object(self.app,'_copy',wraps=self.app._copy) as copies:
            a=self.app.check_tx(tx);b=self.app.check_tx(tx)
        self.assertEqual(a,b);self.assertEqual(copies.call_count,1)
        self.assertEqual(self.app.admission_stats()['hits'],1)
    def test_invalid_signature_never_inherits_valid_body_acceptance(self):
        tx=raw(self.g);self.assertEqual(self.app.check_tx(tx)['code'],0)
        wrong=raw(self.g,key=KEYS[1])
        self.assertEqual(self.app.check_tx(wrong)['code'],1)
        self.assertEqual(self.app.check_tx(wrong)['code'],1)
    def test_syntax_junk_rejected_before_execution_fork(self):
        for tx in (b'',b'{',b'[]',b'{"body":{},"body":{}}',b' '):
            with self.subTest(tx=tx),patch.object(self.app,'_copy',side_effect=AssertionError('unneeded fork')):
                self.assertEqual(self.app.check_tx(tx)['code'],1)
    def test_oversized_transaction_not_cached(self):
        self.assertEqual(self.app.check_tx(b'x'*16385)['code'],1)
        self.assertEqual(self.app.admission_stats()['entries'],0)
    def test_uninitialized_result_does_not_poison_post_init(self):
        app=BlockApplication(':memory:')
        try:
            self.assertEqual(app.check_tx(raw(self.g))['code'],1)
            app.init_chain(self.g['chain_id'],self.g)
            self.assertEqual(app.check_tx(raw(self.g))['code'],0)
        finally:app.close()
    def test_same_tx_after_commit_is_rejected_not_cached_acceptance(self):
        tx=raw(self.g);self.assertEqual(self.app.check_tx(tx)['code'],0);self.block([tx])
        self.assertEqual(self.app.admission_stats()['entries'],0)
        self.assertEqual(self.app.check_tx(tx)['code'],1)
    def test_negative_nonce_answer_invalidated_by_commit(self):
        next_tx=raw(self.g,1)
        self.assertEqual(self.app.check_tx(next_tx)['code'],1)
        self.block([raw(self.g)])
        self.assertEqual(self.app.check_tx(next_tx)['code'],0)
    def test_empty_block_invalidates_height_sensitive_answer(self):
        tx=raw(self.g,until=1);self.assertEqual(self.app.check_tx(tx)['code'],0)
        before=copy.deepcopy(self.app.native);self.block([]);self.assertEqual(self.app.native,before)
        self.assertEqual(self.app.check_tx(tx)['code'],1)
    def test_pending_state_never_invalidates_or_replaces_committed_answer(self):
        tx=raw(self.g);a=self.app.check_tx(tx)
        self.app.finalize_block([tx],1,b'0'*32)
        self.assertEqual(a,self.app.check_tx(tx));self.assertEqual(self.app.height,0)
    def test_rolled_back_commit_keeps_old_answer(self):
        tx=raw(self.g);a=self.app.check_tx(tx);self.app.finalize_block([tx],1,b'0'*32)
        with self.assertRaises(RuntimeError):self.app.commit(fault='before_commit')
        self.assertEqual(a,self.app.check_tx(tx));self.app.commit()
        self.assertEqual(self.app.check_tx(tx)['code'],1)
    def test_shared_budget_commit_invalidates_previous_admission(self):
        self.block(setup_transactions(self.g));t=payment(self.g,1,39)
        self.assertEqual(self.app.check_tx(t)['code'],0);self.block([payment(self.g,0,58)])
        self.assertEqual(self.app.check_tx(t)['code'],1)
    def test_peer_proposal_does_not_reuse_individually_valid_admission(self):
        self.block(setup_transactions(self.g));a,b=payment(self.g,0,58),payment(self.g,1,39)
        self.assertEqual(self.app.check_tx(a)['code'],0);self.assertEqual(self.app.check_tx(b)['code'],0)
        self.assertFalse(self.app.process_proposal([a,b],2))
        self.assertEqual(self.app.prepare_proposal([a,b],2,MAX_BLOCK_BYTES),[a])
        self.assertEqual(self.app.finalize_block([a,b],2,b'x'*32)['tx_results'][1]['code'],1)
    def test_revocation_invalidates_old_agent_result(self):
        self.block(setup_transactions(self.g));tx=payment(self.g,0,10)
        self.assertEqual(self.app.check_tx(tx)['code'],0)
        op={'type':'fence'};self.block([raw(self.g,3,op=op)])
        self.assertEqual(self.app.check_tx(tx)['code'],1)
    def test_owner_key_rotation_invalidates_old_key_result(self):
        tx=raw(self.g,1);self.assertEqual(self.app.check_tx(tx)['code'],1)
        maker=NativeLedger(':memory:',self.g)
        body=maker.body(IDS[0],0,{'type':'rotate_key','public_key':public(KEYS[5]),'acceptance':''});maker.close()
        self.block([canonical(sign(KEYS[0],accept_account_key(KEYS[5],body)))])
        self.assertEqual(self.app.check_tx(tx)['code'],1)
        self.assertEqual(self.app.check_tx(raw(self.g,1,key=KEYS[5]))['code'],0)
    def test_mutated_return_dictionary_cannot_poison_cache(self):
        tx=raw(self.g);a=self.app.check_tx(tx);a['data']='tampered'
        self.assertNotEqual(self.app.check_tx(tx)['data'],'tampered')
    def test_image_fault_cannot_hide_behind_cached_hit(self):
        tx=raw(self.g);self.app.check_tx(tx);image=self.app._execution;self.app._execution=None
        try:
            with self.assertRaises(ExecutionSnapshotFault):self.app.check_tx(tx)
        finally:self.app._execution=image
    def test_internal_failure_not_cached(self):
        tx=raw(self.g)
        with patch.object(self.app,'_copy',side_effect=RuntimeError('fault')):
            with self.assertRaises(RuntimeError):self.app.check_tx(tx)
        self.assertEqual(self.app.admission_stats()['entries'],0)
        self.assertEqual(self.app.check_tx(tx)['code'],0)
    def test_process_restart_discards_memo_not_ledger(self):
        tx=raw(self.g);self.app.check_tx(tx);self.app.close()
        self.app=BlockApplication(self.path)
        self.assertEqual(self.app.admission_stats()['entries'],0)
        self.assertEqual(self.app.check_tx(tx)['code'],0)
    def test_cross_thread_repeat_is_one_validation(self):
        tx=raw(self.g)
        with patch.object(self.app,'_copy',wraps=self.app._copy) as copies,ThreadPoolExecutor(8) as pool:
            results=list(pool.map(lambda _:self.app.check_tx(tx),range(32)))
        self.assertTrue(all(r==results[0] for r in results));self.assertEqual(copies.call_count,1)
    def test_peer_calls_cannot_configure_cache(self):
        for value in (1,'yes',None):
            with self.assertRaises(Reject):BlockApplication(':memory:',admission_cache=value)
        with self.assertRaises(ValueError):BlockApplication(':memory:',admission_cache=False,admission_limits=AdmissionLimits())
    def test_cache_disabled_reference_always_executes(self):
        app=BlockApplication(':memory:',admission_cache=False)
        try:
            app.init_chain(self.g['chain_id'],self.g)
            with patch.object(app,'_copy',wraps=app._copy) as copies:
                self.assertEqual(app.check_tx(raw(self.g)),app.check_tx(raw(self.g)))
            self.assertEqual(copies.call_count,2)
        finally:app.close()
    def test_protocol_and_proof_results_identical_with_and_without_admission_reuse(self):
        for version,smt in ((1,False),(2,False),(3,False),(3,True)):
            g=genesis(version)
            if smt:g['state_commitment']='smt-v1'
            fast=BlockApplication(':memory:');ref=BlockApplication(':memory:',admission_cache=False)
            try:
                for app in (fast,ref):app.init_chain(g['chain_id'],g)
                for height,txs in enumerate(([raw(g,0)],[],[raw(g,1),raw(g,1,7)],[raw(g,2)]),1):
                    for tx in txs:
                        for _ in range(2):self.assertEqual(fast.check_tx(tx),ref.check_tx(tx))
                    self.assertEqual(fast.prepare_proposal(txs,height,MAX_BLOCK_BYTES),ref.prepare_proposal(txs,height,MAX_BLOCK_BYTES))
                    self.assertEqual(fast.process_proposal(txs,height),ref.process_proposal(txs,height))
                    self.assertEqual(fast.finalize_block(txs,height,b'h'*32),ref.finalize_block(txs,height,b'h'*32))
                    self.assertEqual(fast.commit(),ref.commit());self.assertEqual(fast.query('/state'),ref.query('/state'))
                    if smt:self.assertEqual(fast.compact_witness([('accounts',IDS[0])]),ref.compact_witness([('accounts',IDS[0])]))
            finally:fast.close();ref.close()
    def test_proposer_scans_bounded_candidates_but_peer_block_remains_valid(self):
        tx=raw(self.g);candidates=[b'{']*1024+[tx]
        with patch.object(self.app,'_apply',wraps=self.app._apply) as calls:
            self.assertEqual(self.app.prepare_proposal(candidates,1,MAX_BLOCK_BYTES),[])
        self.assertEqual(calls.call_count,1024)
        self.assertTrue(self.app.process_proposal([tx],1))
    def test_proposer_input_byte_budget_not_consensus_rejection(self):
        tx=raw(self.g)
        with patch('block_application.MAX_PROPOSAL_INSPECT_BYTES',len(tx)-1):
            self.assertEqual(self.app.prepare_proposal([tx],1,MAX_BLOCK_BYTES),[])
            self.assertTrue(self.app.process_proposal([tx],1))
    def test_list_required_to_avoid_unbounded_candidate_generator(self):
        with self.assertRaises(Reject):self.app.prepare_proposal(iter([raw(self.g)]),1,MAX_BLOCK_BYTES)

if __name__=='__main__':unittest.main()
