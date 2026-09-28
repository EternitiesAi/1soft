"""Bound local metadata without changing native state, receipts or trust.

Actual local SQLite/process/socket tests; signed headers are fixture attestations.
No CometBFT engine, public endpoint, value-bearing network or real funds.
"""
from __future__ import annotations

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

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from block_application import BlockApplication, restore, encode
from block_history import BlockHistory, validate_keep
from native_core import NativeLedger, Reject, address, canonical, public, sign
from state_sync import OFFER_ABORT, OFFER_ACCEPT, APPLY_ACCEPT

ROOT = Path(__file__).resolve().parents[1]


def fixture(version=3, smt=False):
    owner = Ed25519PrivateKey.from_private_bytes(bytes([91]) * 32)
    recipient = Ed25519PrivateKey.from_private_bytes(bytes([92]) * 32)
    g = {'chain_id': '1soft-local-history', 'asset': 'DEV', 'fee': 2,
         'allocations': [{'public_key': public(owner), 'units': 10000},
                         {'public_key': public(recipient), 'units': 0}]}
    if version != 1:
        g['protocol_version'] = version
    if smt:
        g['state_commitment'] = 'smt-v1'
    return g, owner, address(public(owner)), address(public(recipient))


def transfer(g, owner, sender, recipient, nonce=0, units=10):
    db = NativeLedger(':memory:', g)
    try:
        return canonical(sign(owner, db.body(sender, nonce,
            {'type': 'transfer', 'to': recipient, 'units': units}, valid_until=10000)))
    finally:
        db.close()


def commit(app, txs=(), fault=''):
    h = app.height + 1
    result = app.finalize_block(list(txs), h, hashlib.sha256(str(h).encode()).digest())
    app.commit(fault=fault)
    return result


def history(app):
    q = app.query('/history')
    if q['code']:
        raise AssertionError(q['log'])
    return json.loads(q['value'])


def install(source, target):
    desc = source.list_snapshots()[0]
    assert target.offer_snapshot(desc, bytes.fromhex(source.app_hash)) == OFFER_ACCEPT
    for i in range(desc['chunks']):
        out = target.apply_snapshot_chunk(i, source.load_snapshot_chunk(desc['height'], 1, i), 'fixture-peer')
        assert out['result'] == APPLY_ACCEPT


class HistoryTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(); self.root = Path(self.tmp.name)
        self.g, self.owner, self.sender, self.recipient = fixture()
        self.apps = []
    def tearDown(self):
        for app in self.apps:
            app.close()
        self.tmp.cleanup()
    def app(self, keep=None, *, path=':memory:', genesis=None, init=True):
        g = self.g if genesis is None else genesis
        app = BlockApplication(path, expected_genesis=g, block_history_keep=keep)
        self.apps.append(app)
        if init and app.genesis is None:
            app.init_chain(g['chain_id'], g)
        return app
    def tx(self, nonce=0):
        return transfer(self.g, self.owner, self.sender, self.recipient, nonce)
    def advance(self, app, n):
        for _ in range(n): commit(app)

    def test_default_retains_all_and_creates_no_policy_table(self):
        a = self.app(); self.advance(a, 12)
        self.assertEqual(history(a)['availability']['retained_count'], 12)
        self.assertIsNone(a.db.execute("SELECT name FROM sqlite_master WHERE name='block_history_policy'").fetchone())
    def test_window_is_bounded_on_successful_commits(self):
        a = self.app(3); self.advance(a, 20)
        self.assertEqual(history(a)['availability'], {'keep_blocks': 3, 'bootstrap_height': 0,
            'pruned_through': 17, 'retained_from': 18, 'retained_through': 20,
            'retained_count': 3, 'within_configured_window': True})
    def test_current_and_previous_block_remain_queryable(self):
        a = self.app(2); self.advance(a, 8)
        self.assertEqual(a.query('/block/8')['code'], 0)
        self.assertEqual(a.query('/block/7')['code'], 0)
        self.assertEqual(a.query('/block/6')['code'], 2)
    def test_pruned_query_explicitly_denies_transaction_absence_inference(self):
        a = self.app(2); self.advance(a, 7)
        q = a.query('/block/1'); self.assertEqual(q['code'], 2)
        self.assertEqual(json.loads(q['value']), {'schema': 1, 'status': 'pruned_local_block_results',
            'requested_height': 1, 'historical_transaction_absence_proven': False})
    def test_uncommitted_future_height_is_not_labelled_pruned(self):
        a = self.app(2); self.advance(a, 7)
        q = a.query('/block/8'); self.assertEqual(q['code'], 1)
        self.assertEqual(q['log'], 'block not committed')
    def test_invalid_retention_values_fail_before_creating_store(self):
        for keep in (True, False, 0, 1, -2, 2.0, '3', 1000001):
            with self.subTest(keep=keep):
                path = self.root / 'must-not-exist.sqlite'
                with self.assertRaises(ValueError): self.app(keep, path=path)
                self.assertFalse(path.exists()); self.assertFalse(Path(str(path)+'.lock').exists())
    def test_policy_persists_when_reopen_omits_flag(self):
        p = self.root/'node.sqlite'; a = self.app(3, path=p); self.advance(a, 9); a.close()
        b = self.app(path=p); self.advance(b, 4)
        self.assertEqual(history(b)['availability']['keep_blocks'], 3)
        self.assertEqual(history(b)['availability']['retained_count'], 3)
    def test_different_explicit_policy_is_refused_without_changing_records(self):
        p = self.root/'node.sqlite'; a = self.app(3, path=p); self.advance(a, 9)
        rows = list(a.db.iterdump()); a.close()
        with self.assertRaisesRegex(ValueError, 'policy differs'): self.app(4, path=p)
        db = sqlite3.connect(p)
        try: self.assertEqual(list(db.iterdump()), rows)
        finally: db.close()
    def test_enabling_on_old_complete_store_prunes_only_on_next_commit(self):
        p = self.root/'node.sqlite'; a = self.app(path=p); self.advance(a, 10); before = a.app_hash; a.close()
        b = self.app(3, path=p)
        self.assertEqual(b.app_hash, before)
        self.assertEqual(history(b)['availability']['retained_count'], 10)
        self.assertFalse(history(b)['availability']['within_configured_window'])
        commit(b); self.assertEqual(history(b)['availability']['retained_count'], 3)
    def test_enrollment_refuses_unexplained_old_gaps(self):
        p = self.root/'node.sqlite'; a = self.app(path=p); self.advance(a, 9)
        a.db.execute('DELETE FROM blocks WHERE height=3'); a.close()
        with self.assertRaisesRegex(ValueError, 'incomplete unexplained'): self.app(3, path=p)
    def test_startup_refuses_missing_policy_row(self):
        p = self.root/'node.sqlite'; a = self.app(3, path=p); self.advance(a, 9)
        a.db.execute('DELETE FROM block_history_policy'); a.close()
        with self.assertRaisesRegex(ValueError, 'missing or duplicate'): self.app(path=p)
    def test_startup_refuses_gap_inside_retained_window(self):
        p = self.root/'node.sqlite'; a = self.app(3, path=p); self.advance(a, 9)
        a.db.execute('DELETE FROM blocks WHERE height=8'); a.close()
        with self.assertRaisesRegex(ValueError, 'unexplained gap'): self.app(path=p)
    def test_startup_refuses_extra_old_row(self):
        p = self.root/'node.sqlite'; a = self.app(3, path=p)
        commit(a); old = a.db.execute('SELECT * FROM blocks WHERE height=1').fetchone()
        self.advance(a, 8); a.db.execute('INSERT INTO blocks VALUES (?,?,?,?,?)', old); a.close()
        with self.assertRaisesRegex(ValueError, 'unexplained gap'): self.app(path=p)
    def test_startup_refuses_policy_checkpoint_mismatch(self):
        p = self.root/'node.sqlite'; a = self.app(3, path=p); self.advance(a, 9)
        a.db.execute('UPDATE block_history_policy SET last_app_hash=?', ('a'*64,)); a.close()
        with self.assertRaisesRegex(ValueError, 'checkpoint differs'): self.app(path=p)
    def test_gap_cannot_be_hidden_by_next_prune(self):
        a = self.app(3); self.advance(a, 5); before = a.app_hash
        a.db.execute('DELETE FROM blocks WHERE height=3')
        with self.assertRaisesRegex(ValueError, 'gap before pruning'): commit(a)
        self.assertEqual(a.height, 5); self.assertEqual(a.app_hash, before)
        self.assertEqual(a.db.execute('SELECT height FROM committed').fetchone()[0], 5)
    def test_query_gap_inside_window_is_error_not_pruned(self):
        a = self.app(3); self.advance(a, 5); a.db.execute('DELETE FROM blocks WHERE height=4')
        q = a.query('/block/4'); self.assertEqual(q['code'], 1)
        self.assertNotIn('pruned_local_block_results', q['value'].decode())
    def test_pending_finalization_does_not_prune(self):
        a = self.app(3); self.advance(a, 5); before = history(a)
        a.finalize_block([], 6, b'f'*32)
        self.assertEqual(history(a), before); self.assertEqual(a.query('/block/3')['code'], 0)
    def test_failed_commit_rolls_back_pruning_policy_and_state(self):
        a = self.app(3); self.advance(a, 5); before = list(a.db.iterdump())
        with self.assertRaises(RuntimeError): commit(a, fault='before_commit')
        self.assertEqual(list(a.db.iterdump()), before); self.assertEqual(a.height, 5)
        a.commit(); self.assertEqual(a.height, 6)
        self.assertEqual(history(a)['availability']['pruned_through'], 3)
    def test_database_abort_during_pruning_rolls_back_everything(self):
        a = self.app(3); self.advance(a, 5)
        a.db.execute("CREATE TRIGGER stop_delete BEFORE DELETE ON blocks BEGIN SELECT RAISE(ABORT,'disk-fault-fixture'); END")
        before = list(a.db.iterdump())
        with self.assertRaises(sqlite3.IntegrityError): commit(a)
        self.assertEqual(list(a.db.iterdump()), before); self.assertEqual(a.height, 5)
    def test_commit_retry_is_noop(self):
        a = self.app(3); self.advance(a, 8); before = list(a.db.iterdump())
        a.commit(); a.commit(); self.assertEqual(list(a.db.iterdump()), before)
    def test_metadata_never_requests_cometbft_pruning(self):
        a = self.app(2); self.advance(a, 7); h = history(a)
        self.assertEqual(h['cometbft_retain_height'], 0)
        self.assertFalse(h['engine_history_pruning_requested'])
        self.assertFalse(h['total_storage_bounded'])
    def test_history_reads_leave_logical_state_unchanged(self):
        a = self.app(2); self.advance(a, 7); before = list(a.db.iterdump())
        for _ in range(5): history(a); a.query('/block/1')
        self.assertEqual(list(a.db.iterdump()), before)
    def test_transaction_receipt_survives_its_local_block_metadata(self):
        a = self.app(2); out = commit(a, [self.tx()]); txid = out['tx_results'][0]['data']
        receipt = a.query('/receipt/'+txid)['value']; self.advance(a, 8)
        self.assertEqual(a.query('/block/1')['code'], 2)
        self.assertEqual(a.query('/receipt/'+txid)['value'], receipt)
        self.assertEqual(history(a)['native_receipt_count'], 1)
        self.assertFalse(history(a)['native_receipts_pruned'])
    def test_old_signed_transaction_is_still_rejected_as_replay(self):
        a = self.app(2); raw = self.tx(); commit(a, [raw]); self.advance(a, 8)
        self.assertEqual(a.check_tx(raw)['code'], 1)
        self.assertEqual(a.check_tx(raw)['log'], 'transaction already executed')
    def test_reference_state_receipts_and_hashes_match_all_protocols(self):
        for version, smt in ((1,False), (2,False), (3,False), (3,True)):
            with self.subTest(version=version, smt=smt):
                g, key, payer, recipient = fixture(version, smt)
                a = self.app(3, genesis=g); b = self.app(genesis=g)
                for n in range(12):
                    raw = transfer(g, key, payer, recipient, n)
                    self.assertEqual(commit(a, [raw]), commit(b, [raw]))
                    self.assertEqual(a.app_hash, b.app_hash)
                    self.assertEqual(a.query('/state')['value'], b.query('/state')['value'])
                self.assertEqual(history(a)['availability']['retained_count'], 3)
                self.assertEqual(history(a)['native_receipt_count'], 12)
    def test_snapshots_byte_identical_under_different_retention(self):
        a = self.app(2); b = self.app()
        for n in range(7):
            txs = [self.tx(n)]
            commit(a, txs); commit(b, txs)
        da = a.list_snapshots()[0]; db = b.list_snapshots()[0]
        self.assertEqual(da, db)
        self.assertEqual(a.load_snapshot_chunk(7, 1, 0), b.load_snapshot_chunk(7, 1, 0))
    def test_smt_proofs_byte_identical_under_different_retention(self):
        g, key, payer, recipient = fixture(3, True); a = self.app(2, genesis=g); b = self.app(genesis=g)
        commit(a, [transfer(g,key,payer,recipient)]); commit(b, [transfer(g,key,payer,recipient)])
        self.advance(a, 6); self.advance(b, 6)
        self.assertEqual(a.compact_witness([('accounts',payer)]), b.compact_witness([('accounts',payer)]))
    def test_state_sync_retention_starts_after_bootstrap_marker(self):
        source = self.app(); self.advance(source, 6); target = self.app(2, init=False)
        install(source, target)
        self.assertEqual(history(target)['availability']['bootstrap_height'], 6)
        self.assertEqual(history(target)['availability']['retained_count'], 0)
        self.assertEqual(json.loads(target.query('/block/5')['value'])['status'], 'not_retained_by_state_sync')
        self.advance(target, 5)
        h = history(target)['availability']; self.assertEqual(h['retained_count'], 2)
        self.assertEqual(h['pruned_through'], 9)
        self.assertEqual(json.loads(target.query('/block/7')['value'])['status'], 'pruned_local_block_results')
        self.assertEqual(target.db.execute('SELECT height FROM state_sync_marker').fetchone()[0], 6)
    def test_state_sync_keeps_all_native_receipts_after_local_pruning(self):
        source = self.app(2)
        for n in range(8): commit(source, [self.tx(n)])
        target = self.app(2, init=False); install(source, target)
        self.assertEqual(target.native, source.native)
        self.assertEqual(history(target)['native_receipt_count'], 8)
        self.assertEqual(target.check_tx(self.tx())['code'], 1)
    def test_snapshot_target_can_choose_different_local_window(self):
        source = self.app(2); self.advance(source, 8); target = self.app(5, init=False)
        install(source, target); self.advance(target, 9)
        self.assertEqual(history(target)['availability']['keep_blocks'], 5)
        self.assertEqual(history(target)['availability']['retained_count'], 5)
    def test_bootstrap_marker_and_retention_survive_reopen(self):
        source = self.app(); self.advance(source, 6); p = self.root/'target.sqlite'
        target = self.app(2, path=p, init=False); install(source,target); self.advance(target,5)
        before = history(target); target.close(); reopened = self.app(path=p)
        self.assertEqual(history(reopened), before)
    def test_checkpoint_only_retry_retains_policy_and_can_advance_snapshot(self):
        source = self.app(); self.advance(source, 6); p = self.root/'target.sqlite'
        target = self.app(3, path=p, init=False); install(source,target); target.close()
        target = self.app(path=p); self.advance(source, 3); install(source,target)
        h = history(target)['availability']; self.assertEqual(h['bootstrap_height'], 9)
        self.assertEqual(h['keep_blocks'], 3); self.assertEqual(h['pruned_through'], 0)
        self.assertEqual(h['retained_count'], 0)
    def test_pruning_cannot_reopen_snapshot_only_recovery(self):
        source = self.app(); self.advance(source, 6); target = self.app(2, init=False)
        install(source,target); self.advance(target, 12); self.advance(source, 15)
        desc = source.list_snapshots()[0]
        self.assertEqual(target.offer_snapshot(desc, bytes.fromhex(source.app_hash)), OFFER_ABORT)
        self.assertEqual(history(target)['availability']['retained_count'], 2)
    def test_smt_bootstrap_restart_and_continued_execution(self):
        g,key,payer,recipient = fixture(3,True)
        source = self.app(2, genesis=g); commit(source,[transfer(g,key,payer,recipient)]); self.advance(source,5)
        p = self.root/'smt.sqlite'; target=self.app(2,path=p,genesis=g,init=False); install(source,target)
        target.close(); target=self.app(path=p,genesis=g)
        raw=transfer(g,key,payer,recipient,1); self.assertEqual(commit(source,[raw]),commit(target,[raw]))
        self.advance(source,5);self.advance(target,5)
        self.assertEqual(source.app_hash,target.app_hash)
        self.assertEqual(source.compact_witness([('accounts',payer)]), target.compact_witness([('accounts',payer)]))
    def test_snapshot_policy_update_failure_does_not_install_partial_state(self):
        source=self.app();self.advance(source,5);target=self.app(2,init=False)
        target.db.execute("CREATE TRIGGER stop_policy BEFORE UPDATE ON block_history_policy BEGIN SELECT RAISE(ABORT,'fail snapshot history'); END")
        desc=source.list_snapshots()[0]
        self.assertEqual(target.offer_snapshot(desc,bytes.fromhex(source.app_hash)),OFFER_ACCEPT)
        with self.assertRaises(sqlite3.IntegrityError): target.apply_snapshot_chunk(0,source.load_snapshot_chunk(5,1,0),'peer')
        self.assertIsNone(target.genesis);self.assertIsNone(target.db.execute('SELECT 1 FROM committed').fetchone())
        self.assertEqual(target.db.execute('SELECT last_height,last_app_hash FROM block_history_policy').fetchone(),(0,''))
    def test_unauthenticated_query_proof_flag_is_still_refused(self):
        a=self.app(2); self.assertEqual(a.query('/history',prove=True)['code'],1)
    def test_second_app_process_cannot_open_same_writing_store(self):
        p=self.root/'node.sqlite'; a=self.app(2,path=p)
        code="from block_application import BlockApplication\nimport sys\nBlockApplication(sys.argv[1],block_history_keep=2)"
        run=subprocess.run([sys.executable,'-c',code,str(p)],env={**os.environ,'PYTHONPATH':str(ROOT/'src')},capture_output=True,timeout=5)
        self.assertNotEqual(run.returncode,0)
    def test_abci_commit_still_returns_zero_retain_height(self):
        from abci_server import dispatch
        from abci_wire import Request
        a=self.app(2);self.advance(a,5)
        request= Request(); request.commit.SetInParent()
        result=dispatch(a,request)
        self.assertEqual(result.commit.retain_height,0)
    def test_no_block_retention_rules_in_native_snapshot(self):
        a=self.app(2);self.advance(a,5)
        self.assertNotIn('block_history_policy',a.query('/state')['value'].decode())
        self.assertNotIn('block_history_policy',a.load_snapshot_chunk(5,1,0).decode())
    def test_native_receipt_bytes_remain_committed_after_metadata_pruning(self):
        a=self.app(2);commit(a,[self.tx()]);self.advance(a,5)
        from block_application import application_hash
        tampered=copy.deepcopy(a.native);tampered['receipts']=[]
        self.assertNotEqual(application_hash(a.genesis,a.height,tampered),a.app_hash)

    def test_wallet_holds_and_recorded_spend_survive_pruning(self):
        # Use the existing original wallet/grant fixture, then reproduce its exact
        # genesis/setup block in a retention-enabled application. No second signer.
        import test_wallet_obligations as fixtures
        c = fixtures.ObligationTests(); c.setUp()
        try:
            setup = [canonical(json.loads(r[3])['envelope']) for r in c.app.native['receipts']]
            old_hash = c.app.app_hash; c.app.close()
            c.app = BlockApplication(':memory:', expected_genesis=c.g, block_history_keep=2)
            c.app.init_chain(c.g['chain_id'], c.g); commit(c.app, setup)
            self.assertEqual(c.app.app_hash, old_hash)
            signed = c.approve(); self.assertEqual(c.pending_units(), 60)
            for _ in range(8): c.advance(); c.sync()
            self.assertEqual(c.pending_units(), 60)
            self.assertEqual(c.app.query('/block/1')['code'], 2)
            c.advance([canonical(signed['result'])]); c.sync()
            self.assertEqual(c.pending_units(), 0)
            receipt_height=c.app.height
            for _ in range(7): c.advance(); c.sync()
            self.assertEqual(c.app.query('/block/'+str(receipt_height))['code'],2)
            self.assertEqual(c.pending_units(),0)
            self.assertEqual(c.app.native['budgets'][0][4],60)
            self.assertEqual(c.wallet.export(signed['decision_id'])['result'],signed['result'])
            self.assertEqual(c.wallet.pending()['decisions'][0]['status'],'recorded')
        finally:c.tearDown()


class HistoryCrashTests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory();self.root=Path(self.tmp.name)
        self.g,*_=fixture();self.path=self.root/'node.sqlite'
        a=BlockApplication(self.path,expected_genesis=self.g,block_history_keep=3)
        a.init_chain(self.g['chain_id'],self.g)
        for _ in range(6):commit(a)
        self.old=history(a);self.oldhash=a.app_hash;a.close()
        (self.root/'genesis.json').write_bytes(encode(self.g))
    def tearDown(self):self.tmp.cleanup()
    def run_child(self,when):
        code='''from pathlib import Path
import hashlib,json,os,sys
from block_application import BlockApplication
r=Path(sys.argv[1]);a=BlockApplication(r/'node.sqlite',expected_genesis=json.loads((r/'genesis.json').read_bytes()))
if sys.argv[2]=='after_delete':
 a.db.create_function('die',0,lambda:os._exit(27))
 a.db.execute("CREATE TEMP TRIGGER crash_before_frontier BEFORE UPDATE ON block_history_policy BEGIN SELECT die(); END")
a.finalize_block([],7,hashlib.sha256(b'7').digest())
a.commit(fault='exit_after_commit' if sys.argv[2]=='after_commit' else '')
'''
        return subprocess.run([sys.executable,'-c',code,str(self.root),when],env={**os.environ,'PYTHONPATH':str(ROOT/'src')},capture_output=True,timeout=8)
    def test_actual_exit_after_delete_before_commit_recovers_old_window(self):
        p=self.run_child('after_delete');self.assertEqual(p.returncode,27,p.stderr)
        a=BlockApplication(self.path,expected_genesis=self.g)
        try:
            self.assertEqual(history(a),self.old);self.assertEqual(a.app_hash,self.oldhash)
            commit(a);self.assertEqual(history(a)['availability']['pruned_through'],4)
        finally:a.close()
    def test_actual_exit_after_commit_recovers_new_window(self):
        p=self.run_child('after_commit');self.assertEqual(p.returncode,92,p.stderr)
        a=BlockApplication(self.path,expected_genesis=self.g)
        try:
            self.assertEqual(a.height,7);self.assertEqual(history(a)['availability']['pruned_through'],4)
            self.assertEqual(history(a)['availability']['retained_count'],3)
        finally:a.close()


if __name__=='__main__':unittest.main()
