"""Persistent-index algorithm tests against the unmodified reference tree."""
import copy
import json
import random
import sqlite3
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from state_tree import (COLUMNS, EMPTY, StateTree, ProofError, bind_root, encoded,
                        hash32, make_witness, path_hash, verify_proof)
from state_index import StateIndex, location

GENESIS = {'protocol_version':3,'state_commitment':'smt-v1','chain_id':'index-algorithm-fixture',
           'asset':'DEV','fee':2,'allocations':[{'public_key':'01'*32,'units':1}]}
GH = hash32(encoded(GENESIS)).hex()


def state(count=0):
    result = {table:[] for table in COLUMNS}
    result['meta'] = [[f'key-{i}', str(i)] for i in range(count)]
    return result


def app_hash(s, height=0):
    return bind_root(GH,height,StateTree(s).root)


class IndexTests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory();self.path=Path(self.tmp.name)/'index.sqlite'
        self.db=sqlite3.connect(self.path,isolation_level=None)
        self.db.execute('PRAGMA journal_mode=WAL');self.db.execute('PRAGMA synchronous=FULL')
        self.index=StateIndex(self.db);self.s=state();self.h=0
    def tearDown(self):self.db.close();self.tmp.cleanup()
    def initialize(self,s=None):
        self.s=state() if s is None else copy.deepcopy(s)
        self.db.execute('BEGIN IMMEDIATE')
        self.index.initialize(GH,0,self.s,app_hash(self.s));self.db.execute('COMMIT')
    def advance(self,s):
        self.db.execute('BEGIN IMMEDIATE')
        work=self.index.advance(GH,self.h,app_hash(self.s,self.h),self.h+1,self.s,s,app_hash(s,self.h+1))
        self.db.execute('COMMIT');self.h+=1;self.s=copy.deepcopy(s)
        return work
    def witness(self,queries):return self.index.witness(GENESIS,self.h,app_hash(self.s,self.h),queries)
    def assert_proofs(self,queries):
        self.assertEqual(self.witness(queries),make_witness(GENESIS,self.h,self.s,queries))
    def test_empty_map_proves_absence(self):
        self.initialize();self.assert_proofs([('meta','absent')]);self.assertEqual(self.index.audit(GH,0,app_hash(self.s))['nodes'],0)
    def test_single_leaf_membership_and_absence(self):
        self.initialize(state(1));self.assert_proofs([('meta','key-0'),('meta','else'),('accounts','key-0')])
        self.assertEqual(self.index.audit(GH,0,app_hash(self.s))['nodes'],1)
    def test_many_leaves_identical_proof_bytes(self):
        self.initialize(state(257));self.assert_proofs([('meta',f'key-{i}') for i in range(15)]+[('meta','absent')])
        self.assertEqual(self.index.audit(GH,0,app_hash(self.s))['nodes'],513)
    def test_insertion_order_independent(self):
        s=state(33);random.Random(91).shuffle(s['meta']);self.initialize(s)
        self.assert_proofs([('meta','key-2'),('meta','missing')])
    def test_randomized_insert_update_delete_batches(self):
        self.initialize();rng=random.Random(14);values={}
        for _ in range(80):
            for __ in range(1+rng.randrange(5)):
                key=f'key-{rng.randrange(48)}'
                if rng.randrange(3)==0:values.pop(key,None)
                else:values[key]=str(rng.randrange(10000))
            s=state();s['meta']=[list(item) for item in sorted(values.items())]
            self.advance(s)
            self.assert_proofs([('meta',f'key-{rng.randrange(50)}')])
            self.assertEqual(self.index.audit(GH,self.h,app_hash(self.s,self.h))['records'],len(values))
    def test_delete_all_leaves_collapses_branches(self):
        self.initialize(state(17))
        for i in range(17,0,-1):
            self.advance(state(i-1));self.assert_proofs([('meta','key-0'),('meta','missing')])
        self.assertEqual(self.db.execute('SELECT count(*) FROM proof_nodes').fetchone()[0],0)
    def test_changed_leaf_updates_ancestors_not_every_row(self):
        self.initialize(state(1024));s=copy.deepcopy(self.s);s['meta'][400][1]='replacement'
        work=self.advance(s)
        self.assertEqual(work.changed_records,1);self.assertLess(work.writes,30)
        self.assert_proofs([('meta','key-400')])
    def test_empty_block_no_node_rewrites_but_new_height_binding(self):
        self.initialize(state(33));before=self.index.checkpoint();work=self.advance(self.s)
        after=self.index.checkpoint();self.assertEqual(work.writes,0);self.assertEqual(work.deletes,0)
        self.assertEqual(before['root'],after['root']);self.assertNotEqual(before['app_hash'],after['app_hash'])
    def test_initialize_requires_explicit_transaction(self):
        with self.assertRaises(ProofError):self.index.initialize(GH,0,state(),app_hash(state()))
        self.assertIsNone(self.index.checkpoint())
    def test_update_requires_explicit_transaction(self):
        self.initialize()
        with self.assertRaises(ProofError):self.index.advance(GH,0,app_hash(self.s),1,self.s,state(1),app_hash(state(1),1))
    def test_caller_can_roll_back_successful_index_update(self):
        self.initialize(state(3));old=self.index.checkpoint();self.db.execute('BEGIN IMMEDIATE')
        self.index.advance(GH,0,app_hash(self.s),1,self.s,state(5),app_hash(state(5),1));self.db.execute('ROLLBACK')
        self.assertEqual(self.index.checkpoint(),old);self.assert_proofs([('meta','key-4')])
    def test_bad_expected_root_rolls_back_savepoint_without_committing_caller(self):
        self.initialize(state(3));self.db.execute('CREATE TABLE unrelated(value INTEGER)')
        self.db.execute('BEGIN IMMEDIATE');self.db.execute('INSERT INTO unrelated VALUES (7)')
        with self.assertRaises(ProofError):self.index.advance(GH,0,app_hash(self.s),1,self.s,state(4),'00'*32)
        self.assertTrue(self.db.in_transaction);self.assertEqual(self.index.checkpoint()['height'],0)
        self.assertEqual(self.db.execute('SELECT * FROM unrelated').fetchall(),[(7,)])
        self.db.execute('ROLLBACK');self.assertEqual(self.db.execute('SELECT * FROM unrelated').fetchall(),[])
    def test_previous_value_must_match_index(self):
        self.initialize(state(2));wrong=state(2);wrong['meta'][0][1]='forged'
        self.db.execute('BEGIN IMMEDIATE')
        with self.assertRaisesRegex(ProofError,'delta does not start'):
            self.index.advance(GH,0,app_hash(self.s),1,wrong,state(3),app_hash(state(3),1))
        self.db.execute('ROLLBACK');self.assert_proofs([('meta','key-0')])
    def test_height_skip_rejected(self):
        self.initialize();self.db.execute('BEGIN IMMEDIATE')
        with self.assertRaises(ProofError):self.index.advance(GH,0,app_hash(self.s),2,self.s,self.s,app_hash(self.s,2))
        self.db.execute('ROLLBACK')
    def test_wrong_genesis_rejected(self):
        self.initialize()
        with self.assertRaises(ProofError):self.index.assert_checkpoint('ff'*32,0,app_hash(self.s))
    def test_double_initialize_does_not_reset(self):
        self.initialize(state(2));self.db.execute('BEGIN IMMEDIATE')
        with self.assertRaises(ProofError):self.index.initialize(GH,0,state(),app_hash(state()))
        self.db.execute('ROLLBACK');self.assert_proofs([('meta','key-1')])
    def test_duplicate_snapshot_key_rejected(self):
        s=state(2);s['meta'].append(s['meta'][0]);self.db.execute('BEGIN IMMEDIATE')
        with self.assertRaises(ProofError):self.index.initialize(GH,0,s,'00'*32)
        self.db.execute('ROLLBACK');self.assertIsNone(self.index.checkpoint())
    def test_invalid_snapshot_shapes_rejected(self):
        for bad in ({}, {'meta':[]}, {**state(),'meta':False}, {**state(),'meta':[[True,1]]}):
            with self.subTest(snapshot=bad),self.assertRaises(ProofError):self.index.rows(bad)
    def test_row_limit_rejected(self):
        with patch('state_index.MAX_ROWS',2),self.assertRaises(ProofError):self.index.rows(state(3))
    def test_orphan_index_nodes_not_silently_rebuilt(self):
        self.initialize(state(1));self.db.execute('DELETE FROM proof_checkpoint');self.db.execute('BEGIN IMMEDIATE')
        with self.assertRaisesRegex(ProofError,'orphaned'):self.index.initialize(GH,0,self.s,app_hash(self.s))
        self.db.execute('ROLLBACK')
    def test_corrupt_leaf_refused_on_proof(self):
        self.initialize(state(1));self.db.execute('UPDATE proof_nodes SET value=?',(b'["key-0","altered"]',))
        with self.assertRaises(ProofError):self.witness([('meta','key-0')])
    def test_corrupt_branch_refused_on_proof(self):
        self.initialize(state(4));self.db.execute('UPDATE proof_nodes SET root=? WHERE depth<256',(bytes(32),))
        with self.assertRaises(ProofError):self.witness([('meta','key-0')])
    def test_missing_child_refused(self):
        self.initialize(state(4));ref=self.db.execute('SELECT location FROM proof_nodes WHERE depth=256 LIMIT 1').fetchone()[0]
        self.db.execute('DELETE FROM proof_nodes WHERE location=?',(ref,))
        with self.assertRaises(ProofError):self.index.audit(GH,0,app_hash(self.s))
    def test_same_child_twice_refused(self):
        self.initialize(state(4));self.db.execute('UPDATE proof_nodes SET right_ref=left_ref WHERE depth<256')
        with self.assertRaises(ProofError):self.index.audit(GH,0,app_hash(self.s))
    def test_reopening_index_uses_persisted_nodes(self):
        self.initialize(state(8));before=self.witness([('meta','key-2')]);self.db.close()
        self.db=sqlite3.connect(self.path,isolation_level=None);self.index=StateIndex(self.db)
        self.assertEqual(self.witness([('meta','key-2')]),before)
    def test_proofs_perform_no_database_writes(self):
        self.initialize(state(32));before=self.db.total_changes;self.witness([('meta','key-2'),('meta','absent')])
        self.assertEqual(self.db.total_changes,before);self.assertEqual(self.index.work.writes,0)
    def test_unknown_schema_refused(self):
        self.initialize();self.db.execute('UPDATE proof_checkpoint SET schema_version=99')
        with self.assertRaises(ProofError):self.index.checkpoint()
    def test_invalid_query_sets_refused(self):
        self.initialize(state(3))
        for q in ([],[('meta','key-0')]*2,[('evil','x')],['meta'],[('meta',str(i)) for i in range(17)]):
            with self.subTest(q=q),self.assertRaises(ProofError):self.witness(q)
    def test_path_collision_never_overwrites_record(self):
        self.initialize(state(1));fake=path_hash('meta','key-0');s=state(1);s['meta'].append(['other','2'])
        self.db.execute('BEGIN IMMEDIATE')
        with patch('state_index.path_hash',return_value=fake),self.assertRaises(ProofError):
            self.index.advance(GH,0,app_hash(self.s),1,self.s,s,app_hash(s,1))
        self.db.execute('ROLLBACK');self.assert_proofs([('meta','key-0')])
    def test_noncanonical_path_location_rejected(self):
        with self.assertRaises(ProofError):location(0,1)
        with self.assertRaises(ProofError):location(True,0)
    def test_multi_table_membership_and_absence(self):
        s=state(1);s['accounts']=[['account','01'*32,0,0,25]]
        s['grant_budgets']=[['account::grant','account::budget']]
        self.initialize(s);self.assert_proofs([('accounts','account'),('meta','account'),('grant_budgets','account::grant')])


if __name__=='__main__':unittest.main()
