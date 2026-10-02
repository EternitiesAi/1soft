"""Merkle map tests with a separate uncompressed recursive oracle. No validators."""
import copy
import hashlib
import json
import random
import unittest
from unittest.mock import patch
from state_tree import (StateTree, ProofError, COLUMNS, EMPTY, MAX_ROWS, bind_root,
                        make_witness, verify_proof, enabled, path_hash)


def blank():
    return {name: [] for name in COLUMNS}


def oracle(state):
    """Independent algorithm: full binary recursion, no compressed Node/lift code."""
    h = lambda b: hashlib.sha256(b).digest()
    enc = lambda v: json.dumps(v, sort_keys=True, separators=(',', ':'), ensure_ascii=True).encode()
    empties = [h(b'\x02')]
    for _ in range(256): empties.append(h(b'\x01' + empties[-1] + empties[-1]))
    items = []
    for table, rows in state.items():
        for row in rows:
            p = h(b'1soft/state-key/v1\x00' + enc([table, row[0]]))
            items.append((int.from_bytes(p, 'big'), h(b'\x00' + p + h(enc(row)))))
    def recur(items, depth):
        if not items: return empties[256-depth]
        if depth == 256:
            if len(items) != 1: raise ValueError('duplicate')
            return items[0][1]
        left = [x for x in items if not (x[0] >> (255-depth)) & 1]
        right = [x for x in items if (x[0] >> (255-depth)) & 1]
        return h(b'\x01' + recur(left, depth+1) + recur(right, depth+1))
    return recur(items, 0)


class StateTreeTests(unittest.TestCase):
    def setUp(self):
        self.state = blank()
        self.state['meta'] = [[f'key-{i}',str(i)] for i in range(12)]
        self.tree = StateTree(self.state)
    def test_empty_tree_matches_oracle(self):
        self.assertEqual(StateTree(blank()).root, oracle(blank()))
    def test_empty_tree_proves_nonmembership(self):
        tree=StateTree(blank());p=tree.proof('accounts','absent')
        self.assertEqual(p['siblings'],[]);self.assertIsNone(verify_proof(tree.root,'accounts','absent',p))
    def test_single_leaf_matches_oracle(self):
        state=blank();state['meta']=[['height','5']]
        self.assertEqual(StateTree(state).root,oracle(state))
    def test_many_leaves_match_independent_oracle(self):
        self.assertEqual(self.tree.root,oracle(self.state))
    def test_each_inclusion_proof_opens_exact_record(self):
        for key,value in self.state['meta']:
            self.assertEqual(verify_proof(self.tree.root,'meta',key,self.tree.proof('meta',key)),[key,value])
    def test_different_missing_paths_prove_absence(self):
        for i in range(40):
            key=f'absent-{i}'
            self.assertIsNone(verify_proof(self.tree.root,'meta',key,self.tree.proof('meta',key)))
    def test_input_row_order_does_not_change_map_root(self):
        state=copy.deepcopy(self.state);state['meta'].reverse()
        self.assertEqual(StateTree(state).root,self.tree.root)
    def test_table_order_does_not_change_root(self):
        self.assertEqual(StateTree(dict(reversed(list(self.state.items())))).root,self.tree.root)
    def test_changed_value_changes_root(self):
        state=copy.deepcopy(self.state);state['meta'][0][1]='different'
        self.assertNotEqual(StateTree(state).root,self.tree.root)
    def test_deleted_record_changes_root(self):
        state=copy.deepcopy(self.state);state['meta'].pop()
        self.assertNotEqual(StateTree(state).root,self.tree.root)
    def test_table_name_is_in_key_domain(self):
        self.assertNotEqual(path_hash('meta','x'),path_hash('grant_budgets','x'))
    def test_logical_key_encoding_is_unambiguous(self):
        self.assertNotEqual(path_hash('meta','a::b'),path_hash('meta','a:b'))
    def test_wrong_requested_key_refused(self):
        with self.assertRaises(ProofError):verify_proof(self.tree.root,'meta','key-1',self.tree.proof('meta','key-0'))
    def test_wrong_table_refused(self):
        with self.assertRaises(ProofError):verify_proof(self.tree.root,'grant_budgets','key-0',self.tree.proof('meta','key-0'))
    def test_wrong_root_refused(self):
        with self.assertRaises(ProofError):verify_proof(bytes(32),'meta','key-0',self.tree.proof('meta','key-0'))
    def test_altered_row_refused(self):
        p=self.tree.proof('meta','key-0');p['value'][1]='9'
        with self.assertRaises(ProofError):verify_proof(self.tree.root,'meta','key-0',p)
    def test_membership_cannot_be_presented_as_absence(self):
        p=self.tree.proof('meta','key-0');p['value']=None
        with self.assertRaises(ProofError):verify_proof(self.tree.root,'meta','key-0',p)
    def test_absence_cannot_be_presented_as_membership(self):
        p=self.tree.proof('meta','missing');p['value']=['missing','9']
        with self.assertRaises(ProofError):verify_proof(self.tree.root,'meta','missing',p)
    def test_changed_sibling_refused(self):
        p=self.tree.proof('meta','key-0');p['siblings'][0]='00'*32
        with self.assertRaises(ProofError):verify_proof(self.tree.root,'meta','key-0',p)
    def test_omitted_sibling_refused(self):
        p=self.tree.proof('meta','key-0');p['siblings'].pop()
        with self.assertRaises(ProofError):verify_proof(self.tree.root,'meta','key-0',p)
    def test_reordered_siblings_refused(self):
        p=self.tree.proof('meta','key-0');self.assertGreater(len(p['siblings']),1);p['siblings'].reverse()
        with self.assertRaises(ProofError):verify_proof(self.tree.root,'meta','key-0',p)
    def test_changed_path_bitmap_refused(self):
        p=self.tree.proof('meta','key-0');m=int(p['mask'],16);low=m&-m
        p['mask']=f'{(m^low)|1:064x}'
        with self.assertRaises(ProofError):verify_proof(self.tree.root,'meta','key-0',p)
    def test_explicit_default_sibling_refused_as_noncanonical(self):
        p=self.tree.proof('meta','key-0');self.assertEqual(int(p['mask'],16)&1,0)
        p['mask']=f'{int(p["mask"],16)|1:064x}';p['siblings'].insert(0,EMPTY[0].hex())
        with self.assertRaisesRegex(ProofError,'redundant'):verify_proof(self.tree.root,'meta','key-0',p)
    def test_extra_proof_field_refused(self):
        p=self.tree.proof('meta','key-0');p['verified']=True
        with self.assertRaises(ProofError):verify_proof(self.tree.root,'meta','key-0',p)
    def test_mask_must_be_exact_canonical_256_bits(self):
        for val in (0,True,'f'*65,'0x'+('0'*64),'a'*63,'A'*64):
            p=self.tree.proof('meta','key-0');p['mask']=val
            with self.subTest(val=val),self.assertRaises(ProofError):verify_proof(self.tree.root,'meta','key-0',p)
    def test_duplicate_logical_record_refused(self):
        self.state['meta'].append(self.state['meta'][0])
        with self.assertRaises(ProofError):StateTree(self.state)
    def test_simulated_key_hash_collision_fails_closed(self):
        with patch('state_tree.path_hash',return_value=bytes(32)),self.assertRaises(ProofError):StateTree(self.state)
    def test_snapshot_table_set_is_exact(self):
        for state in ({}, {**self.state,'evil':[]}, {k:v for k,v in self.state.items() if k!='budgets'}):
            with self.assertRaises(ProofError):StateTree(state)
    def test_row_shapes_and_ambiguous_cells_refused(self):
        for row in (['x'],['x',True],['x',1.1],['x',None],['x',{}],['x',[]]):
            s=blank();s['meta']=[row]
            with self.subTest(row=row),self.assertRaises(ProofError):StateTree(s)
    def test_oversized_value_refused(self):
        s=blank();s['meta']=[['x','x'*32768]]
        with self.assertRaises(ProofError):StateTree(s)
    def test_key_bound_and_controls_refused(self):
        for key in ('','x'*513,'\x00','é','line\nbreak'):
            with self.subTest(key=key),self.assertRaises(ProofError):self.tree.proof('meta',key)
    def test_global_map_record_bound_refused(self):
        with patch('state_tree.MAX_ROWS',5),self.assertRaises(ProofError):StateTree(self.state)
    def test_root_binding_commits_genesis_and_height(self):
        a=bind_root('01'*32,1,self.tree.root)
        self.assertNotEqual(a,bind_root('02'*32,1,self.tree.root))
        self.assertNotEqual(a,bind_root('01'*32,2,self.tree.root))
    def test_height_bounds(self):
        for h in (-1,True,1.0,'1',2**63-1):
            with self.subTest(h=h),self.assertRaises(ProofError):bind_root('01'*32,h,self.tree.root)
    def test_unknown_commitment_never_falls_back(self):
        for g in ({'state_commitment':'unknown'}, {'state_commitment':'smt-v1','protocol_version':2}):
            with self.assertRaises(ProofError):enabled(g)
        self.assertFalse(enabled({'protocol_version':3}))
    def test_proof_values_are_copied(self):
        p=self.tree.proof('meta','key-0');p['value'][1]='changed'
        self.assertEqual(self.tree.proof('meta','key-0')['value'],['key-0','0'])
    def test_randomized_roots_and_queries_against_oracle(self):
        rng=random.Random(737)
        for count in (1,2,3,7,16,40):
            s=blank();s['meta']=[[f'random-{n}',str(rng.randrange(10000))] for n in rng.sample(range(1000),count)]
            tree=StateTree(s);self.assertEqual(tree.root,oracle(s))
            for key,value in s['meta']:
                self.assertEqual(verify_proof(tree.root,'meta',key,tree.proof('meta',key)),[key,value])
            self.assertIsNone(verify_proof(tree.root,'meta','absent',tree.proof('meta','absent')))
    def test_all_bit_changes_to_root_rejected(self):
        p=self.tree.proof('meta','key-0')
        for bit in range(256):
            altered=(int.from_bytes(self.tree.root,'big')^(1<<bit)).to_bytes(32,'big')
            with self.assertRaises(ProofError):verify_proof(altered,'meta','key-0',p)


if __name__=='__main__':unittest.main()
