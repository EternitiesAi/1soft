import copy
import unittest
from commit_verifier import MAX_POWER,header_hash,verify_signed_header
from validator_transition import (canonical_set,parse_set,set_hash,policy_for,verify_anchor,
    verify_step,verify_link,preview_update,check_time,nanos)
from transition_fixture import fixture,resign

class TransitionTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):cls.f=fixture()
    def step(self,n):return copy.deepcopy(self.f['steps'][n-1])
    def verify(self,s):return verify_step(s,self.f['policy'])
    def test_complete_changing_sets(self):
        prev=self.f['steps'][0];verify_anchor(prev,self.f['policy'],self.f['genesis'],self.f['now'])
        for step in self.f['steps'][1:]:verify_link(prev,step,self.f['policy']);prev=step
        self.assertEqual(self.verify(prev)['validator_count'],4)
    def test_full_replacement_needs_no_key_overlap_when_adjacent(self):
        a,b=self.step(7),self.step(8)
        self.assertFalse({v['public_key'] for v in a['validators']} & {v['public_key'] for v in b['validators']})
        self.assertEqual(verify_link(a,b,self.f['policy'])['height'],8)
    def test_static_parent_remains_fail_closed_at_change_announcement(self):
        verify_signed_header(self.step(2)['signed_header'],self.f['original_trust'])
        with self.assertRaisesRegex(ValueError,'validator changes unsupported'):
            verify_signed_header(self.step(3)['signed_header'],self.f['original_trust'])
    def test_duplicate_validator_refused(self):
        s=self.step(4);s['validators'].append(s['validators'][0])
        with self.assertRaises(ValueError):self.verify(s)
    def test_reordered_set_refused(self):
        s=self.step(4);s['validators'].reverse()
        with self.assertRaises(ValueError):self.verify(s)
    def test_boolean_and_string_power_refused(self):
        for p in (True,False,'10',10.0,-1,0):
            s=self.step(4);s['validators'][0]['power']=p
            with self.subTest(p=p),self.assertRaises(ValueError):self.verify(s)
    def test_total_power_limit(self):
        s=self.step(2)['validators']
        for r in s:r['power']=MAX_POWER
        with self.assertRaises(ValueError):canonical_set(s)
    def test_unsupported_validator_key_type(self):
        s=self.step(4);s['validators'][0]['type']='secp256k1'
        with self.assertRaises(ValueError):self.verify(s)
    def test_forged_power_cannot_change_weight(self):
        s=self.step(4);s['validators'][0]['power']=50;s['validators']=canonical_set(s['validators'])
        with self.assertRaises(ValueError):self.verify(s)
    def test_next_set_hash_must_match_contents(self):
        s=self.step(3);s['next_validators']=s['validators']
        with self.assertRaises(ValueError):self.verify(s)
    def test_old_set_cannot_vote_after_replacement(self):
        s=self.step(8);s['validators']=self.step(6)['validators']
        s['signed_header']['header']['validators_hash']=set_hash(s['validators'])
        s['signed_header']['header']['proposer_address']=parse_set(s['validators'])[0].address.hex()
        resign(self.f,s)
        with self.assertRaisesRegex(ValueError,'predecessor'):verify_link(self.step(7),s,self.f['policy'])
    def test_missing_height_refused(self):
        with self.assertRaises(ValueError):verify_link(self.step(3),self.step(5),self.f['policy'])
    def test_full_previous_block_id_checked(self):
        s=self.step(4);s['signed_header']['header']['last_block_id']['parts']['hash']='aa'*32;resign(self.f,s)
        with self.assertRaisesRegex(ValueError,'block identity'):verify_link(self.step(3),s,self.f['policy'])
    def test_equal_header_timestamp_refused(self):
        s=self.step(4);s['signed_header']['header']['time']=self.step(3)['signed_header']['header']['time'];resign(self.f,s)
        with self.assertRaises(ValueError):verify_link(self.step(3),s,self.f['policy'])
    def test_wrong_chain_refused(self):
        s=self.step(4);s['signed_header']['header']['chain_id']='other';resign(self.f,s)
        with self.assertRaises(ValueError):self.verify(s)
    def test_application_upgrade_is_not_implicitly_approved(self):
        s=self.step(4);s['signed_header']['header']['version']['app']='4';resign(self.f,s)
        with self.assertRaisesRegex(ValueError,'version'):self.verify(s)
    def test_block_version_mismatch_refused(self):
        s=self.step(4);s['signed_header']['header']['version']['block']='12';resign(self.f,s)
        with self.assertRaises(ValueError):self.verify(s)
    def test_all_signature_slots_checked_even_after_quorum(self):
        s=self.step(4);s['signed_header']['commit']['signatures'][-1]['signature']='AA=='
        with self.assertRaises(ValueError):self.verify(s)
    def test_nil_vote_valid_but_does_not_count(self):
        s=self.step(4);resign(self.f,s,[2,2,2,3,3])
        with self.assertRaisesRegex(ValueError,'two-thirds'):self.verify(s)
    def test_absent_vote_constraints(self):
        s=self.step(4);resign(self.f,s,[2,2,2,2,1]);self.verify(s)
        s['signed_header']['commit']['signatures'][-1]['validator_address']='aa'*20
        with self.assertRaises(ValueError):self.verify(s)
    def test_exact_two_thirds_power_is_not_quorum(self):
        s=self.step(6);resign(self.f,s,[2,2,1,1])
        self.assertEqual(sum(r['power'] for r in s['validators']),50)
        with self.assertRaises(ValueError):self.verify(s)
        s=self.step(4);s['validators']=canonical_set([{**r,'power':10} for r in s['validators'][:3]])
        s['signed_header']['header']['validators_hash']=set_hash(s['validators'])
        s['signed_header']['header']['proposer_address']=parse_set(s['validators'])[0].address.hex()
        resign(self.f,s,[2,2,1])
        with self.assertRaisesRegex(ValueError,'two-thirds'):self.verify(s)
    def test_weighted_not_headcount_quorum(self):
        s=self.step(6);resign(self.f,s,[1,2,2,2])
        with self.assertRaisesRegex(ValueError,'two-thirds'):self.verify(s)
        resign(self.f,s,[2,2,2,1]);self.assertEqual(self.verify(s)['signed_power'],40)
    def test_external_checkpoint_pin(self):
        p={**self.f['policy'],'initial_header_hash':'ab'*32}
        with self.assertRaises(ValueError):verify_anchor(self.step(1),p,self.f['genesis'],self.f['now'])
    def test_expired_at_exact_boundary_refused(self):
        info=self.verify(self.step(1));p=self.f['policy']
        with self.assertRaises(ValueError):check_time(info,p,info['time_ns']+p['trust_period_seconds']*10**9)
    def test_future_drift_boundary_refused(self):
        info=self.verify(self.step(1));p=self.f['policy']
        with self.assertRaises(ValueError):check_time(info,p,info['time_ns']-p['max_clock_drift_seconds']*10**9)
    def test_later_external_anchor_can_start_without_genesis_set(self):
        s=self.step(8)
        p=policy_for(self.f['genesis'],self.f['policy']['genesis_sha256'],initial_height=8,
                     initial_header_hash=header_hash(s['signed_header']['header']).hex(),trust_period_seconds=3600)
        self.assertEqual(verify_anchor(s,p,self.f['genesis'],self.f['now'])['height'],8)
    def test_extra_step_field_refused(self):
        s=self.step(4);s['trusted']=True
        with self.assertRaises(ValueError):self.verify(s)

class PreviewTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):cls.f=fixture()
    def test_activation_is_h_plus_two_not_h_plus_one(self):
        p=self.f['plans'][0];self.assertEqual((p['finalize_height'],p['next_hash_header_height'],p['active_validator_height'],p['changed_last_commit_height']),(2,3,4,5))
        self.assertFalse(p['chain_mutated']);self.assertFalse(p['activation_scheduled']);self.assertFalse(p['governance_authorization_checked'])
    def test_combined_remove_and_power_change(self):
        p=self.f['plans'][1];self.assertEqual(len(p['next_validators']),4)
        self.assertEqual(p['next_validators'][0]['power'],20)
    def test_pure_model_does_not_mutate_inputs(self):
        a=copy.deepcopy(self.f['steps'][0]['validators']);before=copy.deepcopy(a)
        preview_update(a,[{**a[0],'power':12}],3);self.assertEqual(a,before)
    def test_delta_order_is_deterministic(self):
        a=self.f['steps'][0]['validators'];changes=[{**a[0],'power':12},{**a[1],'power':11}]
        self.assertEqual(preview_update(a,changes,3),preview_update(a,list(reversed(changes)),3))
    def test_cannot_remove_whole_set(self):
        a=self.f['steps'][0]['validators']
        with self.assertRaises(ValueError):preview_update(a,[{**v,'power':0} for v in a],2)
    def test_unknown_removal_refused(self):
        a=self.f['steps'][0]['validators']
        with self.assertRaises(ValueError):preview_update(a,[{'public_key':'aa'*32,'power':0}],2)
    def test_duplicate_delta_refused(self):
        a=self.f['steps'][0]['validators']
        with self.assertRaises(ValueError):preview_update(a,[a[0],a[0]],2)
    def test_boolean_height_refused(self):
        a=self.f['steps'][0]['validators']
        with self.assertRaises(ValueError):preview_update(a,[a[0]],True)
    def test_delta_uses_already_scheduled_next_set(self):
        p1,p2=self.f['plans'][:2]
        self.assertEqual(p2['before_hash'],p1['after_hash'])
