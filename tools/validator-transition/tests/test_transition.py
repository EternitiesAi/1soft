import copy
import random
import unittest
from unittest.mock import patch
from commit_verifier import encode, sha, header_hash, pinned_genesis, verify_signed_header, MAX_POWER
from validator_sets import (ValidatorSet, canonical_roster, validator_updates, draft_transition,
                            validate_draft, document_id, MAX_HEIGHT)
from validator_witness import (start_witness, extend_witness, verify_witness, verify_header,
                               audit_transition, nanos)
from transition_fixture import scenario, sign_header


class RosterTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls): cls.c = scenario()
    def test_canonical_roster_matches_existing_genesis_hash(self):
        trust = pinned_genesis(self.c['genesis'], self.c['policy']['genesis_sha256'])
        self.assertEqual(self.c['sets']['old'].hash, trust.validators_hash.hex())
    def test_parse_does_not_silently_sort_untrusted_roster(self):
        with self.assertRaises(ValueError): ValidatorSet.parse(list(reversed(self.c['old'])))
    def test_authoring_helper_sorts_without_mutating_input(self):
        value = list(reversed(self.c['old'])); old = copy.deepcopy(value)
        self.assertEqual(canonical_roster(value), self.c['old']); self.assertEqual(value, old)
    def test_empty_set_is_not_legal(self):
        with self.assertRaises(ValueError): ValidatorSet.parse([])
    def test_duplicate_validator_refused(self):
        with self.assertRaises(ValueError): canonical_roster([self.c['old'][0]] * 2)
    def test_invalid_power_types(self):
        for value in (True, False, 1.0, '10', None):
            with self.subTest(value=value), self.assertRaises(ValueError):
                canonical_roster([{**self.c['old'][0], 'power':value}])
    def test_zero_negative_and_overflow_power_refused(self):
        for value in (0,-1,MAX_POWER+1):
            with self.subTest(value=value), self.assertRaises(ValueError):
                canonical_roster([{**self.c['old'][0], 'power':value}])
    def test_total_power_overflow_refused(self):
        with self.assertRaises(ValueError):
            canonical_roster([{**r,'power':MAX_POWER} for r in self.c['old'][:2]])
    def test_power_boundary_is_exact(self):
        rows = canonical_roster([{**self.c['old'][0],'power':MAX_POWER}])
        self.assertEqual(ValidatorSet.parse(rows).total_power, MAX_POWER)
    def test_unknown_key_type_or_field_refused(self):
        with self.assertRaises(ValueError): ValidatorSet.parse([{**self.c['old'][0],'key_type':'rsa'}])
    def test_key_encoding_canonical(self):
        for key in ('a'*63, 'g'*64, self.c['old'][0]['public_key'].upper()):
            with self.subTest(key=key), self.assertRaises(ValueError):
                ValidatorSet.parse([{'public_key':key,'power':10}])
    def test_roster_count_is_bounded(self):
        with self.assertRaises(ValueError): ValidatorSet.parse(self.c['old'] * 65)
    def test_removal_is_zero_delta_not_zero_full_roster(self):
        updates = self.c['draft']['validator_updates']
        removed = set(r['public_key'] for r in self.c['old']) - set(r['public_key'] for r in self.c['new'])
        self.assertEqual({r['public_key'] for r in updates if r['power']==0}, removed)
    def test_apply_delta_reconstructs_target(self):
        values = {r['public_key']:r['power'] for r in self.c['old']}
        for r in self.c['draft']['validator_updates']:
            if r['power']==0: values.pop(r['public_key'])
            else: values[r['public_key']] = r['power']
        self.assertEqual(canonical_roster([{'public_key':k,'power':p} for k,p in values.items()]), self.c['new'])
    def test_randomized_delta_equivalence(self):
        rng=random.Random(732193); pool=list(self.c['keys'])
        for _ in range(200):
            a=canonical_roster([{'public_key':k,'power':rng.randrange(1,1000)} for k in rng.sample(pool,rng.randrange(1,13))])
            b=canonical_roster([{'public_key':k,'power':rng.randrange(1,1000)} for k in rng.sample(pool,rng.randrange(1,13))])
            delta=validator_updates(ValidatorSet.parse(a),ValidatorSet.parse(b));values={r['public_key']:r['power'] for r in a}
            for r in delta:
                if r['power']:values[r['public_key']]=r['power']
                else:values.pop(r['public_key'])
            self.assertEqual(canonical_roster([{'public_key':k,'power':p} for k,p in values.items()]),b)
    def test_wire_zero_power_removal_omits_default_integer_field(self):
        from validator_wire import encode_update_response,FinalizeBlock
        raw=encode_update_response(self.c['draft']['validator_updates'])
        message=FinalizeBlock.FromString(raw)
        self.assertEqual(len(message.validator_updates),len(self.c['draft']['validator_updates']))
        self.assertTrue(any(v.power==0 for v in message.validator_updates))
        for v,r in zip(message.validator_updates,self.c['draft']['validator_updates']):
            self.assertEqual(v.pub_key.ed25519.hex(),r['public_key']);self.assertEqual(v.power,r['power'])
    def test_wire_duplicate_update_refused(self):
        from validator_wire import encode_update_response
        with self.assertRaises(ValueError):encode_update_response([self.c['draft']['validator_updates'][0]]*2)
    def test_direct_validator_constructor_cannot_bypass_guards(self):
        from commit_verifier import Validator
        v=self.c['sets']['old'].validators[0]
        with self.assertRaises(ValueError):ValidatorSet((Validator(v.address,v.public_key,True),))
        with self.assertRaises(ValueError):ValidatorSet(())
    def test_noop_draft_refused(self):
        with self.assertRaises(ValueError): self.draft(self.c['old'])
    def draft(self,target,**kw):
        return draft_transition(self.c['old'],target,chain_id=self.c['draft']['chain_id'],
            native_genesis_hash=self.c['draft']['native_genesis_hash'],
            expected_current_hash=kw.get('expected_current_hash',self.c['sets']['old'].hash),
            emitted_height=kw.get('emitted_height',3))
    def test_wrong_current_hash_refused(self):
        with self.assertRaises(ValueError):self.draft(self.c['new'],expected_current_hash='0'*64)
    def test_activation_delay_is_exact(self):
        p=self.draft(self.c['new']);self.assertEqual([p[k] for k in
            ('emitted_height','announcement_height','activation_height','last_commit_height')],[3,4,5,6])
    def test_draft_does_not_authorize_or_activate(self):
        p=self.c['draft'];self.assertEqual(p['authorization'],'not-established')
        self.assertIs(p['activation_performed'],False);self.assertIs(p['protocol_upgrade_required'],True)
    def test_draft_tampered_delay_rejected(self):
        p=copy.deepcopy(self.c['draft']);p['activation_height']-=1
        with self.assertRaises(ValueError):validate_draft(p)
    def test_boolean_draft_schema_is_not_one(self):
        p=copy.deepcopy(self.c['draft']);p['schema']=True
        with self.assertRaises(ValueError):validate_draft(p)
    def test_height_bounds(self):
        for h in (True,0,-1,MAX_HEIGHT-2):
            with self.subTest(h=h),self.assertRaises(ValueError):self.draft(self.c['new'],emitted_height=h)


class WitnessTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):cls.c=scenario()
    def initial(self,c=None,**kw):
        c=c or self.c
        return start_witness(c['entries'][0],c['genesis'],kw.get('policy',c['policy']),now_ns=kw.get('now_ns',c['now_ns']))
    def whole(self,c=None):
        c=c or self.c; first=self.initial(c)
        return extend_witness(first,c['entries'][1:],c['genesis'],c['policy'],expected_parent_sha256=document_id(first),now_ns=c['now_ns'])
    def verify(self,w=None,**kw):
        return verify_witness(w or self.whole(),kw.get('genesis',self.c['genesis']),kw.get('policy',self.c['policy']),
                              now_ns=kw.get('now_ns',self.c['now_ns']))
    def test_added_removed_and_reweighted_validator_path(self):
        r=self.verify();self.assertEqual(r['headers_verified'],12)
        self.assertEqual(len(r['validator_changes']),1);self.assertEqual(r['validator_changes'][0]['height'],5)
    def test_second_rotation_follows_first_without_changing_old_witness(self):
        c=self.c;entries=copy.deepcopy(c['entries']);third=ValidatorSet.parse(canonical_roster(
            [{'public_key':k,'power':13} for k in list(c['keys'])[6:10]]))
        for i in range(7,len(entries)):
            h=entries[i]['signed_header']['header']
            h['last_block_id']=entries[i-1]['signed_header']['commit']['block_id']
            current=c['sets']['new'] if i==7 else third
            h['validators_hash']=current.hash.upper();h['next_validators_hash']=third.hash.upper()
            h['proposer_address']=current.validators[0].address.hex().upper()
            entries[i]={'signed_header':sign_header(h,current,c['keys']),
                        'validators':current.json(),'next_validators':third.json()}
        first=self.initial();mid=extend_witness(first,entries[1:6],c['genesis'],c['policy'],
            expected_parent_sha256=document_id(first),now_ns=c['now_ns']);before=encode(mid)
        final=extend_witness(mid,entries[6:],c['genesis'],c['policy'],
            expected_parent_sha256=document_id(mid),now_ns=c['now_ns'])
        self.assertEqual([t['height'] for t in self.verify(final)['validator_changes']],[5,9])
        self.assertEqual(encode(mid),before)
    def test_later_external_anchor_does_not_claim_earlier_history(self):
        e=self.c['entries'][8];h=e['signed_header']['header']
        p={**self.c['policy'],'anchor_height':9,'anchor_hash':header_hash(h).hex(),'anchor_time':h['time']}
        w=start_witness(e,self.c['genesis'],p,now_ns=self.c['now_ns'])
        r=verify_witness(w,self.c['genesis'],p,now_ns=self.c['now_ns'])
        self.assertEqual(r['anchor_height'],9);self.assertEqual(r['headers_verified'],1)
    def test_complete_roster_replacement_uses_signed_adjacency(self):
        c=scenario(full_replace=True);w=self.whole(c)
        r=verify_witness(w,c['genesis'],c['policy'],now_ns=c['now_ns'])
        self.assertEqual(len(r['validator_changes']),1)
    def test_legacy_static_verifier_still_refuses_transition(self):
        trust=pinned_genesis(self.c['genesis'],self.c['policy']['genesis_sha256'])
        with self.assertRaisesRegex(ValueError,'validator changes unsupported'):
            verify_signed_header(self.c['entries'][3]['signed_header'],trust)
    def test_anchor_not_taken_from_peer(self):
        p={**self.c['policy'],'anchor_hash':'0'*64}
        with self.assertRaises(ValueError):self.initial(policy=p)
    def test_anchor_time_exactly_bound(self):
        p={**self.c['policy'],'anchor_time':'2026-01-01T00:00:00Z'}
        with self.assertRaises(ValueError):self.initial(policy=p)
    def test_wrong_genesis_file_rejected(self):
        with self.assertRaises(ValueError):self.verify(genesis=self.c['genesis']+b' ')
    def test_fixed_expiry_not_renewed_by_later_headers(self):
        p=self.c['policy'];expiry=nanos(p['anchor_time'])+p['trust_period_seconds']*10**9
        with self.assertRaises(ValueError):self.verify(now_ns=expiry)
    def test_one_nanosecond_before_expiry(self):
        p=self.c['policy'];expiry=nanos(p['anchor_time'])+p['trust_period_seconds']*10**9
        self.assertEqual(self.verify(now_ns=expiry-1)['trust_expires_ns'],expiry)
    def test_clock_rollback_is_refused(self):
        with self.assertRaises(ValueError):self.verify(now_ns=self.c['now_ns']-1)
    def test_boolean_policy_version_rejected(self):
        with self.assertRaises(ValueError):self.initial(policy={**self.c['policy'],'schema':True})
    def test_parent_witness_pin_required(self):
        w=self.initial()
        with self.assertRaises(ValueError):extend_witness(w,self.c['entries'][1:2],self.c['genesis'],self.c['policy'],
            expected_parent_sha256='0'*64,now_ns=self.c['now_ns'])
    def test_failed_append_preserves_input_bytes(self):
        w=self.initial();raw=encode(w)
        with self.assertRaises(ValueError):extend_witness(w,self.c['entries'][2:3],self.c['genesis'],self.c['policy'],
            expected_parent_sha256=document_id(w),now_ns=self.c['now_ns'])
        self.assertEqual(encode(w),raw)
    def test_success_append_does_not_mutate_old_witness(self):
        w=self.initial();raw=encode(w);extended=extend_witness(w,self.c['entries'][1:3],self.c['genesis'],self.c['policy'],
            expected_parent_sha256=document_id(w),now_ns=self.c['now_ns'])
        self.assertEqual(encode(w),raw);self.assertEqual(len(extended['entries']),3)
    def test_nonadjacent_path_refused(self):
        w=self.whole();del w['entries'][3]
        with self.assertRaises(ValueError):self.verify(w)
    def test_duplicate_header_not_extra_progress(self):
        w=self.whole();w['entries'].insert(3,w['entries'][3])
        with self.assertRaises(ValueError):self.verify(w)
    def test_current_roster_cannot_be_replaced_by_endpoint(self):
        w=self.whole();w['entries'][4]['validators']=self.c['old']
        with self.assertRaises(ValueError):self.verify(w)
    def test_next_roster_cannot_be_replaced_by_endpoint(self):
        w=self.whole();w['entries'][3]['next_validators']=self.c['old']
        with self.assertRaises(ValueError):self.verify(w)
    def test_unannounced_new_set_refused_even_with_valid_signatures(self):
        c=self.c;w=self.whole();entry=w['entries'][3]
        h=entry['signed_header']['header'];h['next_validators_hash']=c['sets']['old'].hash.upper()
        entry['next_validators']=c['old'];entry['signed_header']=sign_header(h,c['sets']['old'],c['keys'])
        # Keep EVERY block-ID link and signature valid. Only the handover promise
        # is violated: height 5 introduces B although height 4 committed A as next.
        for i in range(4,len(w['entries'])):
            following=w['entries'][i];head=following['signed_header']['header']
            head['last_block_id']=w['entries'][i-1]['signed_header']['commit']['block_id']
            following['signed_header']=sign_header(head,c['sets']['new'],c['keys'])
        with self.assertRaisesRegex(ValueError,'not announced'):self.verify(w)
    def test_full_part_set_identity_bound(self):
        w=self.whole();entry=w['entries'][5];h=entry['signed_header']['header'];h['last_block_id']['parts']['hash']='aa'*32
        entry['signed_header']=sign_header(h,self.c['sets']['new'],self.c['keys'])
        with self.assertRaisesRegex(ValueError,'preceding block'):self.verify(w)
    def test_wrong_header_chain_refused(self):
        w=self.whole();entry=w['entries'][-1];h=entry['signed_header']['header'];h['chain_id']='different'
        entry['signed_header']=sign_header(h,self.c['sets']['new'],self.c['keys'])
        with self.assertRaises(ValueError):self.verify(w)
    def test_protocol_upgrade_cannot_sneak_through_rotation(self):
        w=self.whole();entry=w['entries'][-1];h=entry['signed_header']['header'];h['version']['app']='4'
        entry['signed_header']=sign_header(h,self.c['sets']['new'],self.c['keys'])
        with self.assertRaisesRegex(ValueError,'separate upgrade'):self.verify(w)
    def test_exact_two_thirds_is_not_supermajority(self):
        e=copy.deepcopy(self.c['entries'][0]);roster=ValidatorSet.parse(self.c['old'][:3]);h=e['signed_header']['header']
        h['validators_hash']=h['next_validators_hash']=roster.hash.upper()
        e['validators']=e['next_validators']=roster.json()
        e['signed_header']=sign_header(h,roster,self.c['keys'],[2,2,1])
        with self.assertRaisesRegex(ValueError,'insufficient'):
            verify_header(e,h['chain_id'],self.c['policy'],self.c['now_ns'])
    def test_bad_nil_vote_after_supermajority_is_not_ignored(self):
        e=copy.deepcopy(self.c['entries'][0]);e['signed_header']=sign_header(e['signed_header']['header'],self.c['sets']['old'],self.c['keys'],[2,2,2,3])
        e['signed_header']['commit']['signatures'][-1]['signature']='AA=='
        with self.assertRaises(ValueError):verify_header(e,e['signed_header']['header']['chain_id'],self.c['policy'],self.c['now_ns'])
    def test_old_power_is_used_at_announcement_height(self):
        e=copy.deepcopy(self.c['entries'][3]);e['signed_header']=sign_header(e['signed_header']['header'],self.c['sets']['old'],self.c['keys'],[2,2,1,1])
        with self.assertRaisesRegex(ValueError,'insufficient'):
            verify_header(e,e['signed_header']['header']['chain_id'],self.c['policy'],self.c['now_ns'])
    def test_saved_observation_cannot_predate_final_header(self):
        w=self.whole();w['last_observed_clock_ns']=self.c['initial_ns']
        with self.assertRaisesRegex(ValueError,'observation predates'):self.verify(w)
    def test_header_history_capacity_refuses_without_silent_pruning(self):
        w=self.whole()
        with patch('validator_witness.MAX_STORED_HEADERS',11):
            with self.assertRaises(ValueError):self.verify(w)
    def test_future_header_refused(self):
        w=self.whole();e=w['entries'][-1];e['signed_header']['header']['time']='2099-01-01T00:00:00Z'
        e['signed_header']=sign_header(e['signed_header']['header'],self.c['sets']['new'],self.c['keys'])
        with self.assertRaisesRegex(ValueError,'future'):self.verify(w)
    def test_zero_absent_signature_timestamp_is_required(self):
        e=copy.deepcopy(self.c['entries'][0]);e['signed_header']=sign_header(e['signed_header']['header'],self.c['sets']['old'],self.c['keys'],[2,2,2,1])
        e['signed_header']['commit']['signatures'][-1]['timestamp']=e['signed_header']['header']['time']
        with self.assertRaises(ValueError):start_witness(e,self.c['genesis'],self.c['policy'],now_ns=self.c['now_ns'])
    def test_last_signature_still_checked_after_quorum(self):
        e=copy.deepcopy(self.c['entries'][0]);e['signed_header']['commit']['signatures'][-1]['signature']='AA=='
        with self.assertRaises(ValueError):start_witness(e,self.c['genesis'],self.c['policy'],now_ns=self.c['now_ns'])
    def test_absent_last_slot_does_not_count_but_three_of_four_passes(self):
        e=copy.deepcopy(self.c['entries'][0]);e['signed_header']=sign_header(e['signed_header']['header'],self.c['sets']['old'],self.c['keys'],[2,2,2,1])
        w=start_witness(e,self.c['genesis'],self.c['policy'],now_ns=self.c['now_ns']);self.assertEqual(len(w['entries']),1)
    def test_nil_votes_are_verified_but_not_counted(self):
        e=copy.deepcopy(self.c['entries'][0]);e['signed_header']=sign_header(e['signed_header']['header'],self.c['sets']['old'],self.c['keys'],[2,2,3,3])
        with self.assertRaisesRegex(ValueError,'insufficient'):start_witness(e,self.c['genesis'],self.c['policy'],now_ns=self.c['now_ns'])
    def test_signature_slot_reordering_refused(self):
        e=copy.deepcopy(self.c['entries'][0]);e['signed_header']['commit']['signatures'].reverse()
        with self.assertRaises(ValueError):start_witness(e,self.c['genesis'],self.c['policy'],now_ns=self.c['now_ns'])
    def test_boolean_flag_not_integer(self):
        e=copy.deepcopy(self.c['entries'][0]);e['signed_header']['commit']['signatures'][0]['block_id_flag']=True
        with self.assertRaises(ValueError):start_witness(e,self.c['genesis'],self.c['policy'],now_ns=self.c['now_ns'])
    def test_oversized_batch_refused_before_progress(self):
        w=self.initial()
        with self.assertRaises(ValueError):extend_witness(w,self.c['entries'][1:2]*65,self.c['genesis'],self.c['policy'],
            expected_parent_sha256=document_id(w),now_ns=self.c['now_ns'])
    def test_empty_append_refused(self):
        w=self.initial()
        with self.assertRaises(ValueError):extend_witness(w,[],self.c['genesis'],self.c['policy'],expected_parent_sha256=document_id(w),now_ns=self.c['now_ns'])
    def test_no_network_or_private_key_access(self):
        with patch('socket.socket',side_effect=AssertionError('no RPC')),patch('certified_wallet._load_vault',side_effect=AssertionError('no keys')):
            self.verify()
    def test_no_state_or_governance_authority_claimed(self):
        r=self.verify()
        for field in ('native_state_verified','wallet_authority_changed','governance_authorization_established','latest_state_guaranteed','public_network_ready'):
            self.assertIs(r[field],False)
    def test_timestamp_regression_refused(self):
        w=self.whole();e=w['entries'][-1];e['signed_header']['header']['time']=w['entries'][-2]['signed_header']['header']['time']
        e['signed_header']=sign_header(e['signed_header']['header'],self.c['sets']['new'],self.c['keys'])
        with self.assertRaisesRegex(ValueError,'time did not advance'):self.verify(w)
    def test_complete_timeline_audit(self):
        r=audit_transition(self.c['draft'],self.whole(),self.c['genesis'],self.c['policy'],now_ns=self.c['now_ns'])
        self.assertEqual([e['height'] for e in r['timeline']],[3,4,5,6]);self.assertIs(r['abci_emission_observed'],False)
    def test_incomplete_timeline_not_a_pass(self):
        w=self.initial()
        with self.assertRaises(ValueError):audit_transition(self.c['draft'],w,self.c['genesis'],self.c['policy'],now_ns=self.c['now_ns'])
    def test_early_or_late_activation_refused(self):
        for h in (2,4):
            p=draft_transition(self.c['old'],self.c['new'],chain_id=self.c['draft']['chain_id'],
                native_genesis_hash=self.c['draft']['native_genesis_hash'],expected_current_hash=self.c['sets']['old'].hash,emitted_height=h)
            with self.subTest(h=h),self.assertRaises(ValueError):audit_transition(p,self.whole(),self.c['genesis'],self.c['policy'],now_ns=self.c['now_ns'])
    def test_different_native_genesis_in_plan_refused(self):
        p={**self.c['draft'],'native_genesis_hash':'0'*64}
        with self.assertRaises(ValueError):audit_transition(p,self.whole(),self.c['genesis'],self.c['policy'],now_ns=self.c['now_ns'])


if __name__=='__main__':unittest.main()
