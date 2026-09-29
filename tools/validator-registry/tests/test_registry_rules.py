import copy
import json
import unittest
from unittest.mock import patch
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from commit_verifier import encode
from validator_sets import ValidatorSet, canonical_roster, validator_updates, MAX_POWER
from registry_rules import (validate_genesis, initial_state, restore_state, state_hash,
    decode_command, draft, block_transition, command_id, sha, PROFILE)
from registry_fixture import fixture, schedule, cancel, block, approve, pub


class RegistryRulesTests(unittest.TestCase):
    def setUp(self):
        self.g, self.admins, self.vals, self.target = fixture()
        self.s = initial_state(self.g)
        self.raw = schedule(self.g, self.s, self.admins[:2], self.target)
    def step(self, txs=()):
        self.s, r = block(self.g, self.s, txs)
        return r
    def reject(self, raw):
        before = copy.deepcopy(self.s)
        r = self.step([raw]); self.assertEqual(r['tx_results'], [{'code':1,'command_id':None}])
        self.assertEqual(self.s['nonce'], before['nonce'])
        self.assertEqual(self.s['receipts'], before['receipts'])
    def test_initial_registry_is_explicit_separate_profile(self):
        self.assertEqual(self.s['profile'], PROFILE); self.assertEqual(self.s['epoch'], 0)
        self.assertEqual(self.s['nonce'], 0); self.assertIsNone(self.s['pending'])
    def test_schedule_emission_announcement_activation_and_last_commit_timing(self):
        old = ValidatorSet.parse(self.g['validators']).hash; new = ValidatorSet.parse(self.target).hash
        r1 = self.step([self.raw]); self.assertEqual(r1['validator_updates'], [])
        self.assertEqual(self.s['pending']['activation_height'], 5)
        r2 = self.step(); self.assertEqual(r2['validator_updates'], [])
        r3 = self.step(); self.assertEqual(r3['validator_updates'], validator_updates(ValidatorSet.parse(self.g['validators']), ValidatorSet.parse(self.target)))
        self.assertEqual(r3['active_set_hash'], old); self.assertEqual(r3['next_height_set_hash'], old)
        r4 = self.step(); self.assertEqual(r4['validator_updates'], [])
        self.assertEqual(r4['active_set_hash'], old); self.assertEqual(r4['next_height_set_hash'], new)
        r5 = self.step(); self.assertEqual(r5['active_set_hash'], new); self.assertEqual(r5['active_epoch'], 1)
        self.assertIsNone(self.s['pending']); self.assertEqual(r5['activation']['height'], 5)
        r6 = self.step(); self.assertEqual(r6['active_set_hash'], new)
    def test_two_administrators_meet_configured_threshold_not_consensus_quorum(self):
        self.assertEqual(self.step([self.raw])['tx_results'][0]['code'], 0)
    def test_one_administrator_refused(self):
        b=json.loads(self.raw)['body']; self.reject(approve(b, self.admins[:1]))
    def test_consensus_keys_have_no_governance_authority(self):
        b=json.loads(self.raw)['body']; self.reject(approve(b, self.vals[:3]))
    def test_extra_invalid_signature_after_threshold_is_not_ignored(self):
        b=json.loads(approve(json.loads(self.raw)['body'], self.admins))
        b['approvals'][-1]['signature']='00'*64; self.reject(encode(b))
    def test_duplicate_admin_does_not_increase_threshold(self):
        b=json.loads(self.raw); b['approvals']=[b['approvals'][0]]*2; self.reject(encode(b))
    def test_unordered_approvals_refused(self):
        b=json.loads(self.raw); b['approvals'].reverse(); self.reject(encode(b))
    def test_replay_same_block_and_later_block_refused(self):
        r=self.step([self.raw,self.raw]); self.assertEqual([x['code'] for x in r['tx_results']], [0,1])
        self.reject(self.raw)
    def test_second_pending_proposal_refused(self):
        self.step([self.raw]); target=canonical_roster(self.g['validators']+[{'public_key':pub(self.vals[5]),'power':10}])
        r=schedule(self.g,self.s,self.admins[:2],target,4); self.reject(r)
    def test_unauthorized_command_does_not_consume_nonce(self):
        b=json.loads(self.raw); b['approvals'][0]['signature']='00'*64
        r=self.step([encode(b), self.raw]); self.assertEqual([x['code'] for x in r['tx_results']],[1,0])
        self.assertEqual(self.s['nonce'],1)
    def test_exact_delay_boundary(self):
        self.assertEqual(self.step([self.raw])['tx_results'][0]['code'],0)
    def test_emission_one_block_too_soon(self):
        self.reject(schedule(self.g,self.s,self.admins[:2],self.target,2))
    def test_future_schedule_limit(self):
        self.reject(schedule(self.g,self.s,self.admins[:2],self.target,102))
    def test_expired_command_refused(self):
        r=schedule(self.g,self.s,self.admins[:2],self.target,5,until=1)
        self.step(); self.reject(r)
    def test_not_yet_valid_command_refused(self):
        r=schedule(self.g,self.s,self.admins[:2],self.target,5,start=2);self.reject(r)
    def test_boolean_integer_fields_refused(self):
        for field in ('schema','nonce','base_epoch','authority_epoch','valid_from','valid_until'):
            with self.subTest(field=field):
                b=json.loads(self.raw)['body'];b[field]=True
                with self.assertRaises(ValueError):decode_command(approve(b,self.admins[:2]),self.g)
    def test_wrong_chain_genesis_and_authority_epoch_refused(self):
        for field,value in (('chain_id','other'),('genesis_sha256','00'*32),('authority_epoch',1)):
            with self.subTest(field=field):
                b=json.loads(self.raw)['body'];b[field]=value
                with self.assertRaises(ValueError):decode_command(approve(b,self.admins[:2]),self.g)
    def test_signature_from_another_body_refused(self):
        e=json.loads(self.raw);e['body']['operation']['emission_height']=4;self.reject(encode(e))
    def test_old_epoch_or_roster_refused(self):
        for field,value in (('base_epoch',1),('base_set_hash','00'*32),('nonce',1)):
            s=initial_state(self.g);b=json.loads(self.raw)['body'];b[field]=value
            _,r=block(self.g,s,[approve(b,self.admins[:2])]);self.assertEqual(r['tx_results'][0]['code'],1)
    def test_cancel_before_emission_keeps_accepted_history_immutable(self):
        self.step([self.raw]); old=copy.deepcopy(self.s['receipts'][0]); self.step([cancel(self.g,self.s,self.admins[:2])])
        self.assertIsNone(self.s['pending']);self.assertEqual(self.s['receipts'][0],old)
        self.assertEqual(self.s['nonce'],2);self.assertEqual(self.step()['validator_updates'],[])
    def test_cancel_at_emission_is_rejected_but_emission_still_occurs(self):
        self.step([self.raw]);self.step();wire=cancel(self.g,self.s,self.admins[:2])
        r=self.step([wire]);self.assertEqual(r['tx_results'][0]['code'],1);self.assertTrue(r['validator_updates'])
    def test_cancel_after_emission_refused(self):
        self.step([self.raw]);self.step();self.step();self.reject(cancel(self.g,self.s,self.admins[:2]))
    def test_cancel_wrong_proposal_refused(self):
        self.step([self.raw]);self.reject(cancel(self.g,self.s,self.admins[:2],'00'*32))
    def test_cancel_then_reschedule_same_block_ordered(self):
        self.step([self.raw]);c=cancel(self.g,self.s,self.admins[:2]);anticipated=copy.deepcopy(self.s);anticipated['nonce']+=1
        # Author manually constructs the next-nonce command; a draft is not authority.
        b=json.loads(schedule(self.g,self.s,self.admins[:2],self.target,4))['body'];b['nonce']+=1
        r=self.step([c,approve(b,self.admins[:2])]);self.assertEqual([t['code'] for t in r['tx_results']],[0,0])
        self.assertEqual(self.s['pending']['emission_height'],4)
    def test_cancelled_schedule_cannot_be_replayed(self):
        self.step([self.raw]);self.step([cancel(self.g,self.s,self.admins[:2])]);self.reject(self.raw)
    def test_schedule_on_activation_height_cooldown(self):
        self.step([self.raw]);self.step();self.step();self.step()
        b=json.loads(self.raw)['body'];b.update(nonce=1,base_epoch=1,base_set_hash=ValidatorSet.parse(self.target).hash,valid_from=5,valid_until=20)
        b['operation']={'type':'schedule','emission_height':7,'validators':self.g['validators']}
        r=self.step([approve(b,self.admins[:2])]);self.assertEqual(r['tx_results'][0]['code'],1);self.assertEqual(self.s['epoch'],1)
    def test_add_remove_and_reweight_over_multiple_epochs(self):
        self.step([self.raw])
        for _ in range(4):self.step()
        self.step()
        remove=schedule(self.g,self.s,self.admins[:2],self.g['validators'],9)
        self.step([remove]);self.step();r=self.step()
        self.assertTrue(any(v['power']==0 for v in r['validator_updates']))
        self.step();self.step();self.step()
        reweighted=copy.deepcopy(self.g['validators']);reweighted[0]['power']=11;reweighted=canonical_roster(reweighted)
        self.step([schedule(self.g,self.s,self.admins[:2],reweighted,15)]);self.step();r=self.step()
        self.assertEqual(len(r['validator_updates']),1)
    def test_whole_roster_replacement_still_requires_admins(self):
        target=canonical_roster([{'public_key':pub(k),'power':10} for k in self.vals[4:]])
        r=schedule(self.g,self.s,self.admins[:2],target,3);self.step([r]);self.step();out=self.step()
        self.assertEqual(len(out['validator_updates']),8)
    def test_empty_small_duplicate_and_concentrated_rosters_refused(self):
        targets=[[],self.target[:3],self.target+[self.target[0]],
                 canonical_roster([{'public_key':pub(k),'power':100 if n==0 else 10} for n,k in enumerate(self.vals[:4])])]
        for target in targets:
            b=json.loads(self.raw)['body'];b['operation']['validators']=target
            with self.assertRaises(ValueError):decode_command(approve(b,self.admins[:2]),self.g)
    def test_administrator_cannot_also_be_new_validator(self):
        target=canonical_roster(self.target+[{'public_key':pub(self.admins[0]),'power':10}])
        self.reject(schedule(self.g,self.s,self.admins[:2],target))
    def test_unchanged_roster_refused(self):
        self.reject(schedule(self.g,self.s,self.admins[:2],self.g['validators']))
    def test_unknown_version_or_operation_refused(self):
        for change in ({'format':'p4-live'}, {'operation':{'type':'mint','units':100}}):
            b=json.loads(self.raw)['body'];b.update(change)
            with self.assertRaises(ValueError):decode_command(approve(b,self.admins[:2]),self.g)
    def test_noncanonical_and_duplicate_json_refused(self):
        for raw in (self.raw+b'\n',b'{"body":{},"body":{}}', b'not json'):
            with self.assertRaises(ValueError):decode_command(raw,self.g)
    def test_command_and_block_work_limits(self):
        with self.assertRaises(ValueError):decode_command(b'x'*65537,self.g)
        with self.assertRaises(ValueError):block_transition(self.g,self.s,1,'00'*32,[self.raw]*9)
    def test_restore_at_queued_emitted_and_activated_boundaries(self):
        self.step([self.raw])
        for _ in range(7):
            self.assertEqual(restore_state(self.g,self.s,state_hash(self.s)),self.s);self.step()
    def test_snapshot_mutation_cannot_be_rehashed_into_authority(self):
        self.step([self.raw]);self.step();self.step()
        for field,value in (('epoch',1),('nonce',999),('active_set',self.target),('pending',None),('receipts',[])):
            s=copy.deepcopy(self.s);s[field]=value
            with self.assertRaises(ValueError):restore_state(self.g,s,state_hash(s))
    def test_rehashed_receipt_with_forged_approval_refused(self):
        self.step([self.raw]);s=copy.deepcopy(self.s)
        s['receipts'][0]['envelope']['approvals'][0]['signature']='00'*64
        with self.assertRaises(ValueError):restore_state(self.g,s,state_hash(s))
    def test_invalid_empty_height_jump_and_negative_height(self):
        for h in (0,2,True,-1):
            with self.assertRaises(ValueError):block_transition(self.g,self.s,h,'00'*32,[])
    def test_capacity_refuses_commands_without_disabling_due_activation(self):
        self.step([self.raw])
        with patch('registry_rules.MAX_RECEIPTS',1):
            self.reject(cancel(self.g,self.s,self.admins[:2]))
            r=self.step();self.assertTrue(r['validator_updates']);self.step();self.step()
            self.assertEqual(self.s['epoch'],1)
    def test_inputs_are_not_modified_and_deterministic(self):
        before=encode(self.s);g=encode(self.g)
        a=block(self.g,self.s,[self.raw]);b=block(self.g,self.s,[self.raw])
        self.assertEqual(a,b);self.assertEqual(encode(self.s),before);self.assertEqual(encode(self.g),g)
    def test_no_clock_network_or_wallet_keys_used(self):
        with patch('socket.socket',side_effect=AssertionError('no network')),patch('time.time',side_effect=AssertionError('no clock')):
            self.step([self.raw]);self.step();self.step()
    def test_legacy_native_genesis_is_not_silently_upgraded(self):
        from native_core import NativeLedger
        with self.assertRaises(ValueError):NativeLedger(':memory:',self.g)
        legacy={'chain_id':'legacy','asset':'DEV','fee':2,'allocations':[{'public_key':pub(self.vals[0]),'units':1000}]}
        with self.assertRaises(ValueError):validate_genesis(legacy)
    def test_genesis_policy_fields_are_strict(self):
        for change in (('threshold',True),('threshold',1),('threshold',4)):
            g=copy.deepcopy(self.g);g['administrators'][change[0]]=change[1]
            with self.assertRaises(ValueError):validate_genesis(g)
        g=copy.deepcopy(self.g);g['validators'][0]['public_key']=pub(self.admins[0]);g['validators']=canonical_roster(g['validators'])
        with self.assertRaises(ValueError):validate_genesis(g)

if __name__=='__main__':unittest.main()
