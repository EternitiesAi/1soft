"""Synthetic committee signatures over actual P4 application execution, not consensus."""
import base64
import copy
import hashlib
import unittest
from unittest.mock import patch

from block_application import BlockApplication, encode
from commit_verifier import header_hash, load_json, merkle_root, sha, trust_from_genesis
from native_core import canonical
from p4_evidence import (MAX_EVIDENCE_BYTES, content_id, nanos, p4_genesis, policy_checked,
                          verify_account, verify_evidence, verify_receipt)
from p4_fixture import build, bundle, rechain, sign_header
from validator_sets_core import ValidatorSet


class EvidenceTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.c = build()
        cls.e = bundle(cls.c)
    def verify(self, value=None, policy=None, now=None):
        return verify_evidence(self.e if value is None else value, self.c['genesis'],
            self.c['policy'] if policy is None else policy,
            now_ns=self.c['now_ns'] if now is None else now)
    def changed(self): return copy.deepcopy(self.e)
    def sign_changed(self, e): return rechain(e, self.c['keys'])
    def account(self, account=None, evidence=None):
        return verify_account(self.e if evidence is None else evidence, self.c['genesis'],
            self.c['policy'], self.c['payer'] if account is None else account, now_ns=self.c['now_ns'])
    def receipt(self, raw, payer=None, evidence=None):
        return verify_receipt(self.e if evidence is None else evidence, self.c['genesis'],
            self.c['policy'], raw, payer=self.c['payer'] if payer is None else payer, now_ns=self.c['now_ns'])

    def test_native_money_and_governance_verified_across_two_handovers(self):
        r = self.verify()
        self.assertEqual(r['status'], 'verified-p4-historical-state')
        self.assertEqual((r['state_height'], r['header_height'], r['registry_epoch']), (16, 17, 2))
        self.assertEqual([t['height'] for t in r['validator_transitions']], [6, 14])
        self.assertEqual([u['emitted_height'] for u in r['validator_updates']], [4, 12])
        self.assertTrue(r['native_execution_replayed']); self.assertTrue(r['registry_authorization_replayed'])
    def test_full_roster_replacement_does_not_need_old_signers(self):
        e = self.e
        old = {v['public_key'] for v in e['headers'][0]['validators']}
        new = {v['public_key'] for v in e['headers'][-1]['validators']}
        self.assertFalse(old & new); self.assertEqual(self.verify()['verified_headers'], 17)
    def test_recorded_account_and_shared_budget_values(self):
        r = self.verify(); a = self.account()['account']
        self.assertEqual(a['recorded_balance'], '874'); self.assertEqual(a['nonce'], 4)
        self.assertEqual(r['recorded_supply_units'], '1000')
        self.assertEqual(r['budgets'][0][4], 100)
        self.assertFalse(r['pending_wallet_debits_included']); self.assertFalse(r['spending_authority'])
    def test_positive_receipts_before_and_after_replacement(self):
        for name, height in (('before', 1), ('raven', 2), ('after', 7), ('replacement', 15)):
            with self.subTest(name=name):
                r = self.receipt(self.c['wires'][name])
                self.assertEqual(r['status'], 'recorded'); self.assertEqual(r['receipt']['height'], height)
                self.assertFalse(r['wallet_reservations_changed'])
    def test_snapshot_replay_without_signed_history_refused(self):
        e = self.changed(); del e['headers']
        with self.assertRaises(ValueError): self.verify(e)
    def test_h_plus_one_not_reported_as_executed(self):
        r = self.verify()
        self.assertTrue(all(a['height'] <= 16 for a in r['attempts']))
        self.assertFalse(r['actual_abci_responses_observed']); self.assertFalse(r['latest_state_guaranteed'])
        self.assertFalse(r['independent_validator_hosts_verified'])
    def test_unknown_account_is_not_a_zero_balance(self):
        r = self.account('unknown-account')
        self.assertEqual(r['status'], 'unavailable'); self.assertIsNone(r['account'])
        self.assertFalse(r['spending_authority'])
    def test_later_payment_not_yet_in_checkpoint_remains_unknown(self):
        r = self.receipt(self.c['wires']['replacement'], evidence=bundle(self.c, 8))
        self.assertEqual(r['status'], 'unavailable'); self.assertFalse(r['historical_absence_proven'])
    def test_wrong_payer_refused(self):
        with self.assertRaises(ValueError): self.receipt(self.c['wires']['after'], payer=self.c['merchant'])
    def test_same_body_changed_signature_does_not_match_receipt(self):
        p = load_json(self.c['wires']['after']); p['signature'] = '0' * 128
        r = self.receipt(canonical(p))
        self.assertEqual(r['status'], 'unavailable'); self.assertIsNone(r['receipt'])
    def test_administrative_approval_is_not_payment_receipt(self):
        with self.assertRaises(ValueError): self.receipt(self.c['wires']['schedule2'])
    def test_noncanonical_signed_transaction_refused(self):
        with self.assertRaises(ValueError): self.receipt(self.c['wires']['after'] + b'\n')
    def test_view_dictionary_cannot_be_submitted_as_verified_evidence(self):
        r = self.verify()
        with self.assertRaises(ValueError): self.account(evidence=r)
    def test_original_input_objects_not_mutated(self):
        before = encode(self.e); beforep = encode(self.c['policy']); self.verify()
        self.assertEqual(encode(self.e), before); self.assertEqual(encode(self.c['policy']), beforep)
    def test_wrong_genesis_bytes_or_digest_refused(self):
        with self.assertRaises(ValueError):
            verify_evidence(self.e, self.c['genesis'] + b' ', self.c['policy'], now_ns=self.c['now_ns'])
    def test_genesis_validator_power_mismatch_even_when_file_repinned(self):
        engine = load_json(self.c['genesis']); engine['validators'][0]['power'] = '11'
        raw = encode(engine); p = {**self.c['policy'], 'genesis_sha256': hashlib.sha256(raw).hexdigest()}
        with self.assertRaises(ValueError): verify_evidence(self.e, raw, p, now_ns=self.c['now_ns'])
    def test_height_one_previous_block_refused_before_quorum_verification(self):
        e=self.changed()
        e['headers'][0]['signed_header']['header']['last_block_id']={
            'hash':'AA'*32,'parts':{'total':1,'hash':'BB'*32}}
        h=e['headers'][7]['signed_header']['header']
        policy={**self.c['policy'],'anchor_height':8,'anchor_hash':header_hash(h).hex(),'anchor_time':h['time']}
        with self.assertRaisesRegex(ValueError,'previous block|earlier'):self.verify(e,policy=policy)

    def test_wrong_anchor_hash_refused(self):
        with self.assertRaises(ValueError): self.verify(policy={**self.c['policy'], 'anchor_hash':'0'*64})
    def test_wrong_anchor_time_refused(self):
        p = {**self.c['policy'], 'anchor_time': self.e['headers'][1]['signed_header']['header']['time']}
        with self.assertRaises(ValueError): self.verify(policy=p)
    def test_external_anchor_not_yet_reached_refused(self):
        p = {**self.c['policy'], 'anchor_height':100}
        with self.assertRaises(ValueError): self.verify(policy=p)
    def test_later_out_of_band_anchor_still_requires_complete_history(self):
        entry = self.e['headers'][7]['signed_header']['header']
        p = {**self.c['policy'], 'anchor_height':8, 'anchor_hash':header_hash(entry).hex(), 'anchor_time':entry['time']}
        self.assertEqual(self.verify(policy=p)['state_height'], 16)
        e = self.changed(); e['headers'] = e['headers'][7:]
        with self.assertRaises(ValueError): self.verify(e, policy=p)
    def test_expiry_exactly_at_boundary_is_refused(self):
        p = self.c['policy']; expiry = nanos(p['anchor_time']) + p['trust_period_seconds']*10**9
        with self.assertRaises(ValueError): self.verify(now=expiry)
    def test_future_and_preanchor_clocks_refused(self):
        with self.assertRaises(ValueError): self.verify(now=nanos(self.c['policy']['anchor_time'])-1)
        p = {**self.c['policy'], 'max_clock_drift_seconds':0}
        with self.assertRaises(ValueError): self.verify(policy=p, now=nanos(p['anchor_time']))
    def test_boolean_numeric_policy_or_state_refused(self):
        for field in ('schema','anchor_height','trust_period_seconds','max_clock_drift_seconds','expected_block_version'):
            with self.subTest(field=field), self.assertRaises(ValueError):
                self.verify(policy={**self.c['policy'], field:True})
        e = self.changed(); e['state']['height'] = True
        with self.assertRaises(ValueError): self.verify(e)
    def test_unsupported_schema_or_untrusted_authority_fields_refused(self):
        for mutation in ({'schema':2}, {'paid':True}, {'policy':self.c['policy']}):
            with self.subTest(mutation=mutation), self.assertRaises(ValueError): self.verify({**self.e, **mutation})
    def test_missing_final_header_refused(self):
        e = self.changed(); e['headers'].pop()
        with self.assertRaises(ValueError): self.verify(e)
    def test_missing_or_reordered_transaction_history_refused(self):
        e = self.changed(); e['history'].pop(3)
        with self.assertRaises(ValueError): self.verify(e)
        e = self.changed(); e['history'][4],e['history'][5]=e['history'][5],e['history'][4]
        with self.assertRaises(ValueError): self.verify(e)
    def test_boolean_history_height_refused(self):
        e = self.changed(); e['history'][0]['height']=True
        with self.assertRaises(ValueError): self.verify(e)
    def test_changed_transaction_bytes_refused_by_data_root(self):
        e = self.changed(); e['history'][6]['txs']=[base64.b64encode(self.c['wires']['raven']).decode()]
        with self.assertRaisesRegex(ValueError, 'signed block data'): self.verify(e)
    def test_unknown_block_extra_is_not_trusted_history(self):
        e = self.changed(); e['history'][0]['votes']=[]
        with self.assertRaises(ValueError): self.verify(e)
    def test_forged_signature_after_threshold_still_refused(self):
        e = self.changed(); e['headers'][6]['signed_header']['commit']['signatures'][-1]['signature']='AA=='
        with self.assertRaises(ValueError): self.verify(e)
    def test_exact_two_thirds_is_not_quorum(self):
        c = build(count=8, validator_count=6); e = bundle(c); entry = e['headers'][6]
        entry['signed_header']=sign_header(entry['signed_header']['header'],ValidatorSet.parse(entry['validators']), c['keys'],[2,2,2,2,1,1])
        with self.assertRaisesRegex(ValueError, 'committing power'):
            verify_evidence(e,c['genesis'],c['policy'],now_ns=c['now_ns'])
    def test_nil_vote_does_not_count_as_committing_power(self):
        e = self.changed(); entry = e['headers'][6]
        entry['signed_header'] = sign_header(entry['signed_header']['header'], ValidatorSet.parse(entry['validators']), self.c['keys'], [2,2,3,3])
        with self.assertRaisesRegex(ValueError, 'committing power'): self.verify(e)
    def test_alternate_valid_quorum_subset_is_accepted(self):
        e = self.changed()
        for entry in e['headers']:
            entry['signed_header'] = sign_header(entry['signed_header']['header'], ValidatorSet.parse(entry['validators']), self.c['keys'], [2,2,2,1])
        self.assertEqual(self.verify(e)['app_hash'], self.e['state']['app_hash'])
    def test_signature_slots_cannot_be_reordered(self):
        e = self.changed(); e['headers'][6]['signed_header']['commit']['signatures'].reverse()
        with self.assertRaises(ValueError): self.verify(e)
    def test_successor_roster_must_match_prior_next_commitment(self):
        e = self.changed(); entry=e['headers'][6]; entry['validators']=e['headers'][0]['validators']
        entry['signed_header']['header']['validators_hash']=ValidatorSet.parse(entry['validators']).hash.upper()
        entry['signed_header']['header']['proposer_address']=ValidatorSet.parse(entry['validators']).validators[0].address.hex().upper()
        self.sign_changed(e)
        with self.assertRaisesRegex(ValueError, 'unannounced'): self.verify(e)
    def test_complete_parent_parts_id_checked_not_only_hash(self):
        e = self.changed(); entry=e['headers'][6]
        entry['signed_header']['header']['last_block_id']['parts']['hash']='FE'*32
        entry['signed_header']=sign_header(entry['signed_header']['header'],ValidatorSet.parse(entry['validators']), self.c['keys'])
        with self.assertRaisesRegex(ValueError,'previous block ID'): self.verify(e)
    def test_validly_signed_but_false_composite_state_refused(self):
        e=self.changed(); e['state']['native']['accounts'][0][4]+=1
        from protocol4_application import application_hash
        e['state']['app_hash']=application_hash(self.c['g'],16,{'native':e['state']['native'],'registry':e['state']['registry']})
        e['headers'][-1]['signed_header']['header']['app_hash']=e['state']['app_hash'].upper()
        self.sign_changed(e)
        with self.assertRaisesRegex(ValueError,'composite execution'): self.verify(e)
    def test_valid_quorum_cannot_replace_admin_authorization(self):
        e=self.changed(); row=e['history'][1]; packet=load_json(base64.b64decode(row['txs'][0]))
        packet['approvals']=packet['approvals'][:2];row['txs'][0]=base64.b64encode(encode(packet)).decode()
        e['headers'][1]['signed_header']['header']['data_hash']=merkle_root([sha(base64.b64decode(t)) for t in row['txs']]).hex().upper()
        self.sign_changed(e)
        with self.assertRaisesRegex(ValueError,'composite execution'): self.verify(e)
    def test_validly_signed_early_activation_is_not_registry_execution(self):
        e=self.changed()
        # Begin the new roster a block early while keeping header-to-header roster
        # commitments internally consistent; deterministic governance still refuses.
        new=e['headers'][5]['validators']
        e['headers'][3]['next_validators']=new
        e['headers'][3]['signed_header']['header']['next_validators_hash']=ValidatorSet.parse(new).hash.upper()
        e['headers'][4]['validators']=new
        e['headers'][4]['signed_header']['header']['validators_hash']=ValidatorSet.parse(new).hash.upper()
        e['headers'][4]['signed_header']['header']['proposer_address']=ValidatorSet.parse(new).validators[0].address.hex().upper()
        self.sign_changed(e)
        with self.assertRaisesRegex(ValueError,'roster schedule'): self.verify(e)
    def test_rejected_replay_in_signed_block_is_not_second_receipt(self):
        c=build(count=16,rejected=True);r=verify_evidence(bundle(c),c['genesis'],c['policy'],now_ns=c['now_ns'])
        self.assertEqual(len(r['receipts']),6)
        rejected=[a for a in r['attempts'] if a['height']==8]
        self.assertEqual(len(rejected),1);self.assertEqual(rejected[0]['code'],1)
    def test_size_bound_refuses_before_replay(self):
        e=self.changed();e['large']='x'*(MAX_EVIDENCE_BYTES+1)
        with self.assertRaises(ValueError): self.verify(e)
    def test_no_rpc_or_vault_access_during_read_verification(self):
        with patch('socket.socket',side_effect=AssertionError('network not permitted')), \
             patch('certified_wallet._load_vault',side_effect=AssertionError('private key not permitted')):
            self.verify()
    def test_legacy_node_and_static_trust_continue_refusing_p4(self):
        with self.assertRaisesRegex(ValueError,'refuses'): BlockApplication(':memory:',expected_genesis=self.c['g'])
        with self.assertRaisesRegex(ValueError,'static trust'): trust_from_genesis(load_json(self.c['genesis']))
    def test_legacy_signer_refuses_p4_before_private_key_load(self):
        from offline_signer import approve_intent
        from pathlib import Path
        with patch('offline_signer._load_vault',side_effect=AssertionError('never unlock')):
            with self.assertRaisesRegex(ValueError,'refuses protocol 4'):
                approve_intent(Path('/unused'),b'not-password',self.c['g'],load_json(self.c['wires']['after'])['body'],'00'*32,'not-approval')


if __name__ == '__main__': unittest.main()
