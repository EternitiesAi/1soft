import copy
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
from commit_verifier import encode
from native_core import public,NativeLedger
from block_application import BlockApplication
from validator_sets import canonical_roster,ValidatorSet
from registry_rules import RegistryRules,RegistryReject,GENESIS_FORMAT,APP_VERSION,MAX_TX_BYTES
from registry_application import RegistryApplication
from registry_wire import encode_finalize,ResponseFinalizeBlock
from registry_fixture import fixture,authorize,schedule,apply,advance


class RuleTests(unittest.TestCase):
    def setUp(self):
        self.g,self.admins,self.vals,self.target=fixture();self.tmp=tempfile.TemporaryDirectory()
        self.app=RegistryApplication(Path(self.tmp.name)/'registry.sqlite',self.g,create=True)
    def tearDown(self):self.app.close();self.tmp.cleanup()
    def draft(self,**changes):
        op={'kind':'schedule','emitted_height':4,'target_validators':self.target}
        b=self.app.rules.body(self.app.state(),op,valid_from=1,valid_until=20)
        b.update(changes);return b
    def signed(self,body=None,keys=None):return authorize(self.app.rules,body or self.draft(),self.admins[:3] if keys is None else keys)
    def rejected(self,raw):
        before=encode(self.app.state());result=self.app.check_tx(raw)
        self.assertEqual(result['code'],1);self.assertEqual(before,encode(self.app.state()))
    def test_valid_approvals_schedule_without_activating(self):
        raw=self.signed();self.assertEqual(self.app.check_tx(raw)['code'],0)
        result=apply(self.app,[raw]);s=self.app.state()
        self.assertEqual(s['epoch'],0);self.assertEqual(s['pending']['phase'],'queued')
        self.assertEqual(result['validator_updates'],[]);self.assertEqual(s['sequence'],1)
    def test_timeline_emit_announce_activate_lastcommit(self):
        apply(self.app,[self.signed()]);advance(self.app,3);old=self.app.state()['active_hash'];new=ValidatorSet.parse(self.target).hash
        r4=apply(self.app);r5=apply(self.app);r6=apply(self.app);r7=apply(self.app)
        self.assertTrue(r4['validator_updates']);self.assertEqual((r4['validators_hash'],r4['next_validators_hash']),(old,old))
        self.assertEqual((r5['validators_hash'],r5['next_validators_hash']),(old,new))
        self.assertEqual((r6['validators_hash'],r6['next_validators_hash'],r6['epoch']),(new,new,1))
        self.assertEqual(r6['last_commit_validators_hash'],old);self.assertEqual(r7['last_commit_validators_hash'],new)
        self.assertEqual(r5['validator_updates'],[]);self.assertEqual(r6['validator_updates'],[])
    def test_below_threshold_refused(self):self.rejected(self.signed(keys=self.admins[:2]))
    def test_duplicate_signature_cannot_make_threshold(self):
        p=json.loads(self.signed());p['approvals'][2]=p['approvals'][0];self.rejected(encode(p))
    def test_unknown_administrator_refused(self):
        raw=authorize(self.app.rules,self.draft(),[self.admins[0],self.admins[1],self.vals[0]])
        self.rejected(raw)
    def test_all_signatures_checked_after_threshold(self):
        p=json.loads(self.signed(keys=self.admins));p['approvals'][-1]['signature']='00'*64;self.rejected(encode(p))
    def test_changed_recipient_roster_invalidates_authorization(self):
        p=json.loads(self.signed());p['body']['operation']['target_validators']=self.g['validators'];self.rejected(encode(p))
    def test_reversed_approval_order_refused(self):
        p=json.loads(self.signed());p['approvals'].reverse();self.rejected(encode(p))
    def test_wrong_signature_domain_refused(self):
        b=self.draft();p={'body':b,'approvals':sorted([{'public_key':public(k),'signature':k.sign(encode(b)).hex()} for k in self.admins[:3]],key=lambda a:a['public_key'])};self.rejected(encode(p))
    def test_genesis_and_policy_binding(self):
        for field in ('genesis_sha256','policy_sha256','chain_id'):
            with self.subTest(field=field):
                p=json.loads(self.signed());p['body'][field]='f'*64;self.rejected(encode(p))
    def test_exact_epoch_sequence_not_booleans(self):
        for field in ('schema','sequence','expected_epoch','valid_from','valid_until'):
            with self.subTest(field=field):
                p=json.loads(self.signed());p['body'][field]=True;self.rejected(encode(p))
    def test_no_implicit_clock_authorization(self):
        self.rejected(self.signed(self.draft(valid_from=2)))
        advance(self.app,21);self.rejected(self.signed(self.draft(valid_from=1,valid_until=20)))
    def test_signature_expiry_does_not_cancel_committed_schedule(self):
        body=self.draft(valid_from=1,valid_until=1);apply(self.app,[self.signed(body)]);advance(self.app,6)
        self.assertEqual(self.app.state()['epoch'],1)
    def test_noop_roster_refused(self):
        b=self.draft();b['operation']['target_validators']=self.g['validators'];self.rejected(self.signed(b))
    def test_minimum_delay_checked_at_inclusion_not_drafting(self):
        raw=self.signed();advance(self.app,2);self.rejected(raw)
    def test_schedule_too_far_away_refused(self):
        b=self.draft();b['operation']['emitted_height']=1026;self.rejected(self.signed(b))
    def test_pending_proposal_blocks_replacement(self):
        apply(self.app,[self.signed()]);self.rejected(schedule(self.app,self.admins,self.target,emitted=5))
    def test_two_same_sequence_requests_cannot_both_execute(self):
        raw=self.signed();result=apply(self.app,[raw,raw])
        self.assertEqual([r['code'] for r in result['tx_results']],[0,1]);self.assertEqual(self.app.state()['sequence'],1)
    def test_sequential_proposal_check_rejects_duplicate(self):
        raw=self.signed();self.assertFalse(self.app.process_proposal([raw,raw],1));self.assertEqual(self.app.state()['height'],0)
    def test_replay_cannot_reschedule_after_cancellation(self):
        raw=self.signed();p=apply(self.app,[raw])['tx_results'][0]['data']
        b=self.app.rules.body(self.app.state(),{'kind':'cancel','proposal_id':p},valid_from=2,valid_until=2)
        apply(self.app,[authorize(self.app.rules,b,self.admins[:3])]);self.rejected(raw)
        advance(self.app,7);self.assertEqual(self.app.state()['epoch'],0)
    def test_cancellation_before_emission_consumes_sequence_and_keeps_receipts(self):
        p=apply(self.app,[self.signed()])['tx_results'][0]['data'];head=self.app.state()['receipt_head']
        b=self.app.rules.body(self.app.state(),{'kind':'cancel','proposal_id':p},valid_from=2,valid_until=3)
        result=apply(self.app,[self.signed(b)])
        self.assertEqual(result['tx_results'][0]['code'],0);s=self.app.state();self.assertIsNone(s['pending'])
        self.assertEqual(s['sequence'],2);self.assertNotEqual(head,s['receipt_head']);advance(self.app,7)
        self.assertEqual(self.app.state()['active_validators'],self.g['validators'])
    def test_cancel_at_emission_too_late_and_does_not_consume_nonce(self):
        p=apply(self.app,[self.signed()])['tx_results'][0]['data'];advance(self.app,3)
        b=self.app.rules.body(self.app.state(),{'kind':'cancel','proposal_id':p},valid_from=4,valid_until=4)
        result=apply(self.app,[self.signed(b)])
        self.assertEqual(result['tx_results'][0]['code'],1);self.assertTrue(result['validator_updates'])
        self.assertEqual(self.app.state()['sequence'],1);advance(self.app,6);self.assertEqual(self.app.state()['epoch'],1)
    def test_cancel_wrong_proposal_refused(self):
        apply(self.app,[self.signed()]);b=self.app.rules.body(self.app.state(),{'kind':'cancel','proposal_id':'f'*64},valid_from=2,valid_until=2)
        self.rejected(self.signed(b))
    def test_cancellation_is_not_free_override_without_threshold(self):
        p=apply(self.app,[self.signed()])['tx_results'][0]['data']
        b=self.app.rules.body(self.app.state(),{'kind':'cancel','proposal_id':p},valid_from=2,valid_until=2)
        self.rejected(self.signed(b,keys=self.admins[:2]))
    def test_stale_epoch_after_activation_refused_even_correct_sequence(self):
        apply(self.app,[self.signed()]);old=self.app.state();advance(self.app,6)
        b=self.app.rules.body(old,{'kind':'schedule','emitted_height':10,'target_validators':self.g['validators']},valid_from=7,valid_until=9)
        self.rejected(self.signed(b))
    def test_second_change_including_full_replacement(self):
        apply(self.app,[self.signed()]);advance(self.app,6)
        replacement=canonical_roster([{'public_key':public(k),'power':10} for k in self.vals[6:10]])
        raw=schedule(self.app,self.admins,replacement,emitted=9,valid_from=7,valid_until=7)
        self.assertEqual(apply(self.app,[raw])['tx_results'][0]['code'],0);advance(self.app,11)
        self.assertEqual(self.app.state()['epoch'],2);self.assertEqual(self.app.state()['active_validators'],replacement)
    def test_new_validators_must_not_reuse_admin_keys(self):
        target=canonical_roster([{'public_key':public(k),'power':10} for k in [self.admins[0],*self.vals[:3]]])
        b=self.draft();b['operation']['target_validators']=target
        with self.assertRaises(ValueError):self.signed(b)
    def test_invalid_genesis_authority_policy(self):
        for mutate in (
            lambda g:g.update(mode='mainnet'),lambda g:g.update(schema=True),
            lambda g:g['administrators'].update(threshold=2),lambda g:g['administrators'].update(threshold=True),
            lambda g:g['administrators']['public_keys'].append(g['administrators']['public_keys'][0]),
            lambda g:g.update(protocol_version=4),lambda g:g.update(minimum_delay_blocks=0)):
            g=copy.deepcopy(self.g);mutate(g)
            with self.assertRaises(ValueError):RegistryRules(g)
    def test_minimum_roster_and_concentration(self):
        for rows in (self.g['validators'][:3],canonical_roster([{'public_key':public(k),'power':p} for k,p in zip(self.vals[:4],(50,10,10,10))])):
            g=copy.deepcopy(self.g);g['validators']=rows
            with self.assertRaises(ValueError):RegistryRules(g)
    def test_legacy_native_ledger_refuses_registry_genesis(self):
        with self.assertRaises(ValueError):NativeLedger(':memory:',self.g)
        legacy=BlockApplication(':memory:',expected_genesis=self.g)
        try:
            with self.assertRaises(ValueError):legacy.init_chain(self.g['chain_id'],self.g)
        finally:legacy.close()
    def test_legacy_action_cannot_change_registry(self):
        self.rejected(encode({'body':{'version':3,'op':{'type':'transfer'}},'signature':'00'*64}))
    def test_codec_contains_full_apphash_results_and_updates(self):
        apply(self.app,[self.signed()]);advance(self.app,3);result=apply(self.app)
        wire=encode_finalize(result);decoded=ResponseFinalizeBlock.FromString(wire)
        self.assertEqual(decoded.app_hash.hex(),result['app_hash']);self.assertEqual(len(decoded.validator_updates),len(result['validator_updates']))
        self.assertEqual(wire,encode_finalize(self.app.committed_result(4)))
    def test_output_changes_cannot_mutate_pending_state(self):
        raw=self.signed();result=self.app.finalize_block([raw],1,b'a'*32);result['validator_updates']=[{}]
        self.app.commit();self.assertEqual(self.app.committed_result(1)['validator_updates'],[])
    def test_genesis_and_state_inputs_are_detached(self):
        self.g['validators'].clear();state=self.app.state();state['epoch']=999
        self.assertEqual(len(self.app.rules.genesis['validators']),4);self.assertEqual(self.app.state()['epoch'],0)
    def test_noncanonical_or_duplicate_json_not_accepted(self):
        self.rejected(self.signed()+b'\n');self.rejected(b'{"body":{},"body":{},"approvals":[]}')
    def test_transaction_and_block_size_limits(self):
        with self.assertRaises(ValueError):self.app.check_tx(b'x'*(MAX_TX_BYTES+1))
        with self.assertRaises(ValueError):self.app.finalize_block([b'{}']*9,1,b'a'*32)
    def test_determinism_across_fresh_applications(self):
        raw=self.signed();second=RegistryApplication(Path(self.tmp.name)/'other.sqlite',self.app.rules.genesis,create=True)
        try:
            for h in range(1,9):
                txs=[raw] if h==1 else []
                self.assertEqual(apply(self.app,txs),apply(second,txs));self.assertEqual(self.app.state(),second.state())
        finally:second.close()
    def test_stale_sequence_cannot_reschedule_after_cancel(self):
        b=self.draft();b['operation']['emitted_height']=10;raw=self.signed(b)
        proposal=apply(self.app,[raw])['tx_results'][0]['data']
        cancel=self.app.rules.body(self.app.state(),{'kind':'cancel','proposal_id':proposal},valid_from=2,valid_until=2)
        apply(self.app,[self.signed(cancel)]);self.rejected(raw)
    def test_bad_request_does_not_consume_authorization_sequence(self):
        raw=self.signed();r=apply(self.app,[b'{}',raw])
        self.assertEqual([t['code'] for t in r['tx_results']],[1,0]);self.assertEqual(self.app.state()['sequence'],1)
    def test_alternate_valid_approval_subset_is_not_a_second_action(self):
        raw=self.signed();alternative=self.signed(keys=self.admins[1:]);self.assertNotEqual(raw,alternative)
        r=apply(self.app,[raw,alternative]);self.assertEqual([t['code'] for t in r['tx_results']],[0,1])
    def test_policy_cooldown_blocks_immediate_second_change(self):
        # New explicitly selected development genesis, not editing a saved policy.
        g=copy.deepcopy(self.g);g['cooldown_blocks']=3
        app=RegistryApplication(Path(self.tmp.name)/'cooldown.sqlite',g,create=True)
        try:
            first=schedule(app,self.admins,self.target);apply(app,[first]);advance(app,6)
            raw=schedule(app,self.admins,g['validators'],emitted=12,valid_from=7,valid_until=9)
            self.assertEqual(app.check_tx(raw)['code'],1);advance(app,8);self.assertEqual(app.check_tx(raw)['code'],0)
        finally:app.close()
    def test_future_activation_cannot_be_inferred_from_checktx(self):
        self.queue_for_test=self.signed();self.assertEqual(self.app.check_tx(self.queue_for_test)['code'],0)
        advance(self.app,7);self.assertEqual(self.app.state()['epoch'],0);self.assertIsNone(self.app.state()['pending'])
    def test_no_key_unlock_or_network(self):
        with (patch('socket.socket',side_effect=AssertionError('no network')),
              patch('certified_wallet._load_vault',side_effect=AssertionError('no wallet'))):
            apply(self.app,[self.signed()]);advance(self.app,7)

if __name__=='__main__':unittest.main()
