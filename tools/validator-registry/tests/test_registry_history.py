import copy
import tempfile
from pathlib import Path
import unittest
from registry_history_fixture import history_case
from registry_evidence import verify_registry_history
from commit_verifier import encode
from registry_wire import encode_finalize

class RegistryHistoryTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        with tempfile.TemporaryDirectory() as d:cls.case=history_case(Path(d)/'reg.sqlite')
    def verify(self,snapshot=None,witness=None,policy=None,now=None):
        c=self.case
        return verify_registry_history(c['snapshot'] if snapshot is None else snapshot,
                c['witness'] if witness is None else witness,c['engine_genesis'],c['policy'] if policy is None else policy,
                now_ns=c['now_ns'] if now is None else now)
    def test_executed_governance_bound_to_signed_header_history(self):
        r=self.verify();self.assertTrue(r['registry_administrative_authorization_verified'])
        self.assertTrue(r['activation_schedule_verified']);self.assertEqual(r['epoch'],1)
        self.assertFalse(r['native_payment_state_verified']);self.assertFalse(r['consensus_executed'])
    def test_corrupted_approvals_cannot_hide_behind_valid_committee(self):
        s=copy.deepcopy(self.case['snapshot']);import base64,json
        b=s['blocks'][0];p=json.loads(base64.b64decode(b['transactions'][0]));p['approvals'][0]['signature']='00'*64
        b['transactions'][0]=base64.b64encode(encode(p)).decode()
        with self.assertRaises(ValueError):self.verify(snapshot=s)
    def test_fake_block_hash_rejected_despite_same_application_state(self):
        s=copy.deepcopy(self.case['snapshot']);s['blocks'][2]['block_hash']='ff'*32
        with self.assertRaisesRegex(ValueError,'signed block'):self.verify(snapshot=s)
    def test_missing_signed_header_is_not_silently_trusted(self):
        w=copy.deepcopy(self.case['witness']);w['entries'].pop(3)
        with self.assertRaises(ValueError):self.verify(witness=w)
    def test_expired_policy_is_not_renewed_by_governance_approvals(self):
        with self.assertRaises(ValueError):self.verify(now=self.case['now_ns']+3600*10**9)
    def test_other_application_version_not_accepted(self):
        p=copy.deepcopy(self.case['policy']);p['expected_app_version']=3
        with self.assertRaises(ValueError):self.verify(policy=p)
    def test_caller_mutation_after_verification_does_not_change_verified_copy(self):
        from unittest.mock import patch
        import registry_evidence
        w=copy.deepcopy(self.case['witness']);actual=registry_evidence.verify_witness
        def modify(*args,**kwargs):
            result=actual(*args,**kwargs)
            w['entries'][0]['signed_header']['header']['app_hash']='f'*64
            return result
        with patch('registry_evidence.verify_witness',side_effect=modify):
            self.assertTrue(self.verify(witness=w)['registry_administrative_authorization_verified'])
    def test_wire_vectors_include_one_actual_emission_only(self):
        responses=self.case['responses'];encoded=[encode_finalize(r) for r in responses]
        self.assertEqual([r['height'] for r in responses if r['validator_updates']],[4])
        self.assertEqual(len(encoded),7)
    def test_old_witness_report_not_relabelled_native_state_verified(self):
        r=self.verify();self.assertFalse(r['validator_history']['native_state_verified'])
        self.assertFalse(r['validator_history']['governance_authorization_established'])
        self.assertTrue(r['registry_administrative_authorization_verified'])

if __name__=='__main__':unittest.main()
