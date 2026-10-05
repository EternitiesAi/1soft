import copy,json,unittest
import qualify as q

class ProofEvidenceGateTests(unittest.TestCase):
    def fixture(self):
        p=q.read_json(q.PROFILE)
        measured={'actual_halo2_proofs':5,'proof_bytes':3136,'same_parent_orders':2,
                  'stale_rejected':True,'revoked_rejected':True,'refreshed_survivor_accepted':True,
                  'exact_parent_exhaustion':True,'parameter_sha256':p['parameter_sha256'],
                  'verifying_key_sha256':p['verifying_key_sha256']}
        def log(value):
            ordinary=''.join('test '+name+' ... ok\n' for name in sorted(q.EXPECTED_TESTS)
                             if name!='actual_proofs_bind_shared_current_state_and_ordered_revocation')
            return ordinary+'test actual_proofs_bind_shared_current_state_and_ordered_revocation ... AUTHORITY_EVIDENCE '+json.dumps(value)+'\nok\n'
        return measured,log

    def test_complete_actual_proof_roster_passes(self):
        measured,log=self.fixture();self.assertEqual(q.parse_log(log(measured)),measured)

    def test_every_measurement_and_type_is_bound(self):
        measured,log=self.fixture()
        for key,value in measured.items():
            with self.subTest(key=key):
                changed=copy.deepcopy(measured)
                changed[key]=1 if isinstance(value,bool) else (value+1 if isinstance(value,int) else '0'*64)
                with self.assertRaises(ValueError):q.parse_log(log(changed))
        changed=copy.deepcopy(measured);changed['extra']=True
        with self.assertRaises(ValueError):q.parse_log(log(changed))

    def test_omission_duplication_ignored_and_failure_are_refused(self):
        measured,log=self.fixture();valid=log(measured)
        first=valid.splitlines()[0]
        for bad in [valid.replace(first+'\n',''),valid+first+'\n',valid.replace(first,first.replace('ok','ignored')),
                    valid+'\nFAILED\n',valid.replace('AUTHORITY_EVIDENCE','MISSING'),valid+valid]:
            with self.subTest(log=bad[:40]):
                with self.assertRaises(ValueError):q.parse_log(bad)

    def test_duplicate_json_keys_are_refused(self):
        with self.assertRaises(ValueError):json.loads('{"a":1,"a":1}',object_pairs_hook=q.duplicate_safe)

if __name__=='__main__':unittest.main()
