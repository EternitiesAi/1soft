import json,unittest
import qualify as q
class ReceiptParserTests(unittest.TestCase):
    def valid_logs(self):
        m=q.profile_measurement()
        rust=''.join('test '+name+' ... '+('TREASURY_PROFILE '+json.dumps(m)+'\nok' if name.startswith('actual_') else 'ok')+'\n' for name in sorted(q.RUST_TESTS))
        fixtures='TREASURY_FIXTURES '+json.dumps({'actual_halo2_proofs':6,**m})+'\n'
        ledger=''.join(name+' (test_ledger.AtomicLedgerTests.'+name+') ... ok\n' for name in sorted(q.PYTHON_TESTS))+'\nRan 13 tests in 1.0s\n\nOK\n'
        return {'rust':rust,'fixtures':fixtures,'ledger':ledger,'build':''}
    def test_exact_rosters_and_profile_are_required(self):
        logs=self.valid_logs();self.assertEqual(q.parse_logs(logs)['actual_halo2_proofs'],7)
        for label in ['rust','ledger','fixtures']:
            for change in [lambda x:x.replace('3200','3136'),lambda x:x+'FAILED\n',lambda x:x.replace(' ... ok',' ... skipped')]:
                bad=dict(logs);bad[label]=change(logs[label])
                if bad[label]!=logs[label]:
                    with self.assertRaises(ValueError):q.parse_logs(bad)
    def test_duplicate_and_missing_test_execution_is_refused(self):
        logs=self.valid_logs()
        for label in ['rust','ledger']:
            for text in [logs[label].splitlines()[0]+'\n'+logs[label],'\n'.join(logs[label].splitlines()[1:])]:
                bad=dict(logs);bad[label]=text
                with self.assertRaises(ValueError):q.parse_logs(bad)
    def test_duplicate_measurement_keys_and_markers_are_refused(self):
        logs=self.valid_logs();m=logs['fixtures']
        for text in [m+m,m.replace('"actual_halo2_proofs": 6','"actual_halo2_proofs": 6, "actual_halo2_proofs": 6')]:
            bad=dict(logs,fixtures=text)
            with self.assertRaises(ValueError):q.parse_logs(bad)
    def test_boolean_instead_of_integer_proof_count_is_refused(self):
        logs=self.valid_logs();bad=dict(logs,fixtures=logs['fixtures'].replace('"actual_halo2_proofs": 6','"actual_halo2_proofs": true'))
        with self.assertRaises(ValueError):q.parse_logs(bad)
if __name__=='__main__':unittest.main()
