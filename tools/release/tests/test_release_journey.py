import json
import unittest
from journey import run_journey


class IntegratedJourneyTests(unittest.TestCase):
    def check(self, compact):
        report = run_journey(compact)
        self.assertEqual(report['status'], 'passed')
        self.assertEqual(report['submission_count'], 2)
        self.assertEqual(report['final_wallet_pending'], 0)
        self.assertEqual(report['recorded_budget_spend'], 100)
        self.assertEqual(report['archived_receipts'], 2)
        self.assertGreater(report['observer_final_height'], report['snapshot_height'])
        self.assertFalse(report['consensus_executed'])
        print('INTEGRATED_JOURNEY=' + json.dumps(report, sort_keys=True), flush=True)

    def test_protocol_three_flat_complete_local_journey(self): self.check(False)
    def test_protocol_three_smt_complete_local_journey(self): self.check(True)


if __name__ == '__main__': unittest.main()
