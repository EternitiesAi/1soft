"""The actual-hour qualifier refuses shortened/synthetic acceptance requests."""
from pathlib import Path
import tempfile
import unittest
from alpha_acceptance import qualify_alpha,EXPECTED_CHECKS

class AlphaAcceptanceContract(unittest.TestCase):
    def test_duration_cannot_be_replaced_with_short_or_unbounded_run(self):
        with tempfile.TemporaryDirectory() as folder:
            for duration in (0,1,3599,3600,7201,True,3601.0):
                output=Path(folder)/'absent-output'
                with self.assertRaises(ValueError):qualify_alpha(Path(folder)/'missing-engine',output,duration_seconds=duration)
                self.assertFalse(output.exists())
    def test_acceptance_contract_has_exact_distinct_ids(self):
        self.assertEqual(len(EXPECTED_CHECKS),len(set(EXPECTED_CHECKS)))
        for case in ('actual_elapsed_over_one_hour','same_genesis_home_db_restart','post_hour_exact_native_execution','complete_encrypted_history_and_inert_recovery'):
            self.assertIn(case,EXPECTED_CHECKS)

if __name__=='__main__':unittest.main()
