"""The actual-hour qualifier refuses shortened/synthetic acceptance requests."""
from pathlib import Path
import tempfile
import unittest
import subprocess
import sys
from alpha_acceptance import stop_with_facts,_birth
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

class ActualShutdownContract(unittest.TestCase):
    class Network:
        def __init__(self,process):self.apps=[process];self.engines=[]
        def stop(self):
            for p in self.apps:
                if p.poll() is None:p.terminate()
                p.wait(timeout=5)
            return {'warnings':[]}
    def test_unexpected_actual_child_exit_remains_failure_after_reap(self):
        p=subprocess.Popen([sys.executable,'-c','raise SystemExit(7)'])
        birth=_birth(p.pid);p.wait(timeout=5)
        rows=[{'pid':p.pid,'birth':birth}]
        self.assertFalse(stop_with_facts(self.Network(p),rows))
        self.assertEqual(rows[0]['returncode'],7);self.assertEqual(rows[0]['returncode_before_stop'],7)
        self.assertTrue(rows[0]['reaped']);self.assertFalse(rows[0]['expected_stop_outcome'])
    def test_owned_actual_running_child_has_expected_stop_outcome(self):
        p=subprocess.Popen([sys.executable,'-c','import time;time.sleep(10)'])
        try:
            rows=[{'pid':p.pid,'birth':_birth(p.pid)}]
            self.assertTrue(stop_with_facts(self.Network(p),rows))
            self.assertIsNone(rows[0]['returncode_before_stop']);self.assertTrue(rows[0]['expected_stop_outcome'])
            self.assertTrue(rows[0]['reaped']);self.assertFalse(rows[0]['same_birth_still_present'])
        finally:
            if p.poll() is None:p.terminate();p.wait(timeout=5)

if __name__=='__main__':unittest.main()
