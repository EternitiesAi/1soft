"""Fault injection into the real owned gate, before any payment or key work."""
from contextlib import redirect_stdout
import io
import json
from pathlib import Path
import shutil
import sys
import tempfile
import unittest
from unittest.mock import patch
import merchant_proof_comet as gate


class Child:
    def __init__(self, *, stuck=False): self.running=True; self.stuck=stuck
    def poll(self): return None if self.running else 0
    def terminate(self): raise OSError('fixture termination failure')
    def wait(self, _):
        if self.running: raise TimeoutError('fixture still running')
    def kill(self):
        if self.stuck: raise OSError('fixture kill failure')
        self.running=False


class ProofCleanupTests(unittest.TestCase):
    def run_partial_start(self, children):
        with tempfile.TemporaryDirectory() as root:
            output=Path(root)/'out'
            class Network:
                def __init__(self, workspace, _):
                    self.root=workspace; self.apps=children; self.engines=[]
                def start(self): raise OSError('fixture partial startup failure')
                def stop(self): raise OSError('fixture shutdown failure')
            with patch.object(gate,'initialize'),patch.object(gate,'verify_engine'), \
                 patch.object(gate,'MerchantNetwork',Network), \
                 patch.object(sys,'argv',['fixture','not-an-engine',str(output)]),redirect_stdout(io.StringIO()):
                code=gate.main()
            report=json.loads((output/'actual-validator-result.json').read_bytes())
            runtime=Path(report['retained_private_runtime'])
            self.assertEqual(runtime.parent,Path(tempfile.gettempdir()).resolve())
            self.assertTrue(runtime.name.startswith('one-mproof-'))
            shutil.rmtree(runtime)
            self.assertEqual(code,1)
            return report

    def test_partial_start_handles_are_cleaned_even_when_network_stop_fails(self):
        child=Child();report=self.run_partial_start([child])
        self.assertFalse(child.running,'lost partial-start child bypassed fallback cleanup')
        self.assertEqual(report['owned_processes_after_cleanup'],0)
        self.assertIn('owned_child_required_kill',report['cleanup_errors'])

    def test_failed_kill_preserves_receipt_and_continues_remaining_children(self):
        healthy=Child();stuck=Child(stuck=True)
        report=self.run_partial_start([healthy,stuck])
        self.assertFalse(healthy.running)
        self.assertTrue(stuck.running)
        self.assertEqual(report['owned_processes_after_cleanup'],1)
        self.assertIn('owned_child_cleanup_failed',report['cleanup_errors'])


if __name__=='__main__':unittest.main()
