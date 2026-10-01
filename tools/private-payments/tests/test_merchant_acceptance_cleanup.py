"""Owned-handle fallback cleanup must survive one broken process boundary."""
import subprocess
from pathlib import Path
import tempfile
import unittest
from merchant_acceptance import cleanup_owned_native,cleanup_owned_runtime,owned_remaining


class Process:
    def __init__(self, *, broken_terminate=False, slow=False):
        self.alive=True;self.broken_terminate=broken_terminate;self.slow=slow;self.killed=False
    def poll(self): return None if self.alive else 0
    def terminate(self):
        if self.broken_terminate: raise RuntimeError('private error text')
        if not self.slow:self.alive=False
    def kill(self):self.killed=True;self.alive=False
    def wait(self,timeout):
        if self.alive:raise subprocess.TimeoutExpired('owned fixture',timeout)
        return 0


class CleanupTests(unittest.TestCase):
    def test_one_terminate_failure_still_cleans_every_original_handle(self):
        children=[Process(broken_terminate=True),Process()];errors=[]
        cleanup_owned_native(children,errors=errors,seconds=.01)
        self.assertTrue(all(p.poll() is not None for p in children))
        self.assertTrue(children[0].killed)
        self.assertIn('owned_native_terminate_failed',errors)
        self.assertNotIn('private error text',str(errors))

    def test_timeout_uses_original_handle_and_retains_failure_category(self):
        p=Process(slow=True);errors=[]
        cleanup_owned_native([p],errors=errors,seconds=.01)
        self.assertTrue(p.killed);self.assertEqual(0,p.poll())
        self.assertIn('owned_native_required_kill',errors)

    def test_stopped_handle_is_not_signaled_again(self):
        p=Process();p.alive=False;errors=[]
        cleanup_owned_native([p],errors=errors,seconds=.01)
        self.assertFalse(p.killed);self.assertEqual([],errors)

    def test_runtime_is_retained_while_owned_process_is_alive(self):
        with tempfile.TemporaryDirectory(prefix='one-merchant-') as raw:
            root=Path(raw);errors=[]
            self.assertFalse(cleanup_owned_runtime(root,children=[Process()],threads=[],errors=errors))
            self.assertTrue(root.exists());self.assertEqual([],errors)

    def test_runtime_is_retained_after_cleanup_error(self):
        with tempfile.TemporaryDirectory(prefix='one-merchant-') as raw:
            root=Path(raw);errors=['native_cleanup_failed']
            self.assertFalse(cleanup_owned_runtime(root,children=[],threads=[],errors=errors))
            self.assertTrue(root.exists())

    def test_clean_owned_runtime_is_removed(self):
        root=Path(tempfile.mkdtemp(prefix='one-merchant-'));errors=[]
        self.assertTrue(cleanup_owned_runtime(root,children=[],threads=[],errors=errors))
        self.assertFalse(root.exists());self.assertEqual([],errors)

    def test_unavailable_handle_state_is_a_retained_failed_cleanup(self):
        class Unavailable:
            def poll(self):raise OSError('private diagnostic')
        errors=[]
        self.assertEqual((1,0),owned_remaining([Unavailable()],[],errors=errors))
        self.assertEqual(['owned_native_state_unavailable'],errors)
        with tempfile.TemporaryDirectory(prefix='one-merchant-') as raw:
            self.assertFalse(cleanup_owned_runtime(Path(raw),children=[Unavailable()],threads=[],errors=[]))
            self.assertTrue(Path(raw).exists())


if __name__=='__main__':unittest.main()
