"""Cleanup failure must not prevent other owned cleanup or leak diagnostics."""
import threading
import time
import unittest
try:
    from private_acceptance import stop_owned_web
except ImportError:
    stop_owned_web = None

class ThreadBoundary:
    def __init__(self): self.alive=True; self.joined=False
    def is_alive(self): return self.alive
    def join(self, _): self.joined=True; self.alive=False

class CleanupTests(unittest.TestCase):
    def setUp(self): self.assertIsNotNone(stop_owned_web, 'bounded resilient cleanup missing')

    def test_shutdown_error_still_closes_server_and_joins_thread(self):
        events=[]
        class Web:
            def shutdown(self): events.append('shutdown'); raise RuntimeError('secret failure text')
            def server_close(self): events.append('closed')
        thread=ThreadBoundary(); workers=[]; errors=[]
        stop_owned_web(Web(), thread, workers=workers, errors=errors, seconds=.1)
        self.assertEqual(['shutdown', 'closed'], events); self.assertTrue(thread.joined)
        self.assertEqual(['merchant_shutdown_failed'], errors)
        self.assertTrue(all(not t.is_alive() for t in workers))
        self.assertNotIn('secret', str(errors))

    def test_blocking_shutdown_is_bounded_and_explicitly_failed(self):
        release=threading.Event(); workers=[]; errors=[]
        class Web:
            def shutdown(self): release.wait(5)
            def server_close(self): pass
        started=time.monotonic()
        try:
            stop_owned_web(Web(), ThreadBoundary(), workers=workers, errors=errors, seconds=.05)
            self.assertLess(time.monotonic()-started, .5)
            self.assertIn('merchant_shutdown_incomplete', errors)
        finally:
            release.set()
            for t in workers: t.join(1)
        self.assertTrue(all(not t.is_alive() for t in workers))

    def test_close_failure_cannot_skip_thread_join(self):
        class Web:
            def shutdown(self): pass
            def server_close(self): raise OSError('private detail')
        thread=ThreadBoundary(); workers=[]; errors=[]
        stop_owned_web(Web(), thread, workers=workers, errors=errors, seconds=.1)
        self.assertTrue(thread.joined); self.assertEqual(['merchant_close_failed'], errors)

if __name__=='__main__': unittest.main()
