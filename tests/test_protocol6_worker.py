import os
import hashlib, os, tempfile, unittest
from pathlib import Path
from test_protocol6_treasury import FIX
try:
    from protocol6_worker import Worker,Unavailable
except ModuleNotFoundError:
    Worker=None
@unittest.skipUnless(os.environ.get('P6_WORKER') and os.environ.get('P6_WORKER_SHA256'),'unassessed: explicit P6 real-verifier inputs were not supplied')
class WorkerTests(unittest.TestCase):
    def setUp(self):self.assertIsNotNone(Worker,'P6 typed verifier bridge is missing')
    def test_actual_proof_invalid_is_distinct_from_unavailable(self):
        w=Worker(Path(os.environ['P6_WORKER']),os.environ['P6_WORKER_SHA256'],(FIX/'a.tx').read_bytes())
        self.assertTrue(w.verify((FIX/'a.tx').read_bytes()))
        raw=bytearray((FIX/'a.tx').read_bytes());raw[-1]^=1
        self.assertFalse(w.verify(bytes(raw)))
        with self.assertRaises(Unavailable):Worker(Path(os.environ['P6_WORKER']),'00'*32,(FIX/'a.tx').read_bytes())
    def test_failed_executable_or_unexpected_output_is_fatal(self):
        with tempfile.TemporaryDirectory() as d:
            for body in [b'#!/bin/sh\nexit 3\n',b'#!/bin/sh\nprintf INVALID\\n\n',b'#!/bin/sh\nprintf OK\\ntrailing\n']:
                f=Path(d)/'worker';f.write_bytes(body);f.chmod(0o700)
                with self.assertRaises(Unavailable):Worker(f,hashlib.sha256(body).hexdigest(),(FIX/'a.tx').read_bytes())
    def test_unknown_operation_and_oversized_input_never_execute(self):
        w=Worker(Path(os.environ['P6_WORKER']),os.environ['P6_WORKER_SHA256'],(FIX/'a.tx').read_bytes())
        for op,raw in [('fixtures',b''),('verify',b'x'*4097)]:
            with self.assertRaises(ValueError):w.call(op,raw)
if __name__=='__main__':unittest.main()
