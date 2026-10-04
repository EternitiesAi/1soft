"""Finite reads for the actual fixture's owned IPC channel, including partial lines."""
import os,time,unittest
from alpha_resource_browser_fixture import ControlReader

class ResourceBrowserControlTests(unittest.TestCase):
    def pipe(self):
        read,write=os.pipe();stream=os.fdopen(read,'rb',buffering=0)
        self.addCleanup(stream.close);self.addCleanup(os.close,write)
        return ControlReader(stream),write
    def test_idle_channel_expires_instead_of_retaining_workers_forever(self):
        reader,_=self.pipe();start=time.monotonic()
        with self.assertRaises(ValueError):reader.read(start+.05)
        self.assertLess(time.monotonic()-start,1)
    def test_partial_line_expires_instead_of_blocking_readline(self):
        reader,write=self.pipe();os.write(write,b'{');start=time.monotonic()
        with self.assertRaises(ValueError):reader.read(start+.05)
        self.assertLess(time.monotonic()-start,1)
    def test_read_ahead_preserves_two_complete_controls(self):
        reader,write=self.pipe();os.write(write,b'{"operation":"inspect"}\nstop\n')
        self.assertEqual(reader.read(time.monotonic()+1),'{"operation":"inspect"}')
        self.assertEqual(reader.read(time.monotonic()+1),'stop')
    def test_oversized_partial_control_is_refused(self):
        reader,write=self.pipe();os.write(write,b'x'*4097)
        with self.assertRaises(ValueError):reader.read(time.monotonic()+1)

if __name__=='__main__':unittest.main()
