"""Actual disposable POSIX process failure cleanup; no crypto or engine claim."""
import os,subprocess,sys,tempfile,unittest
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'scripts'))
from run_protocol8_wallet_cli import abort_owned_tree,process_identity
from run_devnet import wait_until

class CleanupTests(unittest.TestCase):
    def test_new_session_native_descendant_stops_with_owned_cli(self):
        with tempfile.TemporaryDirectory() as d:
            receipt=Path(d)/'child-pid'
            code='import subprocess,sys,time;from pathlib import Path;p=subprocess.Popen([sys.executable,"-c","import time;time.sleep(60)"],start_new_session=True);Path(sys.argv[1]).write_text(str(p.pid));time.sleep(60)'
            proc=subprocess.Popen([sys.executable,'-c',code,str(receipt)],stdout=subprocess.PIPE,stderr=subprocess.PIPE,start_new_session=True)
            try:
                wait_until(receipt.exists,5);child=int(receipt.read_text());identity=process_identity(child)
                self.assertIsNotNone(identity);self.assertEqual(os.getpgid(child),child)
                records=abort_owned_tree(proc)
                self.assertEqual({r['pid'] for r in records},{proc.pid,child})
                self.assertTrue(all(r['stopped'] for r in records));self.assertEqual(proc.poll(),-9)
                self.assertTrue(process_identity(child) in (None,(identity[0],'Z')) or process_identity(child)[0]!=identity[0])
            finally:
                if proc.poll() is None:abort_owned_tree(proc)

if __name__=='__main__':unittest.main()
