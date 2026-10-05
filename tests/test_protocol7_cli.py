"""CLI bootstrap failures are early; actual prepared owner bytes are retained/exported."""
import hashlib,json,os,subprocess,sys,tempfile,unittest
from pathlib import Path
class CliTests(unittest.TestCase):
    def test_wrong_external_pin_refuses_before_journal_or_worker(self):
        root=Path(__file__).resolve().parents[1]
        with tempfile.TemporaryDirectory() as d:
            p=Path(d);(p/'g.json').write_bytes(b'{}')
            done=subprocess.run([sys.executable,str(root/'scripts/owner_treasury_wallet.py'),'--journal',str(p/'j.sqlite'),'--genesis',str(p/'g.json'),'--genesis-sha256','ab'*32,'--worker','/missing','--worker-sha256','ab'*32,'--kat','/missing','inspect','--txid','ab'*32],capture_output=True,timeout=10)
            self.assertEqual(done.returncode,1);self.assertIn('bootstrap genesis pin',json.loads(done.stdout)['error']);self.assertEqual([x.name for x in p.iterdir()],['g.json'])
    @unittest.skipUnless(os.environ.get('P7_REPORT') and os.environ.get('P7_WORKER'),'unassessed: actual P7 prepared owner inputs absent')
    def test_actual_owner_retain_and_exact_export(self):
        from protocol7_treasury import canonical,digest,txid
        root=Path(__file__).resolve().parents[1];p=Path(os.environ['P7_REPORT']);v=json.loads(p.read_bytes());raw=bytes.fromhex(v['commands'][0]);kat=p.with_name(p.name+'.artifacts')/'fixture-a.tx'
        with tempfile.TemporaryDirectory() as d:
            directory=Path(d);directory.chmod(0o700);g=directory/'g.json';g.write_bytes(canonical(v['genesis']));t=directory/'owner.tx';t.write_bytes(raw)
            base=[sys.executable,str(root/'scripts/owner_treasury_wallet.py'),'--journal',str(directory/'j.sqlite'),'--genesis',str(g),'--genesis-sha256',digest(g.read_bytes()),'--worker',os.environ['P7_WORKER'],'--worker-sha256',v['genesis']['worker_sha256'],'--kat',str(kat)]
            done=subprocess.run(base+['retain','--transaction',str(t)],capture_output=True,timeout=120)
            self.assertEqual(done.returncode,0,done.stdout.decode()+done.stderr.decode());self.assertEqual(json.loads(done.stdout)['result']['kind'],'owner')
            export=directory/'export.tx';done=subprocess.run(base+['export','--txid',txid(raw),'--output',str(export)],capture_output=True,timeout=120)
            self.assertEqual(done.returncode,0,done.stdout.decode()+done.stderr.decode());self.assertEqual(export.read_bytes(),raw);self.assertEqual(export.stat().st_mode&0o777,0o600)
if __name__=='__main__':unittest.main()
