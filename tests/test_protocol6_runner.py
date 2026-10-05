import argparse,json,tempfile,unittest,sys
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'scripts'))
from run_protocol6_engine import run
class RunnerPreflightTests(unittest.TestCase):
    def test_missing_real_inputs_are_unassessed_and_start_no_processes(self):
        with tempfile.TemporaryDirectory() as d:
            root=Path(d);output=root/'result.json'
            args=argparse.Namespace(engine=root/'missing-engine',worker=root/'missing-worker',fixtures=root/'missing-fixtures',output=output,candidate=True)
            self.assertEqual(run(args),2)
            v=json.loads(output.read_bytes());self.assertEqual(v['status'],'unassessed')
            self.assertIn('engine',v['missing_inputs']);self.assertIn('worker',v['missing_inputs']);self.assertEqual(v['processes'],[])
if __name__=='__main__':unittest.main()
