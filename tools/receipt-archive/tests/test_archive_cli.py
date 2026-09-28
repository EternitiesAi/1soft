import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from commit_verifier import encode
from fixtures_archive import case

ROOT=Path(__file__).resolve().parents[1]

class ArchiveCliTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):cls.c=case()
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory();self.root=Path(self.tmp.name)
        for name,raw in [('genesis',self.c['genesis']),('transaction',self.c['raw']),
                         ('packet',encode(self.c['packet'])),('links',encode(self.c['links'])),
                         ('capsule',encode(self.c['capsule']))]:
            (self.root/(name+'.json')).write_bytes(raw)
    def tearDown(self):self.tmp.cleanup()
    def call(self,command,*args):
        return subprocess.run([sys.executable,str(ROOT/'scripts/receipts.py'),'--genesis',str(self.root/'genesis.json'),
            '--genesis-sha256',self.c['genesis_sha256'],command,*map(str,args)],capture_output=True,text=True,timeout=10)
    def pins(self):return ['--transaction',self.root/'transaction.json','--state-header-hash',self.c['pin']]
    def test_complete_pack_init_import_lookup_export_workflow(self):
        out=self.root/'out.json';archive=self.root/'history.sqlite';export=self.root/'export.json'
        p=self.call('pack','--packet',self.root/'packet.json','--continuation',self.root/'links.json',*self.pins(),'--output',out)
        self.assertEqual(p.returncode,0,p.stderr)
        self.assertEqual(json.loads(out.read_bytes()),self.c['capsule'])
        self.assertEqual(self.call('init','--archive',archive).returncode,0)
        p=self.call('import','--archive',archive,'--capsule',out,*self.pins());self.assertEqual(p.returncode,0,p.stderr)
        evidence=json.loads(p.stdout)['evidence_id']
        p=self.call('lookup','--archive',archive,'--transaction',self.root/'transaction.json')
        self.assertEqual(p.returncode,0,p.stderr);self.assertEqual(json.loads(p.stdout)['status'],'available')
        p=self.call('export','--archive',archive,'--evidence-id',evidence,'--output',export)
        self.assertEqual(p.returncode,0,p.stderr);self.assertEqual(out.read_bytes(),export.read_bytes())
    def test_verify_does_not_open_archive_or_node(self):
        p=self.call('verify','--capsule',self.root/'capsule.json',*self.pins())
        self.assertEqual(p.returncode,0,p.stderr)
        self.assertEqual(list(self.root.glob('*.sqlite')),[])
        self.assertFalse(json.loads(p.stdout)['latest_state_guaranteed'])
    def test_missing_archive_is_not_created_by_lookup(self):
        path=self.root/'missing.sqlite'
        p=self.call('lookup','--archive',path,'--transaction',self.root/'transaction.json')
        self.assertEqual(p.returncode,2);self.assertFalse(path.exists());self.assertNotIn('Traceback',p.stderr)
    def test_empty_archive_lookup_is_unknown_not_failed_payment(self):
        path=self.root/'history.sqlite';self.call('init','--archive',path)
        p=self.call('lookup','--archive',path,'--transaction',self.root/'transaction.json')
        self.assertEqual(p.returncode,2)
        r=json.loads(p.stdout);self.assertEqual(r['status'],'unavailable');self.assertFalse(r['historical_absence_proven'])
    def test_export_cannot_replace_existing_file(self):
        output=self.root/'keep.json';output.write_text('preserve')
        p=self.call('pack','--packet',self.root/'packet.json','--continuation',self.root/'links.json',*self.pins(),'--output',output)
        self.assertEqual(p.returncode,2);self.assertEqual(output.read_text(),'preserve')
    def test_wrong_checkpoint_pin_does_not_create_output(self):
        output=self.root/'out.json'
        p=self.call('pack','--packet',self.root/'packet.json','--continuation',self.root/'links.json',
                    '--transaction',self.root/'transaction.json','--state-header-hash','0'*64,'--output',output)
        self.assertEqual(p.returncode,2);self.assertFalse(output.exists())
    def test_missing_lineage_refuses_without_weaker_fallback(self):
        output=self.root/'out.json'
        p=self.call('pack','--packet',self.root/'packet.json',*self.pins(),'--output',output)
        self.assertEqual(p.returncode,2);self.assertFalse(output.exists())
    def test_diagnostics_do_not_echo_untrusted_or_private_path(self):
        (self.root/'capsule.json').write_text('{"secret_path":"private-value"}')
        p=self.call('verify','--capsule',self.root/'capsule.json',*self.pins())
        self.assertEqual(p.returncode,2);self.assertNotIn(str(self.root),p.stderr);self.assertNotIn('private-value',p.stderr)

if __name__=='__main__':unittest.main()
