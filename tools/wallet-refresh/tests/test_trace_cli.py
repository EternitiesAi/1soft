"""Actual command-line diagnostic persistence using a fresh fixture clock."""
import copy
from datetime import datetime, timezone, timedelta
import json
from pathlib import Path
import subprocess
import sys
import unittest

import test_client
from certificate_fixture import make_commit
from commit_verifier import encode
from refresh_trace import read_trace, public_result

ROOT=Path(__file__).resolve().parents[1]


class TraceCliTests(unittest.TestCase):
    def setUp(self):
        self.f=test_client.ClientTests();self.f.setUp();self.c=self.f.c
        now=datetime.now(timezone.utc)
        self.witness=copy.deepcopy(self.c.witness)
        header=self.witness['state_commit']['header'];header['time']=now.isoformat().replace('+00:00','Z')
        self.witness['state_commit']=make_commit(header,self.c.trust,self.c.valkeys)
        self.headers={int(header['height']):self.witness['state_commit']}
        self.policy={**self.c.policy,'trust_expires_utc':(now+timedelta(hours=1)).isoformat().replace('+00:00','Z')}
        self.genesis=self.c.root/'cli-genesis.json';self.genesis.write_bytes(self.c.raw)
        self.policy_path=self.c.root/'cli-policy.json';self.policy_path.write_bytes(encode(self.policy))
        self.report_dir=self.c.root/'cli-report'
    def tearDown(self):self.f.tearDown()
    def call(self,url,with_record=True):
        cmd=[sys.executable,str(ROOT/'scripts/refresh_wallet.py'),'--genesis',str(self.genesis),
             '--policy',str(self.policy_path),'--journal',str(self.c.root/'cli-wallet.sqlite'),'--endpoint',url]
        if with_record:cmd+=['--report-dir',str(self.report_dir)]
        return subprocess.run(cmd,capture_output=True,text=True,timeout=12)
    def test_successful_cli_saves_exact_public_result(self):
        with test_client.rpc(self.witness,self.headers) as (url,reads):p=self.call(url)
        self.assertEqual(p.returncode,0,p.stderr);r=json.loads(p.stdout)
        self.assertTrue(r['state_synced']);self.assertEqual(read_trace(self.report_dir)['outcome'],public_result(r))
        self.assertEqual(len(reads),2)
    def test_original_cli_without_record_still_works(self):
        with test_client.rpc(self.witness,self.headers) as (url,reads):p=self.call(url,False)
        self.assertEqual(p.returncode,0,p.stderr);self.assertFalse(self.report_dir.exists())
    def test_failed_cli_retains_rejected_preflight_status(self):
        self.policy['trust_expires_utc']='2020-01-01T00:00:00Z';self.policy_path.write_bytes(encode(self.policy))
        with test_client.rpc(self.witness,self.headers) as (url,reads):p=self.call(url)
        self.assertEqual(p.returncode,2,p.stderr);self.assertEqual(reads,[])
        r=read_trace(self.report_dir);self.assertEqual(r['outcome']['status'],'rejected')
        self.assertIn({'stage':'preflight'},[e['data'] for e in r['events']])
    def test_existing_directory_refused_without_reads(self):
        self.report_dir.mkdir(mode=0o700);(self.report_dir/'keep').write_text('preserve')
        with test_client.rpc(self.witness,self.headers) as (url,reads):p=self.call(url)
        self.assertNotEqual(p.returncode,0);self.assertEqual(reads,[])
        self.assertEqual((self.report_dir/'keep').read_text(),'preserve')


if __name__=='__main__':unittest.main()
