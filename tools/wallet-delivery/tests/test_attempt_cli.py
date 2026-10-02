"""Actual CLI send/replay review semantics; local fixture network only."""
import json
import subprocess
import sys
import unittest
from pathlib import Path
from delivery_fixture import Scenario,IDS
from commit_verifier import encode

ROOT=Path(__file__).resolve().parents[1]
class AttemptCliTests(unittest.TestCase):
    def setUp(self):
        self.c=Scenario(current_clock=True);self.s=self.c.sign();self.c.mode='decline'
        for name,value in [('genesis',self.c.engine),('policy',self.c.policy)]:
            (self.c.root/(name+'.json')).write_bytes(encode(value))
        self.args=['--genesis',str(self.c.root/'genesis.json'),'--policy',str(self.c.root/'policy.json'),
            '--wallet',str(self.c.wallet_path),'--delivery-journal',str(self.c.delivery_path),
            '--account',IDS[0],'--grant-id','raven','--decision-id',self.s['decision_id']]
    def tearDown(self):self.c.close()
    def call(self,url,*command):
        return subprocess.run([sys.executable,str(ROOT/'scripts/deliver.py'),*self.args,'--endpoint',url,*command],capture_output=True,text=True,timeout=10)
    def test_review_does_not_create_missing_dispatch_store(self):
        with self.c.rpc() as url:p=self.call(url,'review')
        self.assertEqual(p.returncode,2);self.assertFalse(self.c.delivery_path.exists());self.assertEqual(self.c.requests,[])
    def test_cli_replay_requires_explicit_new_review_and_next_attempt(self):
        with self.c.rpc() as url:
            q=json.loads(self.call(url,'queue').stdout)
            p=self.call(url,'send','--confirm',q['delivery_confirmation']);self.assertEqual(p.returncode,0,p.stderr)
            bad=self.call(url,'replay','--confirm',q['delivery_confirmation']);self.assertEqual(bad.returncode,2)
            p=self.call(url,'review','--replay');self.assertEqual(p.returncode,0,p.stderr);review=json.loads(p.stdout)
            self.assertEqual(review['submission_review']['operation'],'replay');self.assertEqual(review['submission_review']['next_attempt'],2)
            p=self.call(url,'replay','--confirm',review['delivery_confirmation']);self.assertEqual(p.returncode,0,p.stderr)
            again=self.call(url,'replay','--confirm',review['delivery_confirmation']);self.assertEqual(again.returncode,2)
            self.assertEqual(len(self.c.seen),2);self.assertEqual(self.c.holds(),60)
    def test_status_prints_no_confirmation_even_while_queued(self):
        with self.c.rpc() as url:
            self.call(url,'queue');p=self.call(url,'status');self.assertEqual(p.returncode,0,p.stderr)
            self.assertIsNone(json.loads(p.stdout)['delivery_confirmation']);self.assertEqual(self.c.requests,[])
    def test_fresh_send_review_uses_existing_signature_no_new_key_prompt(self):
        for file in self.c.root.glob('*.pem'):file.unlink()
        with self.c.rpc() as url:
            q=json.loads(self.call(url,'queue').stdout);p=self.call(url,'review')
            self.assertEqual(p.returncode,0,p.stderr);r=json.loads(p.stdout)
            self.assertEqual(q['delivery_confirmation'],r['delivery_confirmation'])
            self.assertNotIn('passphrase',p.stdout.lower());self.assertEqual(self.c.requests,[])
