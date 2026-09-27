"""CLI over fresh synthetic signed state and actual local native HTTP execution."""
import json
from pathlib import Path
import subprocess
import sys
import time
import unittest
from datetime import datetime, timezone

from delivery_fixture import fixtures, Node, server
from certificate_fixture import make_commit
from commit_verifier import encode

ROOT=Path(__file__).resolve().parents[1]


class DeliveryCliTests(unittest.TestCase):
    def setUp(self):
        self.c=fixtures.ObligationTests();self.c.setUp()
        stamp=datetime.now(timezone.utc).isoformat().replace('+00:00','Z')
        self.c.witness['state_commit']['header']['time']=stamp
        self.c.witness['state_commit']=make_commit(self.c.witness['state_commit']['header'],self.c.trust,self.c.valkeys)
        self.c.clock=time.time_ns();self.c.sync()
        self.signed=self.c.approve();self.node=Node(self.c)
        self.genesis=self.c.root/'genesis.json';self.genesis.write_bytes(self.c.raw)
        self.policy=self.c.root/'policy.json';self.policy.write_bytes(encode(self.c.policy))
    def tearDown(self):self.c.tearDown()
    def command(self,url,*extra):
        return [sys.executable,str(ROOT/'scripts/deliver.py'),'--genesis',str(self.genesis),
                '--policy',str(self.policy),'--journal',str(self.c.path),
                '--dispatch-journal',str(self.c.root/'dispatch.sqlite'),'--endpoint',url,
                '--account',fixtures.IDS[0],'--grant-id','raven',
                '--decision-id',self.signed['decision_id'],*extra]
    def call(self,url,*extra):
        return subprocess.run(self.command(url,*extra),capture_output=True,text=True,timeout=12)
    def test_cli_review_does_not_submit_or_request_a_password(self):
        with server(self.node) as url:out=self.call(url,'review')
        self.assertEqual(out.returncode,0,out.stderr)
        self.assertEqual(json.loads(out.stdout)['operation'],'send');self.assertEqual(self.node.requests,[])
        self.assertNotIn('password',out.stdout.lower())
    def test_cli_full_lifecycle_separates_admission_receipt_and_reconciliation(self):
        with server(self.node) as url:
            review=self.call(url,'review');self.assertEqual(review.returncode,0,review.stderr)
            plan=json.loads(review.stdout)
            sent=self.call(url,'send','--confirm',plan['confirmation'])
            self.assertEqual(sent.returncode,2,sent.stderr)
            self.assertEqual(json.loads(sent.stdout)['delivery_status'],'endpoint_admitted')
            read=self.call(url,'refresh');self.assertEqual(read.returncode,0,read.stderr)
            self.assertEqual(json.loads(read.stdout)['wallet_obligation_status'],'pending')
            synced=self.call(url,'reconcile');self.assertEqual(synced.returncode,0,synced.stderr)
            self.assertTrue(json.loads(synced.stdout)['wallet_reconciled'])
        self.assertEqual(sum(r['method']=='broadcast_tx_sync' for r in self.node.requests),1)
    def test_cli_dropped_reply_not_implicit_retry(self):
        self.node.drop_reply=True
        with server(self.node) as url:
            plan=json.loads(self.call(url,'review').stdout)
            out=self.call(url,'send','--confirm',plan['confirmation'])
            self.assertEqual(out.returncode,2);self.assertEqual(json.loads(out.stdout)['delivery_status'],'unresolved')
            again=self.call(url,'send','--confirm',plan['confirmation']);self.assertEqual(again.returncode,3)
            self.assertEqual(self.call(url,'refresh').returncode,0)
        self.assertEqual(sum(r['method']=='broadcast_tx_sync' for r in self.node.requests),1)
    def test_cli_no_envelope_or_key_import_option(self):
        out=self.call('http://127.0.0.1:26657/','send','--confirm','0'*64,'--vault','unaccepted')
        self.assertEqual(out.returncode,2);self.assertIn('unrecognized',out.stderr)
    def test_cli_error_does_not_leak_path_or_signed_transaction(self):
        out=self.call('http://127.0.0.1:26657/','send','--confirm','0'*64)
        self.assertEqual(out.returncode,3);self.assertNotIn(str(self.c.root),out.stderr)
        self.assertNotIn(self.signed['result']['signature'],out.stderr)
    def test_cli_proof_export_private_and_no_overwrite(self):
        with server(self.node) as url:
            plan=json.loads(self.call(url,'review').stdout)
            self.call(url,'send','--confirm',plan['confirmation']);self.call(url,'refresh')
            output=self.c.root/'proof.json';count=len(self.node.requests)
            r=self.call(url,'export-proof','--output',str(output));self.assertEqual(r.returncode,0,r.stderr)
            self.assertEqual(output.stat().st_mode&0o777,0o600);data=output.read_bytes()
            r=self.call(url,'export-proof','--output',str(output));self.assertEqual(r.returncode,3)
            self.assertEqual(data,output.read_bytes());self.assertEqual(len(self.node.requests),count)
    def test_cli_stale_policy_status_available_refresh_refused(self):
        self.c.policy['trust_expires_utc']='2020-01-01T00:00:00Z'
        # Changed policy must not silently rebind the existing wallet.
        self.policy.write_bytes(encode(self.c.policy))
        with server(self.node) as url:out=self.call(url,'refresh')
        self.assertEqual(out.returncode,3);self.assertEqual(self.node.requests,[])


if __name__=='__main__':unittest.main()
