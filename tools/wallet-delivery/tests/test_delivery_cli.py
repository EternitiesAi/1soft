"""Real subprocess commands over fresh-clock, synthetic signed native states."""
import json
import os
from pathlib import Path
import subprocess
import sys
import unittest

from delivery_fixture import Scenario, IDS
from commit_verifier import encode

ROOT=Path(__file__).resolve().parents[1]


class CliTests(unittest.TestCase):
    def setUp(self):
        self.c=Scenario(current_clock=True);self.signed=self.c.sign();self.decision=self.signed['decision_id']
        for name,value in [('genesis',self.c.engine),('policy',self.c.policy)]:
            (self.c.root/(name+'.json')).write_bytes(encode(value))
        self.args=['--genesis',str(self.c.root/'genesis.json'),'--policy',str(self.c.root/'policy.json'),
                   '--wallet',str(self.c.wallet_path),'--delivery-journal',str(self.c.delivery_path),
                   '--account',IDS[0],'--grant-id','raven','--decision-id',self.decision]
    def tearDown(self):self.c.close()
    def call(self,command,*extra,url='http://127.0.0.1:26657/'):
        return subprocess.run([sys.executable,str(ROOT/'scripts/deliver.py'),*self.args,'--endpoint',url,command,*extra],
                              capture_output=True,text=True,timeout=15)
    def test_actual_cli_queue_send_refresh_reconcile_without_keys(self):
        # Signing occurred in setup; private fixture key files are now removed.
        for p in self.c.root.glob('*.pem'):p.unlink()
        with self.c.rpc() as url:
            p=self.call('queue',url=url);self.assertEqual(p.returncode,0,p.stderr)
            q=json.loads(p.stdout)
            p=self.call('send','--confirm',q['delivery_confirmation'],url=url)
            self.assertEqual(p.returncode,0,p.stderr);self.assertEqual(json.loads(p.stdout)['transport_status'],'unresolved')
            p=self.call('refresh',url=url);self.assertEqual(p.returncode,0,p.stderr)
            r=json.loads(p.stdout);self.assertTrue(r['exact_transport_receipt_verified']);self.assertEqual(self.c.holds(),60)
            proof=self.c.root/'receipt.json'
            p=self.call('export-proof','--output',str(proof),url=url)
            self.assertEqual(p.returncode,0,p.stderr);self.assertTrue(proof.is_file())
            links=self.c.root/'links.json';links.write_bytes(encode(self.c.continuation()))
            p=self.call('reconcile','--continuation',str(links),url=url)
            self.assertEqual(p.returncode,0,p.stderr);self.assertEqual(json.loads(p.stdout)['wallet_obligation_status'],'recorded')
            self.assertEqual(self.c.holds(),0);self.assertEqual(len(self.c.seen),1)
    def test_send_without_queue_cannot_initialize_or_contact_network(self):
        with self.c.rpc() as url:p=self.call('send','--confirm','0'*64,url=url)
        self.assertEqual(p.returncode,2);self.assertEqual(self.c.requests,[]);self.assertFalse(self.c.delivery_path.exists())
    def test_wrong_confirmation_does_not_contact_rpc(self):
        with self.c.rpc() as url:
            p=self.call('queue',url=url);self.assertEqual(p.returncode,0,p.stderr)
            p=self.call('send','--confirm','0'*64,url=url)
        self.assertEqual(p.returncode,2);self.assertEqual(self.c.requests,[])
    def test_no_password_or_envelope_flags(self):
        p=self.call('queue','--password','never-a-real-secret')
        self.assertEqual(p.returncode,2);self.assertFalse(self.c.delivery_path.exists())
    def test_output_never_overwritten(self):
        with self.c.rpc() as url:
            p=self.call('queue',url=url);q=json.loads(p.stdout)
            self.call('send','--confirm',q['delivery_confirmation'],url=url);self.call('refresh',url=url)
            pth=self.c.root/'old.json';pth.write_bytes(b'keep')
            p=self.call('export-proof','--output',str(pth),url=url)
        self.assertEqual(p.returncode,2);self.assertEqual(pth.read_bytes(),b'keep')
    def test_unavailable_evidence_report_not_paid_or_wallet_synced(self):
        self.c.mode='decline'
        with self.c.rpc() as url:
            q=json.loads(self.call('queue',url=url).stdout)
            self.call('send','--confirm',q['delivery_confirmation'],url=url)
            p=self.call('refresh',url=url)
        self.assertEqual(p.returncode,0,p.stderr);r=json.loads(p.stdout)
        self.assertEqual(r['collection_status'],'evidence_unavailable');self.assertFalse(r['wallet_sync_performed'])
        self.assertEqual(r['wallet_obligation_status'],'pending');self.assertEqual(self.c.holds(),60)


if __name__=='__main__':unittest.main()
