import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import time
import unittest

from block_application import encode
from delivery_fixture import Fixture

ROOT=Path(__file__).resolve().parents[1]


class ProcessTests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory();self.root=Path(self.tmp.name);self.f=Fixture(self.root);self.did=self.f.sign()
        (self.root/'genesis.json').write_bytes(self.f.chain.genesis)
        (self.root/'policy.json').write_bytes(encode(self.f.chain.policy))
        (self.root/'review.json').write_bytes(encode(self.f.review(self.did)))
    def tearDown(self):self.f.close();self.tmp.cleanup()
    def child(self,phase):
        code='''import json,os,sys
from pathlib import Path
import p4_delivery as mod
from p4_delivery import P4Delivery
r=Path(sys.argv[1]);now=int(sys.argv[4]);phase=sys.argv[3]
d=P4Delivery(r/'wallet.sqlite',r/'delivery.sqlite',(r/'genesis.json').read_bytes(),json.loads((r/'policy.json').read_bytes()),sys.argv[2],clock=lambda:now)
p=json.loads((r/'review.json').read_bytes())
if phase=='before_claim_commit':
 def die(sql):
  if sql=='COMMIT':os._exit(31)
 d.db.set_trace_callback(die)
if phase=='after_claim':mod.submit_once=lambda *args:os._exit(32)
if phase=='after_network':
 worker=mod.submit_once
 def die(*args):
  worker(*args);os._exit(33)
 mod.submit_once=die
if phase=='after_wallet_sync':
 sync=d.wallet.sync
 def die(*args,**kwargs):
  sync(*args,**kwargs);os._exit(34)
 d.wallet.sync=die
 d.reconcile(p['review']['decision_id'],payer=p['review']['payer'],grant_id=p['review']['grant_id'],expected_revision=d.wallet.status()['revision'])
else:d.send(p['review'],p['confirmation'])
raise SystemExit(99)
'''
        result=subprocess.run([sys.executable,'-c',code,str(self.root),self.f.url,phase,str(self.f.chain.now)],capture_output=True,timeout=12)
        self.assertEqual(result.returncode,{'before_claim_commit':31,'after_claim':32,'after_network':33,'after_wallet_sync':34}[phase],result.stderr)
    def test_exit_before_claim_commit_leaves_no_dispatch_attempt(self):
        self.child('before_claim_commit');self.assertFalse(self.f.delivery.inspect(self.did,**self.f.selection())['attempt_recorded'])
        self.assertEqual(self.f.submissions,[]);self.assertEqual(self.f.held(),60)
    def test_exit_after_claim_before_network_retains_unknown_without_retry(self):
        self.child('after_claim');r=self.f.delivery.inspect(self.did,**self.f.selection())
        self.assertTrue(r['attempt_recorded']);self.assertEqual(r['transport_observation'],'unresolved')
        self.assertEqual(self.f.submissions,[])
        with self.assertRaises(ValueError):self.f.send(self.did)
    def test_exit_after_real_submission_recovers_receipt_without_second_submit(self):
        self.child('after_network');self.assertEqual(len(self.f.submissions),1);self.assertEqual(self.f.held(),60)
        self.f.delivery.close();self.f.delivery=self.f.open_delivery()
        self.f.delivery.collect(self.did,**self.f.selection())
        self.f.delivery.reconcile(self.did,**self.f.selection(),expected_revision=self.f.wallet.status()['revision'])
        self.assertEqual(self.f.held(),0);self.assertEqual(len(self.f.submissions),1)
    def test_exit_after_wallet_sync_is_recognized_without_second_sync(self):
        self.f.send(self.did);self.f.delivery.collect(self.did,**self.f.selection());self.child('after_wallet_sync')
        self.assertEqual(self.f.held(),0)
        r=self.f.delivery.reconcile(self.did,**self.f.selection(),expected_revision=self.f.wallet.status()['revision'])
        self.assertEqual(r['status'],'already_recorded');self.assertFalse(r['wallet_sync_performed'])


class CliTests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory();self.root=Path(self.tmp.name);self.f=Fixture(self.root);self.did=self.f.sign()
        (self.root/'genesis.json').write_bytes(self.f.chain.genesis);(self.root/'policy.json').write_bytes(encode(self.f.chain.policy))
    def tearDown(self):self.f.close();self.tmp.cleanup()
    def call(self,cmd,*args):
        return subprocess.run([sys.executable,str(ROOT/'scripts/p4_delivery_cli.py'),
             '--genesis',str(self.root/'genesis.json'),'--policy',str(self.root/'policy.json'),
             '--wallet',str(self.f.wp),'--journal',str(self.f.dp),'--endpoint',self.f.url,cmd,*map(str,args)],
             capture_output=True,text=True,timeout=12,env={**os.environ,'PYTHONPATH':''})
    def select(self):return ['--decision-id',self.did,'--payer',self.f.chain.payer,'--grant','raven']
    def test_complete_cli_flow_with_lost_response_and_original_receipt(self):
        p=self.root/'delivery-review.json';r=self.call('prepare',*self.select(),'--output',p);self.assertEqual(r.returncode,0,r.stderr)
        token=json.loads(p.read_bytes())['confirmation']
        r=self.call('send','--review',p,'--confirmation',token);self.assertEqual(r.returncode,2,r.stderr)
        self.assertEqual(json.loads(r.stdout)['transport_observation'],'unresolved')
        self.assertEqual(self.call('collect',*self.select()).returncode,0)
        self.assertEqual(self.f.held(),60)
        rev=self.f.wallet.status()['revision'];r=self.call('reconcile',*self.select(),'--expected-revision',rev)
        self.assertEqual(r.returncode,0,r.stderr);self.f.chain.now=time.time_ns();self.assertEqual(self.f.held(),0)
        out=self.root/'receipt.json';r=self.call('export-receipt',*self.select(),'--output',out)
        self.assertEqual(r.returncode,0,r.stderr);self.assertTrue(out.exists());self.assertEqual(len(self.f.submissions),1)
    def test_output_review_refuses_overwrite_without_attempt(self):
        out=self.root/'review.json';out.write_text('preserve')
        r=self.call('prepare',*self.select(),'--output',out)
        self.assertEqual(r.returncode,2);self.assertEqual(out.read_text(),'preserve');self.assertEqual(self.f.submissions,[])
    def test_no_raw_transaction_or_key_command(self):
        self.assertNotEqual(self.call('sign').returncode,0);self.assertNotEqual(self.call('broadcast').returncode,0)
        self.assertEqual(self.f.submissions,[])
    def test_repeated_cli_send_does_not_submit_twice(self):
        p=self.root/'delivery-review.json';self.call('prepare',*self.select(),'--output',p)
        token=json.loads(p.read_bytes())['confirmation'];self.call('send','--review',p,'--confirmation',token)
        r=self.call('send','--review',p,'--confirmation',token);self.assertEqual(r.returncode,2)
        self.assertEqual(len(self.f.submissions),1);self.assertNotIn('Traceback',r.stderr)
    def test_wrong_payer_diagnostic_does_not_echo_paths(self):
        r=self.call('inspect','--decision-id',self.did,'--payer',self.f.chain.merchant,'--grant','raven')
        self.assertEqual(r.returncode,2);self.assertNotIn(str(self.root),r.stderr);self.assertEqual(self.f.reads,[])
    def test_cli_init_does_not_overwrite_existing_database(self):
        before=list(self.f.delivery.db.iterdump());r=self.call('init')
        self.assertEqual(r.returncode,2);self.assertEqual(list(self.f.delivery.db.iterdump()),before)

if __name__=='__main__':unittest.main()
