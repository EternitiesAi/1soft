"""Actual read CLI and explorer consumers auto-open both storage formats."""
import hashlib
import http.client
import json
from pathlib import Path
import subprocess
import sys
import time
import threading
import unittest

from block_application import encode
from p4_fixture import build,bundle
from p4_read_store import P4ReadStore
import test_cli as legacy_cli

ROOT=Path(__file__).resolve().parents[1]


class CLITestsFormat2(legacy_cli.CLITests):
    def initialize(self):
        result=self.call('init','--store',self.path,'--storage-format','2')
        self.assertEqual(result.returncode,0,result.stderr)
        result=self.call('import','--store',self.path,'--expected-tip','empty','--evidence',self.root/'evidence.json')
        self.assertEqual(result.returncode,0,result.stderr)
        return json.loads(result.stdout)
    def test_storage_metrics_same_readonly_contract_for_default_and_format2(self):
        for version in (1,2):
            path=self.root/('metrics'+str(version)+'.sqlite')
            args=['init','--store',path]+(['--storage-format','2'] if version==2 else [])
            result=self.call(*args);self.assertEqual(result.returncode,0,result.stderr)
            result=self.call('storage','--store',path);self.assertEqual(result.returncode,0,result.stderr)
            self.assertEqual(json.loads(result.stdout),{'format_version':version,'observations':0,
                'logical_evidence_bytes':0,'stored_payload_bytes':0,'spending_authority':False})
            result=self.call('import','--store',path,'--expected-tip','empty','--evidence',self.root/'evidence.json')
            self.assertEqual(result.returncode,0,result.stderr)
            before=path.read_bytes();result=self.call('storage','--store',path)
            self.assertEqual(result.returncode,0,result.stderr);metrics=json.loads(result.stdout)
            self.assertEqual(metrics['logical_evidence_bytes'],len(encode(bundle(self.c))))
            self.assertEqual(metrics['observations'],1);self.assertEqual(path.read_bytes(),before)
            self.assertEqual(set(metrics),{'format_version','observations','logical_evidence_bytes',
                                          'stored_payload_bytes','spending_authority'})
    def test_existing_store_selector_is_only_accepted_on_init(self):
        self.initialize();before=self.path.read_bytes()
        for command in ('inspect','storage'):
            result=self.call(command,'--store',self.path,'--storage-format','2')
            self.assertEqual(result.returncode,2);self.assertEqual(self.path.read_bytes(),before)
        for value in ('0','3'):
            path=self.root/('unsupported'+value+'.sqlite')
            result=self.call('init','--store',path,'--storage-format',value)
            self.assertEqual(result.returncode,2);self.assertFalse(path.exists())
    def test_storage_missing_store_refuses_without_creation(self):
        result=self.call('storage','--store',self.path)
        self.assertEqual(result.returncode,2);self.assertFalse(self.path.exists())
    def test_existing_explorer_cli_and_view_consume_format2(self):
        self.initialize();before=self.path.read_bytes()
        explorer=ROOT.parent/'protocol4-explorer'/'scripts/p4_explorer.py'
        result=subprocess.run([sys.executable,str(explorer),'--genesis',str(self.root/'genesis.json'),
            '--policy',str(self.root/'policy.json'),'--store',str(self.path),'inspect'],
            capture_output=True,text=True,timeout=10)
        self.assertEqual(result.returncode,0,result.stderr)
        self.assertEqual(json.loads(result.stdout)['checkpoint']['state_height'],'16')
        from p4_explorer import current_view
        view=current_view(self.path,self.c['genesis'],self.c['policy'],clock=time.time_ns)
        self.assertEqual(view['checkpoint']['evidence_id'],self.initialize_tip())
        self.assertFalse(view['spending_authority']);self.assertEqual(self.path.read_bytes(),before)
    def initialize_tip(self):
        with P4ReadStore(self.path,self.c['genesis'],self.c['policy'],read_only=True,
                         clock=time.time_ns) as store:return store.current()['evidence_id']
    def test_existing_explorer_http_capsule_uses_restored_original_proof(self):
        imported=self.initialize()
        from p4_explorer_web import server
        from p4_receipt_capsule import verify_capsule
        from native_core import canonical
        with P4ReadStore(self.path,self.c['genesis'],self.c['policy'],read_only=True,
                         clock=time.time_ns) as store:
            report=store.current()
        row=next(r for r in report['receipts'] if r['record']['envelope']['body']['op']['type']=='transfer')
        wire=canonical(row['record']['envelope']);before=self.path.read_bytes()
        http_server=server(self.path,self.c['genesis'],self.c['policy'],clock=time.time_ns)
        thread=threading.Thread(target=http_server.serve_forever);thread.start()
        try:
            connection=http.client.HTTPConnection('127.0.0.1',http_server.server_port,timeout=5)
            connection.request('GET','/api/capsule/'+row['native_txid'])
            response=connection.getresponse();raw=response.read();self.assertEqual(response.status,200)
            connection.close()
            result=verify_capsule(raw,self.c['genesis'],self.c['policy'],now_ns=time.time_ns(),
                expected_payer=self.c['payer'],expected_wire_sha256=hashlib.sha256(wire).hexdigest())
            self.assertFalse(result['spending_authority'])
            self.assertEqual(json.loads(raw)['evidence'],bundle(self.c))
            self.assertEqual(self.path.read_bytes(),before)
        finally:http_server.shutdown();thread.join();http_server.server_close()


if __name__=='__main__':unittest.main()
