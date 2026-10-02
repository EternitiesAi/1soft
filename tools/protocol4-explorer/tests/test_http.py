"""Actual private store + loopback HTTP boundaries, no node or signing mocks."""
import hashlib,http.client,json,threading,tempfile,unittest
from pathlib import Path
from p4_fixture import build,bundle
from p4_read_store import P4ReadStore
from p4_explorer_web import server

class HttpTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):cls.c=build()
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory();self.path=Path(self.tmp.name)/'read.sqlite';self.now=self.c['now_ns']
        with P4ReadStore(self.path,self.c['genesis'],self.c['policy'],create=True,clock=lambda:self.now) as s:
            s.import_evidence(bundle(self.c),expected_tip=None)
        self.http=server(self.path,self.c['genesis'],self.c['policy'],clock=lambda:self.now,label='Synthetic signed fixture')
        self.thread=threading.Thread(target=self.http.serve_forever);self.thread.start()
    def tearDown(self):self.http.shutdown();self.thread.join();self.http.server_close();self.tmp.cleanup()
    def request(self,path,method='GET',headers=None):
        c=http.client.HTTPConnection('127.0.0.1',self.http.server_port,timeout=5)
        c.request(method,path,headers=headers or {});r=c.getresponse();data=r.read();out=r.status,dict(r.headers),data;c.close();return out
    def test_view_is_read_only_and_original_proof_reverified(self):
        before=self.path.read_bytes();status,h,raw=self.request('/api/view');self.assertEqual(status,200)
        v=json.loads(raw);self.assertEqual(v['checkpoint']['state_height'],'16');self.assertEqual(v['label'],'Synthetic signed fixture')
        self.assertEqual(before,self.path.read_bytes());self.now+=3600*10**9
        self.assertEqual(self.request('/api/view')[0],503);self.assertEqual(before,self.path.read_bytes())
    def test_security_headers_and_no_remote_code(self):
        status,h,raw=self.request('/');self.assertEqual(status,200)
        self.assertEqual(h['Cache-Control'],'no-store');self.assertIn("default-src 'none'",h['Content-Security-Policy'])
        self.assertEqual(h['X-Frame-Options'],'DENY');self.assertNotIn(b'https://',raw)
        for path in ['/assets/explorer.js','/assets/explorer.css']:
            status,h,raw=self.request(path);self.assertEqual(status,200)
            self.assertNotIn(b'https://',raw);self.assertNotIn(b'http://',raw)
    def test_cross_origin_host_and_site_refused(self):
        for headers in [{'Origin':'https://evil.invalid'},{'Host':'evil.invalid'},{'Sec-Fetch-Site':'cross-site'}]:
            self.assertEqual(self.request('/api/view',headers=headers)[0],403)
    def test_no_write_or_proof_intake_routes(self):
        for method in ['POST','PUT','PATCH','DELETE','OPTIONS','TRACE','CONNECT']:
            self.assertEqual(self.request('/api/view',method)[0],405)
    def test_no_arbitrary_paths_or_history_export(self):
        for path in ['/api/evidence','/../src/p4_explorer.py','/assets/../src/p4_explorer.py','/?bad=1','/api/capsule/../../x']:
            self.assertEqual(self.request(path)[0],404)
    def test_unknown_receipt_is_unavailable_not_absent(self):
        self.assertEqual(self.request('/api/capsule/'+'0'*64)[0],404)
    def test_corrupted_store_becomes_unavailable(self):
        self.path.write_bytes(b'not sqlite');self.assertEqual(self.request('/api/view')[0],503)
    def test_request_refresh_does_not_create_wallet_files(self):
        before=self.path.read_bytes();self.request('/api/view')
        self.assertEqual(self.path.read_bytes(),before)
        self.assertTrue({p.name for p in self.path.parent.iterdir()} <= {'read.sqlite','read.sqlite-shm','read.sqlite-wal'})

    def test_transfer_capsule_matches_original_wire_and_rejects_management(self):
        from p4_evidence import verify_evidence
        from p4_receipt_capsule import verify_capsule
        from native_core import canonical
        v=verify_evidence(bundle(self.c),self.c['genesis'],self.c['policy'],now_ns=self.now)
        row=next(r for r in v['receipts'] if r['record']['envelope']['body']['op']['type']=='transfer')
        status,h,raw=self.request('/api/capsule/'+row['native_txid']);self.assertEqual(status,200)
        wire=canonical(row['record']['envelope']);report=verify_capsule(raw,self.c['genesis'],self.c['policy'],now_ns=self.now,expected_payer=self.c['payer'],expected_wire_sha256=hashlib.sha256(wire).hexdigest())
        self.assertFalse(report['spending_authority']);self.assertIn(row['native_txid'],h['Content-Disposition'])
        management=next(r for r in v['receipts'] if r['record']['envelope']['body']['op']['type']=='grant')
        self.assertEqual(self.request('/api/capsule/'+management['native_txid'])[0],404)
