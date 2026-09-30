"""Browser origin/bounds tests over real P4 composition and a fixture node."""
import hashlib
import http.client
import json
from pathlib import Path
import shutil
import tempfile
import threading
import unittest

from delivery_fixture import Fixture
from wallet_fixture import PASSWORD
from platform_service import PlatformService

try:
    from platform_http import server
except ImportError:
    server=None


class HttpTests(unittest.TestCase):
    def setUp(self):
        self.assertIsNotNone(server,'local browser interface is missing')
        self.tmp=tempfile.TemporaryDirectory();self.root=Path(self.tmp.name);self.root.chmod(0o700)
        node=self.root/'node';node.mkdir(mode=0o700);self.fx=Fixture(node,mode='normal')
        self.workspace=self.root/'platform';self.workspace.mkdir(mode=0o700)
        for name in ('owner','raven','atlas'):
            shutil.copyfile(node/(name+'.pem'),self.workspace/(name+'.pem'))
            (self.workspace/(name+'.pem')).chmod(0o600)
        c=self.fx.chain
        self.roles={n:dict(payer=c.payer,grant_id='' if n=='owner' else n,vault=n+'.pem') for n in ('owner','raven','atlas')}
        with self.service(create=True) as svc:
            svc.import_checkpoint(self.fx.proof,expected_tip=None);svc.sync(expected_revision=None)
        self.web=server(self.service,port=0)
        self.thread=threading.Thread(target=lambda:self.web.serve_forever(poll_interval=.01),daemon=True)
        self.thread.start();self.origin=f'http://127.0.0.1:{self.web.server_port}'
        code,body,_=self.call('GET','/api/session');self.assertEqual(200,code)
        self.token=json.loads(body)['csrf']

    def service(self,**kw):
        return PlatformService(self.workspace,self.fx.chain.genesis,self.fx.chain.policy,
            self.fx.url,self.roles,clock=self.fx.chain.clock,**kw)

    def tearDown(self):
        if hasattr(self,'web'):self.web.shutdown();self.web.server_close();self.thread.join(2)
        if hasattr(self,'fx'):self.fx.close()
        if hasattr(self,'tmp'):self.tmp.cleanup()

    def call(self,method,path,value=None,*,headers=None,raw=None):
        h={'Origin':self.origin,'Sec-Fetch-Site':'same-origin'}
        if method=='POST':
            h.update({'Content-Type':'application/json','X-1soft-CSRF':getattr(self,'token','')})
        h.update(headers or {})
        data=raw if raw is not None else (None if value is None else json.dumps(value).encode())
        conn=http.client.HTTPConnection('127.0.0.1',self.web.server_port,timeout=5)
        conn.request(method,path,body=data,headers=h);response=conn.getresponse()
        result=(response.status,response.read(),dict(response.getheaders()));conn.close();return result

    def request(self):
        code,raw,_=self.call('POST','/api/create-request',dict(recipient=self.fx.chain.merchant,
            units='58',note='Local browser test',lifetime_seconds=600))
        self.assertEqual(200,code,raw);return json.loads(raw)['request_id']

    def test_foreign_origin_host_and_fetch_refused(self):
        for headers in ({'Origin':'https://example.invalid'},{'Host':'evil.invalid'},
                        {'Sec-Fetch-Site':'cross-site'},{'Origin':'null'}):
            self.assertEqual(403,self.call('GET','/api/session',headers=headers)[0])
        self.assertEqual(403,self.call('POST','/api/create-request',{},headers={'Origin':''})[0])

    def test_every_post_requires_token(self):
        for headers in ({'X-1soft-CSRF':''},{'X-1soft-CSRF':'bad'}):
            self.assertEqual(403,self.call('POST','/api/create-request',{},headers=headers)[0])

    def test_get_cannot_mutate(self):
        for path in ('/api/sign','/api/submit','/api/refresh','/api/create-request'):
            self.assertEqual(404,self.call('GET',path)[0])
        self.assertEqual([],self.fx.submissions)

    def test_body_bounds_types_duplicate_keys_and_encoding(self):
        cases=[(b'{}',{'Content-Type':'text/plain'}),
               (b'{"units":"1","units":"2"}',{}),(b'[]',{}),(b'{bad',{}),
               (b'x'*65537,{}),(b'{}',{'Content-Encoding':'gzip'})]
        for raw,headers in cases:
            self.assertIn(self.call('POST','/api/create-request',raw=raw,headers=headers)[0],(400,413,415))

    def test_unknown_fields_and_vault_paths_refused(self):
        self.assertEqual(400,self.call('POST','/api/create-request',dict(recipient=self.fx.chain.merchant,
            units='58',note='x',lifetime_seconds=600,vault='/tmp/secret'))[0])
        self.assertEqual(404,self.call('GET','/../../owner.pem')[0])
        self.assertEqual(404,self.call('POST','/api/reset',{})[0])

    def test_assets_have_no_store_csp_and_no_cors(self):
        code,raw,headers=self.call('GET','/')
        self.assertEqual(200,code);self.assertIn(b'1soft',raw)
        self.assertIn("default-src 'none'",headers['Content-Security-Policy'])
        self.assertEqual('no-store',headers['Cache-Control'])
        self.assertNotIn('Access-Control-Allow-Origin',headers)
        for path in ('/wallet.css','/wallet.js'):self.assertEqual(200,self.call('GET',path)[0])

    def test_request_export_and_state_are_exact_readonly(self):
        rid=self.request();before=list(self.fx.reads)
        code,raw,_=self.call('GET','/api/request/'+rid)
        self.assertEqual(200,code);self.assertEqual('58',json.loads(raw)['units'])
        self.assertEqual(rid,hashlib.sha256(raw).hexdigest())
        self.assertEqual(200,self.call('GET','/api/state')[0]);self.assertEqual(before,self.fx.reads)

    def test_review_is_opaque_canonical_json_not_rounded_browser_numbers(self):
        rid=self.request();code,raw,_=self.call('POST','/api/prepare',dict(request_id=rid,role='raven',valid_until=30))
        self.assertEqual(200,code);p=json.loads(raw)
        self.assertIsInstance(p['review_json'],str);self.assertEqual('60',p['summary']['debit_units'])
        self.assertNotIn('review',p)
        self.assertEqual(p['confirmation'],hashlib.sha256(p['review_json'].encode()).hexdigest())

    def test_full_browser_api_workflow_and_no_secret_echo(self):
        rid=self.request();_,raw,_=self.call('POST','/api/prepare',dict(request_id=rid,role='raven',valid_until=30));p=json.loads(raw)
        code,raw,_=self.call('POST','/api/sign',dict(request_id=rid,role='raven',review_json=p['review_json'],
            confirmation=p['confirmation'],password=PASSWORD.decode()))
        self.assertEqual(200,code,raw);self.assertNotIn(PASSWORD,raw);self.assertEqual([],self.fx.submissions)
        _,raw,_=self.call('POST','/api/submission-review',dict(request_id=rid));q=json.loads(raw)
        code,raw,_=self.call('POST','/api/submit',dict(request_id=rid,review_json=q['review_json'],confirmation=q['confirmation']))
        self.assertEqual(200,code,raw);self.assertFalse(json.loads(raw)['execution_proven'])
        self.assertEqual(200,self.call('POST','/api/collect',dict(request_id=rid))[0])
        _,raw,_=self.call('GET','/api/state');state=json.loads(raw);self.assertEqual('60',state['wallet']['pending_debit_units'])
        code,raw,_=self.call('POST','/api/reconcile',dict(request_id=rid,expected_revision=state['wallet']['revision']))
        self.assertEqual(200,code,raw)
        code,raw,_=self.call('POST','/api/retain',dict(request_id=rid));self.assertEqual(200,code,raw)
        cid=json.loads(raw)['capsule_id']
        self.assertEqual(200,self.call('GET','/api/capsule/'+rid+'/'+cid)[0])
        self.assertEqual(200,self.call('GET','/api/original/'+rid)[0])
        self.assertEqual(1,len(self.fx.submissions))

    def test_generic_error_never_echoes_password_or_raw_input(self):
        sentinel='SECRET_SENTINEL_DO_NOT_ECHO'
        code,raw,_=self.call('POST','/api/sign',dict(request_id='0'*64,role='raven',review_json='{}',
            confirmation='0'*64,password=sentinel))
        self.assertEqual(400,code);self.assertNotIn(sentinel.encode(),raw)

    def test_refresh_is_explicit_and_does_not_sync_wallet(self):
        before=list(self.fx.reads);self.fx.publish()
        _,raw,_=self.call('GET','/api/state');state=json.loads(raw)
        self.assertEqual(before,self.fx.reads)
        code,raw,_=self.call('POST','/api/refresh',dict(expected_tip=state['ledger']['checkpoint']['evidence_id']))
        self.assertEqual(200,code,raw);self.assertFalse(json.loads(raw)['wallet_reservations_changed'])
        _,raw,_=self.call('GET','/api/state');new=json.loads(raw)
        self.assertEqual(state['wallet']['state_height'],new['wallet']['state_height'])
        self.assertGreater(int(new['ledger']['checkpoint']['state_height']),int(state['ledger']['checkpoint']['state_height']))


if __name__=='__main__':unittest.main()
