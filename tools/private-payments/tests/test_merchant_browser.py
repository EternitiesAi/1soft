"""Real committed-invoice/API regression tests; synthetic headers, no consensus."""
from contextlib import contextmanager
import copy
import hashlib
import importlib.util
import http.client
import json
from pathlib import Path
import shutil
import tempfile
import threading
import unittest
from unittest.mock import patch

from block_application import encode
from wallet_fixture import Chain, PASSWORD
from invoice_book import initialize_invoice_storage, open_invoice_storage
from platform_service import PlatformService
from private_payment_desk import PrivatePaymentDesk
from payment_x402 import NativePaymentExpectation, make_payment_required
from platform_http import server


class MerchantBrowserTests(unittest.TestCase):
    def call(self, method, path, value=None, *, headers=None, raw=None):
        h={'Origin':self.origin,'Sec-Fetch-Site':'same-origin'}
        if method=='POST': h.update({'Content-Type':'application/json','X-1soft-CSRF':getattr(self,'token','')})
        h.update(headers or {})
        data=raw if raw is not None else (None if value is None else json.dumps(value).encode())
        conn=http.client.HTTPConnection('127.0.0.1',self.web.server_port,timeout=5)
        conn.request(method,path,body=data,headers=h);response=conn.getresponse()
        result=(response.status,response.read(),dict(response.getheaders()));conn.close();return result

    def setUp(self):
        self.assertIsNotNone(importlib.util.find_spec('merchant_browser'),
                             'merchant browser authority adapter is missing')
        from merchant_browser import MerchantBrowserService
        self.adapter = MerchantBrowserService
        self.tmp = tempfile.TemporaryDirectory(); self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name); self.root.chmod(0o700)
        self.chain = Chain(self.root, invoice_commitments=True); self.addCleanup(self.chain.close)
        c = self.chain
        self.workspace = self.root/'wallet'; self.workspace.mkdir(mode=0o700)
        for name in ('owner', 'raven', 'atlas'):
            shutil.copyfile(self.root/(name+'.pem'), self.workspace/(name+'.pem'))
            (self.workspace/(name+'.pem')).chmod(0o600)
        self.roles = {n:dict(payer=c.payer, grant_id='' if n=='owner' else n, vault=n+'.pem')
                      for n in ('owner', 'raven', 'atlas')}
        with self.platform(create=True) as svc:
            svc.import_checkpoint(c.evidence(), expected_tip=None); svc.sync(expected_revision=None)
        self.storage = self.root/'invoices'
        initialize_invoice_storage(self.storage, c.policy['genesis_sha256'], password=PASSWORD, clock=c.clock)
        expected = NativePaymentExpectation('https://merchant.example', 'https://merchant.example/premium',
            '1soft:local-dev', '1soft:DEV', c.policy['genesis_sha256'], c.merchant, '7')
        self.resource_hash = hashlib.sha256(b'public report\n').hexdigest()
        # Deliberately above JS exact-number precision and not a multiple of 256.
        self.created = c.now-1000000001; self.expires = c.now+60000000001
        header = make_payment_required(expected, created_ns=self.created, expires_ns=self.expires,
            quote_nonce='a'*64, resource_sha256=self.resource_hash)
        with self.platform() as svc, open_invoice_storage(self.storage, c.policy['genesis_sha256'], clock=c.clock) as inv:
            desk = PrivatePaymentDesk(svc, inv)
            self.rid = desk.import_invoice(header, expected, {'description':'private sentinel invoice',
                'contact':'private@example.invalid', 'content':'SECRET_INVOICE_SENTINEL'}, invoice_password=PASSWORD)['request_id']
        self.web = server(self.service)
        self.thread = threading.Thread(target=lambda:self.web.serve_forever(poll_interval=.01), daemon=True)
        self.thread.start(); self.addCleanup(self.stop_web)
        self.origin = f'http://127.0.0.1:{self.web.server_port}'
        code, raw, _ = self.call('GET', '/api/session'); self.assertEqual(code, 200)
        self.token = json.loads(raw)['csrf']

    def stop_web(self):
        self.web.shutdown(); self.web.server_close(); self.thread.join(3)
        self.assertFalse(self.thread.is_alive())

    def platform(self, **kw):
        c=self.chain
        return PlatformService(self.workspace, c.genesis, c.policy, 'http://127.0.0.1:39099/',
                               self.roles, clock=c.clock, **kw)

    @contextmanager
    def service(self):
        with self.platform() as svc, open_invoice_storage(self.storage, self.chain.policy['genesis_sha256'], clock=self.chain.clock) as inv:
            yield self.adapter(PrivatePaymentDesk(svc, inv))

    def prepare(self, role='raven'):
        code, raw, _ = self.call('POST', '/api/prepare', dict(request_id=self.rid, role=role, valid_until=30))
        self.assertEqual(code, 200, raw); return json.loads(raw)

    def sign_body(self, p):
        return dict(request_id=self.rid, role='raven', review_json=p['review_json'], confirmation=p['confirmation'],
                    terms_json=p['terms_json'], terms_confirmation=p['terms_confirmation'], password=PASSWORD.decode())

    def unsigned(self):
        with self.platform() as svc:
            self.assertEqual(svc.wallet.db.execute('SELECT count(*) FROM decisions').fetchone()[0], 0)
            self.assertEqual(svc.state()['wallet']['pending_debit_units'], '0')

    def test_prepare_binds_native_commitment_and_lossless_terms(self):
        p=self.prepare()
        self.assertNotIn('terms', p)
        terms=json.loads(p['terms_json']); review=json.loads(p['review_json'])
        self.assertEqual(hashlib.sha256(p['terms_json'].encode()).hexdigest(), p['terms_confirmation'])
        self.assertEqual(terms['format'], '1soft/private-payment-consent/v2')
        self.assertEqual(terms['created_ns'], self.created); self.assertEqual(terms['expires_ns'], self.expires)
        self.assertEqual(p['terms_summary']['expires_ns'], str(self.expires))
        self.assertEqual(p['terms_summary']['resource_sha256'], self.resource_hash)
        self.assertEqual(review['body']['op']['invoice_commitment'], terms['invoice_commitment'])
        self.unsigned()

    def test_generic_sign_cannot_bypass_merchant_terms(self):
        p=self.prepare(); body=self.sign_body(p); body.pop('terms_json'); body.pop('terms_confirmation')
        with patch('p4_wallet._load_vault', side_effect=AssertionError('must not unlock')) as unlock:
            self.assertEqual(self.call('POST', '/api/sign', body)[0], 400)
            unlock.assert_not_called()
        self.unsigned()

    def test_tampered_or_missing_terms_refused_before_key_access(self):
        p=self.prepare(); body=self.sign_body(p)
        forged=json.loads(p['terms_json']); forged['resource_url']='https://merchant.example/other'
        altered=encode(forged).decode()
        cases=[{**body,'terms_confirmation':'0'*64}, {**body,'terms_json':altered,
               'terms_confirmation':hashlib.sha256(altered.encode()).hexdigest()},
               {k:v for k,v in body.items() if k!='terms_confirmation'},
               {**body,'role':'atlas'}, {**body,'terms_json':p['terms_json']+' '}]
        with patch('p4_wallet._load_vault', side_effect=AssertionError('must not unlock')) as unlock:
            for value in cases: self.assertEqual(self.call('POST', '/api/sign-invoice', value)[0], 400)
            unlock.assert_not_called()
        self.unsigned()

    def test_plain_review_refused_even_with_forged_v2_terms(self):
        p=self.prepare()
        with self.platform() as svc: plain=svc.prepare(self.rid,'raven',valid_until=30)
        body=self.sign_body(p); body.update(review_json=encode(plain['review']).decode(), confirmation=plain['confirmation'])
        with patch('p4_wallet._load_vault', side_effect=AssertionError('must not unlock')) as unlock:
            self.assertEqual(self.call('POST','/api/sign-invoice',body)[0],400); unlock.assert_not_called()
        self.unsigned()

    def test_sign_reserves_original_invoice_wire_and_recovery_does_not_unlock(self):
        p=self.prepare(); code, raw, _=self.call('POST','/api/sign-invoice',self.sign_body(p))
        self.assertEqual(code,200,raw); self.assertNotIn(PASSWORD,raw)
        code, wire, _=self.call('GET','/api/original/'+self.rid); self.assertEqual(code,200)
        self.assertEqual(json.loads(wire)['body']['op']['invoice_commitment'],p['terms_summary']['invoice_commitment'])
        with self.platform() as svc: self.assertEqual(svc.state()['wallet']['pending_debit_units'],'9')
        with patch('p4_wallet._load_vault', side_effect=AssertionError('must not unlock')) as unlock:
            self.assertEqual(self.call('POST','/api/sign-invoice',self.sign_body(p))[0],200)
            unlock.assert_not_called()
        self.chain.now=self.expires
        self.assertEqual(self.call('GET','/api/original/'+self.rid)[1],wire)
        self.assertEqual(self.call('POST','/api/submission-review',dict(request_id=self.rid))[0],400)

    def test_state_is_key_free_lossless_metadata_not_private_content(self):
        with patch('invoice_book._load_vault',side_effect=AssertionError('no decrypt')) as unlock:
            code,raw,_=self.call('GET','/api/state'); self.assertEqual(code,200,raw); unlock.assert_not_called()
        self.assertNotIn(b'SECRET_INVOICE_SENTINEL',raw); self.assertNotIn(PASSWORD,raw)
        state=json.loads(raw); self.assertEqual(state['payment_mode'],'committed_merchant_invoices')
        row=state['requests'][0]
        self.assertEqual(row['request']['expires_ns'],str(self.expires))
        self.assertEqual(row['invoice']['resource_sha256'],self.resource_hash)
        self.assertFalse(row['invoice']['onchain_privacy'])
        self.chain.now=self.expires
        self.assertFalse(json.loads(self.call('GET','/api/state')[1])['requests'][0]['request_open'])

    def test_generic_request_mutations_refused(self):
        before=json.loads(self.call('GET','/api/state')[1])
        for route,value in [('create-request',dict(recipient=self.chain.merchant,units='7',note='x',lifetime_seconds=60)),
                            ('import-request',dict(request_json=encode(before['requests'][0]['request']).decode()))]:
            self.assertEqual(self.call('POST','/api/'+route,value)[0],400)
        self.assertEqual(json.loads(self.call('GET','/api/state')[1]),before)

    def test_catalog_corruption_does_not_fall_back_to_generic_wallet(self):
        with open_invoice_storage(self.storage,self.chain.policy['genesis_sha256'],clock=self.chain.clock) as inv:
            inv.db.execute('UPDATE invoices SET envelope_sha256=?',('0'*64,))
        self.assertEqual(self.call('GET','/api/state')[0],400)
        self.assertEqual(self.call('POST','/api/prepare',dict(request_id=self.rid,role='raven',valid_until=30))[0],400)
        self.unsigned()


    def test_foreign_request_cannot_enter_invoice_actions_or_exports(self):
        from payment_requests import new_request
        with self.platform() as svc:
            foreign=svc.add_request(new_request(self.chain.policy['genesis_sha256'],self.chain.merchant,'3',
                created_ns=self.created,expires_ns=self.expires,note='generic'))['request_id']
        p=self.prepare();bad=self.sign_body(p);bad['request_id']=foreign
        for method,route,body in [('GET','/api/request/'+foreign,None),('GET','/api/original/'+foreign,None),
                ('POST','/api/prepare',dict(request_id=foreign,role='raven',valid_until=30)),
                ('POST','/api/sign-invoice',bad),('POST','/api/submission-review',dict(request_id=foreign)),
                ('POST','/api/submit',dict(request_id=foreign,review_json='{}',confirmation='0'*64))]:
            self.assertEqual(self.call(method,route,body)[0],400)
        state=json.loads(self.call('GET','/api/state')[1])
        self.assertEqual(len(state['requests']),1);self.assertEqual(state['hidden_generic_request_count'],1)
        self.unsigned()

    def test_merchant_sign_route_keeps_origin_csrf_and_body_guards(self):
        body=self.sign_body(self.prepare())
        for headers in ({'Origin':'https://evil.invalid'},{'Host':'evil.invalid'},
                {'Sec-Fetch-Site':'cross-site'},{'X-1soft-CSRF':'bad'}):
            self.assertEqual(self.call('POST','/api/sign-invoice',body,headers=headers)[0],403)
        self.assertEqual(self.call('GET','/api/sign-invoice')[0],404)
        self.assertEqual(self.call('POST','/api/sign-invoice',body,headers={'Content-Type':'text/plain'})[0],415)
        self.assertEqual(self.call('POST','/api/sign-invoice',raw=b'{}'*40000)[0],413)
        self.unsigned()

    def test_legacy_quote_cannot_downgrade_browser_approval(self):
        expected=NativePaymentExpectation('https://merchant.example','https://merchant.example/legacy',
            '1soft:local-dev','1soft:DEV',self.chain.policy['genesis_sha256'],self.chain.merchant,'3')
        header=make_payment_required(expected,created_ns=self.created,expires_ns=self.expires,quote_nonce='b'*64)
        with self.platform() as svc,open_invoice_storage(self.storage,self.chain.policy['genesis_sha256'],clock=self.chain.clock) as inv:
            rid=PrivatePaymentDesk(svc,inv).import_invoice(header,expected,{'description':'legacy','contact':'legacy@example.invalid','content':'legacy fixture'},invoice_password=PASSWORD)['request_id']
        self.assertEqual(self.call('POST','/api/prepare',dict(request_id=rid,role='raven',valid_until=30))[0],400)
        body=self.sign_body(self.prepare());body['request_id']=rid
        with patch('p4_wallet._load_vault',side_effect=AssertionError('no downgrade')) as unlock:
            self.assertEqual(self.call('POST','/api/sign-invoice',body)[0],400);unlock.assert_not_called()
        self.unsigned()

    def test_nanosecond_terms_mutation_refused_before_unlock(self):
        body=self.sign_body(self.prepare());terms=json.loads(body['terms_json']);terms['expires_ns']+=1
        body.update(terms_json=encode(terms).decode(),terms_confirmation=hashlib.sha256(encode(terms)).hexdigest())
        with patch('p4_wallet._load_vault',side_effect=AssertionError('must not unlock')) as unlock:
            self.assertEqual(self.call('POST','/api/sign-invoice',body)[0],400);unlock.assert_not_called()
        self.unsigned()

    def test_corrupt_original_bound_review_refuses_invoice_state_and_export(self):
        p=self.prepare();self.assertEqual(self.call('POST','/api/sign-invoice',self.sign_body(p))[0],200)
        with self.platform() as svc:
            value=svc.book.selected(self.rid);review=copy.deepcopy(value['review']);review['invoice_terms']['resource_sha256']='0'*64
            svc.book.db.execute('UPDATE bindings SET review=? WHERE request_id=?',(encode(review),self.rid))
        self.assertEqual(self.call('GET','/api/state')[0],400)
        self.assertEqual(self.call('GET','/api/original/'+self.rid)[0],400)

    def test_trust_expiry_keeps_original_wire_and_blocks_current_authority(self):
        p=self.prepare();self.assertEqual(self.call('POST','/api/sign-invoice',self.sign_body(p))[0],200)
        wire=self.call('GET','/api/original/'+self.rid)[1]
        self.chain.now+=4000*10**9
        state=json.loads(self.call('GET','/api/state')[1]);self.assertFalse(state['current_evidence_available'])
        self.assertIsNone(state['wallet']);self.assertEqual(state['requests'][0]['stage'],'signed_reserved')
        self.assertEqual(self.call('GET','/api/original/'+self.rid)[1],wire)
        self.assertEqual(self.call('POST','/api/submission-review',dict(request_id=self.rid))[0],400)


class HistoricalLauncherTests(unittest.TestCase):
    def test_original_ready_pins_allow_historical_view_without_clock_renewal(self):
        import merchant_browser
        self.assertTrue(hasattr(merchant_browser,'ready_for_browser'),'historical browser startup validation missing')
        from types import SimpleNamespace
        from unittest.mock import Mock
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory);root.chmod(0o700)
            workspace=b'{"context":"original"}';policy=b'{"deadline":"expired"}'
            (root/'workspace.json').write_bytes(workspace);(root/'policy.json').write_bytes(policy)
            ready=dict(schema=3,format='1soft/local-development-ready/v3',
                workspace_sha256=hashlib.sha256(workspace).hexdigest(),policy_sha256=hashlib.sha256(policy).hexdigest())
            (root/'READY.json').write_bytes(encode(ready))
            for p in root.iterdir():p.chmod(0o600)
            net=SimpleNamespace(root=root,config={'schema':3},_ready_bytes=encode(ready),
                policy=Mock(return_value={'original':'expired'}),_check_config=Mock(),
                ready=Mock(side_effect=AssertionError('live startup must not be called')))
            self.assertTrue(merchant_browser.ready_for_browser(net));net.ready.assert_not_called()
            self.assertEqual((root/'policy.json').read_bytes(),policy)
            ready['policy_sha256']='0'*64;(root/'READY.json').write_bytes(encode(ready))
            net._ready_bytes=encode(ready)
            with self.assertRaises(ValueError):merchant_browser.ready_for_browser(net)

if __name__=='__main__': unittest.main()
