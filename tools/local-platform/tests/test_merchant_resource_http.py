"""Key-free HTTP boundary checks; bridge/native evidence is tested separately."""
from contextlib import contextmanager
import hashlib
import http.client
import json
import threading
import unittest
from platform_http import server

RID='1'*64

class MerchantResourceHttpTests(unittest.TestCase):
    def setUp(self):
        self.calls=[];test=self
        class Service:
            def resource_review(self,rid):
                test.calls.append(('review',rid));return dict(review={'request_id':rid},confirmation='2'*64,summary={'request_id':rid})
            def retrieve_purchase(self,rid,review,confirmation):
                test.calls.append(('retrieve',rid));return dict(request_id=rid,resource=b'public purchase',
                    resource_sha256=hashlib.sha256(b'public purchase').hexdigest(),quote_sha256='3'*64,
                    wire_sha256='4'*64,capsule_sha256='5'*64,native_txid='6'*64,fulfilled_ns=1700000000000000001)
            def merchant_proof(self,rid):
                test.calls.append(('proof',rid));return dict(raw=b'public proof',resource=b'public purchase',
                    report=dict(request_id=rid,quote_sha256='3'*64,wire_sha256='4'*64,
                        capsule_sha256='5'*64,native_txid='6'*64,resource_sha256=hashlib.sha256(b'public purchase').hexdigest()),
                    fulfilled_ns=1700000000000000001)
        @contextmanager
        def factory():yield Service()
        self.http=server(factory);self.origin='http://127.0.0.1:'+str(self.http.server_port)
        self.thread=threading.Thread(target=self.http.serve_forever,daemon=True);self.thread.start()
        self.addCleanup(self.stop)
        _,_,raw=self.request('GET','/api/session');self.csrf=json.loads(raw)['csrf']
    def stop(self):
        self.http.shutdown();self.thread.join(timeout=5);self.http.server_close()
        self.assertFalse(self.thread.is_alive())
    def request(self,method,path,body=None,*,headers=None):
        connection=http.client.HTTPConnection('127.0.0.1',self.http.server_port,timeout=5)
        values=dict(headers or {})
        if body is not None:
            body=json.dumps(body).encode();values.setdefault('Content-Type','application/json')
            values.setdefault('Origin',self.origin);values.setdefault('X-1soft-CSRF',self.csrf)
        try:
            connection.request(method,path,body=body,headers=values);response=connection.getresponse()
            return response.status,dict(response.getheaders()),response.read()
        finally:connection.close()
    def test_exact_review_route_returns_opaque_canonical_text(self):
        code,_,raw=self.request('POST','/api/merchant-review',{'request_id':RID})
        self.assertEqual(code,200)
        self.assertEqual(json.loads(raw)['review_json'],'{"request_id":"'+RID+'"}')
        self.assertEqual(self.calls,[('review',RID)])
    def test_explicit_retrieve_returns_attachment_and_exact_string_pins(self):
        code,headers,raw=self.request('POST','/api/merchant-retrieve',dict(request_id=RID,
            review_json='{"request_id":"'+RID+'"}',confirmation='2'*64))
        self.assertEqual(code,200);self.assertEqual(raw,b'public purchase')
        self.assertEqual(headers['Content-Type'],'application/octet-stream')
        self.assertEqual(headers['X-1soft-Fulfilled-Ns'],'1700000000000000001')
        self.assertIn('attachment',headers['Content-Disposition'])
        self.assertEqual(self.calls,[('retrieve',RID)])
    def test_browser_cannot_supply_merchant_target_or_packet(self):
        code,_,_=self.request('POST','/api/merchant-retrieve',dict(request_id=RID,
            review_json='{}',confirmation='2'*64,merchant_origin='http://127.0.0.1:1'))
        self.assertEqual(code,400);self.assertEqual(self.calls,[])
    def test_proof_export_is_read_only_attachment_with_its_own_digest(self):
        code,headers,raw=self.request('GET','/api/merchant-proof/'+RID)
        self.assertEqual(code,200);self.assertEqual(raw,b'public proof')
        self.assertEqual(headers['X-1soft-Proof-Sha256'],hashlib.sha256(raw).hexdigest())
        self.assertEqual(self.calls,[('proof',RID)])
    def test_cross_origin_and_missing_csrf_refuse_before_retrieval(self):
        body=dict(request_id=RID,review_json='{}',confirmation='2'*64)
        for headers in ({'Origin':'https://other.invalid'},{'X-1soft-CSRF':'wrong'}):
            code,_,_=self.request('POST','/api/merchant-retrieve',body,headers=headers)
            self.assertEqual(code,403)
        self.assertEqual(self.calls,[])

if __name__=='__main__':unittest.main()
