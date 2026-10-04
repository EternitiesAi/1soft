"""Actual native replay with synthetic quorum/clock; real local merchant HTTP."""
import hashlib
import importlib.util
import secrets
import threading
import unittest
from unittest.mock import patch

from block_application import encode
from local_devnet import private_new
from merchant_ops import SESSION_FORMAT
from merchant_http import server
import test_alpha_merchant as fixtures


class AlphaBrowserDeliveryTests(unittest.TestCase):
    setUp = fixtures.AlphaMerchantTests.setUp
    append = fixtures.AlphaMerchantTests.append
    sign = fixtures.AlphaMerchantTests.sign
    counts = fixtures.AlphaMerchantTests.counts
    merchant = fixtures.AlphaMerchantTests.merchant
    invoice = fixtures.AlphaMerchantTests.invoice
    paid = fixtures.AlphaMerchantTests.paid

    def bridge(self, *, enrolled=True):
        spec = importlib.util.find_spec('merchant_browser_delivery')
        self.assertIsNotNone(spec, 'explicit bounded browser merchant bridge is missing')
        from merchant_browser_delivery import AlphaMerchantBridge
        self.token = secrets.token_hex(32)
        self.http = server(self.merchant, session_token=self.token)
        self.addCleanup(self.http.server_close)
        self.origin = self.http.origin
        with patch('p4_alpha_custody.time.time_ns', self.c.clock):
            self.row = self.paid()
            if enrolled:
                with self.merchant() as m:
                    m.enroll_wire(self.row[1], self.c.payer, self.row[5], evidence=self.row[6])
        self.http.configure_quote(self.row[1])
        self.thread = threading.Thread(target=self.http.serve_forever, daemon=True)
        self.thread.start()
        self.addCleanup(self.stop_http)
        self.session = self.root / 'merchant-session.json'
        private_new(self.session, encode(dict(schema=1, format=SESSION_FORMAT,
            origin=self.origin, quote_ids=[self.row[1]], session_token=self.token, configured_seconds=300)))
        return AlphaMerchantBridge(self.session, self.read_merchant, self.c.genesis, self.c.policy)

    def read_merchant(self):
        from merchant_alpha import AlphaMerchantBook
        return AlphaMerchantBook(self.root / 'merchant-alpha.sqlite', self.c.genesis,
                                 self.c.policy, clock=self.c.clock, read_only=True)

    def stop_http(self):
        self.http.shutdown()
        self.thread.join(timeout=5)
        self.assertFalse(self.thread.is_alive(), 'owned local HTTP thread was not closed')

    def test_paid_resource_http_and_proof_preserve_wallet_and_hold(self):
        bridge = self.bridge()
        before = self.counts()
        hold = self.s.state()['wallet']['pending_debit_units']
        review = bridge.review(self.desk, self.row[0])
        with patch('p4_alpha_custody.time.time_ns', self.c.clock):
            result = bridge.retrieve(self.desk, self.row[0], review['review'], review['confirmation'])
            proof = bridge.proof(self.desk, self.row[0])
        self.assertEqual(result['resource'], self.row[4])
        self.assertEqual(result['resource_sha256'], hashlib.sha256(self.row[4]).hexdigest())
        self.assertEqual(proof['raw'], result['proof'])
        self.assertEqual(self.counts(), before)
        self.assertEqual(self.s.state()['wallet']['pending_debit_units'], hold)
        self.assertNotIn(self.token, encode(bridge.status(self.desk, self.row[0])).decode())

    def test_unenrolled_payment_refuses_before_network_transport(self):
        bridge = self.bridge(enrolled=False)
        with patch.object(bridge, '_post') as transport, self.assertRaises(ValueError):
            bridge.review(self.desk, self.row[0])
        transport.assert_not_called()

    def test_changed_review_refuses_before_network_transport(self):
        bridge = self.bridge()
        reviewed = bridge.review(self.desk, self.row[0])
        changed = dict(reviewed['review'], resource_sha256='0' * 64)
        with patch.object(bridge, '_post') as transport, self.assertRaises(ValueError):
            bridge.retrieve(self.desk, self.row[0], changed, reviewed['confirmation'])
        transport.assert_not_called()

    def test_session_replacement_refuses_without_adopting_new_token(self):
        bridge = self.bridge()
        changed = self.session.read_bytes().replace(self.token.encode(), b'0' * 64)
        self.session.write_bytes(changed)
        with self.assertRaises(ValueError):
            bridge.review(self.desk, self.row[0])

    def test_completed_cold_retry_after_horizon_never_uses_live_payer_header(self):
        bridge = self.bridge()
        reviewed = bridge.review(self.desk, self.row[0])
        with patch('p4_alpha_custody.time.time_ns', self.c.clock):
            first = bridge.retrieve(self.desk, self.row[0], reviewed['review'], reviewed['confirmation'])
        self.c.now = self.c.policy['absolute_not_after_ns'] + 1
        from merchant_browser_delivery import AlphaMerchantBridge
        cold = AlphaMerchantBridge(self.session, self.read_merchant, self.c.genesis, self.c.policy)
        with patch.object(self.desk, 'payment_header', side_effect=AssertionError('live payer path used')):
            reviewed = cold.review(self.desk, self.row[0])
            with patch('p4_alpha_custody.time.time_ns', self.c.clock):
                again = cold.retrieve(self.desk, self.row[0], reviewed['review'], reviewed['confirmation'])
        self.assertEqual(again['resource'], first['resource'])
        self.assertEqual(again['fulfilled_ns'], first['fulfilled_ns'])
        self.assertEqual(again['payment_response_header'], first['payment_response_header'])

    def test_expired_unfulfilled_enrollment_cannot_consume(self):
        bridge = self.bridge()
        self.c.now += 700 * 10**9
        with self.assertRaises(ValueError):
            bridge.review(self.desk, self.row[0])
        with self.merchant() as m:
            self.assertIsNone(m.selected(self.row[1])['fulfillment'])

    def test_completion_during_packet_export_invalidates_exact_review_before_post(self):
        bridge=self.bridge();reviewed=bridge.review(self.desk,self.row[0])
        original=self.desk.platform.capsule
        changed=False
        def complete_during_export(*args):
            nonlocal changed
            raw=original(*args)
            if not changed:
                changed=True
                with self.merchant() as book:
                    book.fulfill(self.row[1],self.row[7],self.row[6])
            return raw
        with patch('p4_alpha_custody.time.time_ns',self.c.clock), \
             patch.object(self.desk.platform,'capsule',side_effect=complete_during_export), \
             patch.object(bridge,'_post',side_effect=AssertionError('changed snapshot dispatched')) as transport:
            with self.assertRaises(ValueError):
                bridge.retrieve(self.desk,self.row[0],reviewed['review'],reviewed['confirmation'])
        transport.assert_not_called()

    def test_absolute_reader_refuses_progress_past_deadline(self):
        import io,merchant_browser_delivery
        reader=getattr(merchant_browser_delivery,'_DeadlineReader',None)
        self.assertIsNotNone(reader,'absolute raw response reader is missing')
        now=[0.0]
        class Socket:
            def __init__(self):self.calls=0
            def settimeout(self,value):pass
            def recv_into(self,buffer):
                self.calls+=1;buffer[0]=65;now[0]=121.0;return 1
        socket=Socket()
        with patch('merchant_http.time.monotonic',side_effect=lambda:now[0]):
            stream=io.BufferedReader(reader(socket,120.0))
            try:
                with self.assertRaises(TimeoutError):stream.read(2)
                self.assertEqual(socket.calls,1)
            finally:stream.close()

    def test_unconfigured_browser_has_no_retrieval_capability(self):
        from merchant_browser import MerchantBrowserService
        bridge=self.bridge();browser=MerchantBrowserService(self.desk)
        with self.assertRaises(ValueError):browser.resource_review(self.row[0])
        self.assertFalse(browser.state()['merchant_fulfillment_available'])

    def test_connection_progress_past_deadline_sends_no_packet_bytes(self):
        bridge=self.bridge();row=bridge._row(self.desk,self.row[0],packet=True);now=[0.0]
        class Socket:
            sent=[]
            def settimeout(self,value):pass
            def close(self):pass
            def sendall(self,value):self.sent.append(value)
        socket=Socket()
        def connect(connection):
            connection.sock=socket;now[0]=121.0
        with patch('merchant_browser_delivery.time.monotonic',side_effect=lambda:now[0]), \
             patch('http.client.HTTPConnection.connect',new=connect):
            with self.assertRaises(ValueError):bridge._post(row,120.0)
        self.assertEqual(len(socket.sent),0,'no packet may be sent after connection consumed the deadline')

    def test_corrupted_resource_return_is_unresolved_but_consumption_is_retained(self):
        bridge=self.bridge();reviewed=bridge.review(self.desk,self.row[0])
        handler=self.http.RequestHandlerClass;original=handler._reply
        def wrong(handler,code,raw,mime='application/json',payment=None):
            return original(handler,code,b'wrong public resource' if code==200 else raw,mime,payment)
        with patch('p4_alpha_custody.time.time_ns',self.c.clock),patch.object(handler,'_reply',new=wrong):
            with self.assertRaises(ValueError):bridge.retrieve(self.desk,self.row[0],reviewed['review'],reviewed['confirmation'])
        self.assertTrue(bridge.status(self.desk,self.row[0])['consumption_retained'])
        reviewed=bridge.review(self.desk,self.row[0])
        with patch('p4_alpha_custody.time.time_ns',self.c.clock):
            self.assertEqual(bridge.retrieve(self.desk,self.row[0],reviewed['review'],reviewed['confirmation'])['resource'],self.row[4])

    def test_substituted_native_transaction_header_is_refused(self):
        from payment_x402 import _decode,_header,MAX_RESPONSE_HEADER
        bridge=self.bridge();reviewed=bridge.review(self.desk,self.row[0])
        handler=self.http.RequestHandlerClass;original=handler._reply
        def wrong(handler,code,raw,mime='application/json',payment=None):
            if code==200:
                value,_=_decode(payment[1],MAX_RESPONSE_HEADER);value['transaction']='0'*64
                payment=('PAYMENT-RESPONSE',_header(value,MAX_RESPONSE_HEADER))
            return original(handler,code,raw,mime,payment)
        with patch('p4_alpha_custody.time.time_ns',self.c.clock),patch.object(handler,'_reply',new=wrong):
            with self.assertRaises(ValueError):bridge.retrieve(self.desk,self.row[0],reviewed['review'],reviewed['confirmation'])
        self.assertTrue(bridge.status(self.desk,self.row[0])['consumption_retained'])


if __name__ == '__main__':
    unittest.main()
