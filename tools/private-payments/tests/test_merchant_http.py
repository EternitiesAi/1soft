"""Loopback HTTP over real merchant/P4 components; SYNTHETIC quorum signatures."""
import base64
from contextlib import redirect_stderr
import copy
from dataclasses import replace
import http.client
import io
import json
from pathlib import Path
import socket
import tempfile
import threading
import time
import unittest
from unittest.mock import patch

from p4_fixture import build, bundle
from p4_receipt_capsule import encode_capsule, make_capsule, MAX_CAPSULE_BYTES
from payment_x402 import NativePaymentExpectation, make_payment_required, make_payment_signature
from merchant_book import MerchantBook

try:
    import merchant_http
except ImportError:
    merchant_http = None


class MerchantHTTPTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.case = build(rejected=True)
        c = cls.case
        cls.wire = c['wires']['after']
        cls.capsule = encode_capsule(make_capsule(bundle(c), c['genesis'], c['policy'],
            cls.wire, payer=c['payer'], now_ns=c['now_ns']))

    def setUp(self):
        self.assertIsNotNone(merchant_http, 'bounded loopback merchant fixture is missing')
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name); self.root.chmod(0o700)
        self.path = self.root / 'merchant.sqlite'; self.token = 'e' * 64
        self.now = self.case['now_ns']; self.resource = b'One immutable public report.\n'
        with self.factory(create=True): pass
        self.http = merchant_http.server(self.factory, session_token=self.token)
        self.expectation = NativePaymentExpectation(self.http.origin,
            self.http.origin + '/premium/report?edition=1', '1soft:http-fixture', '1soft:DEV',
            self.case['policy']['genesis_sha256'], self.case['merchant'], '38')
        self.required = make_payment_required(self.expectation,
            created_ns=self.now - 2 * 10**9, expires_ns=self.now + 58 * 10**9,
            quote_nonce='a' * 64, description='Public report', mime_type='text/plain')
        with self.factory() as book:
            self.quote_id = book.add_quote(self.required, self.expectation,
                                          resource=self.resource)['quote_sha256']
            book.enroll_wire(self.quote_id, self.case['payer'], self.wire, evidence=bundle(self.case, 6))
        self.http.configure_quote(self.quote_id)
        self.thread = threading.Thread(target=self.http.serve_forever,
                                       kwargs={'poll_interval': 0.01}, daemon=True)
        self.thread.start()

    def tearDown(self):
        if hasattr(self, 'http'):
            if hasattr(self, 'thread'):
                self.http.shutdown(); self.thread.join(timeout=6)
                self.assertFalse(self.thread.is_alive())
            self.http.server_close()
        if hasattr(self, 'tmp'): self.tmp.cleanup()

    def factory(self, **kwargs):
        return MerchantBook(self.path, self.case['genesis'], self.case['policy'],
                            clock=lambda: self.now, **kwargs)

    def signature(self, capsule=None):
        return make_payment_signature(required_header=self.required, expectation=self.expectation,
            exact_wire=self.wire, capsule=self.capsule if capsule is None else capsule,
            payer=self.case['payer'], now_ns=self.now)

    def request(self, method='GET', path='/premium/report?edition=1', body=None, headers=None):
        h = {'X-1soft-Merchant-Session': self.token} if headers is None else dict(headers)
        connection = http.client.HTTPConnection('127.0.0.1', self.http.server_port, timeout=6)
        try:
            connection.request(method, path, body=body, headers=h)
            response = connection.getresponse()
            return response.status, response.getheaders(), response.read()
        finally: connection.close()

    def post(self, capsule=None, headers=None):
        body = self.capsule if capsule is None else capsule
        h = {'X-1soft-Merchant-Session': self.token, 'Content-Type': 'application/json',
             'PAYMENT-SIGNATURE': self.signature(capsule=body)} if headers is None else headers
        return self.request('POST', body=body, headers=h)

    def raw(self, request):
        with socket.create_connection(('127.0.0.1', self.http.server_port), timeout=6) as sock:
            sock.sendall(request)
            result = b''
            while True:
                part = sock.recv(65536)
                if not part: break
                result += part
            return result

    def baseline_headers(self):
        return ('Host: 127.0.0.1:' + str(self.http.server_port) + '\r\n' +
                'X-1soft-Merchant-Session: ' + self.token + '\r\n')

    def test_authenticated_get_returns_required_offer_without_consume_or_financial_authority(self):
        with self.factory() as book:
            before = book.db.execute('SELECT last_ns FROM config').fetchone()
        code, headers, body = self.request()
        self.assertEqual(code, 402)
        self.assertEqual(dict(headers)['PAYMENT-REQUIRED'], self.required)
        self.assertNotIn(self.resource, body); self.assertNotIn(self.token.encode(), body)
        with self.factory() as book:
            self.assertEqual(book.db.execute('SELECT last_ns FROM config').fetchone(), before)
            self.assertIsNone(book.selected(self.quote_id)['fulfillment'])
        self.assertFalse((self.root / 'wallet.sqlite').exists())

    def test_missing_token_wrong_host_origin_and_fetch_are_refused(self):
        for headers in ({}, {'X-1soft-Merchant-Session': '0' * 64},
            {'X-1soft-Merchant-Session': self.token, 'Host': 'localhost:' + str(self.http.server_port)},
            {'X-1soft-Merchant-Session': self.token, 'Origin': 'https://elsewhere.example'},
            {'X-1soft-Merchant-Session': self.token, 'Sec-Fetch-Site': 'cross-site'}):
            with self.subTest(headers=list(headers)):
                code, _, body = self.request(headers=headers)
                self.assertEqual(code, 403)
                self.assertNotIn(self.token.encode(), body); self.assertNotIn(self.resource, body)
        with self.factory() as book: self.assertIsNone(book.selected(self.quote_id)['fulfillment'])

    def test_genuine_capsule_post_returns_retained_resource_and_response(self):
        code, headers, body = self.post()
        self.assertEqual(code, 200); self.assertEqual(body, self.resource)
        response = dict(headers)
        self.assertIn('PAYMENT-RESPONSE', response)
        self.assertEqual(response['Content-Type'], 'text/plain')
        self.assertEqual(response['Cache-Control'], 'no-store')
        self.assertNotIn('Access-Control-Allow-Origin', response)
        with self.factory() as book: self.assertIsNotNone(book.selected(self.quote_id)['fulfillment'])

    def test_lost_http_return_can_retrieve_same_resource_without_second_claim(self):
        # Close after sending the complete request, without reading a response.
        body = self.capsule
        request = ('POST /premium/report?edition=1 HTTP/1.0\r\n' + self.baseline_headers() +
            'Content-Type: application/json\r\nPAYMENT-SIGNATURE: ' + self.signature() +
            '\r\nContent-Length: ' + str(len(body)) + '\r\n\r\n').encode() + body
        with socket.create_connection(('127.0.0.1', self.http.server_port), timeout=6) as sock:
            sock.sendall(request)
        # Verify the first request actually committed before testing retrieval;
        # a queued/lost socket alone would not prove that local fulfillment.
        deadline = time.monotonic() + 3
        while True:
            with self.factory() as book: retained = book.selected(self.quote_id)['fulfillment']
            if retained is not None or time.monotonic() >= deadline: break
            time.sleep(0.01)
        self.assertIsNotNone(retained)
        code, headers, result = self.post()
        self.assertEqual(code, 200); self.assertEqual(result, self.resource)
        again_code, again_headers, again_result = self.post()
        self.assertEqual((again_code, again_result), (200, self.resource))
        self.assertEqual(dict(headers)['PAYMENT-RESPONSE'], dict(again_headers)['PAYMENT-RESPONSE'])
        with self.factory() as book:
            self.assertEqual(book.db.execute('SELECT count(*) FROM fulfillments').fetchone()[0], 1)

    def test_invalid_capsule_cannot_deliver_resource_even_after_prior_completion(self):
        self.post()
        capsule = json.loads(self.capsule)
        capsule['evidence']['headers'][6]['signed_header']['commit']['signatures'][0]['signature'] = (
            base64.b64encode(b'\0' * 64).decode())
        raw = json.dumps(capsule, sort_keys=True, separators=(',', ':')).encode()
        code, _, body = self.post(capsule=raw)
        self.assertEqual(code, 400); self.assertNotIn(self.resource, body)
        self.assertNotIn(self.token.encode(), body)

    def test_duplicate_headers_chunked_get_body_and_lengths_are_refused_before_consume(self):
        requests = [
            'GET /premium/report?edition=1 HTTP/1.0\r\n' + self.baseline_headers() +
            'host: 127.0.0.1:' + str(self.http.server_port) + '\r\n\r\n',
            'GET /premium/report?edition=1 HTTP/1.0\r\n' + self.baseline_headers() +
            'Content-Length: 1\r\n\r\nx',
            'POST /premium/report?edition=1 HTTP/1.0\r\n' + self.baseline_headers() +
            'Content-Type: application/json\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\n',
            'POST /premium/report?edition=1 HTTP/1.0\r\n' + self.baseline_headers() +
            'Content-Type: application/json\r\nContent-Length: 1\r\ncontent-length: 1\r\n\r\nx',
            'POST /premium/report?edition=1 HTTP/1.0\r\n' + self.baseline_headers() +
            'Content-Type: application/json\r\nPAYMENT-SIGNATURE: ' + self.signature() +
            '\r\nContent-Length: ' + str(MAX_CAPSULE_BYTES + 1) + '\r\n\r\n',
            'POST /premium/report?edition=1 HTTP/1.0\r\n' + self.baseline_headers() +
            'Content-Type: application/json\r\nPAYMENT-SIGNATURE: ' + 'A' * 32769 +
            '\r\nContent-Length: 1\r\n\r\nx']
        for request, expected in zip(requests, (400, 400, 400, 400, 413, 400)):
            with self.subTest(size=len(request)):
                response = self.raw(request.encode())
                self.assertTrue(response.startswith(b'HTTP/1.0 '))
                self.assertEqual(int(response.split(b' ', 2)[1]), expected)
                self.assertNotIn(self.resource, response); self.assertNotIn(self.token.encode(), response)
        with self.factory() as book: self.assertIsNone(book.selected(self.quote_id)['fulfillment'])

    def test_duplicate_json_and_wrong_content_type_never_fulfill(self):
        for raw, mime in ((b'{"schema":1,"schema":1}', 'application/json'),
                          (self.capsule, 'text/plain')):
            headers = {'X-1soft-Merchant-Session': self.token, 'Content-Type': mime,
                       'PAYMENT-SIGNATURE': self.signature()}
            code, _, body = self.post(capsule=raw, headers=headers)
            self.assertIn(code, (400, 415)); self.assertNotIn(self.resource, body)
        with self.factory() as book: self.assertIsNone(book.selected(self.quote_id)['fulfillment'])

    def test_quote_selector_is_trusted_fixed_and_never_taken_from_request(self):
        with self.assertRaises(ValueError): self.http.configure_quote(self.quote_id)
        for path in ('/premium/report', '/premium/report?edition=2', '/api/session',
                     '/premium/report?quote_id=' + self.quote_id, '/enroll'):
            code, _, body = self.request(path=path)
            self.assertEqual(code, 404); self.assertNotIn(self.resource, body)
        for method in ('PUT', 'DELETE', 'PATCH', 'OPTIONS', 'HEAD', 'CUSTOM'):
            code, _, body = self.request(method)
            self.assertEqual(code, 405); self.assertNotIn(self.resource, body)

    def test_obsolete_http_version_never_uses_the_payment_route(self):
        response = self.raw(('GET /premium/report?edition=1 HTTP/0.9\r\n' +
                             self.baseline_headers() + '\r\n').encode())
        self.assertEqual(response, b'{"error":"request_refused"}')
        with self.factory() as book: self.assertIsNone(book.selected(self.quote_id)['fulfillment'])

    def test_server_is_literal_loopback_and_tokens_never_enter_log_or_error_body(self):
        self.assertEqual(self.http.server_address[0], '127.0.0.1')
        self.assertFalse(hasattr(self.http, 'session_token'))
        output = io.StringIO()
        with redirect_stderr(output):
            self.request(headers={'X-1soft-Merchant-Session': self.token + 'SECRET'})
            self.request(path='/not-the-resource/' + self.token)
        self.assertEqual(output.getvalue(), '')
        with self.assertRaises(ValueError): merchant_http.server(self.factory, session_token='short')

    def multi_routes(self, *, configure=True, duplicate_path=False, empty_query=False):
        self.http.shutdown(); self.thread.join(timeout=6); self.http.server_close()
        del self.thread
        self.path = self.root / 'multi.sqlite'
        with self.factory(create=True): pass
        self.http = merchant_http.server(self.factory, session_token=self.token)
        rows = []
        for i, recipient in enumerate((self.case['merchant'], self.case['payer'])):
            path = '/public/one' if i == 0 or duplicate_path else '/public/two'
            if empty_query and i == 0: path += '?'
            expectation = NativePaymentExpectation(self.http.origin, self.http.origin + path,
                '1soft:http-fixture', '1soft:DEV', self.case['policy']['genesis_sha256'], recipient, '38')
            required = make_payment_required(expectation, created_ns=self.now - 10**9,
                expires_ns=self.now + 59 * 10**9, quote_nonce=str(i + 1) * 64,
                mime_type='text/plain')
            with self.factory() as book:
                qid = book.add_quote(required, expectation, resource=b'Public result ' + str(i + 1).encode())['quote_sha256']
                if i == 0: book.enroll_wire(qid, self.case['payer'], self.wire, evidence=bundle(self.case, 6))
            rows.append((qid, required, expectation))
        self.quote_id, self.required, self.expectation = rows[0]
        if configure:
            self.http.configure_quotes(tuple(row[0] for row in rows))
            self.start_multi()
        return rows

    def start_multi(self):
        self.thread = threading.Thread(target=self.http.serve_forever,
            kwargs={'poll_interval': 0.01}, daemon=True)
        self.thread.start()

    def test_multiple_static_routes_return_their_own_offer_without_consumption(self):
        rows = self.multi_routes()
        for path, row in zip(('/public/one', '/public/two'), rows):
            code, headers, body = self.request(path=path)
            self.assertEqual(code, 402)
            self.assertEqual(dict(headers)['PAYMENT-REQUIRED'], row[1])
            self.assertNotIn(b'Public result', body)
        with self.factory() as book:
            self.assertEqual(book.db.execute('SELECT count(*) FROM fulfillments').fetchone()[0], 0)
        self.assertEqual(self.request(path='/public/two?quote_id=' + rows[0][0])[0], 404)
        with self.assertRaises(ValueError): self.http.configure_quote(rows[0][0])

    def test_proof_on_another_static_route_cannot_rebundle_or_poison_first_route(self):
        rows = self.multi_routes()
        headers = {'X-1soft-Merchant-Session': self.token, 'Content-Type': 'application/json',
                   'PAYMENT-SIGNATURE': self.signature()}
        code, _, body = self.request('POST', path='/public/two', body=self.capsule, headers=headers)
        self.assertEqual(code, 400); self.assertNotIn(b'Public result', body)
        first = self.request('POST', path='/public/one', body=self.capsule, headers=headers)
        second = self.request('POST', path='/public/one', body=self.capsule, headers=headers)
        self.assertEqual(first[0], 200); self.assertEqual(first[2], b'Public result 1')
        self.assertEqual(first[2], second[2])
        self.assertEqual(dict(first[1])['PAYMENT-RESPONSE'], dict(second[1])['PAYMENT-RESPONSE'])
        with self.factory() as book:
            self.assertIsNone(book.selected(rows[1][0])['fulfillment'])
            self.assertEqual(book.db.execute('SELECT count(*) FROM fulfillments').fetchone()[0], 1)

    def test_duplicate_static_paths_fail_atomically_before_any_route_is_fixed(self):
        rows = self.multi_routes(configure=False, duplicate_path=True)
        with self.assertRaises(ValueError): self.http.configure_quotes(tuple(r[0] for r in rows))
        self.http.configure_quote(rows[0][0]); self.start_multi()
        code, headers, _ = self.request(path='/public/one')
        self.assertEqual(code, 402); self.assertEqual(dict(headers)['PAYMENT-REQUIRED'], rows[0][1])

    def test_route_configuration_never_drops_original_empty_query_spelling(self):
        rows = self.multi_routes(configure=False, empty_query=True)
        with self.assertRaises(ValueError): self.http.configure_quote(rows[0][0])
        self.http.configure_quote(rows[1][0]); self.start_multi()
        self.assertEqual(self.request(path='/public/two')[0], 402)

    def test_static_route_configuration_is_bounded_unique_and_never_incremental(self):
        rows = self.multi_routes(configure=False)
        for ids in ((), [rows[0][0]], (rows[0][0], rows[0][0]), tuple('a' * 64 for _ in range(65))):
            with self.subTest(count=len(ids)):
                with self.assertRaises(ValueError): self.http.configure_quotes(ids)
        self.http.configure_quotes(tuple(r[0] for r in rows)); self.start_multi()
        with self.assertRaises(ValueError): self.http.configure_quotes((rows[0][0],))
        self.assertEqual(self.request(path='/public/two')[0], 402)

    def test_slow_headers_cannot_extend_the_total_socket_read_budget(self):
        response = b''
        with patch.object(merchant_http, 'SOCKET_TIMEOUT_SECONDS', 0.1):
            with socket.create_connection(('127.0.0.1', self.http.server_port), timeout=2) as sock:
                sock.sendall(b'GET /premium/report?edition=1 HTTP/1.0\r\n')
                try:
                    for line in (('Host: 127.0.0.1:' + str(self.http.server_port) + '\r\n').encode(),
                            ('X-1soft-Merchant-Session: ' + self.token + '\r\n').encode(), b'\r\n'):
                        time.sleep(0.07); sock.sendall(line)
                    while True:
                        part = sock.recv(65536)
                        if not part: break
                        response += part
                except OSError: pass
        self.assertNotIn(b'PAYMENT-REQUIRED', response)
        self.assertNotIn(self.resource, response)
        self.assertEqual(self.request()[0], 402)
        with self.factory() as book: self.assertIsNone(book.selected(self.quote_id)['fulfillment'])


if __name__ == '__main__': unittest.main()
