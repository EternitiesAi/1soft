"""Synchronous bounded loopback merchant fixture; public full-ledger transport.

One trusted retained quote, one handler at a time, and no signing, dispatch or
wire enrollment endpoint. The local session token authenticates fixture access;
it is neither merchant identity nor payment proof and is never served or logged.
"""
from __future__ import annotations

import hmac
from http.server import BaseHTTPRequestHandler, HTTPServer
import re
import sqlite3
from urllib.parse import urlsplit

from p4_evidence import hash_text, integer, need
from p4_receipt_capsule import MAX_CAPSULE_BYTES, parse_capsule
from merchant_book import MerchantBook, MAX_RESOURCE_BYTES
from payment_x402 import MAX_SIGNATURE_HEADER, payment_header, parse_payment_required

MAX_HEADER_COUNT = 64
MAX_HEADER_BYTES = 65536
SOCKET_TIMEOUT_SECONDS = 5
ERROR_BODY = b'{"error":"request_refused"}'
CSP = "default-src 'none'; base-uri 'none'; frame-ancestors 'none'; form-action 'none'"


def server(book_factory, *, session_token, port=0, quote_id=None):
    """Bind literal loopback; configure one immutable trusted quote before serving.

    Supply a fresh independent secrets.token_hex(32) token for each process.
    With an ephemeral port, retain a quote at returned_server.origin, then call
    returned_server.configure_quote(quote_id) exactly once. No client selects it.
    The factory must return the same context-managed MerchantBook per request.
    """
    need(callable(book_factory) and type(session_token) is str and
         re.fullmatch(r'[0-9a-f]{64}', session_token) is not None,
         'independent 32-byte local merchant session token required')
    integer(port, 0, 65535)

    class Handler(BaseHTTPRequestHandler):
        protocol_version = 'HTTP/1.0'

        def log_message(self, *_): pass

        def setup(self):
            super().setup()
            self.connection.settimeout(SOCKET_TIMEOUT_SECONDS)

        def __getattr__(self, name):
            # BaseHTTPRequestHandler otherwise emits a method-reflecting 501.
            # Every unsupported method uses our auth gate and generic 405.
            if name.startswith('do_'): return self.do_unsupported
            raise AttributeError(name)

        def _reply(self, code, raw, mime='application/json', payment=None):
            self.close_connection = True
            try:
                self.send_response(code)
                self.send_header('Content-Type', mime)
                self.send_header('Content-Length', str(len(raw)))
                self.send_header('Cache-Control', 'no-store')
                self.send_header('Connection', 'close')
                self.send_header('Content-Security-Policy', CSP)
                self.send_header('X-Content-Type-Options', 'nosniff')
                self.send_header('Referrer-Policy', 'no-referrer')
                self.send_header('Cross-Origin-Resource-Policy', 'same-origin')
                if payment is not None: self.send_header(*payment)
                self.end_headers()
                if getattr(self, 'command', None) != 'HEAD': self.wfile.write(raw)
            except OSError:
                # A failed return does not undo the durable local result or
                # authorize another side effect. No raw exception is logged.
                pass

        def send_error(self, code, *_args, **_kwargs):
            self._reply(405 if code == 501 else code, ERROR_BODY)

        def _headers(self):
            need(self.request_version in ('HTTP/1.0', 'HTTP/1.1'), 'unsupported HTTP version')
            need(not self.headers.defects, 'malformed HTTP headers')
            rows = list(self.headers.raw_items())
            need(len(rows) <= MAX_HEADER_COUNT and
                 sum(len(k) + len(v) + 4 for k, v in rows) <= MAX_HEADER_BYTES,
                 'HTTP header work exceeds bound')
            names = set()
            for key, value in rows:
                need(type(key) is str and re.fullmatch(r'[!#$%&\x27*+.^_`|~0-9A-Za-z-]{1,128}', key)
                     is not None, 'invalid HTTP header name')
                lower = key.lower()
                need(lower not in names and type(value) is str and len(value) <= MAX_SIGNATURE_HEADER and
                     value.isascii() and all(32 <= ord(c) < 127 for c in value),
                     'duplicate or invalid bounded HTTP header')
                names.add(lower)
            need(self.headers.get('Transfer-Encoding') is None and
                 self.headers.get('Content-Encoding') is None and self.headers.get('Expect') is None,
                 'unsupported request transfer/encoding/expectation')
            return rows

        def _auth(self):
            expected_host = '127.0.0.1:' + str(self.server.server_port)
            need(self.headers.get('Host') == expected_host, 'loopback host refused')
            supplied = self.headers.get('X-1soft-Merchant-Session')
            need(type(supplied) is str and hmac.compare_digest(supplied, session_token),
                 'merchant session refused')
            origin = self.headers.get('Origin')
            need(origin is None or origin == self.server.origin, 'loopback origin refused')
            site = self.headers.get('Sec-Fetch-Site')
            need(site is None or site in ('same-origin', 'none'), 'cross-site request refused')

        def _guard(self):
            try: rows = self._headers()
            except (ValueError, TypeError): self._reply(400, ERROR_BODY); return None
            try: self._auth()
            except (ValueError, TypeError): self._reply(403, ERROR_BODY); return None
            return rows

        def _route(self):
            if self.server._quote is None:
                self._reply(503, ERROR_BODY); return False
            if self.path != self.server._quote['path']:
                self._reply(404, ERROR_BODY); return False
            return True

        def _book(self, book):
            need(type(book) is MerchantBook, 'trusted merchant book required')
            fixed = self.server._quote
            need((book.path, book.policy_id, book.policy['genesis_sha256']) == fixed['book_context'],
                 'merchant book factory changed original context')
            selected = book.selected(fixed['quote_id'])
            need(selected['required_header'] == fixed['required_header'] and
                 selected['expectation'] == fixed['expectation'] and
                 selected['resource_sha256'] == fixed['resource_sha256'],
                 'retained merchant quote/resource context changed')
            return selected

        def do_GET(self):
            if self._guard() is None or not self._route(): return
            if self.headers.get('Content-Length') not in (None, '0') or self.headers.get('PAYMENT-SIGNATURE') is not None:
                self._reply(400, ERROR_BODY); return
            try:
                with book_factory() as book: selected = self._book(book)
                self._reply(402, b'{"error":"payment_required"}',
                            payment=('PAYMENT-REQUIRED', selected['required_header']))
            except (ValueError, KeyError, TypeError, OSError, sqlite3.DatabaseError):
                self._reply(400, ERROR_BODY)
            except Exception: self._reply(500, ERROR_BODY)

        def do_POST(self):
            rows = self._guard()
            if rows is None or not self._route(): return
            if self.headers.get('Content-Type') != 'application/json':
                self._reply(415, ERROR_BODY); return
            length_text = self.headers.get('Content-Length')
            if type(length_text) is not str or re.fullmatch(r'[1-9][0-9]{0,7}', length_text) is None:
                self._reply(400, ERROR_BODY); return
            length = int(length_text)
            if length > MAX_CAPSULE_BYTES:
                self._reply(413, ERROR_BODY); return
            try:
                signature = payment_header(rows, 'PAYMENT-SIGNATURE')
                raw = self.rfile.read(length)
                need(len(raw) == length, 'incomplete bounded capsule body')
                # Strict canonical shape/duplicates/depth are checked before
                # opening the merchant book; actual replay happens in fulfill.
                parse_capsule(raw)
                with book_factory() as book:
                    self._book(book)
                    result = book.fulfill(self.server._quote['quote_id'], signature, raw)
                resource = result['resource']
                need(type(resource) is bytes and 0 < len(resource) <= MAX_RESOURCE_BYTES,
                     'bounded retained local result required')
                self._reply(200, resource, self.server._quote['mime'],
                            payment=('PAYMENT-RESPONSE', result['payment_response_header']))
            except (ValueError, KeyError, TypeError, OSError, sqlite3.DatabaseError):
                self._reply(400, ERROR_BODY)
            except Exception: self._reply(500, ERROR_BODY)

        def do_unsupported(self):
            if self._guard() is not None: self._reply(405, ERROR_BODY)

    class LocalServer(HTTPServer):
        allow_reuse_address = False
        request_queue_size = 4

        def __init__(self):
            self._quote = None
            super().__init__(('127.0.0.1', port), Handler)

        @property
        def origin(self): return 'http://127.0.0.1:' + str(self.server_port)

        def handle_error(self, *_): pass

        def configure_quote(self, selected_quote_id):
            """Trusted once-only setup, before serving; never reachable over HTTP."""
            need(self._quote is None, 'merchant HTTP quote is already fixed')
            hash_text(selected_quote_id)
            with book_factory() as book:
                need(type(book) is MerchantBook, 'trusted merchant book factory required')
                selected = book.selected(selected_quote_id)
                expectation = selected['expectation']
                need(expectation.merchant_origin == self.origin, 'retained quote does not use this exact loopback origin')
                checked = parse_payment_required(selected['required_header'], expectation, now_ns=book.clock())
                parsed = urlsplit(expectation.resource_url)
                path = parsed.path + ('?' + parsed.query if parsed.query else '')
                self._quote = {'quote_id': selected_quote_id, 'path': path, 'expectation': expectation,
                    'required_header': selected['required_header'], 'resource_sha256': selected['resource_sha256'],
                    'mime': checked['offer']['resource'].get('mimeType', 'application/octet-stream'),
                    'book_context': (book.path, book.policy_id, book.policy['genesis_sha256'])}

    bound = LocalServer()
    try:
        if quote_id is not None: bound.configure_quote(quote_id)
        return bound
    except BaseException:
        bound.server_close()
        raise
