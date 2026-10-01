"""Explicit local DEV merchant operations over one immutable consumption book.

The finite recipient pool comes only from an independently validated ready v2
workspace. A recipient remains assigned forever, including after expiry/payment.
No key, wallet journal, submission or external resource callback is accessed.
"""
from contextlib import contextmanager
from dataclasses import asdict
import fcntl
import hashlib
import os
from pathlib import Path
import re
import secrets
import time
from urllib.parse import urlsplit

from block_application import encode
from local_devnet import private_new, read_private
from merchant_book import MerchantBook, MAX_QUOTES, MAX_RESOURCE_BYTES
from merchant_devnet import MerchantNetwork
from native_core import address
from p4_evidence import hash_text, integer, need, p4_genesis, policy_checked
from p4_read_store import private_path
from payment_x402 import NativePaymentExpectation, make_payment_required
from merchant_http import server

ROOT = Path(__file__).resolve().parents[3]
ASSET = '1soft:DEV'
SESSION_FORMAT = '1soft/local-merchant-session/v1'


def private_output(path):
    """Exclusive owner-only output outside source; no replacement or repair."""
    target = private_path(path)
    need(not target.is_relative_to(ROOT) and not target.exists() and not target.is_symlink(),
         'new private output outside source required')
    return target


def loopback_origin(value):
    need(type(value) is str and re.fullmatch(r'http://127\.0\.0\.1:[1-9][0-9]{0,4}', value) is not None,
         'exact literal loopback merchant origin required')
    port = integer(int(value.rsplit(':', 1)[1]), 1, 65535)
    need(value == 'http://127.0.0.1:' + str(port), 'noncanonical loopback port')
    return port


class MerchantOps:
    """An operator adapter, never native spending authority or a second wallet."""
    def __init__(self, network):
        need(type(network) is MerchantNetwork and network.ready(),
             'independently validated ready merchant development network required')
        self.network = network
        self.root = Path(network.root).absolute()
        need(not self.root.is_relative_to(ROOT), 'merchant workspace must be outside source')
        self.path = private_path(self.root / 'merchant.sqlite')
        self.lock_path = private_path(self.root / 'merchant-ops.lock')
        self._configuration = encode(network.config)
        self.genesis = read_private(self.root / 'engine-genesis.json')
        self._policy = encode(policy_checked(network.policy()))
        config = network.config
        genesis, _ = p4_genesis(self.genesis, config['genesis_sha256'])
        pool = config.get('merchant_recipients')
        need(type(pool) is list and 1 <= len(pool) <= MAX_QUOTES and
             all(type(recipient) is str for recipient in pool) and len(set(pool)) == len(pool) and
             config.get('merchant') == pool[0] and genesis['asset'] == 'DEV',
             'validated finite DEV merchant recipient pool required')
        allocated = {address(row['public_key']) for row in genesis['allocations']}
        need(set(pool) <= allocated, 'configured pool recipient is absent from native genesis')
        self.recipients = tuple(pool)
        self.network_id = '1soft:local-' + config['genesis_sha256'][:24]
        self._context()

    def _context(self):
        need(Path(self.network.root).absolute() == self.root and self.network.ready() and
             read_private(self.root / 'workspace.json') == self._configuration and
             encode(self.network.config) == self._configuration and
             read_private(self.root / 'engine-genesis.json') == self.genesis and
             encode(policy_checked(self.network.policy())) == self._policy,
             'independent original merchant workspace/genesis/policy context changed')

    def _rows(self, book):
        rows = book.entries()
        for row in rows:
            e = row['expectation']
            need(e.recipient in self.recipients and e.network == self.network_id and e.asset == ASSET and
                 e.genesis_sha256 == self.network.config['genesis_sha256'],
                 'canonical merchant book contains a quote outside the independently pinned pool/context')
            loopback_origin(e.merchant_origin)
        return rows

    @contextmanager
    def operation(self):
        """Serialize operator route checks and retention without nested SQLite.

        This canonical empty private advisory lock is not a funds journal. It
        fails immediately if another operator owns it and releases on process
        exit/crash. HTTP proof verification still uses MerchantBook transactions.
        """
        self._context()
        need(read_private(self.lock_path, 1) == b'', 'canonical private merchant operator lock differs')
        fd = os.open(self.lock_path, os.O_RDWR | os.O_NOFOLLOW)
        try:
            actual = os.fstat(fd); named = self.lock_path.stat()
            need((actual.st_dev, actual.st_ino, actual.st_size) == (named.st_dev, named.st_ino, 0),
                 'merchant operator lock identity differs')
            try: fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except BlockingIOError: raise ValueError('another merchant operator owns this context') from None
            self._context()
            yield
        finally: os.close(fd)

    def book(self, *, read_only=False):
        """Open only the canonical workspace book, rechecking original pins."""
        self._context()
        need(read_private(self.lock_path, 1) == b'', 'canonical private merchant operator lock differs')
        book = MerchantBook(self.path, self.genesis, self.network.policy(),
                            clock=self.network.clock, read_only=read_only)
        try: self._rows(book)
        except BaseException:
            book.close(); raise
        return book

    def init_book(self):
        self._context(); private_output(self.path)
        private_output(self.lock_path); private_new(self.lock_path, b'')
        with self.operation():
            with MerchantBook(self.path, self.genesis, self.network.policy(),
                              clock=self.network.clock, create=True): pass
        return {'status': 'merchant_book_initialized', 'book': str(self.path),
                'recipient_count': len(self.recipients), 'spending_authority': False}

    def add_quote(self, *, recipient_index, merchant_origin, resource_path, amount_units,
                  resource, expires_ns, description='', mime_type='application/octet-stream'):
        index = integer(recipient_index, 0, len(self.recipients) - 1)
        loopback_origin(merchant_origin)
        need(type(resource_path) is str and resource_path.startswith('/') and
             not resource_path.startswith('//') and len(resource_path) <= 2048 and
             '#' not in resource_path and urlsplit(resource_path).geturl() == resource_path,
             'bounded exact public resource path required')
        need(type(resource) is bytes and 0 < len(resource) <= MAX_RESOURCE_BYTES,
             'explicit bounded nonempty PUBLIC resource bytes required')
        now = integer(self.network.clock(), 1)
        expectation = NativePaymentExpectation(merchant_origin, merchant_origin + resource_path,
            self.network_id, ASSET, self.network.config['genesis_sha256'], self.recipients[index], amount_units)
        required = make_payment_required(expectation, created_ns=now, expires_ns=expires_ns,
            quote_nonce=secrets.token_hex(32), description=description, mime_type=mime_type)
        with self.operation(), self.book() as book:
            rows = self._rows(book)
            need(not any(row['expectation'].resource_url == expectation.resource_url for row in rows),
                 'exact public resource route is already assigned; no replacement')
            result = book.add_quote(required, expectation, resource=resource)
        return {**result, 'recipient_index': index, 'recipient': expectation.recipient,
            'merchant_origin': merchant_origin, 'resource_url': expectation.resource_url,
            'network': self.network_id, 'asset': ASSET,
            'resource_sha256': hashlib.sha256(resource).hexdigest(), 'spending_authority': False}

    def inspect(self):
        with self.book(read_only=True) as book: rows = self._rows(book)
        displayed = [{**row, 'expectation': asdict(row['expectation'])} for row in rows]
        return {'status': 'merchant_book_inspected', 'book': str(self.path),
            'network': self.network_id, 'asset': ASSET, 'recipient_count': len(self.recipients),
            'assigned_recipient_count': len(rows), 'quotes': displayed, 'spending_authority': False}

    def export_quote(self, quote_id, *, required_out, expectation_out):
        hash_text(quote_id)
        required_path = private_output(required_out); expectation_path = private_output(expectation_out)
        need(required_path != expectation_path, 'quote output files must be distinct')
        with self.operation():
            with self.book(read_only=True) as book: row = book.selected(quote_id)
            # Files cannot be committed atomically together. Retained originals
            # stay untouched if either output fails; export into two fresh paths.
            private_new(required_path, row['required_header'].encode('ascii'))
            private_new(expectation_path, encode(asdict(row['expectation'])))
        return {'status': 'original_merchant_quote_exported', 'quote_sha256': quote_id,
            'required_out': str(required_path), 'expectation_out': str(expectation_path),
            'spending_authority': False}

    def enroll_wire(self, quote_id, *, payer, wire, evidence):
        hash_text(quote_id)
        with self.operation(), self.book() as book:
            return book.enroll_wire(quote_id, payer, wire, evidence=evidence)

    def serve(self, quote_ids, *, session_file, seconds, port=None):
        integer(seconds, 1, 300)
        target = private_output(session_file)
        need(type(quote_ids) is tuple and 1 <= len(quote_ids) <= MAX_QUOTES,
             'bounded fixed tuple of merchant quote IDs required')
        for qid in quote_ids: hash_text(qid)
        need(len(set(quote_ids)) == len(quote_ids), 'duplicate selected merchant quote')
        with self.operation():
            with self.book(read_only=True) as book: selected = [book.selected(qid) for qid in quote_ids]
            origins = {row['expectation'].merchant_origin for row in selected}
            need(len(origins) == 1, 'one exact retained loopback origin required for serving')
            origin = next(iter(origins)); pinned_port = loopback_origin(origin)
            if port is not None: need(integer(port, 1, 65535) == pinned_port, 'server port differs from retained merchant origin')
            token = secrets.token_hex(32)
            bound = server(self.book, session_token=token, port=pinned_port)
            try:
                bound.configure_quotes(quote_ids)
                session = {'schema': 1, 'format': SESSION_FORMAT, 'origin': bound.origin,
                    'quote_ids': list(quote_ids), 'session_token': token, 'configured_seconds': seconds}
                private_new(target, encode(session))
            except BaseException:
                bound.server_close(); token = None; raise
        try:
            deadline = time.monotonic() + seconds
            bound.request_deadline = deadline
            while (remaining := deadline - time.monotonic()) > 0:
                bound.timeout = min(0.25, remaining)
                bound.handle_request()
        finally:
            bound.server_close()
            token = None
        return {'status': 'merchant_fixture_stopped', 'origin': origin, 'quote_ids': list(quote_ids),
            'session_file': str(target), 'seconds': seconds, 'owned_handlers_after_cleanup': 0,
            'spending_authority': False, 'wallet_reservations_changed': False,
            'full_public_ledger_disclosed_on_payment': True, 'onchain_privacy': False}
