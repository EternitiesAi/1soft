"""Optional local integration; requires the complete Codex catch-up source."""
import base64
import copy
from contextlib import contextmanager
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
import threading
import unittest
from unittest.mock import patch

import test_wallet_obligations as fixture
from commit_verifier import encode
from native_core import canonical
from wallet_refresh import refresh_wallet


@contextmanager
def rpc(witness, headers, *, target_commit_failures=0):
    reads = []
    remaining = [target_commit_failures]
    target = witness['state']['height'] + 1
    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *_): pass
        def do_POST(self):
            request = json.loads(self.rfile.read(int(self.headers['Content-Length'])))
            reads.append(request)
            if request['method'] == 'abci_query':
                result = {'response': {'code': 0, 'height': str(witness['state']['height']),
                          'value': base64.b64encode(encode(witness['state'])).decode()}}
            elif request['method'] == 'commit':
                height = int(request['params']['height'])
                if height == target and remaining[0]:
                    remaining[0] -= 1
                    raw = encode({'jsonrpc': '2.0', 'id': request['id'],
                                  'error': {'code': -32603, 'message': 'commit unavailable'}})
                    self.send_response(200)
                    self.send_header('Content-Type', 'application/json')
                    self.send_header('Content-Length', str(len(raw)))
                    self.end_headers(); self.wfile.write(raw)
                    return
                result = {'signed_header': headers[height]}
            else:
                self.send_error(400); return
            raw = encode({'jsonrpc': '2.0', 'id': request['id'], 'result': result})
            self.send_response(200)
            self.send_header('Content-Type', 'application/json')
            self.send_header('Content-Length', str(len(raw)))
            self.end_headers(); self.wfile.write(raw)
    server = ThreadingHTTPServer(('127.0.0.1', 0), Handler)
    thread = threading.Thread(target=lambda: server.serve_forever(poll_interval=.01), daemon=True)
    thread.start()
    try: yield f'http://127.0.0.1:{server.server_port}/', reads
    finally: server.shutdown(); server.server_close(); thread.join(timeout=2)


class ClientTests(unittest.TestCase):
    def setUp(self):
        self.c = fixture.ObligationTests(); self.c.setUp()
        self.signed = self.c.approve(until=2)
        self.headers = {2: copy.deepcopy(self.c.witness['state_commit'])}
        for i in range(4):
            self.c.advance([canonical(self.signed['result'])] if i == 0 else [])
            self.headers[self.c.app.height + 1] = copy.deepcopy(self.c.witness['state_commit'])
    def tearDown(self): self.c.tearDown()
    def held(self): return sum(self.c.wallet.pending()['pending_budget_units'].values())
    def test_reads_without_broadcast_then_reconciles(self):
        with rpc(self.c.witness, self.headers) as (url, reads):
            out = refresh_wallet(self.c.wallet, url)
        self.assertEqual(out['status'], 'synced'); self.assertEqual(self.held(), 0)
        self.assertTrue(all(r['method'] in ('abci_query', 'commit') for r in reads))
        self.assertEqual(self.c.witness['state']['native']['budgets'][0][4], 60)
    def test_partial_refresh_preserves_hold(self):
        with rpc(self.c.witness, self.headers) as (url, _):
            out = refresh_wallet(self.c.wallet, url, max_batches=1, headers_per_batch=2)
        self.assertEqual(out['status'], 'headers_only'); self.assertEqual(self.held(), 60)
    def test_reopen_resumes_from_saved_progress(self):
        with rpc(self.c.witness, self.headers) as (url, _):
            refresh_wallet(self.c.wallet, url, max_batches=1, headers_per_batch=2)
            self.c.wallet.close(); self.c.wallet = self.c.open()
            out = refresh_wallet(self.c.wallet, url)
        self.assertEqual(out['headers_accepted'], 2); self.assertEqual(self.held(), 0)
    def test_tampered_state_refused_before_header_reads(self):
        bad = copy.deepcopy(self.c.witness); bad['state']['native']['accounts'][0][4] += 1
        with rpc(bad, self.headers) as (url, reads): out = refresh_wallet(self.c.wallet, url)
        self.assertEqual(out['status'], 'rejected'); self.assertEqual(len(reads), 2)
        self.assertEqual(self.held(), 60)
    def test_expired_policy_has_no_network_effect(self):
        self.c.clock = self.c.wallet.trust_expires
        with rpc(self.c.witness, self.headers) as (url, reads): out = refresh_wallet(self.c.wallet, url)
        self.assertEqual(out['status'], 'rejected'); self.assertEqual(reads, [])
    def test_no_key_access(self):
        with rpc(self.c.witness, self.headers) as (url, _), patch('certified_wallet._load_vault', side_effect=AssertionError('no keys')):
            self.assertTrue(refresh_wallet(self.c.wallet, url)['state_synced'])
    def test_original_signature_unchanged(self):
        with rpc(self.c.witness, self.headers) as (url, _): refresh_wallet(self.c.wallet, url)
        self.assertEqual(self.c.wallet.export(self.signed['decision_id'])['result'], self.signed['result'])
    def test_public_endpoint_is_not_supported(self):
        with self.assertRaises(ValueError): refresh_wallet(self.c.wallet, 'https://example.com/')
    def test_retries_only_captured_commit_then_syncs(self):
        target = self.c.witness['state']['height'] + 1
        with rpc(self.c.witness, self.headers, target_commit_failures=2) as (url, reads):
            out = refresh_wallet(self.c.wallet, url)
        self.assertEqual(out['status'], 'synced')
        self.assertEqual(out['rpc_attempts'], 4 + out['headers_accepted'])
        self.assertEqual(sum(r['method'] == 'abci_query' for r in reads), 1)
        self.assertEqual([int(r['params']['height']) for r in reads[1:4]], [target] * 3)
        self.assertEqual(self.held(), 0)
    def test_missing_target_commit_leaves_wallet_held(self):
        target = self.c.witness['state']['height'] + 1
        before = self.c.wallet.header_status()
        with rpc(self.c.witness, self.headers, target_commit_failures=4) as (url, reads):
            out = refresh_wallet(self.c.wallet, url)
        self.assertEqual(out['status'], 'unavailable')
        self.assertEqual(out['rpc_attempts'], 5)
        self.assertEqual(out['headers_accepted'], 0)
        self.assertEqual(sum(r['method'] == 'abci_query' for r in reads), 1)
        self.assertEqual([int(r['params']['height']) for r in reads[1:]], [target] * 4)
        self.assertEqual(self.c.wallet.header_status(), before)
        self.assertEqual(self.held(), 60)
