"""Local HTTP + real native application, synthetic fixed-committee signatures.

Fixture starts from the known PR7 wallet tests. No CometBFT execution is claimed.
Every transmitted byte is a disposable signed native transaction, never real funds.
"""
import base64
from contextlib import contextmanager
import copy
import hashlib
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
import socket
import threading

import test_wallet_obligations as fixtures
from certificate_fixture import make_header, make_commit
from commit_verifier import encode, header_hash, verify_packet


class Node:
    def __init__(self, case):
        self.c = case
        self.requests = []
        self.packets = {}
        self.continuations = []
        self.drop_reply = False
        self.decline = False
        self.do_execute = True
        self.fail_reads = False
        self.forge = False
        self.delay_target_reads = 0

    def execute(self, raw):
        c = self.c
        # Header h+1 has already attested the wallet snapshot, so its contents
        # are fixed. Advance that empty block before including a new payment.
        stamp = c.witness['state_commit']['header']['time']
        c.advance([])
        state_before = json.loads(c.app.query('/state')['value'])
        previous = c.witnesses[-2]['state_commit']['commit']['block_id']
        h = make_header(c.trust, c.app.height+1, c.app.app_hash, [raw], previous=previous)
        h['version']['app'] = '3'
        h['time'] = stamp
        signed = make_commit(h, c.trust, c.valkeys)
        c.witness['state_commit'] = signed
        c.witnesses[-1] = c.witness
        height = c.app.height + 1
        result = c.app.finalize_block([raw], height, header_hash(h))
        c.app.commit()
        assert result['tx_results'][0]['code'] == 0, result
        c.make_witness()
        c.witness['state_commit']['header']['time'] = stamp
        c.witness['state_commit'] = make_commit(c.witness['state_commit']['header'], c.trust, c.valkeys)
        packet = {'schema': 1, 'state': c.witness['state'], 'state_commit': c.witness['state_commit'],
                  'transactions': [{'tx': base64.b64encode(raw).decode(), 'commit': signed,
                    'block': {'block_id': signed['commit']['block_id'],
                              'block': {'header': h, 'data': {'txs': [base64.b64encode(raw).decode()]}}}}]}
        from native_core import DOMAIN, canonical
        txid = hashlib.sha256(DOMAIN + canonical(json.loads(raw)['body'])).hexdigest()
        assert verify_packet(packet, c.trust, expected_txids=[txid])['status'] == 'verified'
        self.packets[txid] = packet
        self.continuations.append(signed)
        return packet


@contextmanager
def server(node):
    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *args): pass
        def do_POST(self):
            message = json.loads(self.rfile.read(int(self.headers['Content-Length'])))
            node.requests.append(message)
            method, params = message['method'], message['params']
            if method == 'broadcast_tx_sync':
                raw = base64.b64decode(params['tx'], validate=True)
                if node.do_execute and not node.decline:
                    node.execute(raw)
                if node.drop_reply:
                    self.connection.shutdown(socket.SHUT_RDWR)
                    self.connection.close()
                    return
                payload = {'code': 7 if node.decline else 0, 'hash': hashlib.sha256(raw).hexdigest().upper()}
            else:
                if node.fail_reads or not node.packets:
                    self.respond({'jsonrpc':'2.0','id':message['id'], 'error':{'code':-32000}})
                    return
                packet = copy.deepcopy(list(node.packets.values())[-1])
                if node.forge:
                    packet['state_commit']['commit']['signatures'][0]['signature'] = base64.b64encode(bytes(64)).decode()
                if method == 'abci_query':
                    payload = {'response':{'code':0,'height':str(packet['state']['height']),
                               'value':base64.b64encode(encode(packet['state'])).decode()}}
                elif method == 'block':
                    payload = packet['transactions'][0]['block']
                elif method == 'commit':
                    height = int(params['height'])
                    if height == int(packet['state_commit']['header']['height']):
                        if node.delay_target_reads:
                            node.delay_target_reads -= 1
                            self.respond({'jsonrpc':'2.0','id':message['id'], 'error':{'code':-32000}})
                            return
                        payload = {'signed_header':packet['state_commit']}
                    else:
                        payload = {'signed_header':packet['transactions'][0]['commit']}
                else:
                    raise AssertionError('unanticipated RPC method '+method)
            self.respond({'jsonrpc':'2.0','id':message['id'],'result':payload})
        def respond(self, obj):
            raw = encode(obj)
            self.send_response(200)
            self.send_header('Content-Type','application/json')
            self.send_header('Content-Length',str(len(raw)))
            self.end_headers()
            try: self.wfile.write(raw)
            except OSError: pass
    http = ThreadingHTTPServer(('127.0.0.1', 0), Handler)
    http.daemon_threads = True
    http.block_on_close = False
    thread = threading.Thread(target=lambda:http.serve_forever(poll_interval=.01), daemon=True)
    thread.start()
    try: yield f'http://127.0.0.1:{http.server_port}/'
    finally:
        http.shutdown(); http.server_close(); thread.join(timeout=2)
