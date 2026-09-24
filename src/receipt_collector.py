"""Read-only, bounded receipt collection from a literal-loopback development RPC.

The worker collects UNTRUSTED evidence, not a verified balance or payment. The
DispatchJournal independently verifies the returned packet against its pinned
validator set before recording execution. No signing, broadcast, DNS, redirects,
proxies, reserve release, genesis discovery or background polling is implemented.
"""
from __future__ import annotations
import base64
import hashlib
import http.client
import json
from pathlib import Path
import re
import subprocess
import sys
import tempfile
import time

from commit_verifier import (MAX_PACKET_BYTES, MAX_TX_BYTES, b64, encode, exact,
                             load_json, number)
from native_core import BODY_FIELDS, DOMAIN, canonical, fields
from payment_rpc import endpoint_port

MAX_RESPONSE = 8 * 1024 * 1024
MAX_SNAPSHOT = 4 * 1024 * 1024
WORKER_TIMEOUT = 15.0
MAX_READ_ATTEMPTS = 4
READ_PAUSE = 0.25
REASONS = {'rpc_unavailable', 'receipt_not_in_response', 'invalid_response',
           'transport_unavailable', 'worker_deadline_or_failure'}


class Unavailable(ValueError):
    """No usable evidence obtained; never means a payment did not execute."""


def attempts(value: int) -> int:
    if type(value) is not int or not 1 <= value <= MAX_READ_ATTEMPTS:
        raise ValueError('read attempts must be an integer from 1 to 4')
    return value


def _request(method: str, height: int | None) -> dict:
    if method == 'abci_query' and height is None:
        return {'path': '/state', 'prove': False}
    if method in ('block', 'commit'):
        number(height, minimum=1)
        if type(height) is int:
            return {'height': str(height)}
    raise ValueError('only the state query and fixed-height block/commit reads are permitted')


class Reader:
    def __init__(self, endpoint: str):
        self.port = endpoint_port(endpoint)
        self.requests = 0

    def call(self, method: str, height: int | None = None) -> dict:
        params = _request(method, height)  # Validate before any network I/O.
        if self.requests >= 3 + MAX_READ_ATTEMPTS:
            raise ValueError('read request bound reached')
        self.requests += 1
        request_id = self.requests
        body = encode({'jsonrpc': '2.0', 'id': request_id, 'method': method, 'params': params})
        conn = http.client.HTTPConnection('127.0.0.1', self.port, timeout=2)
        try:
            conn.request('POST', '/', body, {'Content-Type':'application/json',
                         'Accept':'application/json', 'Connection':'close'})
            response = conn.getresponse()
            if response.status != 200:
                raise Unavailable('rpc_unavailable')
            headers = response.getheaders()
            for name in ('content-length','transfer-encoding','content-encoding','content-type'):
                if sum(k.lower() == name for k, _ in headers) > 1:
                    raise ValueError('duplicate response framing header')
            length = response.getheader('Content-Length')
            transfer = response.getheader('Transfer-Encoding')
            if length is not None and transfer is not None:
                raise ValueError('ambiguous HTTP framing')
            if transfer is not None and transfer.lower() != 'chunked':
                raise ValueError('unsupported HTTP transfer encoding')
            if response.getheader('Content-Encoding','identity').lower() != 'identity':
                raise ValueError('compressed evidence not accepted')
            if response.getheader('Content-Type','').split(';')[0].strip().lower() != 'application/json':
                raise ValueError('expected JSON evidence')
            if length is not None and (len(length) > 12 or re.fullmatch(r'0|[1-9][0-9]*', length) is None
                                       or int(length) > MAX_RESPONSE):
                raise ValueError('response exceeds bound')
            raw = response.read(MAX_RESPONSE + 1)
            if len(raw) > MAX_RESPONSE or (length is not None and len(raw) != int(length)):
                raise ValueError('response size mismatch')
            message = load_json(raw, max_bytes=MAX_RESPONSE)
            if (type(message) is not dict or message.get('jsonrpc') != '2.0'
                or type(message.get('id')) is not int or message['id'] != request_id):
                raise ValueError('invalid JSON-RPC response')
            if set(message) == {'jsonrpc','id','error'}:
                raise Unavailable('rpc_unavailable')
            exact(message, {'jsonrpc','id','result'}, 'RPC response')
            if type(message['result']) is not dict:
                raise Unavailable('rpc_unavailable')
            return message['result']
        finally:
            conn.close()


def _raw_intention(raw: bytes) -> str:
    envelope = load_json(raw, max_bytes=MAX_TX_BYTES)
    fields(envelope, {'body','signature'})
    fields(envelope['body'], BODY_FIELDS)
    if canonical(envelope) != raw:
        raise ValueError('transaction bytes must be canonical')
    return hashlib.sha256(DOMAIN + canonical(envelope['body'])).hexdigest()


def _state_and_hint(response: dict, txid: str, raw: bytes) -> tuple[dict, int]:
    value = response.get('response')
    if type(value) is not dict or type(value.get('code')) is not int:
        raise ValueError('invalid ABCI response')
    if value['code'] != 0:
        raise Unavailable('rpc_unavailable')
    state = load_json(b64(value.get('value'), max_size=MAX_SNAPSHOT), max_bytes=MAX_SNAPSHOT)
    exact(state, {'genesis','height','app_hash','native'}, 'state response')
    state_height = number(state['height'], minimum=1, maximum=2**63-2)
    if type(state['height']) is not int or number(value.get('height'), minimum=1) != state_height:
        raise ValueError('ABCI/state height mismatch')
    if type(state['native']) is not dict or type(state['native'].get('receipts')) is not list:
        raise ValueError('invalid receipt table')
    matching = []
    for row in state['native']['receipts']:
        if type(row) is not list or len(row) != 5 or type(row[0]) is not str:
            raise ValueError('invalid receipt row')
        if row[0] == txid:
            matching.append(row)
    if not matching:
        raise Unavailable('receipt_not_in_response')
    if len(matching) != 1 or type(matching[0][3]) is not str:
        raise ValueError('ambiguous receipt hint')
    record = load_json(matching[0][3].encode(), max_bytes=MAX_TX_BYTES)
    if (type(record) is not dict or record.get('txid') != txid
        or encode(record.get('envelope')) != raw or type(record.get('height')) is not int):
        raise ValueError('receipt hint does not identify exact payment')
    included_height = number(record['height'], minimum=1, maximum=state_height)
    # These are lookup hints only; signatures and state commitment are verified later.
    return state, included_height


def _collect(endpoint: str, raw: bytes, read_attempts: int) -> dict:
    attempts(read_attempts)
    txid = _raw_intention(raw)
    reader = Reader(endpoint)
    try:
        state, height = _state_and_hint(reader.call('abci_query'), txid, raw)
        block = reader.call('block', height)
        tx_commit = reader.call('commit', height).get('signed_header')
        # Keep the same captured snapshot while waiting for its h+1 commitment.
        # Chasing a new head each attempt could perpetually miss that commitment.
        for attempt in range(read_attempts):
            try:
                state_commit = reader.call('commit', state['height'] + 1).get('signed_header')
                break
            except Unavailable:
                if attempt + 1 == read_attempts:
                    raise
                time.sleep(READ_PAUSE)
        if type(block.get('block')) is not dict:
            raise ValueError('missing transaction block')
        packet = {'schema':1, 'state':state, 'state_commit':state_commit,
                  'transactions':[{'tx':base64.b64encode(raw).decode(), 'commit':tx_commit,
                    'block':{'block_id':block.get('block_id'), 'block':{
                        'header':block['block'].get('header'), 'data':block['block'].get('data')}}}]}
        if len(encode(packet)) > MAX_PACKET_BYTES:
            raise ValueError('collected proof exceeds bound')
        return {'status':'evidence_collected', 'packet':packet, 'requests':reader.requests}
    except Unavailable as exc:
        return {'status':'evidence_unavailable', 'reason':str(exc), 'requests':reader.requests}
    except (OSError, http.client.HTTPException):
        return {'status':'evidence_unavailable', 'reason':'transport_unavailable', 'requests':reader.requests}
    except (ValueError, TypeError, KeyError, RecursionError):
        return {'status':'evidence_rejected', 'reason':'invalid_response', 'requests':reader.requests}


def fetch_packet(endpoint: str, raw: bytes, *, read_attempts: int = 1) -> dict:
    """Bounded child collects untrusted data. This function does NOT verify it."""
    endpoint_port(endpoint); attempts(read_attempts); _raw_intention(raw)
    request = encode({'endpoint':endpoint,'transaction':base64.b64encode(raw).decode(),
                      'read_attempts':read_attempts})
    # File-backed output avoids buffering arbitrary child stdout in parent memory.
    with tempfile.TemporaryFile() as output:
        try:
            result = subprocess.run([sys.executable,str(Path(__file__).resolve())], input=request,
                stdout=output,stderr=subprocess.DEVNULL,timeout=WORKER_TIMEOUT,check=False)
            if result.returncode != 0 or output.tell() > MAX_PACKET_BYTES + 4096:
                raise ValueError('invalid collector output')
            output.seek(0)
            data = load_json(output.read(MAX_PACKET_BYTES+4097), max_bytes=MAX_PACKET_BYTES+4096)
            if type(data) is not dict:
                raise ValueError('invalid collector result')
            number(data.get('requests'), maximum=3+read_attempts)
            if type(data['requests']) is not int:
                raise ValueError('invalid request accounting')
            if data.get('status') == 'evidence_collected':
                exact(data, {'status','packet','requests'}, 'collector result')
            else:
                exact(data, {'status','reason','requests'}, 'collector result')
                if data['status'] not in ('evidence_unavailable','evidence_rejected') or data['reason'] not in REASONS:
                    raise ValueError('invalid collector outcome')
            return data
        except (OSError, ValueError, subprocess.TimeoutExpired):
            return {'status':'evidence_unavailable','reason':'worker_deadline_or_failure','requests':None}


def main() -> int:
    try:
        data = load_json(sys.stdin.buffer.read(50001), max_bytes=50000)
        exact(data, {'endpoint','transaction','read_attempts'}, 'collector request')
        result = _collect(data['endpoint'], b64(data['transaction'], max_size=MAX_TX_BYTES), data['read_attempts'])
    except (OSError, ValueError, TypeError, KeyError, RecursionError):
        result = {'status':'evidence_rejected','reason':'invalid_response','requests':0}
    sys.stdout.buffer.write(encode(result)+b'\n')
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
