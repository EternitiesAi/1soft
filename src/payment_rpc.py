"""Bounded loopback RPC worker for the development native-payment transport.

No keys, signing, DNS names, proxies, redirects, cloud calls or automatic retries.
The parent runs this worker in a subprocess with a total execution deadline.
An endpoint's CheckTx response is an observation, never evidence of settlement.
"""
from __future__ import annotations
import base64
import hashlib
import http.client
import json
import re
import sys

MAX_RESPONSE = 65_536
MAX_TRANSACTION = 16_384
ENDPOINT = re.compile(r'http://127\.0\.0\.1:([1-9][0-9]{0,4})/\Z')


def endpoint_port(endpoint: str) -> int:
    match = ENDPOINT.fullmatch(endpoint) if type(endpoint) is str else None
    if match is None or not 1024 <= int(match[1]) <= 65535:
        raise ValueError('only an explicit http://127.0.0.1:PORT/ development endpoint is allowed')
    return int(match[1])


def strict_json(raw: bytes):
    def pairs(values):
        result = {}
        for key, value in values:
            if key in result:
                raise ValueError('duplicate JSON field')
            result[key] = value
        return result
    def invalid(_):
        raise ValueError('non-integer JSON value')
    return json.loads(raw, object_pairs_hook=pairs, parse_float=invalid, parse_constant=invalid)


def exchange(endpoint: str, raw: bytes, request_id: int) -> dict:
    """One request only. A process-level timeout additionally bounds slow peers."""
    port = endpoint_port(endpoint)
    if type(raw) is not bytes or not 1 <= len(raw) <= MAX_TRANSACTION:
        raise ValueError('invalid transaction size')
    if type(request_id) is not int or not 1 <= request_id <= 2**31-1:
        raise ValueError('invalid request ID')
    payload = json.dumps({'jsonrpc': '2.0', 'id': request_id, 'method': 'broadcast_tx_sync',
        'params': {'tx': base64.b64encode(raw).decode('ascii')}}, separators=(',', ':')).encode('ascii')
    connection = http.client.HTTPConnection('127.0.0.1', port, timeout=2)
    try:
        # http.client does not consult HTTP_PROXY and does not follow redirects.
        connection.request('POST', '/', payload, {'Content-Type': 'application/json',
                                                'Accept': 'application/json', 'Connection': 'close'})
        response = connection.getresponse()
        if response.status != 200:
            return {'observation': 'unresolved', 'reason': 'non-200 HTTP response'}
        headers = response.getheaders()
        for field in ('content-length', 'transfer-encoding', 'content-encoding', 'content-type'):
            if sum(k.lower() == field for k, _ in headers) > 1:
                raise ValueError('duplicate response framing header')
        length = response.getheader('Content-Length')
        transfer = response.getheader('Transfer-Encoding')
        if length is not None and transfer is not None:
            raise ValueError('ambiguous response framing')
        if transfer is not None and transfer.lower() != 'chunked':
            raise ValueError('unsupported transfer encoding')
        if response.getheader('Content-Encoding', 'identity').lower() != 'identity':
            raise ValueError('compressed response forbidden')
        if response.getheader('Content-Type', '').split(';')[0].strip().lower() != 'application/json':
            raise ValueError('expected JSON response')
        if length is not None and (re.fullmatch(r'0|[1-9][0-9]*', length) is None or int(length) > MAX_RESPONSE):
            raise ValueError('invalid response length')
        data = response.read(MAX_RESPONSE + 1)
        if len(data) > MAX_RESPONSE or (length is not None and len(data) != int(length)):
            raise ValueError('response length mismatch')
        result = strict_json(data)
        if (type(result) is not dict or result.get('jsonrpc') != '2.0' or
            type(result.get('id')) is not int or result['id'] != request_id or
            'error' in result or set(result) != {'jsonrpc', 'id', 'result'}):
            raise ValueError('invalid RPC response envelope')
        value = result['result']
        if (type(value) is not dict or type(value.get('code')) is not int or
            not 0 <= value['code'] <= 2**32-1 or type(value.get('hash')) is not str or
            value['hash'].upper() != hashlib.sha256(raw).hexdigest().upper()):
            raise ValueError('response does not identify the submitted transaction')
        return {'observation': 'endpoint_admitted' if value['code'] == 0 else 'endpoint_declined',
                'check_tx_code': value['code'], 'response_sha256': hashlib.sha256(data).hexdigest()}
    finally:
        connection.close()


def main() -> int:
    try:
        raw = sys.stdin.buffer.read(50_001)
        if len(raw) > 50_000:
            raise ValueError('worker input too large')
        item = strict_json(raw)
        if type(item) is not dict or set(item) != {'endpoint', 'transaction', 'request_id'}:
            raise ValueError('invalid worker input')
        tx = base64.b64decode(item['transaction'], validate=True)
        if base64.b64encode(tx).decode('ascii') != item['transaction']:
            raise ValueError('noncanonical transaction encoding')
        result = exchange(item['endpoint'], tx, item['request_id'])
    except (OSError, ValueError, TypeError, KeyError, RecursionError, http.client.HTTPException):
        # Do not render an untrusted server log, HTML error, credential or traceback.
        result = {'observation': 'unresolved', 'reason': 'transport or response validation failed'}
    print(json.dumps(result, sort_keys=True, separators=(',', ':')))
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
