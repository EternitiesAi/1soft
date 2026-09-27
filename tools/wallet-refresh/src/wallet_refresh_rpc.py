"""One bounded, read-only local RPC collection job. Never sees wallet keys or DB.

Reuses the existing strict HTTP reader. Every requested height is selected by the
parent; the endpoint cannot supply another URL, method or validator set.
Output is untrusted until the wallet re-verifies it. No broadcast or payment retry.
Only the captured next signed commitment may have bounded read retries.
"""
from __future__ import annotations
import http.client
from pathlib import Path
import subprocess
import sys
import tempfile
import time

from commit_verifier import b64, encode, exact, load_json, number
from native_core import require
from payment_rpc import endpoint_port
from receipt_collector import Reader, Unavailable, MAX_SNAPSHOT
from wallet_catchup import MAX_HEADERS, MAX_BATCH_BYTES, MAX_HEADER_BYTES

WORKER_TIMEOUT = 15.0
MAX_OUTPUT = 5 * 1024 * 1024
SNAPSHOT_COMMIT_ATTEMPTS = 4
SNAPSHOT_COMMIT_PAUSE = 0.25


def request_fields(request: dict) -> None:
    require(type(request) is dict, 'invalid refresh request')
    mode = request.get('mode')
    if mode == 'snapshot':
        exact(request, {'mode', 'endpoint'}, 'snapshot request')
    elif mode == 'headers':
        exact(request, {'mode', 'endpoint', 'start', 'count'}, 'header request')
        require(type(request['start']) is int and type(request['count']) is int,
                'header range must use integers')
        number(request['start'], minimum=1, maximum=2**53-1)
        number(request['count'], minimum=1, maximum=MAX_HEADERS)
        require(request['start'] + request['count'] - 1 <= 2**53-1, 'header range overflow')
    else:
        raise ValueError('only snapshot and fixed consecutive header reads are supported')
    endpoint_port(request['endpoint'])


def collect(request: dict) -> dict:
    request_fields(request)
    reads = 0
    def call(method, height=None):
        nonlocal reads
        reads += 1
        # The inherited reader caps its own requests at seven. A new reader per
        # fixed-height read does not raise that cap; this job separately bounds
        # the COMPLETE range to at most 64 reads / 2 MiB and one process deadline.
        return Reader(request['endpoint']).call(method, height)
    try:
        if request['mode'] == 'snapshot':
            result = call('abci_query').get('response')
            require(type(result) is dict and type(result.get('code')) is int,
                    'invalid state-query response')
            if result['code'] != 0:
                raise Unavailable('query_not_available')
            raw = b64(result.get('value'), max_size=MAX_SNAPSHOT)
            state = load_json(raw, max_bytes=MAX_SNAPSHOT)
            exact(state, {'genesis', 'height', 'app_hash', 'native'}, 'state')
            require(type(state['height']) is int, 'invalid application height')
            height = number(state['height'], maximum=2**53-2)
            require(number(result.get('height')) == height, 'query/state height mismatch')
            # The state query may reach the current tip before its h+1 signed
            # header exists. Keep the captured state and retry only that fixed
            # height; never chase a later state or accept an unsigned snapshot.
            for attempt in range(SNAPSHOT_COMMIT_ATTEMPTS):
                try:
                    signed = call('commit', height + 1).get('signed_header')
                    break
                except Unavailable:
                    if attempt + 1 == SNAPSHOT_COMMIT_ATTEMPTS:
                        raise
                    time.sleep(SNAPSHOT_COMMIT_PAUSE)
            require(type(signed) is dict and len(encode(signed)) <= MAX_HEADER_BYTES,
                    'invalid state commitment')
            payload = {'schema': 1, 'state': state, 'state_commit': signed}
        else:
            payload = []
            for height in range(request['start'], request['start'] + request['count']):
                signed = call('commit', height).get('signed_header')
                require(type(signed) is dict and len(encode(signed)) <= MAX_HEADER_BYTES,
                        'invalid header response')
                payload.append(signed)
                require(len(encode(payload)) <= MAX_BATCH_BYTES, 'header batch too large')
        answer = {'status': 'collected', 'payload': payload, 'rpc_attempts': reads}
        require(len(encode(answer)) <= MAX_OUTPUT, 'refresh result too large')
        return answer
    except (Unavailable, OSError, http.client.HTTPException):
        return {'status': 'unavailable', 'rpc_attempts': reads}
    except (ValueError, TypeError, KeyError, RecursionError):
        return {'status': 'rejected', 'rpc_attempts': reads}


def fetch(request: dict) -> dict:
    """Kill-and-wait deadline via subprocess.run; stdout is file-backed and bounded.

    This is transport isolation, not a general untrusted-code sandbox. The child
    is project code and receives only public endpoint/range data, never passwords,
    wallet paths, signed payment bytes or genesis-discovery authority.
    """
    request_fields(request)
    with tempfile.TemporaryFile() as out:
        try:
            proc = subprocess.run([sys.executable, str(Path(__file__).resolve())],
                                  input=encode(request), stdout=out, stderr=subprocess.DEVNULL,
                                  timeout=WORKER_TIMEOUT, check=False)
            require(proc.returncode == 0 and out.tell() <= MAX_OUTPUT, 'invalid collector output')
            out.seek(0)
            result = load_json(out.read(MAX_OUTPUT + 1), max_bytes=MAX_OUTPUT)
            require(type(result) is dict and result.get('status') in ('collected','unavailable','rejected'),
                    'invalid collector result')
            exact(result, {'status','rpc_attempts'} | ({'payload'} if result['status']=='collected' else set()),
                  'collector result')
            bound = 1 + SNAPSHOT_COMMIT_ATTEMPTS if request['mode']=='snapshot' else request['count']
            require(type(result['rpc_attempts']) is int and 0 <= result['rpc_attempts'] <= bound,
                    'invalid request accounting')
            if result['status']=='collected':
                require((2 <= result['rpc_attempts'] <= bound) if request['mode']=='snapshot'
                        else result['rpc_attempts']==bound, 'incomplete collection')
            return result
        except (OSError, ValueError, subprocess.TimeoutExpired):
            # The parent cannot know how many reads a terminated child completed.
            return {'status':'unavailable','rpc_attempts':None}


if __name__ == '__main__':
    try:
        request = load_json(sys.stdin.buffer.read(4097), max_bytes=4096)
        answer = collect(request)
    except (OSError, ValueError, TypeError, KeyError, RecursionError):
        answer = {'status':'rejected','rpc_attempts':0}
    sys.stdout.buffer.write(encode(answer)+b'\n')
