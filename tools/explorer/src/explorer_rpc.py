"""Finite loopback read collection. Reuses the native strict HTTP receipt reader.

Captures /state once and retries ONLY its fixed H+1 signed commit. No transaction
submission, wallet path, secrets, DNS, proxies, public endpoint or periodic task.
"""
import http.client
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import time

# The bounded worker is launched as a new process; it must resolve the
# native verifier from this checkout even when its caller clears PYTHONPATH.
sys.path.insert(0, str(Path(__file__).resolve().parents[3] / 'src'))

from commit_verifier import b64, encode, exact, load_json
from payment_rpc import endpoint_port
from receipt_collector import Reader, Unavailable
from explorer_index import MAX_INPUT, MAX_BATCH_HEADERS, need, hash_value, ns

MAX_CALLS = 133
PROCESS_TIMEOUT = 45
NEXT_COMMIT_WAIT = 8.0


def collect(endpoint, last_header_height, initial_window=16):
    endpoint_port(endpoint)
    need(type(last_header_height) is int and 0 <= last_header_height <= 2**53-1, 'invalid local frontier')
    need(type(initial_window) is int and 1 <= initial_window <= 64, 'invalid initial block window')
    calls = 0
    def read(method, height=None):
        nonlocal calls
        need(calls < MAX_CALLS, 'RPC request limit reached')
        calls += 1
        # One strict request per reader; a separate process bounds the whole batch.
        return Reader(endpoint).call(method, height)
    response = read('abci_query')['response']
    need(type(response.get('code')) is int and response['code'] == 0, 'state not available')
    state = load_json(b64(response.get('value'), max_size=4*1024*1024), max_bytes=4*1024*1024)
    exact(state, {'genesis','height','app_hash','native'}, 'collected state')
    h = state['height']
    need(type(h) is int and 0 <= h <= 2**53-2 and int(response['height']) == h, 'state height differs')
    target = h+1
    need(target >= last_header_height, 'endpoint is behind indexed state')
    start = max(1, target-initial_window) if not last_header_height else last_header_height
    need(target-start+1 <= MAX_BATCH_HEADERS, 'gap exceeds one bounded import; supply signed batches')
    # The state at H can be visible before the engine publishes signed H+1.
    # Keep that state fixed and wait only for its commitment, within a deadline.
    deadline = time.monotonic() + NEXT_COMMIT_WAIT
    while True:
        try:
            final = read('commit', target)['signed_header']; break
        except Unavailable:
            remaining = deadline - time.monotonic()
            if remaining <= 0: raise
            time.sleep(min(.25, remaining))
    headers=[]; blocks=[]
    for height in range(start, target+1):
        headers.append(final if height == target else read('commit', height)['signed_header'])
        if height <= h: blocks.append(read('block', height))
    evidence={'schema':1,'state':state,'state_commit':final,'headers':headers,'blocks':blocks}
    raw=encode(evidence);need(len(raw)<=MAX_INPUT,'collected evidence exceeds limit')
    return {'status':'collected','evidence':evidence,'rpc_requests':calls}


def refresh(index, endpoint, *, initial_header_hash=None, clock=time.time_ns):
    endpoint_port(endpoint)
    current=index.current()
    if current is None: hash_value(initial_header_hash)  # Before any network reads.
    request={'endpoint':endpoint,'last_header_height':0 if current is None else current['anchor_height']}
    with tempfile.TemporaryFile() as output:
        try:
            result=subprocess.run([sys.executable,str(Path(__file__).resolve()),'--worker'],
                input=encode(request),stdout=output,stderr=subprocess.DEVNULL,timeout=PROCESS_TIMEOUT,check=False)
        except subprocess.TimeoutExpired:
            raise Unavailable('explorer_collection_deadline')
        need(result.returncode==0,'explorer RPC collection did not complete')
        output.seek(0);raw=output.read(MAX_INPUT+4097)
        need(len(raw)<=MAX_INPUT+4096,'RPC worker output exceeds limit')
    message=load_json(raw,max_bytes=MAX_INPUT+4096)
    exact(message,{'status','evidence','rpc_requests'},'RPC worker result')
    need(message['status']=='collected' and type(message['rpc_requests']) is int and
         1<=message['rpc_requests']<=MAX_CALLS,'invalid RPC worker result')
    # Freshness is for this explicit refresh only; exported views remain historical.
    stamp=ns(message['evidence']['state_commit']['header']['time']);now=clock()
    need(type(now) is int and now-300*10**9<=stamp<=now+30*10**9,'collected snapshot is not recent enough')
    return {**index.ingest(message['evidence'],initial_header_hash=initial_header_hash),
            'rpc_requests':message['rpc_requests'],'broadcast':False}


if __name__=='__main__':
    try:
        raw=sys.stdin.buffer.read(4097);need(len(raw)<=4096,'worker request too large')
        request=load_json(raw,max_bytes=4096);exact(request,{'endpoint','last_header_height'},'RPC request')
        result=collect(**request);print(encode(result).decode())
    except (ValueError,KeyError,TypeError,OSError,http.client.HTTPException):
        # No untrusted endpoint payload, local path or exception text in diagnostics.
        raise SystemExit(2)
