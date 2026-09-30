"""Explicit finite loopback collection for the P4 read client, never a payment path.

Capture state H once. Wait only for fixed signed H+1, then collect every block and
commit from genesis within the small RPC profile limit. Validator rosters are
reconstructed from the pinned registry, not accepted from an RPC validator list.
The receiving read store independently verifies all returned evidence again.
"""
from __future__ import annotations

import argparse
import base64
import http.client
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import time

# A trusted parent process provides the exact already-imported native checkout.
# Neither an RPC response nor a browser request can choose these search paths.
if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--native-root', type=Path, required=True)
    args = parser.parse_args()
    root = args.native_root.resolve()
    sys.path[:0] = [str(root/'src'), str(root/'tools/validator-transition/src')]

from block_application import encode
from commit_verifier import b64, block_id, exact, header_hash, load_json, merkle_root, number, sha
from payment_rpc import endpoint_port
from protocol4_application import Protocol4Application, MAX_TX_BYTES
from receipt_collector import Reader, Unavailable
from p4_evidence import (FORMAT, MAX_EVIDENCE_BYTES, MAX_GENESIS_BYTES, check_clock,
                         freeze, integer, need, nanos, p4_genesis, policy_checked, verify_evidence)
from validator_sets_core import ValidatorSet

MAX_RPC_HEIGHT = 64
MAX_COMMIT_ATTEMPTS = 33
NEXT_COMMIT_WAIT = 8.0
MAX_REQUESTS = 1 + MAX_COMMIT_ATTEMPTS + 2 * MAX_RPC_HEIGHT
PROCESS_TIMEOUT = 45
MAX_STATE_BYTES = 4 * 1024 * 1024


def collect(endpoint, genesis, policy, now_ns):
    started_monotonic = time.monotonic_ns()
    endpoint_port(endpoint)
    p = policy_checked(policy); check_clock(p, now_ns)
    g, _ = p4_genesis(genesis, p['genesis_sha256'])
    calls = 0
    def read(method, height=None):
        nonlocal calls
        need(calls < MAX_REQUESTS, 'bounded read request count exceeded')
        calls += 1
        return Reader(endpoint).call(method, height)
    response = read('abci_query').get('response')
    need(type(response) is dict and type(response.get('code')) is int and response['code']==0,
         'P4 state is unavailable')
    state = load_json(b64(response.get('value'),max_size=MAX_STATE_BYTES), max_bytes=MAX_STATE_BYTES)
    exact(state, {'genesis','height','app_hash','native','registry'}, 'RPC composite state')
    h = integer(state['height'], 1, MAX_RPC_HEIGHT)
    need(number(response.get('height'),minimum=1)==h, 'RPC/state height differs')
    need(encode(state['genesis'])==encode(g), 'RPC changes pinned genesis')
    deadline=time.monotonic()+NEXT_COMMIT_WAIT; final=None
    for attempt in range(MAX_COMMIT_ATTEMPTS):
        try:
            final=read('commit',h+1)['signed_header'];break
        except Unavailable:
            remaining=deadline-time.monotonic()
            if remaining<=0 or attempt+1==MAX_COMMIT_ATTEMPTS:raise
            time.sleep(min(.25,remaining))
    need(final is not None, 'fixed next-height commit unavailable')
    headers=[];history=[]
    with Protocol4Application(':memory:',expected_genesis=g) as app:
        app.init_chain(g['chain_id'],g,g['validator_registry']['validators'])
        for height in range(1,h+1):
            signed=read('commit',height).get('signed_header')
            result=read('block',height)
            need(type(signed) is dict and type(result.get('block')) is dict, 'missing block evidence')
            block=result['block'];data=block.get('data');exact(data,{'txs'},'block transactions')
            rawlist=[] if data['txs'] is None else data['txs']
            need(type(rawlist) is list and len(rawlist)<=64, 'block transaction count exceeds limit')
            txs=[b64(raw,max_size=MAX_TX_BYTES) for raw in rawlist]
            Protocol4Application._bounds(txs)
            need(header_hash(block['header']) == header_hash(signed['header']) and
                 block_id(result.get('block_id')).SerializeToString() ==
                 block_id(signed['commit']['block_id']).SerializeToString(), 'block does not match its commit')
            after,out=app._execute(txs,height)
            headers.append({'signed_header':signed,'validators':after['registry']['active_validators'],
                            'next_validators':after['registry']['next_validators']})
            history.append({'height':height,'txs':[base64.b64encode(tx).decode() for tx in txs]})
            app.state,app.height,app.app_hash=after,height,out['app_hash']
            # Running bound prevents accumulation of an arbitrarily large trace.
            need(len(encode({'headers':headers,'history':history}))<=MAX_EVIDENCE_BYTES,
                 'collected history exceeds byte limit')
        ahead,_=app.rules.transition(app.state['registry'],[],h+1)
        headers.append({'signed_header':final,'validators':ahead['active_validators'],
                        'next_validators':ahead['next_validators']})
    evidence=freeze({'schema':1,'format':FORMAT,'state':state,'headers':headers,'history':history})
    # Do not label even collected bytes as verified without the whole proof check.
    observed_ns = now_ns + max(0, time.monotonic_ns()-started_monotonic)
    verify_evidence(evidence,genesis,p,now_ns=observed_ns)
    return {'schema':1,'status':'collected','evidence':evidence,'rpc_requests':calls}


def sync_read_store(store, endpoint, *, expected_tip):
    endpoint_port(endpoint)
    before=store.current()
    need(expected_tip == (None if before is None else before['evidence_id']),
         'reviewed read tip changed before collection')
    start=store.clock();check_clock(store.policy,start)
    import protocol4_application
    native_root=Path(protocol4_application.__file__).resolve().parents[1]
    request={'endpoint':endpoint,'genesis':base64.b64encode(store.genesis).decode(),
             'policy':store.policy,'now_ns':start}
    with tempfile.TemporaryFile() as out:
        try:
            process=subprocess.run([sys.executable,str(Path(__file__).resolve()),'--native-root',str(native_root)],
                input=encode(request),stdout=out,stderr=subprocess.DEVNULL,
                timeout=PROCESS_TIMEOUT,check=False,env={**os.environ,'PYTHONPATH':''})
        except subprocess.TimeoutExpired as exc:
            raise Unavailable('P4 evidence collection deadline') from exc
        need(process.returncode==0 and out.tell()<=MAX_EVIDENCE_BYTES+4096,
             'P4 collection did not complete')
        out.seek(0);raw=out.read(MAX_EVIDENCE_BYTES+4097)
    result=load_json(raw,max_bytes=MAX_EVIDENCE_BYTES+4096)
    exact(result,{'schema','status','evidence','rpc_requests'},'P4 worker result')
    integer(result['schema'],1,1);integer(result['rpc_requests'],1,MAX_REQUESTS)
    need(result['status']=='collected','P4 evidence not collected')
    now=store.clock();check_clock(store.policy,now,start)
    stamp=nanos(result['evidence']['headers'][-1]['signed_header']['header']['time'])
    need(now-300*10**9<=stamp<=now+store.policy['max_clock_drift_seconds']*10**9,
         'RPC checkpoint outside explicit freshness window')
    stored=store.import_evidence(result['evidence'],expected_tip=expected_tip)
    return {**stored,'rpc_requests':result['rpc_requests'],'signed':False,'broadcast':False,
            'latest_state_guaranteed':False}


if __name__ == '__main__':
    try:
        raw=sys.stdin.buffer.read(2*MAX_GENESIS_BYTES+4097)
        need(len(raw)<=2*MAX_GENESIS_BYTES+4096,'worker input exceeds limit')
        request=load_json(raw,max_bytes=2*MAX_GENESIS_BYTES+4096)
        exact(request,{'endpoint','genesis','policy','now_ns'},'read worker input')
        result=collect(request['endpoint'],b64(request['genesis'],max_size=MAX_GENESIS_BYTES),
                       request['policy'],request['now_ns'])
        sys.stdout.buffer.write(encode(result))
    except (OSError,ValueError,TypeError,KeyError,OverflowError,http.client.HTTPException):
        raise SystemExit(2)
