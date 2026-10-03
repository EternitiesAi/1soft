"""Bounded loopback-only delta capture. Returned candidates are not authority."""
from __future__ import annotations
import base64
import copy
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import time

if __name__=='__main__':
    import argparse
    bootstrap=argparse.ArgumentParser(add_help=False)
    bootstrap.add_argument('--native-root',type=Path,required=True)
    selected,_=bootstrap.parse_known_args()
    native_root=selected.native_root.resolve()
    sys.path[:0]=[str(native_root/'src'),str(native_root/'tools/validator-transition/src'),
                  str(native_root/'tools/protocol4-client/src')]

from block_application import encode
from commit_verifier import b64,block_id,exact,header_hash,load_json,number
from development_profile import max_height_for
from payment_rpc import endpoint_port
from protocol4_application import Protocol4Application,MAX_TX_BYTES
from p4_evidence import freeze,integer,need,p4_genesis
from p4_incremental_evidence import (MAX_SEGMENT_BLOCKS,MAX_SEGMENT_BYTES,
    MAX_STATE_BYTES,SEGMENT_FORMAT,check_clock,policy_v2_checked)
from receipt_collector import Reader,Unavailable

MAX_COMMIT_ATTEMPTS=33
NEXT_COMMIT_WAIT=8.0
MAX_REQUESTS=1+MAX_COMMIT_ATTEMPTS+2*MAX_SEGMENT_BLOCKS
MAX_SECONDS=45.0


def _collect_segment(endpoint,genesis_bytes,policy,now_ns,*,view=None):
    endpoint_port(endpoint)
    p=policy_v2_checked(policy)
    previous=None if view is None else view['checkpoint']
    check_clock(p,now_ns,checkpoint=previous)
    g,_=p4_genesis(genesis_bytes,p['genesis_sha256'])
    start=0 if previous is None else previous['height']
    started=time.monotonic();calls=0
    def read(method,height=None):
        nonlocal calls
        need(calls<MAX_REQUESTS and time.monotonic()-started<MAX_SECONDS,
             'bounded incremental RPC request/time budget exhausted')
        calls+=1
        return Reader(endpoint).call(method,height)
    response=read('abci_query').get('response')
    need(type(response) is dict and type(response.get('code')) is int and response['code']==0,
         'current composite state unavailable')
    state=load_json(b64(response.get('value'),max_size=MAX_STATE_BYTES),max_bytes=MAX_STATE_BYTES)
    exact(state,{'genesis','height','app_hash','native','registry'},'captured RPC state')
    captured=integer(state['height'],1,max_height_for(g))
    need(number(response.get('height'),minimum=1)==captured and encode(state['genesis'])==encode(g),
         'RPC state height or original genesis differs')
    need(captured>start,'same-height or older RPC checkpoint refused')
    target=min(captured,start+MAX_SEGMENT_BLOCKS)
    deadline=min(started+MAX_SECONDS,time.monotonic()+NEXT_COMMIT_WAIT)
    final=None
    for attempt in range(MAX_COMMIT_ATTEMPTS):
        try:
            final=read('commit',target+1).get('signed_header')
            break
        except Unavailable:
            remaining=deadline-time.monotonic()
            if remaining<=0 or attempt+1==MAX_COMMIT_ATTEMPTS:raise
            time.sleep(min(.25,remaining))
    need(type(final) is dict,'fixed next-height commit unavailable')
    # This disposable node-rule execution only DERIVES candidate roster/state.
    # It is never imported as a verified replay cursor or financial authority.
    # The receiving store checks all signatures/ancestry and replays every delta.
    with Protocol4Application(':memory:',expected_genesis=g) as app:
        app.init_chain(g['chain_id'],g,g['validator_registry']['validators'])
        if view is not None:
            need(view['context'].get('format')=='1soft/protocol4-authenticated-context/v1' and
                 view['context']['checkpoint_id']==previous['id'] and
                 encode(view['context']['state']['genesis'])==encode(g),
                 'owned authenticated context required')
            context=view['context']['state']
            app.state=copy.deepcopy({'native':context['native'],'registry':context['registry']})
            app.height=start;app.app_hash=context['app_hash']
        headers=[];history=[]
        for height in range(start+1,target+1):
            signed=read('commit',height).get('signed_header')
            result=read('block',height)
            need(type(signed) is dict and type(result.get('block')) is dict,'missing signed delta block')
            block=result['block'];data=block.get('data');exact(data,{'txs'},'block transactions')
            values=[] if data['txs'] is None else data['txs']
            need(type(values) is list and len(values)<=64,'block transaction count exceeds bound')
            txs=[b64(value,max_size=MAX_TX_BYTES) for value in values]
            Protocol4Application._bounds(txs)
            need(header_hash(block['header'])==header_hash(signed['header']) and
                 block_id(result.get('block_id')).SerializeToString()==
                 block_id(signed['commit']['block_id']).SerializeToString(),
                 'RPC block differs from signed commit')
            after,out=app._execute(txs,height)
            headers.append({'signed_header':signed,'validators':after['registry']['active_validators'],
                            'next_validators':after['registry']['next_validators']})
            history.append({'height':height,'txs':[base64.b64encode(t).decode() for t in txs]})
            app.state,app.height,app.app_hash=after,height,out['app_hash']
            need(len(encode({'headers':headers,'history':history}))<=MAX_SEGMENT_BYTES-MAX_STATE_BYTES,
                 'delta transport byte budget exhausted')
        ahead,_=app.rules.transition(app.state['registry'],[],target+1)
        headers.append({'signed_header':final,'validators':ahead['active_validators'],
                        'next_validators':ahead['next_validators']})
        computed={'genesis':g,'height':target,'app_hash':app.app_hash,**app.state}
        if target==captured:
            need(encode(computed)==encode(state),'captured RPC state differs from candidate replay')
        segment=freeze({'schema':1,'format':SEGMENT_FORMAT,
            'parent_checkpoint':None if previous is None else previous['id'],
            'from_height':start,'state':computed,'history':history,'headers':headers},
            MAX_SEGMENT_BYTES)
    need(time.monotonic()-started<=MAX_SECONDS,'incremental RPC deadline exceeded')
    return {'schema':1,'status':'unverified-delta-collected','segment':segment,
            'rpc_requests':calls,'captured_source_height':captured}


def collect_segment(endpoint,genesis_bytes,policy,now_ns,*,view=None):
    """Owned finite child: a slow HTTP body cannot extend the parent deadline."""
    endpoint_port(endpoint)
    p=policy_v2_checked(policy)
    check_clock(p,now_ns,checkpoint=None if view is None else view['checkpoint'])
    import protocol4_application
    native_root=Path(protocol4_application.__file__).resolve().parents[1]
    minimal=None if view is None else {'checkpoint':{k:v for k,v in view['checkpoint'].items() if k!='state'},
                                      'context':view['context']}
    request=encode({'endpoint':endpoint,'genesis_b64':base64.b64encode(genesis_bytes).decode(),
                    'policy':p,'now_ns':now_ns,'view':minimal})
    need(len(request)<=8*1024*1024,'bounded incremental worker input required')
    env=dict(os.environ);env['PYTHONPATH']='';env['PYTHONDONTWRITEBYTECODE']='1'
    with tempfile.TemporaryFile() as output:
        try:
            result=subprocess.run([sys.executable,'-B',str(Path(__file__).resolve()),
                '--native-root',str(native_root)],input=request,stdout=output,
                stderr=subprocess.DEVNULL,env=env,timeout=MAX_SECONDS)
        except subprocess.TimeoutExpired as exc:
            raise ValueError('incremental read worker deadline exceeded') from exc
        need(result.returncode==0,'incremental read worker unavailable')
        output.seek(0);raw=output.read(MAX_SEGMENT_BYTES+4097)
    need(len(raw)<=MAX_SEGMENT_BYTES+4096,'bounded worker response required')
    value=load_json(raw,max_bytes=MAX_SEGMENT_BYTES+4096)
    need(encode(value)==raw,'noncanonical incremental worker result')
    exact(value,{'schema','status','segment','rpc_requests','captured_source_height'},'worker result')
    integer(value['schema'],1,1);integer(value['rpc_requests'],1,MAX_REQUESTS)
    integer(value['captured_source_height'],1,4096)
    need(value['status']=='unverified-delta-collected','worker result is not an untrusted candidate')
    return value

def _main():
    import argparse
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--native-root',type=Path,required=True)
    args=parser.parse_args()
    request=load_json(sys.stdin.buffer.read(8*1024*1024+1),max_bytes=8*1024*1024)
    exact(request,{'endpoint','genesis_b64','policy','now_ns','view'},'incremental worker request')
    result=_collect_segment(request['endpoint'],b64(request['genesis_b64'],max_size=1024*1024),
                            request['policy'],request['now_ns'],view=request['view'])
    raw=encode(result);need(len(raw)<=MAX_SEGMENT_BYTES+4096,'worker result too large')
    sys.stdout.buffer.write(raw);return 0

if __name__=='__main__':
    try:raise SystemExit(_main())
    except (ValueError,OSError,KeyError,TypeError,OverflowError):raise SystemExit(2)
