#!/usr/bin/env python3
"""Run a disposable, loopback-only four-validator CometBFT integration gate.

Requires the real pinned binary. Missing engine => UNASSESSED, never simulated.
No persistent keys, customer money, public listeners, or cloud resources are used.
"""
from __future__ import annotations
import argparse
import base64
import hashlib
import http.client
import json
import os
from pathlib import Path
import shutil
import socket
import subprocess
import sys
import tempfile
import time
import urllib.request
import re
from datetime import datetime, timedelta, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from threading import Lock, Thread
from unittest.mock import patch

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/'src'))
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from native_core import NativeLedger, Reject, canonical, public, address, sign, DOMAIN, parse_wire, accept_account_key
from commit_verifier import trust_from_genesis, verify_block_transactions, verify_signed_header, verify_packet
from certified_wallet import CertifiedWallet
from payment_transport import DispatchJournal
import payment_transport

PIN='0.38.25'


def _git_bytes(*args):
    try:
        result=subprocess.run(['git','-C',str(ROOT),*args],capture_output=True,
            timeout=3,check=False)
    except (OSError,subprocess.SubprocessError):
        return None
    return result.stdout if result.returncode==0 else None


def source_provenance(started_at: datetime) -> dict:
    runner_path=Path(__file__).resolve()
    manifest_path=ROOT/'SOURCE_MANIFEST.json'
    status=_git_bytes('status','--porcelain','--untracked-files=no')
    diff=_git_bytes('diff','--binary','HEAD')
    commit=_git_bytes('rev-parse','HEAD')
    tree=_git_bytes('rev-parse','HEAD^{tree}')
    return {
        'started_at_utc':started_at.isoformat(timespec='milliseconds').replace('+00:00','Z'),
        'runner_relative_path':str(runner_path.relative_to(ROOT)),
        'runner_sha256':hashlib.sha256(runner_path.read_bytes()).hexdigest(),
        'source_commit':commit.decode('ascii').strip() if commit is not None else None,
        'source_tree':tree.decode('ascii').strip() if tree is not None else None,
        'tracked_worktree_dirty':bool(status.strip()) if status is not None else None,
        'tracked_diff_sha256':hashlib.sha256(diff).hexdigest() if diff is not None else None,
        'source_manifest_sha256':hashlib.sha256(manifest_path.read_bytes()).hexdigest()
            if manifest_path.is_file() else None,
    }


def patch_toml(text, updates):
    """Patch only observed keys, then validate the output as TOML; no silent misses."""
    import tomllib
    section=''; found=set();out=[]
    for line in text.splitlines():
        s=line.strip()
        if s.startswith('[') and s.endswith(']'):section=s[1:-1]
        match=re.match(r'^([A-Za-z0-9_]+)\s*=',s)
        key=f'{section}.{match.group(1)}'.lstrip('.') if match else ''
        if key in updates:
            line=f'{match.group(1)} = {json.dumps(updates[key])}';found.add(key)
        out.append(line)
    missing=set(updates)-found
    if missing:raise ValueError('missing upstream configuration keys: '+','.join(sorted(missing)))
    result='\n'.join(out)+'\n';tomllib.loads(result);return result


def rpc(port, method, params=None):
    payload=json.dumps({'jsonrpc':'2.0','id':1,'method':method,'params':params or {}}).encode()
    req=urllib.request.Request(f'http://127.0.0.1:{port}',data=payload,headers={'Content-Type':'application/json'})
    # Explicitly ignore environment proxies for this loopback-only connection.
    with urllib.request.build_opener(urllib.request.ProxyHandler({})).open(req,timeout=8) as res:data=json.load(res)
    if 'error' in data:raise RuntimeError(json.dumps(data['error']))
    return data['result']


def wait_until(fn,timeout=60):
    deadline=time.monotonic()+timeout;last=None
    while time.monotonic()<deadline:
        try:
            value=fn()
            if value:return value
        except (OSError,RuntimeError,KeyError) as exc:last=str(exc)
        time.sleep(.15)
    raise TimeoutError(last or 'condition did not become true')


def free_ports(count):
    held=[]
    try:
        for _ in range(count):
            s=socket.socket();s.bind(('127.0.0.1',0));held.append(s)
        return [s.getsockname()[1] for s in held]
    finally:
        for s in held:s.close()


class DecisionDeliveryRpcProxy:
    """Forward only two preselected payments and bounded receipt reads.

    The first exact broadcast is forwarded to the real local validator. Its
    successful CheckTx response is validated here, then the downstream socket is
    closed without an HTTP response. The second exact payment and read-only
    state/block/commit requests receive the upstream response normally.
    """
    READ_METHODS={'abci_query','block','commit'}

    def __init__(self, upstream_port: int, payments: list[tuple[str, bytes]]):
        if type(upstream_port) is not int or not 1024 <= upstream_port <= 65535:
            raise ValueError('invalid loopback validator port')
        if len(payments) != 2 or any(type(raw) is not bytes for _,raw in payments):
            raise ValueError('two exact signed payments are required')
        self.upstream_port=upstream_port
        self.payments=[(name,bytes(raw)) for name,raw in payments]
        self._lock=Lock()
        self._broadcast_index=0
        self._records=[]
        self._read_requests=0
        self._http_methods=[]
        self._unexpected_http_methods=[]
        self._unexpected_requests=[]

        owner=self
        class Handler(BaseHTTPRequestHandler):
            protocol_version='HTTP/1.1'

            def parse_request(self):
                parsed=super().parse_request()
                with owner._lock:
                    if parsed:
                        owner._http_methods.append(self.command)
                        if self.command!='POST':
                            owner._unexpected_http_methods.append(self.command)
                    else:
                        owner._http_methods.append(None)
                        owner._unexpected_http_methods.append('malformed_http_request')
                return parsed

            def log_message(self, *_):
                return

            def _reply(self, status: int, body: bytes, content_type='application/json'):
                self.send_response(status)
                self.send_header('Content-Type',content_type)
                self.send_header('Content-Length',str(len(body)))
                self.send_header('Connection','close')
                self.end_headers()
                self.wfile.write(body)
                self.close_connection=True

            def _reject(self, status=400):
                self._reply(status,b'{"error":"loopback RPC proxy rejected request"}')

            def _forward(self, body: bytes):
                conn=http.client.HTTPConnection('127.0.0.1',owner.upstream_port,timeout=8)
                try:
                    conn.request('POST','/',body,{'Content-Type':'application/json',
                        'Accept':'application/json','Connection':'close'})
                    response=conn.getresponse()
                    data=response.read(8*1024*1024+1)
                    if len(data)>8*1024*1024:
                        raise ValueError('upstream RPC response exceeded proxy bound')
                    return response.status,response.getheader('Content-Type','application/json'),data
                finally:
                    conn.close()

            def do_POST(self):
                if self.path!='/' or self.headers.get_all('Content-Length') is None or len(self.headers.get_all('Content-Length'))!=1 or self.headers.get('Transfer-Encoding') is not None:
                    with owner._lock:owner._unexpected_requests.append('invalid_http_post')
                    self._reject()
                    return
                try:
                    length=int(self.headers.get('Content-Length'))
                    if not 1<=length<=65536:
                        raise ValueError('invalid request length')
                    body=self.rfile.read(length)
                    if len(body)!=length:
                        raise ValueError('incomplete request body')
                    def unique_pairs(items):
                        result={}
                        for key,value in items:
                            if key in result: raise ValueError('duplicate JSON field')
                            result[key]=value
                        return result
                    request=json.loads(body,object_pairs_hook=unique_pairs)
                    if (type(request) is not dict or set(request)!={'jsonrpc','id','method','params'} or
                            request['jsonrpc']!='2.0' or type(request['id']) is not int or
                            type(request['params']) is not dict):
                        raise ValueError('invalid JSON-RPC request')
                    method=request['method'];params=request['params']
                    if method=='broadcast_tx_sync':
                        if set(params)!={'tx'} or type(params['tx']) is not str:
                            raise ValueError('invalid broadcast parameters')
                        transaction=base64.b64decode(params['tx'],validate=True)
                        if base64.b64encode(transaction).decode('ascii')!=params['tx']:
                            raise ValueError('noncanonical transaction encoding')
                        with owner._lock:
                            index=owner._broadcast_index
                            if index>=len(owner.payments):
                                owner._unexpected_requests.append('unexpected_broadcast')
                                self._reject(403)
                                return
                            name,expected=owner.payments[index]
                            if transaction!=expected:
                                owner._unexpected_requests.append('different_signed_bytes')
                                self._reject(403)
                                return
                            owner._broadcast_index+=1
                        status,content_type,upstream=self._forward(body)
                        try:
                            message=json.loads(upstream)
                            result=message.get('result') if type(message) is dict else None
                            code=result.get('code') if type(result) is dict else None
                            tx_hash=result.get('hash') if type(result) is dict else None
                            admitted=(status==200 and message.get('jsonrpc')=='2.0' and
                                message.get('id')==request['id'] and type(code) is int and code==0 and
                                type(tx_hash) is str and
                                tx_hash.upper()==hashlib.sha256(transaction).hexdigest().upper())
                        except (ValueError,TypeError,AttributeError):
                            code=None;admitted=False
                        drop=index==0 and admitted
                        record={'name':name,'wire_sha256':hashlib.sha256(transaction).hexdigest(),
                            'upstream_http_status':status,'upstream_check_tx_code':code,
                            'upstream_tx_hash_matches':bool(admitted),
                            'downstream_reply_dropped':drop,'downstream_reply_forwarded':not drop}
                        with owner._lock:owner._records.append(record)
                        if drop:
                            self.close_connection=True
                            return
                        self._reply(status,upstream,content_type)
                        return
                    if method not in owner.READ_METHODS:
                        with owner._lock:owner._unexpected_requests.append('non_read_only_rpc')
                        self._reject(403)
                        return
                    if method=='abci_query':
                        if params!={'path':'/state','prove':False}:
                            raise ValueError('only the full-state read is permitted')
                    elif (set(params)!={'height'} or type(params['height']) is not str or
                            re.fullmatch('[1-9][0-9]*',params['height']) is None):
                        raise ValueError('only fixed-height block and commit reads are permitted')
                    with owner._lock:owner._read_requests+=1
                    status,content_type,upstream=self._forward(body)
                    self._reply(status,upstream,content_type)
                except (OSError,ValueError,TypeError,KeyError,RecursionError,
                        http.client.HTTPException):
                    with owner._lock:owner._unexpected_requests.append('invalid_or_unavailable_rpc')
                    self._reject(502)

        self._server=ThreadingHTTPServer(('127.0.0.1',0),Handler)
        self._server.daemon_threads=True
        self.port=self._server.server_address[1]
        self.endpoint=f'http://127.0.0.1:{self.port}/'
        self._thread=Thread(target=self._server.serve_forever,daemon=True)
        self._thread.start()

    def snapshot(self):
        with self._lock:
            return {'endpoint_scope':'loopback-only',
                'forwarded_payment_submissions':len(self._records),
                'read_only_rpc_requests':self._read_requests,
                'http_methods_seen':list(self._http_methods),
                'unexpected_http_methods':list(self._unexpected_http_methods),
                'unexpected_requests':list(self._unexpected_requests),
                'payments':[dict(item) for item in self._records]}

    def close(self):
        self._server.shutdown()
        self._server.server_close()
        self._thread.join(timeout=5)


def build_native_case(chain: str, protocol_version: int = 1, *, state_commitment=None,
                      wallet_key_sink: dict | None = None) -> dict:
    """Build public signed fixtures without returning or exporting private keys.

    Executing this helper does not start validators or prove consensus. The
    optional sink receives only ephemeral signing-key handles in memory for a
    protocol-3 local integration run; it is never included in the public case.
    fixture plan is also replay-tested locally before the network gate uses it.
    """
    if type(protocol_version) is not int or protocol_version not in (1, 2, 3):
        raise ValueError('unsupported fixture protocol version')
    if state_commitment is not None and (state_commitment != 'smt-v1' or protocol_version != 3):
        raise ValueError('compact commitments require fresh protocol-3 genesis')
    if protocol_version == 3:
        from budget_network_case import build_budget_case
        return build_budget_case(chain, state_commitment=state_commitment, key_sink=wallet_key_sink)
    owner, merchant, agent, newcomer, replacement, second_agent = (
        Ed25519PrivateKey.generate() for _ in range(6))
    owner_id, merchant_id = address(public(owner)), address(public(merchant))
    genesis={'chain_id':chain,'asset':'DEV','fee':100,'allocations':[
        {'public_key':public(owner),'units':100_000_000},
        {'public_key':public(merchant),'units':0}]}
    if protocol_version == 2:genesis['protocol_version']=2
    model=NativeLedger(':memory:',genesis)
    def tx(key,nonce,op,grant='',sender=owner_id,incoming=None):
        body=model.body(sender,nonce,op,grant_id=grant,valid_until=10000)
        if incoming is not None:body=accept_account_key(incoming,body)
        return canonical(sign(key,body))
    accepted=[
        ('native transfer',tx(owner,0,{'type':'transfer','to':merchant_id,'units':10_000_000})),
        ('owner grant',tx(owner,1,{'type':'grant','id':'worker','public_key':public(agent),
            'cap':2_000_100,'expires':10000,'recipients':[merchant_id]})),
        ('agent transfer',tx(agent,0,{'type':'transfer','to':merchant_id,'units':1_250_000},'worker')),
        ('owner fence',tx(owner,2,{'type':'fence'}))]
    rejected=[('old authority rejected by node admission',
               tx(agent,1,{'type':'transfer','to':merchant_id,'units':10},'worker'))]
    case={'genesis':genesis,'accepted':accepted,'rejected':rejected,'protocol_version':protocol_version}
    if protocol_version == 2:
        new_id=address(public(newcomer))
        accepted.extend([
            ('onboard signed native account',tx(owner,3,{'type':'open_account',
                'public_key':public(newcomer),'units':1_000_000,'acceptance':''},incoming=newcomer)),
            ('new account uses same local grant label',tx(newcomer,0,{'type':'grant','id':'worker',
                'public_key':public(second_agent),'cap':20_100,'expires':10000,
                'recipients':[merchant_id]},sender=new_id)),
            ('new account delegated payment',tx(second_agent,0,{'type':'transfer','to':merchant_id,
                'units':10_000},'worker',sender=new_id)),
            ('rotate continuing account key',tx(newcomer,1,{'type':'rotate_key',
                'public_key':public(replacement),'acceptance':''},sender=new_id,incoming=replacement)),
            ('replacement key payment',tx(replacement,2,{'type':'transfer','to':merchant_id,
                'units':1_000},sender=new_id)),
            ('payment to stable rotated address',tx(owner,4,{'type':'transfer','to':new_id,'units':1_000}))])
        rejected.extend([
            ('retired account key rejected',tx(newcomer,3,{'type':'transfer','to':merchant_id,
                'units':1},sender=new_id)),
            ('pre-rotation grant rejected',tx(second_agent,1,{'type':'transfer','to':merchant_id,
                'units':1},'worker',sender=new_id)),
            ('duplicate onboarding cannot reset identity',tx(owner,5,{'type':'open_account',
                'public_key':public(newcomer),'units':1_000,'acceptance':''},incoming=newcomer))])
        case.update(new_account=new_id,new_public_key=public(replacement),expected_new_balance=989_600)
    model.close()
    return case


def run(engine: str, output: Path, protocol_version: int = 1, *, state_commitment=None,
        decision_delivery: bool = False, receipt_convergence: bool = False):
    if type(protocol_version) is not int or protocol_version not in (1, 2, 3):
        raise ValueError('unsupported fixture protocol version')
    if type(decision_delivery) is not bool:
        raise ValueError('decision_delivery must be an explicit boolean')
    if type(receipt_convergence) is not bool:
        raise ValueError('receipt_convergence must be an explicit boolean')
    if receipt_convergence and not decision_delivery:
        raise ValueError('receipt convergence requires decision delivery')
    if decision_delivery and protocol_version != 3:
        raise ValueError('decision delivery requires protocol 3')
    run_started_at=datetime.now(timezone.utc)
    if decision_delivery:
        sys.path.insert(0,str(ROOT/'tools/wallet-account/src'))
        sys.path.insert(0,str(ROOT/'tools/wallet-delivery/src'))
        from decision_delivery import DecisionDelivery
    if state_commitment is not None and (state_commitment != 'smt-v1' or protocol_version != 3):
        raise ValueError('compact commitments require fresh protocol-3 genesis')
    output.parent.mkdir(parents=True,exist_ok=True)
    report={'state_commitment':state_commitment or 'legacy-flat-v1','schema':3,'status':'unassessed','engine_required':PIN,'native_protocol_version':protocol_version,
            'test_scope':'four local equal-power validators on one host; not independent operators',
            'run_provenance':source_provenance(run_started_at),
            'checks':[],'wallet_integration_verified':False,'public_network':False,'real_funds':False}
    if decision_delivery:
        report['decision_delivery']={'enabled':True,'status':'unassessed',
            'scope':'two exact CertifiedWallet decisions sent only to the local four-validator network',
            'adapter_signing_performed':False,'receipt_convergence_requested':receipt_convergence,
            'wallet':{'reopened_original_journals':False},
            'payments':[]}
    binary=shutil.which(engine) if '/' not in engine else str(Path(engine).resolve())
    if not binary or not Path(binary).is_file():
        report['reason']='Pinned CometBFT executable is not installed. No consensus run occurred.'
        output.parent.mkdir(parents=True,exist_ok=True);output.write_text(json.dumps(report,indent=2)+'\n')
        return report
    try:
        version=subprocess.check_output([binary,'version'],text=True,timeout=10).strip()
        if version.lstrip('v')!=PIN:
            raise ValueError(f'requires CometBFT {PIN}; found {version!r}')
    except (OSError, subprocess.SubprocessError, ValueError) as exc:
        report.update(status='failed',reason=f'Engine version check failed: {exc}')
        output.parent.mkdir(parents=True,exist_ok=True);output.write_text(json.dumps(report,indent=2)+'\n')
        return report
    output.parent.mkdir(parents=True,exist_ok=True)
    report['engine_version']=version
    report['engine_sha256']=hashlib.sha256(Path(binary).read_bytes()).hexdigest()
    engine_processes={};app_processes={};handles=[];runtime=None
    wallet_keys={};wallet=None;wallet_dispatch=None;wallet_delivery=None
    wallet_observed=None;wallet_dir=None;policy=None;decision_proxy=None
    def checked(name,condition,details=None):
        report['checks'].append({'name':name,'passed':bool(condition),'details':details})
        if not condition:raise AssertionError(name)
    def stop(table,i):
        p=table.pop(i,None)
        if p and p.poll() is None:
            p.terminate()
            try:p.wait(10)
            except subprocess.TimeoutExpired:p.kill();p.wait()
    with tempfile.TemporaryDirectory(prefix='etn-net-') as d:
        runtime=Path(d)
        try:
            homes=runtime/'nodes'
            subprocess.run([binary,'testnet','--v','4','--o',str(homes),'--initial-height','1'],
                           check=True,capture_output=True,text=True,timeout=30)
            for p in homes.rglob('*'):
                if p.is_dir():os.chmod(p,0o700)
                elif p.is_file():os.chmod(p,0o600)
            chain='eternities-dev-'+os.urandom(6).hex()
            case=build_native_case(chain,protocol_version,state_commitment=state_commitment,
                                   wallet_key_sink=wallet_keys if protocol_version == 3 else None)
            genesis=case['genesis']
            gfile=runtime/'app-genesis.json';gfile.write_bytes(canonical(genesis))
            ports=free_ports(8);p2p=ports[:4];http=ports[4:]
            ids=[subprocess.check_output([binary,'show-node-id','--home',str(homes/f'node{i}')],text=True).strip() for i in range(4)]
            rootgen=json.loads((homes/'node0/config/genesis.json').read_text())
            rootgen.update(chain_id=chain,initial_height='1',app_state=genesis)
            rootgen['consensus_params']['block'].update(max_bytes='1048576',max_gas='-1')
            # Public trust material only; never copy private validator keys into evidence.
            public_genesis=(json.dumps(rootgen,indent=2)+'\n').encode()
            (output.parent/'devnet-public-genesis.json').write_bytes(public_genesis)
            trust=trust_from_genesis(rootgen)
            report['genesis_file_sha256']=hashlib.sha256(public_genesis).hexdigest()
            witnesses=[]
            for i in range(4):
                home=homes/f'node{i}'
                (home/'config/genesis.json').write_text(json.dumps(rootgen,indent=2)+'\n')
                socket_dir=runtime/f'app{i}';socket_dir.mkdir(mode=0o700)
                sock=socket_dir/'a.sock'
                conf=home/'config/config.toml'
                conf.write_text(patch_toml(conf.read_text(),{
                    'proxy_app':f'unix://{sock}','abci':'socket',
                    'rpc.laddr':f'tcp://127.0.0.1:{http[i]}','rpc.unsafe':False,
                    'p2p.laddr':f'tcp://127.0.0.1:{p2p[i]}',
                    'p2p.persistent_peers':','.join(f'{ids[j]}@127.0.0.1:{p2p[j]}' for j in range(4) if j!=i),
                    'p2p.addr_book_strict':False,'p2p.allow_duplicate_ip':True,'p2p.pex':False,
                    'consensus.timeout_commit':'500ms','mempool.max_tx_bytes':16384}))
                log=open(runtime/f'app{i}.log','ab');handles.append(log)
                app_processes[i]=subprocess.Popen([sys.executable,str(ROOT/'scripts/serve_abci.py'),
                    '--db',str(socket_dir/'app.sqlite'),'--socket',str(sock),'--genesis',str(gfile)],stdout=log,stderr=log)
                wait_until(lambda:sock.exists() and app_processes[i].poll() is None,10)
            def start_engine(i):
                log=open(runtime/f'engine{i}.log','ab');handles.append(log)
                engine_processes[i]=subprocess.Popen([binary,'start','--home',str(homes/f'node{i}')],stdout=log,stderr=log)
            for i in range(4):start_engine(i)
            def height(i):return int(rpc(http[i],'status')['sync_info']['latest_block_height'])
            def live_wallet_witness():
                response=rpc(http[0],'abci_query',{'path':'/state','prove':False})['response']
                if int(response['code']) != 0:
                    raise AssertionError('live full-state query failed')
                state=json.loads(base64.b64decode(response['value']))
                next_height=int(state['height'])+1
                wait_until(lambda:height(0)>=next_height)
                signed=rpc(http[0],'commit',{'height':str(next_height)})['signed_header']
                return {'schema':1,'state':state,'state_commit':signed}
            def wallet_continuation(previous, following):
                start=int(previous['state_commit']['header']['height'])
                end=int(following['state_commit']['header']['height'])
                if not start < end <= start+65:
                    raise AssertionError('wallet checkpoint gap exceeds bounded continuation')
                return [rpc(http[0],'commit',{'height':str(h)})['signed_header']
                        for h in range(start+1,end)]
            wait_until(lambda:all(height(i)>=2 for i in range(4)))
            checked('four actual CometBFT processes',len({p.pid for p in engine_processes.values()})==4)
            checked('fresh chain producing blocks',all(height(i)>=2 for i in range(4)))
            wallet_decisions={}
            for name,raw in case['accepted']:
                for reason,bad in case.get('rejections_before',{}).get(name,[]):
                    observed=rpc(http[0],'broadcast_tx_sync',{'tx':base64.b64encode(bad).decode()})
                    checked(reason, int(observed['code'])!=0)
                if name in wallet_decisions:
                    decision=wallet_decisions[name]
                    checked(name+' uses exact wallet-signed bytes',raw==decision['raw'])
                    if decision_delivery:
                        expected_hold=100 if name=='first worker payment' else 40
                        sent=wallet_delivery.send(decision['decision_id'],decision['confirmation'],
                            account=decision['account'],grant_id=decision['grant_id'])
                        current_proxy=decision_proxy.snapshot()
                        proxy_record=current_proxy['payments'][-1] if current_proxy['payments'] else {}
                        sent_pending=wallet.pending()
                        checked(name+' send leaves wallet evidence and budget hold unchanged',
                            sum(sent_pending['pending_budget_units'].values())==expected_hold and
                            sent_pending['state_height']==wallet_observed['state']['height'] and
                            sent['wallet_obligation_status']=='pending')
                        decision['evidence']['stages'].append({'stage':'sent',
                            'wallet':{'obligation_status':sent['wallet_obligation_status'],
                                'pending_budget_units':sum(sent_pending['pending_budget_units'].values()),
                                'state_height':sent_pending['state_height']},
                            'transport':{'status':sent['transport_status'],
                                'submission_attempts':sent['submission_attempts'],
                                'exact_transport_receipt_verified':sent['exact_transport_receipt_verified']}})
                        if name=='first worker payment':
                            checked('first exact RPC reached validator and its successful HTTP reply was dropped',
                                len(current_proxy['payments'])==1 and
                                proxy_record.get('wire_sha256')==hashlib.sha256(raw).hexdigest() and
                                proxy_record.get('upstream_http_status')==200 and
                                proxy_record.get('upstream_check_tx_code')==0 and
                                proxy_record.get('upstream_tx_hash_matches') is True and
                                proxy_record.get('downstream_reply_dropped') is True and
                                sent['transport_status']=='unresolved' and
                                sent['submission_attempts']==1,proxy_record)
                        else:
                            checked('second exact RPC reached validator and returned its successful reply',
                                len(current_proxy['payments'])==2 and
                                proxy_record.get('wire_sha256')==hashlib.sha256(raw).hexdigest() and
                                proxy_record.get('upstream_http_status')==200 and
                                proxy_record.get('upstream_check_tx_code')==0 and
                                proxy_record.get('upstream_tx_hash_matches') is True and
                                proxy_record.get('downstream_reply_forwarded') is True and
                                sent['transport_status']=='endpoint_admitted' and
                                sent['submission_attempts']==1,proxy_record)
                        wallet_delivery.close();wallet_delivery=None
                        wallet.close();wallet=None
                        wallet=CertifiedWallet(wallet_dir/'decisions.sqlite',public_genesis,policy)
                        wallet_delivery=DecisionDelivery(wallet_dir/'decisions.sqlite',
                            wallet_dir/'delivery.sqlite',public_genesis,policy,decision_proxy.endpoint)
                        recovered=wallet.export(decision['decision_id'])
                        recovered_wire=canonical(recovered['result'])
                        original_envelope=parse_wire(raw)
                        recovered_envelope=parse_wire(recovered_wire)
                        checked('reopened original wallet preserves exact signature and intention bytes',
                            recovered_wire==raw and recovered_envelope['signature']==original_envelope['signature'] and
                            recovered_envelope['body']==original_envelope['body'])
                        decision['evidence']['reopened_original_journals']=True
                        report['decision_delivery']['wallet']['reopened_original_journals']=True
                        before_refresh=wallet.pending()
                        checked(name+' journal reopen retains hold before receipt collection',
                            sum(before_refresh['pending_budget_units'].values())==expected_hold and
                            before_refresh['state_height']==wallet_observed['state']['height'])
                        def collected():
                            item=wallet_delivery.refresh(decision['decision_id'],
                                account=decision['account'],grant_id=decision['grant_id'],read_attempts=4)
                            if item['collection_status']=='evidence_rejected':
                                raise AssertionError('actual RPC receipt evidence was rejected')
                            return item if item['exact_transport_receipt_verified'] else None
                        receipt=wait_until(collected,20)
                        checked(name+' receipt refresh verifies exact live inclusion without resubmission',
                            receipt['exact_transport_receipt_verified'] and
                            receipt['submission_attempts']==1 and
                            receipt['wallet_sync_performed'] is False and
                            receipt['collection_status']=='receipt_verified')
                        held=wallet.pending()
                        decision['evidence']['pending_budget_units_before_reconcile'].append(
                            sum(held['pending_budget_units'].values()))
                        checked(name+' receipt-only refresh preserves the wallet hold',
                            sum(held['pending_budget_units'].values())==expected_hold and
                            held['state_height']==wallet_observed['state']['height'] and
                            receipt['wallet_obligation_status']=='pending' and
                            receipt['wallet_sync_performed'] is False)
                        decision['evidence']['stages'].append({'stage':'receipt_refreshed_before_reconcile',
                            'wallet':{'obligation_status':receipt['wallet_obligation_status'],
                                'pending_budget_units':sum(held['pending_budget_units'].values()),
                                'state_height':held['state_height'],'wallet_sync_performed':False},
                            'transport':{'status':receipt['transport_status'],
                                'receipt_verified':receipt['exact_transport_receipt_verified'],
                                'submission_attempts':receipt['submission_attempts'],
                                'read_requests':receipt['read_requests']}})
                        packet=json.loads(wallet_delivery.export_receipt(decision['decision_id'],
                            account=decision['account'],grant_id=decision['grant_id']))
                        transaction=packet['transactions'][0]
                        block=transaction['block'];commitment=transaction['commit']
                        checked(name+' saved receipt contains the original signed transaction',
                            base64.b64decode(transaction['tx'],validate=True)==raw)
                        included_height=int(block['block']['header']['height'])
                        receipt_witness={'schema':1,'state':packet['state'],
                            'state_commit':packet['state_commit']}
                        continuation=wallet_continuation(wallet_observed,receipt_witness)
                        checked(name+' uses signed receipt state and bounded header continuation',
                            len(continuation)<=64 and
                            int(wallet_observed['state_commit']['header']['height']) <
                            int(receipt_witness['state_commit']['header']['height']) <=
                            int(wallet_observed['state_commit']['header']['height'])+65,
                            {'continuation_headers':len(continuation),
                             'receipt_state_height':receipt_witness['state']['height']})
                        reconciled=wallet_delivery.reconcile(decision['decision_id'],
                            account=decision['account'],grant_id=decision['grant_id'],
                            continuation=continuation)
                        wallet_observed=receipt_witness
                        summary=wallet.pending()
                        expected=40 if name=='first worker payment' else 0
                        budget_spent=sum(row[4] for row in receipt_witness['state']['native']['budgets'])
                        checked(name+' DecisionDelivery reconciles original wallet from certified receipt state',
                            reconciled['wallet_sync_performed'] is True and
                            reconciled['network_requested'] is False and
                            reconciled['wallet_obligation_status']=='recorded' and
                            reconciled['transport_status']=='receipt_verified' and
                            reconciled['exact_transport_receipt_verified'] is True and
                            reconciled['submission_attempts']==1)
                        checked(name+' reconciled hold and budget spend match live receipt state',
                            sum(summary['pending_budget_units'].values())==expected and
                            budget_spent==100-expected,
                            {'pending_budget_units':expected,'on_chain_budget_spent':budget_spent})
                        decision['evidence']['stages'].append({'stage':'reconciled',
                            'wallet':{'obligation_status':reconciled['wallet_obligation_status'],
                                'pending_budget_units':sum(summary['pending_budget_units'].values()),
                                'on_chain_budget_spent':budget_spent,
                                'state_height':summary['state_height'],
                                'wallet_sync_performed':True},
                            'transport':{'status':reconciled['transport_status'],
                                'receipt_verified':reconciled['exact_transport_receipt_verified'],
                                'submission_attempts':reconciled['submission_attempts']}})
                        decision['evidence']['receipt_state_height']=receipt_witness['state']['height']
                        decision['evidence']['header_continuation_count']=len(continuation)
                        decision['evidence']['pending_budget_units_after_reconcile']=expected
                        decision['evidence']['on_chain_budget_spent_after_reconcile']=budget_spent
                        decision['evidence']['submission_attempts']=reconciled['submission_attempts']
                        report['decision_delivery']['wallet']['budget_progression'].append({
                            'stage':'first payment reconciled' if name=='first worker payment'
                                else 'second payment reconciled',
                            'pending_budget_units':sum(summary['pending_budget_units'].values()),
                            'on_chain_budget_spent':budget_spent})
                        if name=='second worker boundary payment':
                            report['wallet_integration_verified']=True
                    else:
                        if name=='first worker payment':
                            # Keep the legacy direct-journal acceptance path
                            # unchanged unless the opt-in DecisionDelivery gate is selected.
                            actual=[];real_worker=payment_transport._worker
                            def lose_reply(endpoint,transaction,request_id):
                                actual.append(real_worker(endpoint,transaction,request_id))
                                return {'observation':'unresolved','reason':'injected reply loss after real RPC'}
                            with patch.object(payment_transport,'_worker',side_effect=lose_reply):
                                sent=wallet_dispatch.dispatch(decision['txid'],decision['confirmation'])
                            checked('real endpoint admitted payment before injected client reply loss',
                                    len(actual)==1 and actual[0]['observation']=='endpoint_admitted')
                            checked('injected client-boundary reply loss remains unresolved without resending or resigning',
                                    sent['status']=='unresolved' and sent['attempts']==1)
                            wallet.close()
                            wallet=CertifiedWallet(wallet_dir/'decisions.sqlite',public_genesis,policy)
                            recovered=wallet.export(decision['decision_id'])
                            checked('reopened wallet exports original signed transaction',
                                    canonical(recovered['result'])==raw)
                            checked('unresolved dispatch does not release local budget',
                                    sum(wallet.pending()['pending_budget_units'].values())==100)
                        else:
                            sent=wallet_dispatch.dispatch(decision['txid'],decision['confirmation'])
                            checked('second worker submitted exact reserved signature',
                                    sent['status']=='endpoint_admitted' and sent['attempts']==1)
                        def collected():
                            item=wallet_dispatch.refresh_receipt(decision['txid'],read_attempts=4)
                            if item['collection_status']=='evidence_rejected':
                                raise AssertionError('actual RPC receipt evidence was rejected')
                            return item if item['receipt_verified'] else None
                        receipt=wait_until(collected,20)
                        checked(name+' recovered exact live receipt without another send',
                                receipt['receipt_verified'] and receipt['attempts']==1)
                        packet=json.loads(wallet_dispatch.export_receipt(decision['txid']))
                        transaction=packet['transactions'][0]
                        block=transaction['block'];commitment=transaction['commit']
                        included_height=int(block['block']['header']['height'])
                        newer=live_wallet_witness()
                        summary=wallet.sync(newer,continuation=wallet_continuation(wallet_observed,newer))
                        wallet_observed=newer
                        expected=40 if name=='first worker payment' else 0
                        checked(name+' reconciles signed holds against real certified state',
                                sum(summary['pending_budget_units'].values())==expected and
                                sum(row[4] for row in newer['state']['native']['budgets'])==100-expected,
                                {'pending_budget_units':expected,'on_chain_budget_spent':100-expected})
                        if name=='second worker boundary payment':
                            report['wallet_integration_verified']=True
                else:
                    result=rpc(http[0],'broadcast_tx_commit',{'tx':base64.b64encode(raw).decode()})
                    checked(name,int(result['check_tx']['code'])==0 and int(result['tx_result']['code'])==0,
                            {'height':result.get('height'),'hash':result.get('hash')})
                    included_height=int(result['height'])
                    commitment=rpc(http[0],'commit',{'height':str(included_height)})['signed_header']
                    block=rpc(http[0],'block',{'height':str(included_height)})
                verified=verify_block_transactions(block,commitment,trust,expected_tx=raw)
                checked(name+' independently signature/inclusion verified',True,verified)
                witnesses.append({'tx':base64.b64encode(raw).decode(),'block':block,'commit':commitment})
                if protocol_version==3 and name=='atlas budget membership':
                    wallet_dir=runtime/'wallet';wallet_dir.mkdir(mode=0o700)
                    password=os.urandom(32)
                    deadline=(datetime.now(timezone.utc)+timedelta(hours=1)).strftime('%Y-%m-%dT%H:%M:%SZ')
                    policy={'schema':1,'genesis_sha256':report['genesis_file_sha256'],
                            'trust_expires_utc':deadline,'minimum_header_height':1,
                            'maximum_age_seconds':300,'future_skew_seconds':5}
                    wallet=CertifiedWallet(wallet_dir/'decisions.sqlite',public_genesis,policy)
                    if not decision_delivery:
                        wallet_dispatch=DispatchJournal(wallet_dir/'dispatch.sqlite',public_genesis,
                            report['genesis_file_sha256'],f'http://127.0.0.1:{http[0]}/',deadline)
                    wallet_observed=live_wallet_witness()
                    for label,worker in (('first worker payment','raven'),
                                         ('second worker boundary payment','atlas')):
                        worker_raw=next(value for title,value in case['accepted'] if title==label)
                        key=wallet_keys[worker]
                        vault=wallet_dir/(worker+'.pem')
                        vault.write_bytes(key.private_bytes(serialization.Encoding.PEM,
                            serialization.PrivateFormat.PKCS8,
                            serialization.BestAvailableEncryption(password)))
                        vault.chmod(0o600)
                        body=parse_wire(worker_raw)['body'];signer=public(key)
                        if worker=='atlas':
                            refused=case['rejections_before'][label][0][1]
                            try:wallet.review(wallet_observed,parse_wire(refused)['body'],signer)
                            except Reject as exc:denied='shared budget insufficient' in str(exc)
                            else:denied=False
                            checked('second worker overcommit refused before vault unlock',denied)
                        review=wallet.review(wallet_observed,body,signer)
                        approved=wallet.approve(wallet_observed,body,signer,review['confirmation'],vault,password)
                        signed=canonical(approved['result'])
                        checked(label+' signed by certified wallet against real validator state',
                                signed==worker_raw)
                        if decision_delivery:
                            wallet_decisions[label]={'raw':signed,'decision_id':approved['decision_id'],
                                'account':body['sender'],'grant_id':body['grant_id'],
                                'signer_public_key':signer}
                        else:
                            queued=wallet_dispatch.queue(signed,signer)
                            wallet_decisions[label]={'raw':signed,'decision_id':approved['decision_id'],
                                'txid':queued['native_txid'],'confirmation':queued['dispatch_confirmation']}
                    initial_wallet=wallet.pending()
                    checked('two signed unsettled workers reserve the full shared budget',
                            sum(initial_wallet['pending_budget_units'].values())==100)
                    if decision_delivery:
                        initial_spent=sum(row[4] for row in wallet_observed['state']['native']['budgets'])
                        checked('shared budget begins with zero network spend',initial_spent==0,
                                {'on_chain_budget_spent':initial_spent})
                        for worker in ('raven','atlas'):
                            (wallet_dir/(worker+'.pem')).unlink()
                        wallet_keys.clear()
                        key=None;password=None
                        temporary_key_files_absent=not any(
                            (wallet_dir/(worker+'.pem')).exists() for worker in ('raven','atlas'))
                        runner_key_handles_empty=not wallet_keys
                        checked('temporary signer files absent and runner handle map empty at adapter start',
                            temporary_key_files_absent and runner_key_handles_empty)
                        decision_proxy=DecisionDeliveryRpcProxy(http[0],[
                            ('first worker payment',wallet_decisions['first worker payment']['raw']),
                            ('second worker boundary payment',wallet_decisions['second worker boundary payment']['raw'])])
                        wallet_delivery=DecisionDelivery(wallet_dir/'decisions.sqlite',
                            wallet_dir/'delivery.sqlite',public_genesis,policy,decision_proxy.endpoint,create=True)
                        report['decision_delivery']['wallet'].update({
                            'initial_pending_budget_units':sum(initial_wallet['pending_budget_units'].values()),
                            'initial_on_chain_budget_spent':initial_spent,
                            'adapter_signing_performed':False,
                            'temporary_signing_key_files_absent_at_delivery_start':temporary_key_files_absent,
                            'runner_signing_key_handle_map_empty_at_delivery_start':runner_key_handles_empty,
                            'budget_progression':[{'stage':'both decisions queued',
                                'pending_budget_units':sum(initial_wallet['pending_budget_units'].values()),
                                'on_chain_budget_spent':initial_spent}]})
                        for label in ('first worker payment','second worker boundary payment'):
                            decision=wallet_decisions[label]
                            queued=wallet_delivery.queue(decision['decision_id'],
                                account=decision['account'],grant_id=decision['grant_id'])
                            expected_wire_hash=hashlib.sha256(decision['raw']).hexdigest()
                            checked(label+' queues the exact existing signed wallet decision',
                                queued['decision_id']==decision['decision_id'] and
                                queued['wire_sha256']==expected_wire_hash and
                                queued['native_txid']==hashlib.sha256(
                                    DOMAIN+canonical(parse_wire(decision['raw'])['body'])).hexdigest() and
                                queued['transport_status']=='queued' and
                                queued['submission_attempts']==0 and
                                queued['signing_performed'] is False)
                            evidence={'name':label,'decision_id':decision['decision_id'],
                                'native_txid':queued['native_txid'],'wire_sha256':queued['wire_sha256'],
                                'signer_public_key_sha256':hashlib.sha256(
                                    bytes.fromhex(decision['signer_public_key'])).hexdigest(),
                                'reopened_original_journals':False,
                                'pending_budget_units_before_reconcile':[],
                                'stages':[{'stage':'queued',
                                    'wallet':{'obligation_status':queued['wallet_obligation_status'],
                                        'pending_budget_units':sum(initial_wallet['pending_budget_units'].values()),
                                        'state_height':queued['wallet_state_height']},
                                    'transport':{'status':queued['transport_status'],
                                        'submission_attempts':queued['submission_attempts'],
                                        'signing_performed':queued['signing_performed']}}]}
                            decision.update(txid=queued['native_txid'],
                                confirmation=queued['delivery_confirmation'],evidence=evidence)
                            report['decision_delivery']['payments'].append(evidence)
            for name,raw in case['rejected']:
                rejected=rpc(http[0],'broadcast_tx_sync',{'tx':base64.b64encode(raw).decode()})
                checked(name,int(rejected['code'])!=0)
            before=height(0);stop(engine_processes,3)
            wait_until(lambda:height(0)>=before+3)
            checked('3 of 4 continue',True,{'before':before,'after':height(0)})
            stop(engine_processes,2)
            # Permit already-signed in-flight blocks before measuring a halt interval.
            time.sleep(3);halt=height(0);time.sleep(3)
            checked('2 of 4 do not advance during measured interval',height(0)==halt,{'height':halt,'seconds':3})
            start_engine(2);wait_until(lambda:height(0)>=halt+3)
            checked('quorum restoration resumes progress',True)
            start_engine(3);wait_until(lambda:height(3)>=halt+3)
            checked('stale validator rejoins',True)
            def matching():
                allstates=[json.loads(base64.b64decode(rpc(http[i],'abci_query',{'path':'/state','prove':False})['response']['value'])) for i in range(4)]
                return allstates[0] if all(s==allstates[0] for s in allstates) else None
            final=wait_until(matching,30)
            checked('four applications agree at common height',True,{'height':final['height'],'app_hash':final['app_hash']})
            checked('native test supply conserved',sum(row[4] for row in final['native']['accounts'])==100_000_000)
            checked('all intended native operations recorded',len(final['native']['receipts'])==len(case['accepted']))
            if protocol_version == 2:
                accounts={row[0]:row for row in final['native']['accounts']}
                new_account=accounts[case['new_account']]
                checked('rotated account retains stable identity and expected balance',
                    new_account[1]==case['new_public_key'] and new_account[2:5]==[3,1,case['expected_new_balance']])
                checked('same-named grants remain owner-scoped',len(final['native']['grants'])==2)
            if protocol_version == 3:
                budgets={row[0]:row for row in final['native']['budgets']}
                shared=budgets[case['budget_id']]
                checked('aggregate budget includes both fees and retains revocation',
                        shared[3]==100 and shared[4]==100 and shared[7]==1)
                checked('all grants have one budget and spent counters reconcile',
                        len(final['native']['grant_budgets'])==2 and
                        sum(row[6] for row in final['native']['grants'])==shared[4])
            # Preserve the v0.3 four-state comparison, then require independent
            # quorum signatures anchoring this state at header height h+1.
            state_height=final['height']
            wait_until(lambda:height(0)>=state_height+1)
            state_commit=rpc(http[0],'commit',{'height':str(state_height+1)})['signed_header']
            packet={'schema':1,'state':final,'state_commit':state_commit,'transactions':witnesses}
            expected_ids=[hashlib.sha256(DOMAIN+canonical(parse_wire(raw)['body'])).hexdigest()
                          for _,raw in case['accepted']]
            verification=verify_packet(packet,trust,expected_txids=expected_ids)
            checked('native receipts independently certified against genesis',True,verification)
            (output.parent/'devnet-certificate.json').write_text(json.dumps(packet,indent=2)+'\n')
            (output.parent/'devnet-certificate-verification.json').write_text(json.dumps(verification,indent=2)+'\n')
            # Exercise the customer-side read-only collector against actual RPC.
            # This gate is mandatory when an engine runs; fixture tests do not pass it.
            dispatch_folder=runtime/'receipt-client';dispatch_folder.mkdir(mode=0o700)
            deadline=(datetime.now(timezone.utc)+timedelta(days=1)).strftime('%Y-%m-%dT%H:%M:%SZ')
            first_raw=case['accepted'][0][1]
            with DispatchJournal(dispatch_folder/'journal.sqlite',public_genesis,
                    report['genesis_file_sha256'],f'http://127.0.0.1:{http[0]}/',deadline) as client:
                pending=client.queue(first_raw,genesis['allocations'][0]['public_key'])
                def collect_receipt():
                    result=client.refresh_receipt(pending['native_txid'],read_attempts=4)
                    if result['collection_status']=='evidence_rejected':
                        raise AssertionError('actual RPC receipt collection rejected evidence')
                    return result if result['receipt_verified'] else None
                receipt=wait_until(collect_receipt,10)
                checked('read-only client collected and verified actual RPC receipt',
                        receipt['receipt_verified'] and receipt['attempts']==0,receipt)
                (output.parent/'client-collected-certificate.json').write_bytes(
                    client.export_receipt(pending['native_txid']))
            if state_commitment == 'smt-v1':
                # Actual RPC proof reads, mandatory for this engine scenario.
                # No signed fixture or local file may substitute for these calls.
                from compact_verifier import verify_compact_witness, verify_compact_receipt
                requests=[('accounts',address(genesis['allocations'][0]['public_key'])),
                          ('receipts',expected_ids[0])]
                for table,key in requests:
                    response=rpc(http[0],'abci_query',{'path':'/proof/'+table+'/'+key.encode('ascii').hex(),'prove':False})['response']
                    checked('compact '+table+' query accepted',int(response['code'])==0)
                    witness=json.loads(base64.b64decode(response['value']))
                    wait_until(lambda:height(0)>=witness['height']+1)
                    signed=rpc(http[0],'commit',{'height':str(witness['height']+1)})['signed_header']
                    verified=verify_compact_witness(witness,signed,trust,expected_queries=[(table,key)])
                    checked('compact '+table+' proof independently verified',verified['records'][0]['exists'],verified)
                    if table=='receipts':
                        receipt=verify_compact_receipt(witness,signed,trust,expected_transaction=case['accepted'][0][1],
                            block=witnesses[0]['block'],commit=witnesses[0]['commit'])
                        checked('compact receipt binds exact original transfer',receipt['status']=='verified',receipt)
                    (output.parent/('compact-'+table+'.json')).write_text(json.dumps({'witness':witness,'signed_header':signed},indent=2)+'\n')
            # Fixed-height metadata avoids confusing later advancing heads.
            records=[json.loads(base64.b64decode(rpc(http[i],'abci_query',
                {'path':f'/block/{state_height}','prove':False})['response']['value'])) for i in range(4)]
            checked('four committed block records agree',all(r==records[0] for r in records))
            checked('block record matches signed next-header state commitment',
                    records[0]['app_hash']==verification['state']['state_app_hash'])
            if protocol_version==3:
                checked('certified wallet integration completed against local validators',
                        report['wallet_integration_verified'])
            if receipt_convergence:
                # The first saved receipt is older than the second reconciled
                # payment. Cold reopening must confirm history, not roll back
                # or reimport that older witness. This is an opt-in NEW gate.
                before_wallet=list(wallet.db.iterdump())
                before_dispatch=list(wallet_delivery.dispatch.db.iterdump())
                before_proxy=decision_proxy.snapshot()
                wallet_delivery.close();wallet_delivery=None
                wallet.close();wallet=None
                wallet=CertifiedWallet(wallet_dir/'decisions.sqlite',public_genesis,policy)
                wallet_delivery=DecisionDelivery(wallet_dir/'decisions.sqlite',
                    wallet_dir/'delivery.sqlite',public_genesis,policy,decision_proxy.endpoint)
                first=wallet_decisions['first worker payment']
                again=wallet_delivery.reconcile(first['decision_id'],
                    account=first['account'],grant_id=first['grant_id'])
                checked('older first receipt is already recorded after cold reopen',
                    again['reconciliation_outcome']=='already_recorded' and
                    again['wallet_sync_performed'] is False and
                    again['state_witness_imported'] is False and
                    again['receipt_state_height']<again['wallet_state_height'] and
                    again['wallet_obligation_status']=='recorded',again)
                checked('revisiting receipt preserves wallet transport and RPC counts',
                    list(wallet.db.iterdump())==before_wallet and
                    list(wallet_delivery.dispatch.db.iterdump())==before_dispatch and
                    decision_proxy.snapshot()==before_proxy and
                    sum(wallet.pending()['pending_budget_units'].values())==0)
                report['decision_delivery']['receipt_convergence']=again
            if decision_delivery:
                proxy_final=decision_proxy.snapshot()
                checked('two exact worker payments were forwarded once with no unexpected HTTP methods or RPC requests',
                    len(proxy_final['payments'])==2 and
                    proxy_final['forwarded_payment_submissions']==2 and
                    proxy_final['unexpected_http_methods']==[] and
                    proxy_final['unexpected_requests']==[] and
                    all(item['upstream_check_tx_code']==0 and item['upstream_tx_hash_matches']
                        for item in proxy_final['payments']) and
                    [item['downstream_reply_dropped'] for item in proxy_final['payments']]==[True,False],
                    proxy_final)
                report['decision_delivery']['transport']=proxy_final
                report['decision_delivery']['status']='passed'
            report['final_state']=final;report['certificate']=verification;report['status']='passed'
        except Exception as exc:
            report['status']='failed';report['reason']=f'{type(exc).__name__}: {exc}'
        finally:
            if wallet_dispatch is not None:wallet_dispatch.close()
            if wallet_delivery is not None:wallet_delivery.close()
            if wallet is not None:wallet.close()
            if decision_proxy is not None:
                if decision_delivery:
                    report['decision_delivery']['transport']=decision_proxy.snapshot()
                    report['decision_delivery']['status']=report['status']
                decision_proxy.close()
            wallet_keys.clear()
            for i in list(engine_processes):stop(engine_processes,i)
            for i in list(app_processes):stop(app_processes,i)
            for f in handles:f.close()
            output.parent.mkdir(parents=True,exist_ok=True)
            for log in runtime.glob('*.log'):shutil.copyfile(log,output.parent/log.name)
            report['passed_checks']=sum(c['passed'] for c in report['checks'])
            output.write_text(json.dumps(report,indent=2)+'\n')
    return report

if __name__=='__main__':
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--cometbft',default='cometbft')
    p.add_argument('--output',type=Path,default=ROOT/'evidence/v05/devnet.json')
    p.add_argument('--protocol-version',type=int,choices=(1,2,3),default=1)
    p.add_argument('--state-commitment',choices=('smt-v1',),default=None)
    p.add_argument('--decision-delivery',action='store_true',
                   help='run the real-validator DecisionDelivery acceptance path (protocol 3 only)')
    p.add_argument('--receipt-convergence',action='store_true',
                   help='also confirm older receipts after cold reopen; requires decision delivery')
    args=p.parse_args()
    if args.receipt_convergence and not args.decision_delivery:
        p.error('--receipt-convergence requires --decision-delivery')
    if args.decision_delivery and args.protocol_version!=3:
        p.error('--decision-delivery requires --protocol-version 3')
    report=run(args.cometbft,args.output,args.protocol_version,
        state_commitment=args.state_commitment,decision_delivery=args.decision_delivery,
        receipt_convergence=args.receipt_convergence)
    print(json.dumps(report,indent=2))
    raise SystemExit(0 if report['status']=='passed' else 2)
