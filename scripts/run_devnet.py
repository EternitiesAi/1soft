#!/usr/bin/env python3
"""Run a disposable, loopback-only four-validator CometBFT integration gate.

Requires the real pinned binary. Missing engine => UNASSESSED, never simulated.
No persistent keys, customer money, public listeners, or cloud resources are used.
"""
from __future__ import annotations
import argparse
import base64
import hashlib
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

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/'src'))
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from native_core import NativeLedger, canonical, public, address, sign, DOMAIN, parse_wire, accept_account_key
from commit_verifier import trust_from_genesis, verify_block_transactions, verify_signed_header, verify_packet
from payment_transport import DispatchJournal

PIN='0.38.25'


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


def build_native_case(chain: str, protocol_version: int = 1, *, state_commitment=None) -> dict:
    """Build public signed fixtures, never return or export private keys.

    Executing this helper does not start validators or prove consensus. The
    fixture plan is also replay-tested locally before the network gate uses it.
    """
    if type(protocol_version) is not int or protocol_version not in (1, 2, 3):
        raise ValueError('unsupported fixture protocol version')
    if state_commitment is not None and (state_commitment != 'smt-v1' or protocol_version != 3):
        raise ValueError('compact commitments require fresh protocol-3 genesis')
    if protocol_version == 3:
        from budget_network_case import build_budget_case
        return build_budget_case(chain, state_commitment=state_commitment)
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


def run(engine: str, output: Path, protocol_version: int = 1, *, state_commitment=None):
    if type(protocol_version) is not int or protocol_version not in (1, 2, 3):
        raise ValueError('unsupported fixture protocol version')
    if state_commitment is not None and (state_commitment != 'smt-v1' or protocol_version != 3):
        raise ValueError('compact commitments require fresh protocol-3 genesis')
    output.parent.mkdir(parents=True,exist_ok=True)
    report={'state_commitment':state_commitment or 'legacy-flat-v1','schema':3,'status':'unassessed','engine_required':PIN,'native_protocol_version':protocol_version,
            'test_scope':'four local equal-power validators on one host; not independent operators',
            'checks':[],'public_network':False,'real_funds':False}
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
            case=build_native_case(chain,protocol_version,state_commitment=state_commitment)
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
            wait_until(lambda:all(height(i)>=2 for i in range(4)))
            checked('four actual CometBFT processes',len({p.pid for p in engine_processes.values()})==4)
            checked('fresh chain producing blocks',all(height(i)>=2 for i in range(4)))
            for name,raw in case['accepted']:
                for reason,bad in case.get('rejections_before',{}).get(name,[]):
                    observed=rpc(http[0],'broadcast_tx_sync',{'tx':base64.b64encode(bad).decode()})
                    checked(reason, int(observed['code'])!=0)
                result=rpc(http[0],'broadcast_tx_commit',{'tx':base64.b64encode(raw).decode()})
                checked(name,int(result['check_tx']['code'])==0 and int(result['tx_result']['code'])==0,
                        {'height':result.get('height'),'hash':result.get('hash')})
                included_height=int(result['height'])
                commitment=rpc(http[0],'commit',{'height':str(included_height)})['signed_header']
                block=rpc(http[0],'block',{'height':str(included_height)})
                verified=verify_block_transactions(block,commitment,trust,expected_tx=raw)
                checked(name+' independently signature/inclusion verified',True,verified)
                witnesses.append({'tx':base64.b64encode(raw).decode(),'block':block,'commit':commitment})
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
            report['final_state']=final;report['certificate']=verification;report['status']='passed'
        except Exception as exc:
            report['status']='failed';report['reason']=f'{type(exc).__name__}: {exc}'
        finally:
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
    args=p.parse_args()
    report=run(args.cometbft,args.output,args.protocol_version,state_commitment=args.state_commitment)
    print(json.dumps(report,indent=2))
    raise SystemExit(0 if report['status']=='passed' else 2)
