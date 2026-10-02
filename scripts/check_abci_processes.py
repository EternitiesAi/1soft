#!/usr/bin/env python3
"""Four real application processes, scripted ABCI delivery. NOT a consensus test."""
from __future__ import annotations
import argparse
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import time

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/'src'))
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from native_core import NativeLedger, public, address, sign, canonical
from abci_wire import Client


def run(destination: Path):
    owner,merchant,agent=(Ed25519PrivateKey.generate() for _ in range(3))
    genesis={'chain_id':'eternities-abci-scripted-1','asset':'DEV','fee':100,'allocations':[
        {'public_key':public(owner),'units':100_000_000},{'public_key':public(merchant),'units':0}]}
    model=NativeLedger(':memory:',genesis)
    def tx(key,nonce,op,grant=''):
        return canonical(sign(key,model.body(address(public(owner)),nonce,op,grant_id=grant)))
    grant=tx(owner,0,{'type':'grant','id':'render-worker','public_key':public(agent),'cap':2_000_100,
         'expires':100,'recipients':[address(public(merchant))]})
    spend=tx(agent,0,{'type':'transfer','to':address(public(merchant)),'units':1_250_000},'render-worker')
    fence=tx(owner,1,{'type':'fence'})
    late=tx(agent,1,{'type':'transfer','to':address(public(merchant)),'units':100},'render-worker')
    model.close()
    report={'schema':1,'mode':'scripted ABCI delivery to four application processes',
            'consensus_engine_running':False,'validator_votes_tested':False,
            'genesis':genesis,'checks':[],'blocks':[]}
    def checked(name, condition, details=None):
        report['checks'].append({'name':name,'passed':bool(condition),'details':details})
        if not condition: raise AssertionError(name)
    procs={}; clients={}; logs={}
    with tempfile.TemporaryDirectory(prefix='etn-abci-') as d:
        runtime=Path(d)
        g=runtime/'app-genesis.json';g.write_bytes(canonical(genesis))
        def start(i):
            node=runtime/str(i);node.mkdir(mode=0o700,exist_ok=True)
            socket=node/'a.sock'
            if socket.exists():socket.unlink() # only our stopped test process's owned path
            log=open(node/'server.log','ab');logs[i]=log
            procs[i]=subprocess.Popen([sys.executable,str(ROOT/'scripts/serve_abci.py'),
                '--db',str(node/'app.sqlite'),'--socket',str(socket),'--genesis',str(g)],
                stdout=log,stderr=log,cwd=ROOT)
            deadline=time.monotonic()+10
            while time.monotonic()<deadline:
                if procs[i].poll() is not None:raise RuntimeError((node/'server.log').read_text())
                try:
                    clients[i]=Client(str(socket));clients[i].call('info');return
                except (FileNotFoundError,ConnectionRefusedError,ConnectionError):time.sleep(.02)
            raise TimeoutError('application startup timeout')
        def stop(i,kill=False):
            if i in clients:clients.pop(i).close()
            p=procs.pop(i)
            if p.poll() is None:
                p.kill() if kill else p.terminate()
                try:p.wait(5)
                except subprocess.TimeoutExpired:p.kill();p.wait()
            logs.pop(i).close()
        def info(i):return clients[i].call('info')
        def finalize(i,txs,height):
            return clients[i].call('finalize_block',txs=txs,height=height,hash=hashlib.sha256(f'scripted-only-{height}'.encode()).digest())
        def state(i):return json.loads(clients[i].call('query',path='/state').value)
        try:
            for i in range(4):start(i)
            checked('four distinct OS processes',len({p.pid for p in procs.values()})==4)
            roots=[clients[i].call('init_chain',chain_id=genesis['chain_id'],app_state_bytes=canonical(genesis),initial_height=1).app_hash.hex() for i in range(4)]
            checked('same genesis AppHash',len(set(roots))==1)
            before=state(0)
            for i in range(4):
                checked(f'check grant without spending node {i}',clients[i].call('check_tx',tx=grant).code==0)
                prepared=clients[i].call('prepare_proposal',txs=[grant,spend,spend],height=1,max_tx_bytes=1_048_576)
                checked(f'sequential proposal filters replay node {i}',list(prepared.txs)==[grant,spend])
                checked(f'valid proposal accepted node {i}',clients[i].call('process_proposal',txs=[grant,spend],height=1).status==1)
                checked(f'invalid proposal rejected node {i}',clients[i].call('process_proposal',txs=[grant,spend,spend],height=1).status==2)
            checked('proposal evaluation not committed',state(0)==before)
            results=[finalize(i,[grant,spend],1) for i in range(4)]
            checked('same finalized root on four processes',len({r.app_hash for r in results})==1)
            checked('no early committed height',all(info(i).last_block_height==0 for i in range(4)))
            checked('query excludes pending changes',state(0)==before)
            checked('repeated FinalizeBlock stable',finalize(0,[grant,spend],1).SerializeToString()==results[0].SerializeToString())
            stop(3,kill=True)
            for i in range(3):clients[i].call('commit')
            start(3)
            checked('precommit process kill retains old height',info(3).last_block_height==0)
            checked('replay after precommit crash same root',finalize(3,[grant,spend],1).app_hash==results[0].app_hash)
            clients[3].call('commit')
            states=[state(i) for i in range(4)]
            checked('same committed state after replay',all(s==states[0] for s in states))
            report['blocks'].append({'height':1,'app_hash':states[0]['app_hash'],'transactions':2,'delivery':'scripted'})
            for i in range(4):
                checked(f'committed spend replay rejected node {i}',clients[i].call('check_tx',tx=spend).code!=0)
                finalize(i,[fence],2);clients[i].call('commit')
                checked(f'old agent authority rejected node {i}',clients[i].call('check_tx',tx=late).code!=0)
            stop(0,kill=True);start(0)
            checked('postcommit process kill retains new height',info(0).last_block_height==2)
            checked('revocation survives process restart',clients[0].call('check_tx',tx=late).code!=0)
            states=[state(i) for i in range(4)]
            checked('same final state after restart',all(s==states[0] for s in states))
            checked('fixed test supply conserved',sum(r[4] for r in states[0]['native']['accounts'])==100_000_000)
            checked('query proofs explicitly unavailable',clients[0].call('query',path='/state',prove=True).code!=0)
            report['blocks'].append({'height':2,'app_hash':states[0]['app_hash'],'transactions':1,'delivery':'scripted'})
            report['final_state']=states[0]
            report['status']='passed'
        except Exception as exc:
            report['status']='failed';report['error']=str(exc);raise
        finally:
            for i in list(procs):stop(i)
            destination.parent.mkdir(parents=True,exist_ok=True)
            for node in runtime.glob('[0-3]'):
                (destination.parent/f'abci-node{node.name}.log').write_bytes((node/'server.log').read_bytes())
            report['passed_checks']=sum(c['passed'] for c in report['checks'])
            destination.write_text(json.dumps(report,indent=2)+'\n')
    return report

if __name__=='__main__':
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--output',type=Path,default=ROOT/'evidence/v05/abci-processes.json')
    result=run(p.parse_args().output)
    print(json.dumps({'status':result['status'],'checks':result['passed_checks'],
                      'consensus_engine_running':False,'final_height':result['final_state']['height']}))
