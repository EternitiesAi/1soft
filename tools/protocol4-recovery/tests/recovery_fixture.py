"""Public deterministic development keys; actual P4 execution, synthetic headers."""
from __future__ import annotations
import base64
from datetime import datetime, timezone, timedelta
import hashlib
import json
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from block_application import encode
from native_core import NativeLedger, address, canonical, digest, public, sign
from protocol4_application import Protocol4Application
from protocol4_abci_wire import Request
from registry_rules_core import GENESIS_FORMAT
from validator_sets_core import ValidatorSet, canonical_roster
from commit_verifier import header_hash, vote_sign_bytes, merkle_root


def key(seed): return Ed25519PrivateKey.from_private_bytes(bytes([seed])*32)

def identities():
    payers=[key(1),key(2)];vs=[key(i) for i in range(41,46)];admins=[key(i) for i in range(171,175)]
    old=canonical_roster([{'public_key':public(k),'power':10} for k in vs[:4]])
    new=canonical_roster([{'public_key':public(k),'power':p} for k,p in zip(vs[1:],(12,10,10,9))])
    policy={'schema':1,'format':GENESIS_FORMAT,'mode':'development-only','chain_id':'p4-recovery-fixture',
        'validators':old,'administrators':{'format':'threshold-ed25519-v1',
        'public_keys':sorted(public(k) for k in admins),'threshold':3},
        'minimum_delay_blocks':2,'cooldown_blocks':1,'minimum_validators':4,'maximum_power_bps':3333}
    g={'chain_id':policy['chain_id'],'asset':'DEV','fee':1,'protocol_version':4,'validator_registry':policy,
       'allocations':[{'public_key':public(k),'units':100000} for k in payers]}
    return g,payers,admins,vs,new


def payment(g,owner,to,nonce,units):
    ledger=NativeLedger(':memory:',g)
    try: return canonical(sign(owner,ledger.body(address(public(owner)),nonce,
                 {'type':'transfer','to':to,'units':units},valid_until=400)))
    finally: ledger.close()


def approval(rules,body,admins):
    return encode({'body':body,'approvals':sorted([{'public_key':public(k),
            'signature':k.sign(rules.signing_bytes(body)).hex()} for k in admins[:3]],key=lambda v:v['public_key'])})


def requests_and_headers(app,txs,keys,previous=None):
    h=app.height+1;state,result=app._execute(txs,h)
    current=ValidatorSet.parse(state['registry']['active_validators'])
    following=ValidatorSet.parse(state['registry']['next_validators'])
    sha=lambda b:hashlib.sha256(b).digest()
    stamp=(datetime(2026,9,29,7,0,0,tzinfo=timezone.utc)+timedelta(seconds=h)).isoformat().replace('+00:00','Z')
    header={'version':{'block':'11','app':'4'},'chain_id':app.genesis['chain_id'],'height':str(h),'time':stamp,
      'last_block_id':previous or {'hash':'','parts':{'total':0,'hash':''}},
      'last_commit_hash':sha(b'synthetic-last-commit').hex().upper(),
      'data_hash':merkle_root([sha(t) for t in txs]).hex().upper(),
      'validators_hash':current.hash.upper(),'next_validators_hash':following.hash.upper(),
      'consensus_hash':sha(b'fixture-parameters').hex().upper(),'app_hash':app.app_hash.upper(),
      'last_results_hash':sha(b'fixture-results').hex().upper(),'evidence_hash':merkle_root([]).hex().upper(),
      'proposer_address':current.validators[0].address.hex().upper()}
    bid={'hash':header_hash(header).hex().upper(),'parts':{'total':1,'hash':sha(b'fixture-parts').hex().upper()}}
    keyed={public(k):k for k in keys};sigs=[]
    for v in current.validators:
        material=vote_sign_bytes(app.genesis['chain_id'],h,0,bid,stamp)
        sigs.append({'block_id_flag':2,'validator_address':v.address.hex().upper(),'timestamp':stamp,
                     'signature':base64.b64encode(keyed[v.public_key.hex()].sign(material)).decode()})
    sh={'header':header,'commit':{'height':str(h),'round':0,'block_id':bid,'signatures':sigs}}
    q=Request();q.finalize_block.height=h;q.finalize_block.hash=header_hash(header)
    q.finalize_block.txs.extend(txs);q.finalize_block.next_validators_hash=bytes.fromhex(following.hash)
    if h>1:
        for v in ValidatorSet.parse(app.state['registry']['active_validators']).validators:
            row=q.finalize_block.decided_last_commit.votes.add();row.validator.address=v.address
            row.validator.power=v.power;row.block_id_flag=2
    return q,sh


def model(end=10, third=False):
    from protocol4_abci_server import dispatch
    g,payers,admins,vs,new=identities()
    app=Protocol4Application(':memory:',expected_genesis=g)
    app.init_chain(g['chain_id'],g,g['validator_registry']['validators'])
    first=payment(g,payers[0],address(public(payers[1])),0,37)
    second=payment(g,payers[0],address(public(payers[1])),1,53)
    third_wire=payment(g,payers[0],address(public(payers[1])),2,71)
    action=approval(app.rules,app.rules.body(app.state['registry'],
        {'kind':'schedule','emitted_height':4,'target_validators':new},valid_from=1,valid_until=3),admins)
    headers=[];requests=[];states=[];responses=[];batches=[];prev=None
    try:
        for h in range(1,end+1):
            txs=[action,first] if h==1 else [second] if h==7 else [third_wire] if third and h==9 else []
            q,sh=requests_and_headers(app,txs,vs,prev);result=dispatch(app,q)
            assert all(r.code==0 for r in result.finalize_block.tx_results)
            app.commit();headers.append(sh);requests.append(q.SerializeToString());responses.append(result.SerializeToString())
            states.append(json.loads(encode(app.state)));batches.append(txs);prev=sh['commit']['block_id']
        _,last=requests_and_headers(app,[],vs,prev);headers.append(last)
        return {'genesis':g,'payers':payers,'admins':admins,'validators':vs,'target':new,
                'first':first,'second':second,'third':third_wire,'action':action,'headers':headers,'requests':requests,
                'responses':responses,'states':states,'batches':batches,'history':app.history(),
                'app_hash':app.app_hash}
    finally: app.close()
