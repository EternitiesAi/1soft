"""Synthetic quorum signatures over ACTUAL P4 monetary/admin execution.

Public deterministic keys are test material only. No network, independent
validator, P4 custody, or agent-autonomy claim. Full app Finalize/Commit runs below.
"""
import base64
import copy
from datetime import datetime, timezone, timedelta
import hashlib
import time

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from block_application import encode, restore
from commit_verifier import header_hash, vote_sign_bytes, merkle_root, sha
from native_core import address, public, sign, canonical
from protocol4_application import Protocol4Application
from protocol4_abci_wire import Request
from registry_rules_core import GENESIS_FORMAT
from validator_sets_core import ValidatorSet, canonical_roster
from p4_evidence import FORMAT, POLICY_FORMAT


def sign_header(header, roster, keys, flags=None):
    bid = {'hash': header_hash(header).hex().upper(),
           'parts': {'total':1,'hash':sha(b'P4 fixture block parts').hex().upper()}}
    signatures = []
    for i, val in enumerate(roster.validators):
        flag = flags[i] if flags is not None else 2
        if flag == 1:
            signatures.append({'block_id_flag':1,'validator_address':'','signature':None,
                               'timestamp':'0001-01-01T00:00:00Z'})
        else:
            wire = vote_sign_bytes(header['chain_id'],int(header['height']),0,
                                   bid if flag == 2 else None,header['time'])
            signatures.append({'block_id_flag':flag,'validator_address':val.address.hex().upper(),
                               'timestamp':header['time'],
                               'signature':base64.b64encode(keys[val.public_key.hex()].sign(wire)).decode()})
    return {'header':copy.deepcopy(header),'commit':{'height':header['height'],'round':0,
            'block_id':bid,'signatures':signatures}}


def rechain(evidence, keys):
    """For negative tests only: valid signatures cannot excuse wrong execution."""
    previous = None
    for entry in evidence['headers']:
        h = entry['signed_header']['header']
        h['last_block_id'] = previous or {'hash':'','parts':{'total':0,'hash':''}}
        entry['signed_header'] = sign_header(h,ValidatorSet.parse(entry['validators']),keys)
        previous = entry['signed_header']['commit']['block_id']
    return evidence


def build(count=16, validator_count=4, rejected=False):
    vals=[Ed25519PrivateKey.from_private_bytes(bytes([i])*32) for i in range(181,199)]
    admins=[Ed25519PrivateKey.from_private_bytes(bytes([i])*32) for i in range(171,175)]
    owner=Ed25519PrivateKey.from_private_bytes(b'\x8e'*32)
    merchant=Ed25519PrivateKey.from_private_bytes(b'\x8f'*32)
    raven=Ed25519PrivateKey.from_private_bytes(b'\x90'*32)
    payer, recipient=address(public(owner)),address(public(merchant))
    old=canonical_roster([{'public_key':public(k),'power':10} for k in vals[:validator_count]])
    target=canonical_roster([{'public_key':public(k),'power':10} for k in vals[1:validator_count+1]])
    replacement=canonical_roster([{'public_key':public(k),'power':10} for k in vals[10:10+validator_count]])
    rg={'schema':1,'format':GENESIS_FORMAT,'mode':'development-only','chain_id':'1soft-p4-client-fixture',
        'validators':old,'administrators':{'format':'threshold-ed25519-v1',
        'public_keys':sorted(public(k) for k in admins),'threshold':3},
        'minimum_delay_blocks':2,'cooldown_blocks':1,'minimum_validators':4,'maximum_power_bps':3333}
    g={'chain_id':rg['chain_id'],'asset':'DEV','fee':2,'protocol_version':4,
       'allocations':[{'public_key':public(owner),'units':1000},
                      {'public_key':public(merchant),'units':0}], 'validator_registry':rg}
    engine={'chain_id':g['chain_id'],'initial_height':'1','app_state':g,'validators':[
        {'address':v.address.hex().upper(),'pub_key':{'type':'tendermint/PubKeyEd25519',
        'value':base64.b64encode(v.public_key).decode()},'power':str(v.power),'name':'FIXTURE'}
        for v in ValidatorSet.parse(old).validators]}
    genesis=encode(engine);keys={public(k):k for k in vals};wires={};states={};headers=[];history=[]
    start=datetime.fromtimestamp(int(time.time())-600,timezone.utc)
    def header(h,root,txs,current,following):
        return {'version':{'block':'11','app':'4'},'chain_id':g['chain_id'],'height':str(h),
            'time':(start+timedelta(seconds=h)).isoformat().replace('+00:00','Z'),
            'last_block_id':headers[-1]['signed_header']['commit']['block_id'] if headers else {'hash':'','parts':{'total':0,'hash':''}},
            'last_commit_hash':sha(b'fixture-last-commit').hex().upper(),
            'data_hash':merkle_root([sha(tx) for tx in txs]).hex().upper(),
            'validators_hash':current.hash.upper(),'next_validators_hash':following.hash.upper(),
            'consensus_hash':sha(b'fixture-consensus').hex().upper(),'app_hash':root.upper(),
            'last_results_hash':sha(b'fixture-results').hex().upper(),'evidence_hash':'',
            'proposer_address':current.validators[0].address.hex().upper()}
    with Protocol4Application(':memory:',expected_genesis=g) as app:
        app.init_chain(g['chain_id'],g,old)
        states[0]={'genesis':g,'height':0,'app_hash':app.app_hash,**copy.deepcopy(app.state)}
        for height in range(1,count+1):
            txs=[]
            if height==1:
                ledger=restore(g,app.state['native'])
                try:
                    ops=[{'type':'budget_create','id':'studio','cap':200,'expires':100,'recipients':[recipient]},
                         {'type':'grant','id':'raven','public_key':public(raven),'cap':200,'expires':100,
                          'recipients':[recipient],'budget_id':'studio'},
                         {'type':'transfer','to':recipient,'units':11}]
                    for nonce,op in enumerate(ops):
                        txs.append(canonical(sign(owner,ledger.body(payer,nonce,op,valid_until=100))))
                    wires['before']=txs[-1]
                finally:ledger.close()
            if height in (2,9):
                body=app.rules.body(app.state['registry'],{'kind':'schedule','emitted_height':4 if height==2 else 12,
                    'target_validators':target if height==2 else replacement},valid_from=height,valid_until=30)
                message=app.rules.signing_bytes(body)
                approvals=sorted([{'public_key':public(k),'signature':k.sign(message).hex()} for k in admins[:3]],key=lambda v:v['public_key'])
                txs.append(encode({'body':body,'approvals':approvals}));wires['schedule'+str(height)]=txs[-1]
            if height in (2,7,15):
                ledger=restore(g,app.state['native'])
                try:
                    grant='raven' if height in (2,7) else ''
                    nonce=(0 if height==2 else 1) if grant else 3
                    units={2:58,7:38,15:7}[height]
                    raw=canonical(sign(raven if grant else owner,ledger.body(payer,nonce,
                        {'type':'transfer','to':recipient,'units':units},grant_id=grant,valid_until=100)))
                    txs.append(raw);wires[{2:'raven',7:'after',15:'replacement'}[height]]=raw
                finally:ledger.close()
            if rejected and height==8:
                txs.append(wires['after'])  # Committed duplicate must not become a second execution.
            _, predicted=app._execute(txs,height)
            current=ValidatorSet.parse(app.rules.transition(app.state['registry'],[],height)[0]['active_validators'])
            following=ValidatorSet.parse(app.rules.transition(app.state['registry'],[],height)[0]['next_validators'])
            h=header(height,app.app_hash,txs,current,following)
            signed=sign_header(h,current,keys)
            req=Request();q=req.finalize_block;q.height=height;q.hash=header_hash(h);q.txs.extend(txs)
            q.next_validators_hash=bytes.fromhex(predicted['next_validators_hash'])
            last=[]
            if height>1:
                for v in ValidatorSet.parse(app.state['registry']['active_validators']).validators:
                    vote=q.decided_last_commit.votes.add();vote.validator.address=v.address;vote.validator.power=v.power;vote.block_id_flag=2
                    last.append({'address':v.address.hex(),'power':v.power,'block_id_flag':2})
            result,_=app.finalize_block(txs,height,header_hash(h),q.next_validators_hash,last,
                                        q.SerializeToString(deterministic=True));app.commit()
            if not (rejected and height==8):assert all(r['code']==0 for r in result['tx_results']),result
            headers.append({'signed_header':signed,'validators':current.json(),'next_validators':following.json()})
            history.append({'height':height,'txs':[base64.b64encode(raw).decode() for raw in txs]})
            states[height]={'genesis':g,'height':height,'app_hash':app.app_hash,**copy.deepcopy(app.state)}
        ahead,_=app.rules.transition(app.state['registry'],[],count+1)
        current,following=ValidatorSet.parse(ahead['active_validators']),ValidatorSet.parse(ahead['next_validators'])
        h=header(count+1,app.app_hash,[],current,following)
        headers.append({'signed_header':sign_header(h,current,keys),'validators':current.json(),'next_validators':following.json()})
    policy={'schema':1,'format':POLICY_FORMAT,'genesis_sha256':hashlib.sha256(genesis).hexdigest(),
        'anchor_height':1,'anchor_hash':header_hash(headers[0]['signed_header']['header']).hex(),
        'anchor_time':headers[0]['signed_header']['header']['time'],'trust_period_seconds':3600,
        'max_clock_drift_seconds':5,'expected_block_version':11}
    return {'genesis':genesis,'g':g,'policy':policy,'states':states,'headers':headers,'history':history,
            'keys':keys,'wires':wires,'payer':payer,'merchant':recipient,
            'now_ns':int((start+timedelta(seconds=600)).timestamp()*10**9)}


def bundle(case,height=None):
    height=max(case['states']) if height is None else height
    return copy.deepcopy({'schema':1,'format':FORMAT,'state':case['states'][height],
        'history':case['history'][:height],'headers':case['headers'][:height+1]})
