"""Synthetic signed headers, not CometBFT execution or valid governance votes."""
from datetime import datetime, timezone, timedelta
import base64
import copy
import hashlib
import time
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from native_core import public
from commit_verifier import TrustAnchor, encode, sha, header_hash, vote_sign_bytes
from certificate_fixture import make_header
from validator_sets import ValidatorSet, canonical_roster, draft_transition


def scenario(count=12, *, emitted=3, full_replace=False):
    keys = [Ed25519PrivateKey.from_private_bytes(bytes([i]) * 32) for i in range(31,43)]
    keymap = {public(k):k for k in keys}
    old = canonical_roster([{'public_key':public(k),'power':10} for k in keys[:4]])
    new = canonical_roster([{'public_key':public(k),'power':p} for k,p in zip(keys[1:5],(10,15,10,12))])
    if full_replace:
        new = canonical_roster([{'public_key':public(k),'power':10} for k in keys[6:10]])
    sets = {'old':ValidatorSet.parse(old), 'new':ValidatorSet.parse(new)}
    g = {'chain_id':'1soft-validator-transition-fixture','asset':'DEV','fee':2,
         'allocations':[{'public_key':public(keys[-1]),'units':10000}]}
    engine = {'chain_id':g['chain_id'],'initial_height':'1','app_state':g,'validators':[
        {'address':v.address.hex().upper(),'pub_key':{'type':'tendermint/PubKeyEd25519',
          'value':base64.b64encode(v.public_key).decode()},'power':str(v.power),'name':'FIXTURE'}
        for v in sets['old'].validators]}
    genesis = encode(engine)
    initial = (time.time_ns() // 10**9 - 120) * 10**9
    start = datetime.fromtimestamp(initial // 10**9, timezone.utc)
    entries = []; last = None
    for height in range(1,count+1):
        current = sets['new' if height >= emitted+2 else 'old']
        following = sets['new' if height >= emitted+1 else 'old']
        trust = TrustAnchor(g['chain_id'],current.validators,bytes.fromhex(current.hash),sha(encode(g)).hex(),current.total_power)
        h = make_header(trust,height,sha(f'UNEXECUTED-FIXTURE-STATE-{height-1}'.encode()).hex(),previous=last)
        h['next_validators_hash'] = following.hash.upper()
        h['time'] = (start + timedelta(seconds=height-1)).isoformat().replace('+00:00','Z')
        sh = sign_header(h,current,keymap)
        last = sh['commit']['block_id']
        entries.append({'signed_header':sh,'validators':current.json(),'next_validators':following.json()})
    policy = {'schema':1,'format':'1soft/validator-policy/v1','genesis_sha256':sha(genesis).hex(),
              'anchor_height':1,'anchor_hash':header_hash(entries[0]['signed_header']['header']).hex(),
              'anchor_time':entries[0]['signed_header']['header']['time'],
              'trust_period_seconds':3600,'max_clock_drift_seconds':5,
              'expected_block_version':11,'expected_app_version':1}
    plan = draft_transition(old,new,chain_id=g['chain_id'],native_genesis_hash=sha(encode(g)).hex(),
                            expected_current_hash=sets['old'].hash,emitted_height=emitted)
    return {'genesis':genesis,'policy':policy,'old':old,'new':new,'sets':sets,'keys':keymap,
            'entries':entries,'now_ns':initial+120*10**9,'initial_ns':initial,'draft':plan}


def sign_header(header, roster, keymap, flags=None):
    bid = {'hash':header_hash(header).hex().upper(), 'parts':{'total':1,'hash':sha(b'fixture block parts').hex().upper()}}
    signatures=[]
    for i,v in enumerate(roster.validators):
        flag = 2 if flags is None else flags[i]
        if flag == 1:
            signatures.append({'block_id_flag':1,'validator_address':'','signature':None,'timestamp':'0001-01-01T00:00:00Z'})
            continue
        sig = keymap[v.public_key.hex()].sign(vote_sign_bytes(header['chain_id'],int(header['height']),0,
                                bid if flag == 2 else None, header['time']))
        signatures.append({'block_id_flag':flag,'validator_address':v.address.hex().upper(),
                           'timestamp':header['time'],'signature':base64.b64encode(sig).decode()})
    return {'header':header,'commit':{'height':header['height'],'round':0,'block_id':bid,'signatures':signatures}}
