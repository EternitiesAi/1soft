"""Deterministic LOCAL fixtures. Changing committees are not live validators."""
import base64
import copy
from datetime import datetime, timezone, timedelta
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from block_application import BlockApplication
from commit_verifier import TrustAnchor, encode, header_hash, merkle_root, sha
from certificate_fixture import make_header, make_commit
from native_core import public, address, NativeLedger, canonical, sign
from validator_transition import (FORMAT, canonical_set, parse_set, set_hash, policy_for,
                                  preview_update, nanos)


def fixture(smt=True, start=None):
    keys = [Ed25519PrivateKey.from_private_bytes(bytes([i])*32) for i in range(31,43)]
    keyed = {public(k):k for k in keys}
    a = canonical_set([{'public_key':public(k),'power':10} for k in keys[:4]])
    p1 = preview_update(a,[{'public_key':public(keys[4]),'power':10}],2); b=p1['next_validators']
    p2 = preview_update(b,[{'public_key':public(keys[0]),'power':0},
                           {'public_key':public(keys[4]),'power':20}],4); c=p2['next_validators']
    changes=[{'public_key':r['public_key'],'power':0} for r in c]
    changes += [{'public_key':public(k),'power':10} for k in keys[5:9]]
    p3 = preview_update(c,changes,6); d=p3['next_validators']
    sets=[a,a,a,b,b,c,c,d,d,d]
    nexts=[a,a,b,b,c,c,d,d,d,d]
    owner=Ed25519PrivateKey.from_private_bytes(b'\xca'*32)
    merchant=Ed25519PrivateKey.from_private_bytes(b'\xcb'*32)
    native={'chain_id':'1soft-validator-continuity-dev','asset':'DEV','fee':2,'protocol_version':3,
            'allocations':[{'public_key':public(owner),'units':1000}, {'public_key':public(merchant),'units':0}]}
    if smt:native['state_commitment']='smt-v1'
    def trust(rows):
        vals=parse_set(rows)
        return TrustAnchor(native['chain_id'],vals,bytes.fromhex(set_hash(rows)),sha(encode(native)).hex(),sum(v.power for v in vals))
    original=trust(a)
    engine={'chain_id':native['chain_id'],'initial_height':'1','app_state':native,'validators':[
        {'address':v.address.hex().upper(),'pub_key':{'type':'tendermint/PubKeyEd25519',
        'value':base64.b64encode(v.public_key).decode()},'power':str(v.power)} for v in original.validators]}
    raw=encode(engine); app=BlockApplication(':memory:',expected_genesis=native)
    app.init_chain(native['chain_id'],native); steps=[];start=start or datetime(2026,9,28,12,tzinfo=timezone.utc)
    models=[]
    try:
        for i in range(10):
            h=i+1; t=trust(sets[i]); txs=[]
            if h==5:
                ledger=NativeLedger(':memory:',native)
                try:txs=[canonical(sign(owner,ledger.body(address(public(owner)),0,
                        {'type':'transfer','to':address(public(merchant)),'units':17},valid_until=20)))]
                finally:ledger.close()
            head=make_header(t,h,app.app_hash,txs,
                             steps[-1]['signed_header']['commit']['block_id'] if steps else None)
            head['version']['app']='3'; head['time']=(start+timedelta(seconds=h)).isoformat().replace('+00:00','Z')
            head['next_validators_hash']=set_hash(nexts[i]).upper()
            commit=make_commit(head,t,[keyed[v.public_key.hex()] for v in t.validators])
            result=app.finalize_block(txs,h,header_hash(head));app.commit()
            assert all(r['code']==0 for r in result['tx_results'])
            steps.append({'format':FORMAT,'signed_header':commit,'validators':sets[i],'next_validators':nexts[i]})
            models.append({'height':h,'app_hash':app.app_hash,'receipt_count':len(app.native['receipts'])})
    finally:app.close()
    policy=policy_for(raw,sha(raw).hex(),initial_height=1,initial_header_hash=header_hash(steps[0]['signed_header']['header']).hex(),
                      trust_period_seconds=3600,max_clock_drift_seconds=30)
    now=nanos((start+timedelta(seconds=20)).isoformat().replace('+00:00','Z'))
    return {'steps':steps,'policy':policy,'genesis':raw,'now':now,'keys':keyed,'trust':trust,
            'plans':[p1,p2,p3],'native_execution':models,'original_trust':original}


def resign(f, step, flags=None):
    t=f['trust'](step['validators'])
    step['signed_header']=make_commit(step['signed_header']['header'],t,
                     [f['keys'][v.public_key.hex()] for v in t.validators],flags=flags)
    return step
