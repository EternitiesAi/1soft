"""Locally authored signatures, NOT engine output. Deterministic disposable keys."""
import base64
import json
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from block_application import BlockApplication
from native_core import public
from test_block_application import fixture, signed
from commit_verifier import sha, merkle_root, trust_from_genesis, header_hash, vote_sign_bytes, ZERO_TIME

STAMP='2026-09-24T12:00:00.123456789Z'

def validators(genesis, powers=(10,10,10,10)):
    keys=[Ed25519PrivateKey.from_private_bytes(bytes([i+11])*32) for i in range(len(powers))]
    vals=[{'address':sha(bytes.fromhex(public(k)))[:20].hex().upper(),
           'pub_key':{'type':'tendermint/PubKeyEd25519','value':base64.b64encode(bytes.fromhex(public(k))).decode()},
           'power':str(power),'name':'FIXTURE'} for k,power in zip(keys,powers)]
    engine={'chain_id':genesis['chain_id'],'initial_height':'1','validators':vals,'app_state':genesis}
    trust=trust_from_genesis(engine)
    keyed={sha(bytes.fromhex(public(k)))[:20]:k for k in keys}
    return engine,trust,[keyed[v.address] for v in trust.validators]

def make_header(trust,height,app_hash,txs=(),previous=None):
    return {'version':{'block':'11','app':'1'},'chain_id':trust.chain_id,'height':str(height),'time':STAMP,
      'last_block_id':previous or {'hash':'','parts':{'total':0,'hash':''}},
      'last_commit_hash':sha(b'fixture-last-commit').hex().upper(),
      'data_hash':merkle_root([sha(tx) for tx in txs]).hex().upper(),
      'validators_hash':trust.validators_hash.hex().upper(),'next_validators_hash':trust.validators_hash.hex().upper(),
      'consensus_hash':sha(b'fixture-params').hex().upper(),'app_hash':app_hash.upper(),
      'last_results_hash':sha(b'fixture-results').hex().upper(),'evidence_hash':merkle_root([]).hex().upper(),
      'proposer_address':trust.validators[0].address.hex().upper()}

def make_commit(header,trust,keys,flags=None,round_=0):
    flags=[2]*len(keys) if flags is None else flags
    bid={'hash':header_hash(header).hex().upper(),'parts':{'total':1,'hash':sha(b'fixture-parts').hex().upper()}}
    signatures=[]
    for val,key,flag in zip(trust.validators,keys,flags):
        if flag==1:
            signatures.append({'block_id_flag':1,'validator_address':'','timestamp':ZERO_TIME,'signature':None})
        else:
            wire=vote_sign_bytes(trust.chain_id,int(header['height']),round_,bid if flag==2 else None,STAMP)
            signatures.append({'block_id_flag':flag,'validator_address':val.address.hex().upper(),
                               'timestamp':STAMP,'signature':base64.b64encode(key.sign(wire)).decode()})
    return {'header':header,'commit':{'height':header['height'],'round':round_,'block_id':bid,'signatures':signatures}}

def packet_fixture(powers=(10,10,10,10)):
    owner,_,_,g=fixture();engine,trust,keys=validators(g,powers)
    app=BlockApplication(':memory:');app.init_chain(g['chain_id'],g)
    raw=signed(g,owner)
    h1=make_header(trust,1,app.app_hash,[raw]);c1=make_commit(h1,trust,keys)
    app.finalize_block([raw],1,header_hash(h1));app.commit()
    state=json.loads(app.query('/state')['value']);app.close()
    h2=make_header(trust,2,state['app_hash'],previous=c1['commit']['block_id']);c2=make_commit(h2,trust,keys)
    result={'block_id':c1['commit']['block_id'],'block':{'header':h1,'data':{'txs':[base64.b64encode(raw).decode()]}}}
    packet={'schema':1,'state':state,'state_commit':c2,
            'transactions':[{'tx':base64.b64encode(raw).decode(),'block':result,'commit':c1}]}
    return engine,trust,keys,packet
