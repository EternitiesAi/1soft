"""Development fixture: real native execution, synthetic static-validator signatures.

Public deterministic test seeds only. No live validator, wallet or user keys.
"""
import base64
import copy
from datetime import datetime, timezone, timedelta
import json
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from block_application import BlockApplication, restore
from native_core import address, public, canonical, sign
from certificate_fixture import validators, make_header, make_commit
from commit_verifier import encode, header_hash
from explorer_index import sha


def scenario(blocks=24, protocol=3, smt=True, large_balance=False):
    if protocol!=3:smt=False
    keys=[Ed25519PrivateKey.from_private_bytes(bytes([i])*32) for i in range(221,228)]
    ids=[address(public(k)) for k in keys]
    supply=2**53-1 if large_balance else 2500000
    g={'chain_id':'1soft-explorer-development','asset':'DEV','fee':2,
       'allocations':[{'public_key':public(keys[0]),'units':supply-500000},
                      {'public_key':public(keys[1]),'units':300000},
                      {'public_key':public(keys[2]),'units':100000},
                      {'public_key':public(keys[3]),'units':100000},
                      {'public_key':public(keys[4]),'units':0}]}
    if protocol>1:g['protocol_version']=protocol
    if smt:g['state_commitment']='smt-v1'
    engine,trust,vkeys=validators(g);genesis=encode(engine)
    app=BlockApplication(':memory:',expected_genesis=g,block_history_keep=4);app.init_chain(g['chain_id'],g)
    states={0:json.loads(app.query('/state')['value'])};headers={};bodies={};previous=None
    start=datetime(2026,9,28,5,0,0,tzinfo=timezone.utc)
    try:
        for height in range(1,blocks+1):
            ledger=restore(g,app.native)
            try:
                if protocol==3 and height==1:
                    intents=[(0,{'type':'budget_create','id':'studio','cap':1200,'expires':500,
                                 'recipients':[ids[1],ids[2],ids[3],ids[4]]},'')]
                elif protocol==3 and height in (2,3):
                    who=5 if height==2 else 6;name='raven' if height==2 else 'atlas'
                    intents=[(0,{'type':'grant','id':name,'public_key':public(keys[who]),'cap':800,
                          'expires':400,'recipients':[ids[1],ids[2],ids[3],ids[4]],'budget_id':'studio'},'')]
                elif protocol==3 and height==16:
                    intents=[(0,{'type':'revoke','id':'atlas'},'')]
                else:
                    agent=protocol==3 and height>=4
                    who=(5 if height%2==0 or height>16 else 6) if agent else 0
                    grant=('raven' if who==5 else 'atlas') if agent else ''
                    intents=[(who,{'type':'transfer','to':ids[1+height%4],'units':7+(height*7)%31},grant)]
                txs=[]
                for who,op,grant in intents:
                    sender=ids[0]
                    if grant:
                        nonce=ledger.db.execute('SELECT nonce FROM grants WHERE id=?',(ledger.grant_storage_id(sender,grant),)).fetchone()[0]
                    else:nonce=ledger._account(sender)['nonce']
                    body=ledger.body(sender,nonce,op,grant_id=grant,valid_until=10000)
                    txs.append(canonical(sign(keys[who],body)))
            finally:ledger.close()
            head=make_header(trust,height,app.app_hash,txs,previous);head['version']['app']=str(protocol)
            head['time']=(start+timedelta(seconds=height*2)).isoformat().replace('+00:00','Z')
            sh=make_commit(head,trust,vkeys);previous=sh['commit']['block_id'];headers[height]=sh
            bodies[height]={'block_id':previous,'block':{'header':head,'data':{'txs':[base64.b64encode(t).decode() for t in txs]}}}
            result=app.finalize_block(txs,height,header_hash(head));app.commit()
            assert all(r['code']==0 for r in result['tx_results']),result
            states[height]=json.loads(app.query('/state')['value'])
        head=make_header(trust,blocks+1,app.app_hash,previous=previous);head['version']['app']=str(protocol)
        head['time']=(start+timedelta(seconds=(blocks+1)*2)).isoformat().replace('+00:00','Z')
        headers[blocks+1]=make_commit(head,trust,vkeys)
        return {'genesis':genesis,'genesis_sha256':sha(genesis),'states':states,'headers':headers,
                'blocks':bodies,'accounts':ids,'trust':trust,'validator_keys':vkeys,
                'old_block_status':app.query('/block/1')['code']}
    finally:app.close()


def bundle(c, height=None, first=1, bodies=True):
    height=max(c['states']) if height is None else height
    return copy.deepcopy({'schema':1,'state':c['states'][height],'state_commit':c['headers'][height+1],
        'headers':[c['headers'][h] for h in range(first,height+2)],
        'blocks':[c['blocks'][h] for h in range(first,height+1)] if bodies else []})


def pin(c,height=None):
    height=max(c['states']) if height is None else height
    return header_hash(c['headers'][height+1]['header']).hex()
