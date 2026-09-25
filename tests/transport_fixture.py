"""Synthetic static-validator signatures over actual native-ledger execution.

No ABCI transport, CometBFT process, consensus voting or live-chain provenance.
Known fixture seeds are public and must never be used with real funds.
"""
import base64
import json
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from native_core import NativeLedger, address, canonical, digest, public, sign
from commit_verifier import (encode, sha, merkle_root, trust_from_genesis,
                             vote_sign_bytes, header_hash)

STAMP = '2026-09-24T12:00:00Z'
NOW_NS = 1790251210 * 1_000_000_000  # overridden below from the specified UTC time
from commit_verifier import timestamp
NOW_NS = timestamp('2026-09-24T12:00:10Z').seconds * 1_000_000_000
DEADLINE = '2026-09-25T12:00:00Z'


def fixture():
    owner, merchant = [Ed25519PrivateKey.from_private_bytes(bytes([i])*32) for i in (41,42)]
    keys = [Ed25519PrivateKey.from_private_bytes(bytes([i])*32) for i in range(51,55)]
    genesis = {'chain_id': '1soft-dispatch-fixture', 'protocol_version': 2,
               'asset': 'DEV', 'fee': 2, 'allocations': [
                   {'public_key': public(owner), 'units': 1000},
                   {'public_key': public(merchant), 'units': 0}]}
    vals = [{'address': sha(bytes.fromhex(public(k)))[:20].hex().upper(),
             'pub_key': {'type': 'tendermint/PubKeyEd25519',
                         'value': base64.b64encode(bytes.fromhex(public(k))).decode()},
             'power': '10'} for k in keys]
    engine = {'chain_id': genesis['chain_id'], 'initial_height': '1', 'validators': vals, 'app_state': genesis}
    trust = trust_from_genesis(engine)
    indexed = {sha(bytes.fromhex(public(k)))[:20]: k for k in keys}
    keys = [indexed[v.address] for v in trust.validators]
    ledger = NativeLedger(':memory:', genesis)
    raw = canonical(sign(owner, ledger.body(address(public(owner)), 0,
        {'type':'transfer','to':address(public(merchant)),'units':20})))
    ledger.close()
    return owner, merchant, genesis, engine, trust, keys, raw


def header(trust, height, app_hash, txs=(), previous=None):
    return {'version': {'block':'11','app':'1'}, 'chain_id': trust.chain_id, 'height': str(height),
        'time': STAMP, 'last_block_id': previous or {'hash':'','parts':{'total':0,'hash':''}},
        'last_commit_hash': sha(b'SYNTHETIC-prior-commit').hex().upper(),
        'data_hash': merkle_root([sha(tx) for tx in txs]).hex().upper(),
        'validators_hash': trust.validators_hash.hex().upper(),
        'next_validators_hash': trust.validators_hash.hex().upper(),
        'consensus_hash': sha(b'SYNTHETIC-params').hex().upper(), 'app_hash': app_hash.upper(),
        'last_results_hash': sha(b'SYNTHETIC-results').hex().upper(),
        'evidence_hash': merkle_root([]).hex().upper(), 'proposer_address': trust.validators[0].address.hex().upper()}


def certificate(h, trust, keys):
    bid = {'hash': header_hash(h).hex().upper(), 'parts': {'total':1,'hash':sha(b'SYNTHETIC-parts').hex().upper()}}
    signatures = [{'block_id_flag':2, 'validator_address':v.address.hex().upper(), 'timestamp':STAMP,
        'signature':base64.b64encode(k.sign(vote_sign_bytes(trust.chain_id,int(h['height']),0,bid,STAMP))).decode()}
        for v,k in zip(trust.validators, keys)]
    return {'header':h,'commit':{'height':h['height'],'round':0,'block_id':bid,'signatures':signatures}}


def packet(raw=None):
    owner, merchant, genesis, engine, trust, keys, original = fixture()
    raw = original if raw is None else raw
    ledger = NativeLedger(':memory:', genesis)
    def state_at(height):
        native = {name:[list(row) for row in ledger.db.execute('SELECT * FROM '+name+' ORDER BY '+order)]
            for name,order in [('meta','k'),('accounts','id'),('grants','id'),('receipts','sequence')]}
        app_hash = sha(encode({'domain':'ETERNITIES/ABCI-STATE/v1','genesis':digest(genesis),'height':height,'native':native})).hex()
        return {'genesis':genesis,'height':height,'native':native,'app_hash':app_hash}
    before = state_at(0)
    first = certificate(header(trust,1,before['app_hash'],[raw]),trust,keys)
    ledger.apply(json.loads(raw),height=1)
    state = state_at(1)
    second = certificate(header(trust,2,state['app_hash'],previous=first['commit']['block_id']),trust,keys)
    ledger.close()
    result = {'schema':1,'state':state,'state_commit':second,'transactions':[{'tx':base64.b64encode(raw).decode(),
        'block':{'block_id':first['commit']['block_id'],'block':{'header':first['header'],
        'data':{'txs':[base64.b64encode(raw).decode()]}}},'commit':first}]}
    return result
