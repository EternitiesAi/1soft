"""Synthetic validator attestations over real native-ledger execution.

NOT engine output. Uses disposable public seeds; never use for a network or funds.
No ABCI transport or consensus implementation is imported.
"""
import base64
import copy
import json
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from native_core import NativeLedger, public, digest
from commit_verifier import (trust_from_genesis, sha, encode, merkle_root, header_hash,
    vote_sign_bytes, timestamp)
from wallet_state import COLUMNS

STAMP = '2026-09-24T16:00:00Z'
NOW = timestamp(STAMP).seconds * 10**9


class StateFixture:
    def __init__(self, genesis):
        self.ledger = NativeLedger(':memory:', genesis)
        self.keys = [Ed25519PrivateKey.from_private_bytes(bytes([80+i])*32) for i in range(4)]
        self.genesis = {'chain_id':genesis['chain_id'],'initial_height':'1','app_state':genesis,
            'validators':[{'address':sha(bytes.fromhex(public(k)))[:20].hex().upper(),
                'pub_key':{'type':'tendermint/PubKeyEd25519','value':base64.b64encode(bytes.fromhex(public(k))).decode()},
                'power':'10','name':'SYNTHETIC-NOT-NETWORK'} for k in self.keys]}
        self.trust = trust_from_genesis(self.genesis)
        keyed={sha(bytes.fromhex(public(k)))[:20]:k for k in self.keys}
        self.keys=[keyed[v.address] for v in self.trust.validators]
        self.raw=encode(self.genesis); self.pin=sha(self.raw).hex(); self.packets=[]

    def packet(self, height=None, *, execute=None, stamp=STAMP, mutate_state=None, previous=None):
        height=len(self.packets) if height is None else height
        if execute is not None: self.ledger.apply(execute,height=height)
        native={name:[list(r) for r in self.ledger.db.execute(f"SELECT {','.join(cols)} FROM {name} ORDER BY "+
            ('k' if name=='meta' else 'sequence' if name=='receipts' else 'id'))] for name,cols in COLUMNS.items()}
        state={'genesis':self.genesis['app_state'],'height':height,'native':native}
        if mutate_state: mutate_state(state)
        state['app_hash']=sha(encode({'domain':'ETERNITIES/ABCI-STATE/v1',
            'genesis':digest(state['genesis']),'height':state['height'],'native':state['native']})).hex()
        last=previous or (self.packets[-1]['state_commit']['commit']['block_id'] if self.packets else {'hash':'','parts':{'total':0,'hash':''}})
        header={'version':{'block':'11','app':str(state['genesis'].get('protocol_version',1))},
            'chain_id':self.trust.chain_id,'height':str(height+1),'time':stamp,'last_block_id':last,
            'last_commit_hash':sha(b'SYNTHETIC').hex(),'data_hash':merkle_root([]).hex(),
            'validators_hash':self.trust.validators_hash.hex(),'next_validators_hash':self.trust.validators_hash.hex(),
            'consensus_hash':sha(b'params').hex(),'app_hash':state['app_hash'],'last_results_hash':sha(b'results').hex(),
            'evidence_hash':merkle_root([]).hex(),'proposer_address':self.trust.validators[0].address.hex()}
        block={'hash':header_hash(header).hex(),'parts':{'total':1,'hash':sha(b'SYNTHETIC PARTS').hex()}}
        sigs=[{'block_id_flag':2,'validator_address':v.address.hex(),'timestamp':stamp,
            'signature':base64.b64encode(k.sign(vote_sign_bytes(self.trust.chain_id,height+1,0,block,stamp))).decode()}
            for v,k in zip(self.trust.validators,self.keys)]
        packet={'state':state,'state_commit':{'header':header,'commit':{'height':str(height+1),'round':0,'block_id':block,'signatures':sigs}}}
        self.packets.append(copy.deepcopy(packet)); return packet

    def close(self): self.ledger.close()
