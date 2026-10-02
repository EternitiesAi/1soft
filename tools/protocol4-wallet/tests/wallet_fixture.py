"""Actual native P4 ledger and synthetic committee signatures; disposable keys."""
import base64
import copy
from datetime import datetime, timezone, timedelta
import hashlib
from pathlib import Path
import time
from cryptography.hazmat.primitives import serialization as ser
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from block_application import encode,restore
from commit_verifier import header_hash,sha,merkle_root
from native_core import public,address,canonical,sign
from protocol4_application import Protocol4Application
from protocol4_abci_wire import Request
from registry_rules_core import GENESIS_FORMAT
from validator_sets_core import ValidatorSet,canonical_roster
from p4_fixture import sign_header
from p4_evidence import FORMAT,POLICY_FORMAT

PASSWORD=b'fixture passphrase not for funds'

class Chain:
    def __init__(self, root, *, budget=100, balance=1000, invoice_commitments=False, native_asset='DEV'):
        self.root=Path(root); self.keys=[Ed25519PrivateKey.from_private_bytes(bytes([i])*32) for i in range(181,199)]
        self.admins=[Ed25519PrivateKey.from_private_bytes(bytes([i])*32) for i in range(171,175)]
        self.owner=Ed25519PrivateKey.from_private_bytes(b'\x8e'*32)
        self.merchant_key=Ed25519PrivateKey.from_private_bytes(b'\x8f'*32)
        self.raven=Ed25519PrivateKey.from_private_bytes(b'\x90'*32)
        self.atlas=Ed25519PrivateKey.from_private_bytes(b'\x91'*32)
        self.payer=address(public(self.owner)); self.merchant=address(public(self.merchant_key))
        self.roster=canonical_roster([{'public_key':public(k),'power':10} for k in self.keys[:4]])
        self.replacement=canonical_roster([{'public_key':public(k),'power':10} for k in self.keys[10:14]])
        rg={'schema':1,'format':GENESIS_FORMAT,'mode':'development-only','chain_id':'1soft-p4-wallet-fixture',
            'validators':self.roster,'administrators':{'format':'threshold-ed25519-v1',
            'public_keys':sorted(public(k) for k in self.admins),'threshold':3},
            'minimum_delay_blocks':2,'cooldown_blocks':1,'minimum_validators':4,'maximum_power_bps':3333}
        self.g={'chain_id':rg['chain_id'],'asset':native_asset,'fee':2,'protocol_version':4,
            'allocations':[{'public_key':public(self.owner),'units':balance},
                           {'public_key':public(self.merchant_key),'units':0}], 'validator_registry':rg}
        if invoice_commitments:self.g['invoice_commitment_version']=1
        engine={'chain_id':self.g['chain_id'],'initial_height':'1','app_state':self.g,'validators':[
            {'address':v.address.hex().upper(),'pub_key':{'type':'tendermint/PubKeyEd25519',
            'value':base64.b64encode(v.public_key).decode()},'power':str(v.power),'name':'FIXTURE'}
            for v in ValidatorSet.parse(self.roster).validators]}
        self.genesis=encode(engine);self.keymap={public(k):k for k in self.keys};self.headers=[];self.history=[]
        self.start=datetime.fromtimestamp(int(time.time())-30,timezone.utc)
        self.now=int(time.time())*10**9
        self.app=Protocol4Application(':memory:',expected_genesis=self.g)
        self.app.init_chain(self.g['chain_id'],self.g,self.roster)
        ops=[{'type':'budget_create','id':'studio','cap':budget,'expires':500,'recipients':[self.merchant]}]
        for name,key in [('raven',self.raven),('atlas',self.atlas)]:
            ops.append({'type':'grant','id':name,'public_key':public(key),'cap':budget,'expires':500,
                        'recipients':[self.merchant],'budget_id':'studio'})
        self.block([self.owner_wire(op,nonce=i) for i,op in enumerate(ops)])
        self.policy={'schema':1,'format':POLICY_FORMAT,'genesis_sha256':hashlib.sha256(self.genesis).hexdigest(),
            'anchor_height':1,'anchor_hash':header_hash(self.headers[0]['signed_header']['header']).hex(),
            'anchor_time':self.headers[0]['signed_header']['header']['time'], 'trust_period_seconds':3600,
            'max_clock_drift_seconds':5,'expected_block_version':11}
        for name,key in [('owner',self.owner),('raven',self.raven),('atlas',self.atlas)]:
            p=self.root/(name+'.pem'); p.write_bytes(key.private_bytes(ser.Encoding.PEM,
                ser.PrivateFormat.PKCS8,ser.BestAvailableEncryption(PASSWORD)));p.chmod(0o600)
    def close(self): self.app.close()
    def clock(self): return self.now
    def owner_wire(self, op, nonce=None):
        l=restore(self.g,self.app.state['native'])
        try:
            n=l._account(self.payer)['nonce'] if nonce is None else nonce
            return canonical(sign(self.owner,l.body(self.payer,n,op,valid_until=512)))
        finally:l.close()
    def admin(self, *, emitted=None):
        h=self.app.height+1
        b=self.app.rules.body(self.app.state['registry'],{'kind':'schedule',
            'emitted_height':emitted or h+2,'target_validators':self.replacement},valid_from=h,valid_until=30)
        msg=self.app.rules.signing_bytes(b)
        a=sorted([{'public_key':public(k),'signature':k.sign(msg).hex()} for k in self.admins[:3]],key=lambda x:x['public_key'])
        return encode({'body':b,'approvals':a})
    def header(self, height, root, txs, current, following):
        return {'version':{'block':'11','app':'4'},'chain_id':self.g['chain_id'],'height':str(height),
            'time':(self.start+timedelta(seconds=height)).isoformat().replace('+00:00','Z'),
            'last_block_id':self.headers[-1]['signed_header']['commit']['block_id'] if self.headers else {'hash':'','parts':{'total':0,'hash':''}},
            'last_commit_hash':sha(b'fixture-last-commit').hex().upper(),
            'data_hash':merkle_root([sha(t) for t in txs]).hex().upper(),
            'validators_hash':current.hash.upper(),'next_validators_hash':following.hash.upper(),
            'consensus_hash':sha(b'fixture-consensus').hex().upper(),'app_hash':root.upper(),
            'last_results_hash':sha(b'fixture-results').hex().upper(),'evidence_hash':'',
            'proposer_address':current.validators[0].address.hex().upper()}
    def block(self, txs=()):
        h=self.app.height+1;txs=list(txs)
        ahead,_=self.app.rules.transition(self.app.state['registry'],[],h)
        current,following=ValidatorSet.parse(ahead['active_validators']),ValidatorSet.parse(ahead['next_validators'])
        header=self.header(h,self.app.app_hash,txs,current,following)
        signed=sign_header(header,current,self.keymap)
        _,pred=self.app._execute(txs,h)
        req=Request(); q=req.finalize_block;q.height=h;q.hash=header_hash(header);q.txs.extend(txs)
        q.next_validators_hash=bytes.fromhex(pred['next_validators_hash']);last=[]
        if h>1:
            for v in ValidatorSet.parse(self.app.state['registry']['active_validators']).validators:
                vote=q.decided_last_commit.votes.add();vote.validator.address=v.address;vote.validator.power=v.power;vote.block_id_flag=2
                last.append({'address':v.address.hex(),'power':v.power,'block_id_flag':2})
        result,_=self.app.finalize_block(txs,h,header_hash(header),q.next_validators_hash,last,q.SerializeToString(deterministic=True));self.app.commit()
        self.headers.append({'signed_header':signed,'validators':current.json(),'next_validators':following.json()})
        self.history.append({'height':h,'txs':[base64.b64encode(t).decode() for t in txs]})
        return result
    def evidence(self):
        # The signed H+1 already exists before a wallet may act. Commit an empty
        # next block, but return state H and its exact signed anchoring header.
        h=self.app.height
        state=copy.deepcopy({'genesis':self.g,'height':h,'app_hash':self.app.app_hash,**self.app.state})
        self.block([])
        return copy.deepcopy({'schema':1,'format':FORMAT,'state':state,
            'history':self.history[:h],'headers':self.headers[:h+1]})
