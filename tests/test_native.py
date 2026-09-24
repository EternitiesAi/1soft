import copy
import json
import os
import subprocess
import sys
import tempfile
import threading
import unittest
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from native_core import NativeLedger, Reject, MAX_UNITS, FEE_ACCOUNT, address, public, sign, parse_wire

# Publicly known test seeds. NEVER fund or deploy these keys.
KEYS = [Ed25519PrivateKey.from_private_bytes(bytes([i])*32) for i in range(1,5)]
ADDRESSES = [address(public(k)) for k in KEYS]
def genesis():
    return {"chain_id":"eternities-local-1", "asset":"DEV", "fee":2,
            "allocations":[{"public_key":public(k),"units":u} for k,u in zip(KEYS[:3],[1000,0,0])]}

class NativeTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(); self.path=Path(self.tmp.name)/'ledger.sqlite'
        self.ledger=NativeLedger(self.path,genesis()); self.a,self.b,self.c=ADDRESSES[:3]
    def tearDown(self):
        self.ledger.close(); self.tmp.cleanup()
    def transfer(self,units=10,nonce=0,to=None,**kw):
        return self.ledger.body(self.a,nonce,{"type":"transfer","to":to or self.b,"units":units},**kw)
    def apply(self,body,key=KEYS[0],height=1):
        return self.ledger.apply(sign(key,body),height=height)
    def denied(self,body,key=KEYS[0],height=1):
        before=self.ledger.state_hash()
        with self.assertRaises(Reject): self.apply(body,key,height)
        self.assertEqual(self.ledger.state_hash(),before)
        self.assertTrue(self.ledger.verify_receipts())
    def grant(self,cap=100,expires=50,recipients=None):
        return self.apply(self.ledger.body(self.a,0,{"type":"grant","id":"agent-1","public_key":public(KEYS[3]),"cap":cap,"expires":expires,"recipients":recipients if recipients is not None else [self.b]}))
    def test_transfer_and_fee_conserve_supply(self):
        self.apply(self.transfer())
        self.assertEqual((self.ledger.balance(self.a),self.ledger.balance(self.b),self.ledger.balance(FEE_ACCOUNT)),(988,10,2))
        self.assertTrue(self.ledger.verify_receipts())
    def test_deterministic_replay_on_independent_database(self):
        other=NativeLedger(Path(self.tmp.name)/'other.sqlite',genesis())
        try:
            for n in range(25):
                env=sign(KEYS[0],self.transfer(units=n+1,nonce=n))
                self.assertEqual(self.ledger.apply(env,height=n+1),other.apply(env,height=n+1))
            self.assertEqual(self.ledger.state_hash(),other.state_hash())
        finally: other.close()
    def test_accepted_retry_idempotent_even_after_expiry(self):
        body=self.transfer(valid_until=1); first=self.apply(body)
        self.assertEqual(first,self.apply(body,height=100))
        self.assertEqual(self.ledger.balance(self.b),10)
    def test_retry_does_not_bypass_signature(self):
        body=self.transfer(); self.apply(body); self.denied(body,key=KEYS[1])
    def test_wrong_signature(self): self.denied(self.transfer(),KEYS[1])
    def test_mutated_signed_payload(self):
        env=sign(KEYS[0],self.transfer()); env['body']['op']['units']=11
        with self.assertRaises(Reject): self.ledger.apply(env,height=1)
        self.assertEqual(self.ledger.balance(self.a),1000)
    def test_wrong_chain(self):
        body=self.transfer(); body['chain_id']='other-chain'; self.denied(body)
    def test_wrong_genesis(self):
        body=self.transfer(); body['genesis_hash']='f'*64; self.denied(body)
    def test_nonce_reuse_different_payment(self):
        self.apply(self.transfer()); self.denied(self.transfer(to=self.c))
    def test_expired_transaction(self): self.denied(self.transfer(valid_until=0))
    def test_height_regression(self):
        self.apply(self.transfer(),height=3); self.denied(self.transfer(nonce=1),height=2)
    def test_fee_cap(self): self.denied(self.transfer(max_fee=1))
    def test_invalid_quantities(self):
        for value in [True,False,1.5,0,-1,'10',MAX_UNITS+1]:
            with self.subTest(value=value): self.denied(self.transfer(units=value))
    def test_invalid_nonce_and_version(self):
        for field,value in [('nonce',True),('nonce',-1),('version',True),('version',2)]:
            with self.subTest(field=field,value=value):
                body=self.transfer(); body[field]=value; self.denied(body)
    def test_unknown_operation_and_fields(self):
        for op in [{'type':'mint','units':1000},{'type':'transfer','to':self.b,'units':1,'memo':'extra'}]:
            self.denied(self.ledger.body(self.a,0,op))
    def test_insufficient_funds_includes_fee(self): self.denied(self.transfer(units=999))
    def test_unknown_self_and_system_recipients(self):
        for recipient in ['unknown',self.a,FEE_ACCOUNT]: self.denied(self.transfer(to=recipient))
    def test_delegate_transfer(self):
        self.grant(); self.apply(self.transfer(grant_id='agent-1'),KEYS[3])
        self.assertEqual(self.ledger.balance(self.a),986)
    def test_delegate_cap_includes_fee(self):
        self.grant(cap=12); self.apply(self.transfer(grant_id='agent-1'),KEYS[3])
        self.denied(self.transfer(units=1,nonce=1,grant_id='agent-1'),KEYS[3])
    def test_delegate_recipient_restriction(self):
        self.grant(); self.denied(self.transfer(to=self.c,grant_id='agent-1'),KEYS[3])
    def test_delegate_nonce_is_shared_by_copied_worker(self):
        self.grant(); self.apply(self.transfer(grant_id='agent-1'),KEYS[3])
        self.denied(self.transfer(units=11,grant_id='agent-1'),KEYS[3])
    def test_delegate_cannot_grant_or_fence(self):
        self.grant()
        for op in [{'type':'fence'},{'type':'grant'}]:
            self.denied(self.ledger.body(self.a,0,op,grant_id='agent-1'),KEYS[3])
    def test_delegate_expiry(self):
        self.grant(expires=2); self.denied(self.transfer(grant_id='agent-1'),KEYS[3],height=3)
    def test_revoke_rejects_new_spend(self):
        self.grant(); self.apply(self.ledger.body(self.a,1,{'type':'revoke','id':'agent-1'}))
        self.denied(self.transfer(grant_id='agent-1'),KEYS[3])
    def test_epoch_fences_existing_grants(self):
        self.grant(); self.apply(self.ledger.body(self.a,1,{'type':'fence'}))
        self.denied(self.transfer(grant_id='agent-1'),KEYS[3])
        self.apply(self.transfer(nonce=2))
    def test_empty_allowlist_rejected(self):
        before=self.ledger.state_hash()
        with self.assertRaises(Reject): self.grant(recipients=[])
        self.assertEqual(before,self.ledger.state_hash())
    def test_duplicate_grant_id(self):
        self.grant()
        body=self.ledger.body(self.a,1,{'type':'grant','id':'agent-1','public_key':public(KEYS[3]),'cap':100,'expires':50,'recipients':[self.b]})
        self.denied(body)
    def test_admin_mutation_rolls_back_on_unpaid_fee(self):
        self.apply(self.transfer(units=997)) # only one unit remains
        body=self.ledger.body(self.a,1,{'type':'fence'})
        self.denied(body)
        self.assertEqual(self.ledger._account(self.a)['epoch'],0)
    def test_restart_preserves_state_and_receipts(self):
        self.grant(); self.apply(self.transfer(grant_id='agent-1'),KEYS[3]); expected=self.ledger.state_hash()
        self.ledger.close(); self.ledger=NativeLedger(self.path,genesis())
        self.assertEqual(expected,self.ledger.state_hash()); self.assertTrue(self.ledger.verify_receipts())
    def test_reopen_with_wrong_genesis(self):
        g=genesis(); g['fee']=3
        with self.assertRaises(Reject): NativeLedger(self.path,g)
    def test_corruption_detected_not_claimed_tamperproof(self):
        self.apply(self.transfer())
        self.ledger.db.execute("UPDATE receipts SET hash='bad'")
        with self.assertRaises(Reject): self.ledger.verify_receipts()
    def test_wire_duplicate_keys_and_nonfinite(self):
        for raw in [b'{"body":{},"body":{}}',b'{"x":NaN}',b'[]',b'{' + b' '*20000+b'}']:
            with self.assertRaises(Reject): parse_wire(raw)
    def test_wire_valid_roundtrip(self):
        env=sign(KEYS[0],self.transfer()); parsed=parse_wire(json.dumps(env).encode())
        self.ledger.apply(parsed,height=1); self.assertEqual(self.ledger.balance(self.b),10)
    def test_two_writers_cannot_double_spend_same_nonce(self):
        barrier=threading.Barrier(2)
        def worker(to):
            ledger=NativeLedger(self.path,genesis())
            try:
                env=sign(KEYS[0],ledger.body(self.a,0,{'type':'transfer','to':to,'units':700}))
                barrier.wait(timeout=5)
                try: ledger.apply(env,height=1); return 'accepted'
                except Reject: return 'rejected'
            finally: ledger.close()
        with ThreadPoolExecutor(max_workers=2) as pool: results=list(pool.map(worker,[self.b,self.c]))
        self.assertEqual(sorted(results),['accepted','rejected']); self.assertEqual(self.ledger.balance(self.a),298)
        self.assertTrue(self.ledger.verify_receipts())
    def test_committed_transfer_survives_abrupt_process_exit(self):
        path=Path(self.tmp.name)/'abrupt.sqlite'
        code='''import json,os,sys
from native_core import *
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
k=Ed25519PrivateKey.from_private_bytes(bytes([1])*32)
g=json.loads(sys.argv[2]); db=NativeLedger(sys.argv[1],g)
a=address(g['allocations'][0]['public_key']); b=address(g['allocations'][1]['public_key'])
db.apply(sign(k,db.body(a,0,{'type':'transfer','to':b,'units':20})),height=1)
os._exit(0)
'''
        subprocess.run([sys.executable,'-c',code,str(path),json.dumps(genesis())],check=True,timeout=10)
        ledger=NativeLedger(path,genesis())
        try: self.assertEqual(ledger.balance(self.b),20); self.assertTrue(ledger.verify_receipts())
        finally: ledger.close()

if __name__=='__main__': unittest.main()
