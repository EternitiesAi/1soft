#!/usr/bin/env python3
"""Execute a local fixture; export evidence, never keys or a live-money balance."""
from __future__ import annotations
import json
import sys
import tempfile
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'src'))
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from native_core import NativeLedger, Reject, address, public, sign
from settlement_journal import SettlementJournal

def run():
    # Known test keys: reproducibility only. These are not wallet credentials.
    owner,merchant,agent=[Ed25519PrivateKey.from_private_bytes(bytes([n])*32) for n in [21,22,23]]
    oa,ma=address(public(owner)),address(public(merchant))
    g={'chain_id':'eternities-local-1','asset':'DEV','fee':100,
       'allocations':[{'public_key':public(owner),'units':100_000_000},{'public_key':public(merchant),'units':0}]}
    with tempfile.TemporaryDirectory() as folder:
        native=NativeLedger(Path(folder)/'native.sqlite',g)
        replay=NativeLedger(Path(folder)/'replay.sqlite',g)
        receipts=[]
        for key,body in [
          (owner,native.body(oa,0,{'type':'grant','id':'raven-dev','public_key':public(agent),'cap':20_000_100,'expires':100,'recipients':[ma]})),
          (agent,native.body(oa,0,{'type':'transfer','to':ma,'units':12_500_000},grant_id='raven-dev')),
          (owner,native.body(oa,1,{'type':'fence'}))]:
            envelope=sign(key,body)
            left=native.apply(envelope,height=len(receipts)+1)
            right=replay.apply(envelope,height=len(receipts)+1)
            assert left==right
            receipts.append(left)
        denied=None
        try:
            native.apply(sign(agent,native.body(oa,1,{'type':'transfer','to':ma,'units':1_000_000},grant_id='raven-dev')),height=4)
        except Reject as exc: denied=str(exc)
        assert denied=='inactive grant'
        journal=SettlementJournal(Path(folder)/'payments.sqlite')
        journal.register_asset('demo:usd',2)
        journal.fixture_credit('fixture-funding','human','demo:usd',125000)
        journal.reserve('render-job',owner='human',asset='demo:usd',units=2500,rail='card',beneficiary='render-provider',provider='fixture-processor')
        journal.dispatch('render-job'); journal.unknown('render-job')
        result={'status':'LOCAL_FIXTURE_NO_REAL_FUNDS','native':{
            'asset':'DEV','decimals':6,'genesis_supply_units':100000000,
            'owner_balance_units':native.balance(oa),'merchant_balance_units':native.balance(ma),
            'genesis_hash':native.genesis_hash,'state_hash':native.state_hash(),
            'receipts':receipts,'fenced_attempt_result':denied,
            'independent_replay_equal':native.state_hash()==replay.state_hash(),
            'receipt_verification':native.verify_receipts()},
            'settlement':{'asset':'demo:usd','decimals':2,
              'available_units':journal.balance('available:human','demo:usd'),
              'held_units':journal.balance('held:render-job','demo:usd'),
              'intent':journal.intent('render-job'),'balanced_journal':journal.verify()},
            'integration_boundary':'Two separate local databases. No chain/card bridge, FX, signer service or authenticated payment adapter.'}
        native.close(); replay.close(); journal.close()
        return result

if __name__=='__main__':
    target=Path(sys.argv[1]) if len(sys.argv)>1 else Path(__file__).resolve().parents[1]/'evidence/demo.json'
    target.parent.mkdir(parents=True,exist_ok=True)
    target.write_text(json.dumps(run(),indent=2)+'\n')
    print(f'Wrote local-only evidence: {target}')
