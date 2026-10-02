#!/usr/bin/env python3
"""Bounded disposable history qualification; synthetic signatures, no engine.

Prepare ONCE in a new private directory, then run baseline and candidate against
the same journals. Each sample is a fresh process with one status warm-up. Fixture
vaults contain publicly known test keys only; never use this tool with real funds.
"""
import argparse
import hashlib
import json
from pathlib import Path
import resource
import sys
import time
from unittest.mock import patch

WORKLOADS = ((8, 1), (24, 8), (48, 16))
FIXED_SECONDS = 1800000000


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument('--root', type=Path, required=True)
    ap.add_argument('--fixtures', type=Path, required=True)
    ap.add_argument('--prepare', action='store_true')
    ap.add_argument('--case', type=int, choices=range(len(WORKLOADS)))
    args = ap.parse_args(); root = args.root.resolve()
    sys.path[:0] = [str(root/p) for p in ('tools/protocol4-wallet/src',
        'tools/protocol4-wallet/tests', 'tools/protocol4-client/src',
        'tools/protocol4-client/tests', 'tools/validator-transition/src', 'src')]
    from block_application import encode
    from native_core import public
    import p4_wallet
    from wallet_fixture import Chain, PASSWORD
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    from cryptography.hazmat.primitives import serialization as ser
    fixtures = args.fixtures.absolute()
    def digest(path): return hashlib.sha256(path.read_bytes()).hexdigest()
    if args.prepare:
        fixtures.mkdir(mode=0o700, parents=False, exist_ok=False)
        cases = []
        for index, (height, decisions) in enumerate(WORKLOADS):
            target = fixtures/str(index); target.mkdir(mode=0o700)
            with patch('wallet_fixture.time.time', return_value=FIXED_SECONDS):
                chain = Chain(target, budget=1000, balance=10000)
            try:
                keys = [Ed25519PrivateKey.from_private_bytes(bytes([40+i])*32) for i in range(decisions)]
                grants = [{'type':'grant', 'id':f'lane{i}', 'public_key':public(key),
                    'cap':1000, 'expires':500, 'recipients':[chain.merchant], 'budget_id':'studio'}
                    for i, key in enumerate(keys)]
                chain.block([chain.owner_wire(op, nonce=i+3) for i, op in enumerate(grants)])
                while chain.app.height < height:
                    chain.block([chain.owner_wire({'type':'transfer','to':chain.merchant,'units':1})])
                evidence = chain.evidence(); chain.now = (FIXED_SECONDS+height)*10**9
                wallet = p4_wallet.P4Wallet(target/'wallet.sqlite', chain.genesis, chain.policy,
                                            create=True, clock=chain.clock)
                try:
                    wallet.sync(evidence, expected_revision=None)
                    ids = []
                    for i, key in enumerate(keys):
                        vault = target/(f'lane{i}.pem')
                        vault.write_bytes(key.private_bytes(ser.Encoding.PEM, ser.PrivateFormat.PKCS8,
                                                            ser.BestAvailableEncryption(PASSWORD)))
                        vault.chmod(0o600); chain.now += 1
                        q = wallet.prepare(payer=chain.payer, recipient=chain.merchant, units=1,
                                           grant_id=f'lane{i}', valid_until=height+20)
                        result = wallet.approve(q['review'], q['confirmation'], vault=vault, password=PASSWORD)
                        ids.append(result['decision_id'])
                    chain.now += 1
                    status = wallet.status()
                    assert status['pending_debit_units'] == str(3*decisions)
                finally: wallet.close()
                data = {'height':height,'decisions':decisions,'now_ns':chain.now,
                    'genesis':json.loads(chain.genesis),'policy':chain.policy,
                    'status_sha256':hashlib.sha256(encode(status)).hexdigest(),
                    'database_sha256':digest(target/'wallet.sqlite'), 'decision_ids':ids,
                    'database_bytes':(target/'wallet.sqlite').stat().st_size,
                    'evidence_bytes':len(encode(evidence)),
                    'receipts':len(evidence['state']['native']['receipts']),
                    'evidence_sha256':hashlib.sha256(encode(evidence)).hexdigest()}
                (target/'case.json').write_bytes(encode(data)); cases.append(data)
            finally: chain.close()
        print(json.dumps({'prepared':True, 'cases':cases}, sort_keys=True)); return
    if args.case is None: ap.error('--case is required when measuring')
    target=fixtures/str(args.case); data=json.loads((target/'case.json').read_bytes())
    before=digest(target/'wallet.sqlite')
    assert before == data['database_sha256']
    count=0; verifier=p4_wallet.verify_evidence
    def counted(*a, **kw):
        nonlocal count
        count += 1
        return verifier(*a, **kw)
    p4_wallet.verify_evidence=counted  # Instrument real work; never fake authority.
    wallet=p4_wallet.P4Wallet(target/'wallet.sqlite',encode(data['genesis']),data['policy'],
                              clock=lambda:data['now_ns'])
    try:
        warm=wallet.status(); count=0
        started=time.perf_counter_ns(); cpu=time.process_time_ns()
        status=wallet.status()
        cpu=time.process_time_ns()-cpu; elapsed=time.perf_counter_ns()-started
        assert hashlib.sha256(encode(warm)).hexdigest() == data['status_sha256']
        assert hashlib.sha256(encode(status)).hexdigest() == data['status_sha256']
        assert status['pending_debit_units'] == str(3*data['decisions'])
    finally: wallet.close()
    after=digest(target/'wallet.sqlite'); assert after == before
    print(json.dumps({'case':args.case,'height':data['height'],'decisions':data['decisions'],
        'full_verifications':count,'elapsed_ns':elapsed,'cpu_ns':cpu,
        'peak_rss_kib':resource.getrusage(resource.RUSAGE_SELF).ru_maxrss,
        'status_sha256':data['status_sha256'],'database_sha256':after,
        'unchanged_database':True,'warmup_status_calls':1,'actual_engine':False},sort_keys=True))


if __name__ == '__main__': main()
