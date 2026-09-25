#!/usr/bin/env python3
"""CLI receipts for v2: synthetic validator signatures, never network evidence."""
import json
from pathlib import Path
import subprocess
import sys
ROOT=Path(__file__).resolve().parents[1]
sys.path[:0]=[str(ROOT/'src'),str(ROOT/'tests')]
from commit_verifier import encode, sha
from block_application import transaction_id
from test_lifecycle_signatures import lifecycle_fixture


def main():
    out=ROOT/'evidence/v05/lifecycle-certificates';out.mkdir(parents=True,exist_ok=True)
    genesis,trust,_,packet,raws=lifecycle_fixture()
    genesis_file=out/'SYNTHETIC-lifecycle-genesis.json';packet_file=out/'SYNTHETIC-lifecycle-packet.json'
    genesis_file.write_bytes(encode(genesis));packet_file.write_bytes(encode(packet))
    pin=sha(encode(genesis)).hex();ids=[transaction_id(raw) for raw in raws]
    report={'schema':1,'scope':'synthetic signatures and local application execution, NOT live consensus',
            'consensus_engine_running':False,'genesis_sha256':pin,'expected_txids':ids,'checks':[]}
    def run(name,expected,txids,trust_pin=pin,extra=(),path=packet_file):
        command=[sys.executable,str(ROOT/'scripts/verify_certificate.py'),'--genesis',str(genesis_file),
            '--genesis-sha256',trust_pin,'--packet',str(path)]
        for txid in txids:command+=['--expect-txid',txid]
        result=subprocess.run(command+list(extra),capture_output=True,text=True,timeout=15)
        parsed=json.loads(result.stdout) if result.stdout else None
        passed=result.returncode==expected
        if expected==0:
            passed=passed and parsed['status']=='verified' and all(
                item['incoming_key_consent_verified'] for item in parsed['transactions'])
        report['checks'].append({'name':name,'passed':passed,'exit_code':result.returncode,
                                 'result':parsed,'stderr':result.stderr})
    run('both onboarding and rotation independently verified',0,ids)
    run('different expected rotation rejected',2,[ids[0],'00'*32])
    run('wrong trusted genesis rejected',2,ids,trust_pin='00'*32)
    run('wrong state height rejected',2,ids,extra=['--expected-state-height','2'])
    run('caller must supply transaction intention',2,[])
    omitted=json.loads(encode(packet));omitted['transactions'].pop()
    omitted_file=out/'SYNTHETIC-omitted-rotation.json';omitted_file.write_bytes(encode(omitted))
    run('provider cannot omit requested rotation',2,ids,path=omitted_file)
    report['status']='passed' if all(c['passed'] for c in report['checks']) else 'failed'
    (out/'checks.json').write_text(json.dumps(report,indent=2)+'\n')
    print(json.dumps({'status':report['status'],'checks':len(report['checks']),
                      'consensus_engine_running':False}))
    return 0 if report['status']=='passed' else 1
if __name__=='__main__':raise SystemExit(main())
