#!/usr/bin/env python3
"""Write SYNTHETIC certificate evidence and exercise the standalone verifier CLI.

Four fixture keys sign locally; NO consensus engine or validator voting occurs.
This script cannot turn the real-network gate green.
"""
import base64
from copy import deepcopy
import json
import os
from pathlib import Path
import subprocess
import sys
ROOT=Path(__file__).resolve().parents[1]
sys.path[:0]=[str(ROOT/'src'),str(ROOT/'tests')]
from commit_verifier import encode,sha
from certificate_fixture import packet_fixture


def main():
    out=ROOT/'evidence/v05/certificates';out.mkdir(parents=True,exist_ok=True)
    genesis,trust,_,packet=packet_fixture()
    (out/'SYNTHETIC-genesis.json').write_bytes(encode(genesis))
    (out/'SYNTHETIC-packet.json').write_bytes(encode(packet))
    pin=sha(encode(genesis)).hex()
    report={'schema':1,'evidence_type':'locally signed synthetic certificate, NOT engine execution',
            'consensus_engine_running':False,'genesis_sha256':pin,'checks':[]}
    def run(name,path,pin_,expected_exit,extra=()):
        result=subprocess.run([sys.executable,str(ROOT/'scripts/verify_certificate.py'),
            '--genesis',str(out/'SYNTHETIC-genesis.json'),'--genesis-sha256',pin_,
            '--packet',str(path),'--expect-txid',packet['state']['native']['receipts'][0][0],*extra],capture_output=True,text=True,timeout=15)
        observed=json.loads(result.stdout)
        report['checks'].append({'name':name,'passed':result.returncode==expected_exit,
                                  'exit':result.returncode,'result':observed})
    run('valid fixture verifies',out/'SYNTHETIC-packet.json',pin,0,('--expected-state-height','1'))
    run('wrong trust anchor rejected',out/'SYNTHETIC-packet.json','00'*32,2)
    run('wrong expected height rejected',out/'SYNTHETIC-packet.json',pin,2,('--expected-state-height','2'))
    bad=deepcopy(packet);bad['state_commit']['commit']['signatures'][3]['signature']=base64.b64encode(bytes(64)).decode()
    (out/'SYNTHETIC-forged-tail.json').write_bytes(encode(bad))
    run('bad signature after quorum rejected',out/'SYNTHETIC-forged-tail.json',pin,2)
    (out/'SYNTHETIC-duplicate-keys.json').write_text('{"schema":1,"schema":1}')
    run('duplicate JSON keys rejected',out/'SYNTHETIC-duplicate-keys.json',pin,2)
    omitted=deepcopy(packet);omitted['transactions']=[]
    (out/'SYNTHETIC-omitted-payment.json').write_bytes(encode(omitted))
    run('omitted requested payment rejected',out/'SYNTHETIC-omitted-payment.json',pin,2)
    report['status']='passed' if all(c['passed'] for c in report['checks']) else 'failed'
    (out/'checks.json').write_text(json.dumps(report,indent=2)+'\n')
    print(json.dumps(report,indent=2))
    return 0 if report['status']=='passed' else 1


if __name__=='__main__':raise SystemExit(main())
