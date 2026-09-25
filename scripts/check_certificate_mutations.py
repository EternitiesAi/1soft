#!/usr/bin/env python3
"""Bounded adversarial structure perturbations of one SYNTHETIC packet.

Not coverage-guided fuzzing and not a cryptographic/security audit.
The caller supplies expected transaction IDs independently of the mutated packet.
"""
from copy import deepcopy
import json
from pathlib import Path
import sys
ROOT=Path(__file__).resolve().parents[1]
sys.path[:0]=[str(ROOT/'src'),str(ROOT/'tests')]
from certificate_fixture import packet_fixture
from commit_verifier import verify_packet,VerificationError


def main():
    _,trust,_,packet=packet_fixture()
    wanted=[packet['state']['native']['receipts'][0][0]]
    paths=[]
    def walk(o,path=()):
        if type(o) is dict:
            for k,v in o.items():paths.append(path+(k,));walk(v,path+(k,))
        elif type(o) is list:
            for k,v in enumerate(o):paths.append(path+(k,));walk(v,path+(k,))
    walk(packet)
    assessed=rejected=0;unexpected=[];accepted=[]
    for path in paths:
        for replacement in (None,True,[],{},-1,'',0):
            p=deepcopy(packet);parent=p
            for key in path[:-1]:parent=parent[key]
            if type(parent[path[-1]]) is type(replacement) and parent[path[-1]]==replacement:continue
            parent[path[-1]]=replacement;assessed+=1
            try:
                verify_packet(p,trust,expected_txids=wanted)
                accepted.append({'path':path,'replacement':replacement})
            except VerificationError:rejected+=1
            except Exception as exc:unexpected.append({'path':path,'exception':type(exc).__name__,'reason':str(exc)})
    report={'status':'passed' if not unexpected and not accepted else 'failed',
      'scope':'single-field schema/value perturbations of one synthetic packet; not comprehensive fuzzing',
      'assessed':assessed,'rejected':rejected,'unexpected_exceptions':unexpected,'unexpected_acceptances':accepted,
      'consensus_engine_running':False}
    out=ROOT/'evidence/v05/certificate-mutations.json'
    out.parent.mkdir(parents=True,exist_ok=True);out.write_text(json.dumps(report,indent=2)+'\n')
    print(json.dumps(report,indent=2))
    return 0 if report['status']=='passed' else 1


if __name__=='__main__':raise SystemExit(main())
