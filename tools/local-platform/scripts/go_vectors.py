#!/usr/bin/env python3
"""Extract four actual Python P4 responses for the pinned upstream Go oracle."""
import argparse
from pathlib import Path
import sys
sys.dont_write_bytecode=True
ROOT=Path(__file__).resolve().parents[3]
sys.path[:0]=[str(ROOT/p) for p in ('src','tests','scripts','tools/validator-transition/src',
 'tools/protocol4-client/src','tools/protocol4-wallet/src','tools/protocol4-delivery/src',
 'tools/protocol4-explorer/src','tools/protocol4-receipts/src','tools/local-platform/src')]
from test_protocol4_application import Protocol4ApplicationTests
from validator_sets_core import ValidatorSet
from local_devnet import private_new
from block_application import encode


def main():
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--output',type=Path,required=True);a=p.parse_args()
    case=Protocol4ApplicationTests();case.setUp()
    try:
        payment,action=case.payment(),case.schedule();initial=case.genesis['validator_registry']['validators'];vectors=[]
        for height in range(1,5):
            result,response,_,_=case.decide(height,(payment,action) if height==1 else ())
            target=case.target if result['validator_updates'] else initial
            vectors.append({'name':f'protocol4-height-{height}','current':initial,'target':target,
                'current_hash':ValidatorSet.parse(initial).hash,'target_hash':ValidatorSet.parse(target).hash,
                'updates':result['validator_updates'],'app_hash':result['app_hash'],
                'tx_results':[{k:item[k] for k in ('code','data','log')} for item in result['tx_results']],
                'wire':response.hex()})
            case.app.commit()
        private_new(a.output,encode(vectors));print(encode({'vectors':len(vectors),'consensus_executed':False}).decode())
    finally:case.tearDown()


if __name__=='__main__':main()
