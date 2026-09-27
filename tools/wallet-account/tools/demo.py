#!/usr/bin/env python3
"""Export private-view specimens from real local execution and synthetic headers.

Uses the native project's public test seeds in a temporary directory. No network,
production credential, real funds or extra key files are exported.
"""
import argparse
import json
from pathlib import Path
import sys
ROOT=Path(__file__).resolve().parents[1]

def main():
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--native-root',type=Path,required=True)
    p.add_argument('--output',type=Path,required=True);a=p.parse_args()
    a.output.mkdir(mode=0o700,parents=True,exist_ok=False)
    sys.path[:0]=[str(ROOT/'src'),str(a.native_root/'src'),str(a.native_root/'tests')]
    from account_view import read_account
    from account_report import render_html
    from native_core import canonical
    import test_wallet_obligations as f
    c=f.ObligationTests();c.setUp();steps=[]
    def save(name):
        view=read_account(c.path,c.raw,c.policy,f.IDS[0],observed_at_ns=c.clock)
        (a.output/(name+'.json')).write_text(json.dumps(view,indent=2)+'\n')
        (a.output/(name+'.html')).write_text(render_html(view,specimen=True))
        steps.append({'stage':name,'recorded_balance':view['funds']['recorded_balance_units'],
                      'pending':view['funds']['pending_debit_units'],
                      'budget_recorded_spend':view['budgets'][0]['recorded_spent_units'],
                      'budget_headroom':view['budgets'][0]['uncommitted_allowance_units'],
                      'observation_flags':view['observation']['blockers']})
    try:
        first=c.approve();save('01-raven-pending')
        second=c.approve(3,38);save('02-both-pending')
        c.advance([canonical(first['result'])]);c.sync();save('03-first-recorded')
        c.advance([canonical(second['result'])]);c.sync();save('04-both-recorded')
        assert [s['pending'] for s in steps]==[60,100,40,0]
        assert [s['budget_recorded_spend'] for s in steps]==[0,0,60,100]
        assert steps[-1]['recorded_balance']==892
        report={'scope':'executed local fixture; committee signatures synthetic; no validator process',
                'steps':steps,'real_funds':False,'public_network':False,'private_keys_exported':False}
        (a.output/'scenario.json').write_text(json.dumps(report,indent=2)+'\n');print(json.dumps(report,indent=2))
    finally:c.tearDown()

if __name__=='__main__':main()
