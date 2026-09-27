#!/usr/bin/env python3
"""Private disposable delivery rehearsal; native execution, synthetic committee.

Uses real loopback HTTP with a socket closed after native execution. Never starts
CometBFT, uses public endpoints or exports private fixture keys. --with-transfer
also exercises the separately delivered prepare/approve adapter when installed.
"""
import argparse
import json
import os
from pathlib import Path
import sys

ROOT=Path(__file__).resolve().parents[1]


def main(argv=None):
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--native-root',type=Path,required=True)
    p.add_argument('--output',type=Path,required=True)
    p.add_argument('--with-transfer',action='store_true')
    a=p.parse_args(argv);native=a.native_root.resolve();account=native/'tools/wallet-account'
    paths=[str(ROOT/'src'),str(ROOT/'tests'),str(account/'src'),str(native/'src'),str(native/'tests')]
    sys.path[:0]=paths;os.environ['PYTHONPATH']=os.pathsep.join(paths)
    from delivery_fixture import Scenario, IDS, PASSWORD
    from decision_delivery import DecisionDelivery
    from account_view import read_account
    from account_report import render_html
    from native_core import canonical
    from commit_verifier import verify_packet, encode
    output=a.output.absolute();output.mkdir(mode=0o700,parents=False,exist_ok=False)
    c=Scenario();steps=[];decisions={};proofs=[]
    def report(stage,delivery=None):
        view=read_account(c.wallet_path,c.raw,c.policy,IDS[0],observed_at_ns=c.clock)
        steps.append({'stage':stage,'balance':view['funds']['recorded_balance_units'],
                      'pending':view['funds']['pending_debit_units'],
                      'recorded_budget_spend':view['budgets'][0]['recorded_spent_units'],
                      'delivery':delivery})
        path=output/f'{len(steps):02d}-{stage}'
        path.with_suffix('.json').write_bytes(encode(view)+b'\n')
        path.with_suffix('.html').write_text(render_html(view,specimen=True))
    def approve(who,units):
        if not a.with_transfer:return c.sign(who=who,units=units)
        from transfer_flow import prepare_transfer,approve_transfer
        role={2:'raven',3:'atlas'}[who]
        kw={'account':IDS[0],'grant_id':role,'clock':lambda:c.clock}
        draft=prepare_transfer(c.wallet_path,c.raw,c.policy,recipient=IDS[1],units=units,valid_until=100,**kw)
        return approve_transfer(c.wallet_path,c.raw,c.policy,draft,confirmation=draft['review']['confirmation'],
                                vault=c.root/f'key{who}.pem',password=PASSWORD,**kw)
    try:
        report('initial')
        raven=approve(2,58);report('raven-signed')
        try:approve(3,39)
        except ValueError:overcommit_refused=True
        else:raise AssertionError('39+2 must be refused after Raven reserves 60')
        atlas=approve(3,38);report('both-signed')
        # The entire delivery/reconciliation flow works after private test keys go away.
        for keyfile in c.root.glob('*.pem'):keyfile.unlink()
        with c.rpc() as url:
            for label,result in [('raven',raven),('atlas',atlas)]:
                kw={'account':IDS[0],'grant_id':label}
                with DecisionDelivery(c.wallet_path,c.delivery_path,c.raw,c.policy,url,create=label=='raven',clock=lambda:c.clock) as d:
                    queued=d.queue(result['decision_id'],**kw)
                    sent=d.send(result['decision_id'],queued['delivery_confirmation'],**kw)
                    assert sent['transport_status']=='unresolved'
                report(label+'-response-lost',sent)
                # New session recovers the SAME source decision, then reads only.
                with DecisionDelivery(c.wallet_path,c.delivery_path,c.raw,c.policy,url,clock=lambda:c.clock) as d:
                    found=d.refresh(result['decision_id'],**kw)
                    assert found['exact_transport_receipt_verified']
                    report(label+'-receipt-collected',found)
                    raw=d.export_receipt(result['decision_id'],**kw)
                    cert=verify_packet(json.loads(raw),c.trust,expected_txids=[found['native_txid']])
                    assert cert['status']=='verified'
                    (output/f'{label}-receipt.json').write_bytes(raw+b'\n');proofs.append(found['native_txid'])
                    synced=d.reconcile(result['decision_id'],continuation=c.continuation(),**kw)
                    assert synced['wallet_obligation_status']=='recorded'
                    report(label+'-wallet-reconciled',synced)
        assert c.seen==[canonical(raven['result']),canonical(atlas['result'])]
        assert c.holds()==0 and steps[-1]['balance']==892 and steps[-1]['recorded_budget_spend']==100
        summary={'scope':'disposable local HTTP/native application; synthetic static committee',
            'uses_transfer_adapter':a.with_transfer,'steps':steps,'overcommit_refused_before_unlock':overcommit_refused,
            'submissions':len(c.seen),'request_methods':[r['method'] for r in c.requests],
            'verified_receipts':proofs,'new_validator_execution':False,'real_funds':False,
            'private_keys_exported':False,'same_exact_signed_bytes':True}
        (output/'scenario.json').write_text(json.dumps(summary,indent=2)+'\n')
        print(json.dumps(summary,indent=2));return 0
    finally:c.close()


if __name__=='__main__':raise SystemExit(main())
