#!/usr/bin/env python3
"""Bounded local admission experiment: work counts and timings, not network TPS."""
import argparse,hashlib,json,os,statistics,sys,tempfile,time
from pathlib import Path
from unittest.mock import patch
ROOT=Path(__file__).resolve().parents[1]
sys.path[:0]=[str(ROOT/'src'),str(ROOT/'tests')]
from admission_cache import AdmissionLimits
from block_application import BlockApplication
from native_core import canonical,sign
from test_execution_snapshot import raw
from test_native_budgets import genesis,KEYS


def timed(app,tx,repeats):
    samples=[];answers=[]
    with patch.object(app,'_copy',wraps=app._copy) as copies:
        for _ in range(repeats):
            start=time.perf_counter_ns();answers.append(app.check_tx(tx));samples.append(time.perf_counter_ns()-start)
    assert all(r==answers[0] for r in answers)
    return {'checks':repeats,'execution_forks':copies.call_count,'answer':answers[0],
            'median_ms':statistics.median(samples)/1e6,'elapsed_ms':sum(samples)/1e6,'samples_ns':samples}

def main():
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--output',type=Path,required=True)
    p.add_argument('--history',type=int,default=256);p.add_argument('--repeats',type=int,default=512)
    a=p.parse_args()
    if not 1<=a.history<=1024 or not 1<=a.repeats<=4096:p.error('bounded history/repeats required')
    a.output.mkdir(parents=True,exist_ok=False)
    with tempfile.TemporaryDirectory() as d:
        g=genesis();g['allocations'][0]['units']=1_000_000
        path=Path(d)/'node.sqlite';node=BlockApplication(path)
        node.init_chain(g['chain_id'],g)
        for offset in range(0,a.history,64):
            txs=[raw(g,n,1) for n in range(offset,min(a.history,offset+64))]
            node.finalize_block(txs,node.height+1,hashlib.sha256(str(offset).encode()).digest());node.commit()
        before=node.query('/state')['value'];node.close()
        ref=BlockApplication(path,admission_cache=False)
        valid=raw(g,a.history,1);invalid=raw(g,a.history,1,key=KEYS[1])
        baseline={label:timed(ref,tx,a.repeats) for label,tx in [('valid',valid),('invalid_signature',invalid)]}
        assert ref.query('/state')['value']==before;ref.close()
        cached=BlockApplication(path)
        optimized={label:timed(cached,tx,a.repeats) for label,tx in [('valid',valid),('invalid_signature',invalid)]}
        stats=cached.admission_stats()
        assert cached.query('/state')['value']==before
        for label in baseline:assert baseline[label]['answer']==optimized[label]['answer']
        cached.close()
        # Distinct junk can churn the cache but cannot increase retained payload
        # or entry count beyond configured local ceilings.
        bounded=BlockApplication(path,admission_limits=AdmissionLimits(16,4096,1024))
        with patch.object(bounded,'_copy',wraps=bounded._copy) as copies:
            for i in range(2048):
                result=bounded.check_tx(b'not-json-'+i.to_bytes(4,'big'))
                assert result['code']==1
            junk_forks=copies.call_count
        junk_stats=bounded.admission_stats()
        assert junk_stats['entries']<=16 and junk_stats['retained_payload_bytes']<=4096 and junk_forks==0
        assert bounded.query('/state')['value']==before;bounded.close()
        report={'scope':'local admission, not consensus/network TPS or independent security audit',
                'history_signed_transfers':a.history,'checks_per_case':a.repeats,
                'reference':baseline,'reused':optimized,'cache_stats':stats,
                'distinct_malformed_inputs':2048,'malformed_execution_forks':junk_forks,'bounded_junk_cache':junk_stats,
                'state_unchanged':True,'answers_equal':True,'consensus_executed':False}
    (a.output/'result.json').write_text(json.dumps(report,indent=2)+'\n')
    summary={k:v for k,v in report.items() if k not in ('reference','reused')}
    for label in baseline:
        summary[label]={'reference_forks':baseline[label]['execution_forks'],'reused_forks':optimized[label]['execution_forks'],
            'reference_median_ms':baseline[label]['median_ms'],'reused_median_ms':optimized[label]['median_ms']}
    print(json.dumps(summary,indent=2));return 0
if __name__=='__main__':raise SystemExit(main())
