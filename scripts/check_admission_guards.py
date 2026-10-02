#!/usr/bin/env python3
"""Selected developer-injected faults; require assertions, never syntax errors."""
import argparse,json,os,shutil,subprocess,sys,tempfile
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
CASES=[
 ('exact_bytes','admission_cache.py','value = self._entries.get(raw)',
  'raw = next(iter(self._entries), raw)\n        value = self._entries.get(raw)',
  'test_admission_cache.AdmissionIntegrationTests.test_invalid_signature_never_inherits_valid_body_acceptance'),
 ('checkpoint_scope','admission_cache.py','if self._point != point:',
  "if self._point is None or self._point[0] != genesis:",
  'test_admission_cache.CacheTests.test_every_checkpoint_dimension_invalidates'),
 ('entry_bound','admission_cache.py','len(self._entries) >= self.limits.max_entries or',
  'False or','test_admission_cache.CacheTests.test_count_ceiling_and_lru'),
 ('before_thread_gate','abci_server.py','or len(self._clients) >= self.max_connections:',
  'or False:','test_node_limits.ServerLimitsTests.test_connection_gate_precedes_thread_construction'),
 ('absolute_frame_deadline','node_io.py','if data and self.deadline is None:',
  'if data:','test_node_limits.FrameIOTests.test_slow_drip_cannot_reset_absolute_deadline'),
 ('proposal_reexecutes','block_application.py','for raw in txs: self._apply(ledger, raw, height)',
  "for raw in txs: require(self.check_tx(raw)['code'] == 0, 'bad transaction')",
  'test_admission_cache.AdmissionIntegrationTests.test_peer_proposal_does_not_reuse_individually_valid_admission'),
]
def main():
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--output',required=True,type=Path)
    a=p.parse_args();a.output.mkdir(parents=True,exist_ok=False);results=[]
    for name,file,old,new,test in CASES:
        with tempfile.TemporaryDirectory(prefix='1soft-admission-guard-') as folder:
            src=Path(folder)/'src';shutil.copytree(ROOT/'src',src,ignore=shutil.ignore_patterns('__pycache__'))
            path=src/file;s=path.read_text()
            if s.count(old)!=1:raise ValueError('mutation anchor missing/ambiguous: '+name)
            path.write_text(s.replace(old,new))
            r=subprocess.run([sys.executable,'-m','unittest',test,'-v'],cwd=folder,
                env=dict(os.environ,PYTHONPATH=str(src)+os.pathsep+str(ROOT/'tests')),
                capture_output=True,text=True,timeout=12)
            log=r.stdout+r.stderr;(a.output/(name+'.log')).write_text(log)
            caught=r.returncode!=0 and 'FAIL:' in log and 'AssertionError' in log and 'ERROR:' not in log
            results.append({'guard':name,'test':test,'returncode':r.returncode,'caught_by_assertion':caught})
    report={'scope':'six bounded developer fault injections; not independent audit','cases':results,
            'all_caught':all(x['caught_by_assertion'] for x in results)}
    (a.output/'result.json').write_text(json.dumps(report,indent=2)+'\n');print(json.dumps(report,indent=2))
    return 0 if report['all_caught'] else 1
if __name__=='__main__':raise SystemExit(main())
