#!/usr/bin/env python3
"""Paired native startup comparison. Public KAT only; no wallet or node I/O."""
import argparse,hashlib,json,statistics,subprocess,sys,time
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1];sys.path.insert(0,str(ROOT/'src'))
import protocol8_transfer as n
from protocol8_worker import Worker

def main():
    p=argparse.ArgumentParser(description=__doc__)
    for name in ('binary','kat','output'):p.add_argument('--'+name,type=Path,required=True)
    a=p.parse_args();assert not a.output.exists()
    raw=a.kat.read_bytes();n.parse(raw);pin=hashlib.sha256(a.binary.read_bytes()).hexdigest()
    rows=[];expected=None
    for pair in range(3):
        for mode in (('legacy','batch') if pair%2==0 else ('batch','legacy')):
            started=time.monotonic();w=Worker(a.binary,pin,raw,startup_mode=mode);elapsed=time.monotonic()-started
            if expected is None:expected=w.startup
            assert w.startup==expected and list(w.cache)==[raw]
            audit=w.audit();assert audit['call_count']==audit['reaped_count']==(3 if mode=='legacy' else 1) and audit['timeout_count']==0
            assert [r['operation'] for r in audit['calls']]==(['verify','verify','identities'] if mode=='legacy' else ['startup'])
            assert all(r['process_reaped'] is True and r['timed_out'] is False and r['exit_code']==0 and r['start_ticks'] for r in audit['calls'])
            rows.append({'pair':pair,'mode':mode,'elapsed_seconds':elapsed,'startup':w.startup,'audit':audit})
            print('MEASURE',pair,mode,round(elapsed,6),flush=True)
    # Independent ordinary operations on the same measured new binary remain.
    w=Worker(a.binary,pin,raw);network=n.parse(raw)[1];bad=bytearray(raw);bad[-1]^=1
    assert w.verify(raw,network) is True and w.verify(bytes(bad),network) is False
    assert json.loads(w.call('identities',b''))=={k:n.PROFILE[k] for k in ('parameter_sha256','verifying_key_sha256')}
    invalid=[]
    for label,payload in [('empty',b''),('truncated',n.field(network)+raw[:-1]),('trailing',n.field(network)+raw+b'x'),('wrong-network',bytes(32)+raw),('corrupt-kat',n.field(network)+bytes(bad)),('oversized',bytes(4097))]:
        before=w.call_count
        try:
            response=w.call('startup',payload)
            value=json.loads(response)
            assert value.get('valid') is not True or value.get('corrupt') is not False,'malformed startup qualified'
            outcome='closed checks not satisfied'
        except (n.Invalid,n.Unavailable):outcome='refused'
        invalid.append({'case':label,'result':outcome,'native_calls':w.call_count-before})
    try:Worker(a.binary,'00'*32,raw)
    except n.Unavailable:wrong_pin=True
    else:raise AssertionError('wrong binary pin accepted')
    legacy=statistics.median(r['elapsed_seconds'] for r in rows if r['mode']=='legacy');batch=statistics.median(r['elapsed_seconds'] for r in rows if r['mode']=='batch')
    source={name:hashlib.sha256((ROOT/name).read_bytes()).hexdigest() for name in ('src/protocol8_worker.py','scripts/protocol8_worker_exec.py','tools/recipient-consensus-bridge/src/main.rs','tools/recipient-transfer/halo2/src/verifier.rs','scripts/measure_protocol8_startup.py')}
    result={'format':'1soft/protocol8-startup-measurement/v1','status':'passed-native-component-comparison','binary_sha256':pin,'kat_sha256':hashlib.sha256(raw).hexdigest(),'source_file_sha256':source,'paired_runs':rows,'legacy_median_seconds':legacy,'batch_median_seconds':batch,'ratio':legacy/batch,'batch_faster_in_this_sample':batch<legacy,'ordinary_valid_and_corrupt_verification_preserved':True,'ordinary_identity_hashes_preserved':True,'malformed_refusals':invalid,'wrong_binary_pin_refused':wrong_pin,'final_audit':w.audit(),'worker_lifetime_extended':False,'checks_removed':False,'wallet_execution_qualified':False,'production_performance_established':False,'scope':'Three alternated paired startup samples on one trusted host; no wallet/validator/UI execution'}
    assert result['final_audit']['call_count']==result['final_audit']['reaped_count'] and result['final_audit']['timeout_count']==0
    a.output.write_bytes((json.dumps(result,sort_keys=True,indent=2)+'\n').encode());print(json.dumps({k:result[k] for k in ('status','legacy_median_seconds','batch_median_seconds','ratio','batch_faster_in_this_sample')}))
if __name__=='__main__':main()
