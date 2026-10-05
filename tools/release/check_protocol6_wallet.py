#!/usr/bin/env python3
"""Exact source/log/genesis/worker/signed-inclusion gate for the P6 controller."""
import argparse,json,re,subprocess,sys
from pathlib import Path
ROOT=Path(__file__).resolve().parents[2];sys.path.insert(0,str(ROOT/'src'));sys.path.insert(0,str(ROOT/'scripts'))
from protocol6_treasury import canonical,decode_canonical_json,digest,genesis_document,txid,need
from protocol6_wallet import checked_observation,_resolve
from protocol6_worker import Worker
from run_protocol6_wallet import CHECKS,CLAIMS,SOURCE_NAMES
from run_protocol6_engine import ENGINE_SHA256
KEYS={'format','status','source','checks','claims','inputs','genesis','genesis_sha256','wallet_startup','transport','state_witness','signed_header','certificate','wallet_record','held_obligation','wallet_status','artifacts','processes'}
def load(path):
    raw=Path(path).read_bytes();need(len(raw)<=2*1024*1024 and raw.endswith(b'\n'),'P6 wallet bounded newline report required')
    return decode_canonical_json(raw[:-1],max_bytes=2*1024*1024)
def validate(v,path,worker):
    need(type(v) is dict and set(v)==KEYS and v['format']=='1soft/protocol6-wallet-engine/v1' and v['status']=='qualified-one-host-certified-treasury-wallet','P6 wallet completed closed report required')
    need(type(v['claims']) is dict and set(v['claims'])==set(CLAIMS) and all(v['claims'][k] is expected for k,expected in CLAIMS.items()),'P6 wallet unsupported claim')
    rows=v['checks'];need(type(rows) is list and len(rows)==len(CHECKS) and [r.get('id') for r in rows if type(r) is dict]==list(CHECKS) and all(set(r)=={'id','passed','evidence'} and r['passed'] is True and type(r['evidence']) is dict for r in rows),'P6 wallet checks incomplete or failed')
    s=v['source'];need(type(s) is dict and set(s)=={'commit','tree','clean','status_porcelain','files'} and s['clean'] is True and s['status_porcelain']=='','P6 wallet source not clean')
    for name in ('commit','tree'):need(type(s[name]) is str and re.fullmatch('[0-9a-f]{40}',s[name]) is not None,'P6 wallet Git identity')
    def git(*args):return subprocess.check_output(['git','-C',str(ROOT),*args],stderr=subprocess.DEVNULL)
    need(git('rev-parse',s['commit']+'^{tree}').decode().strip()==s['tree'],'P6 wallet source tree differs')
    required=set(SOURCE_NAMES)
    required.update(p for p in git('ls-tree','-r','--name-only',s['commit']).decode().splitlines() if p.startswith(('src/','scripts/','tools/private-treasury-payment-lab/','tools/shielded-consensus/halo2/')))
    need(type(s['files']) is dict and set(s['files'])==required,'P6 wallet source coverage differs')
    for rel,row in s['files'].items():
        need(type(row) is dict and set(row)=={'bytes','sha256'} and type(row['bytes']) is int and row['bytes']>=0,'P6 wallet source receipt shape')
        raw=(ROOT/rel).read_bytes();need(raw==git('show',s['commit']+':'+rel) and len(raw)==row['bytes'] and digest(raw)==row['sha256'],'P6 wallet runtime source differs')
    g=genesis_document(canonical(v['genesis']));rawg=canonical(g)
    need(v['genesis_sha256']==digest(rawg),'P6 wallet external genesis differs')
    inputs=v['inputs'];need(type(inputs) is dict and set(inputs)=={'engine','worker','fixtures','treasury_genesis'},'P6 wallet input roster differs')
    for name in ('engine','worker'):
        row=inputs[name];need(type(row) is dict and set(row)=={'bytes','sha256'} and type(row['bytes']) is int and row['bytes']>0 and type(row['sha256']) is str and re.fullmatch('[0-9a-f]{64}',row['sha256']) is not None,'P6 wallet binary receipt shape')
    need(inputs['engine']['sha256']==ENGINE_SHA256 and inputs['worker']['sha256']==g['worker_sha256'],'P6 wallet binary pins differ')
    artifact_path=Path(path).with_name(Path(path).name+'.artifacts')
    artifact_rows=v['artifacts'];need(type(artifact_rows) is list,'P6 wallet raw artifacts required')
    names=['app'+str(i)+'.log' for i in range(4)]+['engine'+str(i)+'.log' for i in range(4)]+['fixture-'+n+'.tx' for n in ('a','b','after_a_b','after_b_a','duplicate_request')]+['fixture-genesis.json','bootstrap-genesis.json','wallet-record.json','wallet-held.json']
    actual={}
    for row in artifact_rows:
        need(type(row) is dict and set(row)=={'name','bytes','sha256'} and type(row['name']) is str and row['name'] in names and row['name'] not in actual and type(row['bytes']) is int and 0<=row['bytes']<=8*1024*1024,'P6 wallet artifact roster differs')
        p=artifact_path/row['name'];need(p.is_file() and not p.is_symlink(),'P6 wallet artifact regular file required')
        raw=p.read_bytes();need(len(raw)==row['bytes'] and digest(raw)==row['sha256'],'P6 wallet artifact bytes differ');actual[row['name']]=raw
    need(set(actual)==set(names),'P6 wallet artifacts incomplete')
    need(actual['bootstrap-genesis.json']==rawg,'P6 wallet bootstrap file not pinned before launch')
    need(type(inputs['fixtures']) is dict and set(inputs['fixtures'])=={'a','b','after_a_b','after_b_a','duplicate_request'} and all(digest(actual['fixture-'+n+'.tx'])==sha for n,sha in inputs['fixtures'].items()),'P6 wallet public fixture identity differs')
    need(inputs['treasury_genesis']==digest(actual['fixture-genesis.json']) and json.loads(actual['fixture-genesis.json'])==g['treasury'],'P6 wallet treasury genesis differs')
    a,b=actual['fixture-a.tx'],actual['fixture-b.tx']
    need(g['kat_sha256']==digest(a),'P6 wallet KAT fixture differs')
    expected_startup={'binary_sha256':g['worker_sha256'],'kat_sha256':g['kat_sha256'],'profile_sha256':g['profile_sha256'],'parameter_sha256':'1cb278fe4d9cf5325e5cbc710d863c0deca3e961e1b8f6c8736890c43345c461','verifying_key_sha256':'1cc94283b32da0e1cbc055986ed2a375a33a899957a6421d5def8d7d056f5408','valid_proof_verified':True,'corrupt_proof_refused':True}
    startup=next(r for r in rows if r['id']=='all_four_initialized')['evidence'].get('worker_startup')
    def startup_matches(x):return type(x) is dict and set(x)==set(expected_startup) and all(x[k] is value if type(value) is bool else x[k]==value for k,value in expected_startup.items())
    need(startup_matches(v['wallet_startup']) and type(startup) is list and len(startup)==4 and all(startup_matches(x) for x in startup),'P6 wallet/application startup identity differs')
    need(isinstance(worker,Worker) and worker.sha256==g['worker_sha256'] and worker.kat_sha256==g['kat_sha256'] and worker.verify(a) and worker.verify(b),'P6 wallet actual verifier pins/proofs differ')
    o,certificate=checked_observation(v['state_witness'],v['signed_header'],rawg,worker)
    need(v['certificate']=={k:value for k,value in certificate.items()},'P6 wallet stored certificate differs')
    need(o['witness']['height']>0 and len(o['witness']['state']['receipts'])==1 and o['witness']['state']['receipts'][0]['raw']==a.hex(),'P6 wallet expected sole actual payment absent')
    record=v['wallet_record'];need(type(record) is dict and set(record)=={'format','genesis','txid','raw','raw_sha256','state_height','receipt','witness','signed_header'} and record['format']=='1soft/protocol6-exact-execution-record/v1','P6 wallet execution record shape')
    reason,receipt=_resolve(a,o)
    need(reason=='executed-exact' and record['genesis']==rawg.hex() and record['txid']==txid(a) and record['raw']==a.hex() and record['raw_sha256']==digest(a) and record['receipt']==receipt and record['state_height']==o['witness']['height'] and record['witness']==o['witness'] and record['signed_header']==o['signed_header'],'P6 wallet exact completion differs')
    need(actual['wallet-record.json']==canonical(record),'P6 wallet exported record differs')
    expected_status={'txid':txid(a),'status':'recorded-certified','attempts':1,'hold_reason':None,'certified_height':o['witness']['height']}
    need(v['wallet_status']==expected_status,'P6 wallet exact status/attempt differs')
    held=v['held_obligation'];need(type(held) is dict and set(held)=={'raw','txid','status'} and held['raw']==b.hex() and held['txid']==txid(b),'P6 wallet original conflicting obligation differs')
    need(_resolve(b,o)[0]=='conflict' and held['status']=={'txid':txid(b),'status':'observed-held','attempts':0,'hold_reason':'conflict','certified_height':o['witness']['height']} and actual['wallet-held.json']==canonical(held),'P6 wallet conflicting obligation improperly released')
    t=v['transport'];need(type(t) is dict and set(t)=={'response_discarded','rpc_returned','response_accepted','calls','delivery','test_injection'} and all(t[k] is True for k in ('response_discarded','rpc_returned','response_accepted')) and t['calls']==[digest(a)] and t['delivery']=={'txid':txid(a),'outcome':'unknown','attempts':1} and t['test_injection']=='intentional response discard; actual validator submission','P6 wallet lost-return injection/one attempt differs')
    ps=v['processes'];need(type(ps) is list and len(ps)>=8,'P6 wallet actual engine/application processes required')
    seen=set();roles=set()
    for p in ps:
        need(type(p) is dict and set(p)=={'role','node','pid','start_ticks','executable_sha256','exit_code'} and p['role'] in ('engine','application') and type(p['node']) is int and 0<=p['node']<4 and type(p['pid']) is int and p['pid']>0 and type(p['start_ticks']) is int and p['start_ticks']>0 and type(p['exit_code']) is int,'P6 wallet process receipt differs')
        ident=(p['pid'],p['start_ticks']);need(ident not in seen,'P6 wallet process identity repeated');seen.add(ident);roles.add((p['role'],p['node']))
        wanted=ENGINE_SHA256 if p['role']=='engine' else s['files']['scripts/serve_abci_p6.py']['sha256']
        need(p['executable_sha256']==wanted,'P6 wallet process executable differs')
    need(roles=={(role,i) for role in ('engine','application') for i in range(4)},'P6 wallet four actual validators required')
    return {'qualified':True,'status':v['status'],'check_count':len(CHECKS),'source_commit':s['commit'],'source_tree':s['tree'],'genesis_sha256':digest(rawg),'state_height':o['witness']['height'],'recorded_txid':txid(a),'conflict_held':True,'claim':'one-host finite controller recovery; no freshness/custody/public deployment'}
def main():
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('report',type=Path);p.add_argument('--worker',type=Path,required=True);args=p.parse_args()
    try:
        v=load(args.report);kat=args.report.with_name(args.report.name+'.artifacts')/'fixture-a.tx'
        w=Worker(args.worker,v['genesis']['worker_sha256'],kat.read_bytes());result=validate(v,args.report,w)
    except Exception as exc:print(json.dumps({'qualified':False,'status':'failed','error':str(exc)}));return 1
    print(json.dumps(result,sort_keys=True));return 0
if __name__=='__main__':raise SystemExit(main())
