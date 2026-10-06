#!/usr/bin/env python3
"""Strict source-bound P8 four-validator receipt and native full-state replay."""
import argparse,json,re,subprocess,sys
from pathlib import Path
ROOT=Path(__file__).resolve().parents[2];sys.path.insert(0,str(ROOT/'src'));sys.path.insert(0,str(ROOT/'scripts'))
import protocol8_transfer as native
from protocol8_consensus import canonical,digest,need,genesis_document,bootstrap_digest
from protocol8_worker import Worker
from protocol8_certificate import verify_state
from run_protocol8_engine import CHECKS,CLAIMS,SOURCE_NAMES,SOURCE_PREFIXES,ENGINE_SHA256
FIXTURES={'first','second','competing','duplicate-intent','wrong-fee'}
def load(path):
    raw=Path(path).read_bytes();need(len(raw)<=4*1024**2 and raw.endswith(b'\n'),'bounded P8 report')
    value=json.loads(raw);need(canonical(value)+b'\n'==raw,'canonical P8 report');return value
def envelope(v):
    expected={'format','status','source','claims','checks','inputs','native_processes','worker_audits',
        'genesis','genesis_sha256','bootstrap_sha256','state_witness','signed_header','certificate','artifacts','processes'}
    need(type(v)is dict and set(v)==expected and v['format']=='1soft/protocol8-recipient-engine/v1' and
         v['status']=='qualified-one-host-recipient-consensus','closed completed P8 receipt')
    need(type(v['claims'])is dict and set(v['claims'])==set(CLAIMS) and all(v['claims'][k] is b for k,b in CLAIMS.items()),'unsupported P8 claim')
    rows=v['checks'];need(type(rows)is list and len(rows)==len(CHECKS) and [r.get('id') for r in rows if type(r)is dict]==list(CHECKS) and
        all(type(r)is dict and set(r)=={'id','passed','evidence'} and r['passed'] is True and type(r['evidence'])is dict for r in rows),'P8 check membership or result')
    return {r['id']:r['evidence'] for r in rows}
def validate(v,path,binary):
    checks=envelope(v);s=v['source'];need(type(s)is dict and set(s)=={'commit','tree','clean','files'} and s['clean'] is True,'clean executed P8 source')
    def git(*args):return subprocess.check_output(['git','-C',str(ROOT),*args],stderr=subprocess.DEVNULL)
    for k in ('commit','tree'):need(type(s[k])is str and re.fullmatch('[0-9a-f]{40}',s[k])is not None,'P8 Git identity')
    need(git('rev-parse',s['commit']+'^{tree}').decode().strip()==s['tree'],'P8 source tree differs')
    paths=set(SOURCE_NAMES)|{p for p in git('ls-tree','-r','--name-only',s['commit']).decode().splitlines() if p.startswith(SOURCE_PREFIXES)}
    need(type(s['files'])is dict and set(s['files'])==paths,'P8 source coverage differs')
    for rel,row in s['files'].items():
        need(type(row)is dict and set(row)=={'bytes','sha256'} and type(row['bytes'])is int and row['bytes']>=0,'P8 source receipt')
        raw=(ROOT/rel).read_bytes();need(raw==git('show',s['commit']+':'+rel) and len(raw)==row['bytes'] and digest(raw)==row['sha256'],'P8 current/executed/committed source differs')
    inputs=v['inputs'];need(type(inputs)is dict and set(inputs)=={'engine','worker','fixture','prover','verifier_feature_mode','fixture_feature_mode','fixtures'} and
        inputs['verifier_feature_mode']=='no-default-features' and inputs['fixture_feature_mode']=='fixtures/prover','P8 feature/input roster')
    for name in ('engine','worker','fixture','prover'):
        row=inputs[name];need(type(row)is dict and set(row)=={'bytes','sha256'} and type(row['bytes'])is int and 0<row['bytes']<=64*1024**2 and
            type(row['sha256'])is str and re.fullmatch('[0-9a-f]{64}',row['sha256'])is not None,'P8 binary receipt')
    need(inputs['engine']['sha256']==ENGINE_SHA256,'P8 actual pinned engine differs')
    need(type(inputs['fixtures'])is dict and set(inputs['fixtures'])==FIXTURES,'P8 fixture membership')
    names={f'app{i}.log' for i in range(4)}|{f'engine{i}.log' for i in range(4)}|{'fixture-'+n+'.tx' for n in FIXTURES}|{'fixture-genesis.json'}
    rows=v['artifacts'];need(type(rows)is list and len(rows)==len(names) and {r.get('name') for r in rows if type(r)is dict}==names,'P8 artifact membership')
    directory=Path(path).with_name(Path(path).name+'.artifacts');need({p.name for p in directory.iterdir()}==names,'P8 actual artifact membership differs')
    artifacts={}
    for row in rows:
        need(type(row)is dict and set(row)=={'name','bytes','sha256'} and type(row['bytes'])is int and 0<=row['bytes']<=8*1024**2,'P8 artifact receipt')
        p=directory/row['name'];need(p.is_file() and not p.is_symlink(),'regular P8 artifact')
        raw=p.read_bytes();need(len(raw)==row['bytes'] and digest(raw)==row['sha256'],'P8 actual artifact differs');artifacts[row['name']]=raw
    g=v['genesis'];rawg=canonical(g)
    need(rawg==artifacts['fixture-genesis.json'] and digest(rawg)==v['genesis_sha256'] and bootstrap_digest(g)==v['bootstrap_sha256'],'P8 complete/acyclic genesis differs')
    need(inputs['worker']['sha256']==g['worker_sha256'] and Path(binary).stat().st_size==inputs['worker']['bytes'],'P8 worker receipt differs')
    w=Worker(binary,g['worker_sha256'],artifacts['fixture-first.tx']);genesis_document(rawg,w)
    txs={name:artifacts['fixture-'+name+'.tx'] for name in FIXTURES}
    for name,raw in txs.items():need(digest(raw)==inputs['fixtures'][name] and native.parse(raw)[1]==g['network'] and w.verify(raw,g['network']),'P8 actual proof/domain fails')
    need(checks['fresh_native_network_proofs']=={'proof_count':5,'worker_startup':w.startup,'domain':g['network']} and
        checks['all_four_initialized']=={'worker_startup':[w.startup]*4},'P8 four measured startup identities differ')
    first=native.parse(txs['first']);second=native.parse(txs['second']);competing=native.parse(txs['competing']);duplicate=native.parse(txs['duplicate-intent'])
    need(competing[5]==first[5] and competing[6]!=first[6] and competing[10]!=first[10] and second[5]!=first[5] and
        duplicate[5]==second[5] and duplicate[6]==first[6] and native.integer(native.parse(txs['wrong-fee'])[9])==2,'P8 valid attack fixtures differ')
    need(checks['ordered_dependent_proposals']=={'probes':[{'node':i,'passed':True} for i in range(4)]},'P8 ordered four-node probe evidence differs')
    need(checks['certificate_tampers_refused']=={'mutations':['fees','history','genesis','height','app_hash','header-apphash','header-height','signature']},'P8 certificate tamper evidence differs')
    witness=v['state_witness'];cert=verify_state(witness,v['signed_header'],rawg,w);need(cert==v['certificate'],'P8 replayed certificate differs')
    expected=[native.txid(txs['first']),native.txid(txs['second'])];ledger=witness['state']['ledger']
    need([r['txid'] for r in ledger['receipts']]==expected and ledger['fees']==2 and len(ledger['notes'])==5 and
        ledger['notes'][1]['commitment']==first[10] and ledger['notes'][3]['commitment']==second[10] and
        checks['recipient_respend_committed']=={'txids':expected},'P8 certified receive/respend differs')
    seen=set();roles=set()
    for row in v['processes']:
        need(type(row)is dict and set(row)=={'role','node','pid','start_ticks','executable_sha256','exit_code'} and row['role'] in ('engine','application') and
            type(row['node'])is int and row['node'] in range(4) and type(row['pid'])is int and row['pid']>0 and
            type(row['start_ticks'])is int and row['start_ticks']>0 and type(row['exit_code'])is int and row['exit_code'] in (0,-15),'P8 owned process lifecycle')
        ident=(row['pid'],row['start_ticks']);need(ident not in seen,'duplicate P8 process identity');seen.add(ident);roles.add((row['role'],row['node']))
        wanted=ENGINE_SHA256 if row['role']=='engine' else s['files']['scripts/serve_abci_p8.py']['sha256']
        need(row['executable_sha256']==wanted,'P8 process source binding')
    need(roles=={(r,i) for r in ('engine','application') for i in range(4)} and len(v['processes'])>=17,'P8 four roles/restarts missing')
    rows=v['native_processes'];need(type(rows)is list and len(rows)==11,'P8 five actual proving runs and six fixture calls required')
    for row in rows:
        need(row['binary'] in ('fixture','prover') and row['binary_sha256']==inputs[row['binary']]['sha256'] and row['exit_code']==0 and
            row['process_reaped'] is True and row['timed_out'] is False and row['start_ticks'] is not None,'P8 native process receipt')
    need(sum(r['binary']=='prover' for r in rows)==5,'P8 actual prover membership')
    audits=v['worker_audits'];need(type(audits)is list and len(audits)==7 and
        {(r['node'],r['phase']) for r in audits}=={(3,'before-restart'),('host','fresh'),('host','bootstrap')}|{(i,'final') for i in range(4)},'P8 worker audit roster')
    for row in audits:
        need(type(row['call_count'])is int and row['call_count']==row['reaped_count'] and row['call_count']>0 and row['timeout_count']==0 and
            row['retention_limit']==512 and row['retained_count']==len(row['calls'])==min(row['call_count'],512),'P8 bounded native lifecycle counters')
        for call in row['calls']:
            need(call['process_reaped'] is True and call['timed_out'] is False and call['exit_code']==0 and call['start_ticks'] is not None and
                call['binary_sha256']==g['worker_sha256'] and call['operation'] in ('verify','note-root','network-domain','identities') and
                type(call['input_bytes'])is int and 0<=call['input_bytes']<=4096 and type(call['output_bytes'])is int and 0<call['output_bytes']<=256,'P8 actual bounded verifier call')
    need(w.call_count==w.reaped_count and not w.timeout_count,'P8 independent replay worker lifecycle')
    return {'qualified':True,'check_count':len(CHECKS),'source_commit':s['commit'],'source_tree':s['tree'],
        'genesis_sha256':v['genesis_sha256'],'state_height':witness['height'],'certificate_header_height':cert['header_height'],
        'actual_fixture_proofs':5,'accepted_txids':expected,'replay_processes_reaped':w.reaped_count,
        'scope':'one host, finite synthetic P8; no freshness, custody, state sync or public release'}
def main():
    parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('report',type=Path);parser.add_argument('--worker',type=Path,required=True);args=parser.parse_args()
    try:result=validate(load(args.report),args.report,args.worker)
    except Exception as e:print(json.dumps({'qualified':False,'error':str(e)},sort_keys=True));return 1
    print(json.dumps(result,sort_keys=True));return 0
if __name__=='__main__':raise SystemExit(main())
