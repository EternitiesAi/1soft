#!/usr/bin/env python3
"""Strict source-bound P7 actual-quorum/real-proof owner lifecycle receipt checker."""
import argparse,json,re,subprocess,sys
from pathlib import Path
ROOT=Path(__file__).resolve().parents[2];sys.path.insert(0,str(ROOT/'src'));sys.path.insert(0,str(ROOT/'scripts'))
from protocol7_treasury import canonical,digest,genesis_document,bootstrap_digest,parse,packet,txid,need,PROFILE,ZERO
from protocol7_worker import Worker
from protocol7_certificate import verify_state
from run_protocol7_engine import CHECKS,CLAIMS,SOURCE_NAMES,SOURCE_PREFIXES,ENGINE_SHA256
FIXTURES={'a','b','rotated_a','reactivated_a','after_rotated_a_revoke_b','revoked_a_b','pre_enroll_a','after_enroll_b','after_a_b','after_b_a','duplicate_request','after_a_revoke_b'}
def load(path):
    raw=Path(path).read_bytes();need(len(raw)<=2*1024*1024 and raw.endswith(b'\n'),'P7 bounded canonical report required')
    v=json.loads(raw);need(canonical(v)+b'\n'==raw,'P7 canonical report bytes');return v
def validate(v,path,worker_binary):
    expected={'format','status','source','scenario','checks','claims','inputs','commands','genesis','genesis_sha256','bootstrap_sha256','state_witness','signed_header','certificate','artifacts','processes'}
    need(type(v) is dict and set(v)==expected and v['format']=='1soft/protocol7-owner-engine/v1' and v['status']=='qualified-one-host-owner-treasury-consensus' and v['scenario'] in ('rotate','reactivate','enroll'),'P7 closed completed report required')
    need(type(v['claims']) is dict and set(v['claims'])==set(CLAIMS) and all(v['claims'][k] is b for k,b in CLAIMS.items()),'P7 unsupported claim')
    checks=v['checks'];need(type(checks) is list and len(checks)==len(CHECKS) and [x.get('id') for x in checks if type(x) is dict]==list(CHECKS)
        and all(type(x) is dict and set(x)=={'id','passed','evidence'} and x['passed'] is True and type(x['evidence']) is dict for x in checks),'P7 check roster incomplete or failed')
    source=v['source'];need(type(source) is dict and set(source)=={'commit','tree','clean','status_porcelain','files'} and source['clean'] is True and source['status_porcelain']=='','P7 executed source was not clean')
    def git(*a):return subprocess.check_output(['git','-C',str(ROOT),*a],stderr=subprocess.DEVNULL)
    for k in ('commit','tree'):need(type(source[k]) is str and re.fullmatch('[0-9a-f]{40}',source[k]) is not None,'P7 Git identity')
    need(git('rev-parse',source['commit']+'^{tree}').decode().strip()==source['tree'],'P7 source tree differs')
    paths=set(SOURCE_NAMES)|{p for p in git('ls-tree','-r','--name-only',source['commit']).decode().splitlines() if p.startswith(SOURCE_PREFIXES)}
    need(type(source['files']) is dict and set(source['files'])==paths,'P7 dependency source coverage differs')
    for rel,row in source['files'].items():
        need(type(row) is dict and set(row)=={'bytes','sha256'} and type(row['bytes']) is int and row['bytes']>=0,'P7 source receipt shape')
        raw=(ROOT/rel).read_bytes();need(raw==git('show',source['commit']+':'+rel) and len(raw)==row['bytes'] and digest(raw)==row['sha256'],'P7 current/committed/executed source differs')
    inputs=v['inputs'];need(type(inputs) is dict and set(inputs)=={'engine','worker','prover','fixtures'},'P7 input roster')
    for n in ('engine','worker','prover'):
        row=inputs[n];need(type(row) is dict and set(row)=={'bytes','sha256'} and type(row['bytes']) is int and 0<row['bytes']<=64*1024*1024,'P7 binary receipt bound')
    need(inputs['engine']['sha256']==ENGINE_SHA256,'P7 engine identity differs')
    need(type(inputs['fixtures']) is dict and set(inputs['fixtures'])==FIXTURES,'P7 twelve actual fixture roster')
    directory=Path(path).with_name(Path(path).name+'.artifacts')
    names={f'app{i}.log' for i in range(4)}|{f'engine{i}.log' for i in range(4)}|{'fixture-'+n+'.tx' for n in FIXTURES}|{'fixture-genesis.json','fixture-enroll-genesis.json','fixture.log','commands.json'}
    artifacts=v['artifacts'];need(type(artifacts) is list and len(artifacts)==len(names) and {x.get('name') for x in artifacts}==names,'P7 artifact roster differs')
    actual={}
    for row in artifacts:
        need(type(row) is dict and set(row)=={'name','bytes','sha256'} and type(row['bytes']) is int and 0<=row['bytes']<=8*1024*1024,'P7 artifact receipt bound')
        p=directory/row['name'];need(not p.is_symlink() and p.is_file(),'P7 regular raw artifact required')
        raw=p.read_bytes();need(len(raw)==row['bytes'] and digest(raw)==row['sha256'],'P7 actual artifact differs');actual[row['name']]=raw
    for n,sha in inputs['fixtures'].items():need(digest(actual['fixture-'+n+'.tx'])==sha,'P7 actual fixture digest differs')
    g=v['genesis'];need(digest(canonical(g))==v['genesis_sha256'] and bootstrap_digest(g)==v['bootstrap_sha256'],'P7 full/acyclic genesis receipt differs')
    kat=actual['fixture-pre_enroll_a.tx' if v['scenario']=='enroll' else 'fixture-a.tx']
    w=Worker(worker_binary,g['worker_sha256'],kat);genesis_document(canonical(g),w)
    need(inputs['worker']['sha256']==g['worker_sha256'] and Path(worker_binary).stat().st_size==inputs['worker']['bytes'],'P7 measured worker receipt differs')
    initial=json.loads(actual['fixture-enroll-genesis.json' if v['scenario']=='enroll' else 'fixture-genesis.json']);need(initial==g['treasury'],'P7 initial treasury differs')
    for n in FIXTURES:
        raw=actual['fixture-'+n+'.tx'];need(parse(raw)[1]==g['treasury']['genesis'] and w.verify(raw),'P7 actual fixture proof/domain fails')
    need(actual['commands.json']==canonical(v['commands']) and type(v['commands']) is list and 1<=len(v['commands'])<=4,'P7 signed command artifacts differ')
    for raw in v['commands']:packet(bytes.fromhex(raw))
    processes=v['processes'];need(type(processes) is list and len(processes)>=11,'P7 process receipts missing');seen=set();roles=set();provers=[]
    for p in processes:
        need(type(p) is dict and set(p)=={'role','node','pid','start_ticks','executable_sha256','exit_code'} and p['role'] in ('engine','application','fixture-prover') and type(p['node']) is int and p['node'] in range(4)
            and type(p['pid']) is int and p['pid']>0 and type(p['start_ticks']) is int and p['start_ticks']>0 and type(p['exit_code']) is int and p['exit_code'] in (0,-15),'P7 complete typed process lifecycle required')
        identity=(p['pid'],p['start_ticks']);need(identity not in seen,'duplicate P7 process identity');seen.add(identity)
        if p['role']=='fixture-prover':provers.append(p);wanted=inputs['prover']['sha256'];need(p['exit_code']==0,'P7 fixture prover failed')
        else:roles.add((p['role'],p['node']));wanted=ENGINE_SHA256 if p['role']=='engine' else source['files']['scripts/serve_abci_p7.py']['sha256']
        need(p['executable_sha256']==wanted,'P7 process executable binding differs')
    need(len(provers)==1 and roles=={(r,i) for r in ('engine','application') for i in range(4)},'P7 exact fixture/four-validator roles missing')
    startup=checks[3]['evidence'];need(set(startup)=={'worker_startup'} and type(startup['worker_startup']) is list and len(startup['worker_startup'])==4,'P7 startup receipts absent')
    need(all(row==w.startup for row in startup['worker_startup']),'P7 KAT/profile/worker startup identity differs')
    certificate=verify_state(v['state_witness'],v['signed_header'],canonical(g),w);need(certificate==v['certificate'],'P7 signed/replayed certificate differs')
    state=v['state_witness']['state'];receipts=state['receipts'];t=state['treasury']
    patterns={'rotate':['owner','payment','owner','payment'],'reactivate':['owner','owner','payment'],'enroll':['owner','payment']}
    need([r['kind'] for r in receipts]==patterns[v['scenario']],'P7 executed lifecycle pattern differs')
    expected_kinds={'rotate':['rotate','revoke'],'reactivate':['revoke','rotate'],'enroll':['enroll']}
    need([r['body']['kind'] for r in receipts if r['kind']=='owner']==expected_kinds[v['scenario']],'P7 executed signed command lifecycle differs')
    payments=[r for r in receipts if r['kind']=='payment'];need(t['owner_sequence']==len(expected_kinds[v['scenario']]) and t['fees']==2*len(payments) and len(t['notes'])==3+2*len(payments)
        and len(t['nullifiers'])==len(payments) and len(t['authority_nullifiers'])==2*len(payments),'P7 aggregate atomic value/lifecycle evidence differs')
    for r in receipts:
        raw=bytes.fromhex(r['raw']);need(txid(raw)==r['txid'] and digest(raw)==r['raw_sha256'],'P7 exact transaction receipt differs')
        if r['kind']=='owner':need(r['raw'] in v['commands'] and packet(raw)['body']==r['body'],'P7 signed owner command receipt differs')
        else:need(parse(raw)==r['statement'],'P7 actual payment statement differs')
    need(checks[2]['evidence']=={'domain':g['treasury']['genesis'],'actual_proofs':12},'P7 generated proof/domain evidence differs')
    need(checks[9]['evidence']=={'txids':[r['txid'] for r in receipts]},'P7 ordered executed txids differ')
    need(checks[11]['evidence']=={'payments':len(payments),'fees':t['fees']},'P7 value claim differs')
    if v['scenario']=='rotate':need(t['grants'][0]['generation']==2 and t['grants'][0]['commitment']==ZERO,'P7 rotated/revoked final state differs')
    elif v['scenario']=='reactivate':need(t['grants'][0]['generation']==2 and t['grants'][0]['commitment']!=ZERO,'P7 reactivated final state differs')
    else:need(t['grants'][1]['generation']==1 and t['grants'][1]['commitment']!=ZERO,'P7 enrolled final state differs')
    return {'qualified':True,'scenario':v['scenario'],'status':v['status'],'check_count':len(CHECKS),'source_commit':source['commit'],'source_tree':source['tree'],'genesis_sha256':v['genesis_sha256']}
def main():
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('report',type=Path);p.add_argument('--worker',type=Path,required=True);a=p.parse_args();print(json.dumps(validate(load(a.report),a.report,a.worker),sort_keys=True))
if __name__=='__main__':main()
