#!/usr/bin/env python3
"""Independent closed source/artifact/quorum checker for developer prepared proofs."""
import argparse,json,re,subprocess,sys
from pathlib import Path
ROOT=Path(__file__).resolve().parents[2]
sys.path.insert(0,str(ROOT/'src'));sys.path.insert(0,str(ROOT/'scripts'))
from protocol7_treasury import canonical,digest,bootstrap_digest,genesis_document,parse,txid,need,PROFILE,PROFILE_SHA256,field
from protocol7_worker import Worker
from protocol7_certificate import verify_state
from protocol7_wallet import checked_observation,_resolve
from run_protocol7_prover import CHECKS,CLAIMS,SOURCE_NAMES
from run_protocol7_engine import SOURCE_PREFIXES,ENGINE_SHA256

FIXTURES={'a','b','rotated_a','reactivated_a','after_rotated_a_revoke_b','revoked_a_b',
          'pre_enroll_a','after_enroll_b','after_a_b','after_b_a','duplicate_request','after_a_revoke_b'}
def load(path):
    raw=Path(path).read_bytes()
    need(len(raw)<=2*1024*1024 and raw.endswith(b'\n'),'P7 bounded report required')
    v=json.loads(raw);need(canonical(v)+b'\n'==raw,'P7 canonical report required');return v
def validate(v,path,worker_binary):
    keys={'format','status','source','checks','claims','inputs','commands','genesis','genesis_sha256',
          'bootstrap_sha256','prepared_public','prepared_wire','prepared_txid','prover_run',
          'transport','record','artifacts','processes','request_binding'}
    need(type(v) is dict and set(v)==keys and v['format']=='1soft/protocol7-prepared-prover-engine/v1'
         and v['status']=='qualified-one-host-prepared-prover','P7 closed completed prover report required')
    need(type(v['claims']) is dict and set(v['claims'])==set(CLAIMS)
         and all(v['claims'][k] is b for k,b in CLAIMS.items()),'P7 prover unsupported claim')
    checks=v['checks']
    need(type(checks) is list and len(checks)==len(CHECKS) and [c.get('id') for c in checks if type(c) is dict]==list(CHECKS)
         and all(set(c)=={'id','passed','evidence'} and c['passed'] is True and type(c['evidence']) is dict for c in checks),
         'P7 prover check roster failed')
    need(checks[0]['evidence']=={'candidate':False},'P7 prover candidate is not qualification')
    source=v['source']
    need(type(source) is dict and set(source)=={'commit','tree','clean','status_porcelain','files'}
         and source['clean'] is True and source['status_porcelain']=='','P7 clean executed source required')
    def git(*args):return subprocess.check_output(['git','-C',str(ROOT),*args],stderr=subprocess.DEVNULL)
    for k in ('commit','tree'):
        need(type(source[k]) is str and re.fullmatch('[0-9a-f]{40}',source[k]) is not None,'P7 source identity')
    need(git('rev-parse',source['commit']+'^{tree}').decode().strip()==source['tree'],'P7 source tree differs')
    names=set(SOURCE_NAMES)|{p for p in git('ls-tree','-r','--name-only',source['commit']).decode().splitlines() if p.startswith(SOURCE_PREFIXES)}
    need(type(source['files']) is dict and set(source['files'])==names,'P7 prover dependency coverage differs')
    for name,row in source['files'].items():
        need(type(row) is dict and set(row)=={'bytes','sha256'} and type(row['bytes']) is int,'P7 source row')
        raw=(ROOT/name).read_bytes()
        need(raw==git('show',source['commit']+':'+name) and len(raw)==row['bytes'] and digest(raw)==row['sha256'],
             'P7 current/committed/executed source differs')
    inputs=v['inputs']
    need(type(inputs) is dict and set(inputs)=={'engine','worker','fixture_prover','prover','request_fixture'},'P7 binary roster')
    for row in inputs.values():
        need(type(row) is dict and set(row)=={'bytes','sha256'} and type(row['bytes']) is int
             and 0<row['bytes']<=64*1024*1024 and re.fullmatch('[0-9a-f]{64}',row['sha256']) is not None,'P7 binary identity')
    need(inputs['engine']['sha256']==ENGINE_SHA256,'P7 engine identity differs')
    directory=Path(path).with_name(Path(path).name+'.artifacts')
    names={f'app{i}.log' for i in range(4)}|{f'engine{i}.log' for i in range(4)}|{'fixture-'+n+'.tx' for n in FIXTURES}|{'fixture-genesis.json','fixture-enroll-genesis.json','fixture.log','commands.json'}
    rows=v['artifacts'];need(type(rows) is list and len(rows)==len(names) and {r.get('name') for r in rows}==names,'P7 raw artifact roster differs')
    artifacts={}
    for r in rows:
        need(type(r) is dict and set(r)=={'name','bytes','sha256'} and type(r['bytes']) is int and 0<=r['bytes']<=8*1024*1024,'P7 artifact row')
        p=directory/r['name'];need(p.is_file() and not p.is_symlink(),'P7 regular artifact required')
        raw=p.read_bytes();need(len(raw)==r['bytes'] and digest(raw)==r['sha256'],'P7 raw artifact differs')
        artifacts[r['name']]=raw
    need(v['commands']==[] and artifacts['commands.json']==canonical([]),'P7 unexpected owner command')
    g=v['genesis'];rawg=canonical(g)
    worker=Worker(worker_binary,inputs['worker']['sha256'],artifacts['fixture-a.tx'])
    need(Path(worker_binary).stat().st_size==inputs['worker']['bytes'],'P7 worker size differs')
    genesis_document(rawg,worker)
    need(g['worker_sha256']==inputs['worker']['sha256'] and digest(rawg)==v['genesis_sha256']
         and bootstrap_digest(g)==v['bootstrap_sha256'],'P7 genesis pins differ')
    need(json.loads(artifacts['fixture-genesis.json'])==g['treasury'],'P7 fixture treasury differs')
    wire=bytes.fromhex(v['prepared_wire']);public=parse(wire)
    need(public==v['prepared_public'] and txid(wire)==v['prepared_txid'] and worker.verify(wire)
         and public[1]==g['treasury']['genesis'],'P7 arbitrary proof differs')
    need(all(public!=parse(artifacts['fixture-'+n+'.tx']) for n in FIXTURES),'P7 proof is still a fixed fixture statement')
    run=v['prover_run']
    need(type(run) is dict and set(run)=={'pid','start_ticks','exit_code','binary_sha256','request_bytes','response_bytes'}
         and type(run['pid']) is int and run['pid']>0 and type(run['exit_code']) is int and run['exit_code']==0
         and type(run['start_ticks']) is int and run['start_ticks']>0
         and run['binary_sha256']==inputs['prover']['sha256'] and run['request_bytes']==2088 and run['response_bytes']==4168,
         'P7 measured prover completion missing')
    prefix=(b'1SOPRV01'+bytes.fromhex(PROFILE_SHA256)+bytes.fromhex(PROFILE['parameter_sha256'])
            +bytes.fromhex(PROFILE['verifying_key_sha256'])+bytes.fromhex(bootstrap_digest(g))
            +b''.join(field(p) for p in public))
    expected_binding={'profile_sha256':PROFILE_SHA256,'parameter_sha256':PROFILE['parameter_sha256'],
                      'verifying_key_sha256':PROFILE['verifying_key_sha256'],'bootstrap_sha256':bootstrap_digest(g),
                      'public_prefix_sha256':digest(prefix),'private_openings_retained':False}
    need(type(v['request_binding']) is dict and v['request_binding']==expected_binding
         and v['request_binding']['private_openings_retained'] is False,'P7 public request binding differs')
    record=v['record']
    record_keys={'format','genesis','genesis_sha256','profile_sha256','worker_sha256','kat_sha256','bootstrap_sha256',
                 'kind','txid','raw','raw_sha256','state_height','receipt','witness','signed_header','certificate'}
    need(type(record) is dict and set(record)==record_keys and record['format']=='1soft/protocol7-exact-execution-record/v1'
         and record['kind']=='payment','P7 exact record shape')
    o,certificate=checked_observation(record['witness'],record['signed_header'],rawg,worker)
    reason,receipt=_resolve(wire,o,worker)
    need(reason=='executed-exact' and record['receipt']==receipt and record['certificate']==certificate
         and record['state_height']==o['witness']['height'] and record['raw']==wire.hex()
         and record['raw_sha256']==digest(wire) and record['txid']==txid(wire),'P7 exact quorum completion differs')
    pins={'genesis':rawg.hex(),'genesis_sha256':digest(rawg),'bootstrap_sha256':bootstrap_digest(g),
          **{k:g[k] for k in ('profile_sha256','worker_sha256','kat_sha256')}}
    need(all(record[k]==value for k,value in pins.items()),'P7 exported pins differ')
    state=o['witness']['state'];need(len(state['receipts'])==1 and state['receipts'][0]['raw']==wire.hex()
          and state['treasury']['fees']==2 and len(state['treasury']['notes'])==5
          and len(state['treasury']['nullifiers'])==1,'P7 native payment effect differs')
    t=v['transport']
    need(type(t) is dict and set(t)=={'rpc_returned','response_accepted','response_discarded','calls','delivery'}
         and all(t[k] is True for k in ('rpc_returned','response_accepted','response_discarded'))
         and t['calls']==[digest(wire)] and t['delivery']=={'txid':txid(wire),'outcome':'unknown','attempts':1},
         'P7 lost return one-attempt evidence differs')
    processes=v['processes'];need(type(processes) is list and len(processes)>=11,'P7 worker lifecycles missing')
    seen=set();roles=set();fixtures=[];arbitrary=[]
    for p in processes:
        need(type(p) is dict and set(p)=={'role','node','pid','start_ticks','executable_sha256','exit_code'}
             and p['role'] in ('engine','application','fixture-prover','arbitrary-prover') and type(p['node']) is int and p['node'] in range(4)
             and type(p['pid']) is int and p['pid']>0 and type(p['start_ticks']) is int and p['start_ticks']>0
             and type(p['exit_code']) is int and p['exit_code'] in (0,-15),'P7 complete process row required')
        identity=(p['pid'],p['start_ticks']);need(identity not in seen,'P7 duplicate process');seen.add(identity)
        if p['role']=='fixture-prover':
            fixtures.append(p);want=inputs['fixture_prover']['sha256'];need(p['exit_code']==0,'P7 fixture generation failed')
        elif p['role']=='arbitrary-prover':
            arbitrary.append(p);want=inputs['prover']['sha256']
            need(p['exit_code']==0 and p['pid']==run['pid'] and p['start_ticks']==run['start_ticks'],
                 'P7 arbitrary prover lifecycle differs')
        else:
            roles.add((p['role'],p['node']))
            want=ENGINE_SHA256 if p['role']=='engine' else source['files']['scripts/serve_abci_p7_admission.py']['sha256']
        need(p['executable_sha256']==want,'P7 process identity differs')
    need(len(fixtures)==1 and len(arbitrary)==1 and roles=={(r,i) for r in ('engine','application') for i in range(4)},'P7 four-validator/prover process coverage')
    return {'qualified':True,'status':v['status'],'check_count':len(CHECKS),'source_commit':source['commit'],
            'genesis_sha256':digest(rawg),'txid':txid(wire),'state_height':o['witness']['height'],
            'claim':'bounded developer inputs and one-host native recovery; no encrypted custody or production claim'}
def main():
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('report',type=Path);p.add_argument('--worker',type=Path,required=True);a=p.parse_args()
    try:result=validate(load(a.report),a.report,a.worker)
    except Exception as exc:
        print(json.dumps({'qualified':False,'error':str(exc)},sort_keys=True));return 1
    print(json.dumps(result,sort_keys=True));return 0
if __name__=='__main__':raise SystemExit(main())
