#!/usr/bin/env python3
"""Fail-closed P6 source, exact report roster, raw-log and signed-state checker."""
import argparse,hashlib,json,re,subprocess,sys
from pathlib import Path
ROOT=Path(__file__).resolve().parents[2];sys.path.insert(0,str(ROOT/'src'));sys.path.insert(0,str(ROOT/'scripts'))
from protocol6_treasury import canonical,decode_canonical_json,digest,genesis_document,parse,txid,need
from protocol6_certificate import verify_state
from run_protocol6_engine import CHECKS,SOURCE_NAMES,ENGINE_SHA256
CLAIMS={'one_host_four_validators':True,'static_genesis_grants':True,'production_ready':False,'public_network':False,
        'independent_operators':False,'seccomp_worker':False,'wallet_integrated':False,'merchant_redemption':False,'owner_lifecycle':False,
        'real_funds':False,'freshness_established':False,'independent_cryptographic_audit':False}
def load(path):
    raw=Path(path).read_bytes();need(len(raw)<=2*1024*1024,'P6 report byte bound')
    need(raw.endswith(b'\n'),'P6 canonical report newline required')
    return decode_canonical_json(raw[:-1],max_bytes=2*1024*1024)
def validate(v,path):
    expected={'format','status','source','checks','claims','inputs','genesis','genesis_sha256','state_witness','signed_header','certificate','artifacts','processes'}
    need(type(v) is dict and set(v)==expected and v['format']=='1soft/protocol6-treasury-engine/v1' and v['status']=='qualified-one-host-static-treasury-consensus','P6 completed closed report required')
    need(type(v['claims']) is dict and set(v['claims'])==set(CLAIMS) and all(v['claims'][k] is value for k,value in CLAIMS.items()),'P6 unsupported or malformed claim')
    checks=v['checks'];need(type(checks) is list and [x.get('id') for x in checks if type(x) is dict]==list(CHECKS) and len(checks)==len(CHECKS)
        and all(type(x) is dict and set(x)=={'id','passed','evidence'} and x['passed'] is True and type(x['evidence']) is dict for x in checks),'P6 checks incomplete, changed or failed')
    s=v['source'];need(type(s) is dict and set(s)=={'commit','tree','clean','status_porcelain','files'} and s['clean'] is True and s['status_porcelain']=='','P6 source must be captured clean')
    for k in ('commit','tree'):need(type(s[k]) is str and re.fullmatch('[0-9a-f]{40}',s[k]) is not None,'P6 Git identity')
    def git(*a):return subprocess.check_output(['git','-C',str(ROOT),*a],stderr=subprocess.DEVNULL)
    need(git('rev-parse',s['commit']+'^{tree}').decode().strip()==s['tree'],'P6 captured tree differs')
    expected_paths=set(SOURCE_NAMES)
    expected_paths.update(p for p in git('ls-tree','-r','--name-only',s['commit']).decode().splitlines() if p.startswith(('src/','scripts/','tools/private-treasury-payment-lab/','tools/shielded-consensus/halo2/')))
    need(type(s['files']) is dict and set(s['files'])==expected_paths,'P6 runtime dependency source coverage differs')
    for rel,row in s['files'].items():
        need(type(row) is dict and set(row)=={'bytes','sha256'} and type(row['bytes']) is int and row['bytes']>=0,'P6 source receipt shape')
        raw=(ROOT/rel).read_bytes();committed=git('show',s['commit']+':'+rel)
        need(raw==committed and len(raw)==row['bytes'] and digest(raw)==row['sha256'],'P6 executed source differs from committed or current source')
    g=genesis_document(canonical(v['genesis']));need(digest(canonical(g))==v['genesis_sha256'],'P6 genesis receipt differs')
    inputs=v['inputs'];need(set(inputs)=={'engine','worker','fixtures','treasury_genesis'},'P6 input roster differs')
    for name in ('engine','worker'):
        row=inputs[name];need(type(row) is dict and set(row)=={'bytes','sha256'} and type(row['bytes']) is int and 0<row['bytes']<=64*1024*1024,'P6 binary receipt bound')
    need(inputs['engine']['sha256']==ENGINE_SHA256 and inputs['worker']['sha256']==g['worker_sha256'],'P6 measured engine/worker binding differs')
    directory=Path(path).with_name(Path(path).name+'.artifacts');artifacts=v['artifacts']
    names={f'app{i}.log' for i in range(4)}|{f'engine{i}.log' for i in range(4)}|{f'fixture-{n}.tx' for n in ('a','b','after_a_b','after_b_a','duplicate_request')}|{'fixture-genesis.json'}
    need(type(artifacts) is list and len(artifacts)==len(names) and {x.get('name') for x in artifacts}==names,'P6 artifact roster differs')
    byname={}
    for row in artifacts:
        need(type(row) is dict and set(row)=={'name','bytes','sha256'} and type(row['bytes']) is int and 0<=row['bytes']<=8*1024*1024,'P6 artifact receipt bound')
        p=directory/row['name'];need(not p.is_symlink() and p.is_file(),'P6 regular artifact required')
        raw=p.read_bytes();need(len(raw)==row['bytes'] and digest(raw)==row['sha256'],'P6 actual raw artifact differs')
        byname[row['name']]=raw
    need(type(inputs['fixtures']) is dict and set(inputs['fixtures'])=={'a','b','after_a_b','after_b_a','duplicate_request'},'P6 fixture roster')
    for n,sha in inputs['fixtures'].items():need(digest(byname['fixture-'+n+'.tx'])==sha,'P6 fixture byte identity differs')
    need(digest(byname['fixture-a.tx'])==g['kat_sha256'] and digest(byname['fixture-genesis.json'])==inputs['treasury_genesis'] and json.loads(byname['fixture-genesis.json'])==g['treasury'],'P6 KAT or initial treasury binding differs')
    processes=v['processes'];need(type(processes) is list and len(processes)>=10,'P6 process receipts missing')
    seen=set();roles=set()
    for p in processes:
        need(type(p) is dict and set(p)=={'role','node','pid','start_ticks','executable_sha256','exit_code'} and p['role'] in ('engine','application') and type(p['node']) is int and p['node'] in range(4)
            and type(p['pid']) is int and p['pid']>0 and type(p['start_ticks']) is int and p['start_ticks']>0 and type(p['exit_code']) is int and p['exit_code'] in (0,-15),'P6 process lifecycle receipt differs')
        ident=(p['pid'],p['start_ticks']);need(ident not in seen,'duplicate P6 process identity');seen.add(ident);roles.add((p['role'],p['node']))
        wanted=ENGINE_SHA256 if p['role']=='engine' else s['files']['scripts/serve_abci_p6.py']['sha256'];need(p['executable_sha256']==wanted,'P6 process executable binding differs')
    need(roles=={(r,i) for r in ('engine','application') for i in range(4)},'four real application/engine process identities missing')
    certificate=verify_state(v['state_witness'],v['signed_header'],canonical(g));need(certificate==v['certificate'],'P6 signed certificate differs')
    state=v['state_witness']['state'];t=state['treasury'];receipts=state['receipts']
    need(len(receipts)==2 and t['fees']==4 and len(t['notes'])==6 and len(t['nullifiers'])==2 and len(t['authority_nullifiers'])==4,'P6 executed aggregate evidence differs')
    for i,r in enumerate(receipts):
        raw=bytes.fromhex(r['raw']);need(parse(raw)==r['statement'] and txid(raw)==r['txid'] and digest(raw)==r['raw_sha256'] and r['fee']==2 and r['merchant_position']==2+2*i and r['change_position']==3+2*i,'P6 exact payment receipt differs')
    initialized=checks[3]['evidence'];need(set(initialized)=={'worker_startup'} and type(initialized['worker_startup']) is list and len(initialized['worker_startup'])==4,'P6 startup KAT receipt absent')
    for row in initialized['worker_startup']:
        need(type(row) is dict and row.get('valid_proof_verified') is True and row.get('corrupt_proof_refused') is True,'P6 typed startup result required')
        need(row=={'binary_sha256':g['worker_sha256'],'kat_sha256':g['kat_sha256'],'valid_proof_verified':True,'corrupt_proof_refused':True,'profile_sha256':g['profile_sha256'],
            'parameter_sha256':'1cb278fe4d9cf5325e5cbc710d863c0deca3e961e1b8f6c8736890c43345c461','verifying_key_sha256':'1cc94283b32da0e1cbc055986ed2a375a33a899957a6421d5def8d7d056f5408'},'P6 actual startup profile/KAT differs')
    return {'qualified':True,'status':v['status'],'check_count':len(CHECKS),'source_commit':s['commit'],'source_tree':s['tree'],'genesis_sha256':v['genesis_sha256']}
def main():
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('report',type=Path);a=p.parse_args();print(json.dumps(validate(load(a.report),a.report),sort_keys=True))
if __name__=='__main__':main()
