#!/usr/bin/env python3
"""Offline finite qualification of the isolated authority relation, never a payment."""
from __future__ import annotations
import argparse, hashlib, json, os, re, subprocess, sys
from pathlib import Path

COMPONENT=Path(__file__).resolve().parents[1]
ROOT=COMPONENT.parents[1]
PROFILE=COMPONENT/'PROFILE_V1.json'
EXPECTED_TESTS={
 'actual_proofs_bind_shared_current_state_and_ordered_revocation',
 'altered_openings_fail_without_replacing_current_commitments',
 'each_public_binding_is_constrained','exact_u64_and_cap_edges_match_native_and_circuit',
 'expiry_and_zero_secret_are_circuit_rules','forged_successors_cannot_change_caps_or_immutable_policy',
 'fresh_bindings_cannot_hide_overflow_or_cap_exhaustion','valid_fee_inclusive_shared_authority'}
FALSE_CLAIMS=['production_ready','production_privacy','independent_security_review',
 'independent_cryptographic_review','consensus_integrated','value_note_integrated',
 'executed_payment','durable_obligation_integrated','owner_authorization_integrated',
 'current_state_certificate','hostile_host_safe','cross_device_safe','metadata_privacy',
 'relationship_graph_privacy','public_network_ready','real_funds_safe','economic_value']

def duplicate_safe(pairs):
    result={}
    for k,v in pairs:
        if k in result:raise ValueError('duplicate JSON key')
        result[k]=v
    return result

def read_json(path):
    if path.is_symlink() or not path.is_file() or path.stat().st_size>1048576:
        raise ValueError('unsafe or excessive receipt')
    return json.loads(path.read_bytes(),object_pairs_hook=duplicate_safe)

def git(*args):
    return subprocess.check_output(['git',*args],cwd=ROOT)

def identity(path):
    raw=path.read_bytes()
    return {'path':path.relative_to(ROOT).as_posix(),'bytes':len(raw),'sha256':hashlib.sha256(raw).hexdigest()}

def source_files():
    local=sorted([*COMPONENT.glob('halo2/src/*.rs'),*COMPONENT.glob('halo2/tests/*.rs'),
                  COMPONENT/'halo2/Cargo.toml',COMPONENT/'halo2/Cargo.lock',PROFILE,*COMPONENT.glob('scripts/*.py')])
    dependency=ROOT/'tools/shielded-consensus/halo2'
    reuse=[dependency/'Cargo.toml',dependency/'Cargo.lock',*dependency.glob('src/**/*.rs')]
    return sorted(set(local+reuse))

def parse_log(log):
    if 'FAILED' in log or 'test result: FAILED' in log:raise ValueError('failed test')
    passed=re.findall(r'^test ([a-z0-9_]+) \.\.\. ok$',log,re.M)
    names=set(passed)
    if len(passed)!=len(names):raise ValueError('duplicate test execution')
    # The real-proof test emits its measurement before the test harness writes ok.
    if re.search(r'^test actual_proofs_bind_shared_current_state_and_ordered_revocation \.\.\. AUTHORITY_EVIDENCE ',log,re.M):
        names.add('actual_proofs_bind_shared_current_state_and_ordered_revocation')
    if names!=EXPECTED_TESTS:raise ValueError('exact test roster differs')
    matches=re.findall(r'AUTHORITY_EVIDENCE (\{[^\n]+\})',log)
    if len(matches)!=1:raise ValueError('actual proof evidence missing or duplicated')
    measured=json.loads(matches[0],object_pairs_hook=duplicate_safe)
    expected={'actual_halo2_proofs':5,'proof_bytes':3136,'same_parent_orders':2,
        'stale_rejected':True,'revoked_rejected':True,'refreshed_survivor_accepted':True,
        'exact_parent_exhaustion':True,'parameter_sha256':read_json(PROFILE)['parameter_sha256'],
        'verifying_key_sha256':read_json(PROFILE)['verifying_key_sha256']}
    if measured!=expected or any(type(measured[k]) is not type(v) for k,v in expected.items()):
        raise ValueError('cryptographic measurement differs')
    return measured

def check(report_path):
    r=read_json(report_path)
    if set(r)!={'format','version','status','source','profile','tests','measurements','log','claims'}:
        raise ValueError('receipt keys differ')
    if r['format']!='1soft/private-authority-proof-lab-result/v1' or type(r['version']) is not int or r['version']!=1:
        raise ValueError('receipt version differs')
    if r['status']!='qualified-local-proof-lab' or r['claims']!={k:False for k in FALSE_CLAIMS} or any(type(v) is not bool for v in r['claims'].values()):
        raise ValueError('status or claims differ')
    if json.dumps(r['profile'],sort_keys=True)!=json.dumps(read_json(PROFILE),sort_keys=True) or r['tests']!=sorted(EXPECTED_TESTS):raise ValueError('profile or roster differs')
    source=r['source']
    if set(source)!={'commit','tree','clean','files'} or source['clean'] is not True:raise ValueError('source shape')
    if not re.fullmatch('[0-9a-f]{40}',source['commit']) or not re.fullmatch('[0-9a-f]{40}',source['tree']):raise ValueError('source identity')
    if git('rev-parse',source['commit']+'^{tree}').decode().strip()!=source['tree']:raise ValueError('source tree differs')
    if json.dumps(source['files'],sort_keys=True)!=json.dumps([identity(p) for p in source_files()],sort_keys=True):raise ValueError('live source identity differs')
    for row in source['files']:
        raw=git('show',source['commit']+':'+row['path'])
        if len(raw)!=row['bytes'] or hashlib.sha256(raw).hexdigest()!=row['sha256']:raise ValueError('commit source differs')
    log_id=r['log']
    if set(log_id)!={'name','bytes','sha256'} or Path(log_id['name']).name!=log_id['name']:raise ValueError('log identity shape')
    lp=report_path.parent/log_id['name']
    if lp.is_symlink() or not lp.is_file() or lp.stat().st_size>1048576:raise ValueError('log bounds')
    raw=lp.read_bytes()
    if len(raw)!=log_id['bytes'] or hashlib.sha256(raw).hexdigest()!=log_id['sha256']:raise ValueError('log identity differs')
    if parse_log(raw.decode())!=r['measurements']:raise ValueError('measurement differs')
    return {'qualified':True,'scope':'isolated local authority proofs only','tests':len(EXPECTED_TESTS),'actual_halo2_proofs':5}

def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--check',type=Path)
    parser.add_argument('--output',type=Path)
    parser.add_argument('--cargo',type=Path)
    parser.add_argument('--target-dir',type=Path)
    args=parser.parse_args()
    if args.check:
        if any((args.output,args.cargo,args.target_dir)):raise ValueError('ambiguous mode')
        print(json.dumps(check(args.check),sort_keys=True));return
    if not all((args.output,args.cargo,args.target_dir)):raise ValueError('exact paths required')
    output=args.output.absolute();target=args.target_dir.resolve()
    if ROOT==output or ROOT in output.parents or ROOT==target or ROOT in target.parents:raise ValueError('evidence and build targets must be external')
    if output.exists() or output.is_symlink() or not output.parent.is_dir():raise ValueError('fresh external output required')
    if git('status','--porcelain').strip():raise ValueError('clean committed source required')
    cargo=args.cargo.absolute()
    if not cargo.is_file():raise ValueError('cargo missing')
    log_path=output.with_suffix('.log')
    if log_path.exists() or log_path.is_symlink():raise ValueError('fresh log required')
    command=[str(cargo),'+1.97.1','test','--release','--locked','--offline','--manifest-path',
        str(COMPONENT/'halo2/Cargo.toml'),'--','--test-threads=1','--nocapture']
    env=dict(os.environ,CARGO_TARGET_DIR=str(target),CARGO_NET_OFFLINE='true')
    result=subprocess.run(command,cwd=ROOT,env=env,stdout=subprocess.PIPE,stderr=subprocess.STDOUT,timeout=600)
    text=result.stdout.decode('utf-8')
    for path,label in [(str(ROOT),'<source>'),(str(target),'<target>'),(str(Path.home()),'<home>')]:text=text.replace(path,label)
    with log_path.open('x') as f:f.write(text)
    if result.returncode:raise ValueError('test execution failed; sanitized log retained')
    measurements=parse_log(text)
    raw=log_path.read_bytes()
    r={'format':'1soft/private-authority-proof-lab-result/v1','version':1,'status':'qualified-local-proof-lab',
       'source':{'commit':git('rev-parse','HEAD').decode().strip(),'tree':git('rev-parse','HEAD^{tree}').decode().strip(),
                 'clean':True,'files':[identity(p) for p in source_files()]},
       'profile':read_json(PROFILE),'tests':sorted(EXPECTED_TESTS),'measurements':measurements,
       'log':{'name':log_path.name,'bytes':len(raw),'sha256':hashlib.sha256(raw).hexdigest()},
       'claims':{k:False for k in FALSE_CLAIMS}}
    with output.open('x') as f:json.dump(r,f,indent=2,sort_keys=True);f.write('\n')
    print(json.dumps(check(output),sort_keys=True))

if __name__=='__main__':
    try:main()
    except (OSError,ValueError,subprocess.SubprocessError,KeyError,TypeError) as exc:
        print('authority qualification refused: '+str(exc),file=sys.stderr);sys.exit(2)
