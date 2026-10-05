#!/usr/bin/env python3
"""Exact-source offline qualification of local atomic treasury behavior; not consensus."""
from __future__ import annotations
import argparse,hashlib,json,os,re,subprocess,sys
from pathlib import Path

COMPONENT=Path(__file__).resolve().parents[1];ROOT=COMPONENT.parents[1]
PROFILE=COMPONENT/'PROFILE_V1.json'
RUST_TESTS={
'actual_composite_proof_rejects_cross_bindings_and_malformed_envelopes',
'change_cannot_escape_the_enrolled_agent','every_public_binding_is_constrained',
'fee_and_u64_edges_preserve_exact_conservation','fresh_bindings_do_not_allow_expiry_zero_or_overflow',
'note_membership_nullifier_and_openings_are_constrained','payment_requires_real_input_and_exact_fee_inclusive_change',
'valid_conserved_payment_with_shared_authority','current_old_openings_cannot_authorize_forged_successors',
'grant_expiry_fences_spend_even_when_value_notes_live_longer'}
PYTHON_TESTS={
'test_actual_payment_commits_all_effects_and_reopens','test_both_race_orders_and_refreshed_exact_exhaustion',
'test_revocation_rejects_prepared_authority_without_refill','test_sqlite_failure_rolls_back_authority_notes_fees_and_receipt',
'test_proof_encoding_and_height_failures_change_nothing','test_outbox_retains_exact_bytes_and_claims_only_once',
'test_lost_return_after_process_commit_does_not_create_second_payment','test_concurrent_claims_and_shared_parent_holds',
'test_crash_before_commit_retains_unknown_claim_and_no_ledger_effect','test_new_transaction_cannot_pay_same_request_twice',
'test_same_parent_execution_is_serialized_across_connections','test_trust_identity_permission_and_backward_height_fail_closed','test_failed_initial_lock_preserves_cause_and_closes_connection'}
FALSE_CLAIMS=['consensus_integrated','validator_authenticated_current_authority','p5_wallet_integrated',
'owner_authorization_integrated','production_privacy','production_ready','production_custody',
'independent_security_review','independent_cryptographic_review','cross_device_safe','hostile_host_safe',
'merchant_redemption_integrated','private_note_discovery','metadata_privacy','relationship_graph_privacy',
'public_network_ready','real_funds_safe','economic_value']
CLAIMS={**{k:False for k in FALSE_CLAIMS},'local_value_note_transition':True,'local_atomic_authority_transition':True,
'local_exact_obligation_retention':True}

def unique(pairs):
    result={}
    for k,v in pairs:
        if k in result:raise ValueError('duplicate JSON key')
        result[k]=v
    return result
def read_json(path):
    if path.is_symlink() or not path.is_file() or path.stat().st_size>1048576:raise ValueError('receipt bounds')
    return json.loads(path.read_bytes(),object_pairs_hook=unique)
def git(*args):return subprocess.check_output(['git',*args],cwd=ROOT)
def identity(path):
    raw=path.read_bytes();return {'path':path.relative_to(ROOT).as_posix(),'bytes':len(raw),'sha256':hashlib.sha256(raw).hexdigest()}
def files():
    local=[*COMPONENT.glob('halo2/src/**/*.rs'),*COMPONENT.glob('halo2/tests/*.rs'),
        COMPONENT/'halo2/Cargo.toml',COMPONENT/'halo2/Cargo.lock',PROFILE,*COMPONENT.glob('scripts/*.py')]
    dep=ROOT/'tools/shielded-consensus/halo2'
    return sorted(set(local+[dep/'Cargo.toml',dep/'Cargo.lock',*dep.glob('src/**/*.rs')]))
def marker(log,name):
    matches=re.findall(name+r' (\{[^\n]+\})',log)
    if len(matches)!=1:raise ValueError('missing or repeated measurement')
    return json.loads(matches[0],object_pairs_hook=unique)
def profile_measurement():
    p=read_json(PROFILE)
    return {k:p[k] for k in ['proof_bytes','parameter_sha256','verifying_key_sha256']}
def rust_log(log):
    if 'FAILED' in log or 'error:' in log:raise ValueError('failed Rust run')
    passed=re.findall(r'^test ([a-z0-9_]+) \.\.\. (?:TREASURY_PROFILE [^\n]+\nok|ok)$',log,re.M)
    if len(passed)!=len(set(passed)) or set(passed)!=RUST_TESTS:raise ValueError('Rust test roster differs')
    m=marker(log,'TREASURY_PROFILE')
    if canonical(m)!=canonical(profile_measurement()):raise ValueError('proof profile differs')
    return m
def python_log(log):
    if 'FAIL' in log or 'ERROR' in log or 'skipped' in log:raise ValueError('failed or skipped Python run')
    passed=re.findall(r'^(test_[a-z0-9_]+) \([^\n]+\) \.\.\. ok$',log,re.M)
    if len(passed)!=len(set(passed)) or set(passed)!=PYTHON_TESTS:raise ValueError('Python test roster differs')
    if not re.search(r'\nRan 13 tests in [0-9.]+s\n\nOK\n',log):raise ValueError('Python run incomplete')
def canonical(v):return json.dumps(v,sort_keys=True,separators=(',',':'))
def parse_logs(logs):
    if any('FAILED' in text or 'error:' in text for text in logs.values()):raise ValueError('failed execution log')
    m=rust_log(logs['rust']);python_log(logs['ledger'])
    f=marker(logs['fixtures'],'TREASURY_FIXTURES')
    if canonical(f)!=canonical({'actual_halo2_proofs':6,**m}):raise ValueError('real fixture proofs differ')
    return {'actual_halo2_proofs':7,'rust_tests':10,'local_ledger_tests':13,'proof_profile':m}
def check(report):
    r=read_json(report)
    if set(r)!={'format','version','status','source','profile','binary','logs','measurements','claims'}:raise ValueError('receipt keys differ')
    if r['format']!='1soft/private-treasury-payment-lab-result/v1' or type(r['version']) is not int or r['version']!=1 or r['status']!='qualified-local-atomic-treasury':raise ValueError('receipt status/version')
    if canonical(r['claims'])!=canonical(CLAIMS) or canonical(r['profile'])!=canonical(read_json(PROFILE)):raise ValueError('claims/profile differ')
    src=r['source']
    if set(src)!={'commit','tree','clean','files'} or src['clean'] is not True:raise ValueError('source shape')
    if not re.fullmatch('[0-9a-f]{40}',src['commit']) or not re.fullmatch('[0-9a-f]{40}',src['tree']):raise ValueError('source identity')
    if git('rev-parse',src['commit']+'^{tree}').decode().strip()!=src['tree']:raise ValueError('tree identity')
    if canonical(src['files'])!=canonical([identity(p) for p in files()]):raise ValueError('live source differs')
    for row in src['files']:
        raw=git('show',src['commit']+':'+row['path'])
        if len(raw)!=row['bytes'] or hashlib.sha256(raw).hexdigest()!=row['sha256']:raise ValueError('committed source differs')
    if set(r['binary'])!={'name','bytes','sha256'} or r['binary']['name']!='treasury-lab' or type(r['binary']['bytes']) is not int or r['binary']['bytes']<1 or not re.fullmatch('[0-9a-f]{64}',r['binary']['sha256']):raise ValueError('binary identity shape')
    if set(r['logs'])!={'rust','build','fixtures','ledger'}:raise ValueError('log roster differs')
    logs={}
    for label,row in r['logs'].items():
        if set(row)!={'name','bytes','sha256'} or type(row['bytes']) is not int or row['bytes']<0 or not re.fullmatch('[0-9a-f]{64}',row['sha256']) or Path(row['name']).name!=row['name']:raise ValueError('log identity')
        p=report.parent/row['name']
        if p.is_symlink() or not p.is_file() or p.stat().st_size>1048576:raise ValueError('log bounds')
        raw=p.read_bytes()
        if len(raw)!=row['bytes'] or hashlib.sha256(raw).hexdigest()!=row['sha256']:raise ValueError('log content differs')
        logs[label]=raw.decode()
    if canonical(parse_logs(logs))!=canonical(r['measurements']):raise ValueError('measurement differs')
    return {'qualified':True,'scope':'trusted local atomic treasury only','actual_halo2_proofs':7,'rust_tests':10,'local_ledger_tests':13}
def run(command,cwd,env,log_path,timeout,paths):
    if log_path.exists() or log_path.is_symlink():raise ValueError('fresh log required')
    result=subprocess.run(command,cwd=cwd,env=env,stdout=subprocess.PIPE,stderr=subprocess.STDOUT,timeout=timeout)
    text=result.stdout.decode()
    for path,label in paths:text=text.replace(str(path),label)
    log_path.write_text(text)
    if result.returncode:raise ValueError('execution failed; sanitized log retained')
    raw=log_path.read_bytes();return {'name':log_path.name,'bytes':len(raw),'sha256':hashlib.sha256(raw).hexdigest()}
def main():
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--check',type=Path);p.add_argument('--output',type=Path);p.add_argument('--cargo',type=Path);p.add_argument('--target-dir',type=Path)
    a=p.parse_args()
    if a.check:
        if any([a.output,a.cargo,a.target_dir]):raise ValueError('ambiguous mode')
        print(json.dumps(check(a.check),sort_keys=True));return
    if not all([a.output,a.cargo,a.target_dir]):raise ValueError('exact execution paths required')
    output=a.output.absolute();target=a.target_dir.resolve();cargo=a.cargo.resolve(strict=True)
    for path in [output,target]:
        if path==ROOT or ROOT in path.parents:raise ValueError('external evidence/target required')
    if output.exists() or output.is_symlink() or not output.parent.is_dir() or git('status','--porcelain').strip():raise ValueError('fresh output and clean committed source required')
    env=dict(os.environ,CARGO_TARGET_DIR=str(target),CARGO_NET_OFFLINE='true')
    paths=[(ROOT,'<source>'),(target,'<target>'),(output.parent,'<evidence>'),(Path.home(),'<home>')]
    base=[str(cargo),'+1.97.1'];manifest=str(COMPONENT/'halo2/Cargo.toml');logs={}
    logs['rust']=run(base+['test','--release','--locked','--offline','--manifest-path',manifest,'--','--test-threads=1','--nocapture'],ROOT,env,output.with_suffix('.rust.log'),300,paths)
    logs['build']=run(base+['build','--release','--locked','--offline','--manifest-path',manifest,'--bin','treasury-lab'],ROOT,env,output.with_suffix('.build.log'),180,paths)
    binary=target/'release/treasury-lab';fixture=output.with_suffix('.fixtures')
    if fixture.exists() or fixture.is_symlink():raise ValueError('fresh fixture directory required')
    logs['fixtures']=run([str(binary),'fixtures',str(fixture)],ROOT,env,output.with_suffix('.fixtures.log'),300,paths)
    env.update(TREASURY_BINARY=str(binary),TREASURY_FIXTURES=str(fixture))
    logs['ledger']=run([sys.executable,'-m','unittest','test_ledger','-v'],COMPONENT/'scripts',env,output.with_suffix('.ledger.log'),600,paths)
    measured=parse_logs({k:(output.parent/v['name']).read_text() for k,v in logs.items()})
    raw=binary.read_bytes()
    r={'format':'1soft/private-treasury-payment-lab-result/v1','version':1,'status':'qualified-local-atomic-treasury',
       'source':{'commit':git('rev-parse','HEAD').decode().strip(),'tree':git('rev-parse','HEAD^{tree}').decode().strip(),'clean':True,'files':[identity(f) for f in files()]},
       'profile':read_json(PROFILE),'binary':{'name':binary.name,'bytes':len(raw),'sha256':hashlib.sha256(raw).hexdigest()},
       'logs':logs,'measurements':measured,'claims':CLAIMS}
    with output.open('x') as f:json.dump(r,f,indent=2,sort_keys=True);f.write('\n')
    print(json.dumps(check(output),sort_keys=True))
if __name__=='__main__':
    try:main()
    except (OSError,ValueError,KeyError,TypeError,subprocess.SubprocessError) as e:
        print('treasury qualification refused: '+str(e),file=sys.stderr);sys.exit(2)
