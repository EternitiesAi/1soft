#!/usr/bin/env python3
"""Supplemental exact-source state-sync fault matrix; no deployment or downloads.

The original nine-profile gate is still required on the candidate. Local app
process tests cannot substitute for these actual pinned-engine scenarios.
"""
from __future__ import annotations
import argparse
import base64
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys

from check_release import ROOT,source_identity,checked_manifests,store_json,run_process,digest,require
from check_network import PIN,SYNC_CORE_CHECKS,named_check,exact_int,hex_sha256
sys.path[:0]=[str(ROOT/'src'),str(ROOT/'scripts')]
from block_application import application_hash,restore
from commit_verifier import load_json,pinned_genesis
from native_core import canonical
from run_state_sync import verify_snapshot_anchor,verify_history_window,verify_compact_proof_response,verify_payment_continuation

PROFILES=(
 ('retained-sync-p1',1,None,2,False),
 ('retained-sync-p3-smt',3,'smt-v1',2,False),
 ('crash-sync-p1',1,None,None,True),
 ('crash-sync-p3-smt',3,'smt-v1',None,True),
 ('retained-crash-sync-p1',1,None,2,True),
 ('retained-crash-sync-p3-smt',3,'smt-v1',2,True),
)
MARKER_CHECK='restored marker AppHash matches source block at that exact height'
SIGNED_CHECK='restored marker matches verified signed next-height commitment'
HISTORY_CHECK='source and recovered target retain bounded results and complete native receipts'
PAYMENT_CHECK='pre- and post-snapshot signed payments match native receipts and ordering'
CRASH_CHECKS=(
 'target application SIGKILL observed after snapshot commit before final Apply reply',
 'killed application retains snapshot checkpoint and no executed block rows',
 'same node home recovers the installed checkpoint before ordinary continuation',
)


def profile(name):
    found=[v for v in PROFILES if v[0]==name]
    require(len(found)==1,'unknown fault profile')
    return found[0]


def command_args(name):
    _,version,commitment,keep,crash=profile(name)
    args=['--protocol-version',str(version)]
    if commitment:args+=['--state-commitment',commitment]
    if keep is not None:args+=['--block-history-keep',str(keep)]
    if crash:args+=['--final-apply-crash']
    return args


def positive(value):return type(value) is int and value>0


def validate_result(value,name,source,engine_sha256,process,genesis_bytes):
    _,version,commitment,keep,crash=profile(name)
    require(type(process) is dict and exact_int(process.get('returncode'),0) and
            process.get('timed_out') is False and process.get('log_truncated') is False,'incomplete process')
    require(type(value) is dict and value.get('status')=='passed','scenario not passed')
    checks=value.get('checks');require(type(checks) is list and checks and
        all(type(c) is dict and c.get('passed') is True and type(c.get('name')) is str for c in checks),'invalid checks')
    files={f['path']:f['sha256'] for f in source['files']};p=value.get('source_provenance',{})
    require(p.get('source_commit')==source['commit'] and p.get('source_tree')==source['tree']
            and p.get('tracked_worktree_dirty') is False and
            p.get('runner_relative_path')=='scripts/run_state_sync.py' and
            p.get('runner_sha256')==files['scripts/run_state_sync.py'] and
            p.get('source_manifest_sha256')==files['SOURCE_MANIFEST.json'],'source differs')
    require(value.get('engine_sha256')==engine_sha256 and
            value.get('engine_version') in (PIN,'v'+PIN),'engine differs')
    require(exact_int(value.get('protocol_version'),version) and
            value.get('state_commitment')==(commitment or 'legacy-flat-v1') and
            type(value.get('block_history_keep')) is type(keep) and value.get('block_history_keep')==keep and
            value.get('final_apply_crash') is crash and value.get('public_network') is False and
            value.get('real_funds') is False and value.get('state_sync_verified') is True and
            value.get('continued_execution_verified') is True,'mode/scope differs')
    for n in SYNC_CORE_CHECKS:
        if n!=MARKER_CHECK:named_check(checks,n)
    marker=value.get('state_sync_marker');final=value.get('final_height')
    require(type(marker) is dict and positive(marker.get('height')) and hex_sha256(marker.get('app_hash'))
            and positive(final) and final>marker['height'] and exact_int(value.get('snapshot_height'),marker['height']),
            'missing marker or continuation heights')
    require(value.get('genesis_file_sha256')==digest(genesis_bytes),'genesis file differs')
    trust=pinned_genesis(genesis_bytes,digest(genesis_bytes));engine=load_json(genesis_bytes)
    state=value.get('final_state');require(type(state) is dict and
        set(state)=={'genesis','height','app_hash','native'} and state['genesis']==engine['app_state']
        and state['genesis']['chain_id']==trust.chain_id and exact_int(state['height'],final),'wrong final state')
    require(exact_int(state['genesis'].get('protocol_version',1),version) and
            state['genesis'].get('state_commitment')==commitment,'native genesis protocol/commitment differs')
    ledger=restore(state['genesis'],state['native'])
    try:
        require(application_hash(state['genesis'],final,state['native'])==state['app_hash'],'final AppHash differs')
    finally:ledger.close()
    pre_raw=base64.b64decode(value['pre_snapshot_transaction'],validate=True)
    raw=base64.b64decode(value['post_snapshot_transaction'],validate=True)
    envelope=load_json(raw,max_bytes=16384)
    require(canonical(envelope)==raw,'post transaction not canonical')
    payments=verify_payment_continuation(state,marker,pre_raw,raw)
    require(named_check(checks,PAYMENT_CHECK).get('details')==payments,
            'exact pre/post payment receipt details differ')
    require(named_check(checks,'source and state-synced applications agree at frozen head').get('details')==
            {'height':final,'app_hash':state['app_hash']},'frozen-state details differ')
    anchor=value.get('snapshot_anchor',{})
    verified=verify_snapshot_anchor(anchor.get('signed_header'),genesis_bytes,marker)
    require(verified==anchor.get('verified')==named_check(checks,SIGNED_CHECK).get('details'),'signed anchor details differ')
    if keep is not None:
        h=value.get('local_history',{});require(h.get('source_snapshot_block_pruned') is True,'pruning not observed')
        source_h=verify_history_window(h.get('source'),height=final,bootstrap=0,keep=keep,receipts=2)
        target_h=verify_history_window(h.get('target'),height=final,bootstrap=marker['height'],keep=keep,receipts=2)
        require(named_check(checks,HISTORY_CHECK).get('details')=={'source':source_h,'target':target_h},'history details differ')
    else:named_check(checks,MARKER_CHECK)
    if crash:
        fault=value.get('final_apply_recovery',{});k=fault.get('killed',{});r=fault.get('recovered',{})
        install=k.get('install',{});snap=k.get('checkpoint',{})
        run_id=fault.get('run_id')
        require(type(run_id) is str and re.fullmatch('[0-9a-f]{32}',run_id) is not None,'invalid fault run')
        require(value.get('final_apply_recovery_verified') is True and fault.get('same_node_home') is True
                and fault.get('engine_restarted') is True and fault.get('retention_flag_repeated') is False,'recovery scope differs')
        require(all(exact_int(e.get('schema'),1) and e.get('run_id')==run_id for e in (k,r,install))
                and k.get('signal')=='SIGKILL' and exact_int(k.get('returncode'),-9)
                and positive(k.get('pid')) and k['pid']==install.get('pid')
                and positive(r.get('pid')) and r['pid']!=k['pid']
                and install.get('transaction_active') is False and install.get('checkpoint_recovery') is False
                and r.get('transaction_active') is False and r.get('checkpoint_recovery') is True,'not the observed crash/recovery boundary')
        require(positive(snap.get('height')) and hex_sha256(snap.get('app_hash')) and
                exact_int(snap.get('local_block_rows'),0) and snap['height']==install.get('height') and
                snap['app_hash']==install.get('app_hash') and exact_int(r.get('height'),marker['height']) and
                r.get('app_hash')==marker['app_hash'] and marker['height']>=snap['height'],'snapshot/recovery identity differs')
        if marker['height']==snap['height']:require(marker['app_hash']==snap['app_hash'],'same-height snapshot changed')
        durable=fault.get('durable')
        require(durable=={'marker':{'height':snap['height'],'app_hash':snap['app_hash']},
                          'block_rows':0,'native_receipts':1},'killed checkpoint body not independently validated')
        require(named_check(checks,CRASH_CHECKS[0]).get('details')==k and
                named_check(checks,CRASH_CHECKS[1]).get('details')==durable
                and named_check(checks,CRASH_CHECKS[2]).get('details')==r,'crash observations differ')
    else:require(value.get('final_apply_recovery_verified') is False,'unexpected crash qualification')
    if commitment:
        proof=verify_compact_proof_response(value.get('compact_proof_response'),state,'accounts',envelope['body']['sender'])
        require(named_check(checks,'state-synced SMT node serves a verified compact account proof after continuation').get('details')==proof,
                'compact proof details differ from verified final state')
    return len(checks)


def run(engine,expected_sha,output,timeout=300):
    require(os.name=='posix' and type(timeout) is int and 60<=timeout<=1800,'POSIX/bounded timeout required')
    require(hex_sha256(expected_sha),'explicit engine SHA-256 required')
    output=Path(os.path.abspath(output));root=ROOT.resolve()
    require(not output.is_relative_to(root),'output must be outside source')
    for p in (output.parent,*output.parent.parents):require(not p.is_symlink(),'aliased output directory')
    source=source_identity(root);inventories=checked_manifests(root)
    output.mkdir(mode=0o700,exist_ok=False)
    report={'schema':1,'status':'unassessed','source_commit':source['commit'],'source_tree':source['tree'],
        'source_id':source['source_id'],'expected_engine_sha256':expected_sha,'planned_profiles':[p[0] for p in PROFILES],
        'inventories':inventories,'scenarios':[],'engine_scenarios_started':0,'consensus_executed':False,'release_status':'blocked',
        'public_network_ready':False,'real_funds_ready':False,
        'remaining':['original nine-profile matrix on exact candidate','independent multi-host operators',
                     'security review','production custody','economics/genesis','hardware power-loss durability']}
    store_json(output/'source.json',source);store_json(output/'started.json',report)
    binary=shutil.which(engine) if '/' not in str(engine) else str(Path(engine).absolute())
    if not binary or not Path(binary).is_file():
        report['reason']='Pinned engine absent; no fault scenario executed.'
        store_json(output/'result.json',report);return 2
    try:
        require(digest(Path(binary).read_bytes())==expected_sha,'engine hash differs')
        version=subprocess.check_output([binary,'version'],text=True,timeout=10).strip()
        require(version in (PIN,'v'+PIN),'engine version differs')
        for name,*_ in PROFILES:
            require(source_identity(root)==source and digest(Path(binary).read_bytes())==expected_sha,'source/engine changed')
            folder=output/name;folder.mkdir(mode=0o700);path=folder/'result.json'
            report['engine_scenarios_started']+=1
            if report['consensus_executed'] is False:report['consensus_executed']=None
            proc=run_process([sys.executable,str(root/'scripts/run_state_sync.py'),'--cometbft',binary,
                              '--output',str(path),*command_args(name)],root,folder/'process.log',timeout)
            item={'name':name,'process':proc,'status':'incomplete','checks':None};report['scenarios'].append(item)
            store_json(output/'progress.json',report,replace=(output/'progress.json').exists())
            value=load_json(path.read_bytes(),max_bytes=8*1024*1024) if path.is_file() else {}
            genesis=(folder/'state-sync-public-genesis.json').read_bytes()
            item['checks']=validate_result(value,name,source,expected_sha,proc,genesis)
            item.update(status='passed',result_sha256=digest(path.read_bytes()))
            report['consensus_executed']=True
        require(source_identity(root)==source and digest(Path(binary).read_bytes())==expected_sha,'source/engine changed at end')
        report.update(status='passed',consensus_executed=True,source_unchanged=True,engine_unchanged=True,
                      observed_checks=sum(s['checks'] for s in report['scenarios']))
    except Exception as exc:
        report.update(status='failed',error_type=type(exc).__name__)
    store_json(output/'result.json',report)
    print(json.dumps(report,indent=2))
    return 0 if report['status']=='passed' else 1


def main():
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--cometbft',required=True)
    p.add_argument('--engine-sha256',required=True);p.add_argument('--output',type=Path,required=True)
    p.add_argument('--timeout',type=int,default=300);a=p.parse_args()
    return run(a.cometbft,a.engine_sha256,a.output,a.timeout)

if __name__=='__main__':raise SystemExit(main())
