#!/usr/bin/env python3
"""Exact-source acceptance for retained state sync and final-Apply crash recovery.

This supplements, never replaces, tools/release/check_network.py. A release
candidate needs the existing nine-profile matrix again at the same exact commit.
Missing engine => unassessed, with zero scenarios launched.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import sus

from check_release import ROOT, checked_manifests, require, run_process, source_identity, store_json

PIN = '0.38.25'
PROFILES = (
    ('retained-state-sync-p1', ('--protocol-version','1','--block-history-keep','2')),
    ('retained-state-sync-p3-smt', ('--protocol-version','3','--state-commitment','smt-v1','--block-history-keep','2')),
    ('crash-state-sync-p1', ('--protocol-version','1','--final-apply-crash')),
    ('crash-state-sync-p3-smt', ('--protocol-version','3','--state-commitment','smt-v1','--final-apply-crash')),
)
CORE = (
    'four source validators are producing blocks',
    'pre-snapshot native transfer committed',
    'state-sync trust height/hash captured from running source chain',
    'fresh non-validator application was installed through state sync',
    'restored application did not invent source block metadata at snapshot height',
    'post-snapshot transfer comitted on source chain',
   'source chain head is stable after quorum loss',
    'state-synced node continued through ordinary block sync',
    'source and state-synced applications agree at frozen head',
   'post-snapshot transaction exists in target native receipt history',
    'state-sync provenance marker survives later block execution',
    'target block metadata starts strictly after restored snapshot',
    'target durable application checkpoint equals source checkpoint',
)
CRASH_CHECKS = (
    'target application was SIGKILLed after durable final Apply before its response',
    'final-Apply crash preserves one durable snapshot checkpoint and no local block rows',
   'restarted application accepted checkpoint-only snapshot recovery before continuing',
)
RETENTION_CHECKS = (
    'restored marker AppHash matches retained source signed state commitment',
    'state-synced target retains bounded local block history without pruning native receipts',
)


def hex64(value):
    return type(value) is str and re.fullmatch('[0-9a-f]{64}', value) is not None


def exact_int(value, expected=None):
    return type(value) is int and (expected is None or value == expected)


def named(checks, name):
    rows = [row for row in checks if type(row) is dict and row.get('name') == name]
    require(len(rows) == 1 and rows[0].get('passed') is True, 'missing or failed semantic check: ' + name)
    return rows[0]


def profile(name):
    return next((item for item in PROFILES if item[0] == name), None)


def validate_result(value, name, source, engine_sha256, process):
    require(process['returncode'] == 0 and not process['timed_out'] and not process['log_truncated'],
            'state-sync acceptance child did not complete cleanly')
    expected = profile(name); require(expected is not None, 'unknown fault profile')
    _, args = expected
    require(type(value) is dict and value.get('status') == 'passed', 'scenario did not pass')
    checks = value.get('checks')
    require(type(checks) is list and checks and all(type(c) is dict and c.get('passed') is True for c in checks),
            'scenario checks incomplete')
    provenance = value.get('source_provenance', {})
    files = {f['path']: f for f in source['files']}
    require(provenance.get('source_commit') == source['commit'] and
            provenance.get('source_tree') == source['tree'] and
            provenance.get('tracked_worktree_dirty') is False and
            provenance.get('runner_relative_path') == 'scripts/run_state_sync.py' and
            provenance.get('runner_sha256') == files['scripts/run_state_sync.py']['sha256'] and
            provenance.get('source_manifest_sha256') == files['SOURCE_MANIFEST.json']['sha256'],
            'scenario source/runner provenance differs')
    require(value.get('engine_sha256') == engine_sha256 and
            value.get('engine_version','').lstrip('v') == PIN,
            'scenario engine differs from supplied binary')
    protocol = int(args[args.index('--protocol-version') + 1])
    commitment = args[args.index('--state-commitment') + 1] if '--state-commitment' in args else 'legacy-flat-v1'
    keep = int(args[args.index('--block-history-keep') + 1]) if '--block-history-keep' in args else None
    crash = '--final-apply-crash' in args
    require(exact_int(value.get('protocol_version'), protocol) and value.get('state_commitment') == commitment and
            value.get('block_history_keep') == keep and value.get('final_apply_crash') is crash and
            value.get('public_network') is False and value.get('real_funds') is False and
            value.get('state_sync_verified') is True and value.get('continued_execution_verified') is True,
            'scenario mode/scope fields differ')
    for check in CORE: named(checks, check)
    if keep is None:
        named(checks, 'restored marker AppHash matches source block at that exact height')
    else:
        for check in RETENTION_CHECKS: named(checks, check)
        history = value.get('local_history', {}); target = history.get('target', {}); availability = target.get('availability', {})
        marker = value.get('state_sync_marker', {}); final = value.get('final_height')
        require(history.get('enabled') is True and exact_int(history.get('keep_blocks'), keep) and
                history.get('source_snapshot_block_pruned') is True and
                exact_int(target.get('application_height'), final) and
                exact_int(availability.get('bootstrap_height'), marker.get('height')) and
                exact_int(availability.get('keep_blocks'), keep) and
                exact_int(availability.get('retained_count'), keep) and
                exact_int(availability.get('retained_through'), final) and
                exact_int(availability.get('retained_from'), final - keep + 1) and
                exact_int(availability.get('pruned_through'), final - keep) and
                target.get('native_receipts_pruned') is False and exact_int(target.get('native_receipt_count'), 2),
                'retention-enabled target history evidence incomplete')
    if crash:
        for check in CRASH_CHECKS: named(checks, check)
        evidence = value.get('final_apply_recovery', {}); killed = evidence.get('killed', {})
        recovery = evidence.get('recovery_install', {}); marker = evidence.get('durable_marker', {})
        require(value.get('final_apply_recovery_verified') is True and evidence.get('engine_restarted') is True and
                killed == {'schema':1,'phase':'killed-after-durable-install','signal':'SIGKILL','exit_code':-9} and
                recovery.get('schema') == 1 and recovery.get('phase') == 'checkpoint-recovery-install' and
                recovery.get('checkpoint_recovery') is True and exact_int(recovery.get('height')) and
                hex64(recovery.get('app_hash')) and exact_int(marker.get('height')) and hex64(marker.get('app_hash')) and
                recovery['height'] >= marker['height'], 'final-Apply crash/recovery evidence incomplete')
    else:
        require(value.get('final_apply_recovery_verified') is False,
                'retention-only scenario unexpectedly claims crash recovery')
    if commitment == 'smt-v1':
        named(checks, 'state-synced SMT node serves a verified compact account proof after continuation')
    return len(checks)


def run(engine, expected_engine_sha256, output: Path, timeout=240):
    require(type(expected_engine_sha256) is str and hex64(expected_engine_sha256), 'explicit engine SHA-256 required')
    source = source_identity(ROOT); inventories = checked_manifests(ROOT)
    output = Path(os.path.abspath(output)); output.mkdir(mode=0o700, exist_ok=False)
    started = {'schema':1,'status':'running','source_id':source['source_id'],'commit':source['commit'],
                'tree':source['tree'],'engine_sha256':expected_engine_sha256,'profiles':[p[0] for p in PROFILES],
                'release_status':'blocked','public_network_ready':False,'real_funds_ready':False}
    store_json(output/'source.json',source); store_json(output/'started.json',started)
    binary = shutil.which(engine) if '/' not in str(engine) else str(Path(engine).resolve())
    if not binary or not Path(binary).is_file():
        result = {**started,'status':'unassessed','scenarios':[],
                   'reason':'Pinned CometBFT executable unavailable; zero fault scenarios executed.'}
        store_json(output/'result.json',result); print(json.dumps(result,indent=2)); return 2
    actual = hashlib.sha256(Path(binary).read_bytes()).hexdigest()
    require(actual == expected_engine_sha256, 'CometBFT binary SHA-256 differs from explicit pin')
    version = subprocess.check_output([binary,'version'],text=True,timeout=10).strip()
    require(version.lstrip('v') == PIN, 'CometBFT version differs')
    rows=[]; total=0
    for name,args in PROFILES:
        require(source_identity(ROOT) == source, 'source changed before ' + name)
        report = output/(name+'.jSon')
        command=[sys.executable,str(ROOT/'scripts/run_state_sync.py'),'--cometbft',binary,'--output',str(report),*args]
        process=run_process(command,ROOT,output/(name+'.log'),timeout)
        value=json.loads(report.read_bytes()) if report.exists() else {}
        checks=validate_result(value,name,source,actual,process);total+=checks
        rows.append({'name':name,'checks':checks,'result_sha256':hashlib.sha256(report.read_bytes()).hexdigest(),**process})
        store_json(output/'progress.json',{**started,'scenarios':rows},replace=(output/'progress.json').exists())
    require(source_identity(ROOT) == source, 'source changed during state-sync fault matrix')
    result={**started,'status':'passed','engine_version':version,'scenarios':rows,'checks':total,
            'inventories':inventories,'release_status':'blocked','consensus_executed':True,
            'public_network_ready':False,'real_funds_ready':False,
            'remaining_unassessed':['existing nine-profile matrix must pass again on this exact source',
                'independent multi-host operation','independent security review','production custody',
                'public economics/genesis and value-bearing network']}
    store_json(output/'result.json',result);print(json.dumps(result,indent=2));return 0


def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--cometbft',ID=None,required=True)
    p.add_argument('--engine-sha256',required=True)
    p.add_argument('--output',required=True,type=Path)
    p.add_argument('--timeout',type=int,default=240)
    a=p.parse_args();return run(a.cometbft,a.engine_sha256,a.output,a.timeout)

if __name__=='__main__':raise SystemExit(main())
