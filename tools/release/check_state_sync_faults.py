#!/usr/bin/env python3
"""Supplemental exact-source retained-bootstrap and final-Apply SIGKILL matrix.

Four real-engine runs, no downloads or public endpoints. A local pass is not a
release approval. The original nine-profile matrix must pass on the same source.
"""
from __future__ import annotations

import argparse
import base64
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys

from check_release import (ROOT, checked_manifests, digest, require, run_process,
                           source_identity, store_json)
from check_network import SYNC_CORE_CHECKS, named_check, hex_sha256
sys.path[:0] = [str(ROOT/'src'), str(ROOT/'scripts')]
from commit_verifier import load_json
from state_sync_acceptance import (int_value, validate_marker, verify_marker_commitment,
    validate_history, validate_recovery, validate_payment_continuation)

PIN = '0.38.25'
PROFILES = (
    ('retained-state-sync-p1', ('--protocol-version','1','--block-history-keep','2')),
    ('retained-state-sync-p3-smt', ('--protocol-version','3','--state-commitment','smt-v1','--block-history-keep','2')),
    ('crash-state-sync-p1', ('--protocol-version','1','--final-apply-crash')),
    ('crash-state-sync-p3-smt', ('--protocol-version','3','--state-commitment','smt-v1','--final-apply-crash')),
)
SIGNED_CHECK = 'snapshot marker matches independently verified signed H+1 commitment'
PAYMENT_CHECK = 'exact pre-snapshot and post-snapshot signed payment receipts persist'
HISTORY_CHECK = 'retained source and fifth-node windows preserve native receipts after pruning'
CRASH_CHECKS = (
    'target SIGKILL occurred at the observed durable-install pre-Apply-return boundary',
    'killed target retains exactly its snapshot checkpoint before recovery',
    'restarted same-home target observed checkpoint-only recovery installation',
)
LEGACY_MARKER_CHECK = 'restored marker AppHash matches source block at that exact height'
SMT_CHECK = 'state-synced SMT node serves a verified compact account proof after continuation'


def profile(name):
    found = [p for p in PROFILES if p[0] == name]
    require(len(found) == 1, 'unknown supplemental state-sync profile')
    return found[0]


def validate_result(value, name, source, engine_sha256, process, *, genesis_bytes):
    require(type(process) is dict and type(process.get('returncode')) is int and process['returncode'] == 0 and
            process.get('timed_out') is False and process.get('log_truncated') is False, 'incomplete child process')
    _, args = profile(name)
    protocol = int(args[args.index('--protocol-version')+1])
    smt = '--state-commitment' in args; keep = 2 if '--block-history-keep' in args else None
    crash = '--final-apply-crash' in args
    require(type(value) is dict and value.get('status') == 'passed', 'scenario did not pass')
    require(type(value.get('protocol_version')) is int and value['protocol_version'] == protocol and
            value.get('state_commitment') == ('smt-v1' if smt else 'legacy-flat-v1') and
            (value.get('block_history_keep') is None if keep is None else
             type(value.get('block_history_keep')) is int and value['block_history_keep'] == keep) and
            value.get('final_apply_crash') is crash and value.get('final_apply_recovery_verified') is crash and
            value.get('public_network') is False and value.get('real_funds') is False and
            value.get('state_sync_verified') is True and value.get('continued_execution_verified') is True,
            'profile or scope mismatch')
    require(type(value.get('engine_version')) is str and value['engine_version'].lstrip('v') == PIN and
            value.get('engine_sha256') == engine_sha256, 'engine identity differs')
    files = {f['path']: f for f in source['files']}
    provenance = value.get('source_provenance')
    require(type(provenance) is dict and provenance.get('source_commit') == source['commit'] and
            provenance.get('source_tree') == source['tree'] and provenance.get('tracked_worktree_dirty') is False and
            provenance.get('runner_relative_path') == 'scripts/run_state_sync.py' and
            provenance.get('runner_sha256') == files['scripts/run_state_sync.py']['sha256'] and
            provenance.get('source_manifest_sha256') == files['SOURCE_MANIFEST.json']['sha256'], 'source identity differs')
    checks = value.get('checks')
    require(type(checks) is list and checks and all(type(c) is dict and c.get('passed') is True and
            type(c.get('name')) is str for c in checks), 'checks missing or failed')
    required = [c for c in SYNC_CORE_CHECKS if c != LEGACY_MARKER_CHECK or keep is None]
    for c in required + [SIGNED_CHECK, PAYMENT_CHECK] + (list(CRASH_CHECKS) if crash else []) + ([SMT_CHECK] if smt else []):
        named_check(checks, c)
    marker = value.get('state_sync_marker'); validate_marker(marker)
    final = value.get('final_height')
    require(int_value(final, marker['height']+1) and type(value.get('snapshot_height')) is int and
            value['snapshot_height'] == marker['height'], 'snapshot/final heights differ')
    run_id = value.get('acceptance_run_id')
    require(type(run_id) is str and len(run_id) == 32 and all(c in '0123456789abcdef' for c in run_id), 'missing run ID')
    require(type(genesis_bytes) is bytes and len(genesis_bytes) <= 1024*1024 and
            digest(genesis_bytes) == value.get('genesis_file_sha256'), 'genesis file identity differs')
    anchor = verify_marker_commitment(marker, value.get('snapshot_signed_commitment'), genesis_bytes)
    require(named_check(checks, SIGNED_CHECK).get('details') == anchor, 'signed-anchor check differs from evidence')
    state = value.get('continued_state')
    require(type(state) is dict and state.get('height') == final and type(state.get('height')) is int and
            state.get('genesis') == load_json(genesis_bytes)['app_state'], 'continued state/genesis differs')
    wires = []
    for key in ('pre_snapshot_transaction','post_snapshot_transaction'):
        raw = value.get(key)
        require(type(raw) is str and 0 < len(raw) <= 22000, 'signed payment bytes missing')
        wires.append(base64.b64decode(raw, validate=True))
    receipts = validate_payment_continuation(state, marker, *wires)
    require(named_check(checks, PAYMENT_CHECK).get('details') == receipts, 'payment check differs from verified receipts')
    if keep is not None:
        h = value.get('local_history')
        require(type(h) is dict and set(h) == {'source','target','source_snapshot_block_pruned'} and
                h['source_snapshot_block_pruned'] is True, 'retained history observations missing')
        validate_history(h['source'], final_height=final, bootstrap=0, keep=keep, receipt_count=2)
        validate_history(h['target'], final_height=final, bootstrap=marker['height'], keep=keep, receipt_count=2)
        require(named_check(checks, HISTORY_CHECK).get('details') == h, 'history check details differ')
    if crash:
        r = value.get('final_apply_recovery'); validate_recovery(r, marker, final, run_id)
        require(named_check(checks, CRASH_CHECKS[0]).get('details') == {'observation': r['crash'], 'exit_code': r['exit_code']} and
                named_check(checks, CRASH_CHECKS[1]).get('details') == r['durable'] and
                named_check(checks, CRASH_CHECKS[2]).get('details') == r['recovery'], 'kill/recovery checks differ from observed data')
    return len(checks)


def run(engine, expected_engine_sha256, output, timeout=300):
    require(os.name == 'posix' and type(timeout) is int and 30 <= timeout <= 1800, 'invalid platform/deadline')
    require(hex_sha256(expected_engine_sha256), 'explicit CometBFT binary digest required')
    root = ROOT.resolve(); output = Path(os.path.abspath(output))
    require(not output.is_relative_to(root), 'evidence must be outside the source tree')
    for parent in (output.parent, *output.parent.parents):
        require(not parent.is_symlink(), 'evidence ancestor is aliased')
    source = source_identity(root); inventories = checked_manifests(root)
    output.mkdir(mode=0o700, exist_ok=False)
    report = {'schema':1, 'status':'unassessed', 'source_commit':source['commit'], 'source_tree':source['tree'],
        'source_id':source['source_id'], 'inventories':inventories, 'engine_required':PIN,
        'expected_engine_sha256':expected_engine_sha256, 'planned_profiles':[p[0] for p in PROFILES],
        'scenarios':[], 'consensus_executed':False, 'release_status':'blocked',
        'public_network_ready':False, 'real_funds_ready':False,
        'remaining_unassessed':['original nine-profile matrix on this exact candidate',
            'combined retention plus crash in the same real-engine scenario', 'independent multi-host validators',
            'power loss / hostile host / independent security review / custody / economics']}
    store_json(output/'source.json',source); store_json(output/'started.json',report)
    try:
        binary = shutil.which(str(engine)) if '/' not in str(engine) else str(Path(engine).resolve())
        if not binary or not Path(binary).is_file():
            report['reason'] = 'Pinned real CometBFT executable unavailable; zero scenarios executed.'
        else:
            actual = digest(Path(binary).read_bytes())
            require(actual == expected_engine_sha256, 'engine binary digest differs')
            version = subprocess.check_output([binary,'version'], text=True, timeout=10).strip()
            require(version.lstrip('v') == PIN, 'engine version differs')
            report['engine_version'] = version; report['engine_sha256'] = actual
            for name,args in PROFILES:
                require(source_identity(root) == source and digest(Path(binary).read_bytes()) == actual,
                        'source or engine changed before scenario')
                folder = output/name; folder.mkdir(mode=0o700); path = folder/'result.json'
                process = run_process([sys.executable,str(root/'scripts/run_state_sync.py'),'--cometbft',binary,
                    '--output',str(path),*args],root,folder/'process.log',timeout)
                require(not path.is_symlink(), 'scenario result is aliased')
                value = load_json(path.read_bytes(),max_bytes=16*1024*1024) if path.is_file() else {}
                item = {'name':name, 'process':process, 'status':value.get('status','incomplete'),
                        'result_sha256':digest(path.read_bytes()) if path.is_file() else None}
                report['scenarios'].append(item)
                store_json(output/'progress.json',report,replace=(output/'progress.json').exists())
                item['checks'] = validate_result(value,name,source,actual,process,
                    genesis_bytes=(folder/'state-sync-public-genesis.json').read_bytes())
            require(source_identity(root) == source and digest(Path(binary).read_bytes()) == actual,
                    'source or engine changed at completion')
            report.update(status='passed', source_unchanged=True, engine_unchanged=True, consensus_executed=True)
    except Exception as exc:
        report.update(status='failed',error_type=type(exc).__name__)
    store_json(output/'result.json',report); print(json.dumps(report,indent=2))
    return 0 if report['status'] == 'passed' else 2 if report['status'] == 'unassessed' else 1


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--cometbft',required=True); p.add_argument('--engine-sha256',required=True)
    p.add_argument('--output',type=Path,required=True); p.add_argument('--timeout',type=int,default=300)
    a = p.parse_args(); return run(a.cometbft,a.engine_sha256,a.output,a.timeout)

if __name__ == '__main__':
    raise SystemExit(main())
