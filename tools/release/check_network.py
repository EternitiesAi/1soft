#!/usr/bin/env python3
"""Exact-source local engine acceptance matrix. No downloads, deployment or funds.

Explicitly supplied real CometBFT binary only. Missing engine is unassessed with
zero scenarios. Logs/results from previous runs are never imported as successes.
"""
from __future__ import annotations

import argparse
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys

from check_release import (ROOT, checked_manifests, digest, require, run_process,
                           source_identity, store_json)

PIN = '0.38.25'
DELIVERY = ('--decision-delivery', '--receipt-convergence')
PROFILES = (
    ('native-p1', 'scripts/run_devnet.py', ('--protocol-version','1')),
    ('native-p2', 'scripts/run_devnet.py', ('--protocol-version','2')),
    ('native-p3-flat', 'scripts/run_devnet.py', ('--protocol-version','3', *DELIVERY)),
    ('native-p3-smt', 'scripts/run_devnet.py', ('--protocol-version','3','--state-commitment','smt-v1', *DELIVERY)),
    ('retained-p1', 'scripts/run_devnet.py', ('--protocol-version','1','--block-history-keep','2')),
    ('product-p3-flat', 'scripts/run_devnet.py', ('--protocol-version','3',*DELIVERY,
                                               '--block-history-keep','2','--product-journey')),
    ('product-p3-smt', 'scripts/run_devnet.py', ('--protocol-version','3','--state-commitment','smt-v1',*DELIVERY,
                                              '--block-history-keep','2','--product-journey')),
    ('state-sync-p1', 'scripts/run_state_sync.py', ('--protocol-version','1')),
    ('state-sync-p3-smt', 'scripts/run_state_sync.py', ('--protocol-version','3','--state-commitment','smt-v1')),
)


def expected_profile(name):
    return next((p for p in PROFILES if p[0] == name), None)


def validate_result(value, profile, source, engine_sha256, process):
    """A status word, test count, or ancestor's report cannot satisfy this matrix."""
    require(process['returncode'] == 0 and not process['timed_out'] and not process['log_truncated'],
            'engine process did not complete cleanly')
    require(type(value) is dict and value.get('status') == 'passed', 'engine scenario did not pass')
    checks=value.get('checks')
    require(type(checks) is list and checks and all(type(c) is dict and c.get('passed') is True for c in checks),
            'missing or failed engine checks')
    names=[c.get('name') for c in checks]
    require(all(type(n) is str and n for n in names), 'engine checks need explicit names')
    # Existing runners intentionally repeat some per-payment check names. Counts
    # are observations, not unique unit-test IDs; do not invent a unique case total.
    require(value.get('engine_sha256') == engine_sha256 and value.get('engine_version','').lstrip('v') == PIN,
            'engine evidence differs from supplied binary')
    provenance=value.get('run_provenance',value.get('source_provenance',{}))
    require(provenance.get('source_commit') == source['commit'] and
            provenance.get('source_tree') == source['tree'] and
            provenance.get('tracked_worktree_dirty') is False,
            'engine result is not for the exact clean source')
    expected=expected_profile(profile);require(expected is not None,'unknown engine profile')
    _,script,args=expected
    sourcefiles={f['path']:f for f in source['files']}
    require(provenance.get('runner_relative_path') == script and
            provenance.get('runner_sha256') == sourcefiles[script]['sha256'] and
            provenance.get('source_manifest_sha256') == sourcefiles['SOURCE_MANIFEST.json']['sha256'],
            'runner bytes or required inventory differ')
    require(value.get('public_network') is False and value.get('real_funds') is False,
            'scope flags differ from local-only acceptance')
    def option(name, default=None):return args[args.index(name)+1] if name in args else default
    require(value.get('native_protocol_version',value.get('protocol_version')) == int(option('--protocol-version')),
            'wrong protocol in scenario report')
    require(value.get('state_commitment') == option('--state-commitment','legacy-flat-v1'),
            'wrong commitment mode in scenario report')
    if '--decision-delivery' in args:
        delivery=value.get('decision_delivery',{})
        require(delivery.get('enabled') is True and delivery.get('status') == 'passed' and
                value.get('wallet_integration_verified') is True and
                delivery.get('receipt_convergence',{}).get('reconciliation_outcome') == 'already_recorded',
                'decision delivery/convergence not verified')
    if '--block-history-keep' in args:
        history=value.get('local_history',{})
        require(history.get('keep_blocks') == 2 and history.get('status') == 'passed' and
                history.get('application_restart_verified') is True, 'bounded-history restart not verified')
    if '--product-journey' in args:
        product=value.get('product_journey',{})
        require(product.get('status') == 'passed' and
                [(r.get('wallet_pending_units'),r.get('explorer_spent_units')) for r in product.get('stages',[])] ==
                [(100,0),(100,60),(40,60),(40,100),(0,100)] and len(product.get('payments',[])) == 2,
                'live product stages missing or mismatched')
        require(len(product.get('verification_after_local_pruning',[])) == 2,
                'archival/indexed receipts after pruning not verified')
    if script == 'scripts/run_state_sync.py':
        require(value.get('state_sync_verified') is True and value.get('continued_execution_verified') is True,
                'fresh-node state sync not verified')
    return len(checks)


def run(engine, expected_engine_sha256, output, *, timeout=300):
    require(os.name == 'posix', 'network matrix requires POSIX')
    require(type(timeout) is int and 60 <= timeout <= 1800, 'invalid scenario timeout')
    require(type(expected_engine_sha256) is str and re.fullmatch('[0-9a-f]{64}',expected_engine_sha256),
            'explicit lowercase engine SHA-256 required')
    output=Path(os.path.abspath(output));root=ROOT.resolve()
    require(not output.is_relative_to(root), 'output must be outside source')
    for ancestor in (output.parent,*output.parent.parents):
        require(not ancestor.is_symlink(),'output ancestor symlink refused')
    source=source_identity(root);inventories=checked_manifests(root)
    output.mkdir(mode=0o700,exist_ok=False)
    report={'schema':1,'status':'unassessed','source_commit':source['commit'],'source_tree':source['tree'],
            'source_id':source['source_id'],'engine_required':PIN,'expected_engine_sha256':expected_engine_sha256,
            'inventories':inventories,'planned_scenarios':[p[0] for p in PROFILES], 'scenarios':[],
            'scope':'one host, disposable local networks only','public_network_ready':False,'real_funds_ready':False,
            'release_status':'blocked','unassessed_remaining':['final-Apply engine kill/restart',
                'retention-enabled five-node state sync (current state-sync profiles use default history)',
                'independent multi-host operations','security review','production custody','economics/genesis']}
    store_json(output/'source.json',source);store_json(output/'started.json',report)
    binary=shutil.which(engine) if '/' not in engine else str(Path(engine).resolve())
    if not binary or not Path(binary).is_file():
        report['reason']='Pinned CometBFT binary absent; no engine or wire scenario executed.'
        store_json(output/'result.json',report);print(json.dumps(report,indent=2));return 2
    try:
        actual=digest(Path(binary).read_bytes());require(actual==expected_engine_sha256,'binary differs from explicit pin')
        version=subprocess.check_output([binary,'version'],text=True,timeout=10).strip()
        require(version.lstrip('v')==PIN,'unsupported CometBFT version')
        report['engine_sha256']=actual;report['engine_version']=version
        # The upstream probe can run go mod tidy. Isolate it on a byte-identical
        # source copy with network dependency fetching disabled: this command never downloads.
        wire=output/'wire';wire.mkdir(mode=0o700);wire_source=wire/'source'
        wire_source.mkdir(mode=0o700)
        for entry in source['files']:
            original=root/entry['path'];destination=wire_source/entry['path']
            raw=original.read_bytes();require(digest(raw)==entry['sha256'],'source changed during probe copy')
            destination.parent.mkdir(parents=True,exist_ok=True)
            destination.write_bytes(raw);destination.chmod(0o755 if entry['mode']=='100755' else 0o644)
        script=wire_source/'scripts/check_upstream_wire.py'
        command=[sys.executable,'-c',
            'import os,runpy,sys;os.environ["GOPROXY"]="off";os.environ["GOTOOLCHAIN"]="local";'
            'os.environ["GOSUMDB"]="off";sys.argv=sys.argv[1:];runpy.run_path(sys.argv[0],run_name="__main__")',
            str(script),'--output',str(wire/'result.json')]
        process=run_process(command,wire_source,wire/'process.log',timeout)
        result=json.loads((wire/'result.json').read_bytes())
        report['wire']={'status':result.get('status'),'process':process,'checks':result.get('checks',[]),
                        'result_sha256':digest((wire/'result.json').read_bytes())}
        if result.get('status')=='unassessed':
            report['reason']='Pinned upstream dependencies unavailable offline; matrix not executed.'
            store_json(output/'result.json',report);print(json.dumps(report,indent=2));return 2
        require(process['returncode']==0 and not process['timed_out'] and not process['log_truncated'] and
                result.get('status')=='passed' and len(result.get('checks',[]))==15 and
                all(c.get('passed') is True for c in result['checks']), 'official snapshot wire check did not pass')
        for name,script,args in PROFILES:
            require(source_identity(root)==source,'source changed before scenario')
            require(digest(Path(binary).read_bytes())==actual,'engine changed during acceptance')
            folder=output/name;folder.mkdir(mode=0o700);path=folder/'result.json'
            process=run_process([sys.executable,str(root/script),'--cometbft',binary,'--output',str(path),*args],
                                root,folder/'process.log',timeout)
            observed=json.loads(path.read_bytes()) if path.is_file() else {}
            item={'name':name,'process':process,'status':observed.get('status','incomplete'),
                  'result_sha256':digest(path.read_bytes()) if path.exists() else None}
            report['scenarios'].append(item)
            store_json(output/'progress.json',report,replace=(output/'progress.json').exists())
            item['observed_checks']=validate_result(observed,name,source,actual,process)
            require(source_identity(root)==source,'source changed in scenario')
        report['status']='passed';report['source_unchanged']=True
        report['engine_unchanged']=digest(Path(binary).read_bytes())==actual
        require(report['engine_unchanged'],'engine changed at completion')
    except Exception as exc:
        report['status']='failed';report['error_type']=type(exc).__name__
    store_json(output/'result.json',report);print(json.dumps(report,indent=2))
    return 0 if report['status']=='passed' else 1


def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--cometbft',required=True);p.add_argument('--engine-sha256',required=True)
    p.add_argument('--output',type=Path,required=True);p.add_argument('--timeout',type=int,default=300)
    a=p.parse_args();return run(a.cometbft,a.engine_sha256,a.output,timeout=a.timeout)

if __name__=='__main__':raise SystemExit(main())
