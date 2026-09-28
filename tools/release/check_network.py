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
NATIVE_CORE_CHECKS = (
    'four actual CometBFT processes',
    'fresh chain producing blocks',
    'native transfer independently signature/inclusion verified',
    '3 of 4 continue',
    '2 of 4 do not advance during measured interval',
    'quorum restoration resumes progress',
    'stale validator rejoins',
    'four applications agree at common height',
    'native test supply conserved',
    'all intended native operations recorded',
    'native receipts independently certified against genesis',
    'read-only client collected and verified actual RPC receipt',
    'four committed block records agree',
    'block record matches signed next-header state commitment',
)
P1_CHECKS = (
    'owner grant independently signature/inclusion verified',
    'agent transfer independently signature/inclusion verified',
    'owner fence independently signature/inclusion verified',
    'old authority rejected by node admission',
)
P2_CHECKS = (
    'onboard signed native account independently signature/inclusion verified',
    'rotate continuing account key independently signature/inclusion verified',
    'replacement key payment independently signature/inclusion verified',
    'retired account key rejected',
    'pre-rotation grant rejected',
    'duplicate onboarding cannot reset identity',
    'rotated account retains stable identity and expected balance',
    'same-named grants remain owner-scoped',
)
P3_CHECKS = (
    'shared budget creation independently signature/inclusion verified',
    'first worker payment signed by certified wallet against real validator state',
    'second worker overcommit refused before vault unlock',
    'second worker boundary payment signed by certified wallet against real validator state',
    'older first receipt is already recorded after cold reopen',
    'revisiting receipt preserves wallet transport and RPC counts',
)
SMT_CHECKS = (
    'compact accounts query accepted',
    'compact accounts proof independently verified',
    'compact receipts query accepted',
    'compact receipts proof independently verified',
    'compact receipt binds exact original transfer',
)
SYNC_CORE_CHECKS = (
    'four source validators are producing blocks',
    'pre-snapshot native transfer committed',
    'state-sync trust height/hash captured from running source chain',
    'fresh non-validator application was installed through state sync',
    'restored marker AppHash matches source block at that exact height',
    'restored application did not invent source block metadata at snapshot height',
    'post-snapshot transfer committed on source chain',
    'source chain head is stable after quorum loss',
    'state-synced node continued through ordinary block sync',
    'source and state-synced applications agree at frozen head',
    'post-snapshot transaction exists in target native receipt history',
    'state-sync provenance marker survives later block execution',
    'target block metadata starts strictly after restored snapshot',
    'target durable application checkpoint equals source checkpoint',
)


def expected_profile(name):
    return next((p for p in PROFILES if p[0] == name), None)


def hex_sha256(value):
    return type(value) is str and re.fullmatch('[0-9a-f]{64}', value) is not None


def exact_int(value, expected):
    return type(value) is int and value == expected


def named_check(checks, name):
    matches = [check for check in checks if check['name'] == name]
    require(len(matches) == 1, 'missing or duplicate semantic engine check: ' + name)
    return matches[0]


def retained_snapshot(value, keep, receipt_count):
    if type(value) is not dict or type(value.get('availability')) is not dict:
        return False
    availability = value['availability']; height = value.get('application_height')
    return (value.get('scope') == 'local_application_block_results'
            and type(height) is int and height > keep
            and exact_int(availability.get('bootstrap_height'), 0)
            and exact_int(availability.get('keep_blocks'), keep)
            and exact_int(availability.get('pruned_through'), height - keep)
            and exact_int(availability.get('retained_count'), keep)
            and exact_int(availability.get('retained_from'), height - keep + 1)
            and exact_int(availability.get('retained_through'), height)
            and availability.get('within_configured_window') is True
            and exact_int(value.get('native_receipt_count'), receipt_count)
            and value.get('native_receipts_pruned') is False
            and exact_int(value.get('cometbft_retain_height'), 0)
            and value.get('engine_history_pruning_requested') is False
            and value.get('historical_transaction_absence_proven') is False
            and value.get('total_storage_bounded') is False)


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
    require(exact_int(value.get('native_protocol_version',value.get('protocol_version')),
                      int(option('--protocol-version'))),
            'wrong protocol in scenario report')
    require(value.get('state_commitment') == option('--state-commitment','legacy-flat-v1'),
            'wrong commitment mode in scenario report')
    for check_name in (SYNC_CORE_CHECKS if script == 'scripts/run_state_sync.py' else NATIVE_CORE_CHECKS):
        named_check(checks, check_name)
    if script == 'scripts/run_devnet.py':
        if profile in ('native-p1', 'retained-p1'):
            specific = P1_CHECKS
        elif profile == 'native-p2':
            specific = P1_CHECKS + P2_CHECKS
        else:
            specific = P3_CHECKS
        for check_name in specific:
            named_check(checks, check_name)
        if profile in ('native-p3-smt', 'product-p3-smt'):
            for check_name in SMT_CHECKS:
                named_check(checks, check_name)
    if profile == 'state-sync-p3-smt':
        named_check(checks, 'state-synced SMT node serves a verified compact account proof after continuation')
    if '--decision-delivery' in args:
        delivery=value.get('decision_delivery',{})
        require(delivery.get('enabled') is True and delivery.get('status') == 'passed' and
                value.get('wallet_integration_verified') is True and
                delivery.get('receipt_convergence',{}).get('reconciliation_outcome') == 'already_recorded',
                'decision delivery/convergence not verified')
        payments=delivery.get('payments');transport=delivery.get('transport',{})
        transport_payments=transport.get('payments')
        expected_names=('first worker payment','second worker boundary payment')
        require(type(payments) is list and len(payments) == 2 and
                type(transport_payments) is list and len(transport_payments) == 2 and
                all(type(row) is dict for row in payments + transport_payments) and
                [row.get('name') for row in payments] == list(expected_names) and
                [row.get('name') for row in transport_payments] == list(expected_names),
                'two exact delivery and transport payment records required')
        require(transport.get('endpoint_scope') == 'loopback-only' and
                exact_int(transport.get('forwarded_payment_submissions'), 2) and
                type(transport.get('read_only_rpc_requests')) is int and
                transport['read_only_rpc_requests'] > 0 and
                type(transport.get('http_methods_seen')) is list and
                bool(transport['http_methods_seen']) and
                all(method == 'POST' for method in transport['http_methods_seen']) and
                transport.get('unexpected_http_methods') == [] and
                transport.get('unexpected_requests') == [],
                'delivery transport did not preserve bounded loopback read/submission scope')
        for index,(payment,witness) in enumerate(zip(payments,transport_payments)):
            require(hex_sha256(payment.get('decision_id')) and
                    hex_sha256(payment.get('native_txid')) and
                    hex_sha256(payment.get('wire_sha256')) and
                    exact_int(payment.get('submission_attempts'), 1) and
                    witness.get('wire_sha256') == payment['wire_sha256'] and
                    exact_int(witness.get('upstream_http_status'), 200) and
                    exact_int(witness.get('upstream_check_tx_code'), 0) and
                    witness.get('upstream_tx_hash_matches') is True and
                    witness.get('downstream_reply_dropped') is (index == 0) and
                    witness.get('downstream_reply_forwarded') is (index == 1),
                    'delivery payment identity, CheckTx, submission or reply-loss evidence differs')
        revisit=delivery['receipt_convergence']
        require(revisit.get('native_txid') == payments[0]['native_txid'] and
                revisit.get('wire_sha256') == payments[0]['wire_sha256'] and
                exact_int(revisit.get('submission_attempts'), 1) and
                revisit.get('network_requested') is False and
                revisit.get('wallet_sync_performed') is False and
                revisit.get('signing_performed') is False,
                'cold-reopened older receipt was not exact read-only convergence')
        named_check(checks,'two exact worker payments were forwarded once with no unexpected HTTP methods or RPC requests')
    if '--block-history-keep' in args:
        history=value.get('local_history',{})
        receipts=value.get('final_state',{}).get('native',{}).get('receipts')
        before,after,nodes=(history.get('before_restart'),history.get('after_restart'),
                            history.get('nodes'))
        require(history.get('enabled') is True and exact_int(history.get('keep_blocks'), 2) and
                history.get('status') == 'passed' and
                history.get('application_restart_verified') is True and
                type(receipts) is list and bool(receipts) and
                type(nodes) is list and len(nodes) == 4 and
                retained_snapshot(before,2,len(receipts)) and
                retained_snapshot(after,2,len(receipts)) and
                after['application_height'] > before['application_height'] and
                all(retained_snapshot(node,2,len(receipts)) for node in nodes),
                'bounded-history restart/window/receipt evidence incomplete')
        require(named_check(checks,'retention survives actual application and engine restart without a repeated flag').get('details') ==
                {'before':before,'after':after} and
                named_check(checks,'all four applications retain the bounded local window without pruning native receipts').get('details') == nodes,
                'retention check details differ from report snapshots')
    if '--product-journey' in args:
        product=value.get('product_journey',{})
        stages=product.get('stages');product_payments=product.get('payments')
        pruned=product.get('verification_after_local_pruning')
        expected_stages=(('both-signed',100,0),('raven-before-reconcile',100,60),
                         ('raven-reconciled',40,60),('atlas-before-reconcile',40,100),
                         ('atlas-reconciled',0,100))
        require(product.get('enabled') is True and product.get('status') == 'passed' and
                product.get('source_node_mutations_by_product_clients') is False and
                product.get('wallet_mutations_by_product_clients') is False and
                product.get('public_network') is False and product.get('real_funds') is False and
                type(stages) is list and len(stages) == 5 and
                all(type(stage) is dict for stage in stages) and
                [(stage.get('stage'),stage.get('wallet_pending_units'),stage.get('explorer_spent_units'))
                 for stage in stages] == list(expected_stages) and
                all(stage.get('wallet_pending_debits_included') is False and
                    type(stage.get('wallet_pending_units')) is int and
                    type(stage.get('explorer_spent_units')) is int and
                    type(stage.get('wallet_state_height')) is int and
                    type(stage.get('explorer_state_height')) is int and
                    hex_sha256(stage.get('explorer_anchor_hash')) and
                    hex_sha256(stage.get('view_sha256')) for stage in stages),
                'live wallet/explorer stages or read-only boundaries missing')
        require(type(product_payments) is list and len(product_payments) == 2 and
                type(pruned) is list and len(pruned) == 2 and
                all(type(row) is dict for row in product_payments + pruned) and
                [row.get('label') for row in product_payments] == ['raven','atlas'],
                'two exact product payments and post-pruning receipts required')
        expected_proof='smt-v1' if option('--state-commitment') == 'smt-v1' else 'legacy-full-state-v1'
        for index,(payment,after_pruning) in enumerate(zip(product_payments,pruned)):
            require(payment.get('txid') == payments[index]['native_txid'] and
                    payment.get('wire_sha256') == payments[index]['wire_sha256'] and
                    all(hex_sha256(payment.get(field)) for field in
                        ('txid','wire_sha256','receipt_sha256','header_hash','evidence_id')) and
                    type(payment.get('inclusion_height')) is int and payment['inclusion_height'] > 0 and
                    payment.get('proof_kind') == expected_proof and
                    after_pruning.get('native_txid') == payment['txid'] and
                    exact_int(after_pruning.get('pruned_block'), payment['inclusion_height']) and
                    after_pruning.get('exact_archived_receipt_verified') is True and
                    after_pruning.get('index_retains_verified_inclusion') is True,
                    'product payment/receipt identity or post-pruning proof differs')
            label=payment['label']
            named_check(checks,label+': explorer and archive bind the exact live receipt without releasing a hold')
            named_check(checks,label+': reopened derived stores preserve both indexed and archived payment')
        named_check(checks,'integrated product stages match signed obligations and recorded spending')
        named_check(checks,'old local payment metadata pruned while exact explorer and archive evidence remain')
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
