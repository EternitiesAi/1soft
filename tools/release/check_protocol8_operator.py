#!/usr/bin/env python3
"""Closed operator receipt consistency, separate from native/engine execution."""
import argparse
import hashlib
import json
from pathlib import Path
import sys
ROOT = Path(__file__).resolve().parents[2]; sys.path[:0] = [str(ROOT/'src'),str(ROOT/'scripts')]
from run_protocol8_operator import CHECKS
from check_protocol8_recovery import check as recovery_check
import protocol8_operator as operator

def check(report, path):
    operator.require(set(report) == {'format','status','source','recovery_report','recovery_report_sha256',
        'operator','checks','claims'}, 'closed operator result required')
    operator.require(report['format'] == '1soft/protocol8-operator-gate/v1' and
        report['status'] == 'qualified-one-host-operator-workflow', 'operator result unqualified')
    operator.require(report['checks'] == [{'id':n,'passed':True} for n in CHECKS], 'operator checks differ')
    operator.require(report['claims'] == {'actual_operator_cli':True,'one_trusted_host':True,'synthetic_funds':True,
        'engine_provisioned_by_operator':False,'validator_signer_recovery':False,'freshness_established':False,
        'production_ready':False,'public_network':False}, 'operator claims differ')
    name = report['recovery_report']
    operator.require(type(name) is str and Path(name).name == name and name.endswith('.recovery.json'), 'recovery reference differs')
    target = path.parent/name
    raw = target.read_bytes(); operator.require(operator.sha(raw) == report['recovery_report_sha256'], 'recovery hash differs')
    recovery = recovery_check(target)
    operator.require(report['source'] == recovery['source'] and report['source']['clean'] is True, 'source differs')
    e = report['operator']; operator.require(e == recovery['operator'], 'operator evidence differs')
    operator.require(len(e['init']) == len(e['doctor']) == len(e['audit']) == 5 and
        [r['node'] for r in e['init']] == [r['node'] for r in e['doctor']] == [r['node'] for r in e['audit']] == list(range(5)), 'five node identities differ')
    for init, doctor, audit in zip(e['init'], e['doctor'], e['audit']):
        operator.require(init['status'] == 'initialized' and init['database_created'] is False and
            init['native_startup']['valid_proof_verified'] is True and init['native_startup']['corrupt_proof_refused'] is True,
            'native init differs')
        operator.require(doctor['status'] == 'configuration-valid' and doctor['files_unchanged'] is True and
            doctor['database_present'] is False and doctor['native_executed'] is False and
            doctor['store_replay_verified'] is False and doctor['consensus_verified'] is False,
            'static doctor differs')
        operator.require(doctor['pins']['genesis_sha256'] == recovery['genesis_sha256'] and
            doctor['pins']['worker_sha256'] == recovery['inputs']['worker']['sha256'] and
            doctor['pins']['engine_sha256'] == recovery['inputs']['engine']['sha256'], 'pins differ')
        operator.require(audit['status'] == 'local-store-replayed' and audit['consensus_verified'] is False and
            audit['freshness_established'] is False, 'audit authority differs')
        for a in (init['worker_audit'], audit['worker_audit']):
            operator.require(a['call_count'] == a['reaped_count'] and a['timeout_count'] == 0 and a['call_count'] > 0
                and all(c['process_reaped'] is True for c in a['calls']), 'native calls unreaped')
    operator.require(e['bad_pin_refused'] is True and e['duplicate_refused'] is True, 'refusals absent')
    calls = e['invocations']; operator.require(len(calls) == 17 and
        [sum(r['command'] == c for r in calls) for c in ('init','doctor','audit')] == [6,6,5] and
        sum(r['exit_code'] == 1 for r in calls) == 2 and
        len({(r['pid'],r['start_ticks']) for r in calls}) == 17 and
        all(r['process_reaped'] is True and r['exit_code'] in (0,1) for r in calls), 'CLI lifecycle differs')
    script_sha = report['source']['files']['scripts/protocol8_operator.py']['sha256']
    processes = {r['pid']:r for r in recovery['processes']}
    operator.require(len(e['normal_pids']) >= 5 and len(set(e['normal_pids'])) == len(e['normal_pids']) and
        all(pid in processes and processes[pid]['role'] == 'application' and
            processes[pid]['executable_sha256'] == script_sha and processes[pid]['exit_code'] == 0 for pid in e['normal_pids']),
        'normal operator application lifecycle differs')
    expected = next(c['evidence'] for c in recovery['checks'] if c['id'] == 'origin_real_suffix_audited')
    audit = e['audit'][4]
    operator.require(audit['origin_marker'] == expected['origin_marker'] and
        audit['real_response_heights'] == expected['real_local_response_heights'] and
        audit['height'] == expected['checkpoint_height'], 'target origin/suffix differs')

if __name__ == '__main__':
    p = argparse.ArgumentParser(description=__doc__); p.add_argument('report',type=Path); args = p.parse_args()
    check(json.loads(args.report.read_bytes()), args.report)
    print('P8_OPERATOR_CHECK passed: 11 operator checks and 22 actual recovery checks')
