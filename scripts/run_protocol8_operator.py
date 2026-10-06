#!/usr/bin/env python3
"""Qualify the operator CLI through the unchanged actual P8 recovery journey."""
import argparse
import json
import os
from pathlib import Path
import stat
import subprocess
import sys
import time
ROOT = Path(__file__).resolve().parents[1]; sys.path.insert(0, str(ROOT/'src'))
import protocol8_operator as operator
import run_protocol8_recovery as recovery
from run_protocol8_engine import source
from run_protocol5_engine import _application_ready, _stop
from run_devnet import wait_until

CHECKS = ('inherited_actual_recovery_gate', 'five_cli_init_native_validations',
          'five_read_only_doctors', 'bad_external_pin_no_creation', 'duplicate_owner_refused',
          'normal_apps_used_operator_cli', 'normal_apps_gracefully_stopped',
          'five_existing_store_native_audits', 'target_origin_and_suffix_match',
          'all_cli_invocations_reaped', 'source_unchanged')

class Network(recovery.Network):
    def __init__(self, paths, output, report):
        super().__init__(paths, output, report)
        self.operator_evidence = {'init': [], 'doctor': [], 'audit': [], 'invocations': [],
                                  'normal_pids': [], 'test_pids': [], 'bad_pin_refused': False,
                                  'duplicate_refused': False}
        report['operator'] = self.operator_evidence
    def cli(self, command, i, *, bad_pin=False):
        args = [sys.executable, '-B', str(ROOT/'scripts/protocol8_operator.py'), command,
                '--workspace', str(self.runtime/f'app{i}'), '--genesis-sha256',
                'ef'*32 if bad_pin else self.genesis_sha256]
        if command == 'init':
            for key, value in [('genesis', self.genesis_path), ('kat', self.paths['kat']),
                               ('worker', self.paths['worker']), ('engine', self.paths['engine'])]:
                args += ['--'+key, str(value)]
        started = time.monotonic()
        proc = subprocess.Popen(args, stdout=subprocess.PIPE, stderr=subprocess.PIPE, start_new_session=True)
        ticks = int(Path(f'/proc/{proc.pid}/stat').read_text().rsplit(')', 1)[1].split()[19])
        try:
            raw, error = proc.communicate(timeout=240)
        finally:
            if proc.poll() is None:
                proc.kill(); proc.communicate()
            self.operator_evidence['invocations'].append({'command': command, 'node': i,
                'pid': proc.pid, 'start_ticks': ticks, 'exit_code': proc.returncode,
                'process_reaped': proc.poll() is not None,
                'elapsed_seconds': round(time.monotonic()-started, 6)})
        operator.require(not error and len(raw) <= 256*1024, 'CLI response/diagnostics differ')
        value = json.loads(raw)
        if value['status'] == 'refused':
            operator.require(proc.returncode == 1, 'refusal exit code differs')
        else: operator.require(proc.returncode == 0, 'CLI invocation failed')
        return value
    def install_genesis(self, raw, worker):
        super().install_genesis(raw, worker)
        for i in range(5):
            target = self.runtime/f'app{i}'
            # These empty directories were just created by this owned fixture.
            operator.require(not list(target.iterdir()), 'owned fixture unexpectedly nonempty')
            target.rmdir()
            if i == 0:
                refusal = self.cli('init', i, bad_pin=True)
                self.operator_evidence['bad_pin_refused'] = refusal['status'] == 'refused' and not target.exists()
                operator.require(self.operator_evidence['bad_pin_refused'], 'bad pin created workspace')
            self.operator_evidence['init'].append({'node': i, **self.cli('init', i)})
            before = {n: operator.sha((target/n).read_bytes()) for n in operator.REQUIRED}
            result = self.cli('doctor', i)
            after = {n: operator.sha((target/n).read_bytes()) for n in operator.REQUIRED}
            operator.require(before == after, 'doctor changed workspace')
            self.operator_evidence['doctor'].append({'node': i, 'files_unchanged': True, **result})
    def start_app(self, i, *, crash=None):
        if crash is not None:
            super().start_app(i, crash=crash)
            self.operator_evidence['test_pids'].append(self.apps[i].pid)
            return
        endpoint = self.runtime/f'app{i}/a.sock'
        if endpoint.exists():
            # Test-only abrupt exits can leave a socket; remove only the fixture's
            # known terminated test endpoint. The operator CLI never does this.
            old = self.apps.get(i); mode = endpoint.lstat()
            operator.require(old and old.pid in self.operator_evidence['test_pids'] and old.poll() is not None
                             and stat.S_ISSOCK(mode.st_mode) and mode.st_uid == os.getuid(),
                             'unknown operator socket retained')
            endpoint.unlink()
        log = (self.runtime/f'app{i}.log').open('ab'); self.handles.append(log)
        args = [sys.executable, '-B', str(ROOT/'scripts/protocol8_operator.py'), 'serve',
                '--workspace', str(endpoint.parent), '--genesis-sha256', self.genesis_sha256]
        proc = subprocess.Popen(args, stdout=log, stderr=log); self.apps[i] = proc
        self.operator_evidence['normal_pids'].append(proc.pid)
        self._record('application', i, proc, operator.sha((ROOT/'scripts/protocol8_operator.py').read_bytes()))
        wait_until(lambda:_application_ready(self, i, proc, endpoint), 120)
        if not self.operator_evidence['duplicate_refused']:
            response = self.cli('doctor', i)
            self.operator_evidence['duplicate_refused'] = response['status'] == 'refused' and 'busy' in response['reason']
            operator.require(self.operator_evidence['duplicate_refused'], 'duplicate owner accepted')
    def close(self):
        for process in list(self.engines.values())+list(self.apps.values()):
            self._record_exit(process.pid, _stop(process))
        try:
            if all((self.runtime/f'app{i}/operator.json').exists() for i in range(5)):
                for i in range(5):
                    self.operator_evidence['audit'].append({'node': i, **self.cli('audit', i)})
        finally: super().close()

def run(args):
    output = args.output.absolute()
    operator.require(not output.exists(), 'fresh operator result required')
    inner = output.with_name(output.stem+'.recovery.json')
    original = recovery.Network
    recovery.Network = Network
    try:
        params = argparse.Namespace(**vars(args)); params.output = inner
        code = recovery.run(params)
    finally: recovery.Network = original
    r = json.loads(inner.read_bytes()); e = r.get('operator', {})
    by_pid = {p['pid']:p for p in r.get('processes', [])}
    target = next((a for a in e.get('audit', []) if a['node'] == 4), {})
    expected = next((c['evidence'] for c in r['checks'] if c['id'] == 'origin_real_suffix_audited'), {})
    checks = [code == 0, len(e.get('init', [])) == 5 and all(
        x['status'] == 'initialized' and not x['database_created'] and x['native_startup']['valid_proof_verified']
        and x['native_startup']['corrupt_proof_refused'] and x['worker_audit']['call_count'] == x['worker_audit']['reaped_count']
        for x in e.get('init', [])),
        len(e.get('doctor', [])) == 5 and all(x['status'] == 'configuration-valid' and x['files_unchanged']
            and not x['native_executed'] and not x['store_replay_verified'] for x in e.get('doctor', [])),
        e.get('bad_pin_refused') is True, e.get('duplicate_refused') is True,
        len(e.get('normal_pids', [])) >= 5 and all(pid in by_pid for pid in e.get('normal_pids', [])),
        all(by_pid.get(pid, {}).get('exit_code') == 0 for pid in e.get('normal_pids', [])),
        len(e.get('audit', [])) == 5 and all(x['status'] == 'local-store-replayed' and not x['consensus_verified']
            and not x['freshness_established'] and x['worker_audit']['call_count'] == x['worker_audit']['reaped_count']
            for x in e.get('audit', [])),
        target.get('origin_marker') == expected.get('origin_marker') and target.get('real_response_heights') == expected.get('real_local_response_heights')
            and 'origin_marker' in target,
        len(e.get('invocations', [])) == 17 and all(x['process_reaped'] and type(x['exit_code']) is int for x in e.get('invocations', [])),
        source() == r['source']]
    result = {'format': '1soft/protocol8-operator-gate/v1', 'status': 'failed',
        'source': r['source'], 'recovery_report': inner.name, 'recovery_report_sha256': operator.sha(inner.read_bytes()),
        'operator': e, 'checks': [{'id':n,'passed':bool(ok)} for n,ok in zip(CHECKS,checks)],
        'claims': {'actual_operator_cli': True, 'one_trusted_host': True, 'synthetic_funds': True,
            'engine_provisioned_by_operator': False, 'validator_signer_recovery': False,
            'freshness_established': False, 'production_ready': False, 'public_network': False}}
    if all(checks): result['status'] = 'qualified-one-host-operator-workflow'
    output.write_bytes(operator.canonical(result)+b'\n')
    return 0 if all(checks) else 1

if __name__ == '__main__':
    p = argparse.ArgumentParser(description=__doc__)
    for name in ('engine','worker','helper','fixture','prover','kat','output'):
        p.add_argument('--'+name,type=Path,required=True)
    raise SystemExit(run(p.parse_args()))
