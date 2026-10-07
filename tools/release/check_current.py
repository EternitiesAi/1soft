#!/usr/bin/env python3
"""Qualify the current clean checkout locally, with explicit whole-repo coverage.

Historical manifests remain records of their original snapshots. This command
binds new results to every current Git byte/mode instead of claiming that a
changed checkout matches those older manifests. No engine, download or deployment.
"""
from __future__ import annotations

import argparse
import hashlib
import importlib.metadata
import importlib.util
import json
import os
from pathlib import Path
import platform
import re
import sys
import unittest
import uuid

import check_release as base

ROOT = Path(__file__).resolve().parents[2]
COMPONENTS = (
    'explorer', 'local-platform', 'private-payments', 'protocol4-client',
    'protocol4-custody', 'protocol4-delivery', 'protocol4-explorer',
    'protocol4-receipts', 'protocol4-recovery', 'protocol4-wallet',
    'receipt-archive', 'release', 'validator-registry', 'validator-transition',
    'wallet-account', 'wallet-delivery', 'shielded-note-lab',
    'privacy-proof-benchmark', 'p8-wallet',
)
COMMON = (['tools/validator-transition/src', 'src', 'tests', 'scripts', 'tools/release']
          + [f'tools/{name}/src' for name in COMPONENTS]
          + [f'tools/{name}/scripts' for name in COMPONENTS]
          + [f'tools/{name}/tests' for name in COMPONENTS])
GROUPS = {'native': ('tests', 'test_*.py', ['src', 'tests', 'scripts', *COMMON])}
GROUPS.update({name.replace('-', '_'): (
    f'tools/{name}/tests',
    'test_account_view.py' if name == 'wallet-account' else 'test_*.py',
    list(dict.fromkeys([f'tools/{name}/src', f'tools/{name}/tests',
                        f'tools/{name}/scripts', *COMMON]))) for name in COMPONENTS})
# This historical journey imports the legacy delivery_fixture.Scenario. P4 has
# a distinct module with the same basename; preserve the journey's own imports.
GROUPS['release'] = ('tools/release/tests', 'test_*.py',
                     list(dict.fromkeys([*base.GROUPS['release'][2], *COMMON])))
GROUPS['shielded_note_lab'] = (
    'tools/shielded-note-lab/tests', 'test_*.py',
    ['tools/shielded-note-lab/src', 'tools/shielded-note-lab/tests'],
)
GROUPS['privacy_proof_benchmark'] = (
    'tools/privacy-proof-benchmark/tests', 'test_*.py',
    ['tools/privacy-proof-benchmark/src', 'tools/privacy-proof-benchmark/tests'],
)
EXCLUDED = {'tools/wallet-account/tests/test_account_catchup.py':
            'optional unpublished wallet_catchup core is absent from this checkout'}
JAVASCRIPT_GROUPS = {'reference': 'reference/kernel.test.mjs',
                     'wallet': 'tools/local-platform/tests/wallet.test.cjs',
                     'history_backup': 'tools/local-platform/tests/backup_history.test.cjs',
                     'alpha_history': 'tools/local-platform/tests/alpha_history.test.cjs',
                     'merchant_resource': 'tools/local-platform/tests/merchant_resource.test.cjs'}
JAVASCRIPT_SCENARIOS = (
    'tools/local-platform/tests/browser_service.test.cjs',
    'tools/local-platform/tests/browser_workflow.test.cjs',
    'tools/local-platform/tests/merchant_resource_browser.test.cjs',
    'tools/private-payments/tests/browser_comet.test.cjs',
    'tools/private-payments/tests/alpha_invoice_browser.test.cjs',
    'tools/private-payments/tests/alpha_resource_browser.test.cjs',
    'tools/p8-wallet/tests/browser_native.test.cjs',
)

PYTHON_ENGINE_SCENARIOS = tuple(dict(
    path='scripts/run_protocol4_state_sync.py',profile=name,status='unassessed',
    reason='requires separate exact-source pinned-engine qualification')
    for name in ('basic','final-apply-crash'))
PRIVACY_BOUNDARIES = (
    'cryptographic proof soundness and formal security review',
    'anonymity, unlinkability, and measured anonymity sets',
    'network, timing, metadata, endpoint, and wallet UX leakage',
    'trusted setup, proving-system implementation, and production key custody',
    'validator enforcement, public-network behavior, and real-funds safety',
)


def load_unique_json_bytes(data):
    def unique_object(pairs):
        value = {}
        for key, item in pairs:
            if key in value:
                raise ValueError('duplicate JSON key: ' + key)
            value[key] = item
        return value

    return json.loads(data, object_pairs_hook=unique_object)


def refuse_python_bytecode(root):
    for directory, names, files in os.walk(root, followlinks=False):
        names[:] = [name for name in names
                    if not Path(directory, name).is_symlink()]
        base.require('__pycache__' not in Path(directory).parts,
                     'stale Python bytecode directory: ' + directory)
        for name in files:
            base.require(not name.endswith('.pyc'),
                         'stale Python bytecode file: ' + str(Path(directory, name)))


def coverage(root):
    """Refuse unknown, missing, empty or silently omitted test components."""
    root = Path(root)
    present = {p.parent.name for p in (root / 'tools').glob('*/tests') if p.is_dir()}
    base.require(present == set(COMPONENTS), 'component coverage map differs from checkout')
    candidates = [*(root / 'tests').rglob('test_*.py'),
                  *(root / 'tools').glob('*/tests/**/test_*.py')]
    all_files = {p.relative_to(root).as_posix() for p in candidates}
    base.require(all(not p.is_symlink() and p.is_file() for p in candidates), 'aliased test refused')
    groups = {}; included = set()
    for name, (directory, pattern, _) in GROUPS.items():
        files = sorted(p.relative_to(root).as_posix() for p in (root / directory).glob(pattern))
        base.require(files, 'empty test group: ' + name)
        base.require(not included.intersection(files), 'duplicate test-file coverage')
        groups[name] = files; included.update(files)
    excluded = sorted(all_files.intersection(EXCLUDED))
    base.require(included | set(excluded) == all_files, 'uncovered test file refused')
    js_candidates = [*(root / 'reference').rglob('*.test.*'),
                     *(root / 'tools').glob('*/tests/**/*.test.*')]
    js_candidates = [p for p in js_candidates if p.suffix in ('.js', '.cjs', '.mjs')]
    base.require(all(not p.is_symlink() and p.is_file() for p in js_candidates),
                 'aliased JavaScript test refused')
    js_files = {p.relative_to(root).as_posix() for p in js_candidates}
    base.require(js_files == set(JAVASCRIPT_GROUPS.values()) | set(JAVASCRIPT_SCENARIOS),
                 'JavaScript coverage map differs from checkout')
    return {'groups': groups, 'test_files': sorted(included),
            'excluded_test_files': excluded, 'exclusion_reasons': EXCLUDED,
            'javascript_groups': JAVASCRIPT_GROUPS,
            'python_engine_scenarios': list(PYTHON_ENGINE_SCENARIOS),
            'privacy_boundaries': [{'area': area, 'status': 'unassessed'} for area in PRIVACY_BOUNDARIES],
            'javascript_scenarios': [
                {'path': path, 'status': 'unassessed',
                 'reason': 'requires separate scenario qualification with an existing browser'}
                for path in JAVASCRIPT_SCENARIOS]}


def javascript_cases(raw, path, summary):
    """Bind the current flat Node cases to their TAP summary and source path."""
    cases = []
    for line in raw.decode('utf-8', errors='strict').splitlines():
        match = re.fullmatch(r'(ok|not ok) ([1-9][0-9]*) - (.+?)(?: # (SKIP|TODO)\b.*)?', line)
        if match:
            status = {'SKIP': 'skipped', 'TODO': 'todo'}.get(
                match[4], 'passed' if match[1] == 'ok' else 'failed')
            cases.append({'number': int(match[2]), 'name': match[3], 'status': status,
                          'id': path + '::' + match[3]})
    base.require([c['number'] for c in cases] == list(range(1, summary['tests'] + 1)),
                 'JavaScript case listing differs from summary')
    base.require(len({c['id'] for c in cases}) == len(cases), 'duplicate JavaScript case identity')
    base.require(sum(c['status'] == 'passed' for c in cases) == summary['pass'],
                 'JavaScript passing cases differ from summary')
    return cases


def javascript_checks(root, output, source, run_id, timeout):
    """Run only the registered key-free Node units; retain each failure separately."""
    fields = ('tests', 'pass', 'fail', 'cancelled', 'skipped', 'todo')
    report = {'source_id': source['source_id'], 'run_id': run_id,
              'groups': [], 'qualified_tests': 0, **dict.fromkeys(fields, 0)}
    for name, path in JAVASCRIPT_GROUPS.items():
        base.require(base.source_identity(root) == source,
                     'source changed before JavaScript group: ' + name)
        log = output / ('javascript-' + name + '.log')
        record = {'schema': 1, 'name': name, 'path': path,
                  'source_id': source['source_id'], 'run_id': run_id,
                  'commit': source['commit'], 'tree': source['tree'],
                  'log': log.name, 'passed': False, 'test_cases': [], **dict.fromkeys(fields, 0)}
        try:
            process = base.run_process(['node', '--test', '--test-reporter=tap', path], root, log, timeout)
            record.update(process)
            raw = log.read_bytes()
            base.require(process['log_sha256'] == base.digest(raw), 'JavaScript log hash differs')
            js = base.javascript_result(raw)
            record.update(js)
            record['test_cases'] = javascript_cases(raw, path, js)
            record['passed'] = (process['returncode'] == 0 and not process['timed_out']
                                and not process['log_truncated'] and js['passed'])
        except Exception as exc:
            record['passed'] = False
            record['error_type'] = type(exc).__name__
        result_path = output / ('javascript-' + name + '.json')
        base.store_json(result_path, record)
        report['groups'].append({**record, 'result': result_path.name,
                                 'result_sha256': base.digest(result_path.read_bytes())})
        for key in fields: report[key] += record[key]
        if record['passed']: report['qualified_tests'] += record['tests']
    base.require(base.source_identity(root) == source, 'source changed during JavaScript checks')
    report['passed'] = all(r['passed'] for r in report['groups'])
    return report


def worker(group, output, source_id, run_id):
    directory, pattern, paths = GROUPS[group]
    paths = list(dict.fromkeys(str(ROOT / p) for p in paths))
    sys.path[:0] = paths
    os.environ['PYTHONPATH'] = os.pathsep.join(paths)
    os.chdir(ROOT)
    suite = unittest.TestLoader().discover(str(ROOT / directory), pattern=pattern)
    expected = [test.id() for test in base.flatten(suite)]

    class Result(unittest.TextTestResult):
        def __init__(self, *args, **kwargs):
            super().__init__(*args, **kwargs); self.ids = []
        def addSuccess(self, test):
            super().addSuccess(test); self.ids.append(test.id())

    result = unittest.TextTestRunner(verbosity=2, resultclass=Result).run(suite)
    report = {'schema': 1, 'group': group, 'source_id': source_id, 'run_id': run_id,
              'expected_ids': expected, 'successful_ids': result.ids, 'run': result.testsRun,
              'skips': len(result.skipped), 'errors': len(result.errors),
              'failures': len(result.failures), 'expected_failures': len(result.expectedFailures),
              'unexpected_successes': len(result.unexpectedSuccesses)}
    report['passed'] = base.successful(report)
    base.store_json(output, report)
    return 0 if report['passed'] else 1


def shielded_note_verification(root, output, source, timeout):
    report_path = output / 'shielded-note-lab-verifier.json'
    log_path = output / 'shielded-note-lab-verifier.log'
    process = base.run_process(
        [sys.executable, str(root / 'tools/shielded-note-lab/tools/verify.py'),
         '--report', str(report_path)], root, log_path, timeout)
    record = {'name': 'shielded_note_lab_verifier', 'passed': False,
              'report': report_path.name, 'log': log_path.name, **process}
    try:
        receipt = load_unique_json_bytes(report_path.read_bytes())
        claims = receipt.get('claims')
        manifest_bytes = (root / 'tools/shielded-note-lab/SOURCE_MANIFEST.json').read_bytes()
        dependency_bytes = (root / 'tools/shielded-note-lab/DEPENDENCIES.json').read_bytes()
        manifest = load_unique_json_bytes(manifest_bytes)
        expected_fields = {'format', 'status', 'tests', 'test_log', 'test_log_sha256',
                           'manifest_sha256', 'source_id', 'commit', 'tree', 'python',
                           'cryptography', 'network_policy', 'network_scope',
                           'network_used', 'blocked_attempts', 'child_network_probe',
                           'claims', 'unassessed'}
        expected_unassessed = ['independent cryptographic review', 'consensus integration',
                               'network anonymity', 'production custody', 'external audit']
        expected_claims = {'production_privacy': False, 'zero_knowledge': False,
                           'consensus_integrated': False, 'public_network': False,
                           'real_funds': False}
        expected_tests = sorted(manifest['tests'])
        hashes = ('test_log_sha256', 'manifest_sha256', 'source_id')
        git_ids = ('commit', 'tree')
        record['report_sha256'] = base.digest(report_path.read_bytes())
        record['receipt'] = {key: receipt.get(key) for key in expected_fields}
        record['passed'] = (
            set(receipt) == expected_fields
            and process['returncode'] == 0 and not process['timed_out']
            and not process['log_truncated']
            and type(receipt.get('format')) is int and receipt['format'] == 1
            and receipt.get('status') == 'passed'
            and receipt.get('commit') == source['commit']
            and receipt.get('tree') == source['tree']
            and receipt.get('tests') == expected_tests
            and type(receipt.get('test_log')) is str
            and all(type(receipt.get(name)) is str and
                    re.fullmatch(r'[0-9a-f]{64}', receipt[name]) for name in hashes)
            and all(type(receipt.get(name)) is str and
                    re.fullmatch(r'[0-9a-f]{40}', receipt[name]) for name in git_ids)
            and receipt['manifest_sha256'] == hashlib.sha256(manifest_bytes).hexdigest()
            and receipt['source_id'] == hashlib.sha256(manifest_bytes + dependency_bytes).hexdigest()
            and receipt['test_log_sha256'] == hashlib.sha256(
                receipt['test_log'].encode('utf-8')).hexdigest()
            and receipt['python'] == sys.version
            and receipt['cryptography'] == importlib.metadata.version('cryptography')
            and receipt['network_policy'] == 'python-process-and-python-child-deny'
            and receipt['network_scope'] == (
                'Python socket and DNS APIs in verifier process and Python children; '
                'non-Python child and direct os spawn/exec entrypoints refused')
            and receipt.get('network_used') is False
            and type(receipt.get('blocked_attempts')) is int
            and receipt.get('blocked_attempts') > 0
            and receipt.get('child_network_probe') == 'blocked-before-child-user-network'
            and receipt.get('unassessed') == expected_unassessed
            and type(claims) is dict and set(claims) == set(expected_claims)
            and all(type(value) is bool and value is False for value in claims.values())
            and claims == expected_claims)
    except (OSError, ValueError, TypeError, json.JSONDecodeError) as exc:
        record['error_type'] = type(exc).__name__
    base.store_json(output / 'shielded-note-lab-verifier-result.json', record)
    return record


def privacy_proof_verification(root, output, source, timeout):
    report_path = output / 'privacy-proof-benchmark-verifier.json'
    log_path = output / 'privacy-proof-benchmark-verifier.log'
    process = base.run_process(
        [sys.executable, str(root / 'tools/privacy-proof-benchmark/tools/verify.py'),
         '--report', str(report_path), '--timeout', str(timeout)],
        root, log_path, timeout + 30)
    record = {'name': 'privacy_proof_benchmark_verifier', 'passed': False,
              'report': report_path.name, 'log': log_path.name, **process}

    def evidence_file(name, expected, sha256, size):
        if (type(name) is not str or name != expected or Path(name).name != name
                or type(sha256) is not str or not re.fullmatch(r'[0-9a-f]{64}', sha256)
                or type(size) is not int or size < 0):
            return False
        path = output / name
        return (path.is_file() and not path.is_symlink()
                and path.stat().st_size == size
                and base.digest(path.read_bytes()) == sha256)

    try:
        receipt_bytes = report_path.read_bytes()
        receipt = load_unique_json_bytes(receipt_bytes)
        component = root / 'tools/privacy-proof-benchmark'
        manifest_bytes = (component / 'SOURCE_MANIFEST.json').read_bytes()
        dependency_bytes = (component / 'DEPENDENCIES.json').read_bytes()
        manifest = load_unique_json_bytes(manifest_bytes)
        expected_fields = {'format', 'status', 'commit', 'tree', 'manifest_sha256',
                           'source_id', 'circuit_source_digest', 'python', 'go',
                           'python_tests', 'go_tests', 'logs', 'backend_receipt',
                           'network_policy', 'network_used', 'claims', 'unassessed'}
        expected_manifest_fields = {'format', 'package', 'files', 'python_tests',
                                    'go_tests', 'rust_tests', 'circuit_files',
                                    'halo2_circuit_files'}
        base.require(set(manifest) == expected_manifest_fields,
                     'invalid privacy proof manifest fields')
        circuit_hash = hashlib.sha256()
        for relative in manifest['circuit_files']:
            data = (component / relative).read_bytes()
            circuit_hash.update(relative.encode('utf-8'))
            circuit_hash.update(b'\0')
            circuit_hash.update(str(len(data)).encode('ascii'))
            circuit_hash.update(b'\0')
            circuit_hash.update(data)
        expected_circuit_digest = circuit_hash.hexdigest()

        module_path = component / 'src/privacy_proof_benchmark.py'
        spec = importlib.util.spec_from_file_location(
            '_one_soft_privacy_proof_benchmark', module_path)
        base.require(spec is not None and spec.loader is not None,
                     'privacy proof contract loader unavailable')
        contract = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(contract)

        logs = receipt.get('logs')
        base.require(type(logs) is dict and set(logs) == {
            'python', 'go_test', 'go_build', 'benchmark'}, 'invalid proof logs')
        python_log = logs['python']
        base.require(type(python_log) is dict
                     and set(python_log) == {'path', 'sha256', 'bytes'},
                     'invalid Python proof log')
        evidence_ok = evidence_file(
            python_log['path'], 'privacy-proof-benchmark-verifier.python.log',
            python_log['sha256'], python_log['bytes'])
        process_log_fields = {'returncode', 'seconds_ns', 'log',
                              'log_sha256', 'log_bytes'}
        expected_log_names = {
            'go_test': 'privacy-proof-benchmark-verifier.go-test.log',
            'go_build': 'privacy-proof-benchmark-verifier.go-build.log',
            'benchmark': 'privacy-proof-benchmark-verifier.benchmark.log',
        }
        for name, expected_name in expected_log_names.items():
            value = logs[name]
            evidence_ok = evidence_ok and (
                type(value) is dict and set(value) == process_log_fields
                and type(value['returncode']) is int and value['returncode'] == 0
                and type(value['seconds_ns']) is int and value['seconds_ns'] > 0
                and evidence_file(value['log'], expected_name,
                                  value['log_sha256'], value['log_bytes']))

        backend_record = receipt.get('backend_receipt')
        base.require(type(backend_record) is dict
                     and set(backend_record) == {'path', 'sha256', 'bytes', 'value'},
                     'invalid backend receipt binding')
        evidence_ok = evidence_ok and evidence_file(
            backend_record['path'], 'privacy-proof-benchmark-verifier.backend.json',
            backend_record['sha256'], backend_record['bytes'])
        backend_value = contract.validate_backend_receipt(
            backend_record['value'], expected_commit=source['commit'],
            expected_tree=source['tree'],
            expected_circuit_digest=expected_circuit_digest)
        backend_bytes = (output / backend_record['path']).read_bytes()
        evidence_ok = evidence_ok and (
            contract.load_unique_json_bytes(backend_bytes) == backend_value)

        claims = receipt.get('claims')
        record['report_sha256'] = base.digest(receipt_bytes)
        record['receipt'] = {key: receipt.get(key) for key in expected_fields}
        record['passed'] = (
            set(receipt) == expected_fields
            and process['returncode'] == 0 and not process['timed_out']
            and not process['log_truncated']
            and type(receipt.get('format')) is int and receipt['format'] == 1
            and receipt.get('status') == 'passed'
            and receipt.get('commit') == source['commit']
            and receipt.get('tree') == source['tree']
            and receipt.get('manifest_sha256') == hashlib.sha256(manifest_bytes).hexdigest()
            and receipt.get('source_id') == hashlib.sha256(
                manifest_bytes + dependency_bytes).hexdigest()
            and receipt.get('circuit_source_digest') == expected_circuit_digest
            and receipt.get('python') == sys.version
            and type(receipt.get('go')) is str and receipt['go'].startswith('go version go')
            and receipt.get('python_tests') == manifest['python_tests']
            and receipt.get('go_tests') == manifest['go_tests']
            and evidence_ok
            and receipt.get('network_policy') == 'linux-user-and-network-namespace'
            and receipt.get('network_used') is False
            and type(claims) is dict and claims == contract.EXPECTED_CLAIMS
            and all(type(value) is bool and value is False for value in claims.values())
            and receipt.get('unassessed') == list(contract.EXPECTED_UNASSESSED))
    except (OSError, ValueError, TypeError, json.JSONDecodeError) as exc:
        record['error_type'] = type(exc).__name__
    base.store_json(output / 'privacy-proof-benchmark-verifier-result.json', record)
    return record



def privacy_proof_halo2_verification(root, output, source, timeout):
    """Run and independently bind the strict Rust/Halo2 evidence receipt."""
    report_path = output / 'privacy-proof-benchmark-halo2-verifier.json'
    log_path = output / 'privacy-proof-benchmark-halo2-verifier.log'
    process = base.run_process([sys.executable, str(root / 'tools/privacy-proof-benchmark/tools/verify_halo2.py'),
                                '--report', str(report_path), '--timeout', str(timeout)],
                               root, log_path, timeout + 30)
    record = {'name': 'privacy_proof_halo2_verifier', 'passed': False,
              'report': report_path.name, 'log': log_path.name, **process}
    try:
        component = root / 'tools/privacy-proof-benchmark'
        manifest_bytes = (component / 'SOURCE_MANIFEST.json').read_bytes()
        dependency_bytes = (component / 'DEPENDENCIES_HALO2.json').read_bytes()
        manifest = load_unique_json_bytes(manifest_bytes)
        receipt_bytes = report_path.read_bytes()
        receipt = load_unique_json_bytes(receipt_bytes)
        expected_manifest = {'format', 'package', 'files', 'python_tests', 'go_tests',
                             'rust_tests', 'circuit_files', 'halo2_circuit_files'}
        base.require(set(manifest) == expected_manifest
                     and type(manifest.get('format')) is int and manifest['format'] == 2
                     and manifest.get('package') == 'privacy-proof-benchmark',
                     'invalid Halo2 proof manifest')
        digest = hashlib.sha256()
        for relative in manifest['halo2_circuit_files']:
            data = (component / relative).read_bytes()
            digest.update(relative.encode('utf-8')); digest.update(b'\0')
            digest.update(str(len(data)).encode('ascii')); digest.update(b'\0'); digest.update(data)
        spec = importlib.util.spec_from_file_location('_one_soft_privacy_proof_benchmark_halo2',
                                                       component / 'src/privacy_proof_benchmark.py')
        base.require(spec is not None and spec.loader is not None, 'Halo2 contract loader unavailable')
        contract = importlib.util.module_from_spec(spec); spec.loader.exec_module(contract)
        expected_fields = {'format', 'status', 'commit', 'tree', 'manifest_sha256', 'source_id',
                           'circuit_source_digest', 'python', 'rustc', 'cargo', 'python_tests',
                           'rust_tests', 'logs', 'backend_receipt', 'network_policy',
                           'network_used', 'claims', 'unassessed'}
        logs = receipt.get('logs')
        base.require(type(logs) is dict and set(logs) == {'python', 'rust_test', 'rust_build', 'benchmark'},
                     'invalid Halo2 proof logs')
        py = logs['python']
        py_path = output / py.get('path', '') if type(py) is dict else output / ''
        evidence_ok = (type(py) is dict and set(py) == {'path', 'sha256', 'bytes'}
                       and py.get('path') == 'privacy-proof-benchmark-halo2-verifier.python.log'
                       and py_path.is_file() and py_path.stat().st_size == py.get('bytes')
                       and base.digest(py_path.read_bytes()) == py.get('sha256'))
        for name, suffix in (('rust_test', 'rust-test'), ('rust_build', 'rust-build'), ('benchmark', 'benchmark')):
            value = logs[name]; expected = f'privacy-proof-benchmark-halo2-verifier.{suffix}.log'
            path = output / expected
            evidence_ok = evidence_ok and type(value) is dict and set(value) == {
                'returncode', 'seconds_ns', 'log', 'log_sha256', 'log_bytes'}
            evidence_ok = evidence_ok and value.get('log') == expected and value.get('returncode') == 0
            evidence_ok = evidence_ok and type(value.get('seconds_ns')) is int and value['seconds_ns'] > 0
            evidence_ok = evidence_ok and path.is_file() and path.stat().st_size == value.get('log_bytes')
            evidence_ok = evidence_ok and base.digest(path.read_bytes()) == value.get('log_sha256')
        backend_record = receipt.get('backend_receipt')
        base.require(type(backend_record) is dict and set(backend_record) == {'path', 'sha256', 'bytes', 'value'},
                     'invalid Halo2 backend receipt binding')
        backend_path = output / backend_record['path']
        base.require(backend_record['path'] == 'privacy-proof-benchmark-halo2-verifier.backend.json'
                     and backend_path.is_file() and not backend_path.is_symlink(),
                     'invalid Halo2 backend receipt path')
        backend_value = contract.validate_halo2_backend_receipt(
            backend_record['value'], expected_commit=source['commit'], expected_tree=source['tree'],
            expected_circuit_digest=digest.hexdigest())
        evidence_ok = evidence_ok and backend_path.stat().st_size == backend_record['bytes']
        evidence_ok = evidence_ok and base.digest(backend_path.read_bytes()) == backend_record['sha256']
        evidence_ok = evidence_ok and load_unique_json_bytes(backend_path.read_bytes()) == backend_value
        claims = receipt.get('claims')
        record['report_sha256'] = base.digest(receipt_bytes)
        record['receipt'] = {key: receipt.get(key) for key in expected_fields}
        record['passed'] = (set(receipt) == expected_fields and process['returncode'] == 0
            and not process['timed_out'] and not process['log_truncated']
            and type(receipt.get('format')) is int and receipt.get('format') == 1
            and receipt.get('status') == 'passed' and receipt.get('commit') == source['commit']
            and receipt.get('tree') == source['tree']
            and receipt.get('manifest_sha256') == hashlib.sha256(manifest_bytes).hexdigest()
            and receipt.get('source_id') == hashlib.sha256(manifest_bytes + dependency_bytes).hexdigest()
            and receipt.get('circuit_source_digest') == digest.hexdigest()
            and receipt.get('python') == sys.version
            and re.fullmatch(r'rustc 1[.]97[.]1 [(][0-9a-f]+ [0-9]{4}-[0-9]{2}-[0-9]{2}[)]',
                             receipt.get('rustc', '')) is not None
            and re.fullmatch(r'cargo 1[.]97[.]1 [(][0-9a-f]+ [0-9]{4}-[0-9]{2}-[0-9]{2}[)]',
                             receipt.get('cargo', '')) is not None
            and receipt.get('python_tests') == manifest['python_tests']
            and receipt.get('rust_tests') == manifest['rust_tests'] and evidence_ok
            and receipt.get('network_policy') == 'linux-user-and-network-namespace'
            and receipt.get('network_used') is False
            and claims == contract.EXPECTED_CLAIMS
            and all(type(value) is bool and value is False for value in claims.values())
            and receipt.get('unassessed') == list(contract.EXPECTED_HALO2_UNASSESSED))
    except (OSError, ValueError, TypeError, json.JSONDecodeError, KeyError) as exc:
        record['error_type'] = type(exc).__name__
    base.store_json(output / 'privacy-proof-benchmark-halo2-verifier-result.json', record)
    return record

def run(output, timeout=600):
    base.require(os.name == 'posix', 'current checker requires POSIX process isolation')
    base.require(type(timeout) is int and 30 <= timeout <= 1800, 'invalid per-group timeout')
    root = ROOT.resolve(); output = Path(os.path.abspath(output))
    base.require(not output.is_relative_to(root), 'evidence output must be outside checkout')
    for parent in (output.parent, *output.parent.parents):
        base.require(not parent.is_symlink(), 'output ancestor symlink refused')
    refuse_python_bytecode(root)
    source = base.source_identity(root)
    profile = coverage(root)
    installed = {}
    for line in (root / 'requirements.txt').read_text().splitlines():
        if not line.strip() or line.lstrip().startswith('#'): continue
        name, version = line.strip().split('==')
        installed[name] = importlib.metadata.version(name)
        base.require(installed[name] == version, 'installed dependency differs from pin: ' + name)
    output.mkdir(mode=0o700, exist_ok=False)
    run_id = uuid.uuid4().hex
    report = {'schema': '1soft-current-check-v1', 'run_id': run_id,
              'source_id': source['source_id'], 'commit': source['commit'], 'tree': source['tree'],
              'tracked_files': source['tracked_files'], 'coverage': profile,
              'historical_manifests': 'retained as historical snapshots; no current-match claim',
              'groups': [], 'python_tests': 0, 'distinct_python_test_ids': 0,
              'scenario_qualification': profile['javascript_scenarios'] + profile['python_engine_scenarios'],
              'environment': {'python': sys.version.split()[0], 'platform': platform.platform(),
                              'dependencies': installed},
              **base.release_status(False)}
    base.store_json(output / 'source.json', source)
    base.store_json(output / 'started.json', report)
    completed_ids = set()
    try:
        for group in GROUPS:
            base.require(base.source_identity(root) == source, 'source changed before group: ' + group)
            result_path = output / (group + '.json')
            process = base.run_process(
                [sys.executable, str(root / 'tools/release/check_current.py'), '--worker', group,
                 '--output', str(result_path), '--source-id', source['source_id'], '--run-id', run_id],
                root, output / (group + '.log'), timeout)
            child = json.loads(result_path.read_bytes()) if result_path.is_file() else {}
            passed = base.valid_child(child, process, group, source['source_id'], run_id)
            record = {'name': group, 'passed': passed, 'tests': child.get('run', 0), **process}
            if result_path.is_file(): record['result_sha256'] = base.digest(result_path.read_bytes())
            report['groups'].append(record)
            if passed:
                report['python_tests'] += child['run']
                completed_ids.update(child['successful_ids'])
                report['distinct_python_test_ids'] = len(completed_ids)
            base.store_json(output / 'progress.json', report, replace=(output / 'progress.json').exists())
        report['javascript'] = javascript_checks(root, output, source, run_id, timeout)
        report['shielded_note_lab_verifier'] = shielded_note_verification(
            root, output, source, timeout)
        report['privacy_proof_benchmark_verifier'] = privacy_proof_verification(
            root, output, source, timeout)
        report['privacy_proof_halo2_verifier'] = privacy_proof_halo2_verification(root, output, source, timeout)
        base.require(base.source_identity(root) == source, 'source changed during local checks')
        report['source_unchanged'] = True
        passed = (all(group['passed'] for group in report['groups'])
                  and report['javascript']['passed']
                  and report['shielded_note_lab_verifier']['passed']
                  and report['privacy_proof_benchmark_verifier']['passed']
                  and report['privacy_proof_halo2_verifier']['passed'])
        report.update(base.release_status(passed))
    except BaseException as exc:
        report['error_type'] = type(exc).__name__
    report['incomplete_groups'] = [g for g in GROUPS if g not in {r['name'] for r in report['groups']}]
    report['incomplete_javascript_groups'] = [
        g for g in JAVASCRIPT_GROUPS
        if g not in {r['name'] for r in report.get('javascript', {}).get('groups', [])}]
    base.store_json(output / 'result.json', report)
    print(json.dumps({k: report[k] for k in ('commit', 'tree', 'python_tests', 'local_checks',
          'release_status', 'groups', 'incomplete_groups', 'incomplete_javascript_groups')},
          indent=2), flush=True)
    return 0 if report['local_checks'] == 'passed' else 1


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--timeout', type=int, default=600)
    parser.add_argument('--worker', choices=tuple(GROUPS), help=argparse.SUPPRESS)
    parser.add_argument('--source-id', help=argparse.SUPPRESS)
    parser.add_argument('--run-id', help=argparse.SUPPRESS)
    args = parser.parse_args()
    if args.worker: return worker(args.worker, args.output, args.source_id, args.run_id)
    return run(args.output, args.timeout)


if __name__ == '__main__':
    raise SystemExit(main())
