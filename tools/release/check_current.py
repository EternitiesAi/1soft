#!/usr/bin/env python3
"""Qualify the current clean checkout locally, with explicit whole-repo coverage.

Historical manifests remain records of their original snapshots. This command
binds new results to every current Git byte/mode instead of claiming that a
changed checkout matches those older manifests. No engine, download or deployment.
"""
from __future__ import annotations

import argparse
import importlib.metadata
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
    'wallet-account', 'wallet-delivery',
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
EXCLUDED = {'tools/wallet-account/tests/test_account_catchup.py':
            'optional unpublished wallet_catchup core is absent from this checkout'}
JAVASCRIPT_GROUPS = {'reference': 'reference/kernel.test.mjs',
                     'wallet': 'tools/local-platform/tests/wallet.test.cjs',
                     'history_backup': 'tools/local-platform/tests/backup_history.test.cjs'}
JAVASCRIPT_SCENARIOS = (
    'tools/local-platform/tests/browser_service.test.cjs',
    'tools/local-platform/tests/browser_workflow.test.cjs',
    'tools/private-payments/tests/browser_comet.test.cjs',
)

PYTHON_ENGINE_SCENARIOS = tuple(dict(
    path='scripts/run_protocol4_state_sync.py',profile=name,status='unassessed',
    reason='requires separate exact-source pinned-engine qualification')
    for name in ('basic','final-apply-crash'))


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


def run(output, timeout=600):
    base.require(os.name == 'posix', 'current checker requires POSIX process isolation')
    base.require(type(timeout) is int and 30 <= timeout <= 1800, 'invalid per-group timeout')
    root = ROOT.resolve(); output = Path(os.path.abspath(output))
    base.require(not output.is_relative_to(root), 'evidence output must be outside checkout')
    for parent in (output.parent, *output.parent.parents):
        base.require(not parent.is_symlink(), 'output ancestor symlink refused')
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
        base.require(base.source_identity(root) == source, 'source changed during local checks')
        report['source_unchanged'] = True
        passed = all(group['passed'] for group in report['groups']) and report['javascript']['passed']
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
