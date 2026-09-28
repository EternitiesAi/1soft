#!/usr/bin/env python3
"""One exact-checkout, local release check. No deployment, downloads or Actions.

Local passing tests never authorize a release. Engine/multi-host/custody gates
remain explicitly unassessed. Reports are developer evidence, not attestations
against a malicious local host or a signature over the toolchain.
"""
from __future__ import annotations

import argparse
import hashlib
import importlib.metadata
import json
import os
from pathlib import Path
import platform
import re
import signal
import stat
import subprocess
import sys
import threading
import time
import unittest
import uuid

ROOT = Path(__file__).resolve().parents[2]
LOG_LIMIT = 8 * 1024 * 1024
# Separate interpreters prevent overlapping test_cli/test_http names from reusing
# another add-on's module. Optional unpublished catch-up is deliberately excluded.
GROUPS = {
    'native': ('tests', 'test_*.py', ['src', 'tests', 'scripts']),
    'account': ('tools/wallet-account/tests', 'test_account_view.py',
                ['tools/wallet-account/src', 'src', 'tests']),
    'delivery': ('tools/wallet-delivery/tests', 'test_*.py',
                 ['tools/wallet-delivery/src', 'tools/wallet-delivery/tests',
                  'tools/wallet-account/src', 'src', 'tests', 'scripts']),
    'archive': ('tools/receipt-archive/tests', 'test_*.py',
                ['tools/receipt-archive/src', 'tools/receipt-archive/tests', 'src', 'tests']),
    'explorer': ('tools/explorer/tests', 'test_*.py',
                 ['tools/explorer/src', 'tools/explorer/tests', 'src', 'tests']),
    'release': ('tools/release/tests', 'test_*.py',
                ['tools/release', 'tools/wallet-delivery/src', 'tools/wallet-delivery/tests',
                 'tools/wallet-account/src', 'tools/explorer/src',
                 'tools/receipt-archive/src', 'src', 'tests', 'scripts']),
}
UNASSESSED = [
    'exact-candidate official Go/Python wire compatibility',
    'exact-candidate real validators with default and bounded local history',
    'exact-candidate real-validator wallet -> explorer -> archived receipt journey',
    'exact-candidate fresh-node state sync with continued execution',
    'real-engine final-Apply process kill/restart window',
    'independent multi-host validators and operator fault drills',
    'independent security review, production custody and economic/genesis decisions',
]


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'), allow_nan=False).encode()


def digest(raw):
    return hashlib.sha256(raw).hexdigest()


def require(ok, message):
    if not ok:
        raise ValueError(message)


def git(root, *args):
    return subprocess.check_output(['git', '-C', str(root), *args], timeout=15)


def source_identity(root):
    """Check every tracked byte/mode against HEAD, not only selected manifests."""
    root = Path(root).resolve()
    require(Path(git(root, 'rev-parse', '--show-toplevel').decode().strip()).resolve() == root,
            'source must be the repository root')
    require(not git(root, 'status', '--porcelain', '--untracked-files=normal'),
            'release verification requires a clean tracked/untracked worktree')
    commit = git(root, 'rev-parse', 'HEAD').decode().strip()
    tree = git(root, 'rev-parse', 'HEAD^{tree}').decode().strip()
    entries = []
    for record in git(root, 'ls-tree', '-rz', '--full-tree', 'HEAD').split(b'\0'):
        if not record:
            continue
        metadata, name = record.split(b'\t', 1)
        mode, kind, blob = metadata.decode().split()
        path = name.decode('utf-8'); relative = Path(path)
        require(mode in ('100644', '100755') and kind == 'blob' and
                not relative.is_absolute() and '..' not in relative.parts,
                'source must contain regular tracked files only')
        p = root / relative
        require(not p.is_symlink() and p.is_file(), 'tracked source missing or aliased: ' + path)
        raw = p.read_bytes()
        actual = hashlib.sha1(b'blob ' + str(len(raw)).encode() + b'\0' + raw).hexdigest()
        require(actual == blob, 'tracked bytes differ from Git: ' + path)
        require(bool(p.stat().st_mode & 0o111) == (mode == '100755'), 'tracked mode differs: ' + path)
        entries.append({'path': path, 'mode': mode, 'git_blob': blob,
                        'bytes': len(raw), 'sha256': digest(raw)})
    require(entries, 'empty source checkout')
    material = {'commit': commit, 'tree': tree, 'files': entries}
    return {**material, 'source_id': digest(canonical(material)), 'tracked_files': len(entries)}


def checked_manifests(root):
    paths = ['SOURCE_MANIFEST.json'] + [f'tools/{name}/SOURCE_MANIFEST.json' for name in
            ('wallet-account', 'wallet-delivery', 'receipt-archive', 'explorer')]
    result = []
    for name in paths:
        p = root / name; raw = p.read_bytes(); manifest = json.loads(raw)
        files = manifest['files']; seen = set()
        require(type(files) is list and files, 'empty source inventory')
        for entry in files:
            relative = Path(entry['path'])
            require(not relative.is_absolute() and '..' not in relative.parts and
                    entry['path'] not in seen, 'unsafe or duplicate source inventory entry')
            seen.add(entry['path']); target = p.parent / relative
            require(target.is_file() and not target.is_symlink(), 'manifest source missing')
            data = target.read_bytes()
            require(len(data) == entry['bytes'] and digest(data) == entry['sha256'],
                    'source manifest mismatch: ' + str(relative))
        result.append({'path': name, 'sha256': digest(raw), 'files_matched': len(files)})
    return result


def store_json(path, value, *, replace=False):
    """Persist state before returning. A missing final report stays incomplete."""
    raw = canonical(value) + b'\n'
    temp = path.with_name(path.name + '.new') if replace else path
    fd = os.open(temp, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, 'wb') as f:
        f.write(raw); f.flush(); os.fsync(f.fileno())
    if replace:
        os.replace(temp, path)
    fd = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try: os.fsync(fd)
    finally: os.close(fd)


def flatten(suite):
    for test in suite:
        if isinstance(test, unittest.TestSuite):
            yield from flatten(test)
        else:
            yield test


def successful(report):
    """Zero cases, skip, expected failure, duplicate IDs and partial results fail."""
    try:
        expected, completed = report['expected_ids'], report['successful_ids']
        return (type(expected) is list and type(completed) is list and bool(expected)
                and all(type(x) is str for x in expected + completed)
                and len(set(expected)) == len(expected)
                and sorted(expected) == sorted(completed)
                and type(report['run']) is int and report['run'] == len(expected)
                and all(type(report[k]) is int and report[k] == 0 for k in
                        ('skips', 'failures', 'errors', 'expected_failures', 'unexpected_successes')))
    except (KeyError, TypeError):
        return False


def valid_child(child, process, group, source_id, run_id):
    return (process['returncode'] == 0 and not process['timed_out'] and not process['log_truncated']
            and successful(child) and child.get('group') == group
            and child.get('source_id') == source_id and child.get('run_id') == run_id)


def worker(group, output, source_id, run_id):
    directory, pattern, paths = GROUPS[group]
    paths = [str(ROOT / p) for p in paths]
    sys.path[:0] = paths; os.environ['PYTHONPATH'] = os.pathsep.join(paths)
    os.chdir(ROOT)
    suite = unittest.TestLoader().discover(str(ROOT / directory), pattern=pattern)
    expected = [t.id() for t in flatten(suite)]
    class Result(unittest.TextTestResult):
        def __init__(self, *args, **kw): super().__init__(*args, **kw); self.ids = []
        def addSuccess(self, test): super().addSuccess(test); self.ids.append(test.id())
    result = unittest.TextTestRunner(verbosity=2, resultclass=Result).run(suite)
    report = {'schema': 1, 'group': group, 'source_id': source_id, 'run_id': run_id,
              'expected_ids': expected, 'successful_ids': result.ids, 'run': result.testsRun,
              'skips': len(result.skipped), 'errors': len(result.errors), 'failures': len(result.failures),
              'expected_failures': len(result.expectedFailures),
              'unexpected_successes': len(result.unexpectedSuccesses)}
    report['passed'] = successful(report)
    store_json(output, report)
    return 0 if report['passed'] else 1


def run_process(command, root, log, timeout):
    """Only spawned local test children are terminated. No shell or remote execution."""
    env = {**os.environ, 'PYTHONPATH': '', 'PYTHONUNBUFFERED': '1', 'PYTHONDONTWRITEBYTECODE': '1'}
    started = time.monotonic(); observed = [0]; capture_errors = []
    with log.open('xb') as out:
        os.chmod(log, 0o600)
        proc = subprocess.Popen(command, cwd=root, env=env, stdout=subprocess.PIPE,
                                stderr=subprocess.STDOUT, start_new_session=True)
        def drain():
            try:
                while chunk := proc.stdout.read(65536):
                    left = max(0, LOG_LIMIT - observed[0]); observed[0] += len(chunk)
                    if left: out.write(chunk[:left])
            except Exception:
                capture_errors.append('capture failed')
        thread = threading.Thread(target=drain, daemon=True); thread.start(); timed_out = False
        try:
            proc.wait(timeout=timeout)
        except subprocess.TimeoutExpired:
            timed_out = True
        finally:
            # Tests must not leave descendant servers after the top-level worker.
            try: os.killpg(proc.pid, signal.SIGKILL)
            except ProcessLookupError: pass
            proc.wait(timeout=5); thread.join(timeout=5)
        require(not thread.is_alive() and not capture_errors, 'test log capture incomplete')
        proc.stdout.close(); out.flush(); os.fsync(out.fileno())
    return {'returncode': proc.returncode, 'timed_out': timed_out,
            'seconds': round(time.monotonic() - started, 3), 'observed_log_bytes': observed[0],
            'log_truncated': observed[0] > LOG_LIMIT, 'log_sha256': digest(log.read_bytes())}


def javascript_result(raw):
    fields = {}
    for line in raw.decode('utf-8', errors='replace').splitlines():
        match = re.fullmatch(r'# (tests|pass|fail|cancelled|skipped|todo) (\d+)', line)
        if match:
            require(match[1] not in fields, 'duplicate JavaScript result summary')
            fields[match[1]] = int(match[2])
    require(set(fields) == {'tests', 'pass', 'fail', 'cancelled', 'skipped', 'todo'},
            'incomplete JavaScript result')
    fields['passed'] = (fields['tests'] > 0 and fields['tests'] == fields['pass'] and
                        not any(fields[k] for k in ('fail', 'cancelled', 'skipped', 'todo')))
    return fields


def release_status(local_passed):
    return {'local_checks': 'passed' if local_passed else 'failed', 'release_status': 'blocked',
            'public_network_ready': False, 'real_funds_ready': False,
            'consensus_executed': False, 'unassessed': list(UNASSESSED)}


def run(output, timeout=300):
    require(os.name == 'posix', 'release verifier requires POSIX process isolation')
    require(type(timeout) is int and 30 <= timeout <= 1800, 'invalid per-group timeout')
    root = ROOT.resolve(); output = Path(os.path.abspath(output))
    require(not output.is_relative_to(root), 'evidence output must be outside the source checkout')
    for parent in (output.parent, *output.parent.parents):
        require(not parent.is_symlink(), 'output ancestor symlink refused')
    # All source checks precede test execution and output creation.
    source = source_identity(root); inventories = checked_manifests(root)
    installed = {}
    for line in (root / 'requirements.txt').read_text().splitlines():
        if not line.strip() or line.lstrip().startswith('#'):
            continue
        name, version = line.strip().split('==')
        installed[name] = importlib.metadata.version(name)
        require(installed[name] == version, 'installed dependency differs from pin: ' + name)
    output.mkdir(mode=0o700, exist_ok=False)
    run_id = uuid.uuid4().hex
    report = {'schema': 1, 'run_id': run_id, 'source_id': source['source_id'],
              'commit': source['commit'], 'tree': source['tree'], 'tracked_files': source['tracked_files'],
              'inventories': inventories, 'groups': [], 'python_tests': 0,
              'environment': {'python': sys.version.split()[0], 'platform': platform.platform(),
                  'cryptography': importlib.metadata.version('cryptography'),
                  'protobuf': importlib.metadata.version('protobuf')},
              'excluded': ['unpublished wallet_catchup optional account tests',
                           'browser rendering', 'external/real-engine qualification'],
              **release_status(False)}
    store_json(output / 'source.json', source); store_json(output / 'started.json', report)
    error = None
    try:
        for group in GROUPS:
            require(source_identity(root) == source, 'source changed before group ' + group)
            result_path = output / (group + '.json')
            command = [sys.executable, str(root / 'tools/release/check_release.py'), '--worker', group,
                       '--output', str(result_path), '--source-id', source['source_id'], '--run-id', run_id]
            process = run_process(command, root, output / (group + '.log'), timeout)
            require(not process['timed_out'] and not process['log_truncated'], 'incomplete test process: ' + group)
            child = json.loads(result_path.read_bytes())
            passed = valid_child(child, process, group, source['source_id'], run_id)
            report['groups'].append({'name': group, 'passed': passed, 'tests': child['run'],
                                     'result_sha256': digest(result_path.read_bytes()), **process})
            store_json(output / 'progress.json', report, replace=(output / 'progress.json').exists())
            require(passed, 'local test group failed: ' + group)
            report['python_tests'] += child['run']
        process = run_process(['node', '--test', 'reference/kernel.test.mjs'], root, output / 'javascript.log', timeout)
        js = javascript_result((output / 'javascript.log').read_bytes())
        report['javascript'] = {**js, **process}
        require(process['returncode'] == 0 and not process['timed_out'] and not process['log_truncated']
                and js['passed'], 'JavaScript reference failed')
        require(source_identity(root) == source, 'source changed during local checks')
        report['source_unchanged'] = True
        report.update(release_status(True))
    except BaseException as exc:
        # Diagnostics do not include untrusted stack frames, keys, or test payloads.
        error = exc; report['error_type'] = type(exc).__name__
        report['incomplete_groups'] = [g for g in GROUPS if g not in {v['name'] for v in report['groups']}]
    store_json(output / 'result.json', report)
    print(json.dumps(report, indent=2), flush=True)
    if error is not None:
        print('Release checks did not complete; retained reports do not authorize release.', file=sys.stderr)
    return 0 if report['local_checks'] == 'passed' else 1


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--output', type=Path, required=True, help='New evidence directory, outside source')
    p.add_argument('--timeout', type=int, default=300, help='Deadline per isolated test group')
    p.add_argument('--worker', choices=tuple(GROUPS), help=argparse.SUPPRESS)
    p.add_argument('--source-id', help=argparse.SUPPRESS)
    p.add_argument('--run-id', help=argparse.SUPPRESS)
    a = p.parse_args()
    if a.worker: return worker(a.worker, a.output, a.source_id, a.run_id)
    return run(a.output, a.timeout)


if __name__ == '__main__':
    raise SystemExit(main())
