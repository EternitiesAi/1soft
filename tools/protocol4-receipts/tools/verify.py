#!/usr/bin/env python3
"""Exact-source receipt tests; this does not run consensus or a complete release."""
import argparse
import hashlib
import importlib.metadata
import json
import os
from pathlib import Path
import subprocess
import sys
import unittest

sys.dont_write_bytecode = True
ROOT = Path(__file__).resolve().parents[1]


def checked(root, records):
    seen = set()
    for row in records:
        relative = Path(row['path'])
        if relative.is_absolute() or '..' in relative.parts or relative.as_posix() in seen:
            raise ValueError('invalid manifest path')
        seen.add(relative.as_posix()); target = root / relative
        if any(p.is_symlink() for p in (target, *target.parents)):
            raise ValueError('aliased manifest source')
        raw = target.read_bytes()
        if len(raw) != row['bytes'] or hashlib.sha256(raw).hexdigest() != row['sha256']:
            raise ValueError('source bytes differ: ' + relative.as_posix())
    return len(seen)


def ids(items):
    for test in items:
        if isinstance(test, unittest.TestSuite): yield from ids(test)
        else: yield test.id()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--native-root', type=Path, default=ROOT.parents[1])
    parser.add_argument('--report', type=Path)
    args = parser.parse_args(); native = args.native_root.resolve()
    dependencies = json.loads((ROOT / 'DEPENDENCIES.json').read_bytes())
    own = json.loads((ROOT / 'SOURCE_MANIFEST.json').read_bytes())
    before = {'receipts': checked(ROOT, own['files']),
              'pinned_base_dependencies': checked(native, dependencies['files'])}
    head = subprocess.run(['git', '-C', str(native), 'rev-parse', 'HEAD'],
                          check=True, capture_output=True, text=True).stdout.strip()
    if head != dependencies['parent_commit']:
        raise ValueError('base commit differs; explicit requalification required')
    packages = {}
    for line in (native / 'requirements.txt').read_text().splitlines():
        if not line.strip() or line.lstrip().startswith('#'): continue
        name, version = line.split('=='); packages[name] = importlib.metadata.version(name)
        if packages[name] != version: raise ValueError('installed dependency differs')
    paths = [ROOT / 'src', ROOT / 'tests', native / 'tools/protocol4-client/src',
             native / 'tools/protocol4-client/tests', native / 'src',
             native / 'tools/validator-transition/src', native / 'tools/protocol4-wallet/src',
             native / 'tools/protocol4-wallet/tests', native / 'tools/protocol4-delivery/src',
             native / 'tools/protocol4-delivery/tests']
    sys.path[:0] = [str(path) for path in paths]
    os.environ['PYTHONDONTWRITEBYTECODE'] = '1'
    suite = unittest.defaultTestLoader.discover(str(ROOT / 'tests'), pattern='test_*.py')
    expected = list(ids(suite))
    class Result(unittest.TextTestResult):
        def __init__(self, *args, **kwargs): super().__init__(*args, **kwargs); self.ids = []
        def addSuccess(self, test): super().addSuccess(test); self.ids.append(test.id())
    result = unittest.TextTestRunner(verbosity=2, resultclass=Result).run(suite)
    after = {'receipts': checked(ROOT, own['files']),
             'pinned_base_dependencies': checked(native, dependencies['files'])}
    passed = bool(expected) and len(set(expected)) == len(expected) and sorted(result.ids) == sorted(expected) and result.wasSuccessful() and not result.skipped and not result.expectedFailures
    report = {'schema': 1, 'scope': 'Portable P4 payment capsules and private archive; not consensus',
        'parent_commit': head, 'source_checks_before': before, 'source_checks_after': after,
        'packages': packages, 'tests': result.testsRun, 'expected_ids': expected,
        'successful_ids': result.ids, 'passed': passed, 'failures': len(result.failures),
        'errors': len(result.errors), 'skips': len(result.skipped),
        'actual_consensus_executed': False, 'real_funds': False,
        'independent_security_review': False}
    if args.report:
        from p4_receipt_archive import write_new
        write_new(args.report, json.dumps(report, indent=2).encode() + b'\n')
    print(json.dumps({k: v for k, v in report.items() if not k.endswith('_ids')}, indent=2))
    return 0 if passed else 1


if __name__ == '__main__': raise SystemExit(main())
