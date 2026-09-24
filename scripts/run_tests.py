#!/usr/bin/env python3
"""Run a manifest-checked, nonempty local suite. This does not verify consensus."""
from __future__ import annotations
import argparse
import json
import os
from pathlib import Path
import sys
import unittest

from verify_checkout import CheckoutError, verify_checkout


def run(root: Path, stream=None) -> int:
    stream = stream or sys.stderr
    root = Path(root).resolve()
    try:
        integrity = verify_checkout(root)
        if integrity['status'] != 'passed':
            print(json.dumps(integrity, indent=2), file=stream)
            return 2
        tests = root / 'tests'
        if not tests.is_dir() or tests.is_symlink():
            raise CheckoutError('missing regular tests directory')
        sys.path.insert(0, str(root / 'src'))
        os.environ['PYTHONPATH'] = str(root / 'src') + (os.pathsep + os.environ['PYTHONPATH'] if os.environ.get('PYTHONPATH') else '')
        os.chdir(root)
        suite = unittest.defaultTestLoader.discover(str(tests), pattern='test_*.py')
        discovered = suite.countTestCases()
        if discovered < 1:
            raise CheckoutError('zero tests discovered; refusing a green result')
    except (OSError, ImportError, CheckoutError) as exc:
        print('TEST GATE FAILED: ' + str(exc), file=stream)
        return 2
    result = unittest.TextTestRunner(stream=stream, verbosity=2).run(suite)
    exercised = result.testsRun - len(result.skipped)
    passed = result.wasSuccessful() and result.testsRun == discovered and exercised > 0
    print(json.dumps({'scope': 'local-python-tests-not-consensus',
        'status': 'passed' if passed else 'failed', 'discovered': discovered,
        'run': result.testsRun, 'skipped': len(result.skipped),
        'failures': len(result.failures), 'errors': len(result.errors),
        'required_source_files': integrity['required'], 'source_files_matched': integrity['matched'],
        'manifest_sha256': integrity['manifest_sha256'], 'consensus_verified': False}), file=stream)
    return 0 if passed else 1


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--root', type=Path, default=Path(__file__).resolve().parents[1])
    return run(parser.parse_args(argv).root)


if __name__ == '__main__':
    raise SystemExit(main())
