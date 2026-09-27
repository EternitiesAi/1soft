#!/usr/bin/env python3
"""Test this optional client against an explicitly supplied complete local core."""
import argparse
import json
import os
from pathlib import Path
import sys
import unittest

ROOT = Path(__file__).resolve().parents[1]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--native-root', type=Path, required=True)
    args = parser.parse_args()
    native = args.native_root.resolve()
    if not (native/'src/wallet_catchup.py').is_file():
        parser.error('complete Codex catch-up source required; PR #7 alone does not contain that dependency')
    sys.path.insert(0, str(native/'scripts'))
    from verify_checkout import verify_checkout
    for root in (native, ROOT):
        result = verify_checkout(root)
        if result['status'] != 'passed':
            print(json.dumps(result, indent=2)); return 2
    # Child HTTP workers inherit both this add-on and the supplied native modules.
    paths = [str(ROOT/'src'), str(native/'src'), str(native/'tests')]
    sys.path[:0] = paths
    os.environ['PYTHONPATH'] = os.pathsep.join(paths)
    suite = unittest.defaultTestLoader.discover(str(ROOT/'tests'), pattern='test_client.py')
    expected = suite.countTestCases()
    result = unittest.TextTestRunner(verbosity=2).run(suite)
    passed = expected > 0 and result.testsRun == expected and result.wasSuccessful() and not result.skipped
    print(json.dumps({'scope': 'optional read-only client integration, not full native regression',
                      'run': result.testsRun, 'passed': passed, 'consensus_executed': False}))
    return 0 if passed else 1


if __name__ == '__main__': raise SystemExit(main())
