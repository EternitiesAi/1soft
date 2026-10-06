#!/usr/bin/env python3
"""Protected local P8 recovery application workflow. No provisioning or repair."""
import argparse
import json
import sys
from pathlib import Path
ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT/'src'))
from protocol8_operator import initialize, doctor, audit, serve, OperatorError
from protocol8_consensus import StateError
from protocol8_transfer import Unavailable

def emit(value):
    print(json.dumps(value, sort_keys=True, separators=(',', ':')), flush=True)

def main(argv=None):
    p = argparse.ArgumentParser(description=__doc__)
    sub = p.add_subparsers(dest='command', required=True)
    for name in ('init', 'doctor', 'audit', 'serve'):
        cmd = sub.add_parser(name)
        cmd.add_argument('--workspace', type=Path, required=True)
        cmd.add_argument('--genesis-sha256', required=True)
        if name == 'init':
            for field in ('genesis', 'kat', 'worker', 'engine'):
                cmd.add_argument('--'+field, type=Path, required=True)
    args = p.parse_args(argv)
    try:
        if args.command == 'init':
            value = initialize(args.workspace, args.genesis, args.genesis_sha256,
                               args.kat, args.worker, args.engine)
        elif args.command == 'doctor': value = doctor(args.workspace, args.genesis_sha256)
        elif args.command == 'audit': value = audit(args.workspace, args.genesis_sha256)
        else:
            serve(args.workspace, args.genesis_sha256, emit)
            return 0
        emit(value)
        return 0
    except (OperatorError, StateError, Unavailable, OSError, ValueError, TypeError, RecursionError) as exc:
        # Do not print arbitrary supplied JSON, store contents or traceback locals.
        emit({'status': 'refused', 'error_type': type(exc).__name__,
              'reason': str(exc) if isinstance(exc, (OperatorError, StateError, Unavailable))
                        else 'local file/configuration invalid or unavailable'})
        return 1

if __name__ == '__main__':
    raise SystemExit(main())
