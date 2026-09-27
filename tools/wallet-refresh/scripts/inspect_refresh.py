#!/usr/bin/env python3
"""Inspect a local refresh record without loading any wallet or native core."""
import argparse
import json
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'src'))
from refresh_trace import TraceError, read_trace


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('directory', type=Path)
    args = parser.parse_args(argv)
    try:
        report = read_trace(args.directory)
        print(json.dumps(report, indent=2))
        return 0 if report['recording_status'] == 'completed' else 2
    except (OSError, TraceError, ValueError):
        print('Refresh record is unavailable or invalid; no wallet outcome can be inferred.', file=sys.stderr)
        return 3


if __name__ == '__main__':
    raise SystemExit(main())
