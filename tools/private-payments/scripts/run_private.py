"""Explicit local acceptance only, never starts a public or value-bearing chain."""
import argparse
import os
from pathlib import Path
import sys
import uuid
sys.dont_write_bytecode = True
os.umask(0o077)
ROOT = Path(__file__).resolve().parents[3]
for path in ('src', 'scripts', 'tools/validator-transition/src', 'tools/protocol4-client/src',
             'tools/protocol4-wallet/src', 'tools/protocol4-delivery/src',
             'tools/protocol4-explorer/src', 'tools/protocol4-receipts/src',
             'tools/local-platform/src', 'tools/private-payments/src'):
    sys.path.insert(0, str(ROOT/path))
from block_application import encode
from private_acceptance import run_private
from release_check import source_checked
parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument('--engine', required=True)
parser.add_argument('--output', required=True)
parser.add_argument('--exploratory', action='store_true', help='Includes dirty source; cannot qualify a release')
args = parser.parse_args()
source = None if args.exploratory else source_checked()
result = run_private(args.engine, args.output, source=source, run_id=str(uuid.uuid4()))
print(encode(result).decode())
raise SystemExit(0 if result['status']=='passed' else 1)
