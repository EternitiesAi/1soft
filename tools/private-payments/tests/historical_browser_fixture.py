#!/usr/bin/env python3
"""Cold-launch the actual private-wallet CLI with an injected expired trusted clock.

Test process only. No production clock option, policy rewrite or trust renewal.
The caller owns a freshly generated fixture workspace and stops this listener.
"""
import importlib.util
from pathlib import Path
import sys
sys.dont_write_bytecode=True
ROOT=Path(__file__).resolve().parents[3]
path=ROOT/'tools/private-payments/scripts/serve_private_wallet.py'
spec=importlib.util.spec_from_file_location('private_wallet_launcher',path)
launcher=importlib.util.module_from_spec(spec);spec.loader.exec_module(launcher)
import p4_wallet

def refuse_unlock(*_args,**_kw):raise AssertionError('historical export must not unlock a vault')
p4_wallet._load_vault=refuse_unlock
original=launcher.network_for_workspace
now=int(sys.argv[1])
launcher.network_for_workspace=lambda workspace,engine:original(workspace,engine,clock=lambda:now)
raise SystemExit(launcher.main(sys.argv[2:]))
