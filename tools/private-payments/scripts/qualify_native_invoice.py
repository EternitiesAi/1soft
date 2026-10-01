#!/usr/bin/env python3
"""Qualify the fresh native invoice candidate without changing historical seals."""
from pathlib import Path
import sys
sys.dont_write_bytecode=True
ROOT=Path(__file__).resolve().parents[3]
sys.path[:0]=[str(ROOT/p) for p in ('src','scripts','tests','tools/private-payments/scripts')]+[str(p) for p in sorted((ROOT/'tools').glob('*/src'))]
from native_invoice_qualification import main
if __name__=='__main__':raise SystemExit(main())
