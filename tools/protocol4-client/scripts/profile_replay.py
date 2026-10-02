#!/usr/bin/env python3
"""One historical read-proof sample over an existing private disposable fixture.

No keys are opened, no journal is mutated and no trust period is renewed. This
profiles local verification, not actual validator throughput or production load.
The caller supplies a clean source checkout and freezes the fixture beforehand.
"""
from __future__ import annotations
import argparse
import hashlib
import json
from pathlib import Path
import resource
import sqlite3
import sys
import time


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--root', type=Path, required=True)
    parser.add_argument('--fixture', type=Path, required=True)
    args = parser.parse_args()
    root, fixture = args.root.resolve(), args.fixture.resolve()
    sys.path[:0] = [str(root / p) for p in ('tools/release', 'tools/protocol4-client/src',
                     'tools/validator-transition/src', 'src')]
    import check_release
    import p4_evidence
    import native_core
    for module in (check_release, p4_evidence, native_core):
        if not Path(module.__file__).resolve().is_relative_to(root):
            raise ValueError('profile imported a different source checkout')
    identity = check_release.source_identity(root)
    meta_path, database = fixture / 'case.json', fixture / 'wallet.sqlite'
    if meta_path.is_symlink() or database.is_symlink(): raise ValueError('aliased fixture refused')
    meta_raw = meta_path.read_bytes(); meta = json.loads(meta_raw)
    before = hashlib.sha256(database.read_bytes()).hexdigest()
    if before != meta['database_sha256']: raise ValueError('fixture database changed')
    if any(Path(str(database) + suffix).exists() for suffix in ('-wal', '-shm', '-journal')):
        raise ValueError('fixture must be a frozen closed database')
    with sqlite3.connect(database.as_uri() + '?mode=ro&immutable=1', uri=True) as db:
        raw = bytes(db.execute('SELECT payload FROM observations ORDER BY seq DESC LIMIT 1').fetchone()[0])
    if len(raw) != meta['evidence_bytes'] or hashlib.sha256(raw).hexdigest() != meta['evidence_sha256']:
        raise ValueError('fixture evidence changed')
    evidence = json.loads(raw)
    genesis = check_release.canonical(meta['genesis'])
    arguments = (evidence, genesis, meta['policy'])
    warm = p4_evidence.verify_evidence(*arguments, now_ns=meta['now_ns'])
    inspected = []
    original = native_core.NativeLedger.verify_receipts
    def counted(ledger):
        inspected.append(ledger.db.execute('SELECT COUNT(*) FROM receipts').fetchone()[0])
        return original(ledger)
    native_core.NativeLedger.verify_receipts = counted
    started, cpu = time.perf_counter_ns(), time.process_time_ns()
    try:
        report = p4_evidence.verify_evidence(*arguments, now_ns=meta['now_ns'])
    finally:
        elapsed, cpu_elapsed = time.perf_counter_ns() - started, time.process_time_ns() - cpu
        native_core.NativeLedger.verify_receipts = original
    if check_release.canonical(warm) != check_release.canonical(report):
        raise ValueError('warm and measured reports differ')
    after = hashlib.sha256(database.read_bytes()).hexdigest()
    if before != after or meta_path.read_bytes() != meta_raw or identity != check_release.source_identity(root):
        raise ValueError('source or private fixture changed during sample')
    print(json.dumps({'schema': 1, 'source_commit': identity['commit'], 'source_tree': identity['tree'],
          'source_id': identity['source_id'], 'fixture_metadata_sha256': hashlib.sha256(meta_raw).hexdigest(),
          'evidence_sha256': meta['evidence_sha256'], 'database_sha256': before,
          'state_height': report['state_height'], 'receipts': len(report['receipts']),
          'report_sha256': hashlib.sha256(check_release.canonical(report)).hexdigest(),
          'elapsed_ns': elapsed, 'cpu_ns': cpu_elapsed,
          'receipt_audits': len(inspected), 'receipt_rows_audited': sum(inspected),
          'nonempty_receipt_audits': [n for n in inspected if n],
          'peak_rss_kib': resource.getrusage(resource.RUSAGE_SELF).ru_maxrss,
          'source_unchanged': True, 'fixture_unchanged': True,
          'verification_time_scope': 'unchanged original historical fixture clock',
          'consensus_executed': False, 'production_capacity_established': False}, sort_keys=True))


if __name__ == '__main__': main()
