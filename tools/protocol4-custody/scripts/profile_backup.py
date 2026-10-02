#!/usr/bin/env python3
"""Paired compact-backup profile on one frozen synthetic native journal capture.

This creates no active restore, engine, hosted resource or real funds. Prepare a
NEW private directory once; run each sample in a fresh process. The encrypted
sample and plaintext recovery archive are private payment records, not reports.
"""
import argparse
import hashlib
import json
from pathlib import Path
import resource
import sys
import time

ROOT = Path(__file__).resolve().parents[3]
sys.dont_write_bytecode = True
sys.path[:0] = [str(ROOT/'src'), str(ROOT/'tools/validator-transition/src')]
for name in ('protocol4-client', 'protocol4-wallet', 'protocol4-delivery', 'protocol4-custody'):
    sys.path[:0] = [str(ROOT/'tools'/name/'src'), str(ROOT/'tools'/name/'tests')]
from block_application import encode
from p4_evidence import need
from p4_custody import _publish_parts, _read, RecoveryArchive, restore_backup
import p4_custody_stream as stream


def sha(path, limit):
    return hashlib.sha256(_read(path, limit)).hexdigest()


def source():
    sys.path.insert(0, str(ROOT/'tools/release'))
    from check_release import source_identity
    return source_identity(ROOT)


def rows_digest(pair):
    digest = hashlib.sha256()
    for source_index, table, _, _ in stream.TABLES:
        db = pair[source_index]
        digest.update(encode([source_index, table]))
        for row in db.execute(f'SELECT * FROM {table} ORDER BY 1'):
            digest.update(encode(['row', len(row)]))
            for cell in row:
                if type(cell) is bytes:
                    digest.update(encode(['bytes', len(cell)])); digest.update(cell)
                else:
                    digest.update(encode([type(cell).__name__, cell]))
    return digest.hexdigest()


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument('--fixture', type=Path, required=True)
    ap.add_argument('--prepare', action='store_true')
    ap.add_argument('--format', type=int, choices=(2, 3))
    ap.add_argument('--sample', type=Path)
    args = ap.parse_args(); pin = source(); fixture = args.fixture.absolute()
    if args.prepare:
        from test_large import make_large
        chain, wallet, delivery, ids, receipt, total = make_large(fixture)
        try:
            with stream.capture_pair(delivery) as pair:
                counts = {}; chunks = tuple(stream.plain_chunks(pair, counts))
                manifest = {**stream._manifest(chunks), **counts}
                digest = rows_digest(pair)
                raw = stream.make_archive(chunks, manifest)
                _publish_parts(fixture/'frozen.sqlite', (raw,), stream.MAX_ARCHIVE_BYTES)
            data = {'schema':1, 'fixture_kind':'signed native rules; public test keys; no CometBFT',
                'genesis':json.loads(chain.genesis), 'policy':chain.policy,
                'rows_sha256':digest, 'snapshot_id':stream.snapshot_id(manifest),
                'frozen_archive_sha256':sha(fixture/'frozen.sqlite', stream.MAX_ARCHIVE_BYTES),
                'journal_blob_bytes':total, 'logical_stream_bytes':manifest['stream_bytes'],
                'chunks':manifest['chunks'], 'row_counts':manifest['row_counts'],
                'blob_bytes':manifest['blob_bytes'], 'expected_pending_debit_units':'40',
                'prepare_commit':pin['commit'], 'prepare_source_id':pin['source_id']}
            _publish_parts(fixture/'fixture.json', (encode(data),), 4096)
        finally:
            delivery.close(); wallet.close(); chain.close()
        need(source() == pin, 'source changed during preparation')
        print(json.dumps({k:v for k,v in data.items() if k not in ('genesis', 'policy')}, sort_keys=True))
        return
    if args.format is None or args.sample is None:
        ap.error('--format and --sample are required for measurement')
    from test_custody import BACKUP_PASSWORD
    data = json.loads(_read(fixture/'fixture.json', 4096))
    need(data['prepare_commit'] == pin['commit'] and data['prepare_source_id'] == pin['source_id'],
         'frozen fixture was prepared by a different source')
    frozen = fixture/'frozen.sqlite'
    need(sha(frozen, stream.MAX_ARCHIVE_BYTES) == data['frozen_archive_sha256'], 'frozen input changed')
    args.sample.mkdir(mode=0o700, parents=False, exist_ok=False)
    raw = _read(frozen, stream.MAX_ARCHIVE_BYTES)
    chunks, snapshot = stream.archive_chunks(raw)
    need(snapshot == data['snapshot_id'], 'frozen snapshot differs')
    codec = stream
    if args.format == 3:
        import p4_custody_compressed as codec
    bp, apath = args.sample/'backup.bin', args.sample/'recovery.sqlite'
    result = {}
    with stream.stream_pair(chunks) as pair:
        need(rows_digest(pair) == data['rows_sha256'], 'frozen logical rows changed')
        # A frozen, already audited capture is identical for both encoders.
        start = time.perf_counter_ns(); cpu = time.process_time_ns()
        _publish_parts(bp, codec.sealed_parts(pair[:3], BACKUP_PASSWORD, result), codec.MAX_BACKUP_BYTES)
        encode_cpu = time.process_time_ns()-cpu; encode_wall = time.perf_counter_ns()-start
    need(result['snapshot_id'] == snapshot, 'codec changed the original snapshot identity')
    start = time.perf_counter_ns(); cpu = time.process_time_ns()
    restored = restore_backup(bp, apath, encode(data['genesis']), data['policy'], BACKUP_PASSWORD)
    restore_cpu = time.process_time_ns()-cpu; restore_wall = time.perf_counter_ns()-start
    need(restored['backup_format_version'] == args.format and restored['snapshot_id'] == snapshot,
         'restored envelope or snapshot differs')
    with RecoveryArchive(apath, encode(data['genesis']), data['policy']) as archive:
        view = archive.inspect()
        need(view['pending_debit_units'] == data['expected_pending_debit_units'] and
             view['signing_enabled'] is False and view['dispatch_enabled'] is False and
             view['trust_policy_renewed'] is False, 'historical obligations or authority differ')
        with stream.stream_pair(archive._chunks) as pair:
            need(rows_digest(pair) == data['rows_sha256'], 'restored logical rows differ')
    need(sha(frozen, stream.MAX_ARCHIVE_BYTES) == data['frozen_archive_sha256'] and source() == pin,
         'frozen fixture or source changed during measurement')
    print(json.dumps({'schema':1, 'source':{k:v for k,v in pin.items() if k != 'files'},
        'format_version':args.format, 'prepare_commit':data['prepare_commit'],
        'prepare_source_id':data['prepare_source_id'], 'fixture_archive_sha256':data['frozen_archive_sha256'],
        'rows_sha256':data['rows_sha256'], 'snapshot_id':snapshot,
        'journal_blob_bytes':data['journal_blob_bytes'], 'logical_stream_bytes':data['logical_stream_bytes'],
        'backup_bytes':bp.stat().st_size, 'backup_sha256':sha(bp, codec.MAX_BACKUP_BYTES),
        'recovery_archive_bytes':apath.stat().st_size, 'recovery_archive_sha256':sha(apath, stream.MAX_ARCHIVE_BYTES),
        'encoding_wall_ns':encode_wall, 'encoding_cpu_ns':encode_cpu,
        'restore_wall_ns':restore_wall, 'restore_cpu_ns':restore_cpu,
        'whole_process_peak_rss_kib':resource.getrusage(resource.RUSAGE_SELF).ru_maxrss,
        'python':sys.version.split()[0], 'exact_rows_preserved':True,
        'pending_debit_units':view['pending_debit_units'], 'actual_engine':False,
        'scope':'one frozen native signed fixture, encoding excludes capture/audit; restore includes original audit',
        'constant_memory_audit_claim':False, 'maximum_capacity_claim':False}, sort_keys=True))


if __name__ == '__main__': main()
