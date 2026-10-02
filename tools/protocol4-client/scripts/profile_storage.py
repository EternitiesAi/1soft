#!/usr/bin/env python3
"""Profile fresh read-store formats on the same private canonical proof sequence.

This development tool imports complete signed evidence, with full verification.
It creates no engine, signing journal, submission or value-bearing account. Its
input archives, generated proof files and SQLite stores remain private fixtures.
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
for name in ('protocol4-client', 'protocol4-custody', 'protocol4-explorer',
             'protocol4-wallet', 'protocol4-delivery'):
    sys.path.insert(0, str(ROOT/'tools'/name/'src'))
from block_application import encode
from commit_verifier import load_json
from p4_evidence import MAX_EVIDENCE_BYTES, need
from p4_read_store import P4ReadStore, private_path, write_new
from p4_explorer import current_view


def source():
    sys.path.insert(0, str(ROOT/'tools/release'))
    from check_release import source_identity
    return source_identity(ROOT)


def public_pin(pin):
    return {k: v for k, v in pin.items() if k != 'files'}


def bounded_read(path, maximum):
    path = private_path(path)
    need(path.is_file() and 0 < path.stat().st_size <= maximum,
         'bounded private input file required')
    with path.open('rb') as handle:
        raw = handle.read(maximum+1)
    need(0 < len(raw) <= maximum, 'private input changed size')
    return raw


def file_sizes(path):
    return {suffix or 'database': Path(str(path)+suffix).stat().st_size
            if Path(str(path)+suffix).is_file() else 0
            for suffix in ('', '-wal', '-shm', '-journal')}


CAPTURE_PIN_SHA256 = 'c5f16fa77ace09d1a6e41627d97fb65a82a9ed94af414a0f2d5c18408992acc2'
CAPTURE_COMMIT = '3df15e3f14795ec5641a47e449ebc350fe452937'
CAPTURE_TREE = '155fbdb8dee8e51c90dadf45789d1c41ce243a24'
CAPTURE_SOURCE_ID = 'bd773da7d10997a8b723d3fa0ecc70168c11ec9cd81303606206c6042eb2e58d'


def read_provenance_pin(path):
    need(path.is_file() and not path.is_symlink() and
         0 < path.stat().st_size <= 4*1024*1024, 'bounded public provenance pin required')
    with path.open('rb') as handle:
        raw = handle.read(4*1024*1024+1)
    need(0 < len(raw) <= 4*1024*1024, 'provenance pin changed size')
    return raw


def checked_capture_pin(raw):
    # This benchmark's frozen reference capture has one complete immutable pin.
    # A subset manifest cannot stand in for the native/verifier membership.
    need(type(raw) is bytes and 0 < len(raw) <= 4*1024*1024 and
         hashlib.sha256(raw).hexdigest() == CAPTURE_PIN_SHA256,
         'exact complete original capture source pin required')
    pin = json.loads(raw)
    need(pin['commit'] == CAPTURE_COMMIT and pin['tree'] == CAPTURE_TREE and
         pin['source_id'] == CAPTURE_SOURCE_ID and pin['tracked_files'] == 560 and
         type(pin['files']) is list and len(pin['files']) == 560 and
         len({row['path'] for row in pin['files']}) == 560, 'complete capture membership differs')
    material = {key: pin[key] for key in ('commit', 'tree', 'files')}
    canonical = json.dumps(material, sort_keys=True, separators=(',', ':')).encode()
    need(hashlib.sha256(canonical).hexdigest() == CAPTURE_SOURCE_ID,
         'capture full source identity differs')
    return pin


def prepare(args, pin):
    from p4_custody import RecoveryArchive
    import p4_custody_stream as stream
    provenance_raw = read_provenance_pin(args.provenance_source_pin)
    provenance = checked_capture_pin(provenance_raw)
    metadata_raw = bounded_read(args.fixture_metadata, 1024*1024)
    metadata = load_json(metadata_raw, max_bytes=1024*1024)
    need(metadata['prepare_commit'] == provenance['commit'] and
         metadata['prepare_source_id'] == provenance['source_id'],
         'input capture source differs from provenance pin')
    old_files = {row['path']: row for row in provenance['files']}
    new_files = {row['path']: row for row in pin['files']}
    unchanged = []
    for name, row in old_files.items():
        if name.startswith(('src/', 'tools/validator-transition/src/')) or name == 'tools/protocol4-client/src/p4_evidence.py':
            need(new_files.get(name) == row, 'native or evidence verifier changed since capture')
            unchanged.append(name)
    need(unchanged and 'tools/protocol4-client/src/p4_evidence.py' in unchanged,
         'capture verifier provenance missing')
    frozen_raw = bounded_read(args.frozen_archive, stream.MAX_ARCHIVE_BYTES)
    frozen_sha = hashlib.sha256(frozen_raw).hexdigest()
    need(frozen_sha == metadata['frozen_archive_sha256'], 'frozen archive changed')
    genesis = encode(metadata['genesis']); policy = metadata['policy']
    args.fixture.mkdir(mode=0o700, parents=False, exist_ok=False)
    private_path(args.fixture/'fixture.json')
    with RecoveryArchive(args.frozen_archive, genesis, policy) as archive:
        view = archive.inspect()
        need(view['snapshot_id'] == metadata['snapshot_id'] and
             view['signing_enabled'] is False and view['dispatch_enabled'] is False,
             'original capture audit or authority differs')
        with stream.stream_pair(archive._chunks) as pair:
            rows = pair[0].execute('SELECT * FROM observations ORDER BY seq').fetchall()
    need(0 < len(rows) <= 32, 'bounded original observation count required')
    records = []
    for index, row in enumerate(rows, 1):
        seq, evidence_id, parent, checked_ns, payload = row
        need(seq == index and type(payload) is bytes and 0 < len(payload) <= MAX_EVIDENCE_BYTES and
             hashlib.sha256(payload).hexdigest() == evidence_id and type(checked_ns) is int,
             'original observation metadata differs')
        filename = f'proof-{index:02d}.json'
        write_new(args.fixture/filename, payload)
        records.append({'seq': seq, 'evidence_id': evidence_id, 'parent_id': parent,
                        'checked_ns': checked_ns, 'bytes': len(payload), 'file': filename})
    logical = sum(row['bytes'] for row in records)
    need(logical <= 64*1024*1024, 'original logical proof capacity exceeded')
    data = {'schema': 1, 'fixture_kind': metadata['fixture_kind'],
            'genesis': metadata['genesis'], 'policy': policy, 'records': records,
            'records_sha256': hashlib.sha256(encode(records)).hexdigest(),
            'logical_evidence_bytes': logical,
            'input_archive_sha256': frozen_sha, 'input_snapshot_id': metadata['snapshot_id'],
            'input_capture_commit': provenance['commit'],
            'input_capture_source_id': provenance['source_id'],
            'input_provenance_pin_sha256': hashlib.sha256(provenance_raw).hexdigest(),
            'unchanged_native_and_evidence_files': len(unchanged),
            'prepare_source': public_pin(pin)}
    write_new(args.fixture/'fixture.json', encode(data))
    need(source() == pin and hashlib.sha256(bounded_read(args.frozen_archive,
         stream.MAX_ARCHIVE_BYTES)).hexdigest() == frozen_sha and
         read_provenance_pin(args.provenance_source_pin) == provenance_raw and
         bounded_read(args.fixture_metadata, 1024*1024) == metadata_raw,
         'source, provenance or immutable inputs changed during preparation')
    print(json.dumps({k: v for k, v in data.items() if k not in ('genesis', 'policy', 'records')}, sort_keys=True))


def measure(args, pin):
    data_raw = bounded_read(args.fixture/'fixture.json', 1024*1024)
    data = load_json(data_raw, max_bytes=1024*1024)
    need(data['prepare_source'] == public_pin(pin), 'derived fixture prepared by another source')
    records = data['records']
    need(0 < len(records) <= 32 and hashlib.sha256(encode(records)).hexdigest() == data['records_sha256'],
         'frozen proof inventory changed')
    packets = []
    for index, row in enumerate(records, 1):
        need(row['seq'] == index and row['file'] == f'proof-{index:02d}.json', 'unsafe proof inventory')
        raw = bounded_read(args.fixture/row['file'], MAX_EVIDENCE_BYTES)
        need(len(raw) == row['bytes'] and hashlib.sha256(raw).hexdigest() == row['evidence_id'],
             'frozen original proof bytes changed')
        packet = load_json(raw, max_bytes=MAX_EVIDENCE_BYTES)
        need(encode(packet) == raw, 'original proof is not canonical')
        packets.append((row, raw, packet))
    need(sum(len(raw) for _, raw, _ in packets) == data['logical_evidence_bytes'] <= 64*1024*1024,
         'frozen logical capacity changed')
    args.sample.mkdir(mode=0o700, parents=False, exist_ok=False)
    path = args.sample/'read.sqlite'; now = records[0]['checked_ns']
    genesis = encode(data['genesis']); policy = data['policy']; tip = None
    start = time.perf_counter_ns(); cpu = time.process_time_ns()
    with P4ReadStore(path, genesis, policy, create=True, storage_version=args.format,
                     clock=lambda: now) as store:
        for row, raw, packet in packets:
            now = row['checked_ns']
            imported = store.import_evidence(packet, expected_tip=tip)
            need(imported['status'] == 'recorded' and imported['evidence_id'] == row['evidence_id'],
                 'original proof import identity changed')
            tip = imported['evidence_id']
        import_cpu = time.process_time_ns()-cpu; import_wall = time.perf_counter_ns()-start
        statistics = store.storage_stats()
        need(statistics['format_version'] == args.format and statistics['observations'] == len(records) and
             statistics['logical_evidence_bytes'] == data['logical_evidence_bytes'] and
             statistics['spending_authority'] is False, 'logical capacity or storage authority differs')
        start = time.perf_counter_ns(); cpu = time.process_time_ns()
        report = store.current()
        read_cpu = time.process_time_ns()-cpu; read_wall = time.perf_counter_ns()-start
        need(report['evidence_id'] == tip and report['spending_authority'] is False and
             report['native_execution_replayed'] is True, 'final verification or authority differs')
        for row, raw, _ in packets:
            need(encode(store.export(row['evidence_id'])) == raw, 'original canonical export bytes differ')
        open_sizes = file_sizes(path)
    closed_sizes = file_sizes(path)
    projection = current_view(path, genesis, policy, clock=lambda: now)
    need(projection['spending_authority'] is False, 'explorer projection gained authority')
    need(source() == pin and bounded_read(args.fixture/'fixture.json', 1024*1024) == data_raw,
         'source or frozen inventory changed during measurement')
    for row, raw, _ in packets:
        need(bounded_read(args.fixture/row['file'], MAX_EVIDENCE_BYTES) == raw, 'frozen proof changed during measurement')
    print(json.dumps({'schema': 1, 'source': public_pin(pin), 'format_version': args.format,
        'input_capture_commit': data['input_capture_commit'], 'input_capture_source_id': data['input_capture_source_id'],
        'input_archive_sha256': data['input_archive_sha256'], 'input_snapshot_id': data['input_snapshot_id'],
        'derived_fixture_sha256': hashlib.sha256(data_raw).hexdigest(),
        'records_sha256': data['records_sha256'], 'statistics': statistics,
        'database_open_files_bytes': open_sizes, 'database_closed_files_bytes': closed_sizes,
        'closed_database_total_bytes': sum(closed_sizes.values()),
        'import_wall_ns': import_wall, 'import_cpu_ns': import_cpu,
        'current_wall_ns': read_wall, 'current_cpu_ns': read_cpu,
        'whole_process_peak_rss_kib': resource.getrusage(resource.RUSAGE_SELF).ru_maxrss,
        'verified_report_sha256': hashlib.sha256(encode(report)).hexdigest(),
        'explorer_projection_sha256': hashlib.sha256(encode(projection)).hexdigest(),
        'exact_original_exports': True, 'same_original_clocks': True, 'python': sys.version.split()[0],
        'actual_engine': False, 'maximum_capacity_claim': False,
        'scope': f'{len(records)} original signed-native proofs; fresh store creation/import and one fully verified current read; exports excluded from timed read'}, sort_keys=True))


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument('--fixture', type=Path, required=True)
    ap.add_argument('--prepare', action='store_true')
    ap.add_argument('--frozen-archive', type=Path)
    ap.add_argument('--fixture-metadata', type=Path)
    ap.add_argument('--provenance-source-pin', type=Path)
    ap.add_argument('--format', type=int, choices=(1, 2))
    ap.add_argument('--sample', type=Path)
    args = ap.parse_args(); pin = source()
    if args.prepare:
        if not all((args.frozen_archive, args.fixture_metadata, args.provenance_source_pin)):
            ap.error('preparation requires frozen archive, capture metadata and provenance source pin')
        prepare(args, pin)
    else:
        if args.format is None or args.sample is None:
            ap.error('measurement requires format and new sample directory')
        measure(args, pin)


if __name__ == '__main__':
    main()
