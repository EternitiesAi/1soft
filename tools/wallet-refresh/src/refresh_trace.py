"""Local, bounded refresh diagnostics. Never proof of payment or authority.

A new private directory is required for every invocation. Each whitelisted event
is flushed before execution continues. A missing terminal result stays unknown;
this log never attempts to undo, replay, or reconcile wallet state. Hash linking
catches accidental changes, not a malicious writer or whole-workspace rollback.
"""
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import secrets
import stat
import time

MAX_EVENTS = 64
MAX_EVENT_BYTES = 4096
MAX_LOG_BYTES = MAX_EVENTS * MAX_EVENT_BYTES
ZERO = '0' * 64
STATUSES = {'synced', 'headers_only', 'unavailable', 'rejected',
            'target_behind_wallet', 'concurrent_progress'}
STAGES = {'preflight', 'snapshot_read', 'target_validation', 'frontier_check',
          'headers_read', 'headers_validation', 'header_commit', 'state_sync'}
RESULT_FIELDS = ('status', 'state_synced', 'headers_accepted', 'batches_committed',
                 'rpc_attempts', 'request_bound', 'target_header_height',
                 'verified_header_height', 'state_header_height')


class TraceError(RuntimeError):
    """Diagnostics could not be retained; wallet state may already have advanced."""


def need(value, message):
    if not value:
        raise TraceError(message)


def integer(value, low=0, high=2**63-1):
    need(type(value) is int and low <= value <= high, 'invalid diagnostic integer')


def wire(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'),
                      ensure_ascii=True, allow_nan=False).encode('ascii')


def digest(data):
    return hashlib.sha256(data).hexdigest()


def hex_string(value, length):
    return type(value) is str and len(value) == length and all(c in '0123456789abcdef' for c in value)


def public_result(report):
    """Select only outcome/count/height fields; deliberately omit financial data."""
    need(type(report) is dict, 'invalid refresh outcome')
    result = {key: report.get(key) for key in RESULT_FIELDS}
    need(type(result['status']) is str and result['status'] in STATUSES, 'invalid refresh status')
    need(type(result['state_synced']) is bool and
         result['state_synced'] == (result['status'] == 'synced'), 'inconsistent refresh status')
    integer(result['headers_accepted'], high=256)
    integer(result['batches_committed'], high=4)
    integer(result['request_bound'], low=6, high=261)
    if result['rpc_attempts'] is not None:
        integer(result['rpc_attempts'], high=result['request_bound'])
    for key in ('target_header_height', 'verified_header_height', 'state_header_height'):
        if result[key] is not None:
            integer(result[key], low=1, high=2**53-1)
    if result['state_synced']:
        need(result['state_header_height'] is not None and
             result['state_header_height'] == result['target_header_height'], 'synced height mismatch')
    return result


def validate_event(event, data):
    need(type(data) is dict, 'diagnostic data must be an object')
    shapes = {
        'started': {'started_ns', 'max_batches', 'headers_per_batch'},
        'local_ready': {'height'},
        'collection_started': {'kind', 'start', 'count'},
        'collection_finished': {'kind', 'status', 'rpc_attempts'},
        'target_verified': {'height'},
        'batch_commit_started': {'start', 'count'},
        'batch_committed': {'height', 'count'},
        'state_sync_started': {'height'},
        'state_synced': {'height'},
        'rejected': {'stage'},
        'completed': set(RESULT_FIELDS),
        'aborted': {'reason'},
    }
    need(type(event) is str and event in shapes and set(data) == shapes[event],
         'unrecognized diagnostic fields')
    if event == 'completed':
        need(public_result(data) == data, 'invalid final diagnostic result')
        return
    for key in ('height', 'start'):
        if key in data and data[key] is not None:
            integer(data[key], high=2**53-1)
    if 'count' in data and data['count'] is not None:
        integer(data['count'], low=1, high=64)
    if event == 'started':
        integer(data['started_ns']); integer(data['max_batches'], 1, 4)
        integer(data['headers_per_batch'], 1, 64)
    if event.startswith('collection_'):
        need(type(data['kind']) is str and data['kind'] in ('snapshot', 'headers'), 'invalid collection kind')
        if event == 'collection_started':
            if data['kind'] == 'snapshot':
                need(data['start'] is None and data['count'] is None, 'snapshot has no header range')
            else:
                integer(data['start'], low=1, high=2**53-1); integer(data['count'], 1, 64)
        else:
            need(type(data['status']) is str and data['status'] in ('collected', 'unavailable', 'rejected'), 'invalid worker outcome')
            if data['rpc_attempts'] is not None:
                integer(data['rpc_attempts'], high=5 if data['kind'] == 'snapshot' else 64)
    if event == 'rejected':
        need(type(data['stage']) is str and data['stage'] in STAGES, 'invalid rejection stage')
    if event == 'aborted':
        need(type(data['reason']) is str and data['reason'] in ('interrupted', 'exception'), 'invalid abort reason')


def private_directory(path):
    path = Path(os.path.abspath(path))
    need(os.name == 'posix', 'private trace storage requires POSIX')
    for parent in (path, *path.parents):
        need(not parent.is_symlink(), 'trace directory symlinks refused')
    info = path.stat()
    need(stat.S_ISDIR(info.st_mode) and info.st_uid == os.geteuid() and
         stat.S_IMODE(info.st_mode) & 0o077 == 0, 'trace directory must be private and owned')
    return path


class RefreshTrace:
    """One newly created run; no append-to-old-log or automatic repair API."""
    def __init__(self, directory):
        self.fd = None
        self.closed = False
        self.failed = False
        self.finished = False
        self.sequence = 0
        self.previous = ZERO
        self.run_id = secrets.token_hex(16)
        path = Path(os.path.abspath(directory))
        for parent in (path.parent, *path.parent.parents):
            need(not parent.is_symlink(), 'trace parent symlinks refused')
        path.mkdir(mode=0o700, exist_ok=False)
        self.directory = private_directory(path)
        parent_fd = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        try:
            os.fsync(parent_fd)
        finally:
            os.close(parent_fd)
        directory_fd = os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        try:
            self.fd = os.open('events.jsonl', os.O_WRONLY | os.O_CREAT | os.O_EXCL |
                              os.O_NOFOLLOW | os.O_CLOEXEC, 0o600, dir_fd=directory_fd)
            os.fsync(directory_fd)
        except BaseException:
            self.close()
            raise
        finally:
            os.close(directory_fd)

    def record(self, event, data):
        need(not self.closed and not self.failed and not self.finished, 'trace cannot accept more records')
        need(self.sequence < MAX_EVENTS, 'trace event limit reached')
        validate_event(event, data)
        need((self.sequence == 0) == (event == 'started'), 'trace must start exactly once')
        material = {'schema': 1, 'run_id': self.run_id, 'seq': self.sequence + 1,
                    'event': event, 'data': data, 'previous': self.previous}
        record = {**material, 'sha256': digest(wire(material))}
        raw = wire(record) + b'\n'
        need(len(raw) <= MAX_EVENT_BYTES, 'diagnostic event exceeds byte limit')
        try:
            remaining = memoryview(raw)
            while remaining:
                written = os.write(self.fd, remaining)
                need(written > 0, 'diagnostic write made no progress')
                remaining = remaining[written:]
            os.fsync(self.fd)
        except BaseException:
            self.failed = True
            raise
        self.sequence += 1
        self.previous = record['sha256']
        self.finished = event in ('completed', 'aborted')

    def close(self):
        if self.fd is not None:
            os.close(self.fd); self.fd = None
        self.closed = True

    def __enter__(self): return self
    def __exit__(self, *_): self.close()


def recorded_refresh(wallet, endpoint, directory, *, max_batches=2, headers_per_batch=64):
    """Persist the returned outcome BEFORE returning to the caller's assertions.

    A diagnostic-write failure is not payment failure. Earlier wallet commits may
    survive; no automatic retry or rollback is attempted. Inspect the wallet using
    its own authenticated state path, not this record, to resume safely.
    """
    from wallet_refresh import refresh_wallet
    integer(max_batches, 1, 4); integer(headers_per_batch, 1, 64)
    with RefreshTrace(directory) as trace:
        trace.record('started', {'started_ns': time.time_ns(), 'max_batches': max_batches,
                                 'headers_per_batch': headers_per_batch})
        try:
            report = refresh_wallet(wallet, endpoint, max_batches=max_batches,
                                    headers_per_batch=headers_per_batch, observer=trace.record)
        except BaseException as exc:
            # Exception text, args, paths and endpoint payloads are never copied.
            if not trace.failed:
                try:
                    trace.record('aborted', {'reason': 'interrupted' if isinstance(exc, (KeyboardInterrupt, SystemExit))
                                            else 'exception'})
                except BaseException:
                    pass
            raise
        trace.record('completed', public_result(report))
        return report


def read_trace(directory):
    """Inspect diagnostics without opening a wallet, loading keys or contacting RPC."""
    directory = private_directory(directory)
    fd = os.open(directory / 'events.jsonl', os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(fd, 'rb') as stream:
        info = os.fstat(stream.fileno())
        need(stat.S_ISREG(info.st_mode) and info.st_uid == os.geteuid() and
             stat.S_IMODE(info.st_mode) & 0o077 == 0 and info.st_nlink == 1,
             'trace must be a private owned regular file without hard links')
        need(info.st_size <= MAX_LOG_BYTES, 'trace log too large')
        raw = stream.read(MAX_LOG_BYTES + 1)
        need(len(raw) <= MAX_LOG_BYTES, 'trace log grew past its limit')
    lines = raw.split(b'\n')
    tail = lines.pop()
    need(len(tail) < MAX_EVENT_BYTES, 'partial trace record exceeds limit')
    events = []
    previous = ZERO
    run_id = None
    terminal = None
    def pairs(items):
        out = {}
        for key, value in items:
            need(key not in out, 'duplicate trace field'); out[key] = value
        return out
    for line in lines:
        need(len(events) < MAX_EVENTS and len(line) + 1 <= MAX_EVENT_BYTES, 'trace count/size exceeded')
        need(terminal is None, 'data follows a terminal trace result')
        try:
            record = json.loads(line, object_pairs_hook=pairs)
        except (ValueError, UnicodeError, RecursionError) as exc:
            raise TraceError('invalid trace JSON') from exc
        need(type(record) is dict and set(record) == {'schema','run_id','seq','event','data','previous','sha256'},
             'invalid trace envelope')
        need(type(record['schema']) is int and record['schema'] == 1 and
             type(record['seq']) is int and record['seq'] == len(events) + 1, 'invalid trace sequence/schema')
        need(hex_string(record['run_id'], 32) and hex_string(record['sha256'], 64), 'invalid trace digest or identity')
        if run_id is None: run_id = record['run_id']
        need(record['run_id'] == run_id and record['previous'] == previous, 'trace chain mismatch')
        need(wire(record) == line, 'trace is not canonical JSON')
        material = {k: v for k, v in record.items() if k != 'sha256'}
        need(digest(wire(material)) == record['sha256'], 'trace content hash mismatch')
        validate_event(record['event'], record['data'])
        need((not events) == (record['event'] == 'started'), 'invalid trace start')
        events.append(record); previous = record['sha256']
        if record['event'] in ('completed', 'aborted'): terminal = record
    need(not (terminal and tail), 'partial bytes follow a terminal result')
    return {'schema': 1, 'run_id': run_id, 'records': len(events),
            'recording_status': 'completed' if terminal and terminal['event'] == 'completed'
                                else ('aborted' if terminal else 'incomplete'),
            'outcome': terminal['data'] if terminal and terminal['event'] == 'completed' else None,
            'last_event': None if not events else events[-1]['event'],
            'partial_tail': bool(tail), 'events': events,
            'wallet_state_inferred': False, 'financial_authority': False,
            'scope': 'local diagnostic observations only, not signed chain evidence'}
