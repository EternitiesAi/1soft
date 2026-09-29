"""Acceptance-only P4 checkpoint checks. No signing, money or network authority."""
from __future__ import annotations
import base64
import hashlib
import json
import os
from pathlib import Path
import re
import sqlite3
import stat
from block_application import encode
from commit_verifier import load_json, block_id, merkle_root
from native_core import canonical, digest
from protocol4_application import Protocol4Application, application_hash
from protocol4_abci_wire import encode_finalization
from validator_sets_core import ValidatorSet

MAX_EVIDENCE = 16 * 1024 * 1024

def need(ok, text):
    if not ok: raise ValueError(text)

def integer(n, low=0, high=512):
    need(type(n) is int and low <= n <= high, 'invalid exact bounded integer')
    return n

def sha(data): return hashlib.sha256(data).hexdigest()

def hex64(value):
    need(type(value) is str and re.fullmatch('[0-9a-f]{64}', value) is not None, 'invalid hash')
    return value

def read_json(path, limit=MAX_EVIDENCE):
    with Path(path).open('rb') as f: raw = f.read(limit + 1)
    need(len(raw) <= limit, 'oversized evidence')
    return load_json(raw, max_bytes=limit)

def write_new(path, value):
    """Exclusive atomic evidence, with no replace-existing option."""
    path = Path(os.path.abspath(path))
    for parent in (path.parent, *path.parent.parents):
        need(not parent.is_symlink(), 'symlink evidence ancestor')
    m = path.parent.stat()
    need(m.st_uid == os.getuid() and stat.S_ISDIR(m.st_mode) and not m.st_mode & 0o077,
         'private owned evidence directory required')
    raw = encode(value) + b'\n'
    need(len(raw) <= MAX_EVIDENCE, 'oversized evidence output')
    temporary = path.with_name(path.name + '.partial')
    fd = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    try:
        with os.fdopen(fd, 'wb') as f:
            f.write(raw); f.flush(); os.fsync(f.fileno())
        # link() is exclusive; unlike rename it never overwrites a prior report.
        os.link(temporary, path, follow_symlinks=False)
        temporary.unlink()
        directory = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        try: os.fsync(directory)
        finally: os.close(directory)
    except BaseException:
        # Preserve partial evidence on failed output. Never interpret it as success.
        raise

def validate_state(genesis, state, height, app_hash, history):
    """Reexecute every ordered input; return the final deterministic result."""
    integer(height, 1); hex64(app_hash)
    need(type(history) is list and len(history) == height, 'incomplete replay history')
    app = Protocol4Application(':memory:', expected_genesis=genesis)
    try:
        app._audit_state(genesis,state,height,app_hash)
        app.init_chain(genesis['chain_id'],genesis,genesis['validator_registry']['validators'])
        result = None
        for h,row in enumerate(history,1):
            need(type(row) is dict and set(row) == {'height','txs'} and
                 type(row['height']) is int and row['height'] == h and type(row['txs']) is list,
                 'invalid replay row')
            txs = [app._wire_from_b64(t) for t in row['txs']]
            following,result = app._execute(txs,h)
            app.state,app.height,app.app_hash = following,h,result['app_hash']
        need(app.state == state and app.app_hash == app_hash, 'replayed composite state differs')
        return result
    finally: app.close()

def checkpoint(path, genesis):
    """Read one durable SQLite snapshot; independently replay money and registry."""
    path = Path(path).absolute()
    need(path.is_file() and not path.is_symlink(), 'missing/aliased checkpoint database')
    db = sqlite3.connect(path.as_uri() + '?mode=ro', uri=True, isolation_level=None, timeout=5)
    try:
        db.execute('BEGIN')
        rows = db.execute('SELECT genesis,height,app_hash,state FROM committed').fetchall()
        need(len(rows) == 1, 'missing/ambiguous checkpoint')
        g, height, app_hash, raw = rows[0]
        need(encode(json.loads(g)) == encode(genesis), 'checkpoint genesis mismatch')
        state = load_json(raw.encode(), max_bytes=MAX_EVIDENCE)
        history = [{'height': h, 'txs': json.loads(t)} for h, t in
                   db.execute('SELECT height,txs FROM history ORDER BY height')]
        marker_rows = db.execute('SELECT height,app_hash FROM snapshot_marker').fetchall()
        need(len(marker_rows) <= 1, 'ambiguous bootstrap marker')
        marker = None if not marker_rows else dict(zip(('height','app_hash'),marker_rows[0]))
        count = db.execute('SELECT count(*) FROM blocks').fetchone()[0]
        block = db.execute('SELECT block_hash,request_sha256,txs,result,response FROM blocks WHERE height=?', (height,)).fetchone()
        replay_result = validate_state(genesis, state, height, app_hash, history)
        record = None
        if block is not None:
            result = json.loads(block[3]); raw_response = bytes(block[4])
            need(result.get('height') == height and type(result.get('height')) is int and
                 result.get('app_hash') == app_hash, 'block result not at checkpoint')
            need(raw_response == encode_finalization(result), 'saved full response differs')
            need(encode({k:result.get(k) for k in replay_result}) == encode(replay_result),
                 'saved response differs from independently replayed result')
            need(json.loads(block[2]) == history[-1]['txs'], 'saved wires differ from replay history')
            record = {'block_hash': hex64(block[0]), 'request_sha256': hex64(block[1]),
                      'txs': json.loads(block[2]), 'result': result,
                      'response_hex': raw_response.hex(), 'response_sha256': sha(raw_response)}
        else:
            need(marker == {'height':height,'app_hash':app_hash} and count == 0,
                 'neither local block nor untouched snapshot checkpoint')
        db.execute('COMMIT')
        return {'height':height,'app_hash':app_hash,'state':state,'history':history,
                'snapshot_marker':marker,'local_block_count':count,'latest_block':record}
    finally: db.close()

def fingerprint(saved):
    return {k: saved[k] for k in ('height','app_hash','snapshot_marker','local_block_count')} | {
        'state_sha256':sha(encode(saved['state'])), 'history_sha256':sha(encode(saved['history'])),
        'latest_block_sha256':sha(encode(saved['latest_block'])),
        'registry_epoch':saved['state']['registry']['epoch'],
        'native_receipt_count':len(saved['state']['native']['receipts'])}

def verify_boundary(observed, saved, *, run_id, pid, height, returncode):
    need(type(pid) is int and pid > 0 and type(returncode) is int and returncode == -9,
         'exact child SIGKILL was not observed')
    integer(height, 1)
    need(type(observed) is dict and observed.get('schema') == 1 and type(observed.get('schema')) is int and
         observed.get('run_id') == run_id and observed.get('pid') == pid and type(observed.get('pid')) is int and
         observed.get('phase') == 'committed-before-reply' and observed.get('height') == height and
         type(observed.get('height')) is int and encode(observed.get('checkpoint')) == encode(fingerprint(saved)) and
         observed.get('genesis_sha256') == saved['state']['registry']['native_genesis_sha256'],
         'commit boundary receipt differs from independently read durable state')
    need(saved['latest_block'] is not None and saved['height'] == height, 'durable block missing')
    return {'status':'verified-commit-boundary','height':height,'app_hash':saved['app_hash'],
            'reply_received':False, 'outcome_from_timeout_alone':False}

def remove_dead_socket(path, observed, proc):
    need(proc.poll() == -9 and observed['pid'] == proc.pid, 'must reap the exact killed process first')
    path = Path(path); m = path.lstat()
    expected = observed['socket']
    need(stat.S_ISSOCK(m.st_mode) and m.st_uid == os.getuid() and
         type(expected.get('device')) is int and type(expected.get('inode')) is int and
         (m.st_dev,m.st_ino) == (expected['device'],expected['inode']), 'socket identity changed')
    path.unlink()

def verify_payment_rows(state, exact_wires):
    rows = state['native']['receipts']
    need(len(rows) == len(exact_wires), 'payment receipt count differs')
    for row, wire in zip(rows, exact_wires):
        record = load_json(row[3].encode(), max_bytes=65536)
        need(canonical(record['envelope']) == wire and row[4] == sha(encode(record)),
             'ordered native receipt differs from exact signed payment')
    return {'receipt_count':len(rows),'wire_sha256':[sha(w) for w in exact_wires]}


def verify_replayed_anchor(genesis, history, state, headers, initial_hash, now_ns):
    """Acceptance witness only: reexecute inputs and verify EVERY dynamic header.

    The initial header hash and genesis are external test-controller pins. Do not
    use this as a wallet, trust-renewal mechanism or production light client.
    """
    from validator_witness import verify_header, nanos
    from commit_verifier import header_hash
    hex64(initial_hash)
    need(type(history) is list and 1 <= len(history) < 512 and
         type(headers) is list and len(headers) == len(history)+1, 'complete adjacent header path required')
    need(type(now_ns) is int, 'invalid clock')
    start = nanos(headers[0]['header']['time'])
    need(start <= now_ns < start + 3600 * 10**9, 'fixed one-hour acceptance anchor expired')
    policy = {'expected_block_version':11,'expected_app_version':4,'max_clock_drift_seconds':30}
    app = Protocol4Application(':memory:', expected_genesis=genesis)
    app.init_chain(genesis['chain_id'],genesis,genesis['validator_registry']['validators'])
    prior = None; summaries = []
    try:
        for h, sh in enumerate(headers,1):
            txs = [] if h > len(history) else [app._wire_from_b64(t) for t in history[h-1]['txs']]
            if h <= len(history):
                need(type(history[h-1]['height']) is int and history[h-1]['height'] == h, 'history gap')
            next_state, result = app._execute(txs,h)
            # Registry transition derives the rosters at header h, not at h+2.
            registry = next_state['registry']
            entry = {'signed_header':sh,'validators':registry['active_validators'],
                     'next_validators':registry['next_validators']}
            info = verify_header(entry,genesis['chain_id'],policy,now_ns)
            need(info['height'] == h and info['app_hash'] == app.app_hash, 'signed state commitment mismatch')
            if prior is None: need(info['block_hash'] == initial_hash, 'initial header pin differs')
            else:
                need(block_id(sh['header']['last_block_id']).SerializeToString() ==
                     block_id(prior['commit']['block_id']).SerializeToString(), 'signed ancestry differs')
                need(nanos(sh['header']['time']) > nanos(prior['header']['time']), 'non-increasing header time')
                need(info['validators_hash'] == summaries[-1]['next_validators_hash'],
                     'successor validator set was not committed by preceding header')
            if h <= len(history):
                root = merkle_root([hashlib.sha256(t).digest() for t in txs]).hex()
                need(sh['header']['data_hash'].lower() == root, 'replay inputs not included in signed block')
                need(all(t['code'] == 0 for t in result['tx_results']), 'nonexecuting replay input')
                app.state, app.height, app.app_hash = next_state,h,result['app_hash']
            summaries.append(info); prior = sh
        need(app.state == state, 'replayed monetary/registry state differs')
        return {'height':app.height,'app_hash':app.app_hash,'header_height':summaries[-1]['height'],
                'header_hash':summaries[-1]['block_hash'],'headers_verified':len(headers),
                'genesis_sha256':digest(genesis),'dynamic_validator_history_verified':True,
                'wallet_authority':False}
    finally: app.close()
