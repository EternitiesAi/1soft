"""Read-only 1soft account projection from one verified wallet-journal snapshot.

No signing, RPC, policy renewal, imports, migrations or reservation updates. The
source is opened mode=ro, never immutable: committed WAL records must be visible.
SQLite may maintain its normal WAL coordination files; logical wallet tables are
not changed. A private, trusted POSIX workspace and separately pinned policy are
required. This is a historical view, not a payment authorization or balance lock.
"""
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import sqlite3
import stat
import time

from block_application import restore
from certified_wallet import POLICY_FIELDS, MAX_EVIDENCE, MAX_ROWS, nanos
from commit_verifier import encode, load_json, pinned_genesis, verify_state_witness, verify_signed_header
from native_core import FEE_ACCOUNT, address, identifier, require
from wallet_obligations import inventory, MAX_DECISIONS, MAX_REVIEW_BYTES

MAX_JOURNAL_BYTES = 256 * 1024 * 1024
MAX_DECISION_BYTES = 32 * 1024 * 1024
MAX_REPORT_BYTES = 4 * 1024 * 1024
MAX_HEADER_BYTES = 256 * 1024
TABLES = {'checkpoint', 'decisions', 'wallet_evidence', 'wallet_header_progress'}
COLUMNS = {
    'checkpoint': ('id', 'policy_id', 'height', 'block_hash', 'header_ns', 'clock_ns'),
    'decisions': ('id', 'slot', 'review', 'result', 'result_hash'),
    'wallet_evidence': ('id', 'witness', 'witness_hash'),
    'wallet_header_progress': ('id', 'policy_id', 'origin_height', 'origin_hash', 'signed_header', 'header_digest', 'clock_ns'),
}


def _int(value, low=0, high=2**63-1):
    require(type(value) is int and low <= value <= high, 'invalid view integer')
    return value


def _hash(data):
    return hashlib.sha256(data).hexdigest()


def _private_file(path):
    info = path.lstat()
    require(stat.S_ISREG(info.st_mode) and info.st_uid == os.geteuid() and
            info.st_nlink == 1 and stat.S_IMODE(info.st_mode) & 0o077 == 0,
            'private owned regular journal and sidecars required')
    require(info.st_size <= MAX_JOURNAL_BYTES, 'journal exceeds view size bound')


def open_readonly(path: Path) -> sqlite3.Connection:
    """Do not create a missing wallet, execute stored schema, or change its mode."""
    require(os.name == 'posix', 'account inspection requires POSIX file controls')
    path = Path(os.path.abspath(path))
    for parent in (path.parent, *path.parent.parents):
        require(not parent.is_symlink(), 'journal directory symlink refused')
    info = path.parent.stat()
    require(stat.S_ISDIR(info.st_mode) and info.st_uid == os.geteuid() and
            stat.S_IMODE(info.st_mode) & 0o077 == 0, 'private owned journal directory required')
    _private_file(path)
    for suffix in ('-wal', '-shm', '-journal'):
        candidate = Path(str(path) + suffix)
        if candidate.exists() or candidate.is_symlink():
            _private_file(candidate)
    db = sqlite3.connect(path.as_uri() + '?mode=ro', uri=True, isolation_level=None, timeout=2)
    try:
        db.execute('PRAGMA query_only=ON')
        db.execute('PRAGMA trusted_schema=OFF')
        require(db.execute('PRAGMA page_count').fetchone()[0] *
                db.execute('PRAGMA page_size').fetchone()[0] <= MAX_JOURNAL_BYTES,
                'logical journal exceeds view size bound')
        return db
    except BaseException:
        db.close()
        raise


def _policy(genesis_bytes, policy):
    require(type(genesis_bytes) is bytes and len(genesis_bytes) <= 1024*1024,
            'bounded independently selected genesis required')
    require(type(policy) is dict and set(policy) == POLICY_FIELDS, 'invalid view trust policy')
    _int(policy['schema'], 1, 1)
    _int(policy['minimum_header_height'], 1, 2**53-1)
    _int(policy['maximum_age_seconds'], 1, 86400)
    _int(policy['future_skew_seconds'], 0, 30)
    deadline = nanos(policy['trust_expires_utc'])
    trust = pinned_genesis(genesis_bytes, policy['genesis_sha256'])
    return trust, _hash(encode(policy)), deadline


def _schema(db):
    objects = db.execute("SELECT type,name,sql FROM sqlite_master WHERE name NOT LIKE 'sqlite_%'").fetchall()
    tables = set()
    for kind, name, sql in objects:
        require(kind == 'table' and name in TABLES and type(sql) is str and
                'VIRTUAL' not in sql.upper(), 'unsupported journal schema; no implicit migration')
        columns = tuple(row[1] for row in db.execute('PRAGMA table_info("' + name + '")'))
        require(columns == COLUMNS[name], 'journal columns differ from supported wallet')
        tables.add(name)
    require({'checkpoint', 'decisions', 'wallet_evidence'} <= tables,
            'certificate wallet with saved evidence required')
    return tables


def _limits(db, tables):
    for table in ('checkpoint', 'wallet_evidence', 'wallet_header_progress'):
        if table in tables:
            rows = db.execute('SELECT id FROM ' + table).fetchall()
            require(len(rows) <= 1 and (not rows or type(rows[0][0]) is int and rows[0][0] == 1),
                    'invalid singleton journal row')
    count, total = db.execute('SELECT count(*), coalesce(sum(length(CAST(review AS BLOB)) + '
                             'length(CAST(result AS BLOB))),0) FROM decisions').fetchone()
    require(count <= MAX_DECISIONS and total <= MAX_DECISION_BYTES, 'signing inventory exceeds view bound')
    require(db.execute('SELECT 1 FROM decisions WHERE length(CAST(review AS BLOB)) > ? OR '
                       'length(CAST(result AS BLOB)) > 16384 LIMIT 1', (MAX_REVIEW_BYTES,)).fetchone() is None,
            'individual signing decision exceeds view bound')
    require(db.execute('SELECT 1 FROM wallet_evidence WHERE length(CAST(witness AS BLOB)) > ?',
                       (MAX_EVIDENCE,)).fetchone() is None, 'saved witness exceeds view bound')
    if 'wallet_header_progress' in tables:
        require(db.execute('SELECT 1 FROM wallet_header_progress WHERE length(CAST(signed_header AS BLOB)) > ?',
                           (MAX_HEADER_BYTES,)).fetchone() is None, 'saved header exceeds view bound')


def _frontier(db, tables, trust, policy_id, cert, checkpoint):
    """Recheck optional committed header-progress metadata; never advance it."""
    if 'wallet_header_progress' not in tables:
        return cert['height'], checkpoint[4]
    row = db.execute('SELECT policy_id,origin_height,origin_hash,signed_header,header_digest,clock_ns '
                     'FROM wallet_header_progress WHERE id=1').fetchone()
    if row is None:
        return cert['height'], checkpoint[4]
    require(row[0] == policy_id and row[1] == cert['height'] and row[2] == cert['block_hash'],
            'header progress belongs to a different state checkpoint')
    require(type(row[3]) is str and _hash(row[3].encode()) == row[4], 'header-progress digest differs')
    header = load_json(row[3].encode(), max_bytes=MAX_HEADER_BYTES)
    verified = verify_signed_header(header, trust)
    require(verified['height'] > cert['height'] and nanos(header['header']['time']) >= checkpoint[3],
            'invalid saved header frontier')
    _int(row[5], checkpoint[4])
    return verified['height'], row[5]


def _activity(ledger, account):
    result = []
    for record_json, in ledger.db.execute('SELECT record FROM receipts ORDER BY sequence DESC'):
        record = load_json(record_json.encode(), max_bytes=32768)
        body = record['envelope']['body']; op = body['op']
        sender = body['sender']
        recipient = op.get('to') if op['type'] == 'transfer' else (
                    address(op['public_key']) if op['type'] == 'open_account' else None)
        amount = op.get('units', 0) if op['type'] in ('transfer', 'open_account') else 0
        if sender == account:
            delta = -(amount + record['fee_units']); fee = record['fee_units']
        elif recipient == account:
            delta = amount; fee = 0
        else:
            continue
        result.append({'native_txid': record['txid'], 'sequence': record['sequence'],
                       'height': record['height'], 'operation': op['type'],
                       'counterparty': recipient if sender == account else sender,
                       'delta_units': delta, 'fee_charged_to_account_units': fee,
                       'scope': 'receipt in the verified historical native state'})
    return result


def _allowance(row, pending, account, next_height):
    reasons = []
    if row['revoked']: reasons.append('revoked')
    if row['epoch'] != account['epoch']: reasons.append('older_authority_epoch')
    if row['expires'] < next_height: reasons.append('expired_at_next_height')
    remaining = row['cap'] - row['spent']
    return {'id': row['id'], 'cap_units': row['cap'], 'recorded_spent_units': row['spent'],
            'pending_debit_units': pending, 'uncommitted_allowance_units': max(0, remaining - pending),
            'overcommitted_units': max(0, pending - remaining), 'expires_height': row['expires'],
            'active_at_next_height': not reasons, 'inactive_reasons': reasons,
            'permitted_recipients': json.loads(row['recipients'])}


def _project(db, genesis_bytes, policy, account, observed_ns, limit):
    trust, policy_id, deadline = _policy(genesis_bytes, policy)
    tables = _schema(db); _limits(db, tables)
    checkpoint = db.execute('SELECT policy_id,height,block_hash,header_ns,clock_ns FROM checkpoint WHERE id=1').fetchone()
    require(checkpoint is not None and checkpoint[0] == policy_id, 'journal trust policy differs')
    _int(checkpoint[1], 1, 2**53-1); _int(checkpoint[3]); _int(checkpoint[4])
    saved = db.execute('SELECT witness,witness_hash FROM wallet_evidence WHERE id=1').fetchone()
    require(saved is not None and type(saved[0]) is str and _hash(saved[0].encode()) == saved[1],
            'no intact verified state saved; sync the wallet first')
    witness = load_json(saved[0].encode(), max_bytes=MAX_EVIDENCE)
    require(type(witness) is dict and set(witness) == {'schema','state','state_commit'} and
            type(witness['schema']) is int and witness['schema'] == 1, 'invalid saved witness')
    state = witness['state']; cert = verify_state_witness(state, witness['state_commit'], trust)
    header_ns = nanos(witness['state_commit']['header']['time'])
    require((cert['height'], cert['block_hash'], header_ns) == tuple(checkpoint[1:4]),
            'saved witness does not match the wallet checkpoint')
    require(cert['height'] >= policy['minimum_header_height'], 'checkpoint below trusted minimum')
    require(all(type(rows) is list and len(rows) <= MAX_ROWS for rows in state['native'].values()),
            'native state exceeds view row bound')
    frontier, frontier_clock = _frontier(db, tables, trust, policy_id, cert, checkpoint)
    ledger = restore(state['genesis'], state['native'])
    try:
        require(int(dict(ledger.db.execute('SELECT k,v FROM meta'))['height']) <= state['height'],
                'native execution height exceeds state checkpoint')
        owner = ledger._account(account)
        summary = inventory(db, policy_id, ledger, state['height'])
        pending = summary['accounts'].get(account, 0)
        budgets = []
        if ledger.budgets is not None:
            for row in ledger.db.execute('SELECT * FROM budgets WHERE owner=? ORDER BY id', (account,)):
                budgets.append(_allowance(row, summary['budgets'].get(row['id'],0), owner, state['height']+1))
        budget_map = {b['id']:b for b in budgets}
        grants = []
        for row in ledger.db.execute('SELECT * FROM grants WHERE owner=? ORDER BY id', (account,)):
            grant = _allowance(row, summary['grants'].get(row['id'],0), owner, state['height']+1)
            parent = None
            if ledger.budgets is not None:
                parent = ledger.db.execute('SELECT budget_id FROM grant_budgets WHERE grant_id=?',(row['id'],)).fetchone()[0]
                if not budget_map[parent]['active_at_next_height']:
                    grant['inactive_reasons'].append('parent_budget_inactive')
                    grant['active_at_next_height'] = False
            grant['budget_id'] = parent
            grant['shared_budget_headroom_units'] = budget_map[parent]['uncommitted_allowance_units'] if parent else None
            grants.append(grant)
        decisions = [{k:v for k,v in e.items() if k != 'lane'} for e in summary['entries'] if e['account'] == account]
        history = _activity(ledger, account)
        opening = sum(a['units'] for a in ledger.genesis['allocations'] if address(a['public_key']) == account)
        net_change = sum(item['delta_units'] for item in history)
        require(opening + net_change == owner['balance'],
                'selected account does not reconcile to its complete native receipt history')
        flags = []
        if observed_ns >= deadline: flags.append('policy_expired')
        if observed_ns < frontier_clock: flags.append('local_clock_rollback')
        if header_ns > observed_ns + policy['future_skew_seconds']*10**9: flags.append('snapshot_from_future')
        if observed_ns-header_ns > policy['maximum_age_seconds']*10**9: flags.append('snapshot_too_old')
        if frontier > cert['height']: flags.append('newer_headers_need_state_sync')
        for grant in grants:
            ceiling = min(max(0, owner['balance']-pending), grant['uncommitted_allowance_units'])
            if grant['budget_id']:
                ceiling = min(ceiling, grant['shared_budget_headroom_units'])
            grant['effective_next_debit_ceiling_units'] = (None if flags else
                (ceiling if grant['active_at_next_height'] else 0))
        collections = {'budgets':budgets, 'grants':grants, 'decisions':decisions, 'history':history}
        view = {'schema':1, 'product':'1soft', 'kind':'verified-historical-account-view',
                'account':account, 'asset':ledger.genesis['asset'], 'units':'atomic native units',
                'account_nonce':owner['nonce'], 'account_epoch':owner['epoch'], 'native_fee_units':ledger.genesis['fee'],
                'state':{'application_height':state['height'], 'witness_header_height':cert['height'],
                         'verified_header_height':frontier, 'app_hash':cert['state_app_hash'],
                         'header_hash':cert['block_hash'], 'native_genesis_hash':trust.native_genesis_hash,
                         'header_time_utc':witness['state_commit']['header']['time']},
                'observation':{'observed_at_ns':observed_ns, 'policy_expires_utc':policy['trust_expires_utc'],
                               'within_local_time_and_frontier_policy':not flags, 'blockers':flags,
                               'latest_state_guaranteed':False},
                'funds':{'recorded_balance_units':owner['balance'], 'pending_debit_units':pending,
                         'uncommitted_headroom_units':max(0,owner['balance']-pending),
                         'overcommitted_units':max(0,pending-owner['balance']),
                         'genesis_allocation_units':opening, 'net_recorded_change_units':net_change,
                         'complete_receipt_history_reconciles':True},
                'coverage':{'limit_per_list':limit, 'total_items':{k:len(v) for k,v in collections.items()},
                            'truncated_lists':[k for k,v in collections.items() if len(v)>limit],
                            'totals_include_all_verified_decisions':True},
                'authority':{'signing_enabled':False, 'broadcast_enabled':False, 'wallet_state_modified':False,
                             'fresh_payment_authorization':False, 'scope':'this journal and historical snapshot only'},
                **{k:v[:limit] for k,v in collections.items()}}
        view['view_sha256'] = _hash(b'1soft/account-view/v1\x00' + encode(view))
        require(len(encode(view)) <= MAX_REPORT_BYTES, 'account view exceeds output bound')
        return view
    finally:
        ledger.close()


def read_account(journal: Path, genesis_bytes: bytes, policy: dict, account: str,
                 *, observed_at_ns: int | None = None, limit: int = 50) -> dict:
    """One consistent read transaction; never creates or upgrades the wallet.

    Expired/behind snapshots remain inspectable, but are visibly flagged. Invalid
    evidence fails rather than returning zero funds or a claimed current balance.
    Counts are historical native units, not dollars, card balances or trading quotes.
    """
    identifier(account); require(account != FEE_ACCOUNT, 'system account is not a customer account')
    _int(limit, 1, 200)
    observed_at_ns = time.time_ns() if observed_at_ns is None else _int(observed_at_ns)
    _policy(genesis_bytes, policy)  # wrong trust must fail before opening a file
    db = open_readonly(journal)
    try:
        db.execute('BEGIN')
        view = _project(db, genesis_bytes, policy, account, observed_at_ns, limit)
        db.execute('ROLLBACK')  # explicitly end a transaction that made no changes
        return view
    finally:
        if db.in_transaction: db.execute('ROLLBACK')
        db.close()
