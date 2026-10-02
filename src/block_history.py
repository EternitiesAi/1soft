"""Opt-in bounded LOCAL block-result history; never prunes native receipts.

This table is node-local metadata outside AppHash. Monetary state, replay records,
wallet obligations, snapshots and CometBFT's block store remain unchanged. Only a
successful ordinary block Commit may remove old local block-result rows. All
policy/frontier changes share that same SQLite transaction. This is NOT a total
node-disk bound, a history archive, or proof of historical transaction absence.
"""
from __future__ import annotations

import sqlite3
from typing import Any

from native_core import require

TABLE = 'block_history_policy'
COLUMNS = ('id', 'schema_version', 'keep_blocks', 'bootstrap_height',
           'pruned_through', 'last_height', 'last_app_hash')
SCHEMA = 1
MIN_KEEP = 2
MAX_KEEP = 1_000_000


def validate_keep(value: int | None) -> None:
    require(value is None or type(value) is int and MIN_KEEP <= value <= MAX_KEEP,
            'block history keep must be an integer from 2 through 1000000')


def _height(value: Any) -> None:
    require(type(value) is int and 0 <= value <= 2**63 - 2,
            'invalid local history height')


def _hash(value: Any, *, empty: bool = False) -> None:
    require(type(value) is str and ((empty and value == '') or
            len(value) == 64 and all(c in '0123456789abcdef' for c in value)),
            'invalid local history AppHash')


def _span(db: sqlite3.Connection) -> tuple[int, int | None, int | None]:
    count, low, high = db.execute('SELECT count(*),min(height),max(height) FROM blocks').fetchone()
    return count, low, high


def _marker(db: sqlite3.Connection) -> tuple[int, str] | None:
    row = db.execute('SELECT height,app_hash FROM state_sync_marker WHERE id=1').fetchone()
    if row is None:
        return None
    _height(row[0]); _hash(row[1])
    require(row[0] > 0, 'invalid bootstrap marker height')
    return tuple(row)


class BlockHistory:
    """Persisted opt-in policy; absence of a CLI flag reuses an existing policy.

    A different explicit policy is refused, not silently adopted. First enabling
    retention on a complete older store does not delete rows during startup: the
    next successful block commit enforces the bound. No API disables/relabels a
    previously truncated store as an archive. Hostile local DB edits are outside
    the trust model, but normal inconsistencies and gaps fail closed.
    """
    def __init__(self, db: sqlite3.Connection, keep: int):
        self.db = db
        self.keep = keep

    @classmethod
    def open(cls, db: sqlite3.Connection, requested_keep: int | None,
             height: int, app_hash: str) -> BlockHistory | None:
        validate_keep(requested_keep)
        require(not db.in_transaction, 'history startup requires an idle connection')
        kind = db.execute("SELECT type FROM sqlite_master WHERE name=?", (TABLE,)).fetchone()
        if kind is None and requested_keep is None:
            return None  # Preserve default legacy storage/schema exactly.
        require(kind is None or kind[0] == 'table', 'invalid history policy object')
        db.execute('BEGIN IMMEDIATE')
        try:
            if kind is None:
                _height(height); _hash(app_hash, empty=height == 0)
                mark = _marker(db)
                bootstrap = mark[0] if mark else 0
                require(bootstrap <= height, 'bootstrap marker exceeds committed height')
                count, low, high = _span(db)
                expected = height - bootstrap
                require(count == expected and
                        (count == 0 or (low == bootstrap + 1 and high == height)),
                        'cannot enable retention on incomplete unexplained local history')
                db.execute('''CREATE TABLE block_history_policy (
                    id INTEGER PRIMARY KEY CHECK(id=1), schema_version INTEGER NOT NULL,
                    keep_blocks INTEGER NOT NULL, bootstrap_height INTEGER NOT NULL,
                    pruned_through INTEGER NOT NULL, last_height INTEGER NOT NULL,
                    last_app_hash TEXT NOT NULL)''')
                db.execute('INSERT INTO block_history_policy VALUES (1,?,?,?,?,?,?)',
                           (SCHEMA, requested_keep, bootstrap, 0, height, app_hash))
            columns = tuple(row[1] for row in db.execute('PRAGMA table_info(block_history_policy)'))
            require(columns == COLUMNS, 'unsupported local history schema')
            rows = db.execute('SELECT * FROM block_history_policy').fetchall()
            require(len(rows) == 1 and rows[0][0] == 1, 'missing or duplicate local history policy')
            row = rows[0]
            require(type(row[1]) is int and row[1] == SCHEMA, 'unsupported history policy version')
            validate_keep(row[2]); require(row[2] is not None, 'missing history retention value')
            require(requested_keep is None or requested_keep == row[2],
                    'explicit retention policy differs; no implicit policy change')
            result = cls(db, row[2])
            result.audit(height, app_hash)
            db.execute('COMMIT')
            return result
        except BaseException:
            if db.in_transaction:
                db.execute('ROLLBACK')
            raise

    def _policy(self) -> tuple:
        rows = self.db.execute('SELECT * FROM block_history_policy').fetchall()
        require(len(rows) == 1, 'missing or duplicate history policy')
        row = tuple(rows[0])
        require(row[:3] == (1, SCHEMA, self.keep), 'history policy changed during operation')
        for value in row[3:6]:
            _height(value)
        _hash(row[6], empty=row[5] == 0)
        require(row[3] <= row[5] and (row[4] == 0 or row[3] < row[4] < row[5]),
                'invalid bootstrap/pruning frontier')
        return row

    def audit(self, height: int, app_hash: str) -> dict:
        row = self._policy()
        _, _, keep, bootstrap, pruned, last, last_hash = row
        require((last, last_hash) == (height, app_hash), 'history checkpoint differs from committed state')
        disk = self.db.execute('SELECT height,app_hash FROM committed WHERE id=1').fetchone()
        require(tuple(disk) == (height, app_hash) if disk is not None else (height == 0 and app_hash == ''),
                'history checkpoint differs from durable application')
        mark = _marker(self.db)
        require((mark is None and bootstrap == 0) or
                (mark is not None and mark[0] == bootstrap), 'history/bootstrap marker differs')
        if mark and height == bootstrap:
            require(mark[1] == app_hash, 'bootstrap AppHash differs at restored height')
        count, low, high = _span(self.db)
        start = max(bootstrap, pruned) + 1
        expected = max(0, height - start + 1)
        require(count == expected and (count == 0 or (low == start and high == height)),
                'local history has an unexplained gap or extra row')
        if pruned:
            require(count <= keep, 'retained block window exceeded')
        if count:
            latest = self.db.execute('SELECT app_hash FROM blocks WHERE height=?', (height,)).fetchone()
            require(latest is not None and latest[0] == app_hash, 'latest local block differs from checkpoint')
        return {'keep_blocks': keep, 'bootstrap_height': bootstrap, 'pruned_through': pruned,
                'retained_from': low, 'retained_through': high, 'retained_count': count,
                'within_configured_window': count <= keep}

    def advance(self, old_height: int, old_app_hash: str,
                height: int, app_hash: str) -> None:
        """Called AFTER the new committed/block rows, BEFORE their shared commit."""
        require(self.db.in_transaction, 'history changes require caller-owned transaction')
        row = self._policy()
        require((row[5], row[6]) == (old_height, old_app_hash) and height == old_height + 1,
                'history advance does not extend its exact checkpoint')
        _height(height); _hash(app_hash)
        bootstrap, prior_floor = row[3:5]
        count, low, high = _span(self.db)
        expected = height - max(bootstrap, prior_floor)
        require(count == expected and low == max(bootstrap, prior_floor) + 1 and high == height,
                'history gap before pruning; nothing may be silently discarded')
        cutoff = height - self.keep
        floor = max(prior_floor, cutoff) if cutoff > bootstrap else prior_floor
        if floor > prior_floor:
            removed = self.db.execute('DELETE FROM blocks WHERE height<=?', (floor,))
            require(removed.rowcount == floor - max(bootstrap, prior_floor),
                    'history deletion count differs from contiguous prefix')
        self.db.execute('UPDATE block_history_policy SET pruned_through=?,last_height=?,last_app_hash=? WHERE id=1',
                        (floor, height, app_hash))
        self.audit(height, app_hash)

    def install_snapshot(self, height: int, app_hash: str) -> None:
        """Local bootstrap marker joins the existing atomic snapshot install.

        StateSyncManager independently limits this call to a fresh application or
        its exact untouched snapshot-only checkpoint. Pruning cannot make a node
        eligible again: at least two executed block rows are always retained.
        """
        require(self.db.in_transaction, 'snapshot history install requires transaction')
        row = self._policy()
        require(row[4] == 0 and row[5] == row[3] and height >= row[5],
                'ordinary or pruned history cannot be relabelled as snapshot-only')
        require(self.db.execute('SELECT 1 FROM blocks LIMIT 1').fetchone() is None,
                'snapshot history must have no local block rows')
        self.db.execute('UPDATE block_history_policy SET bootstrap_height=?,last_height=?,last_app_hash=? WHERE id=1',
                        (height, height, app_hash))
        self.audit(height, app_hash)

    def init_chain(self, app_hash: str) -> None:
        require(self.db.in_transaction, 'history genesis update requires transaction')
        row = self._policy()
        require(row[3:6] == (0, 0, 0) and row[6] == '', 'history already initialized')
        self.db.execute('UPDATE block_history_policy SET last_app_hash=? WHERE id=1', (app_hash,))
        self.audit(0, app_hash)

    def classify_missing(self, height: int, current_height: int, app_hash: str) -> str:
        info = self.audit(current_height, app_hash)
        if height <= info['bootstrap_height']:
            return 'not_retained_by_state_sync'
        if height <= info['pruned_through']:
            return 'pruned_local_block_results'
        require(False, 'missing block inside retained history; storage requires investigation')
        raise AssertionError('unreachable')


def describe(app) -> dict:
    """Unauthenticated local availability metadata, never payment absence proof."""
    if app.block_history is not None:
        info = app.block_history.audit(app.height, app.app_hash)
    else:
        count, low, high = _span(app.db)
        mark = _marker(app.db)
        info = {'keep_blocks': None, 'bootstrap_height': mark[0] if mark else 0,
                'pruned_through': 0, 'retained_from': low, 'retained_through': high,
                'retained_count': count, 'within_configured_window': True}
    return {'schema': 1, 'scope': 'local_application_block_results',
            'application_height': app.height, 'availability': info,
            'native_receipts_pruned': False,
            'native_receipt_count': len(app.native['receipts']) if app.native is not None else 0,
            'cometbft_retain_height': 0,
            'engine_history_pruning_requested': False,
            'historical_transaction_absence_proven': False,
            'total_storage_bounded': False,
            'notice': 'Local block-result availability is not consensus evidence; native receipts remain complete.'}
