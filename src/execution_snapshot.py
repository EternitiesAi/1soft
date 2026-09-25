"""Private, immutable database image for isolated native execution trials.

Only BlockApplication supplies this image, after startup validation or its own
successful deterministic execution. This is NOT an import format, remote cache,
validation bypass for peer snapshots, or a source of financial authority.

SQLite's backup API clones an already validated database into a fresh connection.
The committed image is query-only. Each trial still verifies incoming signatures,
nonces, permissions, fees, balances, supply and budgets via NativeLedger.apply.
The application promotes a staged image only AFTER its durable block commit.
"""
from __future__ import annotations

from dataclasses import dataclass
import json
import sqlite3
import threading

from native_core import NativeLedger, digest


class ExecutionSnapshotFault(RuntimeError):
    """An internal checkpoint/lifecycle fault, not an invalid user transaction."""


def _need(condition: bool, message: str) -> None:
    if not condition:
        raise ExecutionSnapshotFault(message)


@dataclass(frozen=True)
class Checkpoint:
    genesis_hash: str
    height: int
    app_hash: str


def _checkpoint(genesis_hash: str, height: int, app_hash: str) -> Checkpoint:
    import re
    _need(type(height) is int and 0 <= height <= 2**63 - 2, 'invalid execution height')
    _need(all(type(h) is str and re.fullmatch('[0-9a-f]{64}', h) is not None
              for h in (genesis_hash, app_hash)), 'invalid execution checkpoint digest')
    return Checkpoint(genesis_hash, height, app_hash)


class ExecutionSnapshot:
    """One process-local validated state image, never updated in place.

    NativeLedger connection affinity is retained: each fork is created and used
    by its caller thread. Only the read-only source permits cross-thread access,
    serialized with this lock and BlockApplication's existing lifecycle lock.
    Python code or a hostile host with direct object access is outside the model.
    """
    def __init__(self):
        raise TypeError('use from_validated_ledger inside the application lifecycle')

    @classmethod
    def from_validated_ledger(cls, ledger: NativeLedger, height: int, app_hash: str):
        _need(isinstance(ledger, NativeLedger), 'native execution source required')
        _need(not ledger.db.in_transaction, 'cannot capture an unfinished native transaction')
        point = _checkpoint(ledger.genesis_hash, height, app_hash)
        _need(digest(ledger.genesis) == point.genesis_hash, 'execution genesis changed')
        item = object.__new__(cls)
        item._lock = threading.RLock()
        item._closed = False
        item._point = point
        # A private deep copy prevents a caller changing genesis through its input.
        item._genesis_bytes = json.dumps(ledger.genesis, sort_keys=True, separators=(',', ':'),
                                        ensure_ascii=True, allow_nan=False).encode('ascii')
        item._db = sqlite3.connect(':memory:', isolation_level=None, check_same_thread=False)
        try:
            ledger.db.backup(item._db)
            _need(item._db.execute("SELECT v FROM meta WHERE k='genesis'").fetchone() ==
                  (point.genesis_hash,), 'execution image has a different native genesis')
            # These are connection settings, not part of the native database/schema.
            item._db.execute('PRAGMA query_only=ON')
            item._db.set_authorizer(item._read_only)
            item._changes = item._db.total_changes
        except BaseException:
            item._db.close()
            item._closed = True
            raise
        return item

    @staticmethod
    def _read_only(action, arg1, arg2, database, source):
        # The backup API does not execute caller-supplied SQL. Allow only reads
        # and read-only inspection PRAGMAs on the cached source connection.
        if action in (sqlite3.SQLITE_SELECT, sqlite3.SQLITE_READ, sqlite3.SQLITE_FUNCTION):
            return sqlite3.SQLITE_OK
        if action == sqlite3.SQLITE_PRAGMA and arg2 is None and arg1 in (
                'query_only', 'page_count', 'page_size'):
            return sqlite3.SQLITE_OK
        return sqlite3.SQLITE_DENY

    @property
    def checkpoint(self) -> Checkpoint:
        return self._point

    @property
    def closed(self) -> bool:
        return self._closed

    def assert_checkpoint(self, genesis_hash: str, height: int, app_hash: str) -> None:
        with self._lock:
            _need(not self._closed, 'execution image is closed')
            _need(self._point == _checkpoint(genesis_hash, height, app_hash),
                  'execution image does not match committed checkpoint')
            _need(not self._db.in_transaction and self._db.total_changes == self._changes
                  and self._db.execute('PRAGMA query_only').fetchone() == (1,),
                  'committed execution image was made writable or changed')

    def fork(self, genesis_hash: str, height: int, app_hash: str) -> NativeLedger:
        """Return an independent trial database; no saved receipt revalidation.

        Startup still validates all imported committed state. Current transaction
        validation is unchanged. This copies database pages (O(database size));
        it is not zero-copy, a full-history pruning scheme or constant-time state.
        """
        with self._lock:
            self.assert_checkpoint(genesis_hash, height, app_hash)
            trial = NativeLedger(':memory:', json.loads(self._genesis_bytes))
            try:
                self._db.backup(trial.db)
                _need(not trial.db.in_transaction and
                      trial.db.execute('PRAGMA query_only').fetchone()[0] == 0,
                      'execution trial did not receive an isolated writable connection')
                _need(trial.db.execute("SELECT v FROM meta WHERE k='genesis'").fetchone()[0]
                      == genesis_hash, 'forked native genesis mismatch')
            except BaseException:
                trial.close()
                raise
            return trial

    def storage_bytes(self) -> int:
        """SQLite page allocation only; not total Python/process RAM usage."""
        with self._lock:
            self.assert_checkpoint(self._point.genesis_hash, self._point.height, self._point.app_hash)
            return self._db.execute('PRAGMA page_count').fetchone()[0] * self._db.execute(
                'PRAGMA page_size').fetchone()[0]

    def close(self) -> None:
        with self._lock:
            if not self._closed:
                self._db.close()
                self._closed = True
