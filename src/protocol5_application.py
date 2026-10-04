"""Atomic fresh-genesis Protocol 5 application lifecycle."""
from __future__ import annotations

import hashlib
import os
from pathlib import Path
import re
import sqlite3
import stat
import threading

from block_application import StoreLock, transaction_data_size
from protocol5_abci_wire import encode_finalization
from protocol5_encoding import (
    EncodingError, GenesisDocument, canonical_json, comet_validator_set,
    decode_canonical_json, genesis_document,
)
from protocol5_state import (
    CODE_CAPACITY, CODE_MALFORMED, HistoryLimitError, StateError,
    application_hash, execute_block, initial_state, replay_state, result,
)

APP_NAME = "1soft-shielded-development"
APP_VERSION = 5
REQUEST_DOMAIN = b"1soft/shielded-finalize-request/v1\0"


class Protocol5Error(ValueError):
    pass


def _need(condition: bool, message: str) -> None:
    if not condition:
        raise Protocol5Error(message)


def _copy(value):
    return decode_canonical_json(canonical_json(value))


SCHEMA_SQL = {
    "committed": """CREATE TABLE committed (
                id INTEGER PRIMARY KEY CHECK(id=1),
                genesis BLOB NOT NULL,
                height INTEGER NOT NULL,
                app_hash TEXT NOT NULL,
                state BLOB NOT NULL
              )""",
    "blocks": """CREATE TABLE blocks (
                height INTEGER PRIMARY KEY,
                block_hash TEXT NOT NULL,
                request_sha256 TEXT NOT NULL,
                txs BLOB NOT NULL,
                result BLOB NOT NULL,
                response BLOB NOT NULL
              )""",
    "history": """CREATE TABLE history (
                height INTEGER PRIMARY KEY,
                txs BLOB NOT NULL
              )""",
    "snapshot_marker": """CREATE TABLE snapshot_marker (
                id INTEGER PRIMARY KEY CHECK(id=1),
                genesis_sha256 TEXT NOT NULL,
                profile_id TEXT NOT NULL,
                deployment_id TEXT NOT NULL,
                height INTEGER NOT NULL,
                app_hash TEXT NOT NULL,
                payload_sha256 TEXT NOT NULL
              )""",
}

SCHEMA_INFO = {
    "committed": (
        ("id", "INTEGER", 0, 1), ("genesis", "BLOB", 1, 0),
        ("height", "INTEGER", 1, 0), ("app_hash", "TEXT", 1, 0),
        ("state", "BLOB", 1, 0),
    ),
    "blocks": (
        ("height", "INTEGER", 0, 1), ("block_hash", "TEXT", 1, 0),
        ("request_sha256", "TEXT", 1, 0), ("txs", "BLOB", 1, 0),
        ("result", "BLOB", 1, 0), ("response", "BLOB", 1, 0),
    ),
    "history": (
        ("height", "INTEGER", 0, 1), ("txs", "BLOB", 1, 0),
    ),
    "snapshot_marker": (
        ("id", "INTEGER", 0, 1), ("genesis_sha256", "TEXT", 1, 0),
        ("profile_id", "TEXT", 1, 0), ("deployment_id", "TEXT", 1, 0),
        ("height", "INTEGER", 1, 0), ("app_hash", "TEXT", 1, 0),
        ("payload_sha256", "TEXT", 1, 0),
    ),
}


def _normalized_sql(sql: str) -> str:
    return " ".join(sql.split())


def _safe_store_path(path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    parent = path.parent.lstat()
    _need(stat.S_ISDIR(parent.st_mode), "unsafe Protocol 5 storage parent")
    _need(parent.st_uid == os.getuid(), "unsafe Protocol 5 storage parent owner")
    _need(not parent.st_mode & 0o022, "unsafe Protocol 5 storage parent mode")
    candidates = (
        path, Path(str(path) + "-wal"), Path(str(path) + "-shm"),
        path.with_name(path.name + ".lock"),
    )
    for candidate in candidates:
        try:
            mode = candidate.lstat()
        except FileNotFoundError:
            continue
        _need(not stat.S_ISLNK(mode.st_mode),
              "unsafe Protocol 5 storage symlink")
        _need(stat.S_ISREG(mode.st_mode), "unsafe Protocol 5 storage object")
        _need(mode.st_uid == os.getuid(), "unsafe Protocol 5 storage owner")
        _need(not mode.st_mode & 0o022, "unsafe Protocol 5 storage mode")


def _audit_schema(db: sqlite3.Connection, *, allow_empty: bool = False) -> bool:
    rows = db.execute(
        "SELECT type,name,sql FROM sqlite_master "
        "WHERE name NOT LIKE 'sqlite_%' ORDER BY type,name").fetchall()
    if allow_empty and not rows:
        return False
    expected_names = [("table", name) for name in sorted(SCHEMA_SQL)]
    _need([(row[0], row[1]) for row in rows] == expected_names,
          "Protocol 5 database schema objects differ")
    for object_type, table, sql in rows:
        _need(object_type == "table" and type(sql) is str
              and _normalized_sql(sql) == _normalized_sql(SCHEMA_SQL[table]),
              "Protocol 5 database table definition differs")
        observed = tuple(
            (row[1], row[2].upper(), row[3], row[5])
            for row in db.execute("PRAGMA table_info(" + table + ")").fetchall())
        _need(observed == SCHEMA_INFO[table],
              "Protocol 5 database column semantics differ")
    return True


def _votes(rows: list[dict], validator_set, height: int) -> list[dict]:
    if height == 1:
        _need(rows == [], "height-one last commit must be empty")
        return []
    _need(type(rows) is list, "invalid last-commit votes")
    wanted = {v.address.hex(): v.power for v in validator_set.validators}
    observed = {}
    closed = []
    for row in rows:
        _need(type(row) is dict and set(row) == {
            "address", "power", "block_id_flag"
        }, "invalid last-commit vote")
        address = row["address"]
        power = row["power"]
        flag = row["block_id_flag"]
        _need(type(address) is str and len(address) == 40
              and all(ch in "0123456789abcdef" for ch in address)
              and type(power) is int and type(flag) is int and flag in (1, 2, 3),
              "invalid last-commit vote")
        _need(address not in observed, "duplicate last-commit validator")
        observed[address] = power
        closed.append({"address": address, "power": power, "block_id_flag": flag})
    _need(observed == wanted, "last-commit validator roster differs")
    commit_power = sum(row["power"] for row in closed if row["block_id_flag"] == 2)
    _need(commit_power * 3 > validator_set.total_power * 2,
          "insufficient last-commit voting power")
    return closed


class Protocol5Application:
    def __init__(self, path: str | Path, worker, *,
                 expected_genesis: bytes | None = None):
        self.lock = threading.RLock()
        self.worker = worker
        self.expected_genesis_raw = expected_genesis
        self.genesis: GenesisDocument | None = None
        self.validator_set = None
        self.state: dict | None = None
        self.height = 0
        self.app_hash = ""
        self.pending: dict | None = None
        self.closed = False
        self.store_lock = None
        db_path = str(path)
        if db_path != ":memory:":
            p = Path(path)
            _safe_store_path(p)
            self.store_lock = StoreLock(p.with_name(p.name + ".lock"))
            os.chmod(p.with_name(p.name + ".lock"), 0o600)
        try:
            self.db = sqlite3.connect(
                db_path, isolation_level=None, timeout=10, check_same_thread=False)
            existing_schema = _audit_schema(self.db, allow_empty=True)
            self.db.execute("PRAGMA journal_mode=WAL")
            self.db.execute("PRAGMA synchronous=FULL")
            if not existing_schema:
                self.db.executescript(";\n".join(SCHEMA_SQL.values()) + ";")
            _audit_schema(self.db)
            if db_path != ":memory:":
                _safe_store_path(Path(path))
                for candidate in (
                        Path(path), Path(str(path) + "-wal"),
                        Path(str(path) + "-shm"),
                        Path(path).with_name(Path(path).name + ".lock")):
                    if candidate.exists():
                        os.chmod(candidate, 0o600)
            row = self.db.execute(
                "SELECT genesis,height,app_hash,state FROM committed WHERE id=1"
            ).fetchone()
            if row is not None:
                raw_genesis = bytes(row[0])
                if expected_genesis is not None:
                    _need(raw_genesis == expected_genesis,
                          "committed Protocol 5 genesis differs")
                genesis = genesis_document(raw_genesis)
                height = row[1]
                _need(type(height) is int, "invalid committed Protocol 5 height")
                state = decode_canonical_json(bytes(row[3]))
                replay_state(genesis, state, height, worker)
                app_hash = application_hash(genesis, height, state)
                _need(row[2] == app_hash, "committed Protocol 5 AppHash differs")
                self.genesis = genesis
                self.validator_set = comet_validator_set(genesis.value["validators"])
                self.state, self.height, self.app_hash = state, height, app_hash
                self._audit_database()
            from protocol5_state_sync import Protocol5StateSync
            self.state_sync = Protocol5StateSync(self)
        except BaseException:
            if hasattr(self, "db"):
                self.db.close()
            if self.store_lock is not None:
                self.store_lock.close()
            raise

    def _audit_database(self) -> None:
        assert self.genesis is not None and self.state is not None
        histories = self.db.execute(
            "SELECT height,txs FROM history ORDER BY height").fetchall()
        _need(len(histories) == self.height, "Protocol 5 history rows incomplete")
        if histories:
            for block, row in zip(self.state["execution_blocks"], histories):
                _need(row[0] == block["height"]
                      and decode_canonical_json(bytes(row[1])) == block["transactions"],
                      "Protocol 5 history row differs")
        blocks = self.db.execute(
            "SELECT height,result,response FROM blocks ORDER BY height").fetchall()
        for height, raw_result, response in blocks:
            retained = decode_canonical_json(bytes(raw_result))
            _need(retained["height"] == height
                  and bytes(response) == encode_finalization(retained),
                  "retained Protocol 5 finalization differs")
        marker = self.db.execute(
            "SELECT genesis_sha256,profile_id,deployment_id,height,app_hash "
            "FROM snapshot_marker WHERE id=1").fetchone()
        if self.height > 0:
            current = [row for row in blocks if row[0] == self.height]
            if current:
                _need(marker is None, "ordinary checkpoint retained snapshot marker")
            else:
                _need(marker == (
                    self.genesis.sha256.hex(), self.genesis.profile.identity.hex(),
                    self.genesis.deployment.identity.hex(), self.height, self.app_hash),
                    "snapshot-only checkpoint marker differs")
                _need(not blocks, "snapshot checkpoint invented block rows")
        else:
            _need(not blocks and marker is None, "height-zero response or marker differs")

    def close(self):
        with self.lock:
            if self.closed:
                return
            self.pending = None
            self.db.close()
            if self.store_lock is not None:
                self.store_lock.close()
            self.closed = True

    def __enter__(self):
        return self

    def __exit__(self, *_):
        self.close()

    def info(self) -> dict:
        with self.lock:
            return {
                "name": APP_NAME, "version": APP_VERSION, "height": self.height,
                "app_hash": self.app_hash, "initialized": self.genesis is not None,
            }

    def init_chain(self, chain_id: str, raw_genesis: bytes,
                   initial_validators: list[dict], initial_height: int = 1) -> str:
        with self.lock:
            _need(type(raw_genesis) is bytes, "canonical Protocol 5 genesis bytes required")
            genesis = genesis_document(raw_genesis)
            _need(chain_id == genesis.value["chain_id"], "engine chain identity differs")
            _need(initial_height == 1 and type(initial_height) is int,
                  "Protocol 5 initial height must equal one")
            if self.expected_genesis_raw is not None:
                _need(raw_genesis == self.expected_genesis_raw,
                      "unexpected Protocol 5 genesis")
            _need(type(initial_validators) is list and len(initial_validators) == 4,
                  "engine initial validator count differs")
            observed = {}
            for row in initial_validators:
                _need(type(row) is dict and set(row) == {"public_key", "power"},
                      "invalid engine initial validator")
                key, power = row["public_key"], row["power"]
                _need(type(key) is str and len(key) == 64
                      and all(ch in "0123456789abcdef" for ch in key)
                      and type(power) is int and power > 0 and key not in observed,
                      "invalid engine initial validator")
                observed[key] = power
            wanted = {row["public_key"]: row["power"]
                      for row in genesis.value["validators"]}
            _need(observed == wanted, "engine initial validators differ")
            if self.genesis is not None:
                _need(self.genesis.raw == raw_genesis and self.height == 0,
                      "Protocol 5 chain already initialized")
                return self.app_hash
            state = initial_state(genesis, self.worker)
            app_hash = application_hash(genesis, 0, state)
            self.db.execute("BEGIN IMMEDIATE")
            try:
                self.db.execute(
                    "INSERT INTO committed VALUES (1,?,?,?,?)",
                    (raw_genesis, 0, app_hash, canonical_json(state)))
                self.db.execute("COMMIT")
            except BaseException:
                if self.db.in_transaction:
                    self.db.execute("ROLLBACK")
                raise
            self.genesis = genesis
            self.validator_set = comet_validator_set(genesis.value["validators"])
            self.state, self.app_hash = state, app_hash
            return app_hash

    def _require_initialized(self):
        _need(self.genesis is not None and self.state is not None
              and self.validator_set is not None, "Protocol 5 chain not initialized")

    def _container_bounds(self, txs: list[bytes]) -> None:
        self._require_initialized()
        assert self.genesis is not None
        limits = self.genesis.value["limits"]
        _need(type(txs) is list and all(type(raw) is bytes for raw in txs)
              and len(txs) <= limits["max_txs_per_block"],
              "Protocol 5 block transaction bound exceeded")
        _need(transaction_data_size(txs) <= limits["max_block_bytes"],
              "Protocol 5 block byte bound exceeded")

    def check_tx(self, raw: bytes) -> dict:
        with self.lock:
            self._require_initialized()
            if type(raw) is not bytes:
                return result(CODE_MALFORMED)
            try:
                assert self.genesis is not None and self.state is not None
                _, results = execute_block(
                    self.genesis, self.state, [raw], self.height + 1, self.worker)
                return results[0]
            except HistoryLimitError:
                return result(CODE_CAPACITY)

    def prepare_proposal(self, candidates: list[bytes], height: int,
                         max_bytes: int) -> list[bytes]:
        with self.lock:
            self._require_initialized()
            assert self.genesis is not None and self.state is not None
            limits = self.genesis.value["limits"]
            _need(type(candidates) is list and type(height) is int
                  and height == self.height + 1 and type(max_bytes) is int
                  and max_bytes >= 0, "invalid Protocol 5 proposal context")
            accepted = []
            inspected = 0
            selected_limit = min(max_bytes, limits["max_block_bytes"])
            for raw in candidates[:limits["max_candidates"]]:
                if type(raw) is not bytes:
                    continue
                cost = transaction_data_size([raw])
                if inspected + cost > limits["max_candidate_inspect_bytes"]:
                    break
                inspected += cost
                if len(accepted) >= limits["max_txs_per_block"]:
                    break
                if transaction_data_size(accepted + [raw]) > selected_limit:
                    continue
                try:
                    _, results = execute_block(
                        self.genesis, self.state, accepted + [raw], height, self.worker)
                except HistoryLimitError:
                    break
                if all(item["code"] == 0 for item in results):
                    accepted.append(raw)
            return accepted

    def process_proposal(self, txs: list[bytes], height: int,
                         next_validators_hash: bytes) -> bool:
        with self.lock:
            self._require_initialized()
            assert self.genesis is not None and self.state is not None
            if type(next_validators_hash) is not bytes                     or next_validators_hash.hex() != self.validator_set.hash:
                return False
            try:
                self._container_bounds(txs)
                _, results = execute_block(
                    self.genesis, self.state, txs, height, self.worker)
                return all(item["code"] == 0 for item in results)
            except (Protocol5Error, StateError, HistoryLimitError):
                return False

    def finalize_block(self, txs: list[bytes], height: int, block_hash: bytes,
                       next_validators_hash: bytes, last_commit_votes: list[dict],
                       request_wire: bytes) -> tuple[dict, bytes]:
        with self.lock:
            self._require_initialized()
            assert self.genesis is not None and self.state is not None
            limits = self.genesis.value["limits"]
            _need(type(block_hash) is bytes and len(block_hash) == 32
                  and type(request_wire) is bytes
                  and len(request_wire) <= limits["max_finalize_request_bytes"],
                  "invalid Protocol 5 finalization identity")
            request_sha = hashlib.sha256(REQUEST_DOMAIN + request_wire).hexdigest()
            if height == self.height and height > 0:
                row = self.db.execute(
                    "SELECT block_hash,request_sha256,result,response "
                    "FROM blocks WHERE height=?", (height,)).fetchone()
                _need(row is not None and row[0] == block_hash.hex()
                      and row[1] == request_sha,
                      "conflicting committed Protocol 5 FinalizeBlock replay")
                return decode_canonical_json(bytes(row[2])), bytes(row[3])
            _need(height == self.height + 1, "Protocol 5 finalize height differs")
            if self.pending is not None:
                _need(self.pending["request_sha256"] == request_sha
                      and self.pending["block_hash"] == block_hash.hex(),
                      "conflicting pending Protocol 5 FinalizeBlock")
                return _copy(self.pending["result"]), self.pending["response"]
            _need(type(next_validators_hash) is bytes
                  and next_validators_hash.hex() == self.validator_set.hash,
                  "engine next-validator commitment differs")
            votes = _votes(last_commit_votes, self.validator_set, height)
            self._container_bounds(txs)
            state, results = execute_block(
                self.genesis, self.state, txs, height, self.worker)
            app_hash = application_hash(self.genesis, height, state)
            retained = {
                "height": height,
                "app_hash": app_hash,
                "tx_results": results,
                "validator_updates": [],
                "last_commit_votes": votes,
            }
            response = encode_finalization(retained)
            self.pending = {
                "state": state, "result": retained, "response": response,
                "request_sha256": request_sha, "block_hash": block_hash.hex(),
                "txs": list(state["execution_blocks"][-1]["transactions"]),
            }
            return _copy(retained), response

    def _commit_test_hook(self, phase: str) -> None:
        """Private seam overridden only by the run-token-gated test server."""

    def _state_sync_test_hook(self, phase: str) -> None:
        """Private seam overridden only by the run-token-gated test server."""

    def commit(self) -> dict:
        with self.lock:
            if self.pending is None:
                return self.info()
            assert self.genesis is not None
            pending = self.pending
            state = pending["state"]
            result_value = pending["result"]
            replay_state(self.genesis, state, result_value["height"], self.worker)
            self.db.execute("BEGIN IMMEDIATE")
            try:
                self.db.execute(
                    "UPDATE committed SET height=?,app_hash=?,state=? WHERE id=1",
                    (result_value["height"], result_value["app_hash"],
                     canonical_json(state)))
                self._commit_test_hook("after_state")
                self.db.execute(
                    "INSERT INTO blocks VALUES (?,?,?,?,?,?)",
                    (result_value["height"], pending["block_hash"],
                     pending["request_sha256"], canonical_json(pending["txs"]),
                     canonical_json(result_value), pending["response"]))
                self.db.execute(
                    "INSERT INTO history VALUES (?,?)",
                    (result_value["height"], canonical_json(pending["txs"])))
                self.db.execute("DELETE FROM snapshot_marker")
                self._commit_test_hook("after_result")
                self._commit_test_hook("before_commit")
                self.db.execute("COMMIT")
            except BaseException:
                if self.db.in_transaction:
                    self.db.execute("ROLLBACK")
                raise
            self._commit_test_hook("after_commit")
            self.state = state
            self.height = result_value["height"]
            self.app_hash = result_value["app_hash"]
            self.pending = None
            return self.info()

    def committed_result(self, height: int) -> dict:
        row = self.db.execute(
            "SELECT result,response FROM blocks WHERE height=?", (height,)).fetchone()
        _need(row is not None, "Protocol 5 finalization unavailable")
        retained = decode_canonical_json(bytes(row[0]))
        _need(bytes(row[1]) == encode_finalization(retained),
              "Protocol 5 finalization bytes differ")
        return retained

    def query(self, path: str, height: int = 0, prove: bool = False) -> dict:
        with self.lock:
            try:
                self._require_initialized()
                assert self.state is not None
                _need(type(path) is str and not prove and height in (0, self.height),
                      "unsupported Protocol 5 query context")
                if path == "/info":
                    value = self.info()
                elif path == "/state":
                    value = {"genesis": self.genesis.value, "height": self.height,
                             "app_hash": self.app_hash, "state": self.state}
                elif path == "/root-history":
                    value = self.state["root_history"]
                elif path.startswith("/tx/"):
                    txid = path[4:]
                    _need(re.fullmatch(r"[0-9a-f]{64}", txid) is not None,
                          "invalid Protocol 5 transaction ID")
                    rows = [row for row in self.state["receipts"] if row["txid"] == txid]
                    _need(len(rows) == 1, "unknown Protocol 5 transaction")
                    value = rows[0]
                elif path.startswith("/nullifier/"):
                    nullifier = path[len("/nullifier/"):]
                    from protocol5_encoding import field_bytes
                    field_bytes(nullifier)
                    rows = [row for row in self.state["receipts"]
                            if row["nullifier"] == nullifier]
                    _need(len(rows) == 1, "unknown Protocol 5 nullifier")
                    value = {"txid": rows[0]["txid"], "receipt": rows[0]}
                elif path.startswith("/block/"):
                    suffix = path[len("/block/"):]
                    _need(re.fullmatch(r"[1-9][0-9]{0,2}", suffix) is not None,
                          "invalid Protocol 5 block height")
                    wanted = int(suffix)
                    _need(wanted <= self.height, "unknown Protocol 5 block")
                    value = self.state["execution_blocks"][wanted - 1]
                else:
                    raise Protocol5Error("unknown Protocol 5 query path")
                return {
                    "code": 0, "height": self.height,
                    "value": canonical_json(value), "log": "",
                }
            except (Protocol5Error, EncodingError, StateError):
                return {
                    "code": 1, "height": self.height, "value": b"",
                    "log": "unsupported Protocol 5 query",
                }

    def list_snapshots(self):
        return self.state_sync.list()

    def load_snapshot_chunk(self, height: int, format_: int, index: int):
        return self.state_sync.load(height, format_, index)

    def offer_snapshot(self, snapshot: dict, app_hash: bytes):
        return self.state_sync.offer(snapshot, app_hash)

    def apply_snapshot_chunk(self, index: int, chunk: bytes, sender: str):
        return self.state_sync.apply(index, chunk, sender)
