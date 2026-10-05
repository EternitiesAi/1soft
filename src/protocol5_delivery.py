"""Finite one-attempt delivery journal for Protocol 5 development wallets.

The journal stores exact proved bytes before its only network attempt, records
only sanitized endpoint observations, and keeps H+1 evidence separate from
wallet reconciliation. Endpoint admission is never execution authority.
"""
from __future__ import annotations

import hashlib
import os
from contextlib import contextmanager
import fcntl
from pathlib import Path
import sqlite3
import stat
import time
from typing import Any
import urllib.parse

from protocol5_encoding import (
    Transaction, canonical_json, decode_canonical_json, genesis_document,
    transaction_id,
)
from protocol5_state_reader import (
    MAX_STATE_OBSERVATION_BYTES, authenticate_observation,
    extends_observation, read_state_observation,
)
from protocol5_transport import submit_once
from protocol5_wallet import WALLET_FORMAT


APPLICATION_ID = 0x31503544
DELIVERY_FORMAT = "1soft/protocol5-delivery/v1"
PREPARED_FORMAT = "1soft/protocol5-delivery-review/v1"
MAX_ATTEMPTS = 16
MAX_OBSERVATIONS = 32
MAX_TOTAL_OBSERVATION_BYTES = 8 * 1024 * 1024
MAX_MAIN_DATABASE_BYTES = 32 * 1024 * 1024
MAX_DATABASE_BYTES = 64 * 1024 * 1024
_PREPARED_KEYS = {
    "format", "version", "journal_id", "wallet_id", "wallet_revision",
    "delivery_revision", "decision_id", "txid", "wire_sha256",
    "endpoint", "confirmation",
}
_DELIVERY_ID_DOMAIN = b"1soft/protocol5-delivery-id/v1\0"
_CONFIRMATION_DOMAIN = b"1soft/protocol5-delivery-confirmation/v1\0"
_AUTHORITY_DOMAIN = b"1soft/protocol5-delivery-authority/v1\0"

_SCHEMA = {
    "config": (
        "CREATE TABLE config("
        "id INTEGER PRIMARY KEY CHECK(id=1),"
        "version INTEGER NOT NULL CHECK(version=1),"
        "journal_id TEXT NOT NULL UNIQUE,"
        "wallet_id TEXT NOT NULL,"
        "genesis_sha256 TEXT NOT NULL,"
        "engine_genesis_sha256 TEXT NOT NULL,"
        "endpoint TEXT NOT NULL,"
        "revision INTEGER NOT NULL CHECK(revision>=0),"
        "created_ns INTEGER NOT NULL CHECK(created_ns>=0),"
        "attempt_count INTEGER NOT NULL CHECK(attempt_count BETWEEN 0 AND 16),"
        "observation_count INTEGER NOT NULL CHECK(observation_count BETWEEN 0 AND 32),"
        "authority_digest TEXT NOT NULL CHECK(length(authority_digest)=64)"
        ") STRICT"
    ),
    "attempts": (
        "CREATE TABLE attempts("
        "decision_id TEXT PRIMARY KEY,"
        "txid TEXT NOT NULL UNIQUE,"
        "transaction_bytes BLOB NOT NULL,"
        "wire_sha256 TEXT NOT NULL UNIQUE,"
        "wallet_revision_before TEXT NOT NULL,"
        "delivery_revision_before TEXT NOT NULL,"
        "confirmation TEXT NOT NULL UNIQUE,"
        "request_id INTEGER NOT NULL UNIQUE CHECK(request_id BETWEEN 1 AND 16),"
        "transport_state TEXT NOT NULL CHECK(transport_state IN("
        "'attempt_claimed','endpoint_admitted','endpoint_declined','unresolved')),"
        "check_tx_code INTEGER,"
        "response_sha256 TEXT,"
        "unresolved_reason TEXT,"
        "collected_observation_id TEXT,"
        "wallet_revision_after TEXT,"
        "decision_state TEXT,"
        "created_revision INTEGER NOT NULL CHECK(created_revision>=0),"
        "FOREIGN KEY(collected_observation_id) REFERENCES observations(observation_id)"
        ") STRICT"
    ),
    "observations": (
        "CREATE TABLE observations("
        "seq INTEGER PRIMARY KEY,"
        "observation_id TEXT NOT NULL UNIQUE,"
        "height INTEGER NOT NULL UNIQUE CHECK(height BETWEEN 0 AND 511),"
        "payload BLOB NOT NULL,"
        "imported_revision INTEGER NOT NULL CHECK(imported_revision>=0)"
        ") STRICT"
    ),
}


class Protocol5DeliveryError(ValueError):
    pass


def _need(condition: bool, message: str) -> None:
    if not condition:
        raise Protocol5DeliveryError(message)


def _hash_text(value: Any, name: str) -> str:
    _need(type(value) is str and len(value) == 64
          and all(character in "0123456789abcdef" for character in value),
          "invalid " + name)
    return value


def _endpoint(value: str) -> str:
    _need(type(value) is str, "invalid Protocol 5 delivery endpoint")
    try:
        parsed = urllib.parse.urlsplit(value)
        port = parsed.port
    except ValueError as exc:
        raise Protocol5DeliveryError(
            "invalid Protocol 5 delivery endpoint") from exc
    _need(
        parsed.scheme == "http"
        and parsed.hostname == "127.0.0.1"
        and port is not None and 1 <= port <= 65535
        and parsed.netloc == f"127.0.0.1:{port}"
        and parsed.path == "/"
        and parsed.query == "" and parsed.fragment == ""
        and parsed.username is None and parsed.password is None,
        "Protocol 5 delivery endpoint must be exact IPv4 loopback",
    )
    return value


def _private_path(path: str | Path) -> Path:
    _need(os.name == "posix", "Protocol 5 delivery requires a trusted POSIX host")
    selected = Path(os.path.abspath(path))
    for parent in (selected.parent, *selected.parent.parents):
        _need(not parent.is_symlink(), "symlink parent refused")
    parent = selected.parent.stat()
    _need(stat.S_ISDIR(parent.st_mode)
          and parent.st_uid == os.geteuid()
          and not parent.st_mode & 0o077,
          "private owned delivery directory required")
    aggregate = 0
    for candidate in (
        selected, Path(str(selected) + ".lock"),
        *(Path(str(selected) + suffix)
          for suffix in ("-wal", "-shm", "-journal")),
    ):
        if candidate.exists() or candidate.is_symlink():
            entry = candidate.lstat()
            _need(stat.S_ISREG(entry.st_mode)
                  and entry.st_uid == os.geteuid()
                  and entry.st_nlink == 1
                  and not entry.st_mode & 0o077,
                  "unsafe delivery file or sidecar")
            if candidate != Path(str(selected) + ".lock"):
                aggregate += entry.st_size
            if candidate == selected:
                _need(entry.st_size <= MAX_MAIN_DATABASE_BYTES,
                      "delivery database size exceeded")
    _need(aggregate <= MAX_DATABASE_BYTES,
          "delivery database aggregate size exceeded")
    return selected


def _cell(value: Any) -> bytes:
    if value is None:
        tag, raw = b"n", b""
    elif type(value) is int:
        tag, raw = b"i", str(value).encode("ascii")
    elif type(value) is str:
        tag, raw = b"s", value.encode("utf-8")
    elif type(value) is bytes:
        tag, raw = b"b", value
    else:
        raise Protocol5DeliveryError("unsupported delivery authority value")
    return tag + len(raw).to_bytes(8, "little") + raw


class Protocol5Delivery:
    """One wallet-bound journal with exactly one attempt per decision."""

    def __init__(self, path: str | Path, wallet_id: str, app_genesis: bytes,
                 engine_genesis: dict, endpoint: str, *, create: bool = False,
                 clock=time.time_ns):
        _hash_text(wallet_id, "wallet identity")
        _need(type(app_genesis) is bytes, "application genesis bytes required")
        _need(type(engine_genesis) is dict, "engine genesis object required")
        _need(type(create) is bool, "invalid delivery creation mode")
        self.path = _private_path(path)
        self.wallet_id = wallet_id
        self.app_genesis = bytes(app_genesis)
        self.genesis = genesis_document(self.app_genesis)
        self.engine_genesis = decode_canonical_json(
            canonical_json(engine_genesis))
        self.engine_genesis_raw = canonical_json(self.engine_genesis)
        self.endpoint = _endpoint(endpoint)
        self.clock = clock
        self.db: sqlite3.Connection | None = None
        self._lock_handle = None
        self._journal_id = hashlib.sha256(
            _DELIVERY_ID_DOMAIN + bytes.fromhex(wallet_id)
            + self.genesis.sha256
            + hashlib.sha256(self.engine_genesis_raw).digest()
            + self.endpoint.encode("ascii")).hexdigest()

        lock_path = Path(str(self.path) + ".lock")
        lock_created = False
        database_created = False
        try:
            if create:
                descriptor = os.open(
                    lock_path,
                    os.O_RDWR | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
                    0o600)
                lock_created = True
            else:
                _need(lock_path.is_file(), "delivery lock is missing")
                descriptor = os.open(
                    lock_path, os.O_RDWR | os.O_NOFOLLOW)
            self._lock_handle = os.fdopen(descriptor, "r+b", buffering=0)
            try:
                fcntl.flock(self._lock_handle.fileno(),
                            fcntl.LOCK_EX | fcntl.LOCK_NB)
            except BlockingIOError as exc:
                raise Protocol5DeliveryError(
                    "delivery journal is already open") from exc

            if create:
                descriptor = os.open(
                    self.path,
                    os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
                    0o600)
                os.close(descriptor)
                database_created = True
            self.db = sqlite3.connect(
                self.path.as_uri() + "?mode=rw", uri=True,
                isolation_level=None, timeout=5)
            self.db.row_factory = sqlite3.Row
            self.db.execute("PRAGMA trusted_schema=OFF")
            self.db.execute("PRAGMA foreign_keys=ON")
            if create:
                self.db.execute("PRAGMA journal_mode=WAL")
                self.db.execute("PRAGMA synchronous=FULL")
                now = self.clock()
                _need(type(now) is int and now >= 0,
                      "invalid delivery clock")
                with self.atomic():
                    self.db.execute(f"PRAGMA application_id={APPLICATION_ID}")
                    self.db.execute("PRAGMA user_version=1")
                    for statement in _SCHEMA.values():
                        self.db.execute(statement)
                    self.db.execute(
                        "INSERT INTO config VALUES("
                        "1,1,?,?,?,?,?,?,?,0,0,?)",
                        (self._journal_id, self.wallet_id,
                         self.genesis.sha256.hex(),
                         hashlib.sha256(
                             self.engine_genesis_raw).hexdigest(),
                         self.endpoint, 0, now, "0" * 64))
                    self._seal()
                parent = os.open(
                    self.path.parent,
                    os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
                try:
                    os.fsync(parent)
                finally:
                    os.close(parent)
            self._snapshot()
            _need(self.db.execute(
                "PRAGMA journal_mode").fetchone()[0] == "wal",
                "delivery journal mode differs")
            self.db.execute("PRAGMA synchronous=FULL")
        except BaseException:
            self.close()
            if create and lock_created:
                created = [lock_path]
                if database_created:
                    created.extend((
                        self.path,
                        *(Path(str(self.path) + suffix)
                          for suffix in ("-wal", "-shm", "-journal")),
                    ))
                for candidate in created:
                    try:
                        candidate.unlink()
                    except FileNotFoundError:
                        pass
            raise

    def close(self) -> None:
        if self.db is not None:
            self.db.close()
            self.db = None
        if self._lock_handle is not None:
            try:
                fcntl.flock(self._lock_handle.fileno(), fcntl.LOCK_UN)
            finally:
                self._lock_handle.close()
                self._lock_handle = None

    def __enter__(self):
        return self

    def __exit__(self, *_):
        self.close()

    @contextmanager
    def atomic(self, write: bool = True):
        _need(self.db is not None and not self.db.in_transaction,
              "delivery transaction conflict")
        self.db.execute("BEGIN IMMEDIATE" if write else "BEGIN")
        try:
            yield
            self.db.execute("COMMIT")
        except BaseException:
            if self.db.in_transaction:
                self.db.execute("ROLLBACK")
            raise

    def _authority_digest(self) -> str:
        digest = hashlib.sha256(_AUTHORITY_DOMAIN)
        selections = (
            ("config",
             "SELECT id,version,journal_id,wallet_id,genesis_sha256,"
             "engine_genesis_sha256,endpoint,revision,created_ns "
             "FROM config ORDER BY id"),
            ("attempts",
             "SELECT decision_id,txid,transaction_bytes,wire_sha256,"
             "wallet_revision_before,delivery_revision_before,"
             "confirmation,request_id,"
             "transport_state,check_tx_code,response_sha256,"
             "unresolved_reason,collected_observation_id,"
             "wallet_revision_after,decision_state,created_revision "
             "FROM attempts ORDER BY decision_id"),
            ("observations",
             "SELECT seq,observation_id,height,payload,imported_revision "
             "FROM observations ORDER BY seq"),
        )
        for name, statement in selections:
            rows = self.db.execute(statement).fetchall()
            digest.update(_cell(name))
            digest.update(len(rows).to_bytes(8, "little"))
            for row in rows:
                digest.update(len(row).to_bytes(8, "little"))
                for value in row:
                    digest.update(_cell(value))
        return digest.hexdigest()

    def _seal(self) -> None:
        attempts = self.db.execute(
            "SELECT count(*) FROM attempts").fetchone()[0]
        observations = self.db.execute(
            "SELECT count(*) FROM observations").fetchone()[0]
        _need(attempts <= MAX_ATTEMPTS
              and observations <= MAX_OBSERVATIONS,
              "delivery capacity exceeded")
        self.db.execute(
            "UPDATE config SET attempt_count=?,observation_count=?,"
            "authority_digest=? WHERE id=1",
            (attempts, observations, self._authority_digest()))

    def _catalog(self) -> dict:
        _private_path(self.path)
        _need(self.db.execute("PRAGMA application_id").fetchone()[0]
              == APPLICATION_ID,
              "not a Protocol 5 delivery journal")
        _need(self.db.execute("PRAGMA user_version").fetchone()[0] == 1,
              "delivery schema version differs")
        objects = {
            (kind, name): sql
            for kind, name, sql in self.db.execute(
                "SELECT type,name,sql FROM sqlite_master "
                "WHERE name NOT LIKE 'sqlite_%'")
        }
        expected = {("table", name): sql for name, sql in _SCHEMA.items()}
        _need(objects == expected, "unrecognized delivery schema")
        _need(self.db.execute("PRAGMA quick_check(1)").fetchone()[0] == "ok"
              and not self.db.execute(
                  "PRAGMA foreign_key_check").fetchall(),
              "delivery database integrity differs")
        rows = self.db.execute("SELECT * FROM config").fetchall()
        _need(len(rows) == 1, "delivery config differs")
        row = rows[0]
        _need(
            row["id"] == 1 and row["version"] == 1
            and row["journal_id"] == self._journal_id
            and row["wallet_id"] == self.wallet_id
            and row["genesis_sha256"] == self.genesis.sha256.hex()
            and row["engine_genesis_sha256"]
                == hashlib.sha256(self.engine_genesis_raw).hexdigest()
            and row["endpoint"] == self.endpoint
            and type(row["revision"]) is int and row["revision"] >= 0
            and type(row["created_ns"]) is int and row["created_ns"] >= 0,
            "delivery external identity differs")
        _hash_text(row["journal_id"], "delivery journal identity")
        _hash_text(row["wallet_id"], "delivery wallet identity")
        _hash_text(row["authority_digest"], "delivery authority digest")
        counts = (
            self.db.execute("SELECT count(*) FROM attempts").fetchone()[0],
            self.db.execute(
                "SELECT count(*) FROM observations").fetchone()[0],
        )
        total = self.db.execute(
            "SELECT coalesce(sum(length(payload)),0) "
            "FROM observations").fetchone()[0]
        _need(counts == (row["attempt_count"], row["observation_count"])
              and counts[0] <= MAX_ATTEMPTS
              and counts[1] <= MAX_OBSERVATIONS
              and total <= MAX_TOTAL_OBSERVATION_BYTES
              and row["authority_digest"] == self._authority_digest(),
              "delivery authority differs")
        return {
            "journal_id": row["journal_id"],
            "wallet_id": row["wallet_id"],
            "revision": row["revision"],
            "created_ns": row["created_ns"],
        }

    def _confirmation(self, prepared: dict) -> str:
        value = dict(prepared)
        value.pop("confirmation", None)
        return hashlib.sha256(
            _CONFIRMATION_DOMAIN + canonical_json(value)).hexdigest()

    def _observations(self, revision: int) -> list[dict]:
        result = []
        previous = None
        rows = self.db.execute(
            "SELECT seq,observation_id,height,payload,imported_revision "
            "FROM observations ORDER BY seq").fetchall()
        for expected_seq, row in enumerate(rows, 1):
            raw = bytes(row["payload"])
            _need(row["seq"] == expected_seq
                  and row["observation_id"]
                      == hashlib.sha256(raw).hexdigest()
                  and 0 < len(raw) <= MAX_STATE_OBSERVATION_BYTES
                  and type(row["imported_revision"]) is int
                  and 0 <= row["imported_revision"] <= revision,
                  "stored delivery observation differs")
            observation, certificate = authenticate_observation(
                raw, self.engine_genesis, self.app_genesis)
            _need(row["height"] == certificate["state_height"],
                  "stored delivery observation height differs")
            if previous is not None:
                extends_observation(previous["observation"], observation)
            entry = {
                "seq": row["seq"],
                "observation_id": row["observation_id"],
                "height": row["height"],
                "payload": raw,
                "observation": observation,
                "imported_revision": row["imported_revision"],
            }
            result.append(entry)
            previous = entry
        return result

    def _attempts(self, config: dict,
                  observations: list[dict]) -> list[dict]:
        known = {row["observation_id"]: row for row in observations}
        result = []
        for row in self.db.execute(
                "SELECT * FROM attempts ORDER BY decision_id").fetchall():
            raw = bytes(row["transaction_bytes"])
            for name in (
                    "decision_id", "txid", "wire_sha256",
                    "wallet_revision_before", "delivery_revision_before",
                    "confirmation"):
                _hash_text(row[name], "delivery " + name)
            _need(0 < len(raw)
                  <= self.genesis.value["limits"]["max_tx_bytes"]
                  and hashlib.sha256(raw).hexdigest()
                      == row["wire_sha256"]
                  and transaction_id(raw).hex() == row["txid"],
                  "stored delivery transaction differs")
            Transaction.decode(raw, self.genesis)
            prepared = {
                "format": PREPARED_FORMAT,
                "version": 1,
                "journal_id": config["journal_id"],
                "wallet_id": config["wallet_id"],
                "wallet_revision": row["wallet_revision_before"],
                "delivery_revision": row["delivery_revision_before"],
                "decision_id": row["decision_id"],
                "txid": row["txid"],
                "wire_sha256": row["wire_sha256"],
                "endpoint": self.endpoint,
                "confirmation": row["confirmation"],
            }
            _need(self._confirmation(prepared) == row["confirmation"]
                  and type(row["request_id"]) is int
                  and 1 <= row["request_id"] <= MAX_ATTEMPTS
                  and type(row["created_revision"]) is int
                  and 0 <= row["created_revision"] <= config["revision"],
                  "stored delivery attempt differs")
            state = row["transport_state"]
            if state == "attempt_claimed":
                _need(row["check_tx_code"] is None
                      and row["response_sha256"] is None
                      and row["unresolved_reason"] is None,
                      "claimed delivery attempt has endpoint result")
            elif state in ("endpoint_admitted", "endpoint_declined"):
                _need(type(row["check_tx_code"]) is int
                      and (row["check_tx_code"] == 0)
                          == (state == "endpoint_admitted")
                      and row["response_sha256"] is not None,
                      "delivery endpoint result differs")
                _hash_text(row["response_sha256"],
                           "delivery response identity")
                _need(row["unresolved_reason"] is None,
                      "resolved delivery has unresolved reason")
            elif state == "unresolved":
                _need(row["check_tx_code"] is None
                      and row["response_sha256"] is None
                      and type(row["unresolved_reason"]) is str
                      and 0 < len(row["unresolved_reason"]) <= 64,
                      "unresolved delivery result differs")
            else:
                raise Protocol5DeliveryError(
                    "stored delivery state differs")
            observation_id = row["collected_observation_id"]
            wallet_after = row["wallet_revision_after"]
            decision_state = row["decision_state"]
            if observation_id is None:
                _need(wallet_after is None and decision_state is None,
                      "partial delivery reconciliation differs")
            else:
                _need(observation_id in known
                      and wallet_after is not None
                      and decision_state in {
                          "ready", "executed_exact",
                          "executed_equivalent", "conflicting_spend",
                          "expired_unexecuted",
                      },
                      "delivery reconciliation differs")
                _hash_text(wallet_after, "reconciled wallet revision")
            value = dict(row)
            value["transaction_bytes"] = raw
            result.append(value)
        return result

    def _snapshot(self) -> dict:
        config = self._catalog()
        observations = self._observations(config["revision"])
        attempts = self._attempts(config, observations)
        revision = hashlib.sha256(
            b"1soft/protocol5-delivery-revision/v1\0"
            + bytes.fromhex(config["journal_id"])
            + config["revision"].to_bytes(8, "little")
            + bytes.fromhex(self._authority_digest())).hexdigest()
        return {
            "config": config,
            "observations": observations,
            "attempts": attempts,
            "revision": revision,
        }

    def _separate_wallet(self, wallet) -> None:
        wallet_path = Path(os.path.abspath(wallet.path))
        delivery_paths = {
            self.path, Path(str(self.path) + ".lock"),
            *(Path(str(self.path) + suffix)
              for suffix in ("-wal", "-shm", "-journal")),
        }
        wallet_paths = {
            wallet_path, Path(str(wallet_path) + ".lock"),
            *(Path(str(wallet_path) + suffix)
              for suffix in ("-wal", "-shm", "-journal")),
        }
        _need(delivery_paths.isdisjoint(wallet_paths),
              "wallet and delivery files must be separate")

    def _candidate(
            self, wallet, decision_id: str,
            expected_revision: str | None = None,
            delivery_revision: str | None = None) -> tuple[dict, bytes]:
        _hash_text(decision_id, "decision identity")
        self._separate_wallet(wallet)
        record = wallet.delivery_record(
            decision_id, expected_revision=expected_revision)
        _need(record["wallet_id"] == self.wallet_id,
              "delivery wallet identity differs")
        _need(record["decision_state"] == "ready",
              "wallet decision is not ready for its only attempt")
        raw = record["transaction_bytes"]
        _need(type(raw) is bytes, "wallet transaction bytes required")
        Transaction.decode(raw, self.genesis)
        _need(transaction_id(raw).hex() == record["txid"]
              and hashlib.sha256(raw).hexdigest()
                  == record["transaction_sha256"],
              "wallet decision transaction differs")
        if delivery_revision is None:
            with self.atomic(write=False):
                delivery_revision = self._snapshot()["revision"]
        else:
            _hash_text(delivery_revision, "delivery revision")
        prepared = {
            "format": PREPARED_FORMAT,
            "version": 1,
            "journal_id": self._journal_id,
            "wallet_id": self.wallet_id,
            "wallet_revision": record["wallet_revision"],
            "delivery_revision": delivery_revision,
            "decision_id": decision_id,
            "txid": record["txid"],
            "wire_sha256": record["transaction_sha256"],
            "endpoint": self.endpoint,
            "confirmation": "0" * 64,
        }
        prepared["confirmation"] = self._confirmation(prepared)
        return prepared, raw

    def prepare(self, wallet, decision_id: str) -> dict:
        prepared, _ = self._candidate(wallet, decision_id)
        return {
            "review": prepared,
            "confirmation": prepared["confirmation"],
            "attempted": False,
        }

    def _parse_prepared(self, prepared: dict,
                        confirmation: str) -> None:
        _need(type(prepared) is dict
              and set(prepared) == _PREPARED_KEYS
              and prepared.get("format") == PREPARED_FORMAT
              and prepared.get("version") == 1
              and prepared.get("journal_id") == self._journal_id
              and prepared.get("wallet_id") == self.wallet_id
              and prepared.get("endpoint") == self.endpoint,
              "invalid Protocol 5 delivery review")
        for name in (
                "wallet_revision", "delivery_revision",
                "decision_id", "txid", "wire_sha256", "confirmation"):
            _hash_text(prepared.get(name), "delivery " + name)
        _need(type(confirmation) is str
              and confirmation == prepared["confirmation"]
              and self._confirmation(prepared) == confirmation,
              "exact delivery confirmation required")

    def _store_unresolved(self, decision_id: str, reason: str) -> None:
        with self.atomic():
            snapshot = self._snapshot()
            row = next(item for item in snapshot["attempts"]
                       if item["decision_id"] == decision_id)
            _need(row["transport_state"] == "attempt_claimed",
                  "delivery endpoint result already stored")
            self.db.execute(
                "UPDATE attempts SET transport_state='unresolved',"
                "unresolved_reason=? WHERE decision_id=?",
                (reason, decision_id))
            self.db.execute(
                "UPDATE config SET revision=revision+1 WHERE id=1")
            self._seal()

    def send(self, wallet, prepared: dict,
             confirmation: str) -> dict:
        self._parse_prepared(prepared, confirmation)
        current, raw = self._candidate(
            wallet, prepared["decision_id"],
            expected_revision=prepared["wallet_revision"],
            delivery_revision=prepared["delivery_revision"])
        _need(canonical_json(current) == canonical_json(prepared),
              "reviewed delivery decision changed")
        with self.atomic():
            snapshot = self._snapshot()
            _need(not any(
                row["decision_id"] == prepared["decision_id"]
                for row in snapshot["attempts"]),
                "delivery attempt already claimed; retry refused")
            _need(snapshot["revision"] == prepared["delivery_revision"],
                  "reviewed delivery journal changed")
            _need(len(snapshot["attempts"]) < MAX_ATTEMPTS,
                  "delivery attempt capacity reached")
            request_id = len(snapshot["attempts"]) + 1
            created_revision = snapshot["config"]["revision"] + 1
            self.db.execute(
                "INSERT INTO attempts VALUES("
                "?,?,?,?,?,?,?,?,'attempt_claimed',"
                "NULL,NULL,NULL,NULL,NULL,NULL,?)",
                (prepared["decision_id"], prepared["txid"], raw,
                 prepared["wire_sha256"],
                 prepared["wallet_revision"],
                 prepared["delivery_revision"],
                 prepared["confirmation"], request_id,
                 created_revision))
            self.db.execute(
                "UPDATE config SET revision=revision+1 WHERE id=1")
            self._seal()

        self._dispatch_guard(prepared["decision_id"])

        try:
            after_claim, after_raw = self._candidate(
                wallet, prepared["decision_id"],
                expected_revision=prepared["wallet_revision"],
                delivery_revision=prepared["delivery_revision"])
            unchanged = (
                canonical_json(after_claim) == canonical_json(prepared)
                and after_raw == raw)
        except (Protocol5DeliveryError, ValueError):
            unchanged = False
        if not unchanged:
            self._store_unresolved(
                prepared["decision_id"],
                "wallet_changed_after_claim")
            return self.inspect(prepared["decision_id"])

        observed = submit_once(self.endpoint, raw, request_id)
        state = observed.get("observation")
        if state in ("endpoint_admitted", "endpoint_declined"):
            _need(set(observed) == {
                      "observation", "check_tx_code",
                      "response_sha256"}
                  and type(observed["check_tx_code"]) is int
                  and (observed["check_tx_code"] == 0)
                      == (state == "endpoint_admitted"),
                  "invalid sanitized transport observation")
            _hash_text(observed["response_sha256"],
                       "transport response identity")
            values = (state, observed["check_tx_code"],
                      observed["response_sha256"], None)
        else:
            _need(set(observed) == {"observation", "reason"}
                  and state == "unresolved"
                  and type(observed["reason"]) is str
                  and 0 < len(observed["reason"]) <= 64,
                  "invalid unresolved transport observation")
            values = ("unresolved", None, None, observed["reason"])
        with self.atomic():
            snapshot = self._snapshot()
            row = next(item for item in snapshot["attempts"]
                       if item["decision_id"] == prepared["decision_id"])
            _need(row["transport_state"] == "attempt_claimed",
                  "delivery endpoint result already stored")
            self.db.execute(
                "UPDATE attempts SET transport_state=?,"
                "check_tx_code=?,response_sha256=?,"
                "unresolved_reason=? WHERE decision_id=?",
                (*values, prepared["decision_id"]))
            self.db.execute(
                "UPDATE config SET revision=revision+1 WHERE id=1")
            self._seal()
        return self.inspect(prepared["decision_id"])

    def _dispatch_guard(self, _decision_id: str) -> None:
        """Fault-injection seam after the durable claim and before network I/O."""

    def inspect(self, decision_id: str) -> dict:
        _hash_text(decision_id, "decision identity")
        with self.atomic(write=False):
            snapshot = self._snapshot()
            matches = [row for row in snapshot["attempts"]
                       if row["decision_id"] == decision_id]
            _need(len(matches) == 1, "unknown delivery attempt")
            row = matches[0]
            return {
                "format": DELIVERY_FORMAT,
                "journal_id": snapshot["config"]["journal_id"],
                "wallet_id": snapshot["config"]["wallet_id"],
                "revision": snapshot["revision"],
                "decision_id": row["decision_id"],
                "txid": row["txid"],
                "wire_sha256": row["wire_sha256"],
                "endpoint": self.endpoint,
                "request_id": row["request_id"],
                "attempts": 1,
                "transport_state": row["transport_state"],
                "check_tx_code": row["check_tx_code"],
                "observation_id": row["collected_observation_id"],
                "wallet_revision_after": row["wallet_revision_after"],
                "decision_state": row["decision_state"],
                "execution_authenticated": row["decision_state"]
                    in {"executed_exact", "executed_equivalent"},
                "retry_available": False,
                "endpoint_admission_is_execution": False,
            }

    def status(self) -> dict:
        """Return the closed public identity and finite journal occupancy."""
        with self.atomic(write=False):
            snapshot = self._snapshot()
        return {
            "format": DELIVERY_FORMAT,
            "journal_id": snapshot["config"]["journal_id"],
            "wallet_id": snapshot["config"]["wallet_id"],
            "revision": snapshot["revision"],
            "endpoint": self.endpoint,
            "attempts": len(snapshot["attempts"]),
            "observations": len(snapshot["observations"]),
        }

    def import_receipt(self, raw: bytes) -> dict:
        _need(type(raw) is bytes
              and 0 < len(raw) <= MAX_STATE_OBSERVATION_BYTES,
              "invalid Protocol 5 delivery receipt")
        observation, certificate = authenticate_observation(
            raw, self.engine_genesis, self.app_genesis)
        identity = hashlib.sha256(raw).hexdigest()
        height = certificate["state_height"]
        with self.atomic(write=False):
            snapshot = self._snapshot()
            existing = [row for row in snapshot["observations"]
                        if row["observation_id"] == identity]
            if existing:
                return {
                    "status": "already_imported",
                    "observation_id": identity,
                    "state_height": height,
                    "revision": snapshot["revision"],
                }
            if snapshot["observations"]:
                extends_observation(
                    snapshot["observations"][-1]["observation"],
                    observation)
            _need(len(snapshot["observations"]) < MAX_OBSERVATIONS
                  and sum(len(row["payload"])
                          for row in snapshot["observations"])
                      + len(raw) <= MAX_TOTAL_OBSERVATION_BYTES,
                  "delivery observation capacity reached")
            expected_counter = snapshot["config"]["revision"]
        with self.atomic():
            current = self._snapshot()
            _need(current["config"]["revision"] == expected_counter,
                  "delivery journal changed during receipt verification")
            existing = [row for row in current["observations"]
                        if row["observation_id"] == identity]
            if existing:
                return {
                    "status": "already_imported",
                    "observation_id": identity,
                    "state_height": height,
                    "revision": current["revision"],
                }
            if current["observations"]:
                extends_observation(
                    current["observations"][-1]["observation"],
                    observation)
            _need(len(current["observations"]) < MAX_OBSERVATIONS
                  and sum(len(row["payload"])
                          for row in current["observations"])
                      + len(raw) <= MAX_TOTAL_OBSERVATION_BYTES,
                  "delivery observation capacity reached")
            next_revision = current["config"]["revision"] + 1
            self.db.execute(
                "INSERT INTO observations VALUES(?,?,?,?,?)",
                (len(current["observations"]) + 1,
                 identity, height, raw, next_revision))
            self.db.execute(
                "UPDATE config SET revision=revision+1 WHERE id=1")
            self._seal()
        with self.atomic(write=False):
            revision = self._snapshot()["revision"]
        return {
            "status": "imported",
            "observation_id": identity,
            "state_height": height,
            "revision": revision,
        }

    def collect(self, *, timeout: float = 15.0) -> dict:
        raw = read_state_observation(
            self.endpoint, self.engine_genesis,
            self.app_genesis, timeout=timeout)
        return self.import_receipt(raw)

    def export_receipt(self, observation_id: str) -> bytes:
        _hash_text(observation_id, "observation identity")
        with self.atomic(write=False):
            snapshot = self._snapshot()
            matches = [row for row in snapshot["observations"]
                       if row["observation_id"] == observation_id]
            _need(len(matches) == 1, "unknown delivery receipt")
            return matches[0]["payload"]

    def _reconciliation_record(
            self, wallet, decision_id: str, expected_revision: str,
            attempt: dict) -> dict:
        record = wallet.delivery_record(
            decision_id, expected_revision=expected_revision)
        expected_keys = {
            "wallet_id", "wallet_revision", "decision_id",
            "decision_state", "txid", "transaction_sha256",
            "transaction_bytes", "nullifier",
        }
        _need(type(record) is dict and set(record) == expected_keys,
              "wallet reconciliation record differs")
        raw = record["transaction_bytes"]
        _need(record["wallet_id"] == self.wallet_id
              and record["wallet_revision"] == expected_revision
              and record["decision_id"] == decision_id
              and record["txid"] == attempt["txid"]
              and type(raw) is bytes
              and raw == attempt["transaction_bytes"]
              and record["transaction_sha256"]
                  == hashlib.sha256(raw).hexdigest()
              and transaction_id(raw).hex() == record["txid"]
              and record["decision_state"] in {
                  "ready", "executed_exact", "executed_equivalent",
                  "conflicting_spend", "expired_unexecuted",
              },
              "wallet reconciliation result differs")
        _hash_text(record["nullifier"], "wallet decision nullifier")
        return record

    def reconcile(self, wallet, decision_id: str,
                  observation_id: str, *,
                  expected_wallet_revision: str) -> dict:
        _hash_text(decision_id, "decision identity")
        _hash_text(observation_id, "observation identity")
        _hash_text(expected_wallet_revision, "wallet revision")
        self._separate_wallet(wallet)
        with self.atomic(write=False):
            snapshot = self._snapshot()
            attempts = [row for row in snapshot["attempts"]
                        if row["decision_id"] == decision_id]
            observations = [row for row in snapshot["observations"]
                            if row["observation_id"] == observation_id]
            _need(len(attempts) == 1, "unknown delivery attempt")
            _need(len(observations) == 1, "unknown delivery receipt")
            attempt = attempts[0]
            raw = observations[0]["payload"]
            state_height = observations[0]["height"]
            already_reconciled = (
                attempt["collected_observation_id"] == observation_id
                and attempt["wallet_revision_after"]
                    == expected_wallet_revision)

        record_before = self._reconciliation_record(
            wallet, decision_id, expected_wallet_revision, attempt)
        if already_reconciled:
            _need(record_before["decision_state"]
                  == attempt["decision_state"],
                  "wallet reconciliation marker differs")
            return self.inspect(decision_id)

        sync_result = wallet.sync(
            raw, expected_revision=expected_wallet_revision)
        _need(type(sync_result) is dict
              and set(sync_result) == {
                  "status", "observation_id", "state_height", "revision"}
              and sync_result["status"] in {
                  "recorded", "already_recorded"}
              and sync_result["observation_id"] == observation_id
              and sync_result["state_height"] == state_height,
              "wallet synchronization result differs")
        _hash_text(sync_result["revision"], "synchronized wallet revision")
        record = self._reconciliation_record(
            wallet, decision_id, sync_result["revision"], attempt)
        decision_state = record["decision_state"]
        self._reconcile_guard(
            decision_id, observation_id, record["wallet_revision"])
        with self.atomic():
            current = self._snapshot()
            rows = [row for row in current["attempts"]
                    if row["decision_id"] == decision_id]
            _need(len(rows) == 1, "delivery attempt changed")
            row = rows[0]
            if row["decision_state"] in {
                    "executed_exact", "executed_equivalent",
                    "conflicting_spend", "expired_unexecuted"}:
                _need(row["decision_state"] == decision_state,
                      "terminal delivery reconciliation changed")
            self.db.execute(
                "UPDATE attempts SET collected_observation_id=?,"
                "wallet_revision_after=?,decision_state=? "
                "WHERE decision_id=?",
                (observation_id, record["wallet_revision"],
                 decision_state, decision_id))
            self.db.execute(
                "UPDATE config SET revision=revision+1 WHERE id=1")
            self._seal()
        result = self.inspect(decision_id)
        result["wallet_sync_status"] = sync_result["status"]
        return result

    def _reconcile_guard(self, _decision_id: str,
                         _observation_id: str,
                         _wallet_revision: str) -> None:
        """Fault seam after wallet sync and before the delivery marker."""
