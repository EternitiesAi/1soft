"""Finite trusted-host Protocol 5 wallet with authenticated reconciliation.

This synthetic-development wallet persists one owner secret, explicit private
note capsules, exact proved transaction bytes, and complete H+1 observations.
It has no public-network, hostile-host, hardware-custody, automatic-discovery,
or real-funds claim.
"""
from __future__ import annotations

import base64
import binascii
from contextlib import contextmanager
import fcntl
import hashlib
import os
from pathlib import Path
import sqlite3
import stat
import struct
import time
from typing import Any

from protocol5_controller import RecipientOutput, SecretNote, random_field
from protocol5_encoding import (
    EncodingError, PALLAS_BASE_MODULUS, Transaction, canonical_json,
    decode_canonical_json, field_bytes, genesis_document, transaction_id,
)
from protocol5_note_capsule import (
    MAX_NOTE_CAPSULE_BYTES, NOTE_CAPSULE_FORMAT, decode_capsule,
    verify_capsule,
)
from protocol5_state_reader import authenticate_observation, extends_observation

APPLICATION_ID = 0x31503557
WALLET_FORMAT = "1soft/protocol5-wallet/v1"
REVIEW_FORMAT = "1soft/protocol5-wallet-review/v1"
MAX_OBSERVATIONS = 32
MAX_NOTES = 16
MAX_DECISIONS = 16
MAX_OBSERVATION_BYTES = 8_388_608
MAX_TOTAL_OBSERVATION_BYTES = 8 * 1024 * 1024
MAX_REVIEW_BYTES = 4096
PROVER_REQUEST_BYTES = 1010
MAX_MAIN_DATABASE_BYTES = 32 * 1024 * 1024
MAX_DATABASE_BYTES = 64 * 1024 * 1024
_WALLET_ID_DOMAIN = b"1soft/protocol5-wallet-id/v1\0"
_REVIEW_ID_DOMAIN = b"1soft/protocol5-wallet-review-id/v1\0"
_DECISION_ID_DOMAIN = b"1soft/protocol5-decision-id/v1\0"
_CAPSULE_ID_DOMAIN = b"1soft/protocol5-note-capsule-id/v1\0"
_AUTHORITY_DIGEST_DOMAIN = b"1soft/protocol5-wallet-authority/v1\0"

_SCHEMA = {
    "config": (
        "CREATE TABLE config("
        "id INTEGER PRIMARY KEY CHECK(id=1),"
        "version INTEGER NOT NULL CHECK(version=1),"
        "wallet_id TEXT NOT NULL UNIQUE,"
        "genesis_sha256 TEXT NOT NULL,"
        "engine_genesis_sha256 TEXT NOT NULL,"
        "profile_id TEXT NOT NULL,"
        "deployment_id TEXT NOT NULL,"
        "spend_secret BLOB NOT NULL CHECK(length(spend_secret)=32),"
        "owner_key BLOB NOT NULL CHECK(length(owner_key)=32),"
        "revision INTEGER NOT NULL CHECK(revision>=0),"
        "created_ns INTEGER NOT NULL CHECK(created_ns>=0),"
        "observation_count INTEGER NOT NULL CHECK(observation_count BETWEEN 0 AND 32),"
        "note_count INTEGER NOT NULL CHECK(note_count BETWEEN 0 AND 16),"
        "decision_count INTEGER NOT NULL CHECK(decision_count BETWEEN 0 AND 16),"
        "authority_digest TEXT NOT NULL CHECK(length(authority_digest)=64)"
        ") STRICT"
    ),
    "observations": (
        "CREATE TABLE observations("
        "seq INTEGER PRIMARY KEY,"
        "observation_id TEXT NOT NULL UNIQUE,"
        "height INTEGER NOT NULL UNIQUE CHECK(height BETWEEN 0 AND 511),"
        "payload BLOB NOT NULL"
        ") STRICT"
    ),
    "notes": (
        "CREATE TABLE notes("
        "capsule_id TEXT PRIMARY KEY,"
        "payload BLOB NOT NULL,"
        "nullifier BLOB NOT NULL CHECK(length(nullifier)=32),"
        "chain_position INTEGER NOT NULL CHECK(chain_position BETWEEN 0 AND 15),"
        "imported_revision INTEGER NOT NULL CHECK(imported_revision>=0)"
        ") STRICT"
    ),
    "decisions": (
        "CREATE TABLE decisions("
        "decision_id TEXT PRIMARY KEY,"
        "review_id TEXT NOT NULL UNIQUE,"
        "review BLOB NOT NULL,"
        "input_capsule_id TEXT NOT NULL,"
        "nullifier BLOB NOT NULL CHECK(length(nullifier)=32),"
        "txid TEXT NOT NULL UNIQUE,"
        "transaction_bytes BLOB NOT NULL,"
        "prover_request_sha256 TEXT NOT NULL,"
        "payment_capsule BLOB NOT NULL,"
        "change_capsule BLOB NOT NULL,"
        "valid_until INTEGER NOT NULL CHECK(valid_until BETWEEN 1 AND 512),"
        "created_revision INTEGER NOT NULL CHECK(created_revision>=0),"
        "FOREIGN KEY(input_capsule_id) REFERENCES notes(capsule_id)"
        ") STRICT"
    ),
}

_REVIEW_KEYS = {
    "format", "version", "review_id", "wallet_id", "wallet_revision",
    "checkpoint_height", "checkpoint_app_hash", "input_capsule_id",
    "input_value", "input_expiry", "recipient_owner_key", "payment_value",
    "change_value", "fee", "anchor_root", "valid_from", "valid_until",
}

_RECEIPT_KEYS = {
    "txid", "profile_id", "deployment_id", "height", "tx_index",
    "anchor_root", "tree_root_before", "tree_root_after", "nullifier",
    "output_commitment_0", "output_commitment_1",
    "output_position_0", "output_position_1", "fee",
}


class Protocol5WalletError(ValueError):
    pass


def _need(condition: bool, message: str) -> None:
    if not condition:
        raise Protocol5WalletError(message)


def _field(value: bytes | str, name: str) -> bytes:
    try:
        if type(value) is bytes:
            raw = value
            _need(
                len(raw) == 32
                and int.from_bytes(raw, "little") < PALLAS_BASE_MODULUS,
                "invalid " + name,
            )
        else:
            raw = field_bytes(value)
    except (EncodingError, TypeError, ValueError) as exc:
        raise Protocol5WalletError("invalid " + name) from exc
    _need(any(raw), "zero " + name)
    return raw


def _hash_text(value: Any, name: str) -> str:
    _need(type(value) is str and len(value) == 64
          and all(ch in "0123456789abcdef" for ch in value),
          "invalid " + name)
    return value


def _digest_cell(value: Any) -> bytes:
    if value is None:
        payload = b""
        tag = b"n"
    elif type(value) is int:
        payload = str(value).encode("ascii")
        tag = b"i"
    elif type(value) is str:
        payload = value.encode("utf-8")
        tag = b"s"
    elif type(value) is bytes:
        payload = value
        tag = b"b"
    else:
        raise Protocol5WalletError("unsupported wallet authority value")
    return tag + struct.pack("<Q", len(payload)) + payload


def _private_path(path: str | Path) -> Path:
    _need(os.name == "posix", "Protocol 5 wallet requires a trusted POSIX host")
    selected = Path(os.path.abspath(path))
    for parent in (selected.parent, *selected.parent.parents):
        _need(not parent.is_symlink(), "symlink parent refused")
    info = selected.parent.stat()
    _need(stat.S_ISDIR(info.st_mode) and info.st_uid == os.geteuid()
          and not info.st_mode & 0o077,
          "private owned wallet directory required")
    database_bytes = 0
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
                  "unsafe wallet file or sidecar")
            if candidate != Path(str(selected) + ".lock"):
                database_bytes += entry.st_size
            if candidate == selected:
                _need(entry.st_size <= MAX_MAIN_DATABASE_BYTES,
                      "wallet database size exceeded")
    _need(database_bytes <= MAX_DATABASE_BYTES,
          "wallet database aggregate size exceeded")
    return selected


def _capsule_bytes(value: dict) -> bytes:
    projected = dict(value)
    projected.pop("capsule_id", None)
    value = dict(projected)
    value["capsule_id"] = hashlib.sha256(
        _CAPSULE_ID_DOMAIN + canonical_json(projected)).hexdigest()
    raw = canonical_json(value)
    _need(len(raw) <= MAX_NOTE_CAPSULE_BYTES, "note capsule exceeds bound")
    return raw


def _prover_fields(raw: bytes, genesis) -> tuple[bytes, ...]:
    _need(type(raw) is bytes and len(raw) == PROVER_REQUEST_BYTES,
          "invalid Protocol 5 prover request length")
    _need(raw[:8] == b"1SFTPRV1", "invalid Protocol 5 prover request magic")
    version, backend, relation = struct.unpack_from("<HHI", raw, 8)
    _need((version, backend, relation) == (1, 1, 1),
          "invalid Protocol 5 prover request version")
    offset = 16
    _need(raw[offset:offset + 32] == genesis.sha256,
          "prover request genesis differs")
    offset += 32
    _need(raw[offset:offset + 32] == genesis.deployment.identity,
          "prover request deployment differs")
    offset += 32
    count = struct.unpack_from("<H", raw, offset)[0]
    offset += 2
    _need(count == 14, "prover request public field count differs")
    fields = tuple(raw[index:index + 32]
                   for index in range(offset, offset + count * 32, 32))
    _need(len(fields) == 14 and all(
        len(item) == 32
        and int.from_bytes(item, "little") < PALLAS_BASE_MODULUS
        for item in fields), "noncanonical prover request public field")
    _need(raw[offset + count * 32:offset + count * 32 + 8] == b"1SFTWIT1",
          "prover request witness magic differs")
    return fields


def _prover_witness(raw: bytes) -> dict:
    _need(type(raw) is bytes and len(raw) == PROVER_REQUEST_BYTES,
          "invalid Protocol 5 prover request length")
    offset = 530
    _need(raw[offset:offset + 8] == b"1SFTWIT1",
          "invalid Protocol 5 witness magic")
    offset += 8
    version, relation = struct.unpack_from("<HI", raw, offset)
    offset += 6
    _need((version, relation) == (1, 1),
          "invalid Protocol 5 witness version")
    position = struct.unpack_from("<H", raw, offset)[0]
    offset += 2
    input_value, input_expiry = struct.unpack_from("<QQ", raw, offset)
    offset += 16

    def take_fields(count: int) -> tuple[bytes, ...]:
        nonlocal offset
        values = tuple(
            raw[index:index + 32]
            for index in range(offset, offset + count * 32, 32)
        )
        offset += count * 32
        _need(len(values) == count and all(
            len(value) == 32
            and int.from_bytes(value, "little") < PALLAS_BASE_MODULUS
            for value in values), "noncanonical Protocol 5 witness field")
        return values

    input_blinding, spend_secret, note_secret = take_fields(3)
    authentication_path = take_fields(4)
    output_values = struct.unpack_from("<QQ", raw, offset)
    offset += 16
    output_expiries = struct.unpack_from("<QQ", raw, offset)
    offset += 16
    output_owner_keys = take_fields(2)
    output_note_secrets = take_fields(2)
    output_blindings = take_fields(2)
    _need(offset == len(raw)
          and all(any(value) for value in (
              input_blinding, spend_secret, note_secret,
              *output_owner_keys, *output_note_secrets, *output_blindings,
          )), "invalid zero Protocol 5 witness secret")
    return {
        "input_position": position,
        "input_value": input_value,
        "input_expiry": input_expiry,
        "input_blinding": input_blinding,
        "spend_secret": spend_secret,
        "note_secret": note_secret,
        "authentication_path": authentication_path,
        "output_values": output_values,
        "output_expiries": output_expiries,
        "output_owner_keys": output_owner_keys,
        "output_note_secrets": output_note_secrets,
        "output_blindings": output_blindings,
    }


def _statement_prefix(genesis, valid_from: int,
                      valid_until: int) -> tuple[bytes, ...]:
    return (
        (1).to_bytes(32, "little"),
        field_bytes(genesis.value["genesis_field"]),
        field_bytes(genesis.value["asset_field"]),
        field_bytes(genesis.value["context_field"]),
        genesis.value["authority_epoch"].to_bytes(32, "little"),
        valid_from.to_bytes(32, "little"),
        valid_until.to_bytes(32, "little"),
        field_bytes(genesis.value["policy_field"]),
    )


class Protocol5Wallet:
    """One private Protocol 5 owner and its authoritative local obligation journal."""

    def __init__(self, path: str | Path, app_genesis: bytes,
                 engine_genesis: dict, controller, *, create: bool = False,
                 spend_secret: bytes | None = None, clock=time.time_ns):
        _need(type(create) is bool, "invalid wallet creation mode")
        _need(type(app_genesis) is bytes, "application genesis bytes required")
        _need(type(engine_genesis) is dict, "engine genesis object required")
        self.path = _private_path(path)
        self.app_genesis = bytes(app_genesis)
        self.genesis = genesis_document(self.app_genesis)
        self.engine_genesis = decode_canonical_json(canonical_json(engine_genesis))
        self.engine_genesis_raw = canonical_json(self.engine_genesis)
        self.controller = controller
        self.clock = clock
        self.db: sqlite3.Connection | None = None
        self._lock_handle = None

        if create:
            secret = random_field() if spend_secret is None else _field(
                spend_secret, "wallet spend secret")
            owner_key = _field(
                controller.derive_owner_key(secret), "wallet owner key")
        else:
            _need(spend_secret is None,
                  "existing wallet refuses replacement spend secret")
            _need(self.path.is_file(), "wallet is not initialized")
            secret = owner_key = None

        lock_path = Path(str(self.path) + ".lock")
        lock_created = False
        database_created = False
        try:
            if create:
                lock_fd = os.open(
                    lock_path,
                    os.O_RDWR | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
                    0o600,
                )
                lock_created = True
            else:
                _need(lock_path.is_file(), "wallet lock is missing")
                lock_fd = os.open(lock_path, os.O_RDWR | os.O_NOFOLLOW)
            self._lock_handle = os.fdopen(lock_fd, "r+b", buffering=0)
            try:
                fcntl.flock(
                    self._lock_handle.fileno(),
                    fcntl.LOCK_EX | fcntl.LOCK_NB,
                )
            except BlockingIOError as exc:
                raise Protocol5WalletError("wallet is already open") from exc

            if create:
                fd = os.open(
                    self.path,
                    os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
                    0o600,
                )
                os.close(fd)
                database_created = True
            self.db = sqlite3.connect(
                self.path.as_uri() + "?mode=rw", uri=True,
                isolation_level=None, timeout=5)
            self.db.execute("PRAGMA trusted_schema=OFF")
            self.db.execute("PRAGMA foreign_keys=ON")
            if create:
                self.db.execute("PRAGMA journal_mode=WAL")
                self.db.execute("PRAGMA synchronous=FULL")
                now = self.clock()
                _need(type(now) is int and now >= 0, "invalid wallet clock")
                wallet_id = hashlib.sha256(
                    _WALLET_ID_DOMAIN + self.genesis.sha256 + owner_key).hexdigest()
                with self.atomic():
                    self.db.execute(f"PRAGMA application_id={APPLICATION_ID}")
                    self.db.execute("PRAGMA user_version=1")
                    for statement in _SCHEMA.values():
                        self.db.execute(statement)
                    self.db.execute(
                        "INSERT INTO config VALUES("
                        "1,1,?,?,?,?,?,?,?,?,?,?,?,?,'" + "0" * 64 + "')",
                        (
                            wallet_id,
                            self.genesis.sha256.hex(),
                            hashlib.sha256(self.engine_genesis_raw).hexdigest(),
                            self.genesis.profile.identity.hex(),
                            self.genesis.deployment.identity.hex(),
                            secret, owner_key, 0, now, 0, 0, 0,
                        ),
                    )
                    self._seal()
                parent = os.open(
                    self.path.parent,
                    os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
                try:
                    os.fsync(parent)
                finally:
                    os.close(parent)
            self._snapshot(cryptographic=False)
            _need(self.db.execute("PRAGMA journal_mode").fetchone()[0] == "wal",
                  "wallet journal mode differs")
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
              "wallet transaction conflict")
        self.db.execute("BEGIN IMMEDIATE" if write else "BEGIN")
        try:
            yield
            self.db.execute("COMMIT")
        except BaseException:
            if self.db.in_transaction:
                self.db.execute("ROLLBACK")
            raise

    def _authority_digest(self) -> str:
        digest = hashlib.sha256(_AUTHORITY_DIGEST_DOMAIN)
        selections = (
            (
                "config",
                "SELECT id,version,wallet_id,genesis_sha256,"
                "engine_genesis_sha256,profile_id,deployment_id,spend_secret,"
                "owner_key,revision,created_ns FROM config ORDER BY id",
            ),
            (
                "observations",
                "SELECT seq,observation_id,height,payload FROM observations "
                "ORDER BY seq",
            ),
            (
                "notes",
                "SELECT capsule_id,payload,nullifier,chain_position,"
                "imported_revision FROM notes ORDER BY capsule_id",
            ),
            (
                "decisions",
                "SELECT decision_id,review_id,review,input_capsule_id,"
                "nullifier,txid,transaction_bytes,prover_request_sha256,"
                "payment_capsule,change_capsule,valid_until,created_revision "
                "FROM decisions ORDER BY decision_id",
            ),
        )
        for table, statement in selections:
            digest.update(_digest_cell(table))
            rows = self.db.execute(statement).fetchall()
            digest.update(struct.pack("<Q", len(rows)))
            for row in rows:
                digest.update(struct.pack("<Q", len(row)))
                for value in row:
                    digest.update(_digest_cell(value))
        return digest.hexdigest()

    def _seal(self) -> None:
        counts = tuple(
            self.db.execute(f"SELECT count(*) FROM {table}").fetchone()[0]
            for table in ("observations", "notes", "decisions")
        )
        _need(counts[0] <= MAX_OBSERVATIONS
              and counts[1] <= MAX_NOTES
              and counts[2] <= MAX_DECISIONS,
              "wallet capacity exceeded")
        self.db.execute(
            "UPDATE config SET observation_count=?,note_count=?,"
            "decision_count=?,authority_digest=? WHERE id=1",
            (*counts, self._authority_digest()),
        )

    def _catalog(self, *, cryptographic: bool = False) -> dict:
        _private_path(self.path)
        _need(self.db.execute("PRAGMA application_id").fetchone()[0]
              == APPLICATION_ID, "not a Protocol 5 wallet")
        _need(self.db.execute("PRAGMA user_version").fetchone()[0] == 1,
              "wallet schema version differs")
        objects = {
            (object_type, name): sql
            for object_type, name, sql in self.db.execute(
                "SELECT type,name,sql FROM sqlite_master "
                "WHERE name NOT LIKE 'sqlite_%'")
        }
        expected_objects = {
            ("table", name): sql for name, sql in _SCHEMA.items()
        }
        _need(objects == expected_objects, "unrecognized wallet schema")
        _need(self.db.execute("PRAGMA quick_check(1)").fetchall() == [("ok",)]
              and not self.db.execute("PRAGMA foreign_key_check").fetchall(),
              "wallet database integrity differs")
        rows = self.db.execute("SELECT * FROM config").fetchall()
        _need(len(rows) == 1, "wallet config differs")
        row = rows[0]
        _need(row[0:2] == (1, 1), "wallet config version differs")
        _hash_text(row[2], "wallet identity")
        _need(row[3] == self.genesis.sha256.hex()
              and row[4] == hashlib.sha256(
                  self.engine_genesis_raw).hexdigest()
              and row[5] == self.genesis.profile.identity.hex()
              and row[6] == self.genesis.deployment.identity.hex(),
              "wallet external identity differs")
        _need(type(row[7]) is bytes and len(row[7]) == 32
              and type(row[8]) is bytes and len(row[8]) == 32
              and type(row[9]) is int and row[9] >= 0
              and type(row[10]) is int and row[10] >= 0
              and all(type(value) is int and value >= 0
                      for value in row[11:14])
              and _hash_text(row[14], "wallet authority digest"),
              "wallet config value differs")
        if cryptographic:
            derived = self.controller.derive_owner_key(row[7])
            _need(derived == row[8], "wallet owner secret differs")
        expected_id = hashlib.sha256(
            _WALLET_ID_DOMAIN + self.genesis.sha256 + row[8]).hexdigest()
        _need(row[2] == expected_id, "wallet identity differs")
        counts = {
            "observations": self.db.execute(
                "SELECT count(*),coalesce(sum(length(payload)),0) "
                "FROM observations").fetchone(),
            "notes": self.db.execute(
                "SELECT count(*) FROM notes").fetchone()[0],
            "decisions": self.db.execute(
                "SELECT count(*) FROM decisions").fetchone()[0],
        }
        _need(counts["observations"][0] <= MAX_OBSERVATIONS
              and counts["observations"][1] <= MAX_TOTAL_OBSERVATION_BYTES
              and counts["notes"] <= MAX_NOTES
              and counts["decisions"] <= MAX_DECISIONS
              and row[11:14] == (
                  counts["observations"][0], counts["notes"],
                  counts["decisions"])
              and row[14] == self._authority_digest(),
              "wallet capacity exceeded")
        return {
            "wallet_id": row[2], "spend_secret": row[7],
            "owner_key": row[8], "revision": row[9],
            "created_ns": row[10],
        }

    def _observations(self) -> list[tuple[bytes, dict, dict]]:
        rows = self.db.execute(
            "SELECT seq,observation_id,height,payload "
            "FROM observations ORDER BY seq").fetchall()
        result = []
        previous = None
        for expected_seq, (seq, identity, height, raw) in enumerate(rows, 1):
            _need(seq == expected_seq and type(raw) is bytes
                  and 0 < len(raw) <= MAX_OBSERVATION_BYTES
                  and identity == hashlib.sha256(raw).hexdigest(),
                  "stored observation differs")
            observation, certificate = authenticate_observation(
                raw, self.engine_genesis, self.app_genesis)
            _need(certificate["state_height"] == height,
                  "stored observation height differs")
            if previous is not None:
                extends_observation(previous, observation)
            previous = observation
            result.append((raw, observation, certificate))
        return result

    def _note_position(self, capsule: dict, witness: dict) -> int:
        origin = capsule["origin"]
        if origin["kind"] == "genesis":
            return origin["position"]
        matches = [
            row for row in witness["state"]["receipts"]
            if row["txid"] == origin["txid"]]
        _need(len(matches) == 1, "note origin receipt differs")
        position = matches[0][f"output_position_{origin['output_index']}"]
        _need(type(position) is int and 0 <= position < 16,
              "note chain position differs")
        return position

    def _retained_transaction(self, receipt: dict,
                              witness: dict) -> tuple[bytes, Transaction]:
        _need(type(receipt) is dict and set(receipt) == _RECEIPT_KEYS,
              "invalid Protocol 5 receipt")
        txid = _hash_text(receipt["txid"], "receipt transaction identity")
        _need(txid != "0" * 64
              and receipt["profile_id"] == self.genesis.profile.identity.hex()
              and receipt["deployment_id"]
                  == self.genesis.deployment.identity.hex(),
              "receipt identity differs")
        for name in (
                "anchor_root", "tree_root_before", "tree_root_after",
                "nullifier", "output_commitment_0", "output_commitment_1"):
            _field(receipt[name], "receipt " + name.replace("_", " "))
        height = receipt["height"]
        index = receipt["tx_index"]
        output_0 = receipt["output_position_0"]
        output_1 = receipt["output_position_1"]
        commitments = witness["state"].get("commitments")
        blocks = witness["state"].get("execution_blocks")
        _need(type(height) is int and 1 <= height <= witness["height"]
              and type(index) is int and index >= 0
              and type(output_0) is int
              and type(output_1) is int and output_1 == output_0 + 1
              and type(commitments) is list
              and len(self.genesis.value["initial_commitments"])
                  <= output_0 < output_1 < len(commitments)
              and commitments[output_0] == receipt["output_commitment_0"]
              and commitments[output_1] == receipt["output_commitment_1"]
              and type(receipt["fee"]) is int
              and receipt["fee"] == self.genesis.value["fee"],
              "receipt effects differ")
        _need(type(blocks) is list and height <= len(blocks),
              "receipt execution block missing")
        block = blocks[height - 1]
        _need(type(block) is dict
              and set(block) == {"height", "transactions", "results"}
              and block["height"] == height
              and type(block["transactions"]) is list
              and type(block["results"]) is list
              and len(block["transactions"]) == len(block["results"])
              and index < len(block["transactions"]),
              "receipt execution block differs")
        encoded = block["transactions"][index]
        _need(type(encoded) is str, "invalid retained Protocol 5 transaction")
        try:
            wire = base64.b64decode(encoded, validate=True)
        except (ValueError, binascii.Error) as exc:
            raise Protocol5WalletError(
                "invalid retained Protocol 5 transaction") from exc
        _need(base64.b64encode(wire).decode("ascii") == encoded
              and block["results"][index]
                  == {"code": 0, "log": "", "data": txid}
              and transaction_id(wire).hex() == txid,
              "retained Protocol 5 transaction result differs")
        transaction = Transaction.decode(wire, self.genesis)
        fields = transaction.public_fields
        _need(fields[8].hex() == receipt["anchor_root"]
              and fields[9].hex() == receipt["nullifier"]
              and fields[10].hex() == receipt["output_commitment_0"]
              and fields[11].hex() == receipt["output_commitment_1"]
              and int.from_bytes(fields[12], "little") == receipt["fee"],
              "receipt and retained transaction differ")
        return wire, transaction

    def _decision_state(self, decision: dict, witness: dict) -> tuple[str, dict | None]:
        matches = [
            receipt for receipt in witness["state"]["receipts"]
            if receipt["nullifier"] == decision["nullifier"].hex()]
        _need(len(matches) <= 1, "duplicate winning nullifier")
        if matches:
            receipt = matches[0]
            wire, winner = self._retained_transaction(receipt, witness)
            expected = Transaction.decode(
                decision["transaction_bytes"], self.genesis)
            if wire == decision["transaction_bytes"]:
                return "executed_exact", receipt
            if winner.public_fields == expected.public_fields:
                return "executed_equivalent", receipt
            return "conflicting_spend", receipt
        _need(decision["nullifier"].hex()
              not in witness["state"]["spent_nullifiers"],
              "spent wallet nullifier lacks a unique receipt")
        if witness["height"] + 1 >= decision["valid_until"]:
            return "expired_unexecuted", None
        return "ready", None

    def _snapshot(self, *, cryptographic: bool = False) -> dict:
        config = self._catalog(cryptographic=cryptographic)
        observations = self._observations()
        witness = None if not observations else observations[-1][1]["state_witness"]
        notes = []
        for row in self.db.execute(
                "SELECT capsule_id,payload,nullifier,chain_position,"
                "imported_revision FROM notes ORDER BY capsule_id"):
            identity, raw, nullifier, position, revision = row
            _need(type(raw) is bytes and type(nullifier) is bytes
                  and len(nullifier) == 32 and any(nullifier)
                  and type(position) is int and 0 <= position < 16
                  and type(revision) is int and 0 <= revision <= config["revision"],
                  "stored note differs")
            capsule = decode_capsule(raw, self.app_genesis)
            _need(identity == capsule["capsule_id"], "stored note identity differs")
            if witness is not None and cryptographic:
                verify_capsule(
                    raw, config["spend_secret"], witness, self.controller)
                _need(position == self._note_position(capsule, witness),
                      "stored note position differs")
                derived_nullifier = self.controller.derive_note_nullifier(
                    bytes.fromhex(capsule["commitment"]), position,
                    config["spend_secret"],
                    bytes.fromhex(capsule["note_secret"]),
                )
                _need(_field(derived_nullifier, "stored note nullifier")
                      == nullifier, "stored note nullifier differs")
            notes.append({
                "capsule_id": identity, "payload": raw,
                "capsule": capsule, "nullifier": nullifier,
                "chain_position": position, "imported_revision": revision,
            })
        decisions = []
        notes_by_id = {note["capsule_id"]: note for note in notes}
        for row in self.db.execute(
                "SELECT decision_id,review_id,review,input_capsule_id,"
                "nullifier,txid,transaction_bytes,prover_request_sha256,"
                "payment_capsule,change_capsule,valid_until,created_revision "
                "FROM decisions ORDER BY decision_id"):
            (
                decision_id, review_id, review_raw, input_id, nullifier,
                txid, transaction_raw, request_sha, payment_raw, change_raw,
                valid_until, created_revision,
            ) = row
            review = decode_canonical_json(
                review_raw, max_bytes=MAX_REVIEW_BYTES)
            _need(type(review) is dict and set(review) == _REVIEW_KEYS
                  and review["review_id"] == review_id,
                  "stored review differs")
            _need(self._review_id(review) == review_id,
                  "stored review identity differs")
            _hash_text(decision_id, "decision identity")
            _hash_text(txid, "transaction identity")
            _hash_text(request_sha, "prover request identity")
            _need(type(nullifier) is bytes and len(nullifier) == 32
                  and type(transaction_raw) is bytes
                  and 0 < len(transaction_raw)
                      <= self.genesis.value["limits"]["max_tx_bytes"]
                  and transaction_id(transaction_raw).hex() == txid
                  and type(valid_until) is int
                  and valid_until == review["valid_until"]
                  and type(created_revision) is int
                  and 0 <= created_revision <= config["revision"],
                  "stored decision differs")
            transaction = Transaction.decode(transaction_raw, self.genesis)
            payment = decode_capsule(payment_raw, self.app_genesis)
            change = decode_capsule(change_raw, self.app_genesis)
            note = notes_by_id.get(input_id)
            checkpoints = [
                item[1]["state_witness"] for item in observations
                if item[1]["state_witness"]["height"]
                    == review.get("checkpoint_height")]
            _need(note is not None
                  and input_id == review.get("input_capsule_id")
                  and nullifier == note["nullifier"]
                  and review.get("format") == REVIEW_FORMAT
                  and review.get("version") == 1
                  and review.get("wallet_id") == config["wallet_id"]
                  and type(review.get("wallet_revision")) is int
                  and created_revision == review["wallet_revision"] + 1
                  and len(checkpoints) == 1
                  and review.get("checkpoint_app_hash")
                      == checkpoints[0]["app_hash"]
                  and review.get("anchor_root")
                      == checkpoints[0]["state"]["current_root"]
                  and review.get("input_value") == note["capsule"]["value"]
                  and review.get("input_expiry") == note["capsule"]["expiry"]
                  and type(review.get("payment_value")) is int
                  and type(review.get("change_value")) is int
                  and review["payment_value"] > 0
                  and review["change_value"] > 0
                  and review["payment_value"] + review["change_value"]
                      + review.get("fee", -1) == review["input_value"]
                  and review.get("fee") == self.genesis.value["fee"]
                  and type(review.get("valid_from")) is int
                  and review["valid_from"] == review["checkpoint_height"] + 1
                  and type(review.get("valid_until")) is int
                  and review["valid_from"] < review["valid_until"]
                  and transaction.public_fields[:8] == _statement_prefix(
                      self.genesis, review["valid_from"],
                      review["valid_until"])
                  and transaction.public_fields[8].hex()
                      == review["anchor_root"]
                  and transaction.public_fields[9] == nullifier,
                  "stored decision lineage differs")
            _field(review.get("recipient_owner_key"), "recipient owner key")
            _need(payment["commitment"] == transaction.public_fields[10].hex()
                  and change["commitment"] == transaction.public_fields[11].hex()
                  and int.from_bytes(transaction.public_fields[12], "little")
                      == review["fee"]
                  and payment["origin"] == {
                      "kind": "transaction", "txid": txid,
                      "output_index": 0}
                  and change["origin"] == {
                      "kind": "transaction", "txid": txid,
                      "output_index": 1}
                  and payment["owner_key"] == review["recipient_owner_key"]
                  and change["owner_key"] == config["owner_key"].hex()
                  and payment["value"] == review["payment_value"]
                  and change["value"] == review["change_value"]
                  and payment["expiry"] == review["input_expiry"]
                  and change["expiry"] == review["input_expiry"],
                  "stored decision output differs")
            if cryptographic:
                input_note = SecretNote(
                    note["capsule"]["expiry"], note["capsule"]["value"],
                    config["spend_secret"],
                    bytes.fromhex(note["capsule"]["note_secret"]),
                    bytes.fromhex(note["capsule"]["blinding"]),
                )
                outputs = (
                    RecipientOutput(
                        payment["expiry"], payment["value"],
                        bytes.fromhex(payment["owner_key"]),
                        bytes.fromhex(payment["note_secret"]),
                        bytes.fromhex(payment["blinding"]),
                    ),
                    RecipientOutput(
                        change["expiry"], change["value"],
                        bytes.fromhex(change["owner_key"]),
                        bytes.fromhex(change["note_secret"]),
                        bytes.fromhex(change["blinding"]),
                    ),
                )
                request = self.controller.spend_to_recipient_keys(
                    self.app_genesis,
                    checkpoints[0]["state"]["commitments"],
                    note["chain_position"], input_note, outputs,
                    valid_from=review["valid_from"],
                    valid_until=review["valid_until"],
                )
                try:
                    _need(hashlib.sha256(request).hexdigest() == request_sha
                          and _prover_fields(request, self.genesis)
                              == transaction.public_fields,
                          "stored prover request lineage differs")
                    _prover_witness(request)
                finally:
                    wipe = bytearray(request)
                    wipe[:] = b"\0" * len(wipe)
            expected_decision = hashlib.sha256(
                _DECISION_ID_DOMAIN + bytes.fromhex(config["wallet_id"])
                + bytes.fromhex(review_id) + bytes.fromhex(txid)).hexdigest()
            _need(decision_id == expected_decision,
                  "stored decision identity differs")
            decision = {
                "decision_id": decision_id, "review_id": review_id,
                "review": review, "input_capsule_id": input_id,
                "nullifier": nullifier, "txid": txid,
                "transaction_bytes": transaction_raw,
                "prover_request_sha256": request_sha,
                "payment_capsule": payment_raw,
                "change_capsule": change_raw,
                "valid_until": valid_until,
                "created_revision": created_revision,
            }
            if witness is not None:
                decision["state"], decision["receipt"] = (
                    self._decision_state(decision, witness))
            else:
                decision["state"], decision["receipt"] = "unconfirmed", None
            decisions.append(decision)
        tip = None if not observations else hashlib.sha256(
            observations[-1][0]).hexdigest()
        revision = hashlib.sha256(
            b"1soft/protocol5-wallet-revision/v1\0"
            + bytes.fromhex(config["wallet_id"])
            + config["revision"].to_bytes(8, "little")
            + (bytes.fromhex(tip) if tip else b"\0" * 32)
        ).hexdigest()
        return {
            "config": config, "observations": observations,
            "witness": witness, "notes": notes, "decisions": decisions,
            "revision": revision,
        }

    def _require_revision(self, snapshot: dict, expected: str) -> None:
        _hash_text(expected, "wallet revision")
        _need(snapshot["revision"] == expected,
              "reviewed wallet revision changed")

    def _status_from_snapshot(self, snapshot: dict) -> dict:
        witness = snapshot["witness"]
        height = None if witness is None else witness["height"]
        spent = set() if witness is None else set(
            witness["state"]["spent_nullifiers"])
        notes = []
        for note in snapshot["notes"]:
            relevant = [
                decision for decision in snapshot["decisions"]
                if decision["input_capsule_id"] == note["capsule_id"]]
            if witness is None:
                state = "unconfirmed"
            elif note["nullifier"].hex() in spent:
                state = "spent"
            elif any(decision["state"] == "ready" for decision in relevant):
                state = "reserved"
            elif height + 3 > min(
                    note["capsule"]["expiry"],
                    self.genesis.value["limits"]["max_height"]):
                state = "expired"
            else:
                state = "spendable"
            notes.append({"capsule_id": note["capsule_id"], "state": state})
        return {"notes": notes}

    def status(self) -> dict:
        with self.atomic(write=False):
            snapshot = self._snapshot(cryptographic=True)
        witness = snapshot["witness"]
        height = None if witness is None else witness["height"]
        simple = self._status_from_snapshot(snapshot)
        values = {
            "spendable": 0, "reserved": 0, "spent": 0,
            "expired": 0, "unconfirmed": 0,
        }
        notes = []
        for note, state_row in zip(snapshot["notes"], simple["notes"]):
            state = state_row["state"]
            values[state] += note["capsule"]["value"]
            notes.append({
                "capsule_id": note["capsule_id"],
                "commitment": note["capsule"]["commitment"],
                "value": note["capsule"]["value"],
                "expiry": note["capsule"]["expiry"],
                "chain_position": note["chain_position"],
                "state": state,
            })
        return {
            "format": WALLET_FORMAT,
            "wallet_id": snapshot["config"]["wallet_id"],
            "owner_key": snapshot["config"]["owner_key"].hex(),
            "revision": snapshot["revision"],
            "revision_counter": snapshot["config"]["revision"],
            "state_height": height,
            "notes": notes,
            "values": values,
            "decisions": [{
                "decision_id": row["decision_id"], "txid": row["txid"],
                "input_capsule_id": row["input_capsule_id"],
                "state": row["state"],
            } for row in snapshot["decisions"]],
            "latest_state_guaranteed": False,
            "automatic_note_discovery": False,
            "production_custody": False,
            "real_funds": False,
        }

    def _authenticated_changes(self, snapshot: dict,
                               witness: dict) -> list[dict]:
        additions = []
        known = {note["capsule_id"]: note for note in snapshot["notes"]}
        for decision in snapshot["decisions"]:
            state, receipt = self._decision_state(decision, witness)
            if state not in ("executed_exact", "executed_equivalent"):
                continue
            raw = decision["change_capsule"]
            capsule = decode_capsule(raw, self.app_genesis)
            winning_txid = receipt["txid"]
            if capsule["origin"]["txid"] != winning_txid:
                capsule["origin"] = {
                    "kind": "transaction", "txid": winning_txid,
                    "output_index": 1,
                }
                raw = _capsule_bytes(capsule)
                capsule = decode_capsule(raw, self.app_genesis)
            existing = known.get(capsule["capsule_id"])
            if existing is not None:
                _need(existing["payload"] == raw,
                      "authenticated change capsule conflicts")
                continue
            verify_capsule(
                raw, snapshot["config"]["spend_secret"],
                witness, self.controller,
            )
            position = self._note_position(capsule, witness)
            nullifier = self.controller.derive_note_nullifier(
                bytes.fromhex(capsule["commitment"]), position,
                snapshot["config"]["spend_secret"],
                bytes.fromhex(capsule["note_secret"]),
            )
            nullifier = _field(nullifier, "change note nullifier")
            addition = {
                "capsule_id": capsule["capsule_id"],
                "payload": raw,
                "nullifier": nullifier,
                "chain_position": position,
            }
            additions.append(addition)
            known[capsule["capsule_id"]] = addition
        return additions

    def sync(self, observation_raw: bytes, *, expected_revision: str) -> dict:
        observation, certificate = authenticate_observation(
            observation_raw, self.engine_genesis, self.app_genesis)
        identity = hashlib.sha256(observation_raw).hexdigest()
        height = certificate["state_height"]
        with self.atomic(write=False):
            snapshot = self._snapshot()
            self._require_revision(snapshot, expected_revision)
            if snapshot["observations"]:
                previous = snapshot["observations"][-1][1]
                if height == previous["state_witness"]["height"]:
                    _need(observation == previous,
                          "same-height Protocol 5 observation conflicts")
                    return {
                        "status": "already_recorded",
                        "observation_id": identity,
                        "state_height": height,
                        "revision": snapshot["revision"],
                    }
                extends_observation(previous, observation)
            _need(len(snapshot["observations"]) < MAX_OBSERVATIONS
                  and sum(len(row[0]) for row in snapshot["observations"])
                  + len(observation_raw) <= MAX_TOTAL_OBSERVATION_BYTES,
                  "wallet observation capacity reached")

        # Verify private change openings and derive their nullifiers outside
        # the SQLite write transaction. The commit below repeats all mutable
        # state checks and uses the revision as a compare-and-swap boundary.
        changes = self._authenticated_changes(
            snapshot, observation["state_witness"])
        _need(len(snapshot["notes"]) + len(changes) <= MAX_NOTES,
              "wallet note capacity cannot admit authenticated change")

        with self.atomic():
            current = self._snapshot()
            self._require_revision(current, expected_revision)
            if current["observations"]:
                previous = current["observations"][-1][1]
                _need(height != previous["state_witness"]["height"],
                      "wallet revision changed during observation verification")
                extends_observation(previous, observation)
            _need(len(current["observations"]) < MAX_OBSERVATIONS
                  and sum(len(row[0]) for row in current["observations"])
                  + len(observation_raw) <= MAX_TOTAL_OBSERVATION_BYTES,
                  "wallet observation capacity reached")
            _need(len(current["notes"]) + len(changes) <= MAX_NOTES,
                  "wallet note capacity cannot admit authenticated change")
            self.db.execute(
                "INSERT INTO observations VALUES(?,?,?,?)",
                (len(current["observations"]) + 1, identity, height,
                 observation_raw),
            )
            next_revision = current["config"]["revision"] + 1
            for change in changes:
                self.db.execute(
                    "INSERT INTO notes VALUES(?,?,?,?,?)",
                    (
                        change["capsule_id"], change["payload"],
                        change["nullifier"], change["chain_position"],
                        next_revision,
                    ),
                )
            self.db.execute(
                "UPDATE config SET revision=revision+1 WHERE id=1")
            self._seal()
        return {
            "status": "recorded", "observation_id": identity,
            "state_height": height, "revision": self.status()["revision"],
        }

    def _derive_note_nullifier(self, capsule: dict, position: int,
                               secret: bytes) -> bytes:
        result = self.controller.derive_note_nullifier(
            bytes.fromhex(capsule["commitment"]), position, secret,
            bytes.fromhex(capsule["note_secret"]),
        )
        return _field(result, "note nullifier")

    def import_note(self, capsule_raw: bytes, owner_spend_secret: bytes, *,
                    expected_revision: str) -> dict:
        with self.atomic(write=False):
            snapshot = self._snapshot()
        self._require_revision(snapshot, expected_revision)
        _need(snapshot["witness"] is not None,
              "authenticated Protocol 5 state required")
        capsule = decode_capsule(capsule_raw, self.app_genesis)
        secret = _field(owner_spend_secret, "owner spend secret")
        _need(secret == snapshot["config"]["spend_secret"],
              "owner spend secret differs")
        existing = [
            row for row in snapshot["notes"]
            if row["capsule_id"] == capsule["capsule_id"]]
        if existing:
            _need(existing[0]["payload"] == capsule_raw,
                  "stored note capsule conflicts")
            return {
                "status": "already_imported",
                "capsule_id": capsule["capsule_id"],
                "revision": snapshot["revision"],
            }
        _need(len(snapshot["notes"]) < MAX_NOTES,
              "wallet note capacity reached")
        capsule = verify_capsule(
            capsule_raw, secret, snapshot["witness"], self.controller)
        position = self._note_position(capsule, snapshot["witness"])
        nullifier = self._derive_note_nullifier(
            capsule, position, secret)
        with self.atomic():
            current = self._snapshot()
            self._require_revision(current, expected_revision)
            existing = [
                row for row in current["notes"]
                if row["capsule_id"] == capsule["capsule_id"]]
            if existing:
                _need(existing[0]["payload"] == capsule_raw,
                      "stored note capsule conflicts")
                return {
                    "status": "already_imported",
                    "capsule_id": capsule["capsule_id"],
                    "revision": current["revision"],
                }
            _need(len(current["notes"]) < MAX_NOTES,
                  "wallet note capacity reached")
            self.db.execute(
                "INSERT INTO notes VALUES(?,?,?,?,?)",
                (
                    capsule["capsule_id"], capsule_raw, nullifier, position,
                    current["config"]["revision"] + 1,
                ),
            )
            self.db.execute(
                "UPDATE config SET revision=revision+1 WHERE id=1")
            self._seal()
        return {
            "status": "imported", "capsule_id": capsule["capsule_id"],
            "nullifier": nullifier.hex(),
            "revision": self.status()["revision"],
        }

    def _review_id(self, review: dict) -> str:
        projected = dict(review)
        projected.pop("review_id", None)
        return hashlib.sha256(
            _REVIEW_ID_DOMAIN + canonical_json(projected)).hexdigest()

    def _prepare_from_snapshot(self, snapshot: dict, *, note_id: str,
                               recipient_owner_key: str, value: int,
                               valid_until: int) -> dict:
        _hash_text(note_id, "note capsule identity")
        recipient = _field(recipient_owner_key, "recipient owner key")
        _need(type(value) is int and value > 0, "invalid payment value")
        _need(type(valid_until) is int, "invalid validity height")
        witness = snapshot["witness"]
        _need(witness is not None, "authenticated Protocol 5 state required")
        selected = [
            row for row in snapshot["notes"] if row["capsule_id"] == note_id]
        _need(len(selected) == 1, "unknown wallet note")
        note = selected[0]
        status = next(
            row for row in self._status_from_snapshot(snapshot)["notes"]
            if row["capsule_id"] == note_id)
        _need(status["state"] == "spendable", "wallet note is not spendable")
        fee = self.genesis.value["fee"]
        change = note["capsule"]["value"] - value - fee
        _need(change > 0, "payment leaves no positive change")
        height = witness["height"]
        _need(height + 3 <= valid_until
              <= min(note["capsule"]["expiry"],
                     self.genesis.value["limits"]["max_height"]),
              "invalid payment validity window")
        review = {
            "format": REVIEW_FORMAT, "version": 1,
            "review_id": "00" * 32,
            "wallet_id": snapshot["config"]["wallet_id"],
            "wallet_revision": snapshot["config"]["revision"],
            "checkpoint_height": height,
            "checkpoint_app_hash": witness["app_hash"],
            "input_capsule_id": note_id,
            "input_value": note["capsule"]["value"],
            "input_expiry": note["capsule"]["expiry"],
            "recipient_owner_key": recipient.hex(),
            "payment_value": value, "change_value": change,
            "fee": fee,
            "anchor_root": witness["state"]["current_root"],
            "valid_from": height + 1, "valid_until": valid_until,
        }
        review["review_id"] = self._review_id(review)
        return review

    def prepare(self, *, note_id: str, recipient_owner_key: str,
                value: int, valid_until: int) -> dict:
        with self.atomic(write=False):
            snapshot = self._snapshot()
            review = self._prepare_from_snapshot(
                snapshot, note_id=note_id,
                recipient_owner_key=recipient_owner_key,
                value=value, valid_until=valid_until)
        return {
            "review": review,
            "confirmation": review["review_id"],
            "reserved": False, "proved": False, "submitted": False,
        }

    def approve(self, review: dict, confirmation: str) -> dict:
        _need(type(review) is dict and set(review) == _REVIEW_KEYS,
              "invalid Protocol 5 wallet review")
        _need(type(confirmation) is str
              and confirmation == self._review_id(review)
              and review["review_id"] == confirmation,
              "wallet review confirmation differs")
        with self.atomic(write=False):
            snapshot = self._snapshot()
        expected = self._prepare_from_snapshot(
            snapshot,
            note_id=review["input_capsule_id"],
            recipient_owner_key=review["recipient_owner_key"],
            value=review["payment_value"],
            valid_until=review["valid_until"],
        )
        _need(canonical_json(expected) == canonical_json(review),
              "reviewed wallet state changed")
        _need(len(snapshot["decisions"]) < MAX_DECISIONS,
              "wallet decision capacity reached")
        note = next(row for row in snapshot["notes"]
                    if row["capsule_id"] == review["input_capsule_id"])
        verified = verify_capsule(
            note["payload"], snapshot["config"]["spend_secret"],
            snapshot["witness"], self.controller,
        )
        _need(self._note_position(verified, snapshot["witness"])
              == note["chain_position"], "reviewed note position differs")
        derived_nullifier = self.controller.derive_note_nullifier(
            bytes.fromhex(verified["commitment"]), note["chain_position"],
            snapshot["config"]["spend_secret"],
            bytes.fromhex(verified["note_secret"]),
        )
        _need(_field(derived_nullifier, "reviewed note nullifier")
              == note["nullifier"], "reviewed note nullifier differs")
        payment_secret, payment_blinding = random_field(), random_field()
        change_secret, change_blinding = random_field(), random_field()
        outputs = (
            RecipientOutput(
                note["capsule"]["expiry"], review["payment_value"],
                bytes.fromhex(review["recipient_owner_key"]),
                payment_secret, payment_blinding),
            RecipientOutput(
                note["capsule"]["expiry"], review["change_value"],
                snapshot["config"]["owner_key"],
                change_secret, change_blinding),
        )
        input_note = SecretNote(
            note["capsule"]["expiry"], note["capsule"]["value"],
            snapshot["config"]["spend_secret"],
            bytes.fromhex(note["capsule"]["note_secret"]),
            bytes.fromhex(note["capsule"]["blinding"]),
        )
        prover_request = self.controller.spend_to_recipient_keys(
            self.app_genesis, snapshot["witness"]["state"]["commitments"],
            note["chain_position"], input_note, outputs,
            valid_from=review["valid_from"],
            valid_until=review["valid_until"],
        )
        try:
            fields = _prover_fields(prover_request, self.genesis)
            witness = _prover_witness(prover_request)
            _need(fields[:8] == _statement_prefix(
                      self.genesis, review["valid_from"],
                      review["valid_until"])
                  and fields[8].hex() == review["anchor_root"]
                  and fields[9] == note["nullifier"]
                  and int.from_bytes(fields[12], "little") == review["fee"]
                  and any(fields[10]) and any(fields[11])
                  and fields[10] != fields[11]
                  and witness["input_position"] == note["chain_position"]
                  and witness["input_value"] == note["capsule"]["value"]
                  and witness["input_expiry"] == note["capsule"]["expiry"]
                  and witness["input_blinding"]
                      == bytes.fromhex(note["capsule"]["blinding"])
                  and witness["spend_secret"]
                      == snapshot["config"]["spend_secret"]
                  and witness["note_secret"]
                      == bytes.fromhex(note["capsule"]["note_secret"])
                  and witness["output_values"]
                      == (review["payment_value"], review["change_value"])
                  and witness["output_expiries"]
                      == (note["capsule"]["expiry"],) * 2
                  and witness["output_owner_keys"]
                      == (bytes.fromhex(review["recipient_owner_key"]),
                          snapshot["config"]["owner_key"])
                  and witness["output_note_secrets"]
                      == (payment_secret, change_secret)
                  and witness["output_blindings"]
                      == (payment_blinding, change_blinding),
                  "proved public statement differs from review")
            transaction_raw = self.controller.prove(
                self.app_genesis, prover_request)
            transaction = Transaction.decode(transaction_raw, self.genesis)
            _need(transaction.public_fields == fields,
                  "prover changed public statement")
            secrets = (
                snapshot["config"]["spend_secret"],
                bytes.fromhex(note["capsule"]["note_secret"]),
                bytes.fromhex(note["capsule"]["blinding"]),
                payment_secret, payment_blinding, change_secret, change_blinding,
            )
            _need(not any(secret in transaction_raw for secret in secrets),
                  "transaction contains private opening material")
            txid = transaction_id(transaction_raw).hex()
            base = {
                "format": NOTE_CAPSULE_FORMAT, "version": 1,
                "capsule_id": "00" * 32,
                "genesis_sha256": self.genesis.sha256.hex(),
                "profile_id": self.genesis.profile.identity.hex(),
                "deployment_id": self.genesis.deployment.identity.hex(),
                "expiry": note["capsule"]["expiry"],
            }
            payment_capsule = _capsule_bytes({
                **base,
                "origin": {
                    "kind": "transaction", "txid": txid, "output_index": 0},
                "commitment": fields[10].hex(),
                "owner_key": review["recipient_owner_key"],
                "value": review["payment_value"],
                "note_secret": payment_secret.hex(),
                "blinding": payment_blinding.hex(),
            })
            change_capsule = _capsule_bytes({
                **base,
                "origin": {
                    "kind": "transaction", "txid": txid, "output_index": 1},
                "commitment": fields[11].hex(),
                "owner_key": snapshot["config"]["owner_key"].hex(),
                "value": review["change_value"],
                "note_secret": change_secret.hex(),
                "blinding": change_blinding.hex(),
            })
            decision_id = hashlib.sha256(
                _DECISION_ID_DOMAIN
                + bytes.fromhex(snapshot["config"]["wallet_id"])
                + bytes.fromhex(review["review_id"])
                + bytes.fromhex(txid)).hexdigest()
            request_sha = hashlib.sha256(prover_request).hexdigest()
        finally:
            wipe = bytearray(prover_request)
            wipe[:] = b"\0" * len(wipe)
        with self.atomic():
            current = self._snapshot()
            _need(current["config"]["revision"]
                  == review["wallet_revision"],
                  "reviewed wallet revision changed")
            _need(not any(
                row["input_capsule_id"] == review["input_capsule_id"]
                and row["state"] == "ready"
                for row in current["decisions"]),
                "wallet note already has unresolved proof")
            _need(len(current["decisions"]) < MAX_DECISIONS,
                  "wallet decision capacity reached")
            self.db.execute(
                "INSERT INTO decisions VALUES(?,?,?,?,?,?,?,?,?,?,?,?)",
                (
                    decision_id, review["review_id"],
                    canonical_json(review), review["input_capsule_id"],
                    note["nullifier"], txid, transaction_raw, request_sha,
                    payment_capsule, change_capsule,
                    review["valid_until"],
                    current["config"]["revision"] + 1,
                ),
            )
            self.db.execute(
                "UPDATE config SET revision=revision+1 WHERE id=1")
            self._seal()
        self._approval_committed(decision_id)
        return {
            "status": "proved_and_reserved",
            "decision_id": decision_id, "txid": txid,
            "revision": self.status()["revision"],
            "transaction_exposed": False,
        }

    def _approval_committed(self, _decision_id: str) -> None:
        """Fault-injection seam after the durable commit and before return."""

    def delivery_record(
            self, decision_id: str,
            *, expected_revision: str | None = None) -> dict:
        """Return the closed, secret-free decision record used by delivery."""
        _hash_text(decision_id, "decision identity")
        _need(expected_revision is None or type(expected_revision) is str,
              "invalid expected wallet revision")
        with self.atomic(write=False):
            snapshot = self._snapshot()
            if expected_revision is not None:
                self._require_revision(snapshot, expected_revision)
            matches = [
                row for row in snapshot["decisions"]
                if row["decision_id"] == decision_id]
            _need(len(matches) == 1, "unknown wallet decision")
            row = matches[0]
            raw = row["transaction_bytes"]
            return {
                "wallet_id": snapshot["config"]["wallet_id"],
                "wallet_revision": snapshot["revision"],
                "decision_id": row["decision_id"],
                "decision_state": row["state"],
                "txid": row["txid"],
                "transaction_sha256": hashlib.sha256(raw).hexdigest(),
                "transaction_bytes": raw,
                "nullifier": row["nullifier"].hex(),
            }

    def recover(self, decision_id: str) -> bytes:
        _hash_text(decision_id, "decision identity")
        with self.atomic(write=False):
            snapshot = self._snapshot()
            matches = [
                row for row in snapshot["decisions"]
                if row["decision_id"] == decision_id]
            _need(len(matches) == 1, "unknown wallet decision")
            return matches[0]["transaction_bytes"]

    def export_capsule(self, decision_id: str, output_index: int) -> bytes:
        _hash_text(decision_id, "decision identity")
        _need(type(output_index) is int and output_index == 0,
              "only the authenticated payment capsule is exportable")
        with self.atomic(write=False):
            snapshot = self._snapshot(cryptographic=True)
            matches = [
                row for row in snapshot["decisions"]
                if row["decision_id"] == decision_id]
            _need(len(matches) == 1, "unknown wallet decision")
            decision = matches[0]
            _need(decision["state"] in (
                "executed_exact", "executed_equivalent"),
                "wallet decision is not authenticated as executed")
            raw = decision["payment_capsule"]
            value = decode_capsule(raw, self.app_genesis)
            winning_txid = decision["receipt"]["txid"]
            if value["origin"]["txid"] != winning_txid:
                value["origin"] = {
                    "kind": "transaction", "txid": winning_txid,
                    "output_index": output_index,
                }
                raw = _capsule_bytes(value)
                value = decode_capsule(raw, self.app_genesis)
            position = decision["receipt"]["output_position_0"]
            _need(value["origin"] == {
                      "kind": "transaction", "txid": winning_txid,
                      "output_index": 0}
                  and value["commitment"]
                      == decision["receipt"]["output_commitment_0"]
                  and type(position) is int
                  and snapshot["witness"]["state"]["commitments"][position]
                      == value["commitment"],
                  "authenticated payment capsule origin differs")
            return raw
