"""Transparent adversarial model for future private shared authority.

This module makes the proposed parent/grant transition semantics executable. It
uses real Ed25519 authorization and durable SQLite state, but every authority
identifier, counter and transition remains transparent. It is not a shielded
protocol, zero-knowledge circuit, consensus implementation, light client, or
proof of authenticated non-inclusion.
"""
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import re
import sqlite3
from typing import Any, Iterable

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)


MODEL_FORMAT = "1soft/transparent-private-authority-model/v1"
SPEND_FORMAT = "1soft/transparent-private-authority-spend/v1"
CHECKPOINT_FORMAT = "1soft/transparent-private-authority-checkpoint/v1"
EXECUTION_FORMAT = "1soft/transparent-private-authority-execution/v1"
SCOPED_RECEIPT_FORMAT = "1soft/transparent-authority-scoped-receipt/v1"
AUTHORIZATION_DOMAIN = b"1soft/transparent-private-authority/authorization/v1\x00"
TRANSACTION_DOMAIN = b"1soft/transparent-private-authority/transaction/v1\x00"
PARENT_COMMITMENT_DOMAIN = b"1soft/transparent-private-authority/parent/v1\x00"
GRANT_COMMITMENT_DOMAIN = b"1soft/transparent-private-authority/grant/v1\x00"
NULLIFIER_DOMAIN = b"1soft/transparent-private-authority/nullifier/v1\x00"
OUTPUT_COMMITMENT_DOMAIN = b"1soft/transparent-private-authority/output/v1\x00"
STATE_ROOT_DOMAIN = b"1soft/transparent-private-authority/state/v1\x00"
RECEIPT_DOMAIN = b"1soft/transparent-private-authority/receipt/v1\x00"
MAX_INTEGER = 2**53 - 1
HEX_32 = re.compile(r"[0-9a-f]{64}")
HEX_64 = re.compile(r"[0-9a-f]{128}")
IDENTIFIER = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,127}")


class PrivateAuthorityReject(ValueError):
    """The proposed transition violates the transparent attack-model contract."""


def _require(condition: bool, message: str) -> None:
    if not condition:
        raise PrivateAuthorityReject(message)


def _canonical(value: Any) -> bytes:
    try:
        return json.dumps(
            value,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=False,
            allow_nan=False,
        ).encode("utf-8")
    except (TypeError, ValueError) as exc:
        raise PrivateAuthorityReject("value is not canonical JSON") from exc


def _hash(domain: bytes, value: Any) -> str:
    return hashlib.sha256(domain + _canonical(value)).hexdigest()


def _exact_fields(value: Any, expected: set[str], message: str) -> None:
    _require(type(value) is dict and set(value) == expected, message)


def _identifier(value: Any, message: str = "invalid identifier") -> str:
    _require(type(value) is str and IDENTIFIER.fullmatch(value) is not None, message)
    return value


def _integer(value: Any, *, minimum: int = 0, message: str = "invalid integer") -> int:
    _require(type(value) is int and minimum <= value <= MAX_INTEGER, message)
    return value


def _digest(value: Any, message: str = "invalid digest") -> str:
    _require(type(value) is str and HEX_32.fullmatch(value) is not None, message)
    return value


def _public_key(value: Any) -> str:
    _require(type(value) is str and HEX_32.fullmatch(value) is not None, "invalid public key")
    try:
        Ed25519PublicKey.from_public_bytes(bytes.fromhex(value))
    except ValueError as exc:
        raise PrivateAuthorityReject("invalid public key") from exc
    return value


def _parent_payload(
    *,
    genesis_hash: str,
    parent_id: str,
    owner: str,
    asset: str,
    authority_epoch: int,
    cap_units: int,
    spent_units: int,
    version: int,
    revoked: bool,
) -> dict[str, Any]:
    return {
        "asset": asset,
        "authority_epoch": authority_epoch,
        "cap_units": cap_units,
        "genesis_hash": genesis_hash,
        "id": parent_id,
        "kind": "parent",
        "owner": owner,
        "revoked": revoked,
        "spent_units": spent_units,
        "version": version,
    }


def _grant_payload(
    *,
    genesis_hash: str,
    grant_id: str,
    parent_id: str,
    public_key: str,
    authority_epoch: int,
    cap_units: int,
    spent_units: int,
    version: int,
    expires_height: int,
    recipients: list[str],
    revoked: bool,
) -> dict[str, Any]:
    return {
        "authority_epoch": authority_epoch,
        "cap_units": cap_units,
        "expires_height": expires_height,
        "genesis_hash": genesis_hash,
        "id": grant_id,
        "kind": "grant",
        "parent_id": parent_id,
        "public_key": public_key,
        "recipients": recipients,
        "revoked": revoked,
        "spent_units": spent_units,
        "version": version,
    }


def _fragment_commitment(domain: bytes, payload: dict[str, Any]) -> str:
    return _hash(domain, payload)


def _nullifier(kind: str, commitment: str) -> str:
    return _hash(NULLIFIER_DOMAIN, {"commitment": commitment, "kind": kind})


def _output_commitment(body: dict[str, Any]) -> str:
    return _hash(
        OUTPUT_COMMITMENT_DOMAIN,
        {
            "asset": body["asset"],
            "genesis_hash": body["genesis_hash"],
            "intent_id": body["intent_id"],
            "recipient": body["recipient"],
            "units": body["units"],
        },
    )


SPEND_FIELDS = {
    "format",
    "genesis_hash",
    "chain_id",
    "asset",
    "intent_id",
    "parent_id",
    "grant_id",
    "authority_epoch",
    "parent_version",
    "parent_commitment",
    "parent_nullifier",
    "grant_version",
    "grant_commitment",
    "grant_nullifier",
    "recipient",
    "units",
    "fee_units",
    "total_debit_units",
    "valid_until",
    "output_commitment",
    "parent_successor_commitment",
    "grant_successor_commitment",
}

EXECUTION_FIELDS = {
    "format",
    "status",
    "transaction_id",
    "intent_id",
    "parent_id",
    "grant_id",
    "height",
    "units",
    "fee_units",
    "total_debit_units",
    "output_commitment",
    "parent_successor_commitment",
    "grant_successor_commitment",
    "state_root",
    "privacy_established",
    "receipt_commitment",
}


def _validate_spend_body(body: Any) -> dict[str, Any]:
    _exact_fields(body, SPEND_FIELDS, "invalid spend fields")
    _require(body["format"] == SPEND_FORMAT, "invalid spend format")
    _digest(body["genesis_hash"], "invalid genesis hash")
    for field in ("chain_id", "asset", "intent_id", "parent_id", "grant_id", "recipient"):
        _identifier(body[field], f"invalid {field}")
    for field in (
        "authority_epoch",
        "parent_version",
        "grant_version",
        "fee_units",
        "total_debit_units",
        "valid_until",
    ):
        _integer(body[field], message=f"invalid {field}")
    _integer(body["units"], minimum=1, message="invalid units")
    for field in (
        "parent_commitment",
        "parent_nullifier",
        "grant_commitment",
        "grant_nullifier",
        "output_commitment",
        "parent_successor_commitment",
        "grant_successor_commitment",
    ):
        _digest(body[field], f"invalid {field}")
    _require(
        body["units"] + body["fee_units"] == body["total_debit_units"] <= MAX_INTEGER,
        "total debit mismatch",
    )
    return body


def _validate_execution_receipt(receipt: Any) -> dict[str, Any]:
    _exact_fields(receipt, EXECUTION_FIELDS, "invalid execution receipt fields")
    _require(
        receipt["format"] == EXECUTION_FORMAT
        and receipt["status"] == "committed"
        and receipt["privacy_established"] is False,
        "invalid execution receipt boundary",
    )
    for field in ("transaction_id", "output_commitment", "parent_successor_commitment",
                  "grant_successor_commitment", "state_root", "receipt_commitment"):
        _digest(receipt[field], "invalid execution receipt digest")
    for field in ("intent_id", "parent_id", "grant_id"):
        _identifier(receipt[field], "invalid execution receipt identifier")
    _integer(receipt["height"], message="invalid execution receipt height")
    _integer(receipt["units"], minimum=1, message="invalid execution receipt units")
    _integer(receipt["fee_units"], message="invalid execution receipt fee")
    _integer(receipt["total_debit_units"], minimum=1,
             message="invalid execution receipt total")
    _require(
        receipt["units"] + receipt["fee_units"] == receipt["total_debit_units"],
        "invalid execution receipt total",
    )
    material = dict(receipt)
    commitment = material.pop("receipt_commitment")
    _require(
        _hash(RECEIPT_DOMAIN, material) == commitment,
        "invalid execution receipt commitment",
    )
    return receipt


class PrivateAuthorityAttackModel:
    """One-parent transparent state machine used to pressure-test semantics."""

    def __init__(self, path: str | Path, configuration: dict[str, Any]):
        self.path = Path(path)
        self.configuration = json.loads(_canonical(configuration))
        self._validate_configuration(self.configuration)
        self.genesis_hash = hashlib.sha256(_canonical(self.configuration)).hexdigest()
        self.db = sqlite3.connect(str(self.path), isolation_level=None)
        self.db.row_factory = sqlite3.Row
        self.db.execute("PRAGMA foreign_keys=ON")
        self.db.execute("PRAGMA busy_timeout=5000")
        self._initialize()

    @staticmethod
    def _validate_configuration(configuration: dict[str, Any]) -> None:
        _exact_fields(
            configuration,
            {"format", "chain_id", "asset", "fee_units", "parent", "grants"},
            "invalid model configuration fields",
        )
        _require(configuration["format"] == MODEL_FORMAT, "invalid model format")
        _identifier(configuration["chain_id"], "invalid chain id")
        _identifier(configuration["asset"], "invalid asset")
        _integer(configuration["fee_units"], message="invalid fee")
        parent = configuration["parent"]
        _exact_fields(parent, {"id", "owner", "authority_epoch", "cap_units"}, "invalid parent fields")
        _identifier(parent["id"], "invalid parent id")
        _identifier(parent["owner"], "invalid owner")
        _integer(parent["authority_epoch"], message="invalid authority epoch")
        _integer(parent["cap_units"], minimum=1, message="invalid parent cap")
        grants = configuration["grants"]
        _require(type(grants) is list and 1 <= len(grants) <= 64, "invalid grants")
        grant_ids: set[str] = set()
        public_keys: set[str] = set()
        for grant in grants:
            _exact_fields(
                grant,
                {"id", "public_key", "cap_units", "expires_height", "recipients"},
                "invalid grant fields",
            )
            grant_id = _identifier(grant["id"], "invalid grant id")
            _require(grant_id not in grant_ids, "duplicate grant id")
            grant_ids.add(grant_id)
            key = _public_key(grant["public_key"])
            _require(key not in public_keys, "duplicate grant key")
            public_keys.add(key)
            cap = _integer(grant["cap_units"], minimum=1, message="invalid grant cap")
            _require(cap <= parent["cap_units"], "grant cap exceeds parent")
            _integer(grant["expires_height"], message="invalid grant expiry")
            recipients = grant["recipients"]
            _require(type(recipients) is list and 1 <= len(recipients) <= 64, "invalid recipients")
            _require(len(set(recipients)) == len(recipients), "duplicate recipient")
            for recipient in recipients:
                _identifier(recipient, "invalid recipient")

    def _initialize(self) -> None:
        self.db.executescript(
            """
                CREATE TABLE IF NOT EXISTS meta(k TEXT PRIMARY KEY, v TEXT NOT NULL);
                CREATE TABLE IF NOT EXISTS parent_fragment(
                    id TEXT PRIMARY KEY,
                    owner TEXT NOT NULL,
                    asset TEXT NOT NULL,
                    authority_epoch INTEGER NOT NULL,
                    cap_units INTEGER NOT NULL,
                    spent_units INTEGER NOT NULL,
                    version INTEGER NOT NULL,
                    revoked INTEGER NOT NULL,
                    commitment TEXT NOT NULL UNIQUE,
                    nullifier TEXT NOT NULL UNIQUE
                );
                CREATE TABLE IF NOT EXISTS grant_fragments(
                    id TEXT PRIMARY KEY,
                    parent_id TEXT NOT NULL,
                    public_key TEXT NOT NULL UNIQUE,
                    authority_epoch INTEGER NOT NULL,
                    cap_units INTEGER NOT NULL,
                    spent_units INTEGER NOT NULL,
                    version INTEGER NOT NULL,
                    expires_height INTEGER NOT NULL,
                    recipients TEXT NOT NULL,
                    revoked INTEGER NOT NULL,
                    commitment TEXT NOT NULL UNIQUE,
                    nullifier TEXT NOT NULL UNIQUE,
                    FOREIGN KEY(parent_id) REFERENCES parent_fragment(id)
                );
                CREATE TABLE IF NOT EXISTS consumed_nullifiers(
                    nullifier TEXT PRIMARY KEY,
                    kind TEXT NOT NULL,
                    transition_id TEXT NOT NULL,
                    consumed_height INTEGER NOT NULL
                );
                CREATE TABLE IF NOT EXISTS executions(
                    transaction_id TEXT PRIMARY KEY,
                    intent_id TEXT NOT NULL UNIQUE,
                    envelope_json TEXT NOT NULL,
                    receipt_json TEXT NOT NULL,
                    receipt_commitment TEXT NOT NULL UNIQUE
                );
            """
        )
        self.db.execute("BEGIN IMMEDIATE")
        try:
            existing = self.db.execute("SELECT v FROM meta WHERE k='genesis_hash'").fetchone()
            if existing is not None:
                _require(existing[0] == self.genesis_hash, "configuration does not match existing model")
                stored = self.db.execute("SELECT v FROM meta WHERE k='configuration'").fetchone()
                _require(stored is not None and stored[0].encode("utf-8") == _canonical(self.configuration),
                         "configuration bytes do not match existing model")
                self._invariants()
                self.db.execute("COMMIT")
                return

            self.db.execute("INSERT INTO meta VALUES ('genesis_hash',?)", (self.genesis_hash,))
            self.db.execute("INSERT INTO meta VALUES ('configuration',?)", (_canonical(self.configuration).decode(),))
            self.db.execute("INSERT INTO meta VALUES ('height','0')")
            parent = self.configuration["parent"]
            parent_payload = _parent_payload(
                genesis_hash=self.genesis_hash,
                parent_id=parent["id"],
                owner=parent["owner"],
                asset=self.configuration["asset"],
                authority_epoch=parent["authority_epoch"],
                cap_units=parent["cap_units"],
                spent_units=0,
                version=0,
                revoked=False,
            )
            parent_commitment = _fragment_commitment(PARENT_COMMITMENT_DOMAIN, parent_payload)
            self.db.execute(
                "INSERT INTO parent_fragment VALUES (?,?,?,?,?,?,?,?,?,?)",
                (
                    parent["id"],
                    parent["owner"],
                    self.configuration["asset"],
                    parent["authority_epoch"],
                    parent["cap_units"],
                    0,
                    0,
                    0,
                    parent_commitment,
                    _nullifier("parent", parent_commitment),
                ),
            )
            for grant in self.configuration["grants"]:
                recipients = sorted(grant["recipients"])
                payload = _grant_payload(
                    genesis_hash=self.genesis_hash,
                    grant_id=grant["id"],
                    parent_id=parent["id"],
                    public_key=grant["public_key"],
                    authority_epoch=parent["authority_epoch"],
                    cap_units=grant["cap_units"],
                    spent_units=0,
                    version=0,
                    expires_height=grant["expires_height"],
                    recipients=recipients,
                    revoked=False,
                )
                commitment = _fragment_commitment(GRANT_COMMITMENT_DOMAIN, payload)
                self.db.execute(
                    "INSERT INTO grant_fragments VALUES (?,?,?,?,?,?,?,?,?,?,?,?)",
                    (
                        grant["id"],
                        parent["id"],
                        grant["public_key"],
                        parent["authority_epoch"],
                        grant["cap_units"],
                        0,
                        0,
                        grant["expires_height"],
                        _canonical(recipients).decode(),
                        0,
                        commitment,
                        _nullifier("grant", commitment),
                    ),
                )
            self._invariants()
            self.db.execute("COMMIT")
        except Exception:
            self.db.execute("ROLLBACK")
            raise

    def _parent(self) -> sqlite3.Row:
        row = self.db.execute("SELECT * FROM parent_fragment").fetchone()
        _require(row is not None, "parent fragment missing")
        return row

    def _grant(self, grant_id: str) -> sqlite3.Row:
        row = self.db.execute("SELECT * FROM grant_fragments WHERE id=?", (grant_id,)).fetchone()
        _require(row is not None, "unknown grant")
        return row

    def _parent_successor(self, parent: sqlite3.Row, debit: int, *, revoked: bool | None = None,
                          epoch: int | None = None) -> tuple[str, str]:
        payload = _parent_payload(
            genesis_hash=self.genesis_hash,
            parent_id=parent["id"],
            owner=parent["owner"],
            asset=parent["asset"],
            authority_epoch=parent["authority_epoch"] if epoch is None else epoch,
            cap_units=parent["cap_units"],
            spent_units=parent["spent_units"] + debit,
            version=parent["version"] + 1,
            revoked=bool(parent["revoked"]) if revoked is None else revoked,
        )
        commitment = _fragment_commitment(PARENT_COMMITMENT_DOMAIN, payload)
        return commitment, _nullifier("parent", commitment)

    def _grant_successor(self, grant: sqlite3.Row, debit: int, *, revoked: bool | None = None,
                         epoch: int | None = None) -> tuple[str, str]:
        payload = _grant_payload(
            genesis_hash=self.genesis_hash,
            grant_id=grant["id"],
            parent_id=grant["parent_id"],
            public_key=grant["public_key"],
            authority_epoch=grant["authority_epoch"] if epoch is None else epoch,
            cap_units=grant["cap_units"],
            spent_units=grant["spent_units"] + debit,
            version=grant["version"] + 1,
            expires_height=grant["expires_height"],
            recipients=json.loads(grant["recipients"]),
            revoked=bool(grant["revoked"]) if revoked is None else revoked,
        )
        commitment = _fragment_commitment(GRANT_COMMITMENT_DOMAIN, payload)
        return commitment, _nullifier("grant", commitment)

    def review_spend(
        self,
        *,
        grant_id: str,
        recipient: str,
        units: int,
        valid_until: int,
        intent_id: str,
    ) -> dict[str, Any]:
        _identifier(grant_id, "invalid grant id")
        _identifier(recipient, "invalid recipient")
        _identifier(intent_id, "invalid intent id")
        _integer(units, minimum=1, message="invalid units")
        _integer(valid_until, message="invalid validity")
        parent = self._parent()
        grant = self._grant(grant_id)
        _require(not parent["revoked"] and not grant["revoked"], "inactive authority")
        _require(parent["authority_epoch"] == grant["authority_epoch"], "authority epoch mismatch")
        _require(recipient in json.loads(grant["recipients"]), "recipient not allowed")
        _require(valid_until <= grant["expires_height"], "validity exceeds grant expiry")
        total = units + self.configuration["fee_units"]
        _integer(total, minimum=1, message="invalid total debit")
        _require(parent["spent_units"] + total <= parent["cap_units"], "parent cap exceeded")
        _require(grant["spent_units"] + total <= grant["cap_units"], "grant cap exceeded")
        parent_successor, _ = self._parent_successor(parent, total)
        grant_successor, _ = self._grant_successor(grant, total)
        body = {
            "format": SPEND_FORMAT,
            "genesis_hash": self.genesis_hash,
            "chain_id": self.configuration["chain_id"],
            "asset": self.configuration["asset"],
            "intent_id": intent_id,
            "parent_id": parent["id"],
            "grant_id": grant["id"],
            "authority_epoch": parent["authority_epoch"],
            "parent_version": parent["version"],
            "parent_commitment": parent["commitment"],
            "parent_nullifier": parent["nullifier"],
            "grant_version": grant["version"],
            "grant_commitment": grant["commitment"],
            "grant_nullifier": grant["nullifier"],
            "recipient": recipient,
            "units": units,
            "fee_units": self.configuration["fee_units"],
            "total_debit_units": total,
            "valid_until": valid_until,
            "output_commitment": "0" * 64,
            "parent_successor_commitment": parent_successor,
            "grant_successor_commitment": grant_successor,
        }
        body["output_commitment"] = _output_commitment(body)
        return _validate_spend_body(body)

    def apply(self, envelope: dict[str, Any], *, height: int) -> dict[str, Any]:
        _integer(height, message="invalid height")
        _exact_fields(envelope, {"body", "signature", "transaction_id"}, "invalid envelope fields")
        body = _validate_spend_body(json.loads(_canonical(envelope["body"])))
        signature = envelope["signature"]
        _require(type(signature) is str and HEX_64.fullmatch(signature) is not None,
                 "invalid authorization encoding")
        transaction_id = _digest(envelope["transaction_id"], "invalid transaction id")
        grant_for_signature = self._grant(body["grant_id"])
        try:
            Ed25519PublicKey.from_public_bytes(bytes.fromhex(grant_for_signature["public_key"])).verify(
                bytes.fromhex(signature), AUTHORIZATION_DOMAIN + _canonical(body)
            )
        except (InvalidSignature, ValueError) as exc:
            raise PrivateAuthorityReject("bad authorization") from exc
        expected_txid = hashlib.sha256(TRANSACTION_DOMAIN + _canonical(body)).hexdigest()
        _require(transaction_id == expected_txid, "transaction id mismatch")

        self.db.execute("BEGIN IMMEDIATE")
        try:
            previous = self.db.execute(
                "SELECT envelope_json,receipt_json FROM executions WHERE transaction_id=?",
                (transaction_id,),
            ).fetchone()
            if previous is not None:
                _require(previous["envelope_json"].encode() == _canonical(envelope),
                         "conflicting execution replay")
                receipt = json.loads(previous["receipt_json"])
                self.db.execute("COMMIT")
                return receipt

            parent = self._parent()
            grant = self._grant(body["grant_id"])
            _require(body["authority_epoch"] == parent["authority_epoch"], "stale authority epoch")
            _require(not parent["revoked"] and not grant["revoked"], "inactive authority")
            _require(grant["parent_id"] == parent["id"], "grant parent mismatch")
            _require(grant["authority_epoch"] == parent["authority_epoch"], "grant epoch mismatch")
            _require(
                body["genesis_hash"] == self.genesis_hash
                and body["chain_id"] == self.configuration["chain_id"]
                and body["asset"] == self.configuration["asset"],
                "wrong chain or asset",
            )
            _require(body["parent_id"] == parent["id"], "wrong parent")
            _require(
                body["parent_version"] == parent["version"]
                and body["parent_commitment"] == parent["commitment"]
                and body["parent_nullifier"] == parent["nullifier"],
                "parent fragment is stale or consumed",
            )
            _require(
                self.db.execute(
                    "SELECT 1 FROM consumed_nullifiers WHERE nullifier=?",
                    (body["parent_nullifier"],),
                ).fetchone()
                is None,
                "parent fragment is stale or consumed",
            )
            _require(
                body["grant_version"] == grant["version"]
                and body["grant_commitment"] == grant["commitment"]
                and body["grant_nullifier"] == grant["nullifier"],
                "grant fragment is stale or consumed",
            )
            _require(
                self.db.execute(
                    "SELECT 1 FROM consumed_nullifiers WHERE nullifier=?",
                    (body["grant_nullifier"],),
                ).fetchone()
                is None,
                "grant fragment is stale or consumed",
            )
            _require(height <= body["valid_until"] and height <= grant["expires_height"], "expired intent")
            _require(body["fee_units"] == self.configuration["fee_units"], "fee mismatch")
            _require(body["total_debit_units"] == body["units"] + body["fee_units"],
                     "total debit mismatch")
            _require(body["recipient"] in json.loads(grant["recipients"]), "recipient not allowed")
            _require(body["output_commitment"] == _output_commitment(body), "output commitment mismatch")
            debit = body["total_debit_units"]
            _require(parent["spent_units"] + debit <= parent["cap_units"], "parent cap exceeded")
            _require(grant["spent_units"] + debit <= grant["cap_units"], "grant cap exceeded")
            parent_successor, parent_nullifier = self._parent_successor(parent, debit)
            grant_successor, grant_nullifier = self._grant_successor(grant, debit)
            _require(body["parent_successor_commitment"] == parent_successor,
                     "parent successor mismatch")
            _require(body["grant_successor_commitment"] == grant_successor,
                     "grant successor mismatch")

            self.db.execute(
                "INSERT INTO consumed_nullifiers VALUES (?,?,?,?)",
                (parent["nullifier"], "parent", transaction_id, height),
            )
            self.db.execute(
                "INSERT INTO consumed_nullifiers VALUES (?,?,?,?)",
                (grant["nullifier"], "grant", transaction_id, height),
            )
            self.db.execute(
                "UPDATE parent_fragment SET spent_units=spent_units+?,version=version+1,commitment=?,nullifier=? WHERE id=?",
                (debit, parent_successor, parent_nullifier, parent["id"]),
            )
            self.db.execute(
                "UPDATE grant_fragments SET spent_units=spent_units+?,version=version+1,commitment=?,nullifier=? WHERE id=?",
                (debit, grant_successor, grant_nullifier, grant["id"]),
            )
            previous_height = int(self.db.execute("SELECT v FROM meta WHERE k='height'").fetchone()[0])
            _require(height >= previous_height, "height regression")
            self.db.execute("UPDATE meta SET v=? WHERE k='height'", (str(height),))
            state_root = self._state_root()
            receipt = {
                "format": EXECUTION_FORMAT,
                "status": "committed",
                "transaction_id": transaction_id,
                "intent_id": body["intent_id"],
                "parent_id": parent["id"],
                "grant_id": grant["id"],
                "height": height,
                "units": body["units"],
                "fee_units": body["fee_units"],
                "total_debit_units": debit,
                "output_commitment": body["output_commitment"],
                "parent_successor_commitment": parent_successor,
                "grant_successor_commitment": grant_successor,
                "state_root": state_root,
                "privacy_established": False,
            }
            receipt_commitment = _hash(RECEIPT_DOMAIN, receipt)
            receipt["receipt_commitment"] = receipt_commitment
            self.db.execute(
                "INSERT INTO executions VALUES (?,?,?,?,?)",
                (
                    transaction_id,
                    body["intent_id"],
                    _canonical(envelope).decode(),
                    _canonical(receipt).decode(),
                    receipt_commitment,
                ),
            )
            self._invariants()
            self.db.execute("COMMIT")
            return receipt
        except sqlite3.IntegrityError as exc:
            self.db.execute("ROLLBACK")
            raise PrivateAuthorityReject("fragment or intent already consumed") from exc
        except Exception:
            self.db.execute("ROLLBACK")
            raise

    def revoke_authority(self, *, owner: str, expected_epoch: int) -> dict[str, Any]:
        _identifier(owner, "invalid owner")
        _integer(expected_epoch, message="invalid expected epoch")
        self.db.execute("BEGIN IMMEDIATE")
        try:
            parent = self._parent()
            _require(parent["owner"] == owner, "wrong owner")
            _require(parent["authority_epoch"] == expected_epoch, "authority epoch mismatch")
            _require(not parent["revoked"], "authority already revoked")
            new_epoch = expected_epoch + 1
            _integer(new_epoch, message="authority epoch overflow")
            transition_id = f"revoke:{owner}:{new_epoch}"
            height = int(self.db.execute("SELECT v FROM meta WHERE k='height'").fetchone()[0])
            parent_commitment, parent_nullifier = self._parent_successor(
                parent, 0, revoked=True, epoch=new_epoch
            )
            self.db.execute(
                "INSERT INTO consumed_nullifiers VALUES (?,?,?,?)",
                (parent["nullifier"], "parent-revocation", transition_id, height),
            )
            self.db.execute(
                "UPDATE parent_fragment SET authority_epoch=?,version=version+1,revoked=1,commitment=?,nullifier=? WHERE id=?",
                (new_epoch, parent_commitment, parent_nullifier, parent["id"]),
            )
            for grant in self.db.execute("SELECT * FROM grant_fragments ORDER BY id").fetchall():
                commitment, nullifier = self._grant_successor(
                    grant, 0, revoked=True, epoch=new_epoch
                )
                self.db.execute(
                    "INSERT INTO consumed_nullifiers VALUES (?,?,?,?)",
                    (grant["nullifier"], "grant-revocation", transition_id, height),
                )
                self.db.execute(
                    "UPDATE grant_fragments SET authority_epoch=?,version=version+1,revoked=1,commitment=?,nullifier=? WHERE id=?",
                    (new_epoch, commitment, nullifier, grant["id"]),
                )
            self._invariants()
            checkpoint = self.checkpoint()
            self.db.execute("COMMIT")
            return checkpoint
        except Exception:
            self.db.execute("ROLLBACK")
            raise

    def _state_root(self) -> str:
        parent = dict(self._parent())
        grants = [dict(row) for row in self.db.execute("SELECT * FROM grant_fragments ORDER BY id")]
        consumed = [
            dict(row)
            for row in self.db.execute(
                "SELECT nullifier,kind,transition_id,consumed_height FROM consumed_nullifiers ORDER BY nullifier"
            )
        ]
        return _hash(
            STATE_ROOT_DOMAIN,
            {
                "genesis_hash": self.genesis_hash,
                "height": int(self.db.execute("SELECT v FROM meta WHERE k='height'").fetchone()[0]),
                "parent": parent,
                "grants": grants,
                "consumed_nullifiers": consumed,
            },
        )

    def checkpoint(self) -> dict[str, Any]:
        parent = self._parent()
        return {
            "format": CHECKPOINT_FORMAT,
            "genesis_hash": self.genesis_hash,
            "height": int(self.db.execute("SELECT v FROM meta WHERE k='height'").fetchone()[0]),
            "state_root": self._state_root(),
            "authority_epoch": parent["authority_epoch"],
            "parent_commitment": parent["commitment"],
        }

    def state(self) -> dict[str, Any]:
        parent = dict(self._parent())
        parent["revoked"] = bool(parent["revoked"])
        parent["remaining_units"] = parent["cap_units"] - parent["spent_units"]
        grants = []
        for row in self.db.execute("SELECT * FROM grant_fragments ORDER BY id"):
            grant = dict(row)
            grant["revoked"] = bool(grant["revoked"])
            grant["recipients"] = json.loads(grant["recipients"])
            grant["remaining_units"] = grant["cap_units"] - grant["spent_units"]
            grants.append(grant)
        executions = [
            json.loads(row[0])
            for row in self.db.execute("SELECT receipt_json FROM executions ORDER BY transaction_id")
        ]
        consumed_parent = [
            row[0]
            for row in self.db.execute(
                "SELECT nullifier FROM consumed_nullifiers WHERE kind IN ('parent','parent-revocation') ORDER BY nullifier"
            )
        ]
        return {
            "format": MODEL_FORMAT,
            "genesis_hash": self.genesis_hash,
            "state_root": self._state_root(),
            "parent": parent,
            "grants": grants,
            "consumed_parent_nullifiers": consumed_parent,
            "executions": executions,
            "privacy_established": False,
        }

    def scoped_receipt(self, transaction_id: str, *, disclose: Iterable[str]) -> dict[str, Any]:
        _digest(transaction_id, "invalid transaction id")
        allowed = {"units", "fee_units", "total_debit_units", "output_commitment"}
        scope = sorted(set(disclose))
        _require(scope and set(scope) <= allowed, "invalid receipt scope")
        row = self.db.execute(
            "SELECT envelope_json,receipt_json FROM executions WHERE transaction_id=?",
            (transaction_id,),
        ).fetchone()
        _require(row is not None, "unknown execution")
        envelope = json.loads(row["envelope_json"])
        execution = json.loads(row["receipt_json"])
        disclosed: dict[str, Any] = {}
        for field in scope:
            disclosed[field] = (
                envelope["body"][field]
                if field in envelope["body"]
                else execution[field]
            )
        return {
            "format": SCOPED_RECEIPT_FORMAT,
            "execution_commitment": execution["receipt_commitment"],
            "state_root": execution["state_root"],
            "scope": scope,
            "disclosed": disclosed,
            "privacy_established": False,
        }

    def verify_scoped_receipt(self, receipt: dict[str, Any], *, trusted_state_root: str) -> bool:
        _digest(trusted_state_root, "invalid trusted state root")
        _exact_fields(
            receipt,
            {
                "format",
                "execution_commitment",
                "state_root",
                "scope",
                "disclosed",
                "privacy_established",
            },
            "invalid scoped receipt fields",
        )
        _require(receipt["format"] == SCOPED_RECEIPT_FORMAT, "invalid scoped receipt format")
        _require(receipt["privacy_established"] is False, "invalid privacy boundary")
        _digest(receipt["execution_commitment"], "invalid execution commitment")
        _digest(receipt["state_root"], "invalid receipt state root")
        _require(receipt["state_root"] == trusted_state_root, "untrusted receipt anchor")
        row = self.db.execute(
            "SELECT transaction_id FROM executions WHERE receipt_commitment=?",
            (receipt["execution_commitment"],),
        ).fetchone()
        _require(row is not None, "unknown execution commitment")
        expected = self.scoped_receipt(row["transaction_id"], disclose=receipt["scope"])
        _require(_canonical(receipt) == _canonical(expected), "scoped receipt mismatch")
        return True

    def _invariants(self) -> None:
        parent = self._parent()
        grants = self.db.execute("SELECT * FROM grant_fragments ORDER BY id").fetchall()
        _require(0 <= parent["spent_units"] <= parent["cap_units"] <= MAX_INTEGER,
                 "parent bounds violated")
        total_grant_spent = 0
        for grant in grants:
            _require(grant["parent_id"] == parent["id"], "grant parent invariant violated")
            _require(0 <= grant["spent_units"] <= grant["cap_units"] <= parent["cap_units"],
                     "grant bounds violated")
            _require(grant["authority_epoch"] == parent["authority_epoch"],
                     "authority epoch invariant violated")
            _require(bool(grant["revoked"]) == bool(parent["revoked"]),
                     "revocation invariant violated")
            total_grant_spent += grant["spent_units"]
        _require(total_grant_spent == parent["spent_units"], "parent conservation violated")
        execution_total = sum(
            json.loads(row[0])["total_debit_units"]
            for row in self.db.execute("SELECT receipt_json FROM executions")
        )
        _require(execution_total == parent["spent_units"], "execution conservation violated")
        _require(
            self.db.execute(
                "SELECT count(*) FROM consumed_nullifiers WHERE kind='parent'"
            ).fetchone()[0]
            == self.db.execute("SELECT count(*) FROM executions").fetchone()[0],
            "parent nullifier uniqueness invariant violated",
        )

    def close(self) -> None:
        if getattr(self, "db", None) is not None:
            self.db.close()
            self.db = None


class ObligationJournal:
    """Durable local obligations; local rejection never releases an intent.

    `trusted_state_root` is an externally authenticated input. This model does
    not implement the light-client path that authenticates it.
    """

    def __init__(self, path: str | Path, checkpoint: dict[str, Any] | None = None):
        self.path = Path(path)
        existed = self.path.exists()
        self.db = sqlite3.connect(str(self.path), isolation_level=None)
        self.db.row_factory = sqlite3.Row
        self.db.execute("PRAGMA busy_timeout=5000")
        self.db.executescript(
            """
            CREATE TABLE IF NOT EXISTS meta(k TEXT PRIMARY KEY, v TEXT NOT NULL);
            CREATE TABLE IF NOT EXISTS decisions(
                transaction_id TEXT PRIMARY KEY,
                intent_id TEXT NOT NULL UNIQUE,
                envelope_json TEXT NOT NULL,
                status TEXT NOT NULL CHECK(status IN ('pending','committed')),
                receipt_json TEXT,
                last_untrusted_rejection TEXT NOT NULL DEFAULT ''
            );
            """
        )
        stored = self.db.execute("SELECT v FROM meta WHERE k='checkpoint'").fetchone()
        if stored is None:
            _require(checkpoint is not None, "new journal requires checkpoint")
            self._validate_checkpoint(checkpoint)
            self.db.execute(
                "INSERT INTO meta VALUES ('checkpoint',?)",
                (_canonical(checkpoint).decode(),),
            )
        elif checkpoint is not None:
            self._validate_checkpoint(checkpoint)
            _require(stored[0].encode() == _canonical(checkpoint), "journal checkpoint mismatch")
        if not existed:
            try:
                os.chmod(self.path, 0o600)
            except OSError:
                pass

    @staticmethod
    def _validate_checkpoint(checkpoint: Any) -> None:
        _exact_fields(
            checkpoint,
            {
                "format",
                "genesis_hash",
                "height",
                "state_root",
                "authority_epoch",
                "parent_commitment",
            },
            "invalid checkpoint fields",
        )
        _require(checkpoint["format"] == CHECKPOINT_FORMAT, "invalid checkpoint format")
        _digest(checkpoint["genesis_hash"], "invalid checkpoint genesis")
        _digest(checkpoint["state_root"], "invalid checkpoint state root")
        _digest(checkpoint["parent_commitment"], "invalid checkpoint parent")
        _integer(checkpoint["height"], message="invalid checkpoint height")
        _integer(checkpoint["authority_epoch"], message="invalid checkpoint epoch")

    def authorize(self, body: dict[str, Any], private_key: Ed25519PrivateKey) -> dict[str, Any]:
        body = _validate_spend_body(json.loads(_canonical(body)))
        _require(isinstance(private_key, Ed25519PrivateKey), "invalid private key")
        signature = private_key.sign(AUTHORIZATION_DOMAIN + _canonical(body)).hex()
        transaction_id = hashlib.sha256(TRANSACTION_DOMAIN + _canonical(body)).hexdigest()
        envelope = {
            "body": body,
            "signature": signature,
            "transaction_id": transaction_id,
        }
        self.db.execute("BEGIN IMMEDIATE")
        try:
            previous = self.db.execute(
                "SELECT envelope_json FROM decisions WHERE transaction_id=?",
                (transaction_id,),
            ).fetchone()
            if previous is not None:
                _require(previous[0].encode() == _canonical(envelope), "conflicting authorization replay")
                self.db.execute("COMMIT")
                return envelope
            self.db.execute(
                "INSERT INTO decisions(transaction_id,intent_id,envelope_json,status) VALUES (?,?,?,'pending')",
                (transaction_id, body["intent_id"], _canonical(envelope).decode()),
            )
            self.db.execute("COMMIT")
            return envelope
        except sqlite3.IntegrityError as exc:
            self.db.execute("ROLLBACK")
            raise PrivateAuthorityReject("intent already authorized") from exc
        except Exception:
            self.db.execute("ROLLBACK")
            raise

    def record_untrusted_rejection(self, transaction_id: str, reason: str) -> None:
        _digest(transaction_id, "invalid transaction id")
        _require(type(reason) is str and 1 <= len(reason.encode("utf-8")) <= 512,
                 "invalid rejection reason")
        cursor = self.db.execute(
            "UPDATE decisions SET last_untrusted_rejection=? WHERE transaction_id=? AND status='pending'",
            (reason, transaction_id),
        )
        _require(cursor.rowcount == 1, "pending decision not found")

    def reconcile(self, receipt: dict[str, Any], *, trusted_state_root: str) -> None:
        _digest(trusted_state_root, "invalid trusted state root")
        receipt = _validate_execution_receipt(json.loads(_canonical(receipt)))
        _require(receipt["state_root"] == trusted_state_root, "untrusted receipt anchor")
        transaction_id = receipt["transaction_id"]
        self.db.execute("BEGIN IMMEDIATE")
        try:
            row = self.db.execute(
                "SELECT envelope_json,status,receipt_json FROM decisions WHERE transaction_id=?",
                (transaction_id,),
            ).fetchone()
            _require(row is not None, "decision not found")
            body = json.loads(row["envelope_json"])["body"]
            _require(
                receipt["intent_id"] == body["intent_id"]
                and receipt["parent_id"] == body["parent_id"]
                and receipt["grant_id"] == body["grant_id"]
                and receipt["units"] == body["units"]
                and receipt["fee_units"] == body["fee_units"]
                and receipt["total_debit_units"] == body["total_debit_units"]
                and receipt["output_commitment"] == body["output_commitment"]
                and receipt["parent_successor_commitment"]
                == body["parent_successor_commitment"]
                and receipt["grant_successor_commitment"]
                == body["grant_successor_commitment"],
                "invalid execution receipt for decision",
            )
            if row["status"] == "committed":
                _require(row["receipt_json"].encode() == _canonical(receipt),
                         "conflicting receipt replay")
            else:
                self.db.execute(
                    "UPDATE decisions SET status='committed',receipt_json=? WHERE transaction_id=?",
                    (_canonical(receipt).decode(), transaction_id),
                )
            self.db.execute("COMMIT")
        except Exception:
            self.db.execute("ROLLBACK")
            raise

    def decision(self, transaction_id: str) -> dict[str, Any]:
        _digest(transaction_id, "invalid transaction id")
        row = self.db.execute("SELECT * FROM decisions WHERE transaction_id=?", (transaction_id,)).fetchone()
        _require(row is not None, "decision not found")
        return {
            "transaction_id": row["transaction_id"],
            "intent_id": row["intent_id"],
            "envelope": json.loads(row["envelope_json"]),
            "status": row["status"],
            "receipt": None if row["receipt_json"] is None else json.loads(row["receipt_json"]),
            "last_untrusted_rejection": row["last_untrusted_rejection"],
        }

    def close(self) -> None:
        if getattr(self, "db", None) is not None:
            self.db.close()
            self.db = None
