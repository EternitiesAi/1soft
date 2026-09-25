"""Original native-coin state-machine laboratory. NOT a deployed blockchain.

Ed25519 is supplied by cryptography; this module does not invent cryptography.
SQLite serializes a single host. Consensus, networking, a secure signer, recovery
quorums, public issuance and real funds are deliberately outside this model.
"""
from __future__ import annotations

import hashlib
import json
import re
import sqlite3
from pathlib import Path
from typing import Any
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey

MAX_UNITS = 2**53 - 1
ID = re.compile(r"[a-zA-Z0-9][a-zA-Z0-9._:-]{0,127}\Z")
HEX_KEY = re.compile(r"[0-9a-f]{64}\Z")
FEE_ACCOUNT = "system:fees"
DOMAIN = b"ETERNITIES/NATIVE-LAB/v1\x00"
KEY_CONSENT_DOMAIN = b"ETERNITIES/ACCOUNT-KEY-CONSENT/v2\x00"
BODY_FIELDS = {"version", "chain_id", "genesis_hash", "sender", "nonce", "op",
               "grant_id", "valid_until", "max_fee"}
GENESIS_FIELDS = {"chain_id", "asset", "fee", "allocations"}

class Reject(ValueError):
    """The entire transition was rejected; committed state is unchanged."""

def require(ok: bool, reason: str) -> None:
    if not ok:
        raise Reject(reason)

def integer(value: Any, *, minimum: int = 0) -> int:
    require(type(value) is int and minimum <= value <= MAX_UNITS, "invalid integer")
    return value

def identifier(value: Any) -> str:
    require(type(value) is str and ID.fullmatch(value) is not None, "invalid identifier")
    return value

def pubkey(value: Any) -> str:
    require(type(value) is str and HEX_KEY.fullmatch(value) is not None, "invalid public key")
    return value

def fields(value: Any, keys: set[str]) -> None:
    require(type(value) is dict and set(value) == keys, "unexpected or missing fields")

def canonical(value: Any) -> bytes:
    # A deliberately restricted wire format: ASCII JSON, integer quantities,
    # exact fields, no floats. All accepted body values are validated below.
    try:
        data = json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True, allow_nan=False).encode("ascii")
    except (TypeError, ValueError, OverflowError, RecursionError) as exc:
        raise Reject("not serializable") from exc
    require(len(data) <= 16384, "message too large")
    return data

def digest(value: Any) -> str:
    return hashlib.sha256(canonical(value)).hexdigest()

def public(key: Ed25519PrivateKey) -> str:
    return key.public_key().public_bytes_raw().hex()

def address(public_key: str) -> str:
    return "lab_" + hashlib.sha256(bytes.fromhex(pubkey(public_key))).hexdigest()

def sign(key: Ed25519PrivateKey, body: dict[str, Any]) -> dict[str, Any]:
    # Disposable development keys only. Production signing needs a separately
    # authenticated consent interface and protected key custody.
    return {"body": body, "signature": key.sign(DOMAIN + canonical(body)).hex()}

def key_acceptance_message(body: dict[str, Any]) -> bytes:
    """Domain-separated consent by the incoming account key.

    Consent binds the complete payer intention (network, genesis, payer, nonce,
    funding, expiry and fee cap), not an unscoped proof of key possession.
    The acceptance signature itself is excluded to avoid a circular signature.
    The current owner/sponsor still signs the full body including acceptance.
    """
    fields(body, BODY_FIELDS)
    require(type(body["version"]) is int and body["version"] in (2, 3),
            "account-key acceptance requires protocol 2 or 3")
    require(body["grant_id"] == "", "delegated account-key acceptance forbidden")
    op = body["op"]
    require(type(op) is dict, "invalid account-key operation")
    if op.get("type") == "open_account":
        fields(op, {"type", "public_key", "units", "acceptance"})
        integer(op["units"], minimum=1)
    elif op.get("type") == "rotate_key":
        fields(op, {"type", "public_key", "acceptance"})
    else:
        raise Reject("not an account-key operation")
    pubkey(op["public_key"])
    intention = json.loads(canonical(body))
    del intention["op"]["acceptance"]
    return KEY_CONSENT_DOMAIN + canonical(intention)


def accept_account_key(key: Ed25519PrivateKey, body: dict[str, Any]) -> dict[str, Any]:
    """Return a copy with incoming-key consent; does not sign for the payer.

    This is a development signing primitive, not protected wallet custody or a
    substitute for displaying/reviewing the complete intention before signing.
    """
    message = key_acceptance_message(body)
    require(public(key) == body["op"]["public_key"], "wrong incoming private key")
    result = json.loads(canonical(body))
    result["op"]["acceptance"] = key.sign(message).hex()
    return result


def verify_account_key_acceptance(body: dict[str, Any]) -> None:
    message = key_acceptance_message(body)
    sig = body["op"]["acceptance"]
    require(type(sig) is str and re.fullmatch(r"[0-9a-f]{128}", sig) is not None,
            "invalid key acceptance encoding")
    try:
        Ed25519PublicKey.from_public_bytes(bytes.fromhex(body["op"]["public_key"])).verify(
            bytes.fromhex(sig), message)
    except (InvalidSignature, ValueError) as exc:
        raise Reject("bad key acceptance signature") from exc


def parse_wire(raw: bytes) -> dict[str, Any]:
    require(type(raw) is bytes and len(raw) <= 20000, "invalid wire size")
    def pairs(items):
        out = {}
        for key, value in items:
            require(key not in out, "duplicate JSON key")
            out[key] = value
        return out
    def bad_constant(_):
        raise Reject("non-finite JSON")
    try:
        result = json.loads(raw, object_pairs_hook=pairs, parse_constant=bad_constant)
    except (ValueError, UnicodeError, RecursionError) as exc:
        raise Reject("invalid wire JSON") from exc
    require(type(result) is dict, "invalid envelope")
    return result

class NativeLedger:
    def __init__(self, path: str | Path, genesis: dict[str, Any]):
        require(type(genesis) is dict and set(genesis) in
                (GENESIS_FIELDS, GENESIS_FIELDS | {"protocol_version"},
                 GENESIS_FIELDS | {"protocol_version", "state_commitment"}),
                "unexpected or missing genesis fields")
        self.protocol_version = genesis.get("protocol_version", 1)
        require(type(self.protocol_version) is int and self.protocol_version in (1, 2, 3),
                "unsupported genesis protocol version")
        if "state_commitment" in genesis:
            require(self.protocol_version == 3 and genesis["state_commitment"] == "smt-v1",
                    "unsupported state commitment; use an explicit fresh protocol-3 genesis")
        identifier(genesis["chain_id"]); identifier(genesis["asset"])
        if self.protocol_version >= 2:
            require(len(genesis["chain_id"]) <= 50, "engine chain identifier too long")
        integer(genesis["fee"])
        require(type(genesis["allocations"]) is list and 1 <= len(genesis["allocations"]) <= 128, "invalid genesis allocations")
        seen = set(); total = 0
        for item in genesis["allocations"]:
            fields(item, {"public_key", "units"})
            pubkey(item["public_key"]); integer(item["units"])
            require(item["public_key"] not in seen, "duplicate genesis allocation")
            seen.add(item["public_key"]); total += item["units"]
        integer(total, minimum=1)
        self.genesis = json.loads(canonical(genesis))
        self.genesis_hash = digest(genesis)
        self.db = sqlite3.connect(str(path), isolation_level=None, timeout=10)
        self.db.row_factory = sqlite3.Row
        self.db.execute("PRAGMA foreign_keys=ON")
        self.db.execute("PRAGMA journal_mode=WAL")
        self.db.execute("PRAGMA synchronous=FULL")
        self.db.executescript('''
        CREATE TABLE IF NOT EXISTS meta(k TEXT PRIMARY KEY, v TEXT NOT NULL);
        CREATE TABLE IF NOT EXISTS accounts(id TEXT PRIMARY KEY, public_key TEXT NOT NULL,
          nonce INTEGER NOT NULL, epoch INTEGER NOT NULL, balance INTEGER NOT NULL CHECK(balance>=0));
        CREATE TABLE IF NOT EXISTS grants(id TEXT PRIMARY KEY, owner TEXT NOT NULL,
          public_key TEXT NOT NULL, epoch INTEGER NOT NULL, nonce INTEGER NOT NULL,
          cap INTEGER NOT NULL, spent INTEGER NOT NULL, expires INTEGER NOT NULL,
          recipients TEXT NOT NULL, revoked INTEGER NOT NULL);
        CREATE TABLE IF NOT EXISTS receipts(txid TEXT PRIMARY KEY, sequence INTEGER UNIQUE NOT NULL,
          previous TEXT NOT NULL, record TEXT NOT NULL, hash TEXT NOT NULL);
        ''')
        self.budgets = None
        self.db.execute("BEGIN IMMEDIATE")
        try:
            existing = self.db.execute("SELECT v FROM meta WHERE k='genesis'").fetchone()
            if existing:
                require(existing[0] == self.genesis_hash, "genesis mismatch")
            else:
                self.db.executemany("INSERT INTO meta VALUES (?,?)", [("genesis",self.genesis_hash), ("supply",str(total)), ("height","0")])
                self.db.execute("INSERT INTO accounts VALUES (?,?,0,0,0)", (FEE_ACCOUNT,""))
                for item in genesis["allocations"]:
                    self.db.execute("INSERT INTO accounts VALUES (?,?,0,0,?)", (address(item["public_key"]),item["public_key"],item["units"]))
            if self.protocol_version == 3:
                from native_budgets import BudgetRules
                self.budgets = BudgetRules(self)
            self._invariants()
            self.db.execute("COMMIT")
        except Exception:
            self.db.execute("ROLLBACK"); self.db.close(); raise

    def close(self):
        self.db.close()

    def balance(self, account: str) -> int:
        return self._account(account)["balance"]

    def _account(self, account: str):
        row = self.db.execute("SELECT * FROM accounts WHERE id=?", (account,)).fetchone()
        require(row is not None, "unknown account")
        return row

    def state(self) -> dict[str, Any]:
        state = {"meta": [dict(r) for r in self.db.execute("SELECT * FROM meta ORDER BY k")],
                "accounts": [dict(r) for r in self.db.execute("SELECT * FROM accounts ORDER BY id")],
                "grants": [dict(r) for r in self.db.execute("SELECT * FROM grants ORDER BY id")]}
        if self.budgets is not None:
            state.update(self.budgets.state())
        return state

    def state_hash(self) -> str:
        # Full state can grow past the bounded transaction serializer.
        wire = json.dumps(self.state(), sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode()
        return hashlib.sha256(wire).hexdigest()

    def _invariants(self) -> None:
        rows = self.db.execute("SELECT balance FROM accounts").fetchall()
        require(all(type(r[0]) is int and 0 <= r[0] <= MAX_UNITS for r in rows), "invalid balance")
        supply = int(self.db.execute("SELECT v FROM meta WHERE k='supply'").fetchone()[0])
        require(sum(r[0] for r in rows) == supply, "supply not conserved")
        require(not self.db.execute("SELECT 1 FROM grants WHERE spent<0 OR spent>cap LIMIT 1").fetchone(), "grant not conserved")
        if self.budgets is not None:
            self.budgets.invariants()

    def grant_storage_id(self, owner: str, label: str) -> str:
        """Protocol 2 scopes human-readable grant labels to a stable account.

        Never use a caller-supplied composite ID to bypass the owner boundary.
        Protocol 1 keeps its legacy global IDs for exact historical replay.
        """
        identifier(owner); identifier(label)
        return label if self.protocol_version == 1 else owner + "::" + label

    def body(self, sender: str, nonce: int, op: dict[str, Any], *, grant_id: str = "", valid_until: int = 1000, max_fee: int | None = None):
        return {"version":self.protocol_version, "chain_id":self.genesis["chain_id"], "genesis_hash":self.genesis_hash,
                "sender":sender, "nonce":nonce, "op":op, "grant_id":grant_id,
                "valid_until":valid_until, "max_fee":self.genesis["fee"] if max_fee is None else max_fee}

    def apply(self, envelope: dict[str, Any], *, height: int) -> dict[str, Any]:
        """Apply one signed transition at a trusted test height, atomically.

        Height is an explicit test input, not a consensus-derived clock. Same
        accepted payload is idempotent only with the original valid signature.
        """
        envelope = json.loads(canonical(envelope))
        fields(envelope, {"body", "signature"})
        body = envelope["body"]
        fields(body, BODY_FIELDS)
        require(type(body["version"]) is int and body["version"] == self.protocol_version,
                "unsupported version for this genesis")
        require(body["chain_id"] == self.genesis["chain_id"] and body["genesis_hash"] == self.genesis_hash, "wrong chain or genesis")
        identifier(body["sender"]); integer(body["nonce"]); integer(body["valid_until"]); integer(body["max_fee"]); integer(height)
        require(type(body["grant_id"]) is str, "invalid grant")
        if body["grant_id"]: identifier(body["grant_id"])
        sig = envelope["signature"]
        require(type(sig) is str and re.fullmatch(r"[0-9a-f]{128}", sig) is not None, "invalid signature encoding")
        op = body["op"]
        require(type(op) is dict and type(op.get("type")) is str, "invalid operation")
        encoded = canonical(body); txid = hashlib.sha256(DOMAIN+encoded).hexdigest()
        self.db.execute("BEGIN IMMEDIATE")
        try:
            previous = self.db.execute("SELECT record FROM receipts WHERE txid=?", (txid,)).fetchone()
            if previous:
                record = json.loads(previous[0])
                try:
                    Ed25519PublicKey.from_public_bytes(bytes.fromhex(record["signer_public_key"])).verify(bytes.fromhex(sig), DOMAIN+encoded)
                except (InvalidSignature, ValueError) as exc: raise Reject("bad signature") from exc
                self.db.execute("COMMIT")
                return record
            current_height = int(self.db.execute("SELECT v FROM meta WHERE k='height'").fetchone()[0])
            require(height >= current_height, "height regression")
            require(height <= body["valid_until"], "expired transaction")
            owner = self._account(body["sender"])
            require(owner["id"] != FEE_ACCOUNT, "system account cannot sign")
            grant = None
            if body["grant_id"]:
                grant = self.db.execute("SELECT * FROM grants WHERE id=?",
                    (self.grant_storage_id(owner["id"], body["grant_id"]),)).fetchone()
                require(grant is not None and grant["owner"] == owner["id"], "unknown grant")
                require(not grant["revoked"] and grant["epoch"] == owner["epoch"] and height <= grant["expires"], "inactive grant")
                require(op["type"] == "transfer", "grant cannot administer")
            signer = grant if grant else owner
            require(body["nonce"] == signer["nonce"], "nonce mismatch")
            try:
                Ed25519PublicKey.from_public_bytes(bytes.fromhex(signer["public_key"])).verify(bytes.fromhex(sig), DOMAIN+encoded)
            except (InvalidSignature, ValueError) as exc: raise Reject("bad signature") from exc
            fee = self.genesis["fee"]
            require(fee <= body["max_fee"], "fee exceeds consent")
            required = fee
            budget = None
            if op["type"] == "transfer":
                fields(op, {"type","to","units"})
                identifier(op["to"]); integer(op["units"], minimum=1)
                require(op["to"] != owner["id"] and op["to"] != FEE_ACCOUNT, "invalid recipient")
                self._account(op["to"])
                required += op["units"]; integer(required)
                if grant:
                    require(op["to"] in json.loads(grant["recipients"]), "recipient not allowed")
                    require(grant["spent"]+required <= grant["cap"], "grant cap exceeded")
                    if self.budgets is not None:
                        budget = self.budgets.for_grant(owner, grant, height, op["to"], required)
                require(owner["balance"] >= required, "insufficient funds")
                self.db.execute("UPDATE accounts SET balance=balance+? WHERE id=?", (op["units"],op["to"]))
            elif op["type"] == "grant":
                fields(op, {"type","id","public_key","cap","expires","recipients"} |
                       ({"budget_id"} if self.protocol_version == 3 else set()))
                identifier(op["id"]); pubkey(op["public_key"]); integer(op["cap"], minimum=1); integer(op["expires"])
                require(op["expires"] >= height, "grant already expired")
                recipients = op["recipients"]
                require(type(recipients) is list and 1 <= len(recipients) <= 64 and all(type(x) is str for x in recipients), "explicit recipients required")
                require(len(set(recipients)) == len(recipients), "duplicate recipient")
                for recipient in recipients:
                    identifier(recipient); self._account(recipient)
                    require(recipient not in (owner["id"],FEE_ACCOUNT), "invalid recipient")
                grant_key = self.grant_storage_id(owner["id"], op["id"])
                require(not self.db.execute("SELECT 1 FROM grants WHERE id=?", (grant_key,)).fetchone(), "grant already exists")
                self.db.execute("INSERT INTO grants VALUES (?,?,?,?,0,?,0,?,?,0)", (grant_key,owner["id"],op["public_key"],owner["epoch"],op["cap"],op["expires"],json.dumps(sorted(recipients))))
                if self.budgets is not None:
                    self.budgets.bind(owner, grant_key, op, height)
            elif self.protocol_version == 3 and op["type"] == "budget_create":
                self.budgets.create(owner, op, height)
            elif self.protocol_version == 3 and op["type"] == "budget_revoke":
                self.budgets.revoke(owner, op)
            elif op["type"] == "revoke":
                fields(op, {"type","id"}); identifier(op["id"])
                target_id = self.grant_storage_id(owner["id"], op["id"])
                target = self.db.execute("SELECT * FROM grants WHERE id=?", (target_id,)).fetchone()
                require(target is not None and target["owner"] == owner["id"], "not grant owner")
                self.db.execute("UPDATE grants SET revoked=1 WHERE id=?", (target_id,))
            elif self.protocol_version >= 2 and op["type"] == "open_account":
                verify_account_key_acceptance(body)
                new_key = op["public_key"]
                new_id = address(new_key)
                require(self.db.execute("SELECT 1 FROM accounts WHERE id=?", (new_id,)).fetchone() is None,
                        "account already exists")
                require(self.db.execute("SELECT 1 FROM accounts WHERE public_key=?", (new_key,)).fetchone() is None,
                        "key already controls an account")
                required += op["units"]; integer(required)
                require(owner["balance"] >= required, "insufficient funds")
                self.db.execute("INSERT INTO accounts VALUES (?,?,0,0,?)", (new_id, new_key, op["units"]))
            elif self.protocol_version >= 2 and op["type"] == "rotate_key":
                verify_account_key_acceptance(body)
                new_key = op["public_key"]
                require(new_key != owner["public_key"], "key is already active")
                require(self.db.execute("SELECT 1 FROM accounts WHERE public_key=?", (new_key,)).fetchone() is None,
                        "key already controls an account")
                integer(owner["epoch"] + 1)
                # Identity, balances, historical receipts and nonces are retained.
                # Advancing the epoch invalidates ALL old grants atomically.
                self.db.execute("UPDATE accounts SET public_key=?,epoch=epoch+1 WHERE id=?",
                                (new_key, owner["id"]))
            elif op["type"] == "fence":
                fields(op, {"type"})
                integer(owner["epoch"]+1)
                self.db.execute("UPDATE accounts SET epoch=epoch+1 WHERE id=?", (owner["id"],))
            else:
                raise Reject("unsupported operation")
            require(owner["balance"] >= required, "insufficient funds")
            integer(signer["nonce"]+1)
            self.db.execute("UPDATE accounts SET balance=balance-? WHERE id=?", (required,owner["id"]))
            self.db.execute("UPDATE accounts SET balance=balance+? WHERE id=?", (fee,FEE_ACCOUNT))
            if grant:
                self.db.execute("UPDATE grants SET nonce=nonce+1, spent=spent+? WHERE id=?", (required,grant["id"]))
                if budget is not None:
                    self.budgets.debit(budget, required)
            else:
                self.db.execute("UPDATE accounts SET nonce=nonce+1 WHERE id=?", (owner["id"],))
            self.db.execute("UPDATE meta SET v=? WHERE k='height'", (str(height),))
            self._invariants()
            last = self.db.execute("SELECT sequence,hash FROM receipts ORDER BY sequence DESC LIMIT 1").fetchone()
            sequence = 1 if last is None else last["sequence"]+1
            prev = self.genesis_hash if last is None else last["hash"]
            record = {"txid":txid,"sequence":sequence,"previous":prev,"height":height,
                      "state_hash":self.state_hash(),"fee_units":fee,"signer_public_key":signer["public_key"],
                      "envelope":json.loads(canonical(envelope))}
            self.db.execute("INSERT INTO receipts VALUES (?,?,?,?,?)", (txid,sequence,prev,canonical(record).decode(),digest(record)))
            if self.genesis.get("state_commitment") == "smt-v1":
                # Enforce the proof-mode resource bound BEFORE committing. A
                # proposer must not accept a transaction whose eventual root
                # cannot be built. Rejection rolls back debit, nonce and receipt.
                from state_tree import COLUMNS, MAX_ROWS
                total_rows = sum(self.db.execute("SELECT count(*) FROM " + table).fetchone()[0]
                                 for table in COLUMNS)
                require(total_rows <= MAX_ROWS, "compact-state record capacity reached")
            self.db.execute("COMMIT")
            return record
        except Exception:
            self.db.execute("ROLLBACK")
            raise

    def verify_receipts(self) -> bool:
        previous = self.genesis_hash
        for sequence, row in enumerate(self.db.execute("SELECT * FROM receipts ORDER BY sequence"), start=1):
            record = json.loads(row["record"])
            require(row["sequence"] == sequence and record["sequence"] == sequence, "receipt sequence mismatch")
            require(row["previous"] == previous and record["previous"] == previous, "receipt link mismatch")
            require(row["txid"] == record["txid"] and row["hash"] == digest(record), "receipt integrity mismatch")
            envelope = record["envelope"]
            wire = DOMAIN + canonical(envelope["body"])
            require(hashlib.sha256(wire).hexdigest() == record["txid"], "receipt transaction mismatch")
            try:
                Ed25519PublicKey.from_public_bytes(bytes.fromhex(record["signer_public_key"])).verify(bytes.fromhex(envelope["signature"]), wire)
            except (InvalidSignature, ValueError) as exc: raise Reject("receipt signature mismatch") from exc
            if self.protocol_version >= 2 and envelope["body"]["op"]["type"] in ("open_account", "rotate_key"):
                verify_account_key_acceptance(envelope["body"])
            previous = row["hash"]
        last = self.db.execute("SELECT record FROM receipts ORDER BY sequence DESC LIMIT 1").fetchone()
        if last: require(json.loads(last[0])["state_hash"] == self.state_hash(), "state mismatch")
        self._invariants()
        return True
