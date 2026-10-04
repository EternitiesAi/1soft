"""Opt-in local coordination for P4 journal clones sharing one registry.

The registry is trusted local POSIX storage. It is neither native transaction
authority nor protection against an independent registry, a raw signer, rollback,
or a hostile process running as the registry owner.
"""
from __future__ import annotations

from contextlib import contextmanager
import hashlib
import hmac
import json
import os
from pathlib import Path
import re
import sqlite3
import stat

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey, Ed25519PublicKey,
)

DOMAIN = b"1soft/device-fence/v1\0"
OUTCOME_DOMAIN = b"1soft/device-fence/outcome/v1\0"
MAX_TEXT = 128
MAX_BODY = 16384
MAX_INTEGER = 2**63 - 1
APPLICATION_ID = 0x31504644
IDENTIFIER = re.compile(r"[a-zA-Z0-9][a-zA-Z0-9._:-]{0,127}\Z")
SIDECARS = ("-wal", "-shm", "-journal")
SCHEMA_V1 = (
    "CREATE TABLE wallets(wallet TEXT PRIMARY KEY,epoch INTEGER NOT NULL CHECK(epoch>=0),active_device TEXT NOT NULL,owner_key BLOB NOT NULL CHECK(length(owner_key)=32))",
    "CREATE TABLE devices(wallet TEXT NOT NULL REFERENCES wallets(wallet),device TEXT NOT NULL,public_key BLOB NOT NULL CHECK(length(public_key)=32),retired_epoch INTEGER CHECK(retired_epoch>=0),PRIMARY KEY(wallet,device))",
    "CREATE TABLE reservations(wallet TEXT NOT NULL REFERENCES wallets(wallet),lane TEXT NOT NULL,nonce INTEGER NOT NULL CHECK(nonce>=0),request TEXT NOT NULL,device TEXT NOT NULL,epoch INTEGER NOT NULL CHECK(epoch>=0),digest TEXT NOT NULL,state TEXT NOT NULL CHECK(state='reserved'),PRIMARY KEY(wallet,request),UNIQUE(wallet,lane,nonce),FOREIGN KEY(wallet,device) REFERENCES devices(wallet,device))",
)

SCHEMA = (
    "CREATE TABLE wallets(wallet TEXT PRIMARY KEY,epoch INTEGER NOT NULL CHECK(epoch>=0),"
    "active_device TEXT NOT NULL,owner_key BLOB NOT NULL CHECK(length(owner_key)=32))",
    "CREATE TABLE devices(wallet TEXT NOT NULL REFERENCES wallets(wallet),"
    "device TEXT NOT NULL,public_key BLOB NOT NULL CHECK(length(public_key)=32),"
    "retired_epoch INTEGER CHECK(retired_epoch>=0),PRIMARY KEY(wallet,device))",
    "CREATE TABLE reservations(wallet TEXT NOT NULL REFERENCES wallets(wallet),"
    "lane TEXT NOT NULL,nonce INTEGER NOT NULL CHECK(nonce>=0),request TEXT NOT NULL,"
    "device TEXT NOT NULL,epoch INTEGER NOT NULL CHECK(epoch>=0),digest TEXT NOT NULL,"
    "state TEXT NOT NULL CHECK(state IN ('reserved','decision_committed')),"
    "decision_id TEXT,wire_sha256 TEXT,"
    "CHECK((state='reserved' AND decision_id IS NULL AND wire_sha256 IS NULL) OR "
    "(state='decision_committed' AND length(decision_id)=64 AND length(wire_sha256)=64)),"
    "PRIMARY KEY(wallet,request),UNIQUE(wallet,lane,nonce),"
    "FOREIGN KEY(wallet,device) REFERENCES devices(wallet,device))",
    "CREATE TABLE fence_events(seq INTEGER PRIMARY KEY,wallet TEXT NOT NULL,"
    "request TEXT NOT NULL,action TEXT NOT NULL CHECK(action='decision_committed'),"
    "actor TEXT NOT NULL,epoch INTEGER NOT NULL CHECK(epoch>=0),digest TEXT NOT NULL,"
    "decision_id TEXT NOT NULL,wire_sha256 TEXT NOT NULL,"
    "authorization BLOB NOT NULL CHECK(length(authorization)=64),event_hash TEXT NOT NULL UNIQUE,"
    "UNIQUE(wallet,request,action),"
    "FOREIGN KEY(wallet,request) REFERENCES reservations(wallet,request))",
)


class DeviceFenceError(ValueError):
    """Invalid authority or unavailable/unsafe coordination; never permission to sign."""


def _enc(value):
    try:
        return json.dumps(value, sort_keys=True, separators=(",", ":"),
                          ensure_ascii=True, allow_nan=False).encode("ascii")
    except (TypeError, ValueError, OverflowError, RecursionError) as exc:
        raise DeviceFenceError("invalid canonical reservation data") from exc


def _digest(value):
    return hashlib.sha256(DOMAIN + _enc(value)).hexdigest()


def _text(value, name):
    if (type(value) is not str or not value or len(value) > MAX_TEXT
            or IDENTIFIER.fullmatch(value) is None):
        raise DeviceFenceError("invalid " + name)
    return value


def _integer(value, name):
    if type(value) is not int or not 0 <= value <= MAX_INTEGER:
        raise DeviceFenceError("invalid " + name)
    return value


def _hash(value, name):
    if type(value) is not str or re.fullmatch(r"[0-9a-f]{64}", value) is None:
        raise DeviceFenceError("invalid " + name)
    return value


def _key(value):
    if type(value) is not bytes or len(value) != 32:
        raise DeviceFenceError("invalid device key")
    return value


def _freeze_body(body):
    # JSON round trips alone would silently turn integer keys into strings.
    def check(value, depth=0):
        if depth > 32:
            raise DeviceFenceError("reservation data nesting exceeds limit")
        if type(value) is dict:
            if any(type(key) is not str for key in value):
                raise DeviceFenceError("reservation object keys must be text")
            for item in value.values():
                check(item, depth + 1)
        elif type(value) is list:
            for item in value:
                check(item, depth + 1)
        elif type(value) not in (str, int, bool, type(None)):
            raise DeviceFenceError("reservation data must contain exact JSON values")
    if type(body) is not dict:
        raise DeviceFenceError("reservation body must be an object")
    check(body)
    raw = _enc(body)
    if len(raw) > MAX_BODY:
        raise DeviceFenceError("reservation body exceeds limit")
    return json.loads(raw)


def authority_lane(body):
    """One canonical payer/owner-or-grant lane; nonce is a separate unique key."""
    if type(body) is not dict:
        raise DeviceFenceError("reservation body must be an object")
    sender = _text(body.get("sender"), "sender")
    grant = body.get("grant_id")
    if type(grant) is not str:
        raise DeviceFenceError("explicit owner or grant role required")
    if grant:
        _text(grant, "grant")
    _integer(body.get("nonce"), "native nonce")
    return _enc({"sender": sender, "grant_id": grant}).decode("ascii")


def rotation_message(wallet, old, new, public_key, *, epoch):
    """Both device keys consent to exactly this current and successor epoch."""
    _text(wallet, "wallet"); _text(old, "old device"); _text(new, "new device")
    _key(public_key); _integer(epoch, "epoch")
    if old == new or epoch == MAX_INTEGER:
        raise DeviceFenceError("invalid replacement or exhausted epoch")
    return DOMAIN + _enc({
        "action": "rotate", "wallet": wallet, "epoch": epoch,
        "next_epoch": epoch + 1, "old_device": old, "new_device": new,
        "new_key": public_key.hex(),
    })


def reservation_message(wallet, device, epoch, lane, nonce, request, body):
    _text(wallet, "wallet"); _text(device, "device"); _text(request, "request")
    _integer(epoch, "epoch"); _integer(nonce, "nonce")
    body = _freeze_body(body)
    if lane != authority_lane(body) or nonce != body["nonce"]:
        raise DeviceFenceError("reservation lane or nonce differs from body")
    return DOMAIN + _enc({
        "action": "reserve", "wallet": wallet, "device": device, "epoch": epoch,
        "lane": lane, "nonce": nonce, "request": request, "body": body,
    })


def _verify(public_key, signature, message, error):
    if type(signature) is not bytes or len(signature) != 64:
        raise DeviceFenceError(error)
    try:
        Ed25519PublicKey.from_public_bytes(_key(public_key)).verify(signature, message)
    except (InvalidSignature, ValueError, TypeError) as exc:
        raise DeviceFenceError(error) from exc


def _safe_file(info):
    if (not stat.S_ISREG(info.st_mode) or info.st_uid != os.geteuid()
            or info.st_nlink != 1 or info.st_mode & 0o077):
        raise DeviceFenceError("unsafe registry file or sidecar")


class DeviceFence:
    """Serialized reservations and device turnover in one owner-only directory."""

    def __init__(self, path):
        self.path = Path(os.path.abspath(path))
        self.db = None
        self._parent_fd = None
        self._identity = None
        if os.name != "posix":
            raise DeviceFenceError("device fencing requires a trusted POSIX host")
        try:
            self._check_parents()
            self._parent_fd = os.open(
                self.path.parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW,
            )
            self._parent_identity = self._file_identity(os.fstat(self._parent_fd))
            self._check_storage(require_file=False)
            flags = os.O_RDWR | os.O_NOFOLLOW
            try:
                fd = os.open(self.path.name, flags | os.O_CREAT | os.O_EXCL,
                             0o600, dir_fd=self._parent_fd)
                created = True
            except FileExistsError:
                fd = os.open(self.path.name, flags, dir_fd=self._parent_fd)
                created = False
            try:
                info = os.fstat(fd)
                _safe_file(info)
                self._identity = self._file_identity(info)
                if created:
                    os.fsync(fd)
                    os.fsync(self._parent_fd)
            finally:
                os.close(fd)
            self._check_storage()
            self.db = sqlite3.connect(self.path.as_uri() + "?mode=rw", uri=True,
                                      isolation_level=None, timeout=5)
            self._check_storage()
            self.db.execute("PRAGMA foreign_keys=ON")
            if created:
                if self.db.execute("PRAGMA journal_mode=WAL").fetchone()[0] != "wal":
                    raise DeviceFenceError("registry WAL mode unavailable")
                self.db.execute("PRAGMA synchronous=FULL")
                with self._write(check_schema=False):
                    for statement in SCHEMA:
                        self.db.execute(statement)
                    self.db.execute(f"PRAGMA application_id={APPLICATION_ID}")
                    self.db.execute("PRAGMA user_version=2")
            if not created and self.db.execute("PRAGMA user_version").fetchone()[0] == 1:
                self._migrate_v1()
            self._check_schema()
            if self.db.execute("PRAGMA journal_mode").fetchone()[0] != "wal":
                raise DeviceFenceError("registry journal mode differs")
            self.db.execute("PRAGMA synchronous=FULL")
            self._check_storage()
        except (OSError, sqlite3.Error) as exc:
            self.close()
            raise DeviceFenceError("registry storage unavailable; reconcile before retry") from exc
        except BaseException:
            self.close()
            raise

    @staticmethod
    def _file_identity(info):
        return info.st_dev, info.st_ino

    def _check_parents(self):
        for parent in (self.path.parent, *self.path.parent.parents):
            info = parent.lstat()
            if not stat.S_ISDIR(info.st_mode):
                raise DeviceFenceError("registry symlink parent or non-directory refused")
            # Sticky /tmp is allowed; an ordinary writable ancestor could replace
            # our private directory from outside it.
            if info.st_mode & 0o022 and not info.st_mode & stat.S_ISVTX:
                raise DeviceFenceError("writable registry ancestor refused")
        info = self.path.parent.lstat()
        if info.st_uid != os.geteuid() or info.st_mode & 0o077:
            raise DeviceFenceError("private owned registry directory required")

    def _check_storage(self, *, require_file=True):
        self._check_parents()
        if self._parent_fd is not None:
            current = self._file_identity(self.path.parent.lstat())
            if current != self._parent_identity:
                raise DeviceFenceError("registry parent was replaced")
        for suffix in ("", *SIDECARS):
            name = self.path.name + suffix
            try:
                info = os.stat(name, dir_fd=self._parent_fd, follow_symlinks=False)
            except FileNotFoundError:
                if not suffix and require_file:
                    raise DeviceFenceError("registry file is missing")
                continue
            _safe_file(info)
            if not suffix and self._identity is not None:
                if self._file_identity(info) != self._identity:
                    raise DeviceFenceError("registry file was replaced")

    def _migrate_v1(self):
        objects = set(self.db.execute("SELECT type,name FROM sqlite_master WHERE name NOT LIKE 'sqlite_%'"))
        expected = {( "table", n) for n in ("wallets","devices","reservations")}
        sql = {n:q for n,q in self.db.execute("SELECT name,sql FROM sqlite_master WHERE type='table'")}
        if (self.db.execute("PRAGMA application_id").fetchone()[0] != APPLICATION_ID
                or objects != expected or any(sql.get(n) != q for n,q in zip(("wallets","devices","reservations"), SCHEMA_V1))):
            raise DeviceFenceError("unrecognized registry; existing storage is not repaired")
        try:
            with self._write(check_schema=False):
                self.db.execute("ALTER TABLE reservations RENAME TO reservations_v1")
                self.db.execute(SCHEMA[2])
                self.db.execute("INSERT INTO reservations(wallet,lane,nonce,request,device,epoch,digest,state) SELECT wallet,lane,nonce,request,device,epoch,digest,state FROM reservations_v1")
                self.db.execute("DROP TABLE reservations_v1")
                self.db.execute(SCHEMA[3])
                self.db.execute("PRAGMA user_version=2")
        except DeviceFenceError:
            raise
        except sqlite3.Error as exc:
            raise DeviceFenceError("registry migration failed; reconcile before retry") from exc

    def _check_schema(self):
        objects = set(self.db.execute(
            "SELECT type,name FROM sqlite_master WHERE name NOT LIKE 'sqlite_%'",
        ))
        expected = {("table", name) for name in ("wallets", "devices", "reservations", "fence_events")}
        if (self.db.execute("PRAGMA application_id").fetchone()[0] != APPLICATION_ID
                or self.db.execute("PRAGMA user_version").fetchone()[0] != 2
                or objects != expected):
            raise DeviceFenceError("unrecognized registry; existing storage is not repaired")
        sql = {row[0]: row[1] for row in self.db.execute(
            "SELECT name,sql FROM sqlite_master WHERE type='table'",
        )}
        if any(sql[statement.split()[2].split("(")[0]] != statement for statement in SCHEMA):
            raise DeviceFenceError("registry schema differs")

    def close(self):
        if self.db is not None:
            self.db.close()
            self.db = None
        if self._parent_fd is not None:
            os.close(self._parent_fd)
            self._parent_fd = None

    def __enter__(self):
        if self.db is None:
            raise DeviceFenceError("registry is closed")
        return self

    def __exit__(self, *_):
        self.close()

    @contextmanager
    def _read(self):
        if self.db is None:
            raise DeviceFenceError("registry is closed")
        if self.db.in_transaction:
            raise DeviceFenceError("registry transaction already active")
        storage_operation = True
        try:
            self._check_storage()
            self.db.execute("BEGIN")
            self._check_storage()
            self._check_schema()
            storage_operation = False
            yield
            storage_operation = True
            self._check_storage()
            self.db.execute("COMMIT")
        except BaseException as exc:
            try:
                if self.db is not None and self.db.in_transaction:
                    self.db.execute("ROLLBACK")
            except sqlite3.Error:
                self.close()
            if isinstance(exc, sqlite3.Error) or (storage_operation and isinstance(exc, OSError)):
                raise DeviceFenceError(
                    "registry inspection failed; reconcile before retry",
                ) from exc
            raise

    @contextmanager
    def _write(self, *, check_schema=True):
        if self.db is None:
            raise DeviceFenceError("registry is closed")
        if self.db.in_transaction:
            raise DeviceFenceError("registry transaction already active")
        storage_operation = True
        try:
            self._check_storage()
            self.db.execute("BEGIN IMMEDIATE")
            self._check_storage()
            if check_schema:
                self._check_schema()
            storage_operation = False
            yield
            storage_operation = True
            self._check_storage()
            self.db.execute("COMMIT")
        except BaseException as exc:
            try:
                if self.db is not None and self.db.in_transaction:
                    self.db.execute("ROLLBACK")
            except sqlite3.Error:
                self.close()
            if isinstance(exc, sqlite3.Error) or (storage_operation and isinstance(exc, OSError)):
                raise DeviceFenceError(
                    "registry transaction failed; reconcile before retry",
                ) from exc
            raise

    def enroll(self, wallet, device, public_key):
        """Explicit trusted local enrollment; not proof of native account ownership."""
        _text(wallet, "wallet"); _text(device, "device"); _key(public_key)
        with self._write():
            if self.db.execute("SELECT 1 FROM wallets WHERE wallet=?", (wallet,)).fetchone():
                raise DeviceFenceError("wallet is already enrolled")
            self.db.execute("INSERT INTO wallets VALUES (?,?,?,?)",
                            (wallet, 0, device, public_key))
            self.db.execute("INSERT INTO devices VALUES (?,?,?,?)",
                            (wallet, device, public_key, None))

    def _active(self, wallet, device, epoch):
        row = self.db.execute(
            "SELECT w.epoch,w.active_device,w.owner_key,d.public_key,d.retired_epoch "
            "FROM wallets w JOIN devices d ON d.wallet=w.wallet AND d.device=? "
            "WHERE w.wallet=?", (device, wallet),
        ).fetchone()
        if (row is None or (epoch, device) != row[:2] or row[4] is not None
                or row[2] != row[3]):
            raise DeviceFenceError("device is fenced")
        return row[3]

    def rotate(self, wallet, old, new, public_key, old_signature, new_signature, *, epoch):
        message = rotation_message(wallet, old, new, public_key, epoch=epoch)
        with self._write():
            active_key = self._active(wallet, old, epoch)
            if public_key == active_key:
                raise DeviceFenceError("replacement key is already active")
            if self.db.execute(
                "SELECT 1 FROM devices WHERE wallet=? AND device=?", (wallet, new),
            ).fetchone():
                raise DeviceFenceError("device identity is already enrolled")
            _verify(active_key, old_signature, message, "rotation consent invalid")
            _verify(public_key, new_signature, message, "rotation consent invalid")
            successor = epoch + 1
            self.db.execute("UPDATE devices SET retired_epoch=? WHERE wallet=? AND device=?",
                            (successor, wallet, old))
            self.db.execute("INSERT INTO devices VALUES (?,?,?,?)",
                            (wallet, new, public_key, None))
            self.db.execute("UPDATE wallets SET epoch=?,active_device=?,owner_key=? WHERE wallet=?",
                            (successor, new, public_key, wallet))
        return successor

    def _outcome_message(self, wallet, actor, epoch, request, digest, decision_id, wire_sha256):
        _text(wallet, "wallet"); _text(actor, "device"); _integer(epoch, "epoch")
        _text(request, "request"); _hash(digest, "reservation digest")
        _hash(decision_id, "decision"); _hash(wire_sha256, "wire digest")
        return OUTCOME_DOMAIN + _enc({"action":"decision_committed","wallet":wallet,
            "actor":actor,"epoch":epoch,"request":request,"digest":digest,
            "decision_id":decision_id,"wire_sha256":wire_sha256})

    def inspect(self, wallet, request=None):
        _text(wallet, "wallet")
        if request is not None:
            _text(request, "request")
        with self._read():
            query = ("SELECT wallet,lane,nonce,request,device,epoch,digest,state,"
                     "decision_id,wire_sha256 FROM reservations WHERE wallet=?")
            args = [wallet]
            if request is not None:
                query += " AND request=?"
                args.append(request)
            rows = [dict(zip(
                ("wallet", "lane", "nonce", "request", "device", "epoch", "digest",
                 "state", "decision_id", "wire_sha256"),
                row,
            )) for row in self.db.execute(query, args).fetchall()]
        if request is not None:
            return rows[0] if rows else None
        return rows

    def _record_outcome(self, wallet, actor, epoch, request, digest, decision_id, wire_sha256, signature):
        self._active(wallet, actor, epoch)
        message = self._outcome_message(wallet, actor, epoch, request, digest, decision_id, wire_sha256)
        _verify(self.db.execute("SELECT public_key FROM devices WHERE wallet=? AND device=?", (wallet,actor)).fetchone()[0],
                signature, message, "invalid outcome authorization")
        row = self.db.execute("SELECT digest,state,decision_id,wire_sha256 FROM reservations WHERE wallet=? AND request=?", (wallet,request)).fetchone()
        if row is None or row[0] != digest: raise DeviceFenceError("reservation differs")
        if row[1] == "decision_committed":
            if row[2:] != (decision_id, wire_sha256): raise DeviceFenceError("committed outcome differs")
            return {"status":"already_committed","request_id":request,"decision_id":decision_id,"wire_sha256":wire_sha256}
        self.db.execute("UPDATE reservations SET state='decision_committed',decision_id=?,wire_sha256=? WHERE wallet=? AND request=?",
                        (decision_id,wire_sha256,wallet,request))
        event_hash = hashlib.sha256(message + signature).hexdigest()
        self.db.execute(
            "INSERT INTO fence_events(wallet,request,action,actor,epoch,digest,"
            "decision_id,wire_sha256,authorization,event_hash) VALUES (?,?,?,?,?,?,?,?,?,?)",
            (wallet, request, "decision_committed", actor, epoch, digest,
             decision_id, wire_sha256, signature, event_hash),
        )
        return {"status":"decision_committed","request_id":request,"decision_id":decision_id,"wire_sha256":wire_sha256}

    def record_decision_committed(self, wallet, actor, epoch, request, digest, decision_id, wire_sha256, signature):
        with self._write():
            return self._record_outcome(wallet, actor, epoch, request, digest, decision_id, wire_sha256, signature)

    def reserve(self, wallet, device, epoch, lane, nonce, request, body, signature):
        message = reservation_message(wallet, device, epoch, lane, nonce, request, body)
        digest = hashlib.sha256(message).hexdigest()
        with self._write():
            active_key = self._active(wallet, device, epoch)
            _verify(active_key, signature, message, "invalid reservation authorization")
            previous = self.db.execute(
                "SELECT digest,state FROM reservations WHERE wallet=? AND request=?",
                (wallet, request),
            ).fetchone()
            if previous:
                if previous[0] != digest:
                    raise DeviceFenceError("reservation request reused with different body")
                if previous[1] != "reserved":
                    raise DeviceFenceError("reservation is not active")
                return {"status": "already_reserved", "digest": digest}
            if self.db.execute(
                "SELECT 1 FROM reservations WHERE wallet=? AND lane=? AND nonce=?",
                (wallet, lane, nonce),
            ).fetchone():
                raise DeviceFenceError("authority lane is already reserved; reconcile before retry")
            self.db.execute("INSERT INTO reservations(wallet,lane,nonce,request,device,epoch,digest,state) VALUES (?,?,?,?,?,?,?,?)",
                            (wallet, lane, nonce, request, device, epoch, digest, "reserved"))
        return {"status": "reserved", "digest": digest}

    @contextmanager
    def signing_authority(self, wallet, device, epoch, request, digest):
        """Keep rotation serialized after a durable reservation and through signing."""
        _text(wallet, "wallet"); _text(device, "device"); _text(request, "request")
        _integer(epoch, "epoch")
        if type(digest) is not str or re.fullmatch(r"[0-9a-f]{64}", digest) is None:
            raise DeviceFenceError("invalid reservation digest")
        with self._write():
            self._active(wallet, device, epoch)
            row = self.db.execute(
                "SELECT device,epoch,digest,state FROM reservations WHERE wallet=? AND request=?",
                (wallet, request),
            ).fetchone()
            if row != (device, epoch, digest, "reserved"):
                raise DeviceFenceError("signing reservation differs")
            yield


def wallet_identity(wallet):
    """Clone-stable namespace bound to the P4 journal identity and exact genesis."""
    with wallet.atomic(write=False):
        journal_id = wallet._catalog()[0]
    return _digest({
        "action": "wallet_identity", "journal_wallet_id": journal_id,
        "genesis_sha256": hashlib.sha256(wallet.genesis).hexdigest(),
    })


class FencedApproval:
    """Explicit adapter: owns its supplied wallet, borrows the shared registry.

    Closing the adapter closes the wallet, not the caller's shared registry.
    Direct P4Wallet.approve and existing CLIs remain outside this opt-in path.
    """
    def __init__(self, wallet, fence, device, epoch, key, *, owns_wallet=True):
        _text(device, "device"); _integer(epoch, "epoch")
        if not isinstance(fence, DeviceFence) or not isinstance(key, Ed25519PrivateKey):
            raise DeviceFenceError("explicit registry and Ed25519 device key required")
        self.wallet = wallet
        self.fence = fence
        self.device = device
        self.epoch = epoch
        self.key = key
        self.owns_wallet = owns_wallet
        if type(owns_wallet) is not bool: raise DeviceFenceError("invalid wallet ownership")
        self.wallet_id = wallet_identity(wallet)
        self._closed = False

    def close(self):
        if not self._closed:
            if self.owns_wallet:
                self.wallet.close()
            self._closed = True

    def __enter__(self):
        if self._closed:
            raise DeviceFenceError("approval adapter is closed")
        return self

    def __exit__(self, *_):
        self.close()

    def approve(self, review, confirmation, *, vault, password, request_id=None):
        from p4_evidence import content_id, freeze
        if self._closed:
            raise DeviceFenceError("approval adapter is closed")
        # Freeze and validate caller input before any durable reservation.
        review = freeze(review, 32768)
        if type(confirmation) is not str or not hmac.compare_digest(content_id(review), confirmation):
            raise DeviceFenceError("explicit review confirmation differs")
        request = confirmation if request_id is None else _text(request_id, "request")
        if wallet_identity(self.wallet) != self.wallet_id:
            raise DeviceFenceError("wallet identity changed")
        try:
            body = review["body"]
            op = body["op"]
            if op["type"] != "transfer":
                raise DeviceFenceError("fenced approval only supports transfers")
            current = self.wallet.prepare(
                payer=body["sender"], recipient=op["to"], units=op["units"],
                valid_until=body["valid_until"], grant_id=body["grant_id"],
                invoice_terms=review.get("invoice_terms"),
            )
        except (KeyError, TypeError) as exc:
            raise DeviceFenceError("invalid transfer review") from exc
        if _enc(review) != _enc(current["review"]):
            raise DeviceFenceError("reviewed wallet state or transfer changed; review again")
        lane = authority_lane(body)
        message = reservation_message(
            self.wallet_id, self.device, self.epoch, lane, body["nonce"], request, body,
        )
        reservation = self.fence.reserve(
            self.wallet_id, self.device, self.epoch, lane, body["nonce"],
            request, body, self.key.sign(message),
        )
        if reservation["status"] != "reserved":
            raise DeviceFenceError("reservation already consumed; reconcile before retry")
        with self.fence.signing_authority(
            self.wallet_id, self.device, self.epoch, request, reservation["digest"],
        ):
            result = self.wallet.approve(review, confirmation, vault=vault, password=password)
            from native_core import canonical
            wire_sha256 = hashlib.sha256(canonical(result["transaction"])).hexdigest()
            outcome_message = self.fence._outcome_message(self.wallet_id, self.device, self.epoch,
                request, reservation["digest"], confirmation, wire_sha256)
            recorded = self.fence._record_outcome(
                self.wallet_id, self.device, self.epoch, request,
                reservation["digest"], confirmation, wire_sha256,
                self.key.sign(outcome_message),
            )
            result["request_id"] = request
            result["wire_sha256"] = wire_sha256
            result["fence_status"] = recorded["status"]
            return result

    def reconcile(self, review, confirmation, *, request_id=None):
        from p4_evidence import content_id, freeze
        if self._closed:
            raise DeviceFenceError("approval adapter is closed")
        review = freeze(review, 32768)
        if type(confirmation) is not str or not hmac.compare_digest(
                content_id(review), confirmation):
            raise DeviceFenceError("explicit review confirmation differs")
        request = confirmation if request_id is None else _text(request_id, "request")
        if wallet_identity(self.wallet) != self.wallet_id:
            raise DeviceFenceError("wallet identity changed")
        with self.wallet.atomic(write=False):
            _, _, _, decisions, _ = self.wallet._load(historical=True)
            matches = [d for d in decisions if d["id"] == confirmation]
        if len(matches) > 1:
            raise DeviceFenceError("ambiguous committed decision")
        if matches and _enc(matches[0]["review"]) != _enc(review):
            raise DeviceFenceError("review differs from committed decision")
        outcome = self.fence.inspect(self.wallet_id, request)
        if outcome is None:
            if not matches:
                raise DeviceFenceError("reservation differs")
            wire = bytes.fromhex(matches[0]["wire_hex"])
            return {
                "status": "unfenced_decision", "request_id": request,
                "decision_id": confirmation, "transaction": wire,
                "wire_sha256": hashlib.sha256(wire).hexdigest(),
                "signing_performed": False, "registry_recorded": False,
            }
        body = review["body"]
        original = reservation_message(
            self.wallet_id, outcome["device"], outcome["epoch"],
            outcome["lane"], outcome["nonce"], request, body,
        )
        digest = hashlib.sha256(original).hexdigest()
        if outcome["digest"] != digest:
            raise DeviceFenceError("reservation differs")
        if not matches:
            status = ("committed_elsewhere"
                      if outcome["state"] == "decision_committed"
                      else "unknown_quarantined")
            return {
                "status": status, "request_id": request,
                "decision_id": outcome["decision_id"],
                "wire_sha256": outcome["wire_sha256"],
                "signing_performed": False,
            }
        wire = bytes.fromhex(matches[0]["wire_hex"])
        wire_sha256 = hashlib.sha256(wire).hexdigest()
        message = self.fence._outcome_message(
            self.wallet_id, self.device, self.epoch, request, digest,
            confirmation, wire_sha256,
        )
        recorded = self.fence.record_decision_committed(
            self.wallet_id, self.device, self.epoch, request, digest,
            confirmation, wire_sha256, self.key.sign(message),
        )
        return {
            "status": ("already_reconciled"
                       if recorded["status"] == "already_committed"
                       else "reconciled"),
            "request_id": request, "decision_id": confirmation,
            "transaction": wire, "wire_sha256": wire_sha256,
            "signing_performed": False, "registry_recorded": True,
        }
