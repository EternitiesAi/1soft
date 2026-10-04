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
MAX_TEXT = 128
MAX_BODY = 16384
MAX_INTEGER = 2**63 - 1
APPLICATION_ID = 0x31504644
IDENTIFIER = re.compile(r"[a-zA-Z0-9][a-zA-Z0-9._:-]{0,127}\Z")
SIDECARS = ("-wal", "-shm", "-journal")
SCHEMA = (
    "CREATE TABLE wallets(wallet TEXT PRIMARY KEY,epoch INTEGER NOT NULL CHECK(epoch>=0),"
    "active_device TEXT NOT NULL,owner_key BLOB NOT NULL CHECK(length(owner_key)=32))",
    "CREATE TABLE devices(wallet TEXT NOT NULL REFERENCES wallets(wallet),"
    "device TEXT NOT NULL,public_key BLOB NOT NULL CHECK(length(public_key)=32),"
    "retired_epoch INTEGER CHECK(retired_epoch>=0),PRIMARY KEY(wallet,device))",
    "CREATE TABLE reservations(wallet TEXT NOT NULL REFERENCES wallets(wallet),"
    "lane TEXT NOT NULL,nonce INTEGER NOT NULL CHECK(nonce>=0),request TEXT NOT NULL,"
    "device TEXT NOT NULL,epoch INTEGER NOT NULL CHECK(epoch>=0),digest TEXT NOT NULL,"
    "state TEXT NOT NULL CHECK(state='reserved'),PRIMARY KEY(wallet,request),"
    "UNIQUE(wallet,lane,nonce),FOREIGN KEY(wallet,device) REFERENCES devices(wallet,device))",
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
                    self.db.execute("PRAGMA user_version=1")
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

    def _check_schema(self):
        objects = set(self.db.execute(
            "SELECT type,name FROM sqlite_master WHERE name NOT LIKE 'sqlite_%'",
        ))
        expected = {("table", name) for name in ("wallets", "devices", "reservations")}
        if (self.db.execute("PRAGMA application_id").fetchone()[0] != APPLICATION_ID
                or self.db.execute("PRAGMA user_version").fetchone()[0] != 1
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
            self.db.execute("INSERT INTO reservations VALUES (?,?,?,?,?,?,?,?)",
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
    def __init__(self, wallet, fence, device, epoch, key):
        _text(device, "device"); _integer(epoch, "epoch")
        if not isinstance(fence, DeviceFence) or not isinstance(key, Ed25519PrivateKey):
            raise DeviceFenceError("explicit registry and Ed25519 device key required")
        self.wallet = wallet
        self.fence = fence
        self.device = device
        self.epoch = epoch
        self.key = key
        self.wallet_id = wallet_identity(wallet)
        self._closed = False

    def close(self):
        if not self._closed:
            self.wallet.close()
            self._closed = True

    def __enter__(self):
        if self._closed:
            raise DeviceFenceError("approval adapter is closed")
        return self

    def __exit__(self, *_):
        self.close()

    def approve(self, review, confirmation, *, vault, password):
        from p4_evidence import content_id, freeze
        if self._closed:
            raise DeviceFenceError("approval adapter is closed")
        # Freeze and validate caller input before any durable reservation.
        review = freeze(review, 32768)
        if type(confirmation) is not str or not hmac.compare_digest(content_id(review), confirmation):
            raise DeviceFenceError("explicit review confirmation differs")
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
            self.wallet_id, self.device, self.epoch, lane, body["nonce"], confirmation, body,
        )
        reservation = self.fence.reserve(
            self.wallet_id, self.device, self.epoch, lane, body["nonce"],
            confirmation, body, self.key.sign(message),
        )
        if reservation["status"] != "reserved":
            raise DeviceFenceError("reservation already consumed; reconcile before retry")
        with self.fence.signing_authority(
            self.wallet_id, self.device, self.epoch, confirmation, reservation["digest"],
        ):
            return self.wallet.approve(review, confirmation, vault=vault, password=password)
