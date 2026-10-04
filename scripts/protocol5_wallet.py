#!/usr/bin/env python3
"""Secret-safe local commands for the finite Protocol 5 development wallet."""
from __future__ import annotations

import argparse
import base64
import binascii
import hashlib
import json
import math
import os
from pathlib import Path
import select
import sqlite3
import stat
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from protocol5_controller import DevelopmentController
from protocol5_delivery import Protocol5Delivery
from protocol5_encoding import (
    canonical_json, decode_canonical_json, genesis_document,
)
from protocol5_state_reader import MAX_STATE_OBSERVATION_BYTES
from protocol5_wallet import Protocol5Wallet


MAX_ENGINE_GENESIS_BYTES = 1_048_576
MAX_APP_GENESIS_BYTES = 8_388_608
MAX_COMMAND_BYTES = 16_384


class SafeParser(argparse.ArgumentParser):
    """Argparse without token reflection or abbreviated/duplicate flags."""

    def __init__(self, *args, **kwargs):
        kwargs.setdefault("allow_abbrev", False)
        super().__init__(*args, **kwargs)

    def error(self, _message):
        self.exit(2, f"{self.prog}: refused invalid arguments\n")

    def parse_args(self, args=None, namespace=None):
        tokens = list(sys.argv[1:] if args is None else args)
        seen = set()
        for token in tokens:
            if not token.startswith("--") or token == "--":
                continue
            name = token.split("=", 1)[0]
            if name != "--help" and name in seen:
                self.error("duplicate option")
            seen.add(name)
        return super().parse_args(tokens, namespace)


class UnavailableController:
    def __getattr__(self, _name):
        raise RuntimeError("structural command invoked the crypto controller")


def _hash_arg(value: str) -> str:
    if (type(value) is not str or len(value) != 64
            or any(character not in "0123456789abcdef"
                   for character in value)):
        raise argparse.ArgumentTypeError("invalid digest")
    return value


def _positive_integer(value: str) -> int:
    try:
        result = int(value, 10)
    except ValueError as exc:
        raise argparse.ArgumentTypeError("invalid integer") from exc
    if str(result) != value or result <= 0:
        raise argparse.ArgumentTypeError("invalid positive integer")
    return result


def _timeout(value: str) -> float:
    try:
        result = float(value)
    except ValueError as exc:
        raise argparse.ArgumentTypeError("invalid timeout") from exc
    if not math.isfinite(result) or not 0 < result <= 15.0:
        raise argparse.ArgumentTypeError("invalid timeout")
    return result


def _open_regular(path: Path, *, private: bool, limit: int) -> bytearray:
    selected = Path(os.path.abspath(path))
    if private:
        for parent in (selected.parent, *selected.parent.parents):
            if parent.is_symlink():
                raise ValueError("private input has a symlink parent")
        parent = selected.parent.stat()
        if (not stat.S_ISDIR(parent.st_mode)
                or parent.st_uid != os.geteuid()
                or parent.st_mode & 0o077):
            raise ValueError("private owned input directory required")
    descriptor = os.open(
        selected,
        os.O_RDONLY | getattr(os, "O_CLOEXEC", 0)
        | getattr(os, "O_NOFOLLOW", 0)
        | getattr(os, "O_NONBLOCK", 0),
    )
    try:
        metadata = os.fstat(descriptor)
        mode = stat.S_IMODE(metadata.st_mode)
        if (not stat.S_ISREG(metadata.st_mode)
                or metadata.st_uid not in {0, os.geteuid()}
                or metadata.st_size > limit
                or metadata.st_mode & 0o022):
            raise ValueError("unsafe bounded input file")
        if private and (
                metadata.st_uid != os.geteuid()
                or mode != 0o600 or metadata.st_nlink != 1):
            raise ValueError("private input file must be owned mode 0600")
        result = bytearray()
        while len(result) <= limit:
            chunk = os.read(descriptor, min(1_048_576, limit + 1 - len(result)))
            if not chunk:
                break
            result.extend(chunk)
        if len(result) > limit:
            raise ValueError("input file exceeds its byte bound")
        return result
    finally:
        os.close(descriptor)


def _trusted_file(path: Path, expected: str, *, limit: int) -> bytes:
    raw = _open_regular(path, private=False, limit=limit)
    try:
        if hashlib.sha256(raw).hexdigest() != expected:
            raise ValueError("trusted input digest differs")
        return bytes(raw)
    finally:
        raw[:] = b"\0" * len(raw)


def _private_payload(path: Path | None, *, limit: int,
                     optional: bool = False) -> bytearray | None:
    if path is not None:
        if not sys.stdin.isatty() and select.select(
                [sys.stdin.buffer], [], [], 0)[0]:
            supplied = sys.stdin.buffer.read(limit + 1)
            if supplied:
                shadow = bytearray(supplied)
                shadow[:] = b"\0" * len(shadow)
                raise ValueError("file and stdin inputs are ambiguous")
        raw = _open_regular(path, private=True, limit=limit)
    else:
        if sys.stdin.isatty():
            if optional:
                return None
            raise ValueError("bounded stdin or a private input file is required")
        raw = bytearray(sys.stdin.buffer.read(limit + 1))
        if len(raw) > limit:
            raw[:] = b"\0" * len(raw)
            raise ValueError("stdin exceeds its byte bound")
        if not raw and optional:
            return None
    if not raw:
        raise ValueError("empty command input refused")
    return raw


def _engine_genesis(raw: bytes) -> dict:
    def pairs(items):
        result = {}
        for key, value in items:
            if key in result:
                raise ValueError("duplicate engine genesis member")
            result[key] = value
        return result

    def integer_only(_value):
        raise ValueError("non-integer engine genesis number")

    try:
        value = json.loads(
            raw.decode("utf-8"), object_pairs_hook=pairs,
            parse_float=integer_only, parse_constant=integer_only)
    except (UnicodeError, json.JSONDecodeError) as exc:
        raise ValueError("invalid engine genesis") from exc
    if type(value) is not dict:
        raise ValueError("invalid engine genesis")
    return value


def _load_trust(args) -> tuple[bytes, dict]:
    app_raw = _trusted_file(
        args.app_genesis, args.app_genesis_sha256,
        limit=MAX_APP_GENESIS_BYTES)
    genesis_document(app_raw)
    engine_raw = _trusted_file(
        args.engine_genesis, args.engine_genesis_sha256,
        limit=MAX_ENGINE_GENESIS_BYTES)
    return app_raw, _engine_genesis(engine_raw)


def _controller(args, app_raw: bytes):
    if not getattr(args, "crypto", False):
        return UnavailableController()
    controller = DevelopmentController(
        args.client, args.prover, genesis_document(app_raw).value,
        expected_client_sha256=args.client_sha256,
        expected_prover_sha256=args.prover_sha256,
    )
    controller.validate_executables()
    return controller


def _decode_envelope(raw: bytearray, keys: set[str]) -> dict:
    value = decode_canonical_json(bytes(raw), max_bytes=len(raw))
    if type(value) is not dict or set(value) != keys:
        raise ValueError("invalid closed command input")
    return value


def _hex_secret(value, name: str) -> bytes:
    if (type(value) is not str or len(value) != 64
            or any(character not in "0123456789abcdef"
                   for character in value)):
        raise ValueError("invalid " + name)
    result = bytes.fromhex(value)
    if not any(result):
        raise ValueError("invalid " + name)
    return result


def _base64_capsule(value) -> bytes:
    if type(value) is not str:
        raise ValueError("invalid note capsule encoding")
    try:
        raw = base64.b64decode(value, validate=True)
    except (ValueError, binascii.Error) as exc:
        raise ValueError("invalid note capsule encoding") from exc
    if base64.b64encode(raw).decode("ascii") != value:
        raise ValueError("noncanonical note capsule encoding")
    return raw


def _private_parent(path: Path) -> Path:
    selected = Path(os.path.abspath(path))
    for parent in (selected.parent, *selected.parent.parents):
        if parent.is_symlink():
            raise ValueError("symlink output parent refused")
    metadata = selected.parent.stat()
    if (not stat.S_ISDIR(metadata.st_mode)
            or metadata.st_uid != os.geteuid()
            or metadata.st_mode & 0o077):
        raise ValueError("private owned output directory required")
    return selected


def _ensure_new_output(path: Path) -> Path:
    selected = _private_parent(path)
    if os.path.lexists(selected):
        raise FileExistsError("output already exists")
    return selected


def _write_new(path: Path, raw: bytes) -> None:
    selected = _ensure_new_output(path)
    descriptor = None
    created = False
    try:
        descriptor = os.open(
            selected,
            os.O_WRONLY | os.O_CREAT | os.O_EXCL
            | getattr(os, "O_CLOEXEC", 0)
            | getattr(os, "O_NOFOLLOW", 0),
            0o600,
        )
        created = True
        os.fchmod(descriptor, 0o600)
        view = memoryview(raw)
        while view:
            written = os.write(descriptor, view)
            if written <= 0:
                raise OSError("output write stalled")
            view = view[written:]
        os.fsync(descriptor)
        os.close(descriptor)
        descriptor = None
        parent = os.open(
            selected.parent,
            os.O_RDONLY | os.O_DIRECTORY | getattr(os, "O_NOFOLLOW", 0))
        try:
            os.fsync(parent)
        finally:
            os.close(parent)
    except BaseException:
        if descriptor is not None:
            os.close(descriptor)
        if created:
            try:
                selected.unlink()
            except FileNotFoundError:
                pass
        raise


def _emit(value: dict) -> None:
    sys.stdout.buffer.write(canonical_json(value) + b"\n")
    sys.stdout.buffer.flush()


def _add_common(parser) -> None:
    parser.add_argument("--wallet", required=True, type=Path)
    parser.add_argument("--app-genesis", required=True, type=Path)
    parser.add_argument("--app-genesis-sha256", required=True, type=_hash_arg)
    parser.add_argument("--engine-genesis", required=True, type=Path)
    parser.add_argument(
        "--engine-genesis-sha256", required=True, type=_hash_arg)


def _add_crypto(parser) -> None:
    parser.set_defaults(crypto=True)
    parser.add_argument("--client", required=True, type=Path)
    parser.add_argument("--client-sha256", required=True, type=_hash_arg)
    parser.add_argument("--prover", required=True, type=Path)
    parser.add_argument("--prover-sha256", required=True, type=_hash_arg)


def _add_delivery(parser) -> None:
    parser.add_argument("--delivery", required=True, type=Path)
    parser.add_argument("--endpoint", required=True)


def build_parser() -> SafeParser:
    parser = SafeParser(description=__doc__)
    commands = parser.add_subparsers(
        dest="command", required=True, parser_class=SafeParser)

    def command(name: str, *, crypto: bool = False,
                delivery: bool = False):
        selected = commands.add_parser(name, allow_abbrev=False)
        _add_common(selected)
        if crypto:
            _add_crypto(selected)
        else:
            selected.set_defaults(crypto=False)
        if delivery:
            _add_delivery(selected)
        return selected

    init = command("init", crypto=True)
    init.add_argument("--input", type=Path)
    command("owner-key")
    command("status", crypto=True)

    sync = command("sync", crypto=True)
    sync.add_argument("--expected-revision", required=True, type=_hash_arg)
    sync.add_argument("--input", type=Path)

    import_note = command("import-note", crypto=True)
    import_note.add_argument(
        "--expected-revision", required=True, type=_hash_arg)
    import_note.add_argument("--input", type=Path)

    prepare = command("prepare")
    prepare.add_argument("--note-id", required=True, type=_hash_arg)
    prepare.add_argument(
        "--recipient-owner-key", required=True, type=_hash_arg)
    prepare.add_argument("--value", required=True, type=_positive_integer)
    prepare.add_argument(
        "--valid-until", required=True, type=_positive_integer)

    approve = command("approve", crypto=True)
    approve.add_argument("--input", type=Path)

    recover = command("recover")
    identity = recover.add_mutually_exclusive_group(required=True)
    identity.add_argument("--decision-id", type=_hash_arg)
    identity.add_argument("--review-id", type=_hash_arg)
    recover.add_argument("--output", required=True, type=Path)

    export = command("export-capsule", crypto=True)
    export.add_argument("--decision-id", required=True, type=_hash_arg)
    export.add_argument("--output", required=True, type=Path)

    command("delivery-init", delivery=True)
    delivery_prepare = command("delivery-prepare", delivery=True)
    delivery_prepare.add_argument(
        "--decision-id", required=True, type=_hash_arg)
    delivery_send = command("delivery-send", delivery=True)
    delivery_send.add_argument("--input", type=Path)
    delivery_collect = command("delivery-collect", delivery=True)
    delivery_collect.add_argument("--timeout", type=_timeout, default=15.0)
    delivery_reconcile = command(
        "delivery-reconcile", crypto=True, delivery=True)
    delivery_reconcile.add_argument(
        "--decision-id", required=True, type=_hash_arg)
    delivery_reconcile.add_argument(
        "--observation-id", required=True, type=_hash_arg)
    delivery_reconcile.add_argument(
        "--expected-revision", required=True, type=_hash_arg)
    delivery_inspect = command("delivery-inspect", delivery=True)
    delivery_inspect.add_argument(
        "--decision-id", required=True, type=_hash_arg)
    return parser


def _wallet(args, app_raw: bytes, engine: dict, *, create: bool = False,
            spend_secret: bytes | None = None) -> Protocol5Wallet:
    return Protocol5Wallet(
        args.wallet, app_raw, engine, _controller(args, app_raw),
        create=create, spend_secret=spend_secret)


def _resolve_decision(wallet: Protocol5Wallet, args) -> str:
    if args.decision_id is not None:
        return args.decision_id
    matches = [
        row["decision_id"] for row in wallet.continuity()["decisions"]
        if row["review_id"] == args.review_id]
    if len(matches) != 1:
        raise ValueError("review does not identify one durable decision")
    return matches[0]


def dispatch(args) -> dict:
    app_raw, engine = _load_trust(args)
    if args.command == "init":
        controller = _controller(args, app_raw)
        raw = _private_payload(args.input, limit=256, optional=True)
        try:
            secret = None
            if raw is not None:
                value = _decode_envelope(raw, {"owner_spend_secret"})
                secret = _hex_secret(
                    value["owner_spend_secret"], "owner spend secret")
            with Protocol5Wallet(
                    args.wallet, app_raw, engine, controller, create=True,
                    spend_secret=secret) as wallet:
                result = wallet.continuity()
            return {
                "status": "initialized", "wallet_id": result["wallet_id"],
                "owner_key": result["owner_key"],
                "revision": result["revision"],
            }
        finally:
            if raw is not None:
                raw[:] = b"\0" * len(raw)

    with _wallet(args, app_raw, engine) as wallet:
        if args.command == "owner-key":
            value = wallet.continuity()
            return {
                "format": "1soft/protocol5-owner-key/v1",
                "wallet_id": value["wallet_id"],
                "owner_key": value["owner_key"],
                "revision": value["revision"],
            }
        if args.command == "status":
            return wallet.status()
        if args.command == "sync":
            raw = _private_payload(
                args.input, limit=MAX_STATE_OBSERVATION_BYTES)
            try:
                return wallet.sync(
                    bytes(raw), expected_revision=args.expected_revision)
            finally:
                raw[:] = b"\0" * len(raw)
        if args.command == "import-note":
            raw = _private_payload(args.input, limit=MAX_COMMAND_BYTES)
            try:
                value = _decode_envelope(
                    raw, {"capsule_base64", "owner_spend_secret"})
                capsule = _base64_capsule(value["capsule_base64"])
                secret = _hex_secret(
                    value["owner_spend_secret"], "owner spend secret")
                return wallet.import_note(
                    capsule, secret,
                    expected_revision=args.expected_revision)
            finally:
                raw[:] = b"\0" * len(raw)
        if args.command == "prepare":
            return wallet.prepare(
                note_id=args.note_id,
                recipient_owner_key=args.recipient_owner_key,
                value=args.value, valid_until=args.valid_until)
        if args.command == "approve":
            raw = _private_payload(args.input, limit=MAX_COMMAND_BYTES)
            try:
                value = _decode_envelope(raw, {"review", "confirmation"})
                return wallet.approve(
                    value["review"], value["confirmation"])
            finally:
                raw[:] = b"\0" * len(raw)
        if args.command == "recover":
            _ensure_new_output(args.output)
            decision_id = _resolve_decision(wallet, args)
            transaction = wallet.recover(decision_id)
            _write_new(args.output, transaction)
            return {
                "status": "recovered", "decision_id": decision_id,
                "transaction_sha256": hashlib.sha256(
                    transaction).hexdigest(),
                "bytes": len(transaction),
            }
        if args.command == "export-capsule":
            _ensure_new_output(args.output)
            capsule = wallet.export_capsule(args.decision_id, 0)
            _write_new(args.output, capsule)
            return {
                "status": "capsule_exported",
                "decision_id": args.decision_id,
                "capsule_sha256": hashlib.sha256(capsule).hexdigest(),
                "bytes": len(capsule),
            }

        continuity = wallet.continuity()
        with Protocol5Delivery(
                args.delivery, continuity["wallet_id"], app_raw, engine,
                args.endpoint,
                create=args.command == "delivery-init") as delivery:
            if args.command == "delivery-init":
                return delivery.status()
            if args.command == "delivery-prepare":
                return delivery.prepare(wallet, args.decision_id)
            if args.command == "delivery-send":
                raw = _private_payload(args.input, limit=MAX_COMMAND_BYTES)
                try:
                    value = _decode_envelope(
                        raw, {"review", "confirmation"})
                    return delivery.send(
                        wallet, value["review"], value["confirmation"])
                finally:
                    raw[:] = b"\0" * len(raw)
            if args.command == "delivery-collect":
                return delivery.collect(timeout=args.timeout)
            if args.command == "delivery-reconcile":
                return delivery.reconcile(
                    wallet, args.decision_id, args.observation_id,
                    expected_wallet_revision=args.expected_revision)
            if args.command == "delivery-inspect":
                return delivery.inspect(args.decision_id)
    raise ValueError("unknown Protocol 5 wallet command")


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        _emit(dispatch(args))
        return 0
    except (OSError, ValueError, RuntimeError, sqlite3.Error) as exc:
        del exc
        print("Protocol 5 wallet refused", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
