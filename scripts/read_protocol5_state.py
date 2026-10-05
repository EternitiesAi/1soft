#!/usr/bin/env python3
"""Read one authenticated Protocol 5 state observation from loopback RPC."""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import stat
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from protocol5_encoding import genesis_document
from protocol5_state_reader import read_state_observation

MAX_ENGINE_GENESIS_BYTES = 1_048_576
MAX_APP_GENESIS_BYTES = 8_388_608


def _digest(value: str) -> str:
    if (
        type(value) is not str
        or len(value) != 64
        or any(ch not in "0123456789abcdef" for ch in value)
    ):
        raise argparse.ArgumentTypeError("expected lowercase SHA-256")
    return value


def _read_regular(path: Path, *, limit: int, expected_sha256: str) -> bytes:
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(
        os, "O_NOFOLLOW", 0)
    descriptor = os.open(path, flags)
    try:
        metadata = os.fstat(descriptor)
        if not stat.S_ISREG(metadata.st_mode) or metadata.st_size > limit:
            raise ValueError("invalid bounded input file")
        chunks = []
        remaining = limit + 1
        while remaining:
            chunk = os.read(descriptor, min(1024 * 1024, remaining))
            if not chunk:
                break
            chunks.append(chunk)
            remaining -= len(chunk)
        raw = b"".join(chunks)
        if len(raw) > limit:
            raise ValueError("input file exceeds bound")
    finally:
        os.close(descriptor)
    if hashlib.sha256(raw).hexdigest() != expected_sha256:
        raise ValueError("input file digest differs")
    return raw


def _pairs(items):
    value = {}
    for key, item in items:
        if key in value:
            raise ValueError("duplicate engine genesis member")
        value[key] = item
    return value


def _integer_only(value: str):
    raise ValueError("non-integer engine genesis number")


def _engine_genesis(raw: bytes) -> dict:
    try:
        value = json.loads(
            raw.decode("utf-8"),
            object_pairs_hook=_pairs,
            parse_float=_integer_only,
            parse_constant=_integer_only,
        )
    except (UnicodeError, json.JSONDecodeError) as exc:
        raise ValueError("invalid engine genesis") from exc
    if type(value) is not dict:
        raise ValueError("invalid engine genesis")
    return value


def _write_new(path: Path, raw: bytes) -> None:
    if os.path.lexists(path):
        raise FileExistsError("observation output already exists")
    flags = (
        os.O_WRONLY | os.O_CREAT | os.O_EXCL
        | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    )
    descriptor = None
    created = False
    try:
        descriptor = os.open(path, flags, 0o600)
        created = True
        os.fchmod(descriptor, 0o600)
        view = memoryview(raw)
        while view:
            written = os.write(descriptor, view)
            if written <= 0:
                raise OSError("short observation write")
            view = view[written:]
        os.fsync(descriptor)
    except Exception:
        if descriptor is not None:
            os.close(descriptor)
            descriptor = None
        if created:
            try:
                os.unlink(path)
            except FileNotFoundError:
                pass
        raise
    finally:
        if descriptor is not None:
            os.close(descriptor)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--endpoint", required=True)
    parser.add_argument("--engine-genesis", required=True, type=Path)
    parser.add_argument("--engine-genesis-sha256", required=True, type=_digest)
    parser.add_argument("--app-genesis", required=True, type=Path)
    parser.add_argument("--app-genesis-sha256", required=True, type=_digest)
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--timeout", type=float, default=15.0)
    args = parser.parse_args(argv)

    try:
        if os.path.lexists(args.output):
            raise FileExistsError("observation output already exists")
        engine_raw = _read_regular(
            args.engine_genesis,
            limit=MAX_ENGINE_GENESIS_BYTES,
            expected_sha256=args.engine_genesis_sha256,
        )
        app_raw = _read_regular(
            args.app_genesis,
            limit=MAX_APP_GENESIS_BYTES,
            expected_sha256=args.app_genesis_sha256,
        )
        genesis_document(app_raw)
        observation = read_state_observation(
            args.endpoint,
            _engine_genesis(engine_raw),
            app_raw,
            timeout=args.timeout,
        )
        _write_new(args.output, observation)
    except (OSError, ValueError) as exc:
        parser.error(str(exc))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
