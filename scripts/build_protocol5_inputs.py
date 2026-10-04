#!/usr/bin/env python3
"""Build exact Protocol 5 deployment identity and runner genesis inputs."""
from __future__ import annotations

import argparse
import base64
import hashlib
import os
from pathlib import Path
import stat
import struct
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from protocol5_encoding import (
    DEPLOYMENT_MAGIC, DeploymentBinding, ProfileDescriptor, canonical_json,
    decode_canonical_json, derive_genesis_field, field_hex, genesis_document,
)

SETTINGS_KEYS = {
    "chain_id", "asset_field", "context_field", "policy_field",
    "authority_epoch", "fee", "validators", "limits",
}
MAX_INPUT_BYTES = 256 * 1024 * 1024
MAX_METADATA_BYTES = 8 * 1024 * 1024


def _read_regular(path: str | Path, maximum: int) -> bytes:
    path = Path(path)
    mode = path.lstat()
    if stat.S_ISLNK(mode.st_mode) or not stat.S_ISREG(mode.st_mode):
        raise ValueError("Protocol 5 builder input is not a regular file")
    if mode.st_size > maximum:
        raise ValueError("Protocol 5 builder input exceeds its byte bound")
    flags = os.O_RDONLY
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    descriptor = os.open(path, flags)
    try:
        opened = os.fstat(descriptor)
        if (not stat.S_ISREG(opened.st_mode)
                or (opened.st_dev, opened.st_ino) != (mode.st_dev, mode.st_ino)):
            raise ValueError("Protocol 5 builder input changed during open")
        chunks = []
        total = 0
        while True:
            chunk = os.read(descriptor, min(1024 * 1024, maximum + 1 - total))
            if not chunk:
                break
            chunks.append(chunk)
            total += len(chunk)
            if total > maximum:
                raise ValueError("Protocol 5 builder input exceeds its byte bound")
        return b"".join(chunks)
    finally:
        os.close(descriptor)


def _manifest_object(raw: bytes, name: str) -> dict:
    if not raw or not raw.endswith(b"\n"):
        raise ValueError(f"Protocol 5 {name} must be canonical JSON plus newline")
    value = decode_canonical_json(raw[:-1], max_bytes=MAX_METADATA_BYTES)
    if type(value) is not dict or not value:
        raise ValueError(f"Protocol 5 {name} must be a nonempty JSON object")
    return value


def _write_new(path: str | Path, raw: bytes) -> None:
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    descriptor = os.open(path, flags, 0o600)
    failed = True
    try:
        view = memoryview(raw)
        while view:
            written = os.write(descriptor, view)
            if written <= 0:
                raise OSError("Protocol 5 builder output write stalled")
            view = view[written:]
        os.fsync(descriptor)
        failed = False
    finally:
        os.close(descriptor)
        if failed:
            try:
                path.unlink()
            except FileNotFoundError:
                pass


def build_protocol5_inputs(
        *, worker: str | Path, profile: str | Path, toolchain: str | Path,
        policy: str | Path, settings: str | Path,
        binding_output: str | Path, genesis_output: str | Path) -> dict:
    """Construct one exact DeploymentBindingV1 and empty-note runner template."""
    binding_output = Path(binding_output)
    genesis_output = Path(genesis_output)
    if binding_output == genesis_output:
        raise ValueError("Protocol 5 builder outputs must be distinct")
    if binding_output.exists() or binding_output.is_symlink():
        raise FileExistsError("Protocol 5 deployment binding output exists")
    if genesis_output.exists() or genesis_output.is_symlink():
        raise FileExistsError("Protocol 5 genesis output exists")

    profile_raw = _read_regular(profile, MAX_METADATA_BYTES)
    descriptor = ProfileDescriptor.decode(profile_raw)
    worker_raw = _read_regular(worker, MAX_INPUT_BYTES)
    toolchain_raw = _read_regular(toolchain, MAX_METADATA_BYTES)
    policy_raw = _read_regular(policy, MAX_METADATA_BYTES)
    _manifest_object(toolchain_raw, "toolchain manifest")
    _manifest_object(policy_raw, "sandbox policy")
    settings_value = decode_canonical_json(
        _read_regular(settings, MAX_METADATA_BYTES), max_bytes=MAX_METADATA_BYTES)
    if type(settings_value) is not dict or set(settings_value) != SETTINGS_KEYS:
        raise ValueError("invalid Protocol 5 runner settings")

    binding_raw = (
        DEPLOYMENT_MAGIC + struct.pack("<HH", 1, 1)
        + descriptor.identity
        + hashlib.sha256(worker_raw).digest()
        + hashlib.sha256(toolchain_raw).digest()
        + hashlib.sha256(policy_raw).digest()
    )
    binding = DeploymentBinding.decode(binding_raw)
    value = dict(settings_value)
    value.update({
        "protocol_version": 5,
        "profile_descriptor": base64.b64encode(profile_raw).decode("ascii"),
        "profile_id": descriptor.identity.hex(),
        "deployment_binding": base64.b64encode(binding_raw).decode("ascii"),
        "deployment_id": binding.identity.hex(),
        "initial_commitments": [],
    })
    value["genesis_field"] = field_hex(derive_genesis_field(value))
    genesis_raw = canonical_json(value)
    parsed = genesis_document(genesis_raw)

    created = []
    try:
        _write_new(binding_output, binding_raw)
        created.append(binding_output)
        _write_new(genesis_output, genesis_raw)
        created.append(genesis_output)
    except Exception:
        for path in created:
            try:
                path.unlink()
            except FileNotFoundError:
                pass
        raise
    return {
        "profile_id": descriptor.identity.hex(),
        "deployment_id": binding.identity.hex(),
        "genesis_sha256": parsed.sha256.hex(),
        "worker_sha256": hashlib.sha256(worker_raw).hexdigest(),
        "toolchain_sha256": hashlib.sha256(toolchain_raw).hexdigest(),
        "sandbox_policy_sha256": hashlib.sha256(policy_raw).hexdigest(),
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ("worker", "profile", "toolchain", "policy", "settings",
                 "binding_output", "genesis_output"):
        parser.add_argument("--" + name.replace("_", "-"), type=Path, required=True)
    args = parser.parse_args()
    result = build_protocol5_inputs(
        worker=args.worker, profile=args.profile, toolchain=args.toolchain,
        policy=args.policy, settings=args.settings,
        binding_output=args.binding_output, genesis_output=args.genesis_output)
    print(canonical_json(result).decode("ascii"))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())