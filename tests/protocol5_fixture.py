"""Synthetic codec-only Protocol 5 values; never Halo2 or acceptance evidence."""
from __future__ import annotations

import base64
import hashlib
import struct

from protocol5_encoding import canonical_json, h2f, field_hex

HASHES = tuple(bytes([i]) * 32 for i in range(1, 10))
CIRCUIT_ID = b"1soft/shielded-consensus/halo2-pasta/v1"
PROFILE_BYTES = (
    b"1SFTPFD1" + struct.pack("<HHIHHHIH", 1, 1, 1, 13, 4, 14, 1024, len(CIRCUIT_ID))
    + CIRCUIT_ID + b"".join(HASHES)
)
PROFILE_ID = hashlib.sha256(b"1soft/shielded-profile/v1\0" + PROFILE_BYTES).digest()
WORKER_HASH = bytes.fromhex("11" * 32)
TOOLCHAIN_HASH = bytes.fromhex("22" * 32)
POLICY_HASH = bytes.fromhex("33" * 32)
DEPLOYMENT_BYTES = (
    b"1SFTDEP1" + struct.pack("<HH", 1, 1) + PROFILE_ID
    + WORKER_HASH + TOOLCHAIN_HASH + POLICY_HASH
)
DEPLOYMENT_ID = hashlib.sha256(
    b"1soft/shielded-deployment/v1\0" + DEPLOYMENT_BYTES
).digest()

def make_limits(**changes):
    limits = {
        "max_height": 32,
        "max_accepted_transactions": 6,
        "max_txs_per_block": 8,
        "max_candidates": 64,
        "max_candidate_inspect_bytes": 4 * 1024 * 1024,
        "max_tx_bytes": 64 * 1024,
        "max_proof_bytes": 60 * 1024,
        "max_block_bytes": 512 * 1024,
        "max_finalize_request_bytes": 2 * 1024 * 1024,
        "max_history_transactions": 64,
        "max_history_tx_bytes": 2 * 1024 * 1024,
        "max_snapshot_bytes": 8 * 1024 * 1024,
        "snapshot_chunk_bytes": 64 * 1024,
        "max_snapshot_chunks": 128,
        "max_worker_frame_bytes": 1024 * 1024,
        "max_total_voting_power": 4_000_000,
        "max_fee_total": 1000,
        "worker_startup_timeout_seconds": 120,
        "worker_request_timeout_seconds": 30,
    }
    limits.update(changes)
    return limits

def make_genesis(**changes):
    validators = [{"public_key": (bytes([i]) * 32).hex(), "power": 10} for i in (1, 2, 3, 4)]
    value = {
        "chain_id": "p5-test",
        "protocol_version": 5,
        "profile_descriptor": base64.b64encode(PROFILE_BYTES).decode("ascii"),
        "profile_id": PROFILE_ID.hex(),
        "deployment_binding": base64.b64encode(DEPLOYMENT_BYTES).decode("ascii"),
        "deployment_id": DEPLOYMENT_ID.hex(),
        "asset_field": field_hex(h2f(b"asset", b"test")),
        "context_field": field_hex(h2f(b"context", b"test")),
        "policy_field": field_hex(h2f(b"policy", b"test")),
        "authority_epoch": 1,
        "fee": 5,
        "validators": validators,
        "initial_commitments": [
            field_hex(h2f(b"commitment", b"zero")),
            field_hex(h2f(b"commitment", b"one")),
        ],
        "limits": make_limits(),
    }
    value.update(changes)
    projection = dict(value)
    projection.pop("genesis_field", None)
    value["genesis_field"] = field_hex(h2f(b"genesis", canonical_json(projection)))
    return value

def make_public_fields(genesis):
    return (
        field_hex((1).to_bytes(32, "little")),
        genesis["genesis_field"],
        genesis["asset_field"],
        genesis["context_field"],
        field_hex(genesis["authority_epoch"].to_bytes(32, "little")),
        field_hex((1).to_bytes(32, "little")),
        field_hex((10).to_bytes(32, "little")),
        genesis["policy_field"],
        field_hex(h2f(b"root", b"anchor")),
        field_hex(h2f(b"nullifier", b"n")),
        field_hex(h2f(b"output", b"0")),
        field_hex(h2f(b"output", b"1")),
        field_hex(genesis["fee"].to_bytes(32, "little")),
        field_hex(h2f(b"authorization", b"a")),
    )

def make_tx(genesis, proof=b"P" * 1024, fields=None):
    fields = fields or make_public_fields(genesis)
    return (
        b"1SFTSHD1" + struct.pack("<HHI", 1, 1, 1)
        + hashlib.sha256(canonical_json(genesis)).digest()
        + bytes.fromhex(genesis["deployment_id"])
        + struct.pack("<H", 14)
        + b"".join(bytes.fromhex(item) for item in fields)
        + struct.pack("<I", len(proof)) + proof
    )
