"""Protocol 5 canonical identities and consensus encodings.

This module deliberately contains no Poseidon, witness, or proof implementation.
"""
from __future__ import annotations

import base64
import binascii
from dataclasses import dataclass
import hashlib
import json
import struct
from typing import Any

from validator_sets_core import ValidatorSet

PALLAS_BASE_MODULUS = int(
    "40000000000000000000000000000000224698fc094cf91b992d30ed00000001", 16)
U64_MAX = 2**64 - 1
FIELD_DOMAIN = b"1soft/shielded-field/v1\0"
PROFILE_DOMAIN = b"1soft/shielded-profile/v1\0"
DEPLOYMENT_DOMAIN = b"1soft/shielded-deployment/v1\0"
TXID_DOMAIN = b"1soft/shielded-txid/v1\0"
PROFILE_MAGIC = b"1SFTPFD1"
DEPLOYMENT_MAGIC = b"1SFTDEP1"
TX_MAGIC = b"1SFTSHD1"
CIRCUIT_ID = "1soft/shielded-consensus/halo2-pasta/v1"
PROFILE_HEADER = struct.Struct("<HHIHHHIH")
DEPLOYMENT_HEADER = struct.Struct("<HH")
TX_HEADER = struct.Struct("<HHI")
HARD_LIMITS = {
    "max_height": 512,
    "max_accepted_transactions": 8,
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
    "max_fee_total": U64_MAX,
    "worker_startup_timeout_seconds": 120,
    "worker_request_timeout_seconds": 30,
}
GENESIS_KEYS = {
    "chain_id", "protocol_version", "profile_descriptor", "profile_id",
    "deployment_binding", "deployment_id", "genesis_field", "asset_field",
    "context_field", "policy_field", "authority_epoch", "fee", "validators",
    "initial_commitments", "limits",
}


class EncodingError(ValueError):
    pass


class TransactionIdentityError(EncodingError):
    pass


def _need(condition: bool, message: str) -> None:
    if not condition:
        raise EncodingError(message)


def _integer(value: Any, low: int, high: int, name: str) -> int:
    _need(type(value) is int and low <= value <= high, "invalid " + name)
    return value


def _no_float(value: str):
    raise EncodingError("non-integer JSON number")


def _pairs(items):
    out = {}
    for key, value in items:
        if key in out:
            raise EncodingError("duplicate JSON member")
        out[key] = value
    return out


def _scalar_strings(value: Any) -> None:
    if isinstance(value, str):
        _need(not any(0xD800 <= ord(ch) <= 0xDFFF for ch in value),
              "non-scalar Unicode string")
    elif isinstance(value, list):
        for item in value:
            _scalar_strings(item)
    elif isinstance(value, dict):
        for key, item in value.items():
            _scalar_strings(key)
            _scalar_strings(item)


def canonical_json(value: Any) -> bytes:
    try:
        _scalar_strings(value)
        return json.dumps(value, sort_keys=True, separators=(",", ":"),
                          ensure_ascii=True, allow_nan=False).encode("ascii")
    except (TypeError, ValueError, UnicodeError) as exc:
        if isinstance(exc, EncodingError):
            raise
        raise EncodingError("value is not canonical JSON") from exc


def decode_canonical_json(raw: bytes, *, max_bytes: int = 8 * 1024 * 1024) -> Any:
    _need(type(raw) is bytes and len(raw) <= max_bytes, "JSON byte bound exceeded")
    try:
        value = json.loads(raw.decode("ascii"), object_pairs_hook=_pairs,
                           parse_float=_no_float, parse_constant=_no_float)
    except EncodingError:
        raise
    except (json.JSONDecodeError, UnicodeError) as exc:
        raise EncodingError("invalid canonical JSON") from exc
    _scalar_strings(value)
    _need(canonical_json(value) == raw, "noncanonical JSON bytes")
    return value


def _closed(value: Any, keys: set[str], name: str) -> dict:
    _need(type(value) is dict and set(value) == keys, "invalid " + name)
    return value


def _hex(value: Any, size: int, name: str) -> bytes:
    _need(type(value) is str and len(value) == size * 2
          and all(ch in "0123456789abcdef" for ch in value),
          "noncanonical " + name)
    return bytes.fromhex(value)


def _base64(value: Any, name: str) -> bytes:
    _need(type(value) is str, "invalid " + name)
    try:
        raw = base64.b64decode(value, validate=True)
    except (ValueError, binascii.Error) as exc:
        raise EncodingError("invalid " + name) from exc
    _need(base64.b64encode(raw).decode("ascii") == value, "noncanonical " + name)
    return raw


def field_bytes(value: Any) -> bytes:
    raw = _hex(value, 32, "field")
    _need(int.from_bytes(raw, "little") < PALLAS_BASE_MODULUS,
          "field is outside Pallas base modulus")
    _need(int.from_bytes(raw, "little").to_bytes(32, "little") == raw,
          "field round trip differs")
    return raw


def field_hex(raw: bytes) -> str:
    _need(type(raw) is bytes and len(raw) == 32, "invalid field bytes")
    _need(int.from_bytes(raw, "little") < PALLAS_BASE_MODULUS,
          "field is outside Pallas base modulus")
    return raw.hex()


def h2f(label: bytes, payload: bytes) -> bytes:
    _need(type(label) is bytes and type(payload) is bytes, "H2F inputs must be bytes")
    _need(len(label) <= 0xFFFF and len(payload) <= 0xFFFFFFFF, "H2F input too long")
    digest = hashlib.sha512(
        FIELD_DOMAIN + struct.pack("<H", len(label)) + label
        + struct.pack("<I", len(payload)) + payload
    ).digest()
    value = int.from_bytes(digest, "little") % PALLAS_BASE_MODULUS
    return value.to_bytes(32, "little")


@dataclass(frozen=True)
class ProfileDescriptor:
    raw: bytes
    descriptor_version: int
    backend_id: int
    relation_version: int
    k: int
    depth: int
    public_input_count: int
    proof_length: int
    circuit_id: str
    hashes: tuple[bytes, ...]

    @property
    def identity(self) -> bytes:
        return hashlib.sha256(PROFILE_DOMAIN + self.raw).digest()

    @classmethod
    def decode(cls, raw: bytes) -> "ProfileDescriptor":
        _need(type(raw) is bytes and len(raw) >= 8 + PROFILE_HEADER.size + 9 * 32,
              "truncated profile descriptor")
        _need(raw[:8] == PROFILE_MAGIC, "wrong profile descriptor magic")
        fields = PROFILE_HEADER.unpack_from(raw, 8)
        version, backend, relation, k, depth, count, proof_length, circuit_len = fields
        offset = 8 + PROFILE_HEADER.size
        end = offset + circuit_len
        _need(end + 9 * 32 == len(raw), "profile descriptor length differs")
        circuit_raw = raw[offset:end]
        try:
            circuit = circuit_raw.decode("ascii")
        except UnicodeError as exc:
            raise EncodingError("non-ASCII circuit identity") from exc
        _need(circuit_raw and b"\0" not in circuit_raw, "invalid circuit identity")
        hashes = tuple(raw[i:i + 32] for i in range(end, len(raw), 32))
        _need((version, backend, relation, k, depth, count)
              == (1, 1, 1, 13, 4, 14), "unsupported profile descriptor")
        _need(circuit == CIRCUIT_ID, "unexpected circuit identity")
        _need(0 < proof_length <= HARD_LIMITS["max_proof_bytes"],
              "invalid exact proof length")
        _need(len(hashes) == 9, "invalid profile hash count")
        return cls(raw, version, backend, relation, k, depth, count,
                   proof_length, circuit, hashes)


@dataclass(frozen=True)
class DeploymentBinding:
    raw: bytes
    binding_version: int
    worker_protocol_version: int
    profile_id: bytes
    worker_sha256: bytes
    toolchain_sha256: bytes
    sandbox_policy_sha256: bytes

    @property
    def identity(self) -> bytes:
        return hashlib.sha256(DEPLOYMENT_DOMAIN + self.raw).digest()

    @classmethod
    def decode(cls, raw: bytes) -> "DeploymentBinding":
        _need(type(raw) is bytes and len(raw) == 8 + DEPLOYMENT_HEADER.size + 128,
              "deployment binding length differs")
        _need(raw[:8] == DEPLOYMENT_MAGIC, "wrong deployment binding magic")
        version, worker_version = DEPLOYMENT_HEADER.unpack_from(raw, 8)
        _need((version, worker_version) == (1, 1), "unsupported deployment binding")
        offset = 8 + DEPLOYMENT_HEADER.size
        chunks = [raw[i:i + 32] for i in range(offset, len(raw), 32)]
        return cls(raw, version, worker_version, *chunks)


@dataclass(frozen=True)
class GenesisDocument:
    raw: bytes
    value: dict
    profile: ProfileDescriptor
    deployment: DeploymentBinding
    sha256: bytes


@dataclass(frozen=True)
class Transaction:
    raw: bytes
    wire_version: int
    backend_id: int
    relation_version: int
    genesis_sha256: bytes
    deployment_id: bytes
    public_fields: tuple[bytes, ...]
    proof: bytes

    @classmethod
    def decode(cls, raw: bytes, genesis: GenesisDocument) -> "Transaction":
        limits = genesis.value["limits"]
        _need(type(raw) is bytes and len(raw) <= limits["max_tx_bytes"],
              "transaction byte bound exceeded")
        _need(len(raw) >= 534, "truncated shielded transaction")
        _need(raw[:8] == TX_MAGIC, "wrong shielded transaction magic")
        wire, backend, relation = TX_HEADER.unpack_from(raw, 8)
        offset = 8 + TX_HEADER.size
        genesis_hash = raw[offset:offset + 32]; offset += 32
        deployment_id = raw[offset:offset + 32]; offset += 32
        count = struct.unpack_from("<H", raw, offset)[0]; offset += 2
        _need(count == 14, "wrong public field count")
        fields = tuple(raw[i:i + 32] for i in range(offset, offset + 14 * 32, 32))
        _need(all(len(item) == 32 and int.from_bytes(item, "little") < PALLAS_BASE_MODULUS
                  for item in fields), "noncanonical public field")
        offset += 14 * 32
        proof_length = struct.unpack_from("<I", raw, offset)[0]; offset += 4
        _need(proof_length == genesis.profile.proof_length
              and proof_length <= limits["max_proof_bytes"],
              "wrong proof length")
        _need(offset + proof_length == len(raw), "transaction length differs")
        if (wire, backend, relation) != (1, 1, 1) or genesis_hash != genesis.sha256                 or deployment_id != genesis.deployment.identity:
            raise TransactionIdentityError("shielded transaction identity differs")
        return cls(raw, wire, backend, relation, genesis_hash, deployment_id,
                   fields, raw[offset:])


def transaction_id(raw: bytes) -> bytes:
    _need(type(raw) is bytes, "transaction must be bytes")
    return hashlib.sha256(TXID_DOMAIN + raw).digest()


def comet_validator_set(rows: list[dict]) -> ValidatorSet:
    normalized = [{"public_key": row["public_key"], "power": row["power"]} for row in rows]
    normalized.sort(key=lambda row: (
        -row["power"], hashlib.sha256(bytes.fromhex(row["public_key"])).digest()[:20]))
    return ValidatorSet.parse(normalized)


def genesis_document(raw: bytes) -> GenesisDocument:
    value = _closed(decode_canonical_json(raw), GENESIS_KEYS, "Protocol 5 genesis")
    chain_id = value["chain_id"]
    try:
        chain_bytes = chain_id.encode("ascii", "strict") if type(chain_id) is str else b""
    except UnicodeEncodeError as exc:
        raise EncodingError("invalid chain identity") from exc
    _need(1 <= len(chain_bytes) <= 50
          and all(0x20 <= byte <= 0x7E for byte in chain_bytes),
          "invalid chain identity")
    _need(value["protocol_version"] == 5, "fresh Protocol 5 genesis required")
    profile_raw = _base64(value["profile_descriptor"], "profile descriptor")
    profile = ProfileDescriptor.decode(profile_raw)
    _need(_hex(value["profile_id"], 32, "profile identity") == profile.identity,
          "profile identity differs")
    deployment_raw = _base64(value["deployment_binding"], "deployment binding")
    deployment = DeploymentBinding.decode(deployment_raw)
    _need(deployment.profile_id == profile.identity, "deployment profile differs")
    _need(_hex(value["deployment_id"], 32, "deployment identity") == deployment.identity,
          "deployment identity differs")
    for name in ("genesis_field", "asset_field", "context_field", "policy_field"):
        field_bytes(value[name])
    epoch = _integer(value["authority_epoch"], 1, U64_MAX, "authority epoch")
    fee = _integer(value["fee"], 1, U64_MAX, "fee")
    validators = value["validators"]
    _need(type(validators) is list and len(validators) == 4, "exactly four validators required")
    keys = []
    powers = []
    for row in validators:
        _closed(row, {"public_key", "power"}, "validator")
        key = _hex(row["public_key"], 32, "validator public key")
        _need(any(key), "zero validator public key")
        keys.append(key)
        powers.append(_integer(row["power"], 1, 1_000_000, "validator power"))
    _need(keys == sorted(keys) and len(set(keys)) == 4,
          "validators must be unique and public-key sorted")
    _need(len(set(powers)) == 1, "validator powers must be equal")
    commitments = value["initial_commitments"]
    _need(type(commitments) is list and len(commitments) <= 16,
          "invalid genesis commitment count")
    commitment_bytes = [field_bytes(item) for item in commitments]
    _need(all(any(item) for item in commitment_bytes)
          and len(set(commitment_bytes)) == len(commitment_bytes),
          "genesis commitments must be unique and nonzero")
    limits = _closed(value["limits"], set(HARD_LIMITS), "Protocol 5 limits")
    for name, ceiling in HARD_LIMITS.items():
        selected = _integer(limits[name], 1, ceiling, name)
        if name == "max_total_voting_power":
            _need(sum(powers) <= selected, "voting power exceeds selected bound")
    accepted = limits["max_accepted_transactions"]
    _need(accepted <= (16 - len(commitments)) // 2,
          "accepted transaction count exceeds tree capacity")
    _need(accepted <= limits["max_history_transactions"],
          "accepted transaction count exceeds history count")
    _need(profile.proof_length <= limits["max_proof_bytes"],
          "proof exceeds selected proof bound")
    _need(534 + profile.proof_length <= limits["max_tx_bytes"],
          "transaction exceeds selected transaction bound")
    max_worker_request = 56 + 2 + 16 * 32 + 14 * 32 + 4 + profile.proof_length
    _need(max_worker_request <= limits["max_worker_frame_bytes"],
          "worker request exceeds selected frame bound")
    _need(fee * accepted <= limits["max_fee_total"],
          "fees exceed selected total")
    _need(limits["snapshot_chunk_bytes"] * limits["max_snapshot_chunks"]
          >= limits["max_snapshot_bytes"],
          "snapshot chunks cannot carry selected snapshot bound")
    projection = dict(value)
    projection.pop("genesis_field")
    expected_genesis_field = h2f(b"genesis", canonical_json(projection))
    _need(field_bytes(value["genesis_field"]) == expected_genesis_field,
          "derived genesis field differs")
    return GenesisDocument(raw, value, profile, deployment, hashlib.sha256(raw).digest())
