"""Strict private NoteCapsuleV1 parsing and authenticated-origin checks."""
from __future__ import annotations

import base64
import binascii
import hashlib
from typing import Any

from protocol5_controller import SecretNote
from protocol5_encoding import (
    EncodingError,
    Transaction,
    U64_MAX,
    canonical_json,
    decode_canonical_json,
    field_bytes,
    field_hex,
    genesis_document,
    transaction_id,
)

NOTE_CAPSULE_FORMAT = "1soft/protocol5-note-capsule/v1"
MAX_NOTE_CAPSULE_BYTES = 2048
_CAPSULE_ID_DOMAIN = b"1soft/protocol5-note-capsule-id/v1\0"
_CAPSULE_KEYS = {
    "format", "version", "capsule_id", "genesis_sha256", "profile_id",
    "deployment_id", "origin", "commitment", "owner_key", "expiry", "value",
    "note_secret", "blinding",
}


class NoteCapsuleError(ValueError):
    pass


def _need(condition: bool, message: str) -> None:
    if not condition:
        raise NoteCapsuleError(message)


def _hash_hex(value: Any, name: str, *, nonzero: bool = False) -> bytes:
    _need(
        type(value) is str
        and len(value) == 64
        and all(ch in "0123456789abcdef" for ch in value),
        "invalid " + name,
    )
    raw = bytes.fromhex(value)
    _need(not nonzero or any(raw), "zero " + name)
    return raw


def _field(value: Any, name: str) -> bytes:
    try:
        raw = field_bytes(value)
    except EncodingError as exc:
        raise NoteCapsuleError("invalid " + name) from exc
    _need(any(raw), "zero " + name)
    return raw


def _capsule_digest(value: dict) -> str:
    projected = dict(value)
    projected.pop("capsule_id", None)
    return hashlib.sha256(
        _CAPSULE_ID_DOMAIN + canonical_json(projected)
    ).hexdigest()


def capsule_id(value: dict) -> str:
    _need(
        type(value) is dict
        and set(value) in (_CAPSULE_KEYS, _CAPSULE_KEYS - {"capsule_id"}),
        "invalid note capsule identity input",
    )
    return _capsule_digest(value)


def decode_capsule(raw: bytes, genesis_raw: bytes) -> dict:
    try:
        value = decode_canonical_json(raw, max_bytes=MAX_NOTE_CAPSULE_BYTES)
        genesis = genesis_document(genesis_raw)
    except EncodingError as exc:
        raise NoteCapsuleError(str(exc)) from exc
    _need(type(value) is dict and set(value) == _CAPSULE_KEYS,
          "invalid note capsule")
    _need(value["format"] == NOTE_CAPSULE_FORMAT, "wrong note capsule format")
    _need(type(value["version"]) is int and value["version"] == 1,
          "wrong note capsule version")
    _hash_hex(value["capsule_id"], "capsule identity")
    _need(value["capsule_id"] == _capsule_digest(value),
          "note capsule identity differs")
    _hash_hex(value["genesis_sha256"], "genesis identity")
    _hash_hex(value["profile_id"], "profile identity")
    _hash_hex(value["deployment_id"], "deployment identity")
    _need(value["genesis_sha256"] == genesis.sha256.hex(),
          "note capsule genesis differs")
    _need(value["profile_id"] == genesis.profile.identity.hex(),
          "note capsule profile differs")
    _need(value["deployment_id"] == genesis.deployment.identity.hex(),
          "note capsule deployment differs")
    for name in ("commitment", "owner_key", "note_secret", "blinding"):
        _field(value[name], name)
    for name in ("expiry", "value"):
        _need(type(value[name]) is int and 1 <= value[name] <= U64_MAX,
              "invalid note " + name)
    origin = value["origin"]
    _need(type(origin) is dict, "invalid note origin")
    if origin.get("kind") == "genesis":
        _need(set(origin) == {"kind", "position"}
              and type(origin["position"]) is int
              and 0 <= origin["position"] < 16,
              "invalid genesis note origin")
    elif origin.get("kind") == "transaction":
        _need(set(origin) == {"kind", "txid", "output_index"}
              and type(origin["output_index"]) is int
              and origin["output_index"] in (0, 1),
              "invalid transaction note origin")
        _hash_hex(origin["txid"], "origin transaction", nonzero=True)
    else:
        raise NoteCapsuleError("invalid note origin")
    return value


def _controller_commitment(capsule: dict, owner_spend_secret: bytes,
                           controller: Any) -> str:
    try:
        field_hex(owner_spend_secret)
    except EncodingError as exc:
        raise NoteCapsuleError("invalid owner spend secret") from exc
    _need(any(owner_spend_secret), "zero owner spend secret")
    try:
        owner_key = controller.derive_owner_key(owner_spend_secret)
        owner_key_hex = field_hex(owner_key)
    except (EncodingError, OSError, RuntimeError, TypeError, ValueError) as exc:
        raise NoteCapsuleError("owner-key derivation failed") from exc
    _need(any(owner_key) and owner_key_hex == capsule["owner_key"],
          "owner spend secret differs")
    note = SecretNote(
        capsule["expiry"],
        capsule["value"],
        owner_spend_secret,
        bytes.fromhex(capsule["note_secret"]),
        bytes.fromhex(capsule["blinding"]),
    )
    try:
        commitments, _root = controller.commitments([note])
    except (OSError, RuntimeError, TypeError, ValueError) as exc:
        raise NoteCapsuleError("note commitment derivation failed") from exc
    _need(type(commitments) is list and len(commitments) == 1,
          "one-note commitment result differs")
    try:
        computed_raw = _field(
            commitments[0], "one-note commitment result")
        computed = computed_raw.hex()
    except (NoteCapsuleError, TypeError, ValueError) as exc:
        raise NoteCapsuleError("invalid one-note commitment result") from exc
    _need(computed == capsule["commitment"], "note opening differs")
    return computed


def verify_capsule(raw: bytes, owner_spend_secret: bytes,
                   authenticated_state: dict, controller: Any) -> dict:
    """Check a capsule against a previously authenticated state witness.

    authenticated_state must be the state_witness member returned by
    authenticate_observation. This function checks no signed header and never
    upgrades an arbitrary dictionary into authenticated state.
    """
    _need(type(authenticated_state) is dict
          and set(authenticated_state) == {
              "genesis", "height", "app_hash", "state"},
          "invalid authenticated Protocol 5 state")
    try:
        genesis_raw = canonical_json(authenticated_state["genesis"])
    except EncodingError as exc:
        raise NoteCapsuleError("invalid authenticated Protocol 5 genesis") from exc
    capsule = decode_capsule(raw, genesis_raw)
    controller_prefix = getattr(controller, "prefix", None)
    genesis_value = authenticated_state["genesis"]
    domain_names = (
        "genesis_field", "asset_field", "context_field",
        "authority_epoch", "policy_field",
    )
    _need(
        type(controller_prefix) is dict
        and all(
            controller_prefix.get(name) == genesis_value.get(name)
            for name in domain_names
        ),
        "controller note domain differs",
    )
    _controller_commitment(capsule, owner_spend_secret, controller)
    state = authenticated_state["state"]
    _need(type(state) is dict, "invalid authenticated Protocol 5 state")
    _need(state.get("profile_id") == capsule["profile_id"]
          and state.get("deployment_id") == capsule["deployment_id"],
          "authenticated state identity differs")
    commitments = state.get("commitments")
    receipts = state.get("receipts")
    _need(type(commitments) is list and type(receipts) is list,
          "authenticated state note indexes missing")
    origin = capsule["origin"]
    if origin["kind"] == "genesis":
        position = origin["position"]
        genesis_commitments = authenticated_state["genesis"][
            "initial_commitments"]
        _need(position < len(genesis_commitments)
              and position < len(commitments)
              and genesis_commitments[position] == capsule["commitment"]
              and commitments[position] == capsule["commitment"],
              "genesis note origin differs")
    else:
        matches = [
            receipt for receipt in receipts
            if type(receipt) is dict and receipt.get("txid") == origin["txid"]
        ]
        _need(len(matches) == 1, "origin transaction receipt is not unique")
        receipt = matches[0]
        required = {
            "txid", "profile_id", "deployment_id", "height", "tx_index",
            "anchor_root", "tree_root_before", "tree_root_after", "nullifier",
            "output_commitment_0", "output_commitment_1",
            "output_position_0", "output_position_1", "fee",
        }
        _need(set(receipt) == required, "invalid origin transaction receipt")
        index = origin["output_index"]
        commitment_name = f"output_commitment_{index}"
        position_name = f"output_position_{index}"
        position = receipt[position_name]
        height = receipt["height"]
        tx_index = receipt["tx_index"]
        _need(
            receipt["profile_id"] == capsule["profile_id"]
            and receipt["deployment_id"] == capsule["deployment_id"]
            and receipt[commitment_name] == capsule["commitment"]
            and type(position) is int
            and 0 <= position < len(commitments)
            and commitments[position] == capsule["commitment"]
            and type(height) is int
            and 1 <= height <= authenticated_state["height"]
            and type(tx_index) is int
            and tx_index >= 0
            and type(receipt["output_position_0"]) is int
            and type(receipt["output_position_1"]) is int
            and receipt["output_position_0"] >= len(
                authenticated_state["genesis"]["initial_commitments"])
            and receipt["output_position_1"]
                == receipt["output_position_0"] + 1
            and receipt["output_position_1"] < 16,
            "transaction note origin differs",
        )
        blocks = state.get("execution_blocks")
        _need(type(blocks) is list and height <= len(blocks),
              "origin execution block missing")
        block = blocks[height - 1]
        _need(type(block) is dict
              and set(block) == {"height", "transactions", "results"}
              and block["height"] == height
              and type(block["transactions"]) is list
              and type(block["results"]) is list
              and len(block["transactions"]) == len(block["results"])
              and tx_index < len(block["transactions"]),
              "invalid origin execution block")
        encoded = block["transactions"][tx_index]
        _need(type(encoded) is str, "invalid retained origin transaction")
        try:
            transaction_raw = base64.b64decode(encoded, validate=True)
        except (ValueError, binascii.Error) as exc:
            raise NoteCapsuleError(
                "invalid retained origin transaction") from exc
        _need(base64.b64encode(transaction_raw).decode("ascii") == encoded,
              "noncanonical retained origin transaction")
        expected_result = {
            "code": 0, "log": "", "data": origin["txid"]}
        _need(block["results"][tx_index] == expected_result,
              "origin transaction was not successful")
        _need(transaction_id(transaction_raw).hex() == origin["txid"],
              "retained origin transaction identity differs")
        try:
            transaction = Transaction.decode(
                transaction_raw, genesis_document(genesis_raw))
        except (EncodingError, ValueError, TypeError) as exc:
            raise NoteCapsuleError(
                "invalid retained origin transaction") from exc
        fields = transaction.public_fields
        _need(
            fields[8].hex() == receipt["anchor_root"]
            and fields[9].hex() == receipt["nullifier"]
            and fields[10].hex() == receipt["output_commitment_0"]
            and fields[11].hex() == receipt["output_commitment_1"]
            and int.from_bytes(fields[12], "little") == receipt["fee"],
            "origin receipt and transaction differ",
        )
    return capsule
