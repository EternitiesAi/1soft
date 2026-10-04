"""Static four-validator certificate verification for Protocol 5."""
from __future__ import annotations

import base64
import binascii
import hashlib
from typing import Any

from commit_verifier import (
    TrustAnchor, Validator, VerificationError, merkle_root,
    verify_signed_header,
)
from protocol5_encoding import canonical_json, genesis_document
from protocol5_state import application_hash


def _need(condition: bool, message: str) -> None:
    if not condition:
        raise VerificationError(message)


def _power(value: Any) -> int:
    if type(value) is int:
        power = value
    elif type(value) is str and value and value.isascii() and value.isdecimal()             and (value == "0" or not value.startswith("0")):
        power = int(value)
    else:
        raise VerificationError("invalid Protocol 5 validator power")
    _need(1 <= power <= 1_000_000, "invalid Protocol 5 validator power")
    return power


def trust_from_protocol5_genesis(engine_genesis: dict,
                                 expected_app_genesis: bytes) -> TrustAnchor:
    _need(type(engine_genesis) is dict, "invalid Protocol 5 engine genesis")
    genesis = genesis_document(expected_app_genesis)
    _need(engine_genesis.get("chain_id") == genesis.value["chain_id"],
          "Protocol 5 engine chain differs")
    initial_height = engine_genesis.get("initial_height", "1")
    _need(initial_height in (1, "1"), "Protocol 5 initial height differs")
    app_state = engine_genesis.get("app_state")
    _need(type(app_state) is dict and canonical_json(app_state) == expected_app_genesis,
          "Protocol 5 engine application genesis differs")
    rows = engine_genesis.get("validators")
    _need(type(rows) is list and len(rows) == 4,
          "Protocol 5 requires four engine validators")
    validators = []
    seen = set()
    for row in rows:
        _need(type(row) is dict, "invalid Protocol 5 engine validator")
        public = row.get("pub_key")
        _need(type(public) is dict and set(public) == {"type", "value"}
              and public["type"] == "tendermint/PubKeyEd25519",
              "unsupported Protocol 5 validator key")
        try:
            key = base64.b64decode(public["value"], validate=True)
        except (TypeError, ValueError, binascii.Error) as exc:
            raise VerificationError("invalid Protocol 5 validator key") from exc
        _need(len(key) == 32
              and base64.b64encode(key).decode("ascii") == public["value"],
              "noncanonical Protocol 5 validator key")
        address = hashlib.sha256(key).digest()[:20]
        address_text = row.get("address")
        _need(type(address_text) is str and len(address_text) == 40
              and bytes.fromhex(address_text) == address,
              "Protocol 5 validator address differs")
        _need(address not in seen, "duplicate Protocol 5 validator")
        seen.add(address)
        validators.append(Validator(address, key, _power(row.get("power"))))
    wanted = {
        bytes.fromhex(row["public_key"]): row["power"]
        for row in genesis.value["validators"]
    }
    _need({item.public_key: item.power for item in validators} == wanted,
          "engine validators differ from Protocol 5 genesis")
    validators.sort(key=lambda item: (-item.power, item.address))
    total = sum(item.power for item in validators)
    _need(total <= genesis.value["limits"]["max_total_voting_power"],
          "Protocol 5 voting power exceeds genesis bound")
    frozen = tuple(validators)
    validator_hash = merkle_root([item.encoded() for item in frozen])
    return TrustAnchor(
        genesis.value["chain_id"], frozen, validator_hash,
        genesis.sha256.hex(), total,
    )


def verify_protocol5_state_certificate(value: dict, signed_header: dict,
                                       trust: TrustAnchor) -> dict:
    _need(type(value) is dict
          and set(value) == {"genesis", "height", "app_hash", "state"},
          "invalid Protocol 5 state witness")
    raw_genesis = canonical_json(value["genesis"])
    genesis = genesis_document(raw_genesis)
    _need(genesis.sha256.hex() == trust.native_genesis_hash
          and genesis.value["chain_id"] == trust.chain_id,
          "Protocol 5 state genesis differs from trust anchor")
    height = value["height"]
    _need(type(height) is int
          and 0 <= height <= genesis.value["limits"]["max_height"],
          "invalid Protocol 5 state height")
    computed = application_hash(genesis, height, value["state"])
    _need(value["app_hash"] == computed, "Protocol 5 state AppHash differs")
    certificate = verify_signed_header(
        signed_header, trust, expected_height=height + 1)
    _need(certificate["app_hash"] == computed,
          "Protocol 5 state is not bound by signed next header")
    return {
        **certificate,
        "state_height": height,
        "header_height": certificate["height"],
        "app_hash": computed,
        "genesis_sha256": genesis.sha256.hex(),
        "profile_id": genesis.profile.identity.hex(),
        "deployment_id": genesis.deployment.identity.hex(),
        "claim": "Protocol 5 AppHash authenticated by signed next-height header",
    }
