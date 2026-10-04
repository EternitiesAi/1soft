"""Authenticated Protocol 5 H+1 state observations and bounded loopback reading."""
from __future__ import annotations

import base64
import binascii
import json
from typing import Any
import urllib.error
import urllib.parse
import urllib.request


from protocol5_certificate import (
    trust_from_protocol5_genesis,
    verify_protocol5_state_certificate,
)
from protocol5_encoding import canonical_json, decode_canonical_json

STATE_OBSERVATION_FORMAT = "1soft/protocol5-state-observation/v1"
MAX_STATE_OBSERVATION_BYTES = 8_388_608
MAX_RPC_RESPONSE_BYTES = 12_582_912
MAX_COMMIT_RESPONSE_BYTES = 262_144


class StateObservationError(ValueError):
    pass


def _need(condition: bool, message: str) -> None:
    if not condition:
        raise StateObservationError(message)


def authenticate_observation(
    raw: bytes,
    engine_genesis: dict,
    app_genesis: bytes,
) -> tuple[dict, dict]:
    observation = decode_canonical_json(
        raw, max_bytes=MAX_STATE_OBSERVATION_BYTES)
    _need(
        type(observation) is dict
        and set(observation) == {
            "format", "state_witness", "signed_header"},
        "invalid Protocol 5 state observation",
    )
    _need(observation["format"] == STATE_OBSERVATION_FORMAT,
          "wrong Protocol 5 state observation format")
    trust = trust_from_protocol5_genesis(engine_genesis, app_genesis)
    certificate = verify_protocol5_state_certificate(
        observation["state_witness"], observation["signed_header"], trust)
    return observation, certificate


def _observation_parts(value: Any) -> tuple[dict, dict, int]:
    _need(
        type(value) is dict
        and set(value) == {"format", "state_witness", "signed_header"}
        and value["format"] == STATE_OBSERVATION_FORMAT,
        "invalid Protocol 5 state observation",
    )
    witness = value["state_witness"]
    _need(
        type(witness) is dict
        and set(witness) == {"genesis", "height", "app_hash", "state"}
        and type(witness["height"]) is int
        and witness["height"] >= 0
        and type(witness["state"]) is dict,
        "invalid Protocol 5 state witness",
    )
    return witness, witness["state"], witness["height"]


def extends_observation(old: dict, new: dict) -> None:
    old_witness, old_state, old_height = _observation_parts(old)
    new_witness, new_state, new_height = _observation_parts(new)
    if new_height == old_height:
        _need(canonical_json(new) == canonical_json(old),
              "same-height Protocol 5 observation differs")
        return
    _need(new_height > old_height, "Protocol 5 observation rolls back")
    _need(
        canonical_json(new_witness["genesis"])
            == canonical_json(old_witness["genesis"]),
        "Protocol 5 observation genesis differs",
    )
    for name in ("version", "profile_id", "deployment_id"):
        _need(
            name in old_state
            and name in new_state
            and old_state[name] == new_state[name],
            "Protocol 5 state identity differs",
        )
    for name in (
        "commitments", "root_history", "receipts", "execution_blocks"):
        old_rows = old_state.get(name)
        new_rows = new_state.get(name)
        _need(
            type(old_rows) is list
            and type(new_rows) is list
            and len(new_rows) >= len(old_rows)
            and new_rows[:len(old_rows)] == old_rows,
            "Protocol 5 " + name + " does not extend",
        )
    old_nullifiers = old_state.get("spent_nullifiers")
    new_nullifiers = new_state.get("spent_nullifiers")
    _need(
        type(old_nullifiers) is list
        and type(new_nullifiers) is list
        and len(old_nullifiers) == len(set(old_nullifiers))
        and len(new_nullifiers) == len(set(new_nullifiers))
        and set(old_nullifiers) <= set(new_nullifiers),
        "Protocol 5 spent nullifiers do not extend",
    )


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, request, file_pointer, code, message, headers,
                         new_url):
        return None


def _loopback_endpoint(endpoint: str) -> str:
    _need(type(endpoint) is str, "invalid Protocol 5 RPC endpoint")
    try:
        parsed = urllib.parse.urlsplit(endpoint)
        port = parsed.port
    except ValueError as exc:
        raise StateObservationError("invalid Protocol 5 RPC endpoint") from exc
    _need(
        parsed.scheme == "http"
        and parsed.hostname == "127.0.0.1"
        and port is not None
        and 1 <= port <= 65535
        and parsed.netloc == f"127.0.0.1:{port}"
        and parsed.path == "/"
        and parsed.query == ""
        and parsed.fragment == ""
        and parsed.username is None
        and parsed.password is None,
        "Protocol 5 RPC endpoint must be exact IPv4 loopback",
    )
    return endpoint


def _bounded_get(url: str, limit: int, timeout: float,
                 opener: Any) -> bytes:
    request = urllib.request.Request(
        url,
        method="GET",
        headers={
            "Accept": "application/json",
            "Accept-Encoding": "identity",
            "Connection": "close",
        },
    )
    try:
        with opener.open(request, timeout=timeout) as response:
            _need(response.getcode() == 200, "Protocol 5 RPC status differs")
            encoding = response.headers.get("Content-Encoding")
            _need(
                encoding is None or encoding.strip().lower() == "identity",
                "compressed Protocol 5 RPC response refused",
            )
            media_type = response.headers.get("Content-Type", "")
            _need(
                media_type.split(";", 1)[0].strip().lower()
                    == "application/json",
                "Protocol 5 RPC content type differs",
            )
            declared = response.headers.get("Content-Length")
            if declared is not None:
                _need(
                    declared.isascii()
                    and declared.isdecimal()
                    and (declared == "0" or not declared.startswith("0"))
                    and int(declared) <= limit,
                    "Protocol 5 RPC response bound exceeded",
                )
            raw = response.read(limit + 1)
            _need(len(raw) <= limit,
                  "Protocol 5 RPC response bound exceeded")
            if declared is not None:
                _need(len(raw) == int(declared),
                      "truncated Protocol 5 RPC response")
            return raw
    except StateObservationError:
        raise
    except (OSError, TimeoutError, urllib.error.URLError) as exc:
        close = getattr(exc, "close", None)
        if close is not None:
            close()
        raise StateObservationError("Protocol 5 RPC unavailable") from exc


def _json_pairs(items):
    result = {}
    for key, value in items:
        _need(key not in result, "duplicate Protocol 5 RPC JSON member")
        result[key] = value
    return result


def _no_json_number(value: str):
    raise StateObservationError("non-integer Protocol 5 RPC JSON number")


def _rpc_json(raw: bytes) -> dict:
    try:
        value = json.loads(
            raw.decode("utf-8"),
            object_pairs_hook=_json_pairs,
            parse_float=_no_json_number,
            parse_constant=_no_json_number,
        )
    except StateObservationError:
        raise
    except (UnicodeError, json.JSONDecodeError) as exc:
        raise StateObservationError("invalid Protocol 5 RPC JSON") from exc
    _need(type(value) is dict and type(value.get("result")) is dict
          and "error" not in value, "Protocol 5 RPC result missing")
    return value["result"]


def _canonical_base64(value: Any, *, limit: int) -> bytes:
    _need(type(value) is str, "invalid Protocol 5 RPC base64")
    try:
        raw = base64.b64decode(value, validate=True)
    except (ValueError, binascii.Error) as exc:
        raise StateObservationError("invalid Protocol 5 RPC base64") from exc
    _need(len(raw) <= limit
          and base64.b64encode(raw).decode("ascii") == value,
          "noncanonical Protocol 5 RPC base64")
    return raw


def read_state_observation(
    endpoint: str,
    engine_genesis: dict,
    app_genesis: bytes,
    *,
    timeout: float = 15.0,
) -> bytes:
    """Read and authenticate one complete state from exact IPv4 loopback."""
    base = _loopback_endpoint(endpoint)
    _need(type(timeout) in (int, float)
          and not isinstance(timeout, bool)
          and 0 < timeout <= 30,
          "invalid Protocol 5 RPC timeout")
    opener = urllib.request.build_opener(
        urllib.request.ProxyHandler({}),
        _NoRedirect(),
        urllib.request.HTTPHandler(),
    )
    query_raw = _bounded_get(
        base + "abci_query?path=%22%2Fstate%22&prove=false",
        MAX_RPC_RESPONSE_BYTES,
        float(timeout),
        opener,
    )
    query = _rpc_json(query_raw)
    response = query.get("response")
    code = response.get("code") if type(response) is dict else None
    _need(
        type(response) is dict
        and ((type(code) is int and code == 0) or code == "0")
        and "proofOps" in response
        and response["proofOps"] is None,
        "Protocol 5 state query was not an unproved success",
    )
    witness_raw = _canonical_base64(
        response.get("value"), limit=MAX_STATE_OBSERVATION_BYTES)
    try:
        witness = decode_canonical_json(
            witness_raw, max_bytes=MAX_STATE_OBSERVATION_BYTES)
    except ValueError as exc:
        raise StateObservationError(
            "invalid Protocol 5 state witness response") from exc
    _need(type(witness) is dict and type(witness.get("height")) is int,
          "invalid Protocol 5 state witness response")
    height_text = response.get("height")
    _need(
        type(height_text) is str
        and height_text.isascii()
        and height_text.isdecimal()
        and (height_text == "0" or not height_text.startswith("0"))
        and int(height_text) == witness["height"],
        "Protocol 5 query height differs",
    )
    commit_raw = _bounded_get(
        base + "commit?height=" + str(witness["height"] + 1),
        MAX_COMMIT_RESPONSE_BYTES,
        float(timeout),
        opener,
    )
    commit = _rpc_json(commit_raw)
    signed_header = commit.get("signed_header")
    _need(type(signed_header) is dict,
          "Protocol 5 signed header response missing")
    raw = canonical_json({
        "format": STATE_OBSERVATION_FORMAT,
        "state_witness": witness,
        "signed_header": signed_header,
    })
    _need(len(raw) <= MAX_STATE_OBSERVATION_BYTES,
          "Protocol 5 state observation bound exceeded")
    authenticate_observation(raw, engine_genesis, app_genesis)
    return raw
