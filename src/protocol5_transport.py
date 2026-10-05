"""Hardened one-shot loopback transport for Protocol 5 transactions.

This module has no key, wallet, signing, DNS, proxy, redirect, TLS, or retry
capability.  A successful RPC response is only an endpoint admission observation;
it is not evidence that a transaction was committed or settled.
"""
from __future__ import annotations

import base64
import hashlib
import json
import re
import socket
import time


MAX_TRANSACTION_BYTES = 64 * 1024
MAX_RESPONSE_BYTES = 64 * 1024
MAX_HEADER_BYTES = 16 * 1024
TIMEOUT_SECONDS = 15.0
UNRESOLVED_REASON = "transport or response validation failed"
_ENDPOINT = re.compile(r"http://127\.0\.0\.1:([1-9][0-9]{0,4})/\Z")
_HEX_BYTES = re.compile(r"(?:[0-9A-Fa-f]{2})*\Z")
_LOWER_SHA256 = re.compile(r"[0-9a-f]{64}\Z")
_UPPER_SHA256 = re.compile(r"[0-9A-F]{64}\Z")
_RESULT_FIELDS = {"code", "data", "log", "codespace", "hash"}
_FAILURE = {"observation": "unresolved", "reason": UNRESOLVED_REASON}


def _endpoint_port(endpoint: str) -> int:
    match = _ENDPOINT.fullmatch(endpoint) if type(endpoint) is str else None
    if match is None:
        raise ValueError("only an exact literal loopback HTTP endpoint is allowed")
    port = int(match[1])
    if not 1 <= port <= 65535:
        raise ValueError("invalid loopback endpoint port")
    return port


def _strict_json(raw: bytes):
    def pairs(items):
        value = {}
        for key, item in items:
            if key in value:
                raise ValueError("duplicate JSON field")
            value[key] = item
        return value

    def non_integer(_value):
        raise ValueError("non-integer JSON number")

    return json.loads(
        raw,
        object_pairs_hook=pairs,
        parse_float=non_integer,
        parse_constant=non_integer,
    )


def _canonical_request(transaction: bytes, request_id: int) -> bytes:
    return json.dumps(
        {
            "jsonrpc": "2.0",
            "id": request_id,
            "method": "broadcast_tx_sync",
            "params": {"tx": base64.b64encode(transaction).decode("ascii")},
        },
        separators=(",", ":"),
    ).encode("ascii")


def _remaining(deadline: float) -> float:
    remaining = deadline - time.monotonic()
    if remaining <= 0:
        raise TimeoutError("Protocol 5 transport deadline exceeded")
    return remaining


def _request_bytes(port: int, body: bytes) -> bytes:
    headers = (
        f"POST / HTTP/1.1\r\n"
        f"Host: 127.0.0.1:{port}\r\n"
        "Content-Type: application/json\r\n"
        "Accept: application/json\r\n"
        "Connection: close\r\n"
        f"Content-Length: {len(body)}\r\n"
        "\r\n"
    ).encode("ascii")
    return headers + body


def _response_body(connection: socket.socket, deadline: float) -> bytes:
    received = bytearray()
    marker = b"\r\n\r\n"
    while marker not in received:
        if len(received) > MAX_HEADER_BYTES:
            raise ValueError("response headers exceed the bound")
        connection.settimeout(_remaining(deadline))
        chunk = connection.recv(4096)
        if not chunk:
            raise ValueError("truncated response headers")
        received.extend(chunk)
    header_raw, body = bytes(received).split(marker, 1)
    if len(header_raw) > MAX_HEADER_BYTES:
        raise ValueError("response headers exceed the bound")
    lines = header_raw.split(b"\r\n")
    if not lines or re.fullmatch(
            rb"HTTP/1\.1 200(?: [\x20-\x7e]*)?", lines[0]) is None:
        raise ValueError("invalid HTTP response status or version")

    counts: dict[str, int] = {}
    values: dict[str, str] = {}
    for line in lines[1:]:
        if (line.startswith((b" ", b"\t")) or b":" not in line):
            raise ValueError("invalid HTTP response header")
        name, raw_value = line.split(b":", 1)
        if (re.fullmatch(rb"[!#$%&'*+\-.^_`|~0-9A-Za-z]+", name)
                is None
                or any(value != 9 and not 32 <= value <= 126
                       for value in raw_value)):
            raise ValueError("invalid HTTP response header")
        key = name.decode("ascii").lower()
        counts[key] = counts.get(key, 0) + 1
        if counts[key] != 1:
            raise ValueError("duplicate HTTP response header")
        values[key] = raw_value.decode("ascii").strip()

    if set(("content-type", "content-length")) - values.keys():
        raise ValueError("missing response framing header")
    if "transfer-encoding" in values:
        raise ValueError("transfer encoding is forbidden")
    if "content-encoding" in values:
        raise ValueError("content encoding is forbidden")
    if values["content-type"].strip().lower() != "application/json":
        raise ValueError("invalid response content type")

    length_text = values["content-length"]
    if re.fullmatch(r"0|[1-9][0-9]*", length_text) is None:
        raise ValueError("noncanonical response length")
    length = int(length_text)
    if not 1 <= length <= MAX_RESPONSE_BYTES:
        raise ValueError("response length is outside the bound")
    if len(header_raw) + len(marker) + length > MAX_RESPONSE_BYTES:
        raise ValueError("complete response exceeds the bound")

    if len(body) > length:
        raise ValueError("response framing mismatch")
    while len(body) < length:
        connection.settimeout(_remaining(deadline))
        chunk = connection.recv(min(4096, length - len(body)))
        if not chunk:
            raise ValueError("truncated response body")
        body += chunk
    if len(body) != length:
        raise ValueError("response framing mismatch")
    return body


def _observation(raw_response: bytes, transaction: bytes, request_id: int) -> dict:
    envelope = _strict_json(raw_response)
    if (
        type(envelope) is not dict
        or set(envelope) != {"jsonrpc", "id", "result"}
        or envelope["jsonrpc"] != "2.0"
        or type(envelope["id"]) is not int
        or envelope["id"] != request_id
        or type(envelope["result"]) is not dict
        or set(envelope["result"]) != _RESULT_FIELDS
    ):
        raise ValueError("invalid JSON-RPC response envelope")

    result = envelope["result"]
    code = result["code"]
    if type(code) is not int or not 0 <= code <= 2**32 - 1:
        raise ValueError("invalid CheckTx code")
    if not all(type(result[field]) is str for field in ("data", "log", "codespace", "hash")):
        raise ValueError("invalid CheckTx field type")
    if _HEX_BYTES.fullmatch(result["data"]) is None:
        raise ValueError("invalid CheckTx data encoding")

    expected_hash = hashlib.sha256(transaction).hexdigest()
    returned_hash = result["hash"]
    canonical_hash = (
        _LOWER_SHA256.fullmatch(returned_hash) is not None
        or _UPPER_SHA256.fullmatch(returned_hash) is not None
    )
    if not canonical_hash or returned_hash.lower() != expected_hash:
        raise ValueError("response hash does not identify the transaction")

    return {
        "observation": "endpoint_admitted" if code == 0 else "endpoint_declined",
        "check_tx_code": code,
        "response_sha256": hashlib.sha256(raw_response).hexdigest(),
    }


def submit_once(endpoint: str, transaction: bytes, request_id: int) -> dict:
    """Submit exactly once to a literal loopback CometBFT endpoint.

    Invalid caller inputs raise ``ValueError`` without opening a connection.
    Every network or peer-response failure returns one fixed, non-secret result.
    """
    port = _endpoint_port(endpoint)
    if type(transaction) is not bytes or not 1 <= len(transaction) <= MAX_TRANSACTION_BYTES:
        raise ValueError("invalid transaction size")
    if type(request_id) is not int or not 1 <= request_id <= 2**31 - 1:
        raise ValueError("invalid request ID")

    request_body = _canonical_request(transaction, request_id)
    deadline = time.monotonic() + TIMEOUT_SECONDS
    connection = None
    try:
        connection = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        connection.settimeout(_remaining(deadline))
        connection.connect(("127.0.0.1", port))
        connection.settimeout(_remaining(deadline))
        connection.sendall(_request_bytes(port, request_body))
        raw_response = _response_body(connection, deadline)
        return _observation(raw_response, transaction, request_id)
    except (
        OSError,
        ValueError,
        TypeError,
        KeyError,
        RecursionError,
        UnicodeError,
    ):
        return dict(_FAILURE)
    finally:
        if connection is not None:
            connection.close()
