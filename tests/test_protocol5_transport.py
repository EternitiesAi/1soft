"""Adversarial tests for the one-shot key-free Protocol 5 transport."""
from __future__ import annotations

import base64
from contextlib import contextmanager
import hashlib
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
import os
import socket
import threading
import time
import unittest
from unittest.mock import patch

import protocol5_transport as transport


TX = b"protocol-5-transaction"
FIXED_FAILURE = {
    "observation": "unresolved",
    "reason": "transport or response validation failed",
}


class _CountingServer(ThreadingHTTPServer):
    daemon_threads = True
    block_on_close = False

    def __init__(self, address, handler):
        super().__init__(address, handler)
        self.connection_count = 0

    def get_request(self):
        request = super().get_request()
        self.connection_count += 1
        return request


@contextmanager
def rpc_endpoint(mode: str = "admit", *, code: int = 0, hash_case: str = "upper"):
    seen: list[dict] = []

    class Handler(BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.1"

        def log_message(self, *_args):
            pass

        def do_POST(self):
            length = int(self.headers.get("Content-Length", "0"))
            body = self.rfile.read(length)
            seen.append({
                "method": self.command,
                "path": self.path,
                "headers": list(self.headers.items()),
                "body": body,
            })

            if mode == "drop":
                try:
                    self.connection.shutdown(socket.SHUT_RDWR)
                except OSError:
                    pass
                self.connection.close()
                return
            if mode == "stall":
                time.sleep(0.25)
                return
            if mode == "redirect":
                self.send_response(302)
                self.send_header("Location", "http://example.invalid/never")
                self.send_header("Content-Length", "0")
                self.end_headers()
                return

            try:
                request = json.loads(body)
                request_id = request["id"]
                raw_tx = base64.b64decode(request["params"]["tx"], validate=True)
            except Exception:
                request_id = 1
                raw_tx = TX

            digest = hashlib.sha256(raw_tx).hexdigest()
            if hash_case == "upper":
                digest = digest.upper()
            result = {
                "jsonrpc": "2.0",
                "id": request_id,
                "result": {
                    "code": code,
                    "data": "",
                    "log": "untrusted endpoint log must never escape",
                    "codespace": "",
                    "hash": digest,
                },
            }

            if mode == "wrong_id":
                result["id"] = request_id + 1
            elif mode == "boolean_id":
                result["id"] = True
            elif mode == "wrong_hash":
                result["result"]["hash"] = "0" * 64
            elif mode == "mixed_hash":
                mixed = list(digest.upper())
                letter_index = next(i for i, value in enumerate(mixed) if value in "ABCDEF")
                mixed[letter_index] = mixed[letter_index].lower()
                result["result"]["hash"] = "".join(mixed)
            elif mode == "boolean_code":
                result["result"]["code"] = False
            elif mode == "extra_envelope":
                result["extra"] = 1
            elif mode == "extra_result":
                result["result"]["extra"] = 1
            elif mode == "missing_result_field":
                del result["result"]["data"]
            elif mode == "combined_overbound":
                result["result"]["log"] = "x" * 51_000

            data = json.dumps(result, separators=(",", ":")).encode("utf-8")
            if mode == "duplicate_json":
                data = (
                    b'{"jsonrpc":"2.0","id":'
                    + str(request_id).encode("ascii")
                    + b',"id":'
                    + str(request_id).encode("ascii")
                    + b',"result":'
                    b'{"code":0,"data":"","log":"","codespace":"","hash":"'
                    + hashlib.sha256(raw_tx).hexdigest().encode("ascii")
                    + b'"}}'
                )
            elif mode == "malformed_json":
                data = b'{"secret":"raw-body-must-not-escape"'
            elif mode == "non_integer_json":
                data = (
                    b'{"jsonrpc":"2.0","id":'
                    + str(request_id).encode("ascii")
                    + b',"result":{"code":0.0,"data":"","log":"",'
                    b'"codespace":"","hash":"'
                    + hashlib.sha256(raw_tx).hexdigest().encode("ascii")
                    + b'"}}'
                )
            elif mode == "overbound":
                data = b"{" + b"x" * transport.MAX_RESPONSE_BYTES

            status = 503 if mode == "non_200" else 200
            self.send_response(status)
            content_type = "text/plain" if mode == "wrong_content_type" else "application/json"
            self.send_header("Content-Type", content_type)
            if mode == "combined_overbound":
                self.send_header("X-Padding", "x" * 15_500)

            if mode == "missing_length":
                self.send_header("Connection", "close")
            elif mode == "leading_zero_length":
                self.send_header("Content-Length", "0" + str(len(data)))
            elif mode == "oversized_length":
                self.send_header("Content-Length", str(transport.MAX_RESPONSE_BYTES + 1))
            elif mode == "truncated":
                self.send_header("Content-Length", str(len(data) + 7))
                self.send_header("Connection", "close")
            else:
                self.send_header("Content-Length", str(len(data)))

            if mode == "duplicate_content_type":
                self.send_header("Content-Type", "application/json")
            elif mode == "duplicate_length":
                self.send_header("Content-Length", str(len(data)))
            elif mode == "transfer_encoding":
                self.send_header("Transfer-Encoding", "chunked")
            elif mode == "content_encoding":
                self.send_header("Content-Encoding", "gzip")

            self.end_headers()
            if mode == "drip":
                try:
                    for value in data:
                        self.wfile.write(bytes((value,)))
                        self.wfile.flush()
                        time.sleep(0.03)
                except OSError:
                    pass
            elif mode not in {"oversized_length"}:
                try:
                    self.wfile.write(data)
                    self.wfile.flush()
                except OSError:
                    pass
            if mode in {"truncated", "missing_length"}:
                self.close_connection = True

    server = _CountingServer(("127.0.0.1", 0), Handler)
    thread = threading.Thread(
        target=lambda: server.serve_forever(poll_interval=0.01), daemon=True
    )
    thread.start()
    try:
        yield f"http://127.0.0.1:{server.server_port}/", seen, server
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=2)


class Protocol5TransportTests(unittest.TestCase):
    def test_exact_request_one_connection_and_sanitized_admission(self):
        request_id = 37
        for hash_case in ("upper", "lower"):
            with self.subTest(hash_case=hash_case):
                with rpc_endpoint(hash_case=hash_case) as (endpoint, seen, server):
                    result = transport.submit_once(endpoint, TX, request_id)
                self.assertEqual(server.connection_count, 1)
                self.assertEqual(len(seen), 1)
                expected = json.dumps(
                    {
                        "jsonrpc": "2.0",
                        "id": request_id,
                        "method": "broadcast_tx_sync",
                        "params": {"tx": base64.b64encode(TX).decode("ascii")},
                    },
                    separators=(",", ":"),
                ).encode("ascii")
                self.assertEqual(seen[0]["method"], "POST")
                self.assertEqual(seen[0]["path"], "/")
                self.assertEqual(seen[0]["body"], expected)
                request_headers = {key.lower(): value for key, value in seen[0]["headers"]}
                self.assertEqual(request_headers["content-type"], "application/json")
                self.assertEqual(request_headers["content-length"], str(len(expected)))
                self.assertEqual(
                    result,
                    {
                        "observation": "endpoint_admitted",
                        "check_tx_code": 0,
                        "response_sha256": result["response_sha256"],
                    },
                )
                self.assertRegex(result["response_sha256"], r"^[0-9a-f]{64}$")
                self.assertNotIn("untrusted endpoint log", repr(result))

    def test_nonzero_code_is_sanitized_decline(self):
        with rpc_endpoint(code=17) as (endpoint, seen, server):
            result = transport.submit_once(endpoint, TX, 2)
        self.assertEqual(server.connection_count, 1)
        self.assertEqual(len(seen), 1)
        self.assertEqual(result["observation"], "endpoint_declined")
        self.assertEqual(result["check_tx_code"], 17)
        self.assertEqual(set(result), {"observation", "check_tx_code", "response_sha256"})

    def test_only_exact_literal_loopback_endpoint_is_accepted_without_io(self):
        invalid = [
            "https://127.0.0.1:26657/",
            "http://localhost:26657/",
            "http://127.0.0.2:26657/",
            "http://2130706433:26657/",
            "http://[::1]:26657/",
            "http://user@127.0.0.1:26657/",
            "http://127.0.0.1:26657",
            "http://127.0.0.1:26657/rpc",
            "http://127.0.0.1:26657/?x=1",
            "http://127.0.0.1:26657/#fragment",
            "HTTP://127.0.0.1:26657/",
            "http://127.0.0.1:026657/",
            "http://127.0.0.1:0/",
            "http://127.0.0.1:65536/",
        ]
        with patch.object(transport.socket, "socket") as connection:
            for endpoint in invalid:
                with self.subTest(endpoint=endpoint):
                    with self.assertRaises(ValueError):
                        transport.submit_once(endpoint, TX, 1)
            connection.assert_not_called()

    def test_input_bounds_are_enforced_before_io(self):
        endpoint = "http://127.0.0.1:26657/"
        invalid = [
            (b"", 1),
            (b"x" * (transport.MAX_TRANSACTION_BYTES + 1), 1),
            (bytearray(b"x"), 1),
            (b"x", True),
            (b"x", 0),
            (b"x", 2**31),
        ]
        with patch.object(transport.socket, "socket") as connection:
            for transaction, request_id in invalid:
                with self.subTest(size=len(transaction), request_id=request_id):
                    with self.assertRaises(ValueError):
                        transport.submit_once(endpoint, transaction, request_id)
            connection.assert_not_called()

        with rpc_endpoint() as (live_endpoint, seen, server):
            result = transport.submit_once(
                live_endpoint, b"x" * transport.MAX_TRANSACTION_BYTES, 2**31 - 1
            )
        self.assertEqual(result["observation"], "endpoint_admitted")
        self.assertEqual(server.connection_count, 1)
        self.assertEqual(len(seen), 1)

    def test_proxy_environment_is_ignored_and_redirect_is_not_followed(self):
        with rpc_endpoint() as (proxy_endpoint, proxy_seen, proxy_server):
            with rpc_endpoint() as (target_endpoint, target_seen, target_server):
                with patch.dict(
                    os.environ,
                    {"HTTP_PROXY": proxy_endpoint, "HTTPS_PROXY": proxy_endpoint},
                    clear=False,
                ):
                    result = transport.submit_once(target_endpoint, TX, 3)
            self.assertEqual(result["observation"], "endpoint_admitted")
            self.assertEqual(target_server.connection_count, 1)
            self.assertEqual(len(target_seen), 1)
            self.assertEqual(proxy_server.connection_count, 0)
            self.assertEqual(proxy_seen, [])

        with rpc_endpoint("redirect") as (endpoint, seen, server):
            result = transport.submit_once(endpoint, TX, 4)
        self.assertEqual(result, FIXED_FAILURE)
        self.assertEqual(server.connection_count, 1)
        self.assertEqual(len(seen), 1)

    def test_refusal_drop_and_timeout_each_make_one_attempt(self):
        with patch.object(
                transport.socket, "socket",
                side_effect=ConnectionRefusedError) as connect:
            result = transport.submit_once("http://127.0.0.1:26657/", TX, 5)
        self.assertEqual(result, FIXED_FAILURE)
        self.assertEqual(connect.call_count, 1)

        with rpc_endpoint("drop") as (endpoint, seen, server):
            result = transport.submit_once(endpoint, TX, 6)
        self.assertEqual(result, FIXED_FAILURE)
        self.assertEqual(server.connection_count, 1)
        self.assertEqual(len(seen), 1)

        with patch.object(transport, "TIMEOUT_SECONDS", 0.05):
            with rpc_endpoint("drip") as (endpoint, seen, server):
                result = transport.submit_once(endpoint, TX, 8)
        self.assertEqual(result, FIXED_FAILURE)
        self.assertEqual(server.connection_count, 1)
        self.assertEqual(len(seen), 1)

        with patch.object(transport, "TIMEOUT_SECONDS", 0.05):
            with rpc_endpoint("stall") as (endpoint, seen, server):
                result = transport.submit_once(endpoint, TX, 7)
        self.assertEqual(result, FIXED_FAILURE)
        self.assertEqual(server.connection_count, 1)
        self.assertEqual(len(seen), 1)

    def test_http_status_content_type_and_framing_are_strict(self):
        modes = [
            "non_200",
            "wrong_content_type",
            "missing_length",
            "leading_zero_length",
            "oversized_length",
            "truncated",
            "duplicate_content_type",
            "duplicate_length",
            "transfer_encoding",
            "content_encoding",
            "overbound",
            "combined_overbound",
        ]
        for index, mode in enumerate(modes, start=20):
            with self.subTest(mode=mode):
                with rpc_endpoint(mode) as (endpoint, seen, server):
                    result = transport.submit_once(endpoint, TX, index)
                self.assertEqual(result, FIXED_FAILURE)
                self.assertEqual(server.connection_count, 1)
                self.assertEqual(len(seen), 1)

    def test_json_is_duplicate_free_closed_and_bound_to_id_and_transaction(self):
        modes = [
            "malformed_json",
            "duplicate_json",
            "non_integer_json",
            "wrong_id",
            "boolean_id",
            "wrong_hash",
            "mixed_hash",
            "boolean_code",
            "extra_envelope",
            "extra_result",
            "missing_result_field",
        ]
        for index, mode in enumerate(modes, start=50):
            with self.subTest(mode=mode):
                with rpc_endpoint(mode) as (endpoint, seen, server):
                    result = transport.submit_once(endpoint, TX, index)
                self.assertEqual(result, FIXED_FAILURE)
                self.assertEqual(server.connection_count, 1)
                self.assertEqual(len(seen), 1)
                self.assertNotIn("raw-body-must-not-escape", repr(result))
                self.assertNotIn("untrusted endpoint log", repr(result))


if __name__ == "__main__":
    unittest.main()
