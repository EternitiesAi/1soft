from __future__ import annotations

import base64
from contextlib import contextmanager
from copy import deepcopy
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import hashlib
import json
import os
from pathlib import Path
import stat
import subprocess
import sys
import tempfile
import threading
import unittest
from unittest import mock

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from certificate_fixture import make_commit, make_header
from commit_verifier import sha
from protocol5_application import Protocol5Application
from protocol5_certificate import trust_from_protocol5_genesis
from protocol5_encoding import canonical_json, field_hex, genesis_document, h2f
from protocol5_fixture import make_genesis
from protocol5_state import application_hash
from protocol5_state_reader import (
    MAX_STATE_OBSERVATION_BYTES,
    STATE_OBSERVATION_FORMAT,
    StateObservationError,
    authenticate_observation,
    extends_observation,
    read_state_observation,
)
from test_protocol5_state import FixtureWorker


def _field(number: int) -> str:
    return field_hex(number.to_bytes(32, "little"))




@contextmanager
def _rpc_server(query_body: bytes, commit_body: bytes, *, mode: str = "normal"):
    class Handler(BaseHTTPRequestHandler):
        requests = []

        def do_GET(self):
            type(self).requests.append((self.path, dict(self.headers)))
            if mode == "redirect" and self.path.startswith("/abci_query"):
                self.send_response(302)
                self.send_header("Location", "/redirected")
                self.end_headers()
                return
            body = (
                query_body if self.path.startswith("/abci_query")
                else commit_body
            )
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            if mode == "compression" and self.path.startswith("/abci_query"):
                self.send_header("Content-Encoding", "gzip")
            if mode == "oversize" and self.path.startswith("/abci_query"):
                self.send_header("Content-Length", str(12 * 1024 * 1024 + 1))
                self.end_headers()
                return
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, format, *args):
            pass

    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield (
            f"http://127.0.0.1:{server.server_address[1]}/",
            Handler,
        )
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=2)

class Protocol5StateReaderTests(unittest.TestCase):
    def _fixture(self):
        keys = [
            Ed25519PrivateKey.from_private_bytes(bytes([index + 61]) * 32)
            for index in range(4)
        ]
        validators = []
        engine_validators = []
        for key in keys:
            public = key.public_key().public_bytes_raw()
            validators.append({"public_key": public.hex(), "power": 10})
            engine_validators.append({
                "address": sha(public)[:20].hex().upper(),
                "pub_key": {
                    "type": "tendermint/PubKeyEd25519",
                    "value": base64.b64encode(public).decode("ascii"),
                },
                "power": "10",
                "name": "P5",
            })
        validators.sort(key=lambda row: row["public_key"])
        value = make_genesis(validators=validators)
        value["genesis_field"] = field_hex(h2f(
            b"genesis",
            canonical_json({
                key: item for key, item in value.items()
                if key not in ("genesis_field", "initial_commitments")
            }),
        ))
        app_genesis = canonical_json(value)
        engine_genesis = {
            "chain_id": value["chain_id"],
            "initial_height": "1",
            "validators": engine_validators,
            "app_state": value,
        }
        trust = trust_from_protocol5_genesis(engine_genesis, app_genesis)
        keyed = {
            sha(key.public_key().public_bytes_raw())[:20]: key for key in keys}
        ordered = [keyed[validator.address] for validator in trust.validators]
        app = Protocol5Application(
            ":memory:", FixtureWorker(), expected_genesis=app_genesis)
        genesis = genesis_document(app_genesis)
        app.init_chain(
            genesis.value["chain_id"], app_genesis,
            genesis.value["validators"], 1)
        witness = {
            "genesis": genesis.value,
            "height": 0,
            "app_hash": app.app_hash,
            "state": app.state,
        }
        signed_header = make_commit(
            make_header(trust, 1, app.app_hash), trust, ordered)
        app.close()
        observation = {
            "format": STATE_OBSERVATION_FORMAT,
            "state_witness": witness,
            "signed_header": signed_header,
        }
        return (
            canonical_json(observation), observation,
            engine_genesis, app_genesis, trust, ordered,
        )

    def test_extension_requires_exact_history_prefixes_and_nullifier_subset(self):
        _, old, _, _, _, _ = self._fixture()
        same = deepcopy(old)
        extends_observation(old, same)

        changed_same = deepcopy(old)
        changed_same["state_witness"]["app_hash"] = "12" * 32
        with self.assertRaises(StateObservationError):
            extends_observation(old, changed_same)

        newer = deepcopy(old)
        witness = newer["state_witness"]
        witness["height"] = 1
        witness["app_hash"] = "34" * 32
        state = witness["state"]
        state["commitments"].append(_field(20))
        state["root_history"].append({
            "kind": "transaction", "height": 1, "tx_index": 0,
            "txid": "ab" * 32, "root": _field(21)})
        state["receipts"].append({"txid": "ab" * 32})
        state["execution_blocks"].append({
            "height": 1, "transactions": [], "results": []})
        state["spent_nullifiers"].append(_field(22))
        extends_observation(old, newer)

        older = deepcopy(newer)
        with self.assertRaises(StateObservationError):
            extends_observation(newer, old)

        for name in (
            "commitments", "root_history", "receipts", "execution_blocks"):
            anchored_old = deepcopy(old)
            anchored_new = deepcopy(newer)
            if not anchored_old["state_witness"]["state"][name]:
                anchor = {"old": name}
                anchored_old["state_witness"]["state"][name] = [anchor]
                anchored_new["state_witness"]["state"][name] = [
                    anchor,
                    *anchored_new["state_witness"]["state"][name],
                ]
            fork = deepcopy(anchored_new)
            fork["state_witness"]["state"][name][0] = {"fork": name}
            with self.subTest(name=name):
                with self.assertRaises(StateObservationError):
                    extends_observation(anchored_old, fork)

        old_with_nullifier = deepcopy(old)
        old_with_nullifier["state_witness"]["state"][
            "spent_nullifiers"] = [_field(23)]
        without_old_nullifier = deepcopy(newer)
        with self.assertRaises(StateObservationError):
            extends_observation(old_with_nullifier, without_old_nullifier)

    def test_loopback_reader_fetches_state_then_exact_h_plus_one_commit(self):
        _, observation, engine, app_genesis, _, _ = self._fixture()
        witness = observation["state_witness"]
        query = json.dumps({
            "jsonrpc": "2.0",
            "id": -1,
            "result": {
                "response": {
                    "code": 0,
                    "log": "",
                    "info": "",
                    "index": "0",
                    "key": None,
                    "value": base64.b64encode(
                        canonical_json(witness)).decode("ascii"),
                    "proofOps": None,
                    "height": str(witness["height"]),
                    "codespace": "",
                },
            },
        }).encode("ascii")
        commit = json.dumps({
            "jsonrpc": "2.0",
            "id": -1,
            "result": {"signed_header": observation["signed_header"]},
        }).encode("ascii")
        with _rpc_server(query, commit) as (endpoint, handler):
            with mock.patch.dict(
                os.environ,
                {
                    "HTTP_PROXY": "http://127.0.0.1:1",
                    "HTTPS_PROXY": "http://127.0.0.1:1",
                    "ALL_PROXY": "http://127.0.0.1:1",
                },
            ):
                raw = read_state_observation(
                    endpoint, engine, app_genesis, timeout=2)
        decoded, certificate = authenticate_observation(
            raw, engine, app_genesis)
        self.assertEqual(decoded, observation)
        self.assertEqual(certificate["header_height"], witness["height"] + 1)
        self.assertEqual(
            [item[0] for item in handler.requests],
            [
                '/abci_query?path=%22%2Fstate%22&prove=false',
                '/commit?height=1',
            ],
        )
        self.assertTrue(all(
            item[1].get("Accept-Encoding") == "identity"
            for item in handler.requests
        ))

    def test_reader_rejects_unsafe_endpoint_redirect_compression_and_bounds(self):
        _, observation, engine, app_genesis, _, _ = self._fixture()
        witness = observation["state_witness"]
        response = {
            "code": 0,
            "log": "",
            "info": "",
            "index": "0",
            "key": None,
            "value": base64.b64encode(
                canonical_json(witness)).decode("ascii"),
            "proofOps": None,
            "height": str(witness["height"]),
            "codespace": "",
        }
        query = json.dumps({
            "jsonrpc": "2.0", "id": -1,
            "result": {"response": response},
        }).encode("ascii")
        commit = json.dumps({
            "jsonrpc": "2.0", "id": -1,
            "result": {"signed_header": observation["signed_header"]},
        }).encode("ascii")

        for endpoint in (
            "http://localhost:1/",
            "https://127.0.0.1:1/",
            "http://127.0.0.1/",
            "http://127.0.0.1:1/path",
            "http://user@127.0.0.1:1/",
            "http://127.0.0.1:1/?query=1",
        ):
            with self.subTest(endpoint=endpoint):
                with self.assertRaises(StateObservationError):
                    read_state_observation(
                        endpoint, engine, app_genesis, timeout=1)

        for mode in ("redirect", "compression", "oversize"):
            with self.subTest(mode=mode):
                with _rpc_server(query, commit, mode=mode) as (
                        endpoint, handler):
                    with self.assertRaises(StateObservationError):
                        read_state_observation(
                            endpoint, engine, app_genesis, timeout=2)
                    self.assertEqual(len(handler.requests), 1)

        duplicate = (
            b'{"jsonrpc":"2.0","id":-1,"result":{},'
            b'"result":{"response":{}}}'
        )
        with _rpc_server(duplicate, commit) as (endpoint, handler):
            with self.assertRaises(StateObservationError):
                read_state_observation(
                    endpoint, engine, app_genesis, timeout=2)
            self.assertEqual(len(handler.requests), 1)

        proved = deepcopy(response)
        proved["proofOps"] = {"ops": []}
        proved_query = json.dumps({
            "jsonrpc": "2.0", "id": -1,
            "result": {"response": proved},
        }).encode("ascii")
        with _rpc_server(proved_query, commit) as (endpoint, handler):
            with self.assertRaises(StateObservationError):
                read_state_observation(
                    endpoint, engine, app_genesis, timeout=2)
            self.assertEqual(len(handler.requests), 1)

    def test_reader_cli_writes_create_new_authenticated_observation(self):
        _, observation, engine, app_genesis, _, _ = self._fixture()
        witness = observation["state_witness"]
        query = json.dumps({
            "jsonrpc": "2.0",
            "id": -1,
            "result": {
                "response": {
                    "code": 0,
                    "log": "",
                    "info": "",
                    "index": "0",
                    "key": None,
                    "value": base64.b64encode(
                        canonical_json(witness)).decode("ascii"),
                    "proofOps": None,
                    "height": str(witness["height"]),
                    "codespace": "",
                },
            },
        }).encode("ascii")
        commit = json.dumps({
            "jsonrpc": "2.0",
            "id": -1,
            "result": {"signed_header": observation["signed_header"]},
        }).encode("ascii")
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            engine_path = root / "engine.json"
            app_path = root / "app.json"
            output = root / "observation.json"
            engine_raw = json.dumps(
                engine, sort_keys=True, separators=(",", ":")).encode("ascii")
            engine_path.write_bytes(engine_raw)
            app_path.write_bytes(app_genesis)
            with _rpc_server(query, commit) as (endpoint, _):
                command = [
                    sys.executable,
                    "-B",
                    "scripts/read_protocol5_state.py",
                    "--endpoint", endpoint,
                    "--engine-genesis", str(engine_path),
                    "--engine-genesis-sha256",
                    hashlib.sha256(engine_raw).hexdigest(),
                    "--app-genesis", str(app_path),
                    "--app-genesis-sha256",
                    hashlib.sha256(app_genesis).hexdigest(),
                    "--output", str(output),
                    "--timeout", "2",
                ]
                result = subprocess.run(
                    command,
                    cwd=Path(__file__).resolve().parents[1],
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    timeout=10,
                    check=False,
                )
            self.assertEqual(result.returncode, 0, result.stderr.decode())
            self.assertEqual(result.stdout, b"")
            authenticate_observation(
                output.read_bytes(), engine, app_genesis)
            self.assertEqual(
                stat.S_IMODE(output.stat().st_mode), 0o600)
            before = output.read_bytes()
            second = subprocess.run(
                command,
                cwd=Path(__file__).resolve().parents[1],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                timeout=10,
                check=False,
            )
            self.assertNotEqual(second.returncode, 0)
            self.assertEqual(output.read_bytes(), before)

    def test_authentication_rejects_wrong_height_trust_state_and_encoding(self):
        raw, observation, engine, app_genesis, trust, keys = self._fixture()
        genesis = genesis_document(app_genesis)
        height_one = deepcopy(observation)
        witness = height_one["state_witness"]
        witness["height"] = 1
        witness["state"]["execution_blocks"].append({
            "height": 1, "transactions": [], "results": []})
        witness["app_hash"] = application_hash(
            genesis, 1, witness["state"])

        for header_height in (1, 3):
            changed = deepcopy(height_one)
            changed["signed_header"] = make_commit(
                make_header(
                    trust,
                    header_height,
                    witness["app_hash"],
                    previous=(
                        observation["signed_header"]["commit"]["block_id"]
                        if header_height > 1 else None
                    ),
                ),
                trust,
                keys,
            )
            with self.subTest(header_height=header_height):
                with self.assertRaises(ValueError):
                    authenticate_observation(
                        canonical_json(changed), engine, app_genesis)

        changed_state = deepcopy(observation)
        changed_state["state_witness"]["state"]["fee_total"] += 1
        with self.assertRaises(ValueError):
            authenticate_observation(
                canonical_json(changed_state), engine, app_genesis)

        insufficient = deepcopy(observation)
        insufficient["signed_header"] = make_commit(
            insufficient["signed_header"]["header"],
            trust,
            keys,
            flags=[2, 1, 1, 1],
        )
        with self.assertRaises(ValueError):
            authenticate_observation(
                canonical_json(insufficient), engine, app_genesis)

        wrong_engine = deepcopy(engine)
        wrong_engine["validators"][0]["power"] = "11"
        with self.assertRaises(ValueError):
            authenticate_observation(raw, wrong_engine, app_genesis)

        duplicate = raw.replace(
            b'{"format":',
            b'{"format":"duplicate","format":',
            1,
        )
        with self.assertRaises(ValueError):
            authenticate_observation(duplicate, engine, app_genesis)
        with self.assertRaises(ValueError):
            authenticate_observation(raw + b"\n", engine, app_genesis)
        with self.assertRaises(ValueError):
            authenticate_observation(
                b"{" + b" " * MAX_STATE_OBSERVATION_BYTES,
                engine,
                app_genesis,
            )

    def test_signed_h_plus_one_authenticates_exact_state(self):
        raw, expected, engine_genesis, app_genesis, _, _ = self._fixture()

        observation, certificate = authenticate_observation(
            raw, engine_genesis, app_genesis)

        self.assertEqual(observation, expected)
        self.assertEqual(certificate["state_height"], 0)
        self.assertEqual(certificate["header_height"], 1)
        self.assertEqual(
            certificate["app_hash"], expected["state_witness"]["app_hash"])


if __name__ == "__main__":
    unittest.main()
