"""Marker-only Protocol 5 state sync with full verifier replay."""
from __future__ import annotations

from collections import OrderedDict
import hashlib
from typing import Any

from protocol5_encoding import (
    EncodingError, canonical_json, decode_canonical_json, genesis_document,
)
from protocol5_state import StateError, application_hash, replay_state
from state_sync import (
    APPLY_ABORT, APPLY_ACCEPT, APPLY_REJECT_SNAPSHOT, APPLY_RETRY,
    OFFER_ABORT, OFFER_ACCEPT, OFFER_REJECT, OFFER_REJECT_FORMAT,
)

FORMAT = 1
DOMAIN = "1soft/shielded-development/state-sync/v1"
HASH_DOMAIN = b"1soft/shielded-development/state-sync/v1\0"
MAX_METADATA_BYTES = 4096
MAX_CACHED_SNAPSHOTS = 2
METADATA_KEYS = {
    "domain", "format", "profile_id", "deployment_id", "genesis_sha256",
    "height", "app_hash", "payload_bytes", "chunk_bytes", "chunks",
    "payload_sha256",
}
PAYLOAD_KEYS = {"genesis", "height", "app_hash", "state"}


class SnapshotError(ValueError):
    pass


def _need(condition: bool, message: str) -> None:
    if not condition:
        raise SnapshotError(message)


def _hash(payload: bytes) -> bytes:
    return hashlib.sha256(HASH_DOMAIN + payload).digest()


def _metadata(genesis, height: int, app_hash: str, payload: bytes,
              chunk_bytes: int, chunks: int) -> bytes:
    return canonical_json({
        "domain": DOMAIN,
        "format": FORMAT,
        "profile_id": genesis.profile.identity.hex(),
        "deployment_id": genesis.deployment.identity.hex(),
        "genesis_sha256": genesis.sha256.hex(),
        "height": height,
        "app_hash": app_hash,
        "payload_bytes": len(payload),
        "chunk_bytes": chunk_bytes,
        "chunks": chunks,
        "payload_sha256": _hash(payload).hex(),
    })


def _parse_metadata(raw: bytes, genesis) -> dict:
    _need(type(raw) is bytes and len(raw) <= MAX_METADATA_BYTES,
          "invalid Protocol 5 snapshot metadata")
    try:
        value = decode_canonical_json(raw, max_bytes=MAX_METADATA_BYTES)
    except EncodingError as exc:
        raise SnapshotError("invalid Protocol 5 snapshot metadata") from exc
    _need(type(value) is dict and set(value) == METADATA_KEYS,
          "invalid Protocol 5 snapshot metadata fields")
    limits = genesis.value["limits"]
    _need(value["domain"] == DOMAIN and value["format"] == FORMAT,
          "unsupported Protocol 5 snapshot metadata")
    _need(value["profile_id"] == genesis.profile.identity.hex()
          and value["deployment_id"] == genesis.deployment.identity.hex()
          and value["genesis_sha256"] == genesis.sha256.hex(),
          "snapshot identity differs")
    for name in ("app_hash", "payload_sha256"):
        item = value[name]
        _need(type(item) is str and len(item) == 64
              and all(ch in "0123456789abcdef" for ch in item),
              "invalid snapshot digest")
    _need(type(value["height"]) is int
          and 1 <= value["height"] <= limits["max_height"]
          and type(value["payload_bytes"]) is int
          and 0 < value["payload_bytes"] <= limits["max_snapshot_bytes"]
          and type(value["chunk_bytes"]) is int
          and 1 <= value["chunk_bytes"] <= limits["snapshot_chunk_bytes"]
          and type(value["chunks"]) is int
          and 1 <= value["chunks"] <= limits["max_snapshot_chunks"]
          and (value["payload_bytes"] + value["chunk_bytes"] - 1)
              // value["chunk_bytes"] == value["chunks"],
          "invalid Protocol 5 snapshot bounds")
    return value


class Protocol5StateSync:
    def __init__(self, app):
        self.app = app
        self._served: OrderedDict[tuple[int, str], tuple[dict, bytes]] = OrderedDict()
        self._offer: dict | None = None
        self._completed: dict | None = None

    def _expected(self):
        raw = self.app.expected_genesis_raw
        if raw is None:
            return None
        return genesis_document(raw)

    def _marker(self):
        return self.app.db.execute(
            "SELECT genesis_sha256,profile_id,deployment_id,height,app_hash,"
            "payload_sha256 FROM snapshot_marker WHERE id=1").fetchone()

    def _checkpoint_only(self) -> bool:
        app = self.app
        if app.genesis is None or app.height <= 0:
            return False
        marker = self._marker()
        committed = app.db.execute(
            "SELECT height,app_hash FROM committed WHERE id=1").fetchone()
        return (
            marker is not None
            and marker[:5] == (
                app.genesis.sha256.hex(), app.genesis.profile.identity.hex(),
                app.genesis.deployment.identity.hex(), app.height, app.app_hash)
            and committed == (app.height, app.app_hash)
            and app.db.execute("SELECT 1 FROM blocks LIMIT 1").fetchone() is None
        )

    def list(self) -> list[dict]:
        app = self.app
        with app.lock:
            if app.genesis is None or app.height <= 0 or app.state is None:
                return []
            payload = canonical_json({
                "genesis": app.genesis.value,
                "height": app.height,
                "app_hash": app.app_hash,
                "state": app.state,
            })
            limits = app.genesis.value["limits"]
            if not 0 < len(payload) <= limits["max_snapshot_bytes"]:
                return []
            chunk_bytes = limits["snapshot_chunk_bytes"]
            chunks = (len(payload) + chunk_bytes - 1) // chunk_bytes
            if not 1 <= chunks <= limits["max_snapshot_chunks"]:
                return []
            metadata = _metadata(
                app.genesis, app.height, app.app_hash, payload, chunk_bytes, chunks)
            descriptor = {
                "height": app.height, "format": FORMAT, "chunks": chunks,
                "hash": _hash(payload), "metadata": metadata,
            }
            key = (app.height, descriptor["hash"].hex())
            self._served[key] = (descriptor, payload)
            self._served.move_to_end(key)
            while len(self._served) > MAX_CACHED_SNAPSHOTS:
                self._served.popitem(last=False)
            return [dict(descriptor)]

    def load(self, height: int, format_: int, index: int) -> bytes:
        expected = self._expected() or self.app.genesis
        _need(expected is not None and type(height) is int
              and 1 <= height <= expected.value["limits"]["max_height"]
              and format_ == FORMAT and type(format_) is int
              and type(index) is int
              and 0 <= index < expected.value["limits"]["max_snapshot_chunks"],
              "invalid Protocol 5 snapshot chunk request")
        with self.app.lock:
            found = next((item for key, item in reversed(self._served.items())
                          if key[0] == height), None)
            if found is None and self.app.height == height and self.list():
                return self.load(height, format_, index)
            if found is None:
                return b""
            descriptor, payload = found
            if index >= descriptor["chunks"]:
                return b""
            chunk_bytes = expected.value["limits"]["snapshot_chunk_bytes"]
            return payload[index * chunk_bytes:(index + 1) * chunk_bytes]

    def offer(self, snapshot: dict, trusted_app_hash: bytes) -> int:
        with self.app.lock:
            self._offer = None
            expected = self._expected()
            if expected is None:
                return OFFER_ABORT
            checkpoint = self._checkpoint_only()
            if self.app.genesis is not None and not checkpoint:
                return OFFER_ABORT
            if type(snapshot) is not dict or set(snapshot) != {
                    "height", "format", "chunks", "hash", "metadata"}:
                return OFFER_REJECT
            if type(snapshot["format"]) is not int or snapshot["format"] != FORMAT:
                return OFFER_REJECT_FORMAT
            try:
                metadata = _parse_metadata(snapshot["metadata"], expected)
                _need(type(snapshot["height"]) is int
                      and snapshot["height"] == metadata["height"]
                      and type(snapshot["chunks"]) is int
                      and snapshot["chunks"] == metadata["chunks"]
                      and type(snapshot["hash"]) is bytes
                      and len(snapshot["hash"]) == 32
                      and snapshot["hash"].hex() == metadata["payload_sha256"]
                      and type(trusted_app_hash) is bytes
                      and len(trusted_app_hash) == 32
                      and trusted_app_hash.hex() == metadata["app_hash"],
                      "snapshot offer differs from trusted checkpoint")
                if checkpoint:
                    marker = self._marker()
                    assert marker is not None
                    _need(metadata["height"] >= self.app.height,
                          "older Protocol 5 snapshot refused")
                    if metadata["height"] == self.app.height:
                        _need(marker == (
                            metadata["genesis_sha256"], metadata["profile_id"],
                            metadata["deployment_id"], metadata["height"],
                            metadata["app_hash"], metadata["payload_sha256"]),
                            "same-height Protocol 5 snapshot differs")
                self._completed = None
                self._offer = {
                    "metadata": metadata,
                    "height": metadata["height"],
                    "chunks": metadata["chunks"],
                    "hash": snapshot["hash"],
                    "app_hash": metadata["app_hash"],
                    "parts": [], "bytes": 0, "checkpoint": checkpoint,
                }
                return OFFER_ACCEPT
            except SnapshotError:
                return OFFER_REJECT

    def _validate(self, raw: bytes, offer: dict) -> dict:
        try:
            payload = decode_canonical_json(
                raw, max_bytes=offer["metadata"]["payload_bytes"])
        except EncodingError as exc:
            raise SnapshotError("invalid Protocol 5 snapshot payload") from exc
        _need(type(payload) is dict and set(payload) == PAYLOAD_KEYS
              and payload["height"] == offer["height"]
              and payload["app_hash"] == offer["app_hash"],
              "snapshot payload identity differs")
        raw_genesis = canonical_json(payload["genesis"])
        expected_raw = self.app.expected_genesis_raw
        _need(expected_raw is not None and raw_genesis == expected_raw,
              "snapshot genesis differs")
        genesis = genesis_document(raw_genesis)
        state = payload["state"]
        replay_state(genesis, state, payload["height"], self.app.worker)
        _need(application_hash(genesis, payload["height"], state) == payload["app_hash"],
              "snapshot AppHash differs")
        return {**payload, "genesis": genesis}

    def _install(self, payload: dict, payload_sha256: str, checkpoint: bool) -> None:
        app = self.app
        genesis = payload["genesis"]
        state = payload["state"]
        app.db.execute("BEGIN IMMEDIATE")
        try:
            if checkpoint:
                _need(self._checkpoint_only()
                      and payload["height"] >= app.height,
                      "Protocol 5 checkpoint changed during install")
                app.db.execute("DELETE FROM blocks")
                app.db.execute("DELETE FROM history")
                app.db.execute("DELETE FROM committed")
                app.db.execute("DELETE FROM snapshot_marker")
            else:
                _need(app.genesis is None
                      and app.db.execute(
                          "SELECT 1 FROM committed").fetchone() is None,
                      "Protocol 5 application initialized during install")
            app.db.execute(
                "INSERT INTO committed VALUES (1,?,?,?,?)",
                (genesis.raw, payload["height"], payload["app_hash"],
                 canonical_json(state)))
            for block in state["execution_blocks"]:
                app.db.execute(
                    "INSERT INTO history VALUES (?,?)",
                    (block["height"], canonical_json(block["transactions"])))
            app.db.execute(
                "INSERT INTO snapshot_marker VALUES (1,?,?,?,?,?,?)",
                (genesis.sha256.hex(), genesis.profile.identity.hex(),
                 genesis.deployment.identity.hex(), payload["height"],
                 payload["app_hash"], payload_sha256))
            app.db.execute("COMMIT")
        except BaseException:
            if app.db.in_transaction:
                app.db.execute("ROLLBACK")
            raise
        app.genesis = genesis
        from protocol5_encoding import comet_validator_set
        app.validator_set = comet_validator_set(genesis.value["validators"])
        app.state = state
        app.height = payload["height"]
        app.app_hash = payload["app_hash"]
        app.pending = None

    def apply(self, index: int, chunk: bytes, sender: str) -> dict:
        with self.app.lock:
            def reply(code, refetch=None):
                return {
                    "result": code,
                    "refetch_chunks": [] if refetch is None else refetch,
                    "reject_senders": [],
                }
            if self._offer is None:
                completed = self._completed
                if completed is not None and index == completed["index"]:
                    return reply(
                        APPLY_ACCEPT if chunk == completed["chunk"]
                        else APPLY_REJECT_SNAPSHOT)
                return reply(APPLY_ABORT)
            offer = self._offer
            try:
                metadata = offer["metadata"]
                _need(type(index) is int and 0 <= index < offer["chunks"]
                      and type(chunk) is bytes and 0 < len(chunk) <= metadata["chunk_bytes"]
                      and type(sender) is str
                      and len(sender.encode("utf-8")) <= 256,
                      "invalid Protocol 5 snapshot chunk")
                expected = len(offer["parts"])
                if index < expected:
                    if offer["parts"][index] == chunk:
                        return reply(APPLY_ACCEPT)
                    self._offer = None
                    return reply(APPLY_REJECT_SNAPSHOT)
                if index > expected:
                    return reply(APPLY_RETRY, [expected])
                if index + 1 < offer["chunks"]:
                    _need(len(chunk) == metadata["chunk_bytes"],
                          "short non-final Protocol 5 snapshot chunk")
                _need(offer["bytes"] + len(chunk) <= metadata["payload_bytes"],
                      "snapshot chunk exceeds payload bound")
                offer["parts"].append(bytes(chunk))
                offer["bytes"] += len(chunk)
                if len(offer["parts"]) < offer["chunks"]:
                    return reply(APPLY_ACCEPT)
                raw = b"".join(offer["parts"])
                _need(len(raw) == metadata["payload_bytes"]
                      and _hash(raw) == offer["hash"],
                      "Protocol 5 snapshot hash differs")
                payload = self._validate(raw, offer)
                self._install(payload, metadata["payload_sha256"], offer["checkpoint"])
                self._completed = {"index": index, "chunk": bytes(chunk)}
                self._offer = None
                return reply(APPLY_ACCEPT)
            except (SnapshotError, EncodingError, StateError, UnicodeError, TypeError):
                self._offer = None
                return reply(APPLY_REJECT_SNAPSHOT)
