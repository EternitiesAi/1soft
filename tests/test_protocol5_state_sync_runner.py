from __future__ import annotations

import base64
import hashlib
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from protocol5_encoding import canonical_json
from protocol5_state_sync import HASH_DOMAIN
from run_protocol5_state_sync import (
    _prepare_snapshot_provider, _repack_snapshot, _restore_source_peers,
    _semantic_payload_variants, _snapshot_engine_ready, preflight_state_sync,
)

class Protocol5StateSyncRunnerTests(unittest.TestCase):
    def test_snapshot_provider_stays_at_h_while_light_providers_reach_h_plus_two(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            for node in range(5):
                config = root / f"node{node}/config/config.toml"
                config.parent.mkdir(parents=True)
                config.write_text(
                    '[p2p]\npersistent_peers = "all-sources"\n', encoding="utf-8")
                (config.parent / "addrbook.json").write_text("{}")

            class Network:
                homes = root
                node_ids = [f"node-{index}" for index in range(5)]
                p2p = [27000 + index for index in range(5)]
                engines = {0: object(), 1: object()}
                events = []

                def stop_engine(self, index):
                    self.events.append(("stop", index))
                    self.engines.pop(index)

                def start_engine(self, index):
                    self.events.append(("start", index))
                    self.engines[index] = object()

                def height(self, index):
                    return 11 if index in (1, 2, 3) else 9

            network = Network()
            _prepare_snapshot_provider(network, 9)
            self.assertEqual(network.events, [
                ("stop", 0), ("stop", 1), ("start", 1), ("start", 2),
                ("start", 3), ("start", 0)])
            self.assertEqual(set(network.engines), {0, 1, 2, 3})
            configs = [
                (root / f"node{index}/config/config.toml").read_text()
                for index in range(5)
            ]
            self.assertIn("node-4@127.0.0.1:27004", configs[0])
            self.assertNotIn("node-1@127.0.0.1:27001", configs[0])
            self.assertIn("node-0@127.0.0.1:27000", configs[4])
            self.assertNotIn("node-1@127.0.0.1:27001", configs[4])
            for index in (1, 2, 3):
                self.assertNotIn("node-0@127.0.0.1:27000", configs[index])
                self.assertNotIn("node-4@127.0.0.1:27004", configs[index])
                self.assertTrue(any(
                    f"node-{peer}@127.0.0.1:2700{peer}" in configs[index]
                    for peer in (1, 2, 3) if peer != index))
            self.assertFalse(any(
                (root / f"node{index}/config/addrbook.json").exists()
                for index in range(5)))

    def test_restoring_partition_restarts_every_running_affected_engine(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            for node in range(5):
                config = root / f"node{node}/config/config.toml"
                config.parent.mkdir(parents=True)
                config.write_text(
                    '[p2p]\npersistent_peers = "partitioned"\n', encoding="utf-8")

            class Network:
                homes = root
                node_ids = [f"node-{index}" for index in range(5)]
                p2p = [27000 + index for index in range(5)]
                engines = {index: object() for index in range(5)}
                events = []

                def stop_engine(self, index):
                    self.events.append(("stop", index))
                    self.engines.pop(index)

                def start_engine(self, index):
                    self.events.append(("start", index))
                    self.engines[index] = object()

                def height(self, index):
                    return 11

            network = Network()
            _restore_source_peers(network)
            self.assertEqual(network.events, [
                ("stop", 0), ("stop", 1), ("stop", 2), ("stop", 3),
                ("stop", 4), ("start", 1), ("start", 2), ("start", 3),
                ("start", 0), ("start", 4)])
            for index in range(5):
                config = (
                    root / f"node{index}/config/config.toml").read_text()
                for peer in range(5):
                    if peer != index:
                        self.assertIn(
                            f"node-{peer}@127.0.0.1:2700{peer}", config)

    def test_marker_only_completion_uses_engine_phase_not_blockstore_height(self):
        with tempfile.TemporaryDirectory() as td:
            events = Path(td) / "events.jsonl"
            prefix = [
                {"kind": "offer_snapshot", "height": 9, "result": 1},
                {"kind": "after_snapshot_commit", "height": 9},
            ]
            recovery = [
                {"kind": "offer_snapshot", "height": 9, "chunks": 5,
                 "pid": 100, "start_ticks": 200, "result": 1},
                {"kind": "after_snapshot_commit", "height": 9,
                 "pid": 100, "start_ticks": 200},
                {"kind": "apply_snapshot_chunk", "height": 9,
                 "pid": 100, "start_ticks": 200, "index": 4, "result": 1},
            ]
            events.write_text("".join(
                json.dumps(row) + "\n" for row in prefix + recovery))

            class Process:
                @staticmethod
                def poll():
                    return None

            state = {"height": 9, "app_hash": "11" * 32}
            network = type("Network", (), {
                "engines": {4: Process()},
                "http": [0, 1, 2, 3, 29004],
                "direct_state": lambda self, index: state,
            })()
            status = {
                "sync_info": {
                    "catching_up": False,
                    "latest_block_height": "0",
                },
            }
            with patch("run_protocol5_state_sync.rpc", return_value=status):
                self.assertEqual(
                    _snapshot_engine_ready(
                        network, 4, 9, events, len(prefix)),
                    state)
                events.write_text("".join(
                    json.dumps(row) + "\n"
                    for row in prefix + recovery[:-1]))
                self.assertIsNone(
                    _snapshot_engine_ready(
                        network, 4, 9, events, len(prefix)))

    def test_semantic_payload_mutations_are_repacked_coherently(self):
        transaction = b"T" * 100
        payload = {
            "genesis": {"protocol_version": 5},
            "height": 9,
            "app_hash": "11" * 32,
            "state": {
                "execution_blocks": [{
                    "height": 9,
                    "transactions": [base64.b64encode(transaction).decode("ascii")],
                    "results": [],
                }],
                "spent_nullifiers": ["22" * 32],
                "root_history": [{"height": 0, "kind": "genesis",
                                  "root": "33" * 32, "tx_index": 0}],
            },
        }
        original = canonical_json(payload)
        metadata = canonical_json({
            "height": 9, "app_hash": "11" * 32,
            "payload_bytes": len(original), "payload_sha256": "00" * 32,
            "chunk_bytes": 64, "chunks": (len(original) + 63) // 64,
        })
        snapshot = {
            "height": 9, "format": 1,
            "chunks": (len(original) + 63) // 64,
            "hash": b"\0" * 32, "metadata": metadata,
        }

        variants = _semantic_payload_variants(payload)
        self.assertEqual(set(variants), {
            "altered_proof", "removed_nullifier", "changed_root_history"})
        altered = base64.b64decode(
            variants["altered_proof"]["state"]["execution_blocks"][0]
            ["transactions"][0], validate=True)
        self.assertEqual(len(altered), len(transaction))
        self.assertNotEqual(altered, transaction)
        self.assertEqual(
            variants["removed_nullifier"]["state"]["spent_nullifiers"], [])
        self.assertNotEqual(
            variants["changed_root_history"]["state"]["root_history"][0]["root"],
            payload["state"]["root_history"][0]["root"])

        repacked, chunks = _repack_snapshot(
            snapshot, variants["altered_proof"])
        raw = b"".join(chunks)
        repacked_metadata = json.loads(repacked["metadata"])
        digest = hashlib.sha256(HASH_DOMAIN + raw).digest()
        self.assertEqual(repacked["hash"], digest)
        self.assertEqual(repacked_metadata["payload_sha256"], digest.hex())
        self.assertEqual(repacked_metadata["payload_bytes"], len(raw))
        self.assertEqual(repacked["chunks"], len(chunks))

    def test_missing_inputs_remain_unassessed_without_synthetic_transfer(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            report = preflight_state_sync(
                output=root / "state-sync.json",
                **{name: root / name for name in (
                    "engine", "worker", "client", "prover", "profile", "kat",
                    "toolchain", "policy", "genesis")})
            self.assertEqual(report["status"], "unassessed")
            self.assertFalse(report["state_sync_observed"])
            self.assertFalse(report["processes_started"])

if __name__ == "__main__":
    unittest.main()
