from __future__ import annotations

import copy
from pathlib import Path
import tempfile
import unittest

from protocol5_application import Protocol5Application
from protocol5_encoding import canonical_json, comet_validator_set, genesis_document
from protocol5_fixture import make_genesis, make_limits
from state_sync import (
    APPLY_ABORT, APPLY_ACCEPT, APPLY_REJECT_SNAPSHOT, APPLY_RETRY,
    OFFER_ACCEPT, OFFER_REJECT,
)
from test_protocol5_state import FixtureWorker, tx_for

class Protocol5StateSyncTests(unittest.TestCase):
    def setUp(self):
        self.raw = canonical_json(make_genesis(limits=make_limits(snapshot_chunk_bytes=1024, max_snapshot_bytes=128 * 1024)))
        self.genesis = genesis_document(self.raw)

    def _source(self, path):
        app = Protocol5Application(path, FixtureWorker(), expected_genesis=self.raw)
        app.init_chain(
            self.genesis.value["chain_id"], self.raw,
            self.genesis.value["validators"], 1)
        anchor = bytes.fromhex(app.state["current_root"])
        wire = tx_for(self.genesis.value, anchor, b"a")
        validator_hash = bytes.fromhex(comet_validator_set(
            self.genesis.value["validators"]).hash)
        app.finalize_block(
            [wire], 1, b"B" * 32, validator_hash, [], b"source-request")
        app.commit()
        return app

    def test_roundtrip_installs_marker_history_and_no_block_rows(self):
        with tempfile.TemporaryDirectory() as td:
            source = self._source(Path(td) / "source.sqlite")
            target = Protocol5Application(
                Path(td) / "target.sqlite", FixtureWorker(),
                expected_genesis=self.raw)
            snapshot = source.list_snapshots()[0]
            self.assertEqual(target.offer_snapshot(
                snapshot, bytes.fromhex(source.app_hash)), OFFER_ACCEPT)
            for index in range(snapshot["chunks"]):
                chunk = source.load_snapshot_chunk(
                    snapshot["height"], snapshot["format"], index)
                reply = target.apply_snapshot_chunk(index, chunk, "peer")
                self.assertEqual(reply["result"], APPLY_ACCEPT)
            self.assertEqual(target.state, source.state)
            self.assertEqual(target.app_hash, source.app_hash)
            self.assertEqual(target.db.execute(
                "SELECT count(*) FROM blocks").fetchone()[0], 0)
            self.assertEqual(target.db.execute(
                "SELECT count(*) FROM history").fetchone()[0], 1)
            marker = target.db.execute(
                "SELECT height,app_hash FROM snapshot_marker").fetchone()
            self.assertEqual(marker, (1, source.app_hash))
            source.close(); target.close()

    def test_chunk_order_duplicates_and_conflicts_are_exact(self):
        with tempfile.TemporaryDirectory() as td:
            source = self._source(Path(td) / "source.sqlite")
            target = Protocol5Application(
                Path(td) / "target.sqlite", FixtureWorker(),
                expected_genesis=self.raw)
            snapshot = source.list_snapshots()[0]
            self.assertEqual(target.offer_snapshot(
                snapshot, bytes.fromhex(source.app_hash)), OFFER_ACCEPT)
            first = source.load_snapshot_chunk(1, 1, 0)
            if snapshot["chunks"] > 1:
                retry = target.apply_snapshot_chunk(1, source.load_snapshot_chunk(
                    1, 1, 1), "peer")
                self.assertEqual(retry, {
                    "result": APPLY_RETRY, "refetch_chunks": [0],
                    "reject_senders": [],
                })
            self.assertEqual(target.apply_snapshot_chunk(0, first, "peer")["result"],
                             APPLY_ACCEPT)
            self.assertEqual(target.apply_snapshot_chunk(0, first, "other")["result"],
                             APPLY_ACCEPT)
            changed = bytearray(first); changed[0] ^= 1
            self.assertEqual(
                target.apply_snapshot_chunk(0, bytes(changed), "peer")["result"],
                APPLY_REJECT_SNAPSHOT,
            )
            source.close(); target.close()

    def test_completed_final_duplicate_and_restart_reoffer(self):
        with tempfile.TemporaryDirectory() as td:
            source = self._source(Path(td) / "source.sqlite")
            target_path = Path(td) / "target.sqlite"
            target = Protocol5Application(
                target_path, FixtureWorker(), expected_genesis=self.raw)
            snapshot = source.list_snapshots()[0]
            target.offer_snapshot(snapshot, bytes.fromhex(source.app_hash))
            chunks = [source.load_snapshot_chunk(1, 1, i)
                      for i in range(snapshot["chunks"])]
            for index, chunk in enumerate(chunks):
                target.apply_snapshot_chunk(index, chunk, "peer")
            last = len(chunks) - 1
            self.assertEqual(
                target.apply_snapshot_chunk(last, chunks[last], "peer")["result"],
                APPLY_ACCEPT,
            )
            rejected = copy.deepcopy(snapshot)
            rejected["hash"] = b"X" * 32
            self.assertEqual(target.offer_snapshot(
                rejected, bytes.fromhex(source.app_hash)), OFFER_REJECT)
            self.assertEqual(
                target.apply_snapshot_chunk(last, chunks[last], "peer")["result"],
                APPLY_ACCEPT,
                "rejected offer must not erase completed-final receipt",
            )
            target.close()
            reopened = Protocol5Application(
                target_path, FixtureWorker(), expected_genesis=self.raw)
            self.assertEqual(
                reopened.apply_snapshot_chunk(last, chunks[last], "peer")["result"],
                APPLY_ABORT,
            )
            self.assertEqual(reopened.offer_snapshot(
                snapshot, bytes.fromhex(source.app_hash)), OFFER_ACCEPT)
            changed = copy.deepcopy(snapshot)
            changed["hash"] = b"X" * 32
            self.assertEqual(reopened.offer_snapshot(
                changed, bytes.fromhex(source.app_hash)), OFFER_REJECT)
            source.close(); reopened.close()

    def test_partial_chunks_are_process_local_and_restart_requires_reoffer(self):
        with tempfile.TemporaryDirectory() as td:
            source = self._source(Path(td) / "source.sqlite")
            target_path = Path(td) / "target.sqlite"
            target = Protocol5Application(
                target_path, FixtureWorker(), expected_genesis=self.raw)
            snapshot = source.list_snapshots()[0]
            self.assertGreater(snapshot["chunks"], 1)
            target.offer_snapshot(snapshot, bytes.fromhex(source.app_hash))
            first = source.load_snapshot_chunk(1, 1, 0)
            self.assertEqual(target.apply_snapshot_chunk(0, first, "peer")["result"],
                             APPLY_ACCEPT)
            target.close()
            reopened = Protocol5Application(
                target_path, FixtureWorker(), expected_genesis=self.raw)
            second = source.load_snapshot_chunk(1, 1, 1)
            self.assertEqual(
                reopened.apply_snapshot_chunk(1, second, "peer")["result"],
                APPLY_ABORT,
            )
            self.assertEqual(reopened.offer_snapshot(
                snapshot, bytes.fromhex(source.app_hash)), OFFER_ACCEPT)
            source.close(); reopened.close()

    def test_newer_marker_replacement_and_older_rollback_refusal(self):
        with tempfile.TemporaryDirectory() as td:
            source = self._source(Path(td) / "source.sqlite")
            snapshot_one = source.list_snapshots()[0]
            target = Protocol5Application(
                Path(td) / "target.sqlite", FixtureWorker(),
                expected_genesis=self.raw)
            target.offer_snapshot(snapshot_one, bytes.fromhex(source.app_hash))
            for index in range(snapshot_one["chunks"]):
                target.apply_snapshot_chunk(
                    index, source.load_snapshot_chunk(1, 1, index), "peer")
            app_hash_one = source.app_hash
            validator_set = comet_validator_set(self.genesis.value["validators"])
            votes = [{"address": v.address.hex(), "power": v.power, "block_id_flag": 2}
                     for v in validator_set.validators]
            source.finalize_block(
                [], 2, b"C" * 32, bytes.fromhex(validator_set.hash), votes, b"two")
            source.commit()
            snapshot_two = source.list_snapshots()[0]
            self.assertEqual(target.offer_snapshot(
                snapshot_two, bytes.fromhex(source.app_hash)), OFFER_ACCEPT)
            for index in range(snapshot_two["chunks"]):
                target.apply_snapshot_chunk(
                    index, source.load_snapshot_chunk(2, 1, index), "peer")
            self.assertEqual(target.height, 2)
            self.assertEqual(target.offer_snapshot(
                snapshot_one, bytes.fromhex(app_hash_one)), OFFER_REJECT)
            source.close(); target.close()

    def test_short_excess_and_corrupt_chunks_reject_without_install(self):
        with tempfile.TemporaryDirectory() as td:
            source = self._source(Path(td) / "source.sqlite")
            target = Protocol5Application(
                Path(td) / "target.sqlite", FixtureWorker(),
                expected_genesis=self.raw)
            snapshot = source.list_snapshots()[0]
            first = source.load_snapshot_chunk(1, 1, 0)
            target.offer_snapshot(snapshot, bytes.fromhex(source.app_hash))
            self.assertEqual(target.apply_snapshot_chunk(
                0, first[:-1], "peer")["result"], APPLY_REJECT_SNAPSHOT)
            target.offer_snapshot(snapshot, bytes.fromhex(source.app_hash))
            self.assertEqual(target.apply_snapshot_chunk(
                0, first + b"x", "peer")["result"], APPLY_REJECT_SNAPSHOT)
            target.offer_snapshot(snapshot, bytes.fromhex(source.app_hash))
            corrupt = bytearray(first); corrupt[0] ^= 1
            self.assertEqual(target.apply_snapshot_chunk(
                0, bytes(corrupt), "peer")["result"], APPLY_ACCEPT)
            final = None
            for index in range(1, snapshot["chunks"]):
                final = target.apply_snapshot_chunk(
                    index, source.load_snapshot_chunk(1, 1, index), "peer")
            self.assertEqual(final["result"], APPLY_REJECT_SNAPSHOT)
            self.assertIsNone(target.genesis)
            source.close(); target.close()

    def test_sqlite_install_failure_rolls_back_old_marker_and_memory(self):
        with tempfile.TemporaryDirectory() as td:
            source = self._source(Path(td) / "source.sqlite")
            snapshot_one = source.list_snapshots()[0]
            target = Protocol5Application(
                Path(td) / "target.sqlite", FixtureWorker(),
                expected_genesis=self.raw)
            target.offer_snapshot(snapshot_one, bytes.fromhex(source.app_hash))
            for index in range(snapshot_one["chunks"]):
                target.apply_snapshot_chunk(
                    index, source.load_snapshot_chunk(1, 1, index), "peer")
            before = (target.height, target.app_hash, copy.deepcopy(target.state))
            validator_set = comet_validator_set(self.genesis.value["validators"])
            votes = [{"address": v.address.hex(), "power": v.power, "block_id_flag": 2}
                     for v in validator_set.validators]
            source.finalize_block(
                [], 2, b"C" * 32, bytes.fromhex(validator_set.hash), votes, b"two")
            source.commit()
            snapshot_two = source.list_snapshots()[0]
            target.offer_snapshot(snapshot_two, bytes.fromhex(source.app_hash))
            target.db.execute(
                "CREATE TRIGGER fail_history BEFORE INSERT ON history "
                "BEGIN SELECT RAISE(ABORT, 'disk fault'); END")
            chunks = [source.load_snapshot_chunk(2, 1, i)
                      for i in range(snapshot_two["chunks"])]
            for index, chunk in enumerate(chunks[:-1]):
                target.apply_snapshot_chunk(index, chunk, "peer")
            with self.assertRaises(Exception):
                target.apply_snapshot_chunk(len(chunks) - 1, chunks[-1], "peer")
            self.assertEqual((target.height, target.app_hash, target.state), before)
            self.assertEqual(target.db.execute(
                "SELECT height,app_hash FROM committed").fetchone(), before[:2])
            source.close(); target.close()

    def test_first_post_sync_commit_replaces_marker_with_only_real_response(self):
        with tempfile.TemporaryDirectory() as td:
            source = self._source(Path(td) / "source.sqlite")
            target_path = Path(td) / "target.sqlite"
            target = Protocol5Application(
                target_path, FixtureWorker(), expected_genesis=self.raw)
            snapshot = source.list_snapshots()[0]
            target.offer_snapshot(snapshot, bytes.fromhex(source.app_hash))
            for index in range(snapshot["chunks"]):
                target.apply_snapshot_chunk(
                    index, source.load_snapshot_chunk(1, 1, index), "peer")
            validator_set = comet_validator_set(self.genesis.value["validators"])
            votes = [{"address": v.address.hex(), "power": v.power, "block_id_flag": 2}
                     for v in validator_set.validators]
            target.finalize_block(
                [], 2, b"C" * 32, bytes.fromhex(validator_set.hash), votes, b"post-sync")
            target.commit()
            self.assertIsNone(target.db.execute(
                "SELECT 1 FROM snapshot_marker").fetchone())
            self.assertEqual(target.db.execute(
                "SELECT height FROM blocks").fetchall(), [(2,)])
            target.close()
            reopened = Protocol5Application(
                target_path, FixtureWorker(), expected_genesis=self.raw)
            self.assertEqual(reopened.height, 2)
            source.close(); reopened.close()

if __name__ == "__main__":
    unittest.main()
