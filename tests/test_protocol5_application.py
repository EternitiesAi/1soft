from __future__ import annotations

import copy
import hashlib
import sqlite3
from pathlib import Path
import tempfile
import unittest

from protocol5_application import Protocol5Application, Protocol5Error
from protocol5_encoding import canonical_json, comet_validator_set, genesis_document
from protocol5_fixture import make_genesis
from test_protocol5_state import FixtureWorker, tx_for

class Protocol5ApplicationTests(unittest.TestCase):
    def setUp(self):
        self.raw_genesis = canonical_json(make_genesis())
        self.genesis = genesis_document(self.raw_genesis)
        self.validators = list(reversed(self.genesis.value["validators"]))

    def _initialized(self, path=":memory:"):
        app = Protocol5Application(path, FixtureWorker(), expected_genesis=self.raw_genesis)
        app.init_chain(
            self.genesis.value["chain_id"], self.raw_genesis, self.validators, 1)
        return app

    def test_atomic_finalize_commit_restart_and_exact_replay(self):
        with tempfile.TemporaryDirectory() as td:
            db = Path(td) / "p5.sqlite"
            app = self._initialized(db)
            anchor = bytes.fromhex(app.state["current_root"])
            wire = tx_for(self.genesis.value, anchor, b"a")
            validator_hash = bytes.fromhex(comet_validator_set(
                self.genesis.value["validators"]).hash)
            result, response = app.finalize_block(
                [wire], 1, b"B" * 32, validator_hash, [], b"finalize-one")
            self.assertEqual(result["tx_results"][0]["code"], 0)
            self.assertEqual(app.height, 0)
            self.assertIsNotNone(app.pending)
            self.assertEqual(
                app.finalize_block(
                    [wire], 1, b"B" * 32, validator_hash, [], b"finalize-one"),
                (result, response),
            )
            app.commit()
            expected_hash = app.app_hash
            app.close()

            reopened = Protocol5Application(
                db, FixtureWorker(), expected_genesis=self.raw_genesis)
            self.assertEqual(reopened.height, 1)
            self.assertEqual(reopened.app_hash, expected_hash)
            self.assertEqual(
                reopened.finalize_block(
                    [wire], 1, b"B" * 32, validator_hash, [], b"finalize-one"),
                (result, response),
            )
            self.assertEqual(reopened.commit()["height"], 1)
            reopened.close()

    def test_commit_fault_rolls_back_all_tables(self):
        with tempfile.TemporaryDirectory() as td:
            db = Path(td) / "p5.sqlite"
            app = self._initialized(db)
            anchor = bytes.fromhex(app.state["current_root"])
            wire = tx_for(self.genesis.value, anchor, b"a")
            validator_hash = bytes.fromhex(comet_validator_set(
                self.genesis.value["validators"]).hash)
            app.finalize_block(
                [wire], 1, b"B" * 32, validator_hash, [], b"request")
            with self.assertRaises(RuntimeError):
                app.commit(fault="after_state")
            self.assertEqual(app.height, 0)
            self.assertIsNotNone(app.pending)
            self.assertEqual(app.db.execute("SELECT count(*) FROM blocks").fetchone()[0], 0)
            app.close()

    def test_restart_refuses_missing_replay_history(self):
        with tempfile.TemporaryDirectory() as td:
            db = Path(td) / "p5.sqlite"
            app = self._initialized(db)
            validator_hash = bytes.fromhex(comet_validator_set(
                self.genesis.value["validators"]).hash)
            app.finalize_block([], 1, b"B" * 32, validator_hash, [], b"request")
            app.commit()
            app.close()
            connection = sqlite3.connect(db)
            connection.execute("DELETE FROM history")
            connection.commit()
            connection.close()
            with self.assertRaises(Protocol5Error):
                Protocol5Application(
                    db, FixtureWorker(), expected_genesis=self.raw_genesis)

    def test_finalize_checks_next_validators_hash_at_height_one_before_execution(self):
        app = self._initialized()
        calls = app.worker.calls
        with self.assertRaises(Protocol5Error):
            app.finalize_block([], 1, b"B" * 32, b"X" * 32, [], b"request")
        self.assertEqual(app.worker.calls, calls)
        self.assertIsNone(app.pending)
        app.close()

    def test_height_two_requires_exact_four_validator_supermajority(self):
        app = self._initialized()
        validator_set = comet_validator_set(self.genesis.value["validators"])
        validator_hash = bytes.fromhex(validator_set.hash)
        app.finalize_block([], 1, b"A" * 32, validator_hash, [], b"one")
        app.commit()
        votes = [
            {"address": v.address.hex(), "power": v.power, "block_id_flag": 2}
            for v in validator_set.validators
        ]
        app.finalize_block([], 2, b"B" * 32, validator_hash, votes, b"two")
        app.pending = None
        with self.assertRaises(Protocol5Error):
            app.finalize_block([], 2, b"B" * 32, validator_hash, votes[:3], b"two")
        app.close()

    def test_check_prepare_process_and_queries_share_evaluator(self):
        app = self._initialized()
        anchor = bytes.fromhex(app.state["current_root"])
        valid = tx_for(self.genesis.value, anchor, b"a")
        invalid = b"x"
        self.assertEqual(app.check_tx(valid)["code"], 0)
        self.assertEqual(app.check_tx(invalid)["code"], 1)
        prepared = app.prepare_proposal([invalid, valid], 1, 100_000)
        self.assertEqual(prepared, [valid])
        validator_hash = bytes.fromhex(comet_validator_set(
            self.genesis.value["validators"]).hash)
        self.assertTrue(app.process_proposal(prepared, 1, validator_hash))
        self.assertFalse(app.process_proposal([invalid], 1, validator_hash))
        info = app.query("/info")
        self.assertEqual(info["code"], 0)
        self.assertEqual(app.query("/missing")["code"], 1)
        app.close()

if __name__ == "__main__":
    unittest.main()
