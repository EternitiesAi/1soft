from __future__ import annotations

import tempfile
import unittest

from protocol5_abci_server import dispatch
from protocol5_abci_wire import Request, Response
from protocol5_application import Protocol5Application
from protocol5_encoding import canonical_json, comet_validator_set, genesis_document
from protocol5_fixture import make_genesis
from test_protocol5_state import FixtureWorker, tx_for

class Protocol5ABCITests(unittest.TestCase):
    def setUp(self):
        self.raw = canonical_json(make_genesis())
        self.genesis = genesis_document(self.raw)
        self.app = Protocol5Application(
            ":memory:", FixtureWorker(), expected_genesis=self.raw)

    def tearDown(self):
        self.app.close()

    def _init(self):
        request = Request()
        request.init_chain.chain_id = self.genesis.value["chain_id"]
        request.init_chain.app_state_bytes = self.raw
        request.init_chain.initial_height = 1
        for row in reversed(self.genesis.value["validators"]):
            update = request.init_chain.validators.add()
            update.pub_key.ed25519 = bytes.fromhex(row["public_key"])
            update.power = row["power"]
        response = dispatch(self.app, request)
        self.assertEqual(response.WhichOneof("value"), "init_chain")
        self.assertFalse(response.init_chain.validators)
        return response

    def test_dispatch_init_check_finalize_and_commit(self):
        initialized = self._init()
        self.assertEqual(len(initialized.init_chain.app_hash), 32)
        anchor = bytes.fromhex(self.app.state["current_root"])
        wire = tx_for(self.genesis.value, anchor, b"a")

        check = Request()
        check.check_tx.tx = wire
        checked = dispatch(self.app, check).check_tx
        self.assertEqual(checked.code, 0)
        self.assertEqual(checked.codespace, "")

        finalize = Request()
        finalize.finalize_block.txs.append(wire)
        finalize.finalize_block.hash = b"B" * 32
        finalize.finalize_block.height = 1
        finalize.finalize_block.next_validators_hash = bytes.fromhex(
            comet_validator_set(self.genesis.value["validators"]).hash)
        finalized = dispatch(self.app, finalize).finalize_block
        self.assertEqual(finalized.tx_results[0].code, 0)
        self.assertEqual(finalized.validator_updates, [])
        commit = Request(); commit.commit.SetInParent()
        dispatch(self.app, commit)
        self.assertEqual(self.app.height, 1)

    def test_nonzero_result_uses_closed_codespace(self):
        self._init()
        check = Request(); check.check_tx.tx = b"x"
        response = dispatch(self.app, check).check_tx
        self.assertEqual(response.code, 1)
        self.assertEqual(response.codespace, "one-shielded-development")
        self.assertEqual(response.log, "malformed shielded transaction")

    def test_wire_namespace_is_dedicated_and_deterministic(self):
        request = Request(); request.info.SetInParent()
        encoded = request.SerializeToString(deterministic=True)
        self.assertEqual(Request.FromString(encoded).WhichOneof("value"), "info")
        self.assertIn("protocol5", Request.DESCRIPTOR.full_name)
        self.assertNotIn("protocol4", Request.DESCRIPTOR.full_name)

if __name__ == "__main__":
    unittest.main()
