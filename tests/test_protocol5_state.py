from __future__ import annotations

import base64
import copy
import hashlib
import struct
import unittest

from protocol5_encoding import (
    TX_MAGIC, canonical_json, field_hex, genesis_document, h2f,
)
from protocol5_fixture import make_genesis, make_public_fields, make_tx
from protocol5_state import (
    CODE_ANCHOR, CODE_CAPACITY, CODE_MALFORMED, CODE_NULLIFIER,
    CODE_OUTPUT, HistoryLimitError, application_hash, execute_block,
    audit_state, initial_state, replay_state,
)
from protocol5_worker import AppendResult, INVALID_PROOF, INVALID_STATEMENT, OK

class FixtureWorker:
    """Deterministic state-machine fixture; it supplies no Halo2 evidence."""
    def __init__(self):
        self.calls = 0

    def tree_root(self, commitments):
        return h2f(b"fixture-tree", b"".join(commitments))

    def verify_and_append(self, commitments, fields, proof):
        self.calls += 1
        if proof == b"S" * len(proof):
            return AppendResult(INVALID_STATEMENT)
        if proof != b"P" * len(proof):
            return AppendResult(INVALID_PROOF)
        before = self.tree_root(commitments)
        after = self.tree_root(commitments + [fields[10], fields[11]])
        return AppendResult(OK, before, after, len(commitments), len(commitments) + 1)

def tx_for(genesis, anchor, marker, **changes):
    fields = list(make_public_fields(genesis))
    fields[8] = field_hex(anchor)
    fields[9] = field_hex(h2f(b"nullifier", marker))
    fields[10] = field_hex(h2f(b"output-0", marker))
    fields[11] = field_hex(h2f(b"output-1", marker))
    for index, value in changes.pop("field_changes", {}).items():
        fields[index] = value
    return make_tx(genesis, fields=fields, **changes)

class Protocol5StateTests(unittest.TestCase):
    def setUp(self):
        self.genesis = genesis_document(canonical_json(make_genesis()))
        self.worker = FixtureWorker()
        self.state = initial_state(self.genesis, self.worker)

    def test_same_root_spends_and_global_conflicts(self):
        anchor = bytes.fromhex(self.state["current_root"])
        first = tx_for(self.genesis.value, anchor, b"a")
        second = tx_for(self.genesis.value, anchor, b"b")
        duplicate = tx_for(self.genesis.value, anchor, b"a")
        next_state, results = execute_block(
            self.genesis, self.state, [first, second, duplicate], 1, self.worker)
        self.assertEqual([item["code"] for item in results], [0, 0, CODE_NULLIFIER])
        self.assertEqual(next_state["accepted_transaction_count"], 2)
        self.assertEqual(next_state["history_transaction_count"], 3)
        self.assertEqual(next_state["history_transaction_bytes"],
                         len(first) + len(second) + len(duplicate))
        self.assertEqual(next_state["fee_total"], 10)
        self.assertEqual(len(next_state["commitments"]), 6)
        self.assertEqual(len(next_state["root_history"]), 3)
        self.assertEqual(len(next_state["receipts"]), 2)
        self.assertEqual(next_state["receipts"][1]["tx_index"], 1)
        self.assertEqual(next_state["spent_nullifiers"],
                         sorted(next_state["spent_nullifiers"]))

    def test_same_block_root_is_not_an_eligible_anchor(self):
        genesis_anchor = bytes.fromhex(self.state["current_root"])
        first = tx_for(self.genesis.value, genesis_anchor, b"a")
        speculative = copy.deepcopy(self.state)
        speculative, accepted = execute_block(
            self.genesis, speculative, [first], 1, self.worker)
        self.assertEqual(accepted[0]["code"], 0)
        new_root = bytes.fromhex(speculative["current_root"])
        second = tx_for(self.genesis.value, new_root, b"b")
        final, results = execute_block(
            self.genesis, self.state, [first, second], 1, self.worker)
        self.assertEqual([item["code"] for item in results], [0, CODE_ANCHOR])
        self.assertEqual(final["accepted_transaction_count"], 1)

    def test_rejected_wires_are_retained_and_apphash_binds_exact_state(self):
        anchor = bytes.fromhex(self.state["current_root"])
        accepted = tx_for(self.genesis.value, anchor, b"a")
        malformed = b"x"
        next_state, results = execute_block(
            self.genesis, self.state, [malformed, accepted], 1, self.worker)
        self.assertEqual([item["code"] for item in results], [CODE_MALFORMED, 0])
        block = next_state["execution_blocks"][0]
        self.assertEqual(
            block["transactions"],
            [base64.b64encode(malformed).decode("ascii"),
             base64.b64encode(accepted).decode("ascii")],
        )
        self.assertEqual(next_state["history_transaction_count"], 2)
        expected = hashlib.sha256(
            b"1soft/shielded-development/apphash/v1\0"
            + canonical_json({
                "genesis_sha256": self.genesis.sha256.hex(),
                "height": 1,
                "state": next_state,
            })
        ).hexdigest()
        self.assertEqual(application_hash(self.genesis, 1, next_state), expected)

    def test_history_container_budget_aborts_before_worker_or_state_mutation(self):
        genesis_value = make_genesis()
        genesis_value["limits"]["max_history_transactions"] = 1
        genesis_value["limits"]["max_accepted_transactions"] = 1
        genesis_value["genesis_field"] = field_hex(h2f(
            b"genesis",
            canonical_json({k: v for k, v in genesis_value.items()
                            if k not in ("genesis_field", "initial_commitments")}),
        ))
        genesis = genesis_document(canonical_json(genesis_value))
        state = initial_state(genesis, self.worker)
        anchor = bytes.fromhex(state["current_root"])
        txs = [tx_for(genesis.value, anchor, b"a"),
               tx_for(genesis.value, anchor, b"b")]
        calls = self.worker.calls
        with self.assertRaises(HistoryLimitError):
            execute_block(genesis, state, txs, 1, self.worker)
        self.assertEqual(self.worker.calls, calls)
        self.assertEqual(state["history_transaction_count"], 0)

    def test_transaction_precedence_avoids_worker_for_anchor_output_and_capacity(self):
        anchor = bytes.fromhex(self.state["current_root"])
        unknown = tx_for(self.genesis.value, h2f(b"root", b"missing"), b"a")
        zero = field_hex(bytes(32))
        bad_output = tx_for(
            self.genesis.value, anchor, b"b",
            field_changes={10: zero},
        )
        calls = self.worker.calls
        next_state, results = execute_block(
            self.genesis, self.state, [unknown, bad_output], 1, self.worker)
        self.assertEqual([item["code"] for item in results],
                         [CODE_ANCHOR, CODE_OUTPUT])
        self.assertEqual(self.worker.calls, calls)
        self.assertEqual(next_state["accepted_transaction_count"], 0)

    def test_replay_rejects_tampered_receipt_or_result(self):
        anchor = bytes.fromhex(self.state["current_root"])
        wire = tx_for(self.genesis.value, anchor, b"a")
        committed, _ = execute_block(self.genesis, self.state, [wire], 1, self.worker)
        replay_state(self.genesis, committed, 1, self.worker)
        changed = copy.deepcopy(committed)
        changed["receipts"][0]["fee"] += 1
        with self.assertRaises(Exception):
            replay_state(self.genesis, changed, 1, self.worker)

    def test_state_audit_rejects_boolean_counters_and_receipt_positions(self):
        anchor = bytes.fromhex(self.state["current_root"])
        wire = tx_for(self.genesis.value, anchor, b"a")
        committed, _ = execute_block(self.genesis, self.state, [wire], 1, self.worker)
        for mutate in (
            lambda value: value.__setitem__("history_transaction_count", True),
            lambda value: value["receipts"][0].__setitem__("output_position_0", False),
        ):
            changed = copy.deepcopy(committed)
            mutate(changed)
            with self.assertRaises(Exception):
                audit_state(self.genesis, changed, 1, self.worker)

    def test_closed_result_codes_follow_consensus_precedence(self):
        anchor = bytes.fromhex(self.state["current_root"])
        identity = tx_for(
            self.genesis.value, anchor, b"identity",
            field_changes={4: field_hex((2).to_bytes(32, "little")),
                           12: field_hex((999).to_bytes(32, "little"))},
        )
        statement = tx_for(
            self.genesis.value, anchor, b"statement",
            field_changes={12: field_hex((999).to_bytes(32, "little")),
                           5: field_hex((20).to_bytes(32, "little")),
                           6: field_hex((10).to_bytes(32, "little"))},
        )
        validity = tx_for(
            self.genesis.value, anchor, b"validity",
            field_changes={5: field_hex((2).to_bytes(32, "little"))},
        )
        proof = tx_for(self.genesis.value, anchor, b"proof", proof=b"X" * 1024)
        calls = self.worker.calls
        _, results = execute_block(
            self.genesis, self.state, [identity, statement, validity, proof], 1,
            self.worker,
        )
        self.assertEqual([item["code"] for item in results], [2, 8, 3, 9])
        self.assertEqual(self.worker.calls, calls + 1)
        self.assertTrue(all(item["data"] == "" for item in results))

if __name__ == "__main__":
    unittest.main()
