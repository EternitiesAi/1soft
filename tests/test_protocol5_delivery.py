from __future__ import annotations

import copy
import hashlib
from pathlib import Path
import sqlite3
import struct
import tempfile
import unittest
from unittest.mock import patch

from protocol5_delivery import Protocol5Delivery, Protocol5DeliveryError
from protocol5_encoding import (
    TX_MAGIC, canonical_json, decode_canonical_json,
    genesis_document, transaction_id,
)
from protocol5_fixture import make_genesis


def field(number: int) -> bytes:
    return number.to_bytes(32, "little")


def transaction_bytes(genesis_raw: bytes) -> bytes:
    genesis = genesis_document(genesis_raw)
    fields = tuple(field(index + 1) for index in range(14))
    proof = b"\xa5" * genesis.profile.proof_length
    return (
        TX_MAGIC + struct.pack("<HHI", 1, 1, 1)
        + genesis.sha256 + genesis.deployment.identity
        + struct.pack("<H", 14) + b"".join(fields)
        + struct.pack("<I", len(proof)) + proof
    )


class FakeWallet:
    def __init__(self, path: Path, wallet_id: str,
                 decision_id: str, raw: bytes):
        self.path = path
        self.wallet_id = wallet_id
        self.decision_id = decision_id
        self.raw = raw
        self.txid = transaction_id(raw).hex()
        self.revision = "22" * 32
        self.state = "ready"
        self.next_state = "ready"
        self.drift_after_sync = False
        self.delivery_calls = 0
        self.sync_calls = 0
        self.last_observation = None

    def delivery_record(self, decision_id, *, expected_revision=None):
        self.delivery_calls += 1
        if decision_id != self.decision_id:
            raise ValueError("unknown decision")
        if (expected_revision is not None
                and expected_revision != self.revision):
            raise ValueError("wallet revision changed")
        return {
            "wallet_id": self.wallet_id,
            "wallet_revision": self.revision,
            "decision_id": self.decision_id,
            "decision_state": self.state,
            "txid": self.txid,
            "transaction_sha256": hashlib.sha256(self.raw).hexdigest(),
            "transaction_bytes": self.raw,
            "nullifier": "44" * 32,
        }

    def sync(self, observation, *, expected_revision):
        self.sync_calls += 1
        if expected_revision != self.revision:
            raise ValueError("wallet revision changed")
        if observation == self.last_observation:
            return {"status": "already_recorded",
                    "observation_id": hashlib.sha256(observation).hexdigest(),
                    "state_height": decode_canonical_json(
                        observation)["state_witness"]["height"],
                    "revision": self.revision}
        self.last_observation = observation
        self.revision = hashlib.sha256(
            b"wallet-sync" + observation).hexdigest()
        self.state = self.next_state
        result = {
            "status": "recorded",
            "observation_id": hashlib.sha256(observation).hexdigest(),
            "state_height": decode_canonical_json(
                observation)["state_witness"]["height"],
            "revision": self.revision,
        }
        if self.drift_after_sync:
            self.revision = hashlib.sha256(
                b"wallet-post-sync-drift" + observation).hexdigest()
        return result


class CrashAfterClaimDelivery(Protocol5Delivery):
    def _dispatch_guard(self, _decision_id):
        raise RuntimeError("lost after durable claim")


class CrashAfterWalletSyncDelivery(Protocol5Delivery):
    crash_once = True

    def _reconcile_guard(self, *_):
        if self.crash_once:
            self.crash_once = False
            raise RuntimeError("lost after wallet sync")


class Protocol5DeliveryTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.root.chmod(0o700)
        self.genesis_raw = canonical_json(make_genesis())
        self.engine_genesis = {"fixture": "engine"}
        self.wallet_id = "11" * 32
        self.decision_id = "33" * 32
        self.raw = transaction_bytes(self.genesis_raw)
        self.wallet = FakeWallet(
            self.root / "wallet.sqlite", self.wallet_id,
            self.decision_id, self.raw)
        self.path = self.root / "delivery.sqlite"
        self.endpoint = "http://127.0.0.1:26657/"
        self.auth_patch = patch(
            "protocol5_delivery.authenticate_observation",
            side_effect=self.fake_authenticate)
        self.extend_patch = patch(
            "protocol5_delivery.extends_observation", return_value=None)
        self.auth_patch.start()
        self.extend_patch.start()
        self.delivery = Protocol5Delivery(
            self.path, self.wallet_id, self.genesis_raw,
            self.engine_genesis, self.endpoint, create=True)

    def tearDown(self):
        self.delivery.close()
        self.auth_patch.stop()
        self.extend_patch.stop()
        self.temp.cleanup()

    def fake_authenticate(self, raw, *_):
        observation = decode_canonical_json(raw)
        witness = observation["state_witness"]
        return observation, {
            "state_height": witness["height"],
            "header_height": witness["height"] + 1,
            "app_hash": witness["app_hash"],
        }

    def observation(self, height=1, app_hash=None):
        return canonical_json({
            "format": "1soft/protocol5-state-observation/v1",
            "state_witness": {
                "height": height,
                "app_hash": app_hash or f"{height + 10:064x}",
            },
            "signed_header": {"fixture": height},
        })

    def prepared(self):
        result = self.delivery.prepare(
            self.wallet, self.decision_id)
        return result["review"], result["confirmation"]

    def test_prepare_is_mutation_free_and_binds_exact_wallet_record(self):
        before = list(self.delivery.db.iterdump())
        calls = self.wallet.delivery_calls
        review, confirmation = self.prepared()
        self.assertEqual(list(self.delivery.db.iterdump()), before)
        self.assertEqual(self.wallet.delivery_calls, calls + 1)
        self.assertEqual(review["wallet_id"], self.wallet_id)
        self.assertEqual(review["wallet_revision"], self.wallet.revision)
        self.assertEqual(review["delivery_revision"],
                         self.delivery._snapshot()["revision"])
        self.assertEqual(review["decision_id"], self.decision_id)
        self.assertEqual(review["txid"], self.wallet.txid)
        self.assertEqual(
            review["wire_sha256"], hashlib.sha256(self.raw).hexdigest())
        self.assertEqual(review["endpoint"], self.endpoint)
        self.assertEqual(review["confirmation"], confirmation)
        self.assertNotIn(self.raw.hex(), canonical_json(review).decode())

    def test_status_is_closed_and_contains_no_transaction_bytes(self):
        value = self.delivery.status()
        self.assertEqual(set(value), {
            "format", "journal_id", "wallet_id", "revision", "endpoint",
            "attempts", "observations",
        })
        self.assertEqual(value["wallet_id"], self.wallet_id)
        self.assertEqual(value["attempts"], 0)
        self.assertEqual(value["observations"], 0)
        self.assertNotIn(self.raw.hex(), repr(value))

    def test_attempt_is_durable_before_io_and_never_retried(self):
        review, confirmation = self.prepared()
        self.delivery.close()
        self.delivery = CrashAfterClaimDelivery(
            self.path, self.wallet_id, self.genesis_raw,
            self.engine_genesis, self.endpoint)
        with patch("protocol5_delivery.submit_once") as sender:
            with self.assertRaisesRegex(
                    RuntimeError, "durable claim"):
                self.delivery.send(
                    self.wallet, review, confirmation)
            sender.assert_not_called()
        self.delivery.close()
        self.delivery = Protocol5Delivery(
            self.path, self.wallet_id, self.genesis_raw,
            self.engine_genesis, self.endpoint)
        state = self.delivery.inspect(self.decision_id)
        self.assertEqual(state["transport_state"], "attempt_claimed")
        self.assertFalse(state["retry_available"])
        with patch("protocol5_delivery.submit_once") as sender:
            with self.assertRaisesRegex(
                    Protocol5DeliveryError, "retry refused"):
                self.delivery.send(
                    self.wallet, review, confirmation)
            sender.assert_not_called()

    def test_send_runs_outside_transaction_and_stores_sanitized_result(self):
        review, confirmation = self.prepared()

        def admitted(endpoint, raw, request_id):
            self.assertFalse(self.delivery.db.in_transaction)
            self.assertEqual(endpoint, self.endpoint)
            self.assertEqual(raw, self.raw)
            self.assertEqual(request_id, 1)
            return {
                "observation": "endpoint_admitted",
                "check_tx_code": 0,
                "response_sha256": "55" * 32,
            }

        with patch(
                "protocol5_delivery.submit_once",
                side_effect=admitted) as sender:
            state = self.delivery.send(
                self.wallet, review, confirmation)
        self.assertEqual(sender.call_count, 1)
        self.assertEqual(state["transport_state"],
                         "endpoint_admitted")
        self.assertEqual(state["check_tx_code"], 0)
        self.assertFalse(state["execution_authenticated"])
        self.assertFalse(state["endpoint_admission_is_execution"])
        with self.assertRaisesRegex(
                Protocol5DeliveryError, "retry refused"):
            self.delivery.send(
                self.wallet, review, confirmation)
        self.assertEqual(sender.call_count, 1)

    def test_decline_or_unresolved_never_mutates_wallet(self):
        for index, observed in enumerate((
            {
                "observation": "endpoint_declined",
                "check_tx_code": 17,
                "response_sha256": "66" * 32,
            },
            {
                "observation": "unresolved",
                "reason": "transport or response validation failed",
            },
        )):
            with self.subTest(state=observed["observation"]):
                if index:
                    self.delivery.close()
                    self.path = self.root / "unresolved-delivery.sqlite"
                    self.delivery = Protocol5Delivery(
                        self.path, self.wallet_id,
                        self.genesis_raw, self.engine_genesis,
                        self.endpoint, create=True)
                review, confirmation = self.prepared()
                revision = self.wallet.revision
                with patch(
                        "protocol5_delivery.submit_once",
                        return_value=observed):
                    state = self.delivery.send(
                        self.wallet, review, confirmation)
                self.assertEqual(
                    state["transport_state"],
                    observed["observation"])
                self.assertEqual(self.wallet.revision, revision)
                self.assertEqual(self.wallet.sync_calls, 0)

    def test_delivery_change_after_review_refuses_before_claim_or_io(self):
        review, confirmation = self.prepared()
        self.delivery.import_receipt(self.observation())
        with patch("protocol5_delivery.submit_once") as sender:
            with self.assertRaisesRegex(
                    Protocol5DeliveryError,
                    "reviewed delivery journal changed"):
                self.delivery.send(
                    self.wallet, review, confirmation)
            sender.assert_not_called()
        self.assertEqual(
            self.delivery.db.execute(
                "SELECT count(*) FROM attempts").fetchone()[0], 0)

    def test_wallet_change_after_claim_consumes_attempt_without_io(self):
        review, confirmation = self.prepared()

        def change_wallet(_decision_id):
            self.wallet.revision = "77" * 32

        with patch.object(
                self.delivery, "_dispatch_guard",
                side_effect=change_wallet), patch(
                    "protocol5_delivery.submit_once") as sender:
            state = self.delivery.send(
                self.wallet, review, confirmation)
        sender.assert_not_called()
        self.assertEqual(state["transport_state"], "unresolved")
        self.assertFalse(state["retry_available"])

    def test_collection_is_key_free_stores_exact_receipt_and_is_idempotent(self):
        raw = self.observation()
        wallet_revision = self.wallet.revision

        def collect(endpoint, engine, genesis, *, timeout):
            self.assertFalse(self.delivery.db.in_transaction)
            self.assertEqual(endpoint, self.endpoint)
            self.assertEqual(timeout, 4.0)
            return raw

        with patch(
                "protocol5_delivery.read_state_observation",
                side_effect=collect) as reader:
            imported = self.delivery.collect(timeout=4.0)
        self.assertEqual(reader.call_count, 1)
        self.assertEqual(self.wallet.revision, wallet_revision)
        self.assertEqual(self.wallet.sync_calls, 0)
        exported = self.delivery.export_receipt(
            imported["observation_id"])
        self.assertEqual(exported, raw)
        duplicate = self.delivery.import_receipt(raw)
        self.assertEqual(duplicate["status"], "already_imported")
        self.assertEqual(
            duplicate["observation_id"],
            imported["observation_id"])

    def test_reconciliation_accepts_wallet_exact_equivalent_conflict_and_expiry(self):
        cases = (
            "executed_exact", "executed_equivalent",
            "conflicting_spend", "expired_unexecuted")
        for state_name in cases:
            with self.subTest(state=state_name):
                if self.delivery.db.execute(
                        "SELECT count(*) FROM attempts").fetchone()[0]:
                    self.delivery.close()
                    self.path = self.root / (
                        state_name + "-delivery.sqlite")
                    self.delivery = Protocol5Delivery(
                        self.path, self.wallet_id,
                        self.genesis_raw, self.engine_genesis,
                        self.endpoint, create=True)
                    self.wallet.revision = hashlib.sha256(
                        state_name.encode()).hexdigest()
                    self.wallet.state = "ready"
                    self.wallet.last_observation = None
                review, confirmation = self.prepared()
                with patch(
                        "protocol5_delivery.submit_once",
                        return_value={
                            "observation": "endpoint_declined",
                            "check_tx_code": 7,
                            "response_sha256": "88" * 32,
                        }):
                    self.delivery.send(
                        self.wallet, review, confirmation)
                raw = self.observation(
                    height=cases.index(state_name) + 1)
                receipt = self.delivery.import_receipt(raw)
                self.wallet.next_state = state_name
                result = self.delivery.reconcile(
                    self.wallet, self.decision_id,
                    receipt["observation_id"],
                    expected_wallet_revision=self.wallet.revision)
                self.assertEqual(result["decision_state"], state_name)
                self.assertEqual(
                    result["execution_authenticated"],
                    state_name in {
                        "executed_exact", "executed_equivalent"})
                self.assertEqual(self.wallet.sync_calls,
                                 cases.index(state_name) + 1)

    def test_wrong_wallet_is_rejected_before_reconciliation_mutation(self):
        review, confirmation = self.prepared()
        with patch(
                "protocol5_delivery.submit_once",
                return_value={
                    "observation": "unresolved",
                    "reason": "transport or response validation failed",
                }):
            self.delivery.send(self.wallet, review, confirmation)
        receipt = self.delivery.import_receipt(self.observation())
        wrong = FakeWallet(
            self.root / "wrong-wallet.sqlite", "99" * 32,
            self.decision_id, self.raw)
        before = wrong.revision
        with self.assertRaisesRegex(
                Protocol5DeliveryError,
                "wallet reconciliation result differs"):
            self.delivery.reconcile(
                wrong, self.decision_id, receipt["observation_id"],
                expected_wallet_revision=before)
        self.assertEqual(wrong.sync_calls, 0)
        self.assertEqual(wrong.revision, before)

    def test_post_sync_wallet_drift_cannot_be_labeled_by_receipt(self):
        review, confirmation = self.prepared()
        with patch(
                "protocol5_delivery.submit_once",
                return_value={
                    "observation": "unresolved",
                    "reason": "transport or response validation failed",
                }):
            self.delivery.send(self.wallet, review, confirmation)
        receipt = self.delivery.import_receipt(self.observation())
        self.wallet.next_state = "executed_exact"
        self.wallet.drift_after_sync = True
        with self.assertRaisesRegex(ValueError, "wallet revision changed"):
            self.delivery.reconcile(
                self.wallet, self.decision_id,
                receipt["observation_id"],
                expected_wallet_revision=self.wallet.revision)
        self.assertIsNone(
            self.delivery.inspect(self.decision_id)["decision_state"])

    def test_completed_reconciliation_still_validates_supplied_wallet(self):
        review, confirmation = self.prepared()
        with patch(
                "protocol5_delivery.submit_once",
                return_value={
                    "observation": "unresolved",
                    "reason": "transport or response validation failed",
                }):
            self.delivery.send(self.wallet, review, confirmation)
        receipt = self.delivery.import_receipt(self.observation())
        self.wallet.next_state = "executed_exact"
        completed = self.delivery.reconcile(
            self.wallet, self.decision_id, receipt["observation_id"],
            expected_wallet_revision=self.wallet.revision)
        wrong = FakeWallet(
            self.root / "wrong-completed-wallet.sqlite", "99" * 32,
            self.decision_id, self.raw)
        wrong.revision = completed["wallet_revision_after"]
        with self.assertRaisesRegex(
                Protocol5DeliveryError,
                "wallet reconciliation result differs"):
            self.delivery.reconcile(
                wrong, self.decision_id, receipt["observation_id"],
                expected_wallet_revision=wrong.revision)
        self.assertEqual(wrong.delivery_calls, 1)
        self.assertEqual(wrong.sync_calls, 0)

    def test_reconcile_lost_return_is_idempotently_marked_on_retry(self):
        review, confirmation = self.prepared()
        with patch(
                "protocol5_delivery.submit_once",
                return_value={
                    "observation": "unresolved",
                    "reason": "transport or response validation failed",
                }):
            self.delivery.send(
                self.wallet, review, confirmation)
        receipt = self.delivery.import_receipt(
            self.observation())
        self.wallet.next_state = "executed_exact"
        self.delivery.close()
        self.delivery = CrashAfterWalletSyncDelivery(
            self.path, self.wallet_id, self.genesis_raw,
            self.engine_genesis, self.endpoint)
        before = self.wallet.revision
        with self.assertRaisesRegex(RuntimeError, "wallet sync"):
            self.delivery.reconcile(
                self.wallet, self.decision_id,
                receipt["observation_id"],
                expected_wallet_revision=before)
        after = self.wallet.revision
        self.assertNotEqual(after, before)
        pending = self.delivery.inspect(self.decision_id)
        self.assertIsNone(pending["decision_state"])
        recovered = self.delivery.reconcile(
            self.wallet, self.decision_id,
            receipt["observation_id"],
            expected_wallet_revision=after)
        self.assertEqual(
            recovered["decision_state"], "executed_exact")
        self.assertEqual(
            recovered["wallet_sync_status"], "already_recorded")
        repeated = self.delivery.reconcile(
            self.wallet, self.decision_id,
            receipt["observation_id"],
            expected_wallet_revision=after)
        self.assertEqual(repeated["decision_state"], "executed_exact")
        self.assertEqual(self.wallet.sync_calls, 2)

    def test_deleted_attempt_and_unknown_schema_object_are_detected(self):
        review, confirmation = self.prepared()
        with patch(
                "protocol5_delivery.submit_once",
                return_value={
                    "observation": "unresolved",
                    "reason": "transport or response validation failed",
                }):
            self.delivery.send(
                self.wallet, review, confirmation)
        self.delivery.close()
        with sqlite3.connect(self.path) as database:
            database.execute("DELETE FROM attempts")
        with self.assertRaises(Protocol5DeliveryError):
            Protocol5Delivery(
                self.path, self.wallet_id, self.genesis_raw,
                self.engine_genesis, self.endpoint)

    def test_second_writer_and_wallet_sidecar_alias_are_refused(self):
        with self.assertRaisesRegex(
                Protocol5DeliveryError, "already open"):
            Protocol5Delivery(
                self.path, self.wallet_id, self.genesis_raw,
                self.engine_genesis, self.endpoint)
        alias = FakeWallet(
            Path(str(self.path) + "-wal"),
            self.wallet_id, self.decision_id, self.raw)
        with self.assertRaisesRegex(
                Protocol5DeliveryError, "must be separate"):
            self.delivery.prepare(alias, self.decision_id)


if __name__ == "__main__":
    unittest.main()
