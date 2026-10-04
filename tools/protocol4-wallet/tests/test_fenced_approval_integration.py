"""Actual P4 journal clones exercised through the explicit fenced adapter."""
from contextlib import closing
import copy
import json
import sqlite3
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from device_fence import (
    DeviceFence, DeviceFenceError, FencedApproval, rotation_message, wallet_identity,
)
from native_core import canonical
from p4_evidence import content_id
from p4_wallet import P4Wallet
from wallet_fixture import Chain, PASSWORD


class FencedApprovalIntegrationTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        self.chain = Chain(self.root)
        self.source = self.root / "source.sqlite"
        self.registry = self.root / "fence.sqlite"
        with self.wallet(self.source, create=True) as wallet:
            wallet.sync(self.chain.evidence(), expected_revision=None)
            self.wallet_id = wallet_identity(wallet)
            self.journal_id = wallet._catalog()[0]
        self.device = Ed25519PrivateKey.from_private_bytes(b"c" * 32)
        self.new = Ed25519PrivateKey.from_private_bytes(b"e" * 32)
        self.fence = DeviceFence(self.registry)
        self.fence.enroll(self.wallet_id, "device", self.device.public_key().public_bytes_raw())

    def tearDown(self):
        self.fence.close()
        self.chain.close()
        self.tmp.cleanup()

    def wallet(self, path, **kwargs):
        return P4Wallet(path, self.chain.genesis, self.chain.policy,
                        clock=self.chain.clock, **kwargs)

    def clone(self, name):
        path = self.root / (name + ".sqlite")
        with closing(sqlite3.connect(self.source)) as source, closing(sqlite3.connect(path)) as target:
            source.backup(target)
        path.chmod(0o600)
        return path

    def review(self, path, role="raven", units=10):
        with self.wallet(path) as wallet:
            return wallet.prepare(payer=self.chain.payer, recipient=self.chain.merchant,
                                  units=units, grant_id=role, valid_until=30)

    def adapter(self, path, *, key=None):
        adapter = FencedApproval(self.wallet(path), self.fence, "device", 0, key or self.device)
        self.addCleanup(adapter.close)
        return adapter

    def rotate(self):
        public = self.new.public_key().public_bytes_raw()
        message = rotation_message(self.wallet_id, "device", "replacement", public, epoch=0)
        return self.fence.rotate(
            self.wallet_id, "device", "replacement", public,
            self.device.sign(message), self.new.sign(message), epoch=0,
        )

    def reservations(self):
        return self.fence.db.execute("SELECT count(*) FROM reservations").fetchone()[0]

    def test_clones_share_one_lane_but_distinct_grant_lane(self):
        left, right = self.clone("left"), self.clone("right")
        qa, qb = self.review(left, units=10), self.review(right, units=11)
        wa, wb = self.adapter(left), self.adapter(right)
        first = wa.approve(qa["review"], qa["confirmation"],
                           vault=self.root / "raven.pem", password=PASSWORD)
        with self.assertRaisesRegex(DeviceFenceError, "already reserved"):
            wb.approve(qb["review"], qb["confirmation"],
                       vault=self.root / "raven.pem", password=PASSWORD)
        qc = self.review(right, role="atlas", units=7)
        different = wb.approve(qc["review"], qc["confirmation"],
                               vault=self.root / "atlas.pem", password=PASSWORD)
        self.assertNotEqual(canonical(first["transaction"]), canonical(different["transaction"]))
        self.assertEqual(self.reservations(), 2)

    def test_owner_and_grant_are_separate_lanes(self):
        owner, grant = self.clone("owner"), self.clone("grant")
        qa = self.review(owner, role="", units=3)
        first = self.adapter(owner).approve(
            qa["review"], qa["confirmation"], vault=self.root / "owner.pem", password=PASSWORD,
        )
        qb = self.review(grant, role="raven", units=3)
        second = self.adapter(grant).approve(
            qb["review"], qb["confirmation"], vault=self.root / "raven.pem", password=PASSWORD,
        )
        self.assertEqual(first["transaction"]["body"]["grant_id"], "")
        self.assertEqual(second["transaction"]["body"]["grant_id"], "raven")

    def test_retired_device_cannot_reach_vault(self):
        path = self.clone("stale")
        approval = self.review(path)
        adapter = self.adapter(path)
        self.rotate()
        with patch("p4_wallet._load_vault") as load:
            with self.assertRaisesRegex(DeviceFenceError, "fenced"):
                adapter.approve(approval["review"], approval["confirmation"],
                                vault=self.root / "raven.pem", password=PASSWORD)
        load.assert_not_called()
        self.assertEqual(self.reservations(), 0)

    def test_wrong_device_key_cannot_reach_vault(self):
        path = self.clone("wrong_key")
        approval = self.review(path)
        with patch("p4_wallet._load_vault") as load:
            with self.assertRaisesRegex(DeviceFenceError, "authorization"):
                self.adapter(path, key=self.new).approve(
                    approval["review"], approval["confirmation"],
                    vault=self.root / "raven.pem", password=PASSWORD,
                )
        load.assert_not_called()
        self.assertEqual(self.reservations(), 0)

    def test_signer_failure_after_reservation_fails_closed(self):
        path = self.clone("failed")
        approval = self.review(path)
        adapter = self.adapter(path)
        with self.assertRaises(FileNotFoundError):
            adapter.approve(approval["review"], approval["confirmation"],
                            vault=self.root / "missing.pem", password=PASSWORD)
        self.assertEqual(self.reservations(), 1)
        self.assertEqual(adapter.wallet.db.execute("SELECT count(*) FROM decisions").fetchone()[0], 0)
        with self.assertRaisesRegex(DeviceFenceError, "already consumed"):
            adapter.approve(approval["review"], approval["confirmation"],
                            vault=self.root / "raven.pem", password=PASSWORD)

    def test_wrong_password_does_not_release_reservation(self):
        path = self.clone("password")
        approval = self.review(path)
        adapter = self.adapter(path)
        with self.assertRaises(ValueError):
            adapter.approve(approval["review"], approval["confirmation"],
                            vault=self.root / "raven.pem", password=b"wrong")
        self.assertEqual(self.reservations(), 1)
        with self.assertRaisesRegex(DeviceFenceError, "already consumed"):
            adapter.approve(approval["review"], approval["confirmation"],
                            vault=self.root / "raven.pem", password=PASSWORD)

    def test_invalid_confirmation_has_no_registry_effect(self):
        path = self.clone("confirmation")
        approval = self.review(path)
        with patch("p4_wallet._load_vault") as load:
            with self.assertRaisesRegex(DeviceFenceError, "confirmation"):
                self.adapter(path).approve(
                    approval["review"], "0" * 64,
                    vault=self.root / "raven.pem", password=PASSWORD,
                )
        load.assert_not_called()
        self.assertEqual(self.reservations(), 0)

    def test_changed_review_with_valid_digest_has_no_registry_effect(self):
        path = self.clone("changed")
        approval = self.review(path)
        changed = copy.deepcopy(approval["review"])
        changed["wallet_id"] = "0" * 64
        with self.assertRaisesRegex(DeviceFenceError, "wallet state or transfer changed"):
            self.adapter(path).approve(changed, content_id(changed),
                                       vault=self.root / "raven.pem", password=PASSWORD)
        self.assertEqual(self.reservations(), 0)

    def test_malformed_review_has_no_registry_effect(self):
        path = self.clone("malformed")
        changed = {"body": {"op": {"type": "transfer"}}}
        with self.assertRaisesRegex(DeviceFenceError, "invalid transfer review"):
            self.adapter(path).approve(changed, content_id(changed),
                                       vault=self.root / "raven.pem", password=PASSWORD)
        self.assertEqual(self.reservations(), 0)

    def test_key_rotation_review_is_outside_adapter_scope(self):
        path = self.clone("native_rotation")
        with self.wallet(path) as wallet:
            approval = wallet.prepare_rotation(
                payer=self.chain.payer, new_public_key=self.new.public_key().public_bytes_raw().hex(),
                valid_until=30,
            )
        with self.assertRaisesRegex(DeviceFenceError, "only supports transfers"):
            self.adapter(path).approve(approval["review"], approval["confirmation"],
                                       vault=self.root / "owner.pem", password=PASSWORD)
        self.assertEqual(self.reservations(), 0)

    def test_clone_identity_is_stable_and_new_journal_identity_is_distinct(self):
        with self.wallet(self.clone("identity")) as wallet:
            self.assertEqual(wallet_identity(wallet), self.wallet_id)
        with self.wallet(self.root / "fresh.sqlite", create=True) as wallet:
            self.assertNotEqual(wallet_identity(wallet), self.wallet_id)
        self.assertNotEqual(self.wallet_id, self.journal_id)

    def test_identity_change_after_adapter_construction_is_refused(self):
        path = self.clone("identity_changed")
        approval = self.review(path)
        adapter = self.adapter(path)
        adapter.wallet.db.execute("UPDATE config SET wallet_id=?", ("0" * 64,))
        with self.assertRaisesRegex(DeviceFenceError, "wallet identity changed"):
            adapter.approve(approval["review"], approval["confirmation"],
                            vault=self.root / "raven.pem", password=PASSWORD)
        self.assertEqual(self.reservations(), 0)

    def test_genesis_change_after_adapter_construction_is_refused(self):
        path = self.clone("genesis_changed")
        approval = self.review(path)
        adapter = self.adapter(path)
        adapter.wallet.genesis += b" "
        with self.assertRaisesRegex(DeviceFenceError, "wallet identity changed"):
            adapter.approve(approval["review"], approval["confirmation"],
                            vault=self.root / "raven.pem", password=PASSWORD)
        self.assertEqual(self.reservations(), 0)

    def test_rotation_after_reservation_prevents_signer_access(self):
        path = self.clone("rotation_race")
        approval = self.review(path)
        adapter = self.adapter(path)
        reserve = self.fence.reserve
        def rotate_after_reservation(*args):
            reservation = reserve(*args)
            self.rotate()
            return reservation
        with patch.object(self.fence, "reserve", side_effect=rotate_after_reservation):
            with patch("p4_wallet._load_vault") as load:
                with self.assertRaisesRegex(DeviceFenceError, "fenced"):
                    adapter.approve(approval["review"], approval["confirmation"],
                                    vault=self.root / "raven.pem", password=PASSWORD)
        load.assert_not_called()
        self.assertEqual(self.reservations(), 1)

    def test_review_is_frozen_before_signer_access(self):
        path = self.clone("frozen")
        approval = self.review(path)
        from p4_wallet import _load_vault
        def mutate_original(vault, password):
            approval["review"]["body"]["op"]["units"] = 999
            return _load_vault(vault, password)
        with patch("p4_wallet._load_vault", side_effect=mutate_original):
            result = self.adapter(path).approve(
                approval["review"], approval["confirmation"],
                vault=self.root / "raven.pem", password=PASSWORD,
            )
        self.assertEqual(result["transaction"]["body"]["op"]["units"], 10)

    def test_registry_commit_failure_after_signing_preserves_recovery(self):
        path = self.clone("commit_failure")
        approval = self.review(path)
        adapter = self.adapter(path)
        def authorizer(action, name, *_):
            return sqlite3.SQLITE_DENY if action == sqlite3.SQLITE_TRANSACTION and name == "COMMIT" else sqlite3.SQLITE_OK
        reserve = self.fence.reserve
        def deny_commit_after_reservation(*args):
            reservation = reserve(*args)
            self.fence.db.set_authorizer(authorizer)
            return reservation
        with patch.object(self.fence, "reserve", side_effect=deny_commit_after_reservation):
            with self.assertRaisesRegex(DeviceFenceError, "transaction failed"):
                adapter.approve(approval["review"], approval["confirmation"],
                                vault=self.root / "raven.pem", password=PASSWORD)
        self.fence.db.set_authorizer(None)
        self.assertEqual(self.reservations(), 1)
        self.assertEqual(
            self.fence.inspect(self.wallet_id, approval["confirmation"])["state"],
            "reserved",
        )
        recovered = adapter.wallet.recover(
            approval["confirmation"], payer=self.chain.payer, grant_id="raven",
        )
        with patch("p4_wallet._load_vault", side_effect=AssertionError("must not resign")):
            reconciled = adapter.reconcile(
                approval["review"], approval["confirmation"],
            )
        self.assertEqual(reconciled["status"], "reconciled")
        self.assertEqual(reconciled["transaction"], recovered)
        self.assertEqual(json.loads(recovered)["body"]["op"]["units"], 10)
        self.assertEqual(
            self.fence.inspect(self.wallet_id, approval["confirmation"])["state"],
            "decision_committed",
        )
        self.assertEqual(
            self.fence.db.execute("SELECT count(*) FROM fence_events").fetchone()[0], 1,
        )
        self.assertEqual(
            adapter.reconcile(approval["review"], approval["confirmation"])["status"],
            "already_reconciled",
        )
        self.assertEqual(
            self.fence.db.execute("SELECT count(*) FROM fence_events").fetchone()[0], 1,
        )

    def test_context_closes_wallet_and_borrows_shared_registry(self):
        path = self.clone("lifecycle")
        adapter = self.adapter(path)
        with adapter:
            self.assertIsNotNone(adapter.wallet.db)
        self.assertIsNone(adapter.wallet.db)
        adapter.close()
        self.assertIsNotNone(self.fence.db)
        approval = self.review(path)
        with self.assertRaisesRegex(DeviceFenceError, "adapter is closed"):
            adapter.approve(approval["review"], approval["confirmation"],
                            vault=self.root / "raven.pem", password=PASSWORD)

    def test_closed_registry_fails_before_vault_access(self):
        path = self.clone("closed_registry")
        approval = self.review(path)
        adapter = self.adapter(path)
        self.fence.close()
        with patch("p4_wallet._load_vault") as load:
            with self.assertRaisesRegex(DeviceFenceError, "registry is closed"):
                adapter.approve(approval["review"], approval["confirmation"],
                                vault=self.root / "raven.pem", password=PASSWORD)
        load.assert_not_called()

    def test_legacy_direct_approve_is_outside_fence(self):
        fenced, legacy = self.clone("fenced"), self.clone("legacy")
        first, second = self.review(fenced), self.review(legacy, units=11)
        self.adapter(fenced).approve(first["review"], first["confirmation"],
                                     vault=self.root / "raven.pem", password=PASSWORD)
        self.rotate()
        with self.wallet(legacy) as wallet:
            result = wallet.approve(second["review"], second["confirmation"],
                                    vault=self.root / "raven.pem", password=PASSWORD)
        self.assertEqual(result["status"], "signed_and_reserved")
        self.assertEqual(self.reservations(), 1)

    def test_phase3_pre_fence_decision_recovers_without_creating_authority(self):
        path = self.clone("pre-fence")
        approval = self.review(path)
        with self.wallet(path) as wallet:
            direct = wallet.approve(
                approval["review"], approval["confirmation"],
                vault=self.root / "raven.pem", password=PASSWORD,
            )
        with patch("p4_wallet._load_vault", side_effect=AssertionError("must not resign")):
            result = self.adapter(path).reconcile(
                approval["review"], approval["confirmation"],
                request_id="historical-request",
            )
        self.assertEqual(result["status"], "unfenced_decision")
        self.assertFalse(result["registry_recorded"])
        self.assertEqual(result["transaction"], canonical(direct["transaction"]))
        self.assertIsNone(self.fence.inspect(self.wallet_id, "historical-request"))
        self.assertEqual(
            self.fence.db.execute("SELECT count(*) FROM fence_events").fetchone()[0], 0,
        )

    def test_phase3_absent_clone_is_unknown_and_lane_remains_consumed(self):
        first = self.clone("unknown-first")
        other = self.clone("unknown-other")
        approval = self.review(first)
        with self.assertRaises(ValueError):
            self.adapter(first).approve(
                approval["review"], approval["confirmation"],
                vault=self.root / "raven.pem", password=b"wrong",
                request_id="product-request",
            )
        result = self.adapter(other).reconcile(
            approval["review"], approval["confirmation"],
            request_id="product-request",
        )
        self.assertEqual(result["status"], "unknown_quarantined")
        self.assertFalse(result["signing_performed"])
        self.assertNotIn("transaction", result)
        row = self.fence.inspect(self.wallet_id, "product-request")
        self.assertEqual(row["state"], "reserved")
        self.assertEqual(
            self.fence.db.execute("SELECT count(*) FROM fence_events").fetchone()[0], 0,
        )
        with patch("p4_wallet._load_vault") as load:
            with self.assertRaisesRegex(DeviceFenceError, "already reserved"):
                self.adapter(other).approve(
                    approval["review"], approval["confirmation"],
                    vault=self.root / "raven.pem", password=PASSWORD,
                    request_id="replacement-request",
                )
        load.assert_not_called()

    def test_phase3_committed_elsewhere_never_fabricates_bytes(self):
        committed = self.clone("committed")
        empty = self.clone("empty")
        approval = self.review(committed)
        self.adapter(committed).approve(
            approval["review"], approval["confirmation"],
            vault=self.root / "raven.pem", password=PASSWORD,
            request_id="shared-request",
        )
        result = self.adapter(empty).reconcile(
            approval["review"], approval["confirmation"],
            request_id="shared-request",
        )
        self.assertEqual(result["status"], "committed_elsewhere")
        self.assertFalse(result["signing_performed"])
        self.assertNotIn("transaction", result)
        self.assertEqual(result["decision_id"], approval["confirmation"])
        self.assertEqual(
            self.fence.inspect(self.wallet_id, "shared-request")["state"],
            "decision_committed",
        )

    def test_phase3_successor_reconciles_proven_old_device_decision(self):
        path = self.clone("successor")
        approval = self.review(path)
        adapter = self.adapter(path)
        def authorizer(action, name, *_):
            if action == sqlite3.SQLITE_TRANSACTION and name == "COMMIT":
                return sqlite3.SQLITE_DENY
            return sqlite3.SQLITE_OK
        reserve = self.fence.reserve
        def deny_registry_commit(*args):
            result = reserve(*args)
            self.fence.db.set_authorizer(authorizer)
            return result
        with patch.object(self.fence, "reserve", side_effect=deny_registry_commit):
            with self.assertRaisesRegex(DeviceFenceError, "transaction failed"):
                adapter.approve(
                    approval["review"], approval["confirmation"],
                    vault=self.root / "raven.pem", password=PASSWORD,
                    request_id="rotated-request",
                )
        self.fence.db.set_authorizer(None)
        self.rotate()
        successor = FencedApproval(
            adapter.wallet, self.fence, "replacement", 1, self.new, owns_wallet=False,
        )
        self.addCleanup(successor.close)
        with patch("p4_wallet._load_vault", side_effect=AssertionError("must not resign")):
            result = successor.reconcile(
                approval["review"], approval["confirmation"],
                request_id="rotated-request",
            )
        self.assertEqual(result["status"], "reconciled")
        event = self.fence.db.execute(
            "SELECT actor,epoch FROM fence_events WHERE request=?",
            ("rotated-request",),
        ).fetchone()
        self.assertEqual(event, ("replacement", 1))

    def test_phase3_approve_records_positive_terminal_and_wire_hash(self):
        path = self.clone("positive")
        approval = self.review(path)
        result = self.adapter(path).approve(approval["review"], approval["confirmation"],
                                             vault=self.root / "raven.pem", password=PASSWORD)
        row = self.fence.inspect(self.wallet_id, approval["confirmation"])
        self.assertEqual(row["state"], "decision_committed")
        self.assertEqual(row["decision_id"], approval["confirmation"])
        self.assertEqual(row["wire_sha256"], result["wire_sha256"])
        self.assertEqual(self.fence.db.execute("SELECT count(*) FROM fence_events").fetchone()[0], 1)

    def test_phase3_outcome_replay_is_idempotent(self):
        path = self.clone("replay")
        approval = self.review(path)
        result = self.adapter(path).approve(approval["review"], approval["confirmation"],
                                             vault=self.root / "raven.pem", password=PASSWORD)
        row = self.fence.inspect(self.wallet_id, approval["confirmation"])
        msg = self.fence._outcome_message(self.wallet_id, "device", 0, approval["confirmation"],
                                           row["digest"], approval["confirmation"], result["wire_sha256"])
        replay = self.fence.record_decision_committed(self.wallet_id, "device", 0,
                                                       approval["confirmation"], row["digest"],
                                                       approval["confirmation"], result["wire_sha256"],
                                                       self.device.sign(msg))
        self.assertEqual(replay["status"], "already_committed")
        self.assertEqual(self.fence.db.execute("SELECT count(*) FROM fence_events").fetchone()[0], 1)

    def test_phase3_mismatched_outcome_refuses(self):
        path = self.clone("mismatch")
        approval = self.review(path)
        self.adapter(path).approve(approval["review"], approval["confirmation"],
                                   vault=self.root / "raven.pem", password=PASSWORD)
        row = self.fence.inspect(self.wallet_id, approval["confirmation"])
        with self.assertRaisesRegex(DeviceFenceError, "committed outcome differs"):
            self.fence.record_decision_committed(self.wallet_id, "device", 0,
                approval["confirmation"], row["digest"], approval["confirmation"], "0"*64,
                self.device.sign(self.fence._outcome_message(self.wallet_id, "device", 0,
                    approval["confirmation"], row["digest"], approval["confirmation"], "0"*64)))

    def test_phase3_borrowed_wallet_remains_open(self):
        path = self.clone("borrowed")
        wallet = self.wallet(path)
        adapter = FencedApproval(wallet, self.fence, "device", 0, self.device, owns_wallet=False)
        adapter.close()
        self.assertIsNotNone(wallet.db)
        wallet.close()


if __name__ == "__main__":
    unittest.main()
