"""Adversarial semantics for a future private shared-parent transition.

These tests exercise a transparent state-machine model with disposable keys.
They do not establish shielded privacy, secure proving, or authenticated
non-inclusion.
"""
import copy
import hashlib
import json
from pathlib import Path
import random
import shutil
import tempfile
import threading
import unittest
from concurrent.futures import ThreadPoolExecutor

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from private_authority_attack_model import (
    ObligationJournal,
    PrivateAuthorityAttackModel,
    PrivateAuthorityReject,
)


KEY_A = Ed25519PrivateKey.from_private_bytes(bytes([81]) * 32)
KEY_B = Ed25519PrivateKey.from_private_bytes(bytes([82]) * 32)


def public_hex(key):
    return key.public_key().public_bytes(
        serialization.Encoding.Raw,
        serialization.PublicFormat.Raw,
    ).hex()


def recompute_direct_fields(body):
    """Build a structurally valid adversarial body without production helpers."""
    result = copy.deepcopy(body)
    result["total_debit_units"] = result["units"] + result["fee_units"]
    opening = {
        "asset": result["asset"],
        "genesis_hash": result["genesis_hash"],
        "intent_id": result["intent_id"],
        "recipient": result["recipient"],
        "units": result["units"],
    }
    encoded = json.dumps(
        opening,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
    ).encode("utf-8")
    result["output_commitment"] = hashlib.sha256(
        b"1soft/transparent-private-authority/output/v1\x00" + encoded
    ).hexdigest()
    return result


def configuration():
    return {
        "format": "1soft/transparent-private-authority-model/v1",
        "chain_id": "1soft-private-authority-attack-test",
        "asset": "DEV",
        "fee_units": 2,
        "parent": {
            "id": "mission",
            "owner": "mission-owner",
            "authority_epoch": 0,
            "cap_units": 10,
        },
        "grants": [
            {
                "id": "agent-a",
                "public_key": public_hex(KEY_A),
                "cap_units": 8,
                "expires_height": 20,
                "recipients": ["merchant"],
            },
            {
                "id": "agent-b",
                "public_key": public_hex(KEY_B),
                "cap_units": 8,
                "expires_height": 20,
                "recipients": ["merchant"],
            },
        ],
    }


class PrivateAuthorityAttackModelTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)

    def tearDown(self):
        self.tmp.cleanup()

    def model(self, name="authority.sqlite"):
        return PrivateAuthorityAttackModel(self.root / name, configuration())

    def cloned_journals(self, model):
        seed_path = self.root / "seed.sqlite"
        seed = ObligationJournal(seed_path, checkpoint=model.checkpoint())
        seed.close()
        first_path = self.root / "device-a.sqlite"
        second_path = self.root / "device-b.sqlite"
        shutil.copy2(seed_path, first_path)
        shutil.copy2(seed_path, second_path)
        return ObligationJournal(first_path), ObligationJournal(second_path)

    def authorize_competing(self, model, first, second):
        intent_a = model.review_spend(
            grant_id="agent-a",
            recipient="merchant",
            units=4,
            valid_until=10,
            intent_id="purchase-a",
        )
        intent_b = model.review_spend(
            grant_id="agent-b",
            recipient="merchant",
            units=4,
            valid_until=10,
            intent_id="purchase-b",
        )
        return first.authorize(intent_a, KEY_A), second.authorize(intent_b, KEY_B)

    def test_competing_grants_consume_one_parent_successor_in_either_order(self):
        """Break caught: accepting two distinct grants against one copied parent."""
        for winner_index in (0, 1):
            with self.subTest(winner_index=winner_index):
                model = self.model(f"authority-{winner_index}.sqlite")
                journal_a, journal_b = self.cloned_journals(model)
                try:
                    envelopes = self.authorize_competing(model, journal_a, journal_b)
                    journals = (journal_a, journal_b)
                    receipt = model.apply(envelopes[winner_index], height=1)
                    trusted = model.checkpoint()["state_root"]
                    forged = copy.deepcopy(receipt)
                    forged["units"] = 99
                    with self.assertRaisesRegex(
                        PrivateAuthorityReject, "invalid execution receipt"
                    ):
                        journals[winner_index].reconcile(
                            forged, trusted_state_root=trusted
                        )
                    journals[winner_index].reconcile(receipt, trusted_state_root=trusted)

                    with self.assertRaisesRegex(PrivateAuthorityReject, "parent fragment"):
                        model.apply(envelopes[1 - winner_index], height=1)
                    losing_txid = envelopes[1 - winner_index]["transaction_id"]
                    journals[1 - winner_index].record_untrusted_rejection(
                        losing_txid, "peer said stale parent"
                    )

                    losing_path = journals[1 - winner_index].path
                    journals[1 - winner_index].close()
                    reopened = ObligationJournal(losing_path)
                    journals = list(journals)
                    journals[1 - winner_index] = reopened

                    state = model.state()
                    self.assertEqual(state["parent"]["spent_units"], 6)
                    self.assertEqual(state["parent"]["remaining_units"], 4)
                    self.assertEqual(sum(g["spent_units"] for g in state["grants"]), 6)
                    self.assertEqual(len(state["consumed_parent_nullifiers"]), 1)
                    self.assertEqual(len(state["executions"]), 1)
                    self.assertEqual(
                        journals[1 - winner_index].decision(losing_txid)["status"],
                        "pending",
                    )
                    self.assertEqual(
                        journals[1 - winner_index].decision(losing_txid)["last_untrusted_rejection"],
                        "peer said stale parent",
                    )

                    # An exact replay is idempotent and cannot spend the successor.
                    self.assertEqual(model.apply(envelopes[winner_index], height=2), receipt)
                    self.assertEqual(model.state()["parent"]["spent_units"], 6)
                finally:
                    journal_a.close()
                    journal_b.close()
                    model.close()

    def test_two_connections_cannot_race_copied_parent_fragment(self):
        """Break caught: concurrent SQLite writers each mint a parent successor."""
        path = self.root / "authority.sqlite"
        model = PrivateAuthorityAttackModel(path, configuration())
        journal_a, journal_b = self.cloned_journals(model)
        try:
            envelopes = self.authorize_competing(model, journal_a, journal_b)
            barrier = threading.Barrier(2)

            def execute(envelope):
                candidate = PrivateAuthorityAttackModel(path, configuration())
                try:
                    barrier.wait(timeout=5)
                    try:
                        candidate.apply(envelope, height=1)
                        return "committed"
                    except PrivateAuthorityReject:
                        return "rejected"
                finally:
                    candidate.close()

            with ThreadPoolExecutor(max_workers=2) as pool:
                outcomes = list(pool.map(execute, envelopes))
            self.assertEqual(sorted(outcomes), ["committed", "rejected"])
            state = model.state()
            self.assertEqual(state["parent"]["spent_units"], 6)
            self.assertEqual(len(state["consumed_parent_nullifiers"]), 1)
            self.assertEqual(len(state["executions"]), 1)
        finally:
            journal_a.close()
            journal_b.close()
            model.close()

    def test_authorization_binds_payment_fee_recipient_and_fragment_successors(self):
        """Break caught: mutating a signed transition or widening its recipient."""
        model = self.model()
        journal = ObligationJournal(self.root / "journal.sqlite", checkpoint=model.checkpoint())
        try:
            with self.assertRaisesRegex(PrivateAuthorityReject, "recipient not allowed"):
                model.review_spend(
                    grant_id="agent-a",
                    recipient="attacker",
                    units=4,
                    valid_until=10,
                    intent_id="refused-before-signing",
                )
            body = model.review_spend(
                grant_id="agent-a",
                recipient="merchant",
                units=4,
                valid_until=10,
                intent_id="bound-purchase",
            )
            envelope = journal.authorize(body, KEY_A)
            mutations = {
                "units": 3,
                "fee_units": 1,
                "recipient": "attacker",
                "parent_nullifier": "0" * 64,
                "grant_nullifier": "1" * 64,
                "parent_successor_commitment": "2" * 64,
                "grant_successor_commitment": "3" * 64,
                "authority_epoch": 1,
            }
            for field, value in mutations.items():
                with self.subTest(field=field):
                    changed = copy.deepcopy(envelope)
                    changed["body"][field] = value
                    if field in ("units", "fee_units"):
                        changed["body"] = recompute_direct_fields(changed["body"])
                    with self.assertRaisesRegex(PrivateAuthorityReject, "bad authorization"):
                        model.apply(changed, height=1)

            unauthorized = model.review_spend(
                grant_id="agent-a",
                recipient="merchant",
                units=4,
                valid_until=10,
                intent_id="recipient-mutation",
            )
            unauthorized["recipient"] = "attacker"
            unauthorized = recompute_direct_fields(unauthorized)
            signed_unauthorized = journal.authorize(unauthorized, KEY_A)
            with self.assertRaisesRegex(PrivateAuthorityReject, "recipient not allowed"):
                model.apply(signed_unauthorized, height=1)

            wrong_fee = model.review_spend(
                grant_id="agent-a",
                recipient="merchant",
                units=4,
                valid_until=10,
                intent_id="fee-mutation",
            )
            wrong_fee["fee_units"] = 1
            wrong_fee = recompute_direct_fields(wrong_fee)
            signed_wrong_fee = journal.authorize(wrong_fee, KEY_A)
            with self.assertRaisesRegex(PrivateAuthorityReject, "fee mismatch"):
                model.apply(signed_wrong_fee, height=1)
        finally:
            journal.close()
            model.close()

    def test_revocation_rejects_prepared_epoch_without_resetting_history(self):
        """Break caught: stale authority commits after epoch advance or resets spend."""
        model = self.model()
        journal = ObligationJournal(self.root / "journal.sqlite", checkpoint=model.checkpoint())
        try:
            first = journal.authorize(
                model.review_spend(
                    grant_id="agent-a",
                    recipient="merchant",
                    units=1,
                    valid_until=10,
                    intent_id="first",
                ),
                KEY_A,
            )
            first_receipt = model.apply(first, height=1)
            journal.reconcile(
                first_receipt,
                trusted_state_root=model.checkpoint()["state_root"],
            )
            stale = journal.authorize(
                model.review_spend(
                    grant_id="agent-a",
                    recipient="merchant",
                    units=1,
                    valid_until=10,
                    intent_id="stale-after-revoke",
                ),
                KEY_A,
            )
            before = model.state()
            model.revoke_authority(owner="mission-owner", expected_epoch=0)
            after = model.state()
            self.assertEqual(before["parent"]["spent_units"], 3)
            self.assertEqual(after["parent"]["spent_units"], 3)
            self.assertEqual(after["parent"]["authority_epoch"], 1)
            self.assertTrue(after["parent"]["revoked"])
            with self.assertRaisesRegex(PrivateAuthorityReject, "stale authority epoch"):
                model.apply(stale, height=2)
            self.assertEqual(model.state()["parent"]["spent_units"], 3)
            self.assertEqual(journal.decision(stale["transaction_id"])["status"], "pending")
        finally:
            journal.close()
            model.close()

    def test_state_and_pending_obligations_survive_restart(self):
        """Break caught: restart forgets consumed fragments or uncertain obligations."""
        config = configuration()
        model_path = self.root / "authority.sqlite"
        journal_path = self.root / "journal.sqlite"
        model = PrivateAuthorityAttackModel(model_path, config)
        journal = ObligationJournal(journal_path, checkpoint=model.checkpoint())
        envelope = journal.authorize(
            model.review_spend(
                grant_id="agent-a",
                recipient="merchant",
                units=4,
                valid_until=10,
                intent_id="restart-purchase",
            ),
            KEY_A,
        )
        model.close()
        journal.close()

        model = PrivateAuthorityAttackModel(model_path, config)
        journal = ObligationJournal(journal_path)
        try:
            self.assertEqual(journal.decision(envelope["transaction_id"])["status"], "pending")
            model.apply(envelope, height=1)
            model.close()
            model = PrivateAuthorityAttackModel(model_path, config)
            self.assertEqual(model.state()["parent"]["remaining_units"], 4)
            self.assertEqual(len(model.state()["consumed_parent_nullifiers"]), 1)
        finally:
            journal.close()
            model.close()

    def test_internal_sqlite_failures_roll_back_the_complete_transition(self):
        """Break caught: a crash-like database abort leaves half a successor."""
        triggers = {
            "second-nullifier": """
                CREATE TEMP TRIGGER injected_failure
                BEFORE INSERT ON consumed_nullifiers
                WHEN NEW.kind='grant'
                BEGIN SELECT RAISE(ABORT,'injected failure'); END
            """,
            "grant-update": """
                CREATE TEMP TRIGGER injected_failure
                BEFORE UPDATE ON grant_fragments
                BEGIN SELECT RAISE(ABORT,'injected failure'); END
            """,
            "execution-record": """
                CREATE TEMP TRIGGER injected_failure
                BEFORE INSERT ON executions
                BEGIN SELECT RAISE(ABORT,'injected failure'); END
            """,
        }
        for label, trigger in triggers.items():
            with self.subTest(fault=label):
                model = self.model(f"fault-{label}.sqlite")
                journal = ObligationJournal(
                    self.root / f"fault-{label}-journal.sqlite",
                    checkpoint=model.checkpoint(),
                )
                try:
                    envelope = journal.authorize(
                        model.review_spend(
                            grant_id="agent-a",
                            recipient="merchant",
                            units=4,
                            valid_until=10,
                            intent_id=f"fault-{label}",
                        ),
                        KEY_A,
                    )
                    before = model.state()
                    model.db.execute(trigger)
                    with self.assertRaises(PrivateAuthorityReject):
                        model.apply(envelope, height=1)
                    model.db.execute("DROP TRIGGER injected_failure")
                    self.assertEqual(model.state(), before)
                    model.apply(envelope, height=1)
                    self.assertEqual(model.state()["parent"]["spent_units"], 6)
                    self.assertEqual(len(model.state()["executions"]), 1)
                finally:
                    journal.close()
                    model.close()

    def test_bounded_random_sequence_matches_independent_integer_oracle(self):
        """Break caught: later successors diverge from fee-inclusive counters."""
        config = configuration()
        config["parent"]["cap_units"] = 200
        for grant in config["grants"]:
            grant["cap_units"] = 160
        model = PrivateAuthorityAttackModel(self.root / "random.sqlite", config)
        journal = ObligationJournal(
            self.root / "random-journal.sqlite", checkpoint=model.checkpoint()
        )
        rng = random.Random(0x1A50F7)
        parent_spent = 0
        grant_spent = {"agent-a": 0, "agent-b": 0}
        keys = {"agent-a": KEY_A, "agent-b": KEY_B}
        try:
            for sequence in range(60):
                grant_id = ("agent-a", "agent-b")[rng.randrange(2)]
                units = rng.randrange(1, 18)
                debit = units + 2
                allowed = (
                    parent_spent + debit <= 200
                    and grant_spent[grant_id] + debit <= 160
                )
                before = model.state()
                if not allowed:
                    with self.assertRaises(PrivateAuthorityReject):
                        model.review_spend(
                            grant_id=grant_id,
                            recipient="merchant",
                            units=units,
                            valid_until=20,
                            intent_id=f"random-{sequence}",
                        )
                    self.assertEqual(model.state(), before)
                    continue
                body = model.review_spend(
                    grant_id=grant_id,
                    recipient="merchant",
                    units=units,
                    valid_until=20,
                    intent_id=f"random-{sequence}",
                )
                envelope = journal.authorize(body, keys[grant_id])
                receipt = model.apply(envelope, height=sequence // 4)
                journal.reconcile(
                    receipt, trusted_state_root=model.checkpoint()["state_root"]
                )
                parent_spent += debit
                grant_spent[grant_id] += debit
                state = model.state()
                self.assertEqual(state["parent"]["spent_units"], parent_spent)
                self.assertEqual(state["parent"]["remaining_units"], 200 - parent_spent)
                self.assertEqual(
                    {g["id"]: g["spent_units"] for g in state["grants"]},
                    grant_spent,
                )
                self.assertEqual(
                    len(state["consumed_parent_nullifiers"]),
                    len(state["executions"]),
                )
        finally:
            journal.close()
            model.close()

    def test_scoped_receipt_opens_only_selected_fields_and_states_its_limit(self):
        """Break caught: a scoped receipt silently exports authority identities."""
        model = self.model()
        journal = ObligationJournal(self.root / "journal.sqlite", checkpoint=model.checkpoint())
        try:
            envelope = journal.authorize(
                model.review_spend(
                    grant_id="agent-a",
                    recipient="merchant",
                    units=4,
                    valid_until=10,
                    intent_id="scoped-purchase",
                ),
                KEY_A,
            )
            committed = model.apply(envelope, height=1)
            receipt = model.scoped_receipt(
                envelope["transaction_id"], disclose=("units", "fee_units")
            )
            self.assertEqual(
                receipt["format"],
                "1soft/transparent-authority-scoped-receipt/v1",
            )
            self.assertEqual(receipt["disclosed"], {"fee_units": 2, "units": 4})
            self.assertFalse(receipt["privacy_established"])
            encoded = str(receipt)
            for secret in (
                "mission-owner",
                "agent-a",
                "merchant",
                "parent_nullifier",
                "grant_nullifier",
                public_hex(KEY_A),
            ):
                self.assertNotIn(secret, encoded)
            self.assertTrue(
                model.verify_scoped_receipt(
                    receipt, trusted_state_root=committed["state_root"]
                )
            )
            tampered = copy.deepcopy(receipt)
            tampered["disclosed"]["units"] = 5
            with self.assertRaisesRegex(PrivateAuthorityReject, "scoped receipt mismatch"):
                model.verify_scoped_receipt(
                    tampered, trusted_state_root=committed["state_root"]
                )
        finally:
            journal.close()
            model.close()


if __name__ == "__main__":
    unittest.main()
