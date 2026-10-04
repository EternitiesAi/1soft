from __future__ import annotations

import ast
import copy
from concurrent.futures import ThreadPoolExecutor
import json
import os
from pathlib import Path
import socket
import subprocess
import sys
import threading
import unittest
from unittest.mock import patch

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

import shielded_note_lab as lab
from shielded_note_lab import (
    AUTH_FIELDS,
    CAPACITY,
    DOMAIN,
    LINKABILITY,
    MAX_OUTPUTS,
    MAX_VALUE,
    Ledger,
    NoteError,
    disclose,
    enc,
    make_note,
    membership,
    note_commitment,
    nullifier,
    secret_commitment,
    transaction_id,
    tree_root,
    verify_disclosure,
    verify_membership,
)


class ShieldedNoteLabTests(unittest.TestCase):
    def setUp(self):
        self.genesis = "a" * 64
        self.asset = "1S"
        self.context = "lab-context"
        self.policy = "e" * 64
        self.key1 = Ed25519PrivateKey.from_private_bytes(b"a" * 32)
        self.key2 = Ed25519PrivateKey.from_private_bytes(b"b" * 32)
        self.pub1 = self.key1.public_key().public_bytes_raw().hex()
        self.pub2 = self.key2.public_key().public_bytes_raw().hex()
        self.input_secret = "1" * 64
        self.input_note, self.input_commitment = make_note(
            genesis=self.genesis,
            asset=self.asset,
            value=10,
            spend_key=self.pub1,
            incoming_view_key="b" * 64,
            outgoing_view_key="c" * 64,
            epoch=0,
            policy_commitment=self.policy,
            expiry=100,
            secret_commitment=secret_commitment(self.input_secret),
            blinding="d" * 64,
        )
        self.ledger = Ledger(
            self.genesis,
            self.asset,
            epoch=0,
            context=self.context,
            current_height=7,
        )
        self.ledger.notes = [self.input_commitment]

    def output_note(
        self,
        value,
        *,
        variant=0,
        index=0,
        expiry=120,
        recipient=None,
        policy=None,
    ):
        alphabet = "23456789abcdef"
        offset = (variant * 4 + index * 3) % len(alphabet)
        secret = lab.h(b"fixture-secret", {"variant": variant, "index": index})
        blinding = alphabet[(offset + 1) % len(alphabet)] * 64
        incoming = alphabet[(offset + 2) % len(alphabet)] * 64
        outgoing = alphabet[(offset + 3) % len(alphabet)] * 64
        note, commitment = make_note(
            genesis=self.genesis,
            asset=self.asset,
            value=value,
            spend_key=recipient or self.pub2,
            incoming_view_key=incoming,
            outgoing_view_key=outgoing,
            epoch=0,
            policy_commitment=policy or self.policy,
            expiry=expiry,
            secret_commitment=secret_commitment(secret),
            blinding=blinding,
        )
        return note, commitment, secret

    def signed_spend(
        self,
        *,
        ledger=None,
        input_note=None,
        input_secret=None,
        position=0,
        output_values=(8, 1),
        outputs=None,
        fee=1,
        variant=0,
        tx_expiry=90,
        signing_key=None,
    ):
        ledger = ledger or self.ledger
        input_note = input_note or self.input_note
        input_secret = input_secret or self.input_secret
        signing_key = signing_key or self.key1
        if outputs is None:
            made = [
                self.output_note(value, variant=variant, index=index)
                for index, value in enumerate(output_values)
            ]
            openings = [item[0] for item in made]
            output_secrets = [item[2] for item in made]
        else:
            openings = outputs
            output_secrets = []
        output_commitments = [note_commitment(note) for note in openings]
        input_commitment = note_commitment(input_note)
        transaction = {
            "version": 1,
            "genesis": ledger.genesis,
            "asset": ledger.asset,
            "root": tree_root(ledger.notes),
            "nullifiers": [
                nullifier(
                    input_secret,
                    input_commitment,
                    position,
                    ledger.context,
                )
            ],
            "outputs": [
                {"commitment": commitment}
                for commitment in output_commitments
            ],
            "fee": fee,
            "epoch": ledger.epoch,
            "height": ledger.current_height,
            "expiry": tx_expiry,
            "context": ledger.context,
            "signer": signing_key.public_key().public_bytes_raw().hex(),
            "signature": "0" * 128,
        }
        self.resign(transaction, signing_key)
        witness = {
            "input": copy.deepcopy(input_note),
            "secret": input_secret,
            "position": position,
            "path": membership(
                input_commitment,
                position,
                ledger.notes,
            ),
            "outputs": copy.deepcopy(openings),
        }
        return transaction, witness, openings, output_secrets

    @staticmethod
    def resign(transaction, key):
        body = {
            name: copy.deepcopy(transaction[name])
            for name in AUTH_FIELDS
        }
        transaction["signature"] = key.sign(DOMAIN + enc(body)).hex()

    @staticmethod
    def public_bytes(ledger):
        return enc(ledger.export_public(), lab.MAX_STATE_BYTES)

    def assert_refused_without_mutation(self, transaction, witness):
        before = self.public_bytes(self.ledger)
        with self.assertRaises(NoteError):
            self.ledger.apply(transaction, witness)
        self.assertEqual(self.public_bytes(self.ledger), before)

    def test_note_commitment_fixed_vector(self):
        self.assertEqual(
            self.input_commitment,
            "0429bca13e000605d2585aff3c5874aab428675677f4d411e8b2cfacfff39266",
        )
        self.assertEqual(
            secret_commitment(self.input_secret),
            "a85ecfc335fc0ce3d4ca44060ef2bc76c0b009b6c90ff3f5a33214b575908c76",
        )

    def test_tree_and_nullifier_fixed_vectors(self):
        self.assertEqual(
            tree_root([self.input_commitment]),
            "383fb61fa3af6a23f9f42f6932655347cd10df867e1525c14df408060bd2f870",
        )
        self.assertEqual(
            nullifier(
                self.input_secret,
                self.input_commitment,
                0,
                self.context,
            ),
            "170b6633f201d426ceb389b942451563a4a40c9c2512654461213ca6680d776a",
        )

    def test_caller_mutation_cannot_change_validated_note_commitment(self):
        note = copy.deepcopy(self.input_note)
        expected = note_commitment(copy.deepcopy(note))
        reached_hash = threading.Event()
        resume = threading.Event()
        original_hash = lab.h

        def pause_commitment_hash(tag, value):
            if tag == b"commitment":
                reached_hash.set()
                if not resume.wait(timeout=5):
                    raise AssertionError("commitment mutation synchronization timed out")
            return original_hash(tag, value)

        with patch.object(lab, "h", side_effect=pause_commitment_hash):
            with ThreadPoolExecutor(max_workers=1) as pool:
                future = pool.submit(note_commitment, note)
                self.assertTrue(reached_hash.wait(timeout=5))
                note["value"] = 0
                resume.set()
                actual = future.result(timeout=5)

        self.assertEqual(actual, expected)
        with self.assertRaises(NoteError):
            note_commitment(note)

    def test_caller_mutation_cannot_change_verified_transaction_identity(self):
        transaction, _, _, _ = self.signed_spend()
        expected = transaction_id(copy.deepcopy(transaction))
        original_signature = transaction["signature"]
        verified = threading.Event()
        resume = threading.Event()
        real_public_key = lab.Ed25519PublicKey

        class PausingPublicKey:
            @staticmethod
            def from_public_bytes(raw):
                key_object = real_public_key.from_public_bytes(raw)

                class VerifiedKey:
                    def verify(self, signature, message):
                        result = key_object.verify(signature, message)
                        verified.set()
                        if not resume.wait(timeout=5):
                            raise AssertionError(
                                "transaction mutation synchronization timed out"
                            )
                        return result

                return VerifiedKey()

        with patch.object(lab, "Ed25519PublicKey", PausingPublicKey):
            with ThreadPoolExecutor(max_workers=1) as pool:
                future = pool.submit(transaction_id, transaction)
                self.assertTrue(verified.wait(timeout=5))
                transaction["signature"] = "0" * 128
                resume.set()
                actual = future.result(timeout=5)

        self.assertEqual(actual, expected)
        self.assertNotEqual(transaction["signature"], original_signature)
        with self.assertRaises(NoteError):
            transaction_id(transaction)

    def test_commitment_binds_every_note_field(self):
        mutations = {
            "version": 2,
            "genesis": "f" * 64,
            "asset": "ALT",
            "value": 9,
            "spend_key": self.pub2,
            "incoming_view_key": "2" * 64,
            "outgoing_view_key": "3" * 64,
            "epoch": 1,
            "policy_commitment": "4" * 64,
            "expiry": 99,
            "secret_commitment": "5" * 64,
            "blinding": "6" * 64,
        }
        for field, value in mutations.items():
            with self.subTest(field=field):
                changed = copy.deepcopy(self.input_note)
                changed[field] = value
                if field == "version":
                    with self.assertRaises(NoteError):
                        note_commitment(changed)
                else:
                    self.assertNotEqual(
                        note_commitment(changed),
                        self.input_commitment,
                    )

    def test_membership_path_authenticates_position(self):
        path = membership(
            self.input_commitment,
            0,
            self.ledger.notes,
        )
        self.assertTrue(
            verify_membership(
                self.input_commitment,
                0,
                path,
                tree_root(self.ledger.notes),
            )
        )
        tampered = list(path)
        tampered[0] = "0" * 64
        self.assertFalse(
            verify_membership(
                self.input_commitment,
                0,
                tampered,
                tree_root(self.ledger.notes),
            )
        )

    def test_nullifier_binds_secret_position_commitment_and_context(self):
        baseline = nullifier(
            self.input_secret,
            self.input_commitment,
            0,
            self.context,
        )
        alternatives = (
            nullifier("2" * 64, self.input_commitment, 0, self.context),
            nullifier(self.input_secret, "3" * 64, 0, self.context),
            nullifier(self.input_secret, self.input_commitment, 1, self.context),
            nullifier(self.input_secret, self.input_commitment, 0, "other"),
        )
        self.assertTrue(all(value != baseline for value in alternatives))

    def test_apply_retains_exact_public_transaction_and_receipt(self):
        transaction, witness, _, _ = self.signed_spend()
        receipt = self.ledger.apply(transaction, witness)
        txid = transaction_id(transaction)
        self.assertEqual(receipt["txid"], txid)
        self.assertEqual(self.ledger.transactions[txid], transaction)
        self.assertEqual(self.ledger.receipts[txid], receipt)
        public = self.ledger.export_public()
        self.assertEqual(public["transactions"], [transaction])
        self.assertEqual(public["receipts"], [receipt])
        self.assertEqual(public["root"], receipt["root"])

    def test_arbitrary_nullifier_and_any_signer_exploit_is_refused(self):
        transaction, witness, _, _ = self.signed_spend()
        transaction["nullifiers"] = ["0" * 64]
        transaction["signer"] = self.pub2
        self.resign(transaction, self.key2)
        self.assert_refused_without_mutation(transaction, witness)

    def test_unbound_self_reported_input_value_is_refused(self):
        transaction, witness, _, _ = self.signed_spend()
        witness["input_value"] = 1_000_000
        self.assert_refused_without_mutation(transaction, witness)

    def test_missing_private_witness_is_refused(self):
        transaction, _, _, _ = self.signed_spend()
        self.assert_refused_without_mutation(transaction, None)

    def test_wrong_input_opening_is_refused(self):
        transaction, witness, _, _ = self.signed_spend()
        witness["input"]["value"] = 11
        self.assert_refused_without_mutation(transaction, witness)

    def test_wrong_note_secret_is_refused(self):
        transaction, witness, _, _ = self.signed_spend()
        witness["secret"] = "0" * 64
        self.assert_refused_without_mutation(transaction, witness)

    def test_wrong_membership_path_is_refused(self):
        transaction, witness, _, _ = self.signed_spend()
        witness["path"][0] = "0" * 64
        self.assert_refused_without_mutation(transaction, witness)

    def test_wrong_note_position_is_refused(self):
        transaction, witness, _, _ = self.signed_spend()
        witness["position"] = 1
        self.assert_refused_without_mutation(transaction, witness)

    def test_signer_must_equal_input_spend_key(self):
        transaction, witness, _, _ = self.signed_spend(
            signing_key=self.key2
        )
        self.assert_refused_without_mutation(transaction, witness)

    def test_output_opening_must_match_public_commitment(self):
        transaction, witness, _, _ = self.signed_spend()
        witness["outputs"][0]["value"] = 7
        self.assert_refused_without_mutation(transaction, witness)

    def test_output_order_is_authorized_and_witness_bound(self):
        transaction, witness, _, _ = self.signed_spend()
        swapped = copy.deepcopy(transaction)
        swapped["outputs"].reverse()
        self.resign(swapped, self.key1)
        self.assert_refused_without_mutation(swapped, witness)

    def test_recipient_mutation_is_refused(self):
        transaction, witness, _, _ = self.signed_spend()
        witness["outputs"][0]["spend_key"] = self.pub1
        self.assert_refused_without_mutation(transaction, witness)

    def test_conservation_rejects_value_creation(self):
        transaction, witness, _, _ = self.signed_spend(
            output_values=(9, 1)
        )
        self.assert_refused_without_mutation(transaction, witness)

    def test_conservation_rejects_value_destruction(self):
        transaction, witness, _, _ = self.signed_spend(
            output_values=(7, 1)
        )
        self.assert_refused_without_mutation(transaction, witness)

    def test_transaction_domain_mutations_are_refused(self):
        for field, value in (
            ("genesis", "f" * 64),
            ("asset", "ALT"),
            ("epoch", 1),
            ("context", "other-context"),
        ):
            with self.subTest(field=field):
                transaction, witness, _, _ = self.signed_spend()
                transaction[field] = value
                self.resign(transaction, self.key1)
                self.assert_refused_without_mutation(transaction, witness)

    def test_stale_authenticated_root_is_refused(self):
        transaction, witness, _, _ = self.signed_spend()
        transaction["root"] = "0" * 64
        self.resign(transaction, self.key1)
        self.assert_refused_without_mutation(transaction, witness)

    def test_current_height_is_exact_and_monotonic(self):
        transaction, witness, _, _ = self.signed_spend()
        transaction["height"] = 8
        self.resign(transaction, self.key1)
        self.assert_refused_without_mutation(transaction, witness)
        self.ledger.advance_height(8)
        with self.assertRaises(NoteError):
            self.ledger.advance_height(7)
        self.assertEqual(self.ledger.current_height, 8)

    def test_transaction_expiry_refuses_exact_boundary(self):
        self.ledger.advance_height(90)
        transaction, witness, _, _ = self.signed_spend(tx_expiry=90)
        self.assert_refused_without_mutation(transaction, witness)

    def test_input_note_expiry_refuses_exact_boundary(self):
        self.ledger.advance_height(100)
        transaction, witness, _, _ = self.signed_spend(tx_expiry=110)
        self.assert_refused_without_mutation(transaction, witness)

    def test_output_note_expiry_refuses_exact_boundary(self):
        output, _, _ = self.output_note(9, expiry=7)
        transaction, witness, _, _ = self.signed_spend(
            outputs=[output],
            fee=1,
        )
        self.assert_refused_without_mutation(transaction, witness)

    def test_unknown_versions_and_extra_fields_are_refused(self):
        transaction, witness, _, _ = self.signed_spend()
        for mutation in ("version", "extra"):
            with self.subTest(mutation=mutation):
                candidate = copy.deepcopy(transaction)
                if mutation == "version":
                    candidate["version"] = 2
                else:
                    candidate["extra"] = "not-canonical"
                with self.assertRaises(NoteError):
                    self.ledger.apply(candidate, witness)
        note = copy.deepcopy(self.input_note)
        note["extra"] = 1
        with self.assertRaises(NoteError):
            note_commitment(note)

    def test_boolean_zero_negative_and_overflow_values_are_refused(self):
        for value in (True, 0, -1, MAX_VALUE + 1):
            with self.subTest(value=value):
                note = copy.deepcopy(self.input_note)
                note["value"] = value
                with self.assertRaises(NoteError):
                    note_commitment(note)
        transaction, witness, _, _ = self.signed_spend()
        transaction["fee"] = True
        with self.assertRaises(NoteError):
            self.ledger.apply(transaction, witness)

    def test_malformed_and_oversized_inputs_are_refused(self):
        transaction, witness, _, _ = self.signed_spend()
        transaction["signature"] = "00"
        with self.assertRaises(NoteError):
            self.ledger.apply(transaction, witness)
        transaction, witness, _, _ = self.signed_spend()
        transaction["context"] = "x" * 129
        with self.assertRaises(NoteError):
            self.ledger.apply(transaction, witness)
        with self.assertRaises(NoteError):
            enc({"x": "y" * (lab.MAX_BYTES + 1)})

    def test_duplicate_output_commitments_are_refused(self):
        output, _, _ = self.output_note(4)
        transaction, witness, _, _ = self.signed_spend(
            outputs=[output, copy.deepcopy(output)],
            fee=2,
        )
        self.assert_refused_without_mutation(transaction, witness)

    def test_existing_output_commitment_is_not_fresh(self):
        transaction, witness, _, _ = self.signed_spend(
            outputs=[copy.deepcopy(self.input_note)],
            fee=0,
        )
        self.assert_refused_without_mutation(transaction, witness)

    def test_tree_capacity_is_enforced_before_mutation(self):
        self.ledger.notes = [self.input_commitment] + [
            f"{index + 100:064x}"
            for index in range(CAPACITY - 1)
        ]
        transaction, witness, _, _ = self.signed_spend()
        self.assert_refused_without_mutation(transaction, witness)

    def test_signature_tamper_is_refused(self):
        transaction, witness, _, _ = self.signed_spend()
        transaction["signature"] = (
            ("0" if transaction["signature"][0] != "0" else "1")
            + transaction["signature"][1:]
        )
        self.assert_refused_without_mutation(transaction, witness)

    def test_wrong_signing_key_is_refused(self):
        transaction, witness, _, _ = self.signed_spend()
        self.resign(transaction, self.key2)
        self.assert_refused_without_mutation(transaction, witness)

    def test_failed_apply_preserves_exact_public_state(self):
        transaction, witness, _, _ = self.signed_spend()
        failures = []
        wrong_secret = copy.deepcopy(witness)
        wrong_secret["secret"] = "0" * 64
        failures.append((transaction, wrong_secret))
        wrong_output = copy.deepcopy(witness)
        wrong_output["outputs"][0]["blinding"] = "0" * 64
        failures.append((transaction, wrong_output))
        wrong_tx = copy.deepcopy(transaction)
        wrong_tx["fee"] = 2
        self.resign(wrong_tx, self.key1)
        failures.append((wrong_tx, witness))
        before = self.public_bytes(self.ledger)
        for candidate, private in failures:
            with self.assertRaises(NoteError):
                self.ledger.apply(candidate, private)
            self.assertEqual(self.public_bytes(self.ledger), before)

    def test_exact_replay_returns_original_receipt_without_mutation(self):
        transaction, witness, _, _ = self.signed_spend()
        first = self.ledger.apply(transaction, witness)
        after = self.public_bytes(self.ledger)
        self.ledger.advance_height(200)
        height_state = self.public_bytes(self.ledger)
        replay = self.ledger.apply(transaction, None)
        self.assertEqual(replay, first)
        self.assertEqual(self.public_bytes(self.ledger), height_state)
        self.assertNotEqual(after, height_state)

    def test_conflicting_same_nullifier_transaction_is_refused(self):
        first, first_witness, _, _ = self.signed_spend(variant=0)
        second, second_witness, _, _ = self.signed_spend(variant=2)
        self.ledger.apply(first, first_witness)
        second["root"] = tree_root(self.ledger.notes)
        second["height"] = self.ledger.current_height
        self.resign(second, self.key1)
        self.assert_refused_without_mutation(second, second_witness)

    def test_public_export_and_cold_reopen_are_exact(self):
        transaction, witness, _, _ = self.signed_spend()
        receipt = self.ledger.apply(transaction, witness)
        exported = self.ledger.export_public()
        reopened = Ledger.from_public(copy.deepcopy(exported))
        self.assertEqual(reopened.export_public(), exported)
        self.assertEqual(
            reopened.recover_receipt(receipt["txid"]),
            receipt,
        )

    def test_lost_reply_recovers_original_receipt_after_reopen(self):
        transaction, witness, _, _ = self.signed_spend()
        committed = self.ledger.apply(transaction, witness)
        txid = transaction_id(transaction)
        reopened = Ledger.from_public(self.ledger.export_public())
        self.assertEqual(reopened.recover_receipt(txid), committed)
        self.assertEqual(reopened.apply(transaction, None), committed)

    def test_caller_mutation_during_reopen_cannot_corrupt_returned_state(self):
        transaction, witness, _, _ = self.signed_spend()
        receipt = self.ledger.apply(transaction, witness)
        exported = self.ledger.export_public()
        original_signature = exported["transactions"][0]["signature"]
        reached_history_validation = threading.Event()
        resume = threading.Event()
        call_lock = threading.Lock()
        calls = 0
        original_validate = lab._validated_transaction

        def pause_after_validation(candidate):
            nonlocal calls
            result = original_validate(candidate)
            with call_lock:
                calls += 1
                first = calls == 1
            if first:
                reached_history_validation.set()
                if not resume.wait(timeout=5):
                    raise AssertionError("reopen mutation synchronization timed out")
            return result

        with patch.object(
            lab, "_validated_transaction", side_effect=pause_after_validation
        ):
            with ThreadPoolExecutor(max_workers=1) as pool:
                future = pool.submit(Ledger.from_public, exported)
                self.assertTrue(reached_history_validation.wait(timeout=5))
                exported["transactions"][0]["signature"] = "0" * 128
                resume.set()
                reopened = future.result(timeout=5)

        retained = reopened.transactions[receipt["txid"]]
        self.assertEqual(retained["signature"], original_signature)
        self.assertNotEqual(
            retained["signature"], exported["transactions"][0]["signature"]
        )
        second_reopen = Ledger.from_public(reopened.export_public())
        self.assertEqual(
            second_reopen.recover_receipt(receipt["txid"]),
            receipt,
        )

    def test_reopen_rejects_transaction_tamper(self):
        transaction, witness, _, _ = self.signed_spend()
        self.ledger.apply(transaction, witness)
        exported = self.ledger.export_public()
        tampered = copy.deepcopy(exported)
        tampered["transactions"][0]["signature"] = "0" * 128
        with self.assertRaises(NoteError):
            Ledger.from_public(tampered)

    def test_reopen_rejects_receipt_tamper(self):
        transaction, witness, _, _ = self.signed_spend()
        self.ledger.apply(transaction, witness)
        exported = self.ledger.export_public()
        for field, value in (("root", "0" * 64), ("fee", 2), ("height", 8)):
            with self.subTest(field=field):
                tampered = copy.deepcopy(exported)
                tampered["receipts"][0][field] = value
                with self.assertRaises(NoteError):
                    Ledger.from_public(tampered)

    def test_reopen_rejects_root_and_nullifier_tamper(self):
        transaction, witness, _, _ = self.signed_spend()
        self.ledger.apply(transaction, witness)
        exported = self.ledger.export_public()
        wrong_root = copy.deepcopy(exported)
        wrong_root["root"] = "0" * 64
        with self.assertRaises(NoteError):
            Ledger.from_public(wrong_root)
        wrong_nullifier = copy.deepcopy(exported)
        wrong_nullifier["spent_nullifiers"] = ["0" * 64]
        with self.assertRaises(NoteError):
            Ledger.from_public(wrong_nullifier)

    def test_shared_state_and_independent_clone_semantics_are_explicit(self):
        first, first_witness, _, _ = self.signed_spend(variant=0)
        second, second_witness, _, _ = self.signed_spend(variant=3)
        clone_a = copy.deepcopy(self.ledger)
        clone_b = copy.deepcopy(self.ledger)
        receipt_a = clone_a.apply(first, first_witness)
        receipt_b = clone_b.apply(second, second_witness)
        self.assertNotEqual(receipt_a["txid"], receipt_b["txid"])
        self.assertEqual(receipt_a["execution_scope"], lab.EXECUTION_SCOPE)
        self.ledger.apply(first, first_witness)
        with self.assertRaises(NoteError):
            self.ledger.apply(second, second_witness)

    def test_concurrent_shared_ledger_accepts_only_one_competing_spend(self):
        first, first_witness, _, _ = self.signed_spend(variant=0)
        second, second_witness, _, _ = self.signed_spend(variant=4)
        start = threading.Barrier(2)
        precommit = threading.Barrier(2)
        original_receipt = lab._receipt

        def overlap_if_unlocked(*arguments):
            try:
                precommit.wait(timeout=0.2)
            except threading.BrokenBarrierError:
                pass
            return original_receipt(*arguments)

        def attempt(transaction, witness):
            start.wait()
            try:
                return ("accepted", self.ledger.apply(transaction, witness))
            except NoteError as exc:
                return ("refused", str(exc))

        with patch.object(lab, "_receipt", side_effect=overlap_if_unlocked):
            with ThreadPoolExecutor(max_workers=2) as pool:
                futures = (
                    pool.submit(attempt, first, first_witness),
                    pool.submit(attempt, second, second_witness),
                )
                results = [future.result(timeout=5) for future in futures]
        self.assertEqual(
            sorted(result[0] for result in results),
            ["accepted", "refused"],
        )
        self.assertEqual(len(self.ledger.transactions), 1)
        self.assertEqual(len(self.ledger.receipts), 1)
        self.assertEqual(len(self.ledger.spent), 1)

    def test_caller_mutation_after_validation_cannot_corrupt_retained_state(self):
        transaction, witness, _, _ = self.signed_spend()
        original_signature = transaction["signature"]
        reached_witness_validation = threading.Event()
        resume = threading.Event()
        call_lock = threading.Lock()
        calls = 0
        original_commitment = lab.note_commitment

        def pause_first_commitment(note):
            nonlocal calls
            with call_lock:
                calls += 1
                first = calls == 1
            if first:
                reached_witness_validation.set()
                if not resume.wait(timeout=5):
                    raise AssertionError("mutation synchronization timed out")
            return original_commitment(note)

        with patch.object(lab, "note_commitment", side_effect=pause_first_commitment):
            with ThreadPoolExecutor(max_workers=1) as pool:
                future = pool.submit(self.ledger.apply, transaction, witness)
                self.assertTrue(reached_witness_validation.wait(timeout=5))
                transaction["signature"] = "0" * 128
                resume.set()
                receipt = future.result(timeout=5)

        retained = self.ledger.transactions[receipt["txid"]]
        self.assertEqual(retained["signature"], original_signature)
        self.assertNotEqual(retained["signature"], transaction["signature"])
        reopened = Ledger.from_public(self.ledger.export_public())
        self.assertEqual(reopened.recover_receipt(receipt["txid"]), receipt)

    def test_multi_hop_reopen_recovery_and_earlier_disclosure(self):
        first_tx, first_witness, first_outputs, first_secrets = self.signed_spend(
            variant=0
        )
        first_receipt = self.ledger.apply(first_tx, first_witness)
        early_bundle = self.ledger.disclose(
            first_receipt["txid"], 0, first_outputs[0]
        )
        self.ledger.advance_height(8)
        second_tx, second_witness, _, _ = self.signed_spend(
            input_note=first_outputs[0],
            input_secret=first_secrets[0],
            position=1,
            output_values=(6, 1),
            fee=1,
            variant=5,
            signing_key=self.key2,
        )
        second_receipt = self.ledger.apply(second_tx, second_witness)
        reopened = Ledger.from_public(self.ledger.export_public())
        self.assertEqual(
            reopened.recover_receipt(first_receipt["txid"]),
            first_receipt,
        )
        self.assertEqual(
            reopened.recover_receipt(second_receipt["txid"]),
            second_receipt,
        )
        self.assertTrue(reopened.verify_disclosure(early_bundle))
        self.assertEqual(len(reopened.transactions), 2)
        self.assertEqual(len(reopened.spent), 2)

    def test_selected_output_disclosure_verifies_against_receipt(self):
        transaction, witness, openings, _ = self.signed_spend()
        receipt = self.ledger.apply(transaction, witness)
        bundle = self.ledger.disclose(receipt["txid"], 0, openings[0])
        self.assertTrue(self.ledger.verify_disclosure(bundle))
        self.assertTrue(verify_disclosure(bundle, receipt))
        self.assertEqual(bundle["opening"], openings[0])
        self.assertEqual(bundle["linkability"], LINKABILITY)

    def test_disclosure_excludes_secrets_authority_and_unselected_outputs(self):
        transaction, witness, openings, output_secrets = self.signed_spend()
        receipt = self.ledger.apply(transaction, witness)
        bundle = disclose(receipt["txid"], 0, openings[0], receipt)
        raw = json.dumps(bundle, sort_keys=True)
        self.assertNotIn(self.input_secret, raw)
        self.assertNotIn(output_secrets[0], raw)
        self.assertNotIn(output_secrets[1], raw)
        self.assertNotIn(openings[1]["blinding"], raw)
        self.assertNotIn("private", raw.lower())
        self.assertEqual(set(bundle), lab.DISCLOSURE_FIELDS)

    def test_disclosure_tampering_is_refused(self):
        transaction, witness, openings, _ = self.signed_spend()
        receipt = self.ledger.apply(transaction, witness)
        bundle = self.ledger.disclose(receipt["txid"], 0, openings[0])
        mutations = []
        for field, value in (
            ("txid", "0" * 64),
            ("output_index", 1),
            ("receipt_commitment", "0" * 64),
            ("commitment", "0" * 64),
            ("linkability", "hidden"),
        ):
            candidate = copy.deepcopy(bundle)
            candidate[field] = value
            mutations.append(candidate)
        changed_opening = copy.deepcopy(bundle)
        changed_opening["opening"]["blinding"] = "0" * 64
        mutations.append(changed_opening)
        for candidate in mutations:
            with self.subTest(field=next(
                key for key in candidate
                if candidate.get(key) != bundle.get(key)
            )):
                with self.assertRaises(NoteError):
                    verify_disclosure(candidate, receipt)

    def test_public_artifacts_do_not_contain_private_witness_material(self):
        transaction, witness, openings, output_secrets = self.signed_spend()
        receipt = self.ledger.apply(transaction, witness)
        bundle = self.ledger.disclose(receipt["txid"], 0, openings[0])
        ordinary = json.dumps(
            {
                "transaction": transaction,
                "receipt": receipt,
                "state": self.ledger.export_public(),
            },
            sort_keys=True,
        )
        disclosed = json.dumps(bundle, sort_keys=True)
        private_values = (
            self.input_secret,
            output_secrets[0],
            output_secrets[1],
            (b"a" * 32).hex(),
            (b"b" * 32).hex(),
            self.input_note["blinding"],
        )
        for value in private_values:
            self.assertNotIn(value, ordinary)
            self.assertNotIn(value, disclosed)
        self.assertNotIn(openings[0]["blinding"], ordinary)
        self.assertIn(openings[0]["blinding"], disclosed)
        self.assertNotIn(openings[1]["blinding"], disclosed)
        self.assertNotIn('"path"', ordinary)
        self.assertNotIn('"witness"', ordinary)

    def test_process_level_fixed_vector_is_deterministic(self):
        code = """
import json
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from shielded_note_lab import make_note, nullifier, secret_commitment, tree_root
key = Ed25519PrivateKey.from_private_bytes(b'a' * 32)
pub = key.public_key().public_bytes_raw().hex()
secret = '1' * 64
note, commitment = make_note(
    genesis='a' * 64, asset='1S', value=10, spend_key=pub,
    incoming_view_key='b' * 64, outgoing_view_key='c' * 64,
    epoch=0, policy_commitment='e' * 64, expiry=100,
    secret_commitment=secret_commitment(secret), blinding='d' * 64)
print(json.dumps({
    'commitment': commitment,
    'root': tree_root([commitment]),
    'nullifier': nullifier(secret, commitment, 0, 'lab-context')},
    sort_keys=True))
"""
        environment = dict(os.environ)
        environment["PYTHONPATH"] = str(Path(lab.__file__).parent)
        result = subprocess.run(
            [sys.executable, "-c", code],
            capture_output=True,
            text=True,
            env=environment,
            check=False,
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(
            json.loads(result.stdout),
            {
                "commitment": self.input_commitment,
                "root": tree_root([self.input_commitment]),
                "nullifier": nullifier(
                    self.input_secret,
                    self.input_commitment,
                    0,
                    self.context,
                ),
            },
        )

    def test_network_access_is_denied(self):
        if os.environ.get("1SOFT_SHIELDED_OFFLINE") == "1":
            with self.assertRaisesRegex(RuntimeError, "network blocked"):
                socket.getaddrinfo("example.invalid", 443)
            with self.assertRaisesRegex(RuntimeError, "network blocked"):
                socket.create_connection(("127.0.0.1", 9))
            return
        source = Path(lab.__file__).read_text(encoding="utf-8")
        imports = {
            node.names[0].name.split(".", 1)[0]
            for node in ast.walk(ast.parse(source))
            if isinstance(node, ast.Import)
        }
        imports.update(
            node.module.split(".", 1)[0]
            for node in ast.walk(ast.parse(source))
            if isinstance(node, ast.ImportFrom) and node.module
        )
        self.assertTrue(
            imports.isdisjoint(
                {"socket", "urllib", "http", "requests", "aiohttp"}
            )
        )


if __name__ == "__main__":
    unittest.main()
