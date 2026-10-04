from __future__ import annotations

import base64
import copy
import hashlib
import os
from pathlib import Path
import sqlite3
import struct
import tempfile
import unittest
from unittest.mock import patch

from protocol5_controller import PROVER_MAGIC
from protocol5_encoding import (
    TX_MAGIC, Transaction, canonical_json, decode_canonical_json, field_hex,
    genesis_document, transaction_id,
)
from protocol5_fixture import make_genesis, make_limits
from protocol5_note_capsule import NOTE_CAPSULE_FORMAT
from protocol5_wallet import Protocol5Wallet, Protocol5WalletError


def field(number):
    return number.to_bytes(32, "little")


def field_text(number):
    return field_hex(field(number))


def capsule_bytes(genesis_raw, *, commitment, owner_key, secret, blinding,
                  value=100, expiry=32, position=0, origin=None):
    genesis = genesis_document(genesis_raw)
    value_object = {
        "format": NOTE_CAPSULE_FORMAT, "version": 1,
        "capsule_id": "00" * 32,
        "genesis_sha256": genesis.sha256.hex(),
        "profile_id": genesis.profile.identity.hex(),
        "deployment_id": genesis.deployment.identity.hex(),
        "origin": (
            {"kind": "genesis", "position": position}
            if origin is None else origin),
        "commitment": commitment, "owner_key": owner_key.hex(),
        "expiry": expiry, "value": value,
        "note_secret": secret.hex(), "blinding": blinding.hex(),
    }
    projected = dict(value_object)
    projected.pop("capsule_id")
    value_object["capsule_id"] = hashlib.sha256(
        b"1soft/protocol5-note-capsule-id/v1\0"
        + canonical_json(projected)).hexdigest()
    return canonical_json(value_object)


class FakeController:
    def __init__(self, genesis_raw, spend_secret, owner_key, commitment):
        self.genesis = genesis_document(genesis_raw)
        self.prefix = self.genesis.value
        self.spend_secret = spend_secret
        self.owner_key = owner_key
        self.commitment = commitment
        self.prove_calls = 0
        self.client_calls = 0

    def derive_owner_key(self, secret):
        self.client_calls += 1
        if secret != self.spend_secret:
            raise ValueError("wrong secret")
        return self.owner_key

    def commitments(self, notes):
        self.client_calls += 1
        if len(notes) != 1:
            raise ValueError("one note")
        commitment = (
            self.commitment if notes[0].note_secret == field(6)
            else field_text(72)
        )
        return [commitment], field_text(90)

    def derive_note_nullifier(self, commitment, position, spend_secret,
                              note_secret):
        self.client_calls += 1
        if (type(commitment) is not bytes or len(commitment) != 32
                or type(position) is not int or not 0 <= position < 16
                or spend_secret != self.spend_secret
                or type(note_secret) is not bytes or len(note_secret) != 32):
            raise ValueError("invalid nullifier request")
        return field(70) if commitment.hex() == self.commitment else field(74)

    def spend_to_recipient_keys(self, genesis_raw, commitments, position,
                                input_note, outputs, *, valid_from, valid_until):
        self.client_calls += 1
        public = [
            field(1),
            bytes.fromhex(self.genesis.value["genesis_field"]),
            bytes.fromhex(self.genesis.value["asset_field"]),
            bytes.fromhex(self.genesis.value["context_field"]),
            self.genesis.value["authority_epoch"].to_bytes(32, "little"),
            valid_from.to_bytes(32, "little"),
            valid_until.to_bytes(32, "little"),
            bytes.fromhex(self.genesis.value["policy_field"]),
            field(90),
            field(70),
            field(71),
            field(72),
            self.genesis.value["fee"].to_bytes(32, "little"),
            field(73),
        ]
        witness = (
            b"1SFTWIT1" + struct.pack(
                "<HIHQQ", 1, 1, position,
                input_note.value, input_note.expiry,
            )
            + input_note.blinding
            + input_note.owner_spend_secret
            + input_note.note_secret
            + b"\0" * (4 * 32)
            + struct.pack("<QQ", outputs[0].value, outputs[1].value)
            + struct.pack("<QQ", outputs[0].expiry, outputs[1].expiry)
            + b"".join(output.owner_key for output in outputs)
            + b"".join(output.note_secret for output in outputs)
            + b"".join(output.blinding for output in outputs)
        )
        if len(witness) != 480:
            raise AssertionError("fixture witness length differs")
        return (
            PROVER_MAGIC + struct.pack("<HHI", 1, 1, 1)
            + self.genesis.sha256 + self.genesis.deployment.identity
            + struct.pack("<H", 14) + b"".join(public)
            + witness
        )

    def prove(self, genesis_raw, request):
        self.prove_calls += 1
        fields = tuple(
            request[82 + index * 32:114 + index * 32]
            for index in range(14))
        proof = b"\xa5" * self.genesis.profile.proof_length
        return (
            TX_MAGIC + struct.pack("<HHI", 1, 1, 1)
            + self.genesis.sha256 + self.genesis.deployment.identity
            + struct.pack("<H", 14) + b"".join(fields)
            + struct.pack("<I", len(proof)) + proof
        )


class CrashAfterCommitWallet(Protocol5Wallet):
    def _approval_committed(self, _decision_id):
        raise RuntimeError("lost return")


class ExitAfterCommitWallet(Protocol5Wallet):
    def _approval_committed(self, _decision_id):
        os._exit(73)


class UnavailableController:
    def __getattr__(self, name):
        raise RuntimeError("controller unavailable: " + name)


class Protocol5WalletTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.root.chmod(0o700)
        self.secret = field(3)
        self.owner_key = field(4)
        self.commitment = field_text(5)
        genesis = make_genesis(initial_commitments=[self.commitment])
        self.genesis_raw = canonical_json(genesis)
        self.engine_genesis = {"fixture": "engine"}
        self.controller = FakeController(
            self.genesis_raw, self.secret, self.owner_key, self.commitment)
        self.path = self.root / "wallet.sqlite"
        self.capsule = capsule_bytes(
            self.genesis_raw, commitment=self.commitment,
            owner_key=self.owner_key, secret=field(6), blinding=field(7))
        self.witness = {
            "genesis": genesis, "height": 0, "app_hash": "11" * 32,
            "state": {
                "version": 1,
                "profile_id": genesis["profile_id"],
                "deployment_id": genesis["deployment_id"],
                "commitments": [self.commitment],
                "current_root": field_text(90),
                "root_history": [],
                "spent_nullifiers": [],
                "receipts": [],
                "execution_blocks": [],
            },
        }
        self.observation = {
            "format": "1soft/protocol5-state-observation/v1",
            "state_witness": self.witness,
            "signed_header": {"fixture": True},
        }
        self.observation_raw = canonical_json(self.observation)
        self.auth_patch = patch(
            "protocol5_wallet.authenticate_observation",
            side_effect=lambda raw, *_: self.fake_authenticate(raw))
        self.extend_patch = patch(
            "protocol5_wallet.extends_observation", return_value=None)
        self.auth_patch.start()
        self.extend_patch.start()
        self.wallet = Protocol5Wallet(
            self.path, self.genesis_raw, self.engine_genesis,
            self.controller, create=True, spend_secret=self.secret)

    def fake_authenticate(self, raw):
        observation = decode_canonical_json(raw)
        witness = observation["state_witness"]
        return (
            observation,
            {"state_height": witness["height"],
             "header_height": witness["height"] + 1,
             "app_hash": witness["app_hash"]},
        )

    def tearDown(self):
        self.wallet.close()
        self.auth_patch.stop()
        self.extend_patch.stop()
        self.temp.cleanup()

    def bootstrap(self):
        revision = self.wallet.status()["revision"]
        self.wallet.sync(
            self.observation_raw, expected_revision=revision)
        revision = self.wallet.status()["revision"]
        return self.wallet.import_note(
            self.capsule, self.secret, expected_revision=revision)

    def execution_observation(self, decision_id, *, mode="exact",
                              result_code=0):
        original = self.wallet.recover(decision_id)
        decoded = Transaction.decode(
            original, genesis_document(self.genesis_raw))
        fields = list(decoded.public_fields)
        if mode == "conflict":
            fields[10] = field(75)
            fields[11] = field(76)
        proof = (
            b"\xa5" if mode == "exact" else b"\xa6"
        ) * self.controller.genesis.profile.proof_length
        winner = (
            TX_MAGIC + struct.pack("<HHI", 1, 1, 1)
            + self.controller.genesis.sha256
            + self.controller.genesis.deployment.identity
            + struct.pack("<H", 14) + b"".join(fields)
            + struct.pack("<I", len(proof)) + proof
        )
        txid = transaction_id(winner).hex()
        state = copy.deepcopy(self.witness["state"])
        state["commitments"] = [
            self.commitment, fields[10].hex(), fields[11].hex()]
        state["current_root"] = field_text(91)
        state["spent_nullifiers"] = [fields[9].hex()]
        state["receipts"] = [{
            "txid": txid,
            "profile_id": self.controller.genesis.profile.identity.hex(),
            "deployment_id": self.controller.genesis.deployment.identity.hex(),
            "height": 1, "tx_index": 0,
            "anchor_root": fields[8].hex(),
            "tree_root_before": field_text(90),
            "tree_root_after": field_text(91),
            "nullifier": fields[9].hex(),
            "output_commitment_0": fields[10].hex(),
            "output_commitment_1": fields[11].hex(),
            "output_position_0": 1, "output_position_1": 2,
            "fee": int.from_bytes(fields[12], "little"),
        }]
        result = {
            "code": result_code,
            "log": "" if result_code == 0 else "rejected",
            "data": txid if result_code == 0 else "",
        }
        state["execution_blocks"] = [{
            "height": 1,
            "transactions": [base64.b64encode(winner).decode("ascii")],
            "results": [result],
        }]
        witness = {
            "genesis": self.witness["genesis"],
            "height": 1, "app_hash": "22" * 32, "state": state,
        }
        return canonical_json({
            "format": "1soft/protocol5-state-observation/v1",
            "state_witness": witness,
            "signed_header": {"fixture": "execution"},
        }), txid

    def test_prepare_is_mutation_free_and_approval_persists_exact_transaction(self):
        imported = self.bootstrap()
        before = list(self.wallet.db.iterdump())
        prepared = self.wallet.prepare(
            note_id=imported["capsule_id"],
            recipient_owner_key=field_text(10),
            value=20, valid_until=20)
        self.assertEqual(list(self.wallet.db.iterdump()), before)
        self.assertFalse(prepared["reserved"])
        approved = self.wallet.approve(
            prepared["review"], prepared["confirmation"])
        recovered = self.wallet.recover(approved["decision_id"])
        self.assertEqual(transaction_id(recovered).hex(), approved["txid"])
        self.assertEqual(self.controller.prove_calls, 1)
        status = self.wallet.status()
        self.assertEqual(status["notes"][0]["state"], "reserved")
        self.assertNotIn(self.secret.hex(), canonical_json(status).decode())

    def test_lost_approval_return_recovers_without_reproving(self):
        imported = self.bootstrap()
        prepared = self.wallet.prepare(
            note_id=imported["capsule_id"],
            recipient_owner_key=field_text(10),
            value=20, valid_until=20)
        self.wallet.close()
        self.wallet = CrashAfterCommitWallet(
            self.path, self.genesis_raw, self.engine_genesis,
            self.controller)
        with self.assertRaisesRegex(RuntimeError, "lost return"):
            self.wallet.approve(
                prepared["review"], prepared["confirmation"])
        self.assertEqual(self.controller.prove_calls, 1)
        self.wallet.close()
        self.wallet = Protocol5Wallet(
            self.path, self.genesis_raw, self.engine_genesis,
            self.controller)
        decision = self.wallet.status()["decisions"][0]
        raw = self.wallet.recover(decision["decision_id"])
        self.assertEqual(transaction_id(raw).hex(), decision["txid"])
        self.assertEqual(self.controller.prove_calls, 1)

    def test_process_exit_after_commit_recovers_exact_transaction(self):
        imported = self.bootstrap()
        prepared = self.wallet.prepare(
            note_id=imported["capsule_id"],
            recipient_owner_key=field_text(10),
            value=20, valid_until=20)
        self.wallet.close()
        pid = os.fork()
        if pid == 0:
            child_wallet = ExitAfterCommitWallet(
                self.path, self.genesis_raw, self.engine_genesis,
                self.controller)
            child_wallet.approve(
                prepared["review"], prepared["confirmation"])
            os._exit(74)
        _, status = os.waitpid(pid, 0)
        self.assertEqual(os.waitstatus_to_exitcode(status), 73)
        self.wallet = Protocol5Wallet(
            self.path, self.genesis_raw, self.engine_genesis,
            self.controller)
        decision = self.wallet.status()["decisions"][0]
        recovered = self.wallet.recover(decision["decision_id"])
        self.assertEqual(transaction_id(recovered).hex(), decision["txid"])

    def test_revision_cas_and_same_observation_noop(self):
        revision = self.wallet.status()["revision"]
        result = self.wallet.sync(
            self.observation_raw, expected_revision=revision)
        current = result["revision"]
        duplicate = self.wallet.sync(
            self.observation_raw, expected_revision=current)
        self.assertEqual(duplicate["status"], "already_recorded")
        with self.assertRaises(Protocol5WalletError):
            self.wallet.import_note(
                self.capsule, self.secret, expected_revision=revision)

    def test_second_writer_and_unsafe_mode_are_refused(self):
        with self.assertRaisesRegex(Protocol5WalletError, "already open"):
            Protocol5Wallet(
                self.path, self.genesis_raw, self.engine_genesis,
                self.controller)
        self.wallet.close()
        self.path.chmod(0o640)
        with self.assertRaisesRegex(Protocol5WalletError, "unsafe"):
            Protocol5Wallet(
                self.path, self.genesis_raw, self.engine_genesis,
                self.controller)
        self.path.chmod(0o600)
        self.wallet = Protocol5Wallet(
            self.path, self.genesis_raw, self.engine_genesis,
            self.controller)

    def test_corrupt_transaction_never_erases_hold(self):
        imported = self.bootstrap()
        prepared = self.wallet.prepare(
            note_id=imported["capsule_id"],
            recipient_owner_key=field_text(10),
            value=20, valid_until=20)
        approved = self.wallet.approve(
            prepared["review"], prepared["confirmation"])
        raw = self.wallet.recover(approved["decision_id"])
        changed = bytearray(raw)
        changed[-1] ^= 1
        self.wallet.db.execute(
            "UPDATE decisions SET transaction_bytes=? WHERE decision_id=?",
            (bytes(changed), approved["decision_id"]))
        with self.assertRaises(Protocol5WalletError):
            self.wallet.status()

    def test_failed_create_never_deletes_preexisting_database(self):
        sentinel = self.root / "sentinel.sqlite"
        sentinel.write_bytes(b"preexisting-wallet-sentinel")
        sentinel.chmod(0o600)
        with self.assertRaises(OSError):
            Protocol5Wallet(
                sentinel, self.genesis_raw, self.engine_genesis,
                self.controller, create=True, spend_secret=self.secret)
        self.assertEqual(sentinel.read_bytes(), b"preexisting-wallet-sentinel")
        self.assertFalse(Path(str(sentinel) + ".lock").exists())

    def test_deleted_decision_is_detected_on_reopen(self):
        imported = self.bootstrap()
        prepared = self.wallet.prepare(
            note_id=imported["capsule_id"],
            recipient_owner_key=field_text(10),
            value=20, valid_until=20)
        self.wallet.approve(prepared["review"], prepared["confirmation"])
        self.wallet.close()
        with sqlite3.connect(self.path) as database:
            database.execute("DELETE FROM decisions")
        with self.assertRaises(Protocol5WalletError):
            Protocol5Wallet(
                self.path, self.genesis_raw, self.engine_genesis,
                self.controller)

    def test_prepare_and_recover_invoke_no_controller_operations(self):
        imported = self.bootstrap()
        before_prepare = self.controller.client_calls
        prepared = self.wallet.prepare(
            note_id=imported["capsule_id"],
            recipient_owner_key=field_text(10),
            value=20, valid_until=20)
        self.assertEqual(self.controller.client_calls, before_prepare)
        approved = self.wallet.approve(
            prepared["review"], prepared["confirmation"])
        before_recover = self.controller.client_calls
        recovered = self.wallet.recover(approved["decision_id"])
        self.assertEqual(self.controller.client_calls, before_recover)
        self.assertEqual(transaction_id(recovered).hex(), approved["txid"])

    def test_reopen_and_recover_survive_unavailable_controller(self):
        imported = self.bootstrap()
        prepared = self.wallet.prepare(
            note_id=imported["capsule_id"],
            recipient_owner_key=field_text(10),
            value=20, valid_until=20)
        approved = self.wallet.approve(
            prepared["review"], prepared["confirmation"])
        expected = self.wallet.recover(approved["decision_id"])
        self.wallet.close()
        self.wallet = Protocol5Wallet(
            self.path, self.genesis_raw, self.engine_genesis,
            UnavailableController())
        self.assertEqual(
            self.wallet.recover(approved["decision_id"]), expected)

    def test_expired_low_value_note_is_retained_and_duplicate_is_noop(self):
        revision = self.wallet.status()["revision"]
        self.wallet.sync(self.observation_raw, expected_revision=revision)
        raw = capsule_bytes(
            self.genesis_raw, commitment=self.commitment,
            owner_key=self.owner_key, secret=field(6), blinding=field(7),
            value=1, expiry=1)
        revision = self.wallet.status()["revision"]
        imported = self.wallet.import_note(
            raw, self.secret, expected_revision=revision)
        status = self.wallet.status()
        self.assertEqual(status["notes"][0]["state"], "expired")
        calls = self.controller.client_calls
        duplicate = self.wallet.import_note(
            raw, self.secret, expected_revision=status["revision"])
        self.assertEqual(duplicate["status"], "already_imported")
        self.assertEqual(self.controller.client_calls, calls)
        self.assertEqual(duplicate["capsule_id"], imported["capsule_id"])

    def test_duplicate_import_rejects_wrong_secret_without_controller_call(self):
        imported = self.bootstrap()
        revision = self.wallet.status()["revision"]
        before_calls = self.controller.client_calls
        before_dump = list(self.wallet.db.iterdump())
        for wrong in (field(99), b"", b"\0" * 32, b"\xff" * 32):
            with self.subTest(secret=wrong):
                with self.assertRaises(Protocol5WalletError):
                    self.wallet.import_note(
                        self.capsule, wrong, expected_revision=revision)
        self.assertEqual(self.controller.client_calls, before_calls)
        self.assertEqual(list(self.wallet.db.iterdump()), before_dump)
        duplicate = self.wallet.import_note(
            self.capsule, self.secret, expected_revision=revision)
        self.assertEqual(duplicate["status"], "already_imported")
        self.assertEqual(duplicate["capsule_id"], imported["capsule_id"])
        self.assertEqual(self.controller.client_calls, before_calls)

    def test_final_capacity_note_import_uses_nullifier_only_opcode(self):
        initial = [field_text(100 + index) for index in range(14)]
        genesis = make_genesis(
            initial_commitments=initial,
            limits=make_limits(max_accepted_transactions=1),
        )
        genesis_raw = canonical_json(genesis)
        controller = FakeController(
            genesis_raw, self.secret, self.owner_key, self.commitment)
        path = self.root / "full-tree-wallet.sqlite"
        fields = [
            field(1), bytes.fromhex(genesis["genesis_field"]),
            bytes.fromhex(genesis["asset_field"]),
            bytes.fromhex(genesis["context_field"]),
            genesis["authority_epoch"].to_bytes(32, "little"),
            field(1), field(20), bytes.fromhex(genesis["policy_field"]),
            field(90), field(69), field(75), bytes.fromhex(self.commitment),
            genesis["fee"].to_bytes(32, "little"), field(73),
        ]
        proof = b"\xa5" * controller.genesis.profile.proof_length
        transaction = (
            TX_MAGIC + struct.pack("<HHI", 1, 1, 1)
            + controller.genesis.sha256
            + controller.genesis.deployment.identity
            + struct.pack("<H", 14) + b"".join(fields)
            + struct.pack("<I", len(proof)) + proof
        )
        txid = transaction_id(transaction).hex()
        raw = capsule_bytes(
            genesis_raw, commitment=self.commitment,
            owner_key=self.owner_key, secret=field(6), blinding=field(7),
            origin={"kind": "transaction", "txid": txid,
                    "output_index": 1})
        commitments = initial + [field_text(75), self.commitment]
        witness = {
            "genesis": genesis, "height": 0, "app_hash": "33" * 32,
            "state": {
                "version": 1, "profile_id": genesis["profile_id"],
                "deployment_id": genesis["deployment_id"],
                "commitments": commitments,
                "current_root": field_text(90), "root_history": [],
                "spent_nullifiers": [field_text(69)],
                "receipts": [{
                    "txid": txid, "profile_id": genesis["profile_id"],
                    "deployment_id": genesis["deployment_id"],
                    "height": 1, "tx_index": 0,
                    "anchor_root": field_text(90),
                    "tree_root_before": field_text(90),
                    "tree_root_after": field_text(91),
                    "nullifier": field_text(69),
                    "output_commitment_0": field_text(75),
                    "output_commitment_1": self.commitment,
                    "output_position_0": 14, "output_position_1": 15,
                    "fee": genesis["fee"],
                }],
                "execution_blocks": [{
                    "height": 1,
                    "transactions": [
                        base64.b64encode(transaction).decode("ascii")],
                    "results": [{"code": 0, "log": "", "data": txid}],
                }],
            },
        }
        witness["height"] = 1
        observation = canonical_json({
            "format": "1soft/protocol5-state-observation/v1",
            "state_witness": witness,
            "signed_header": {"fixture": "full"},
        })
        with Protocol5Wallet(
                path, genesis_raw, self.engine_genesis, controller,
                create=True, spend_secret=self.secret) as wallet:
            revision = wallet.status()["revision"]
            wallet.sync(observation, expected_revision=revision)
            revision = wallet.status()["revision"]
            imported = wallet.import_note(
                raw, self.secret, expected_revision=revision)
            self.assertEqual(imported["nullifier"], field_text(70))
            self.assertEqual(wallet.status()["notes"][0]["chain_position"], 15)

    def test_exact_execution_atomically_admits_change_and_exports_payment(self):
        imported = self.bootstrap()
        prepared = self.wallet.prepare(
            note_id=imported["capsule_id"],
            recipient_owner_key=field_text(10),
            value=20, valid_until=20)
        approved = self.wallet.approve(
            prepared["review"], prepared["confirmation"])
        observation, winning_txid = self.execution_observation(
            approved["decision_id"], mode="exact")
        revision = self.wallet.status()["revision"]
        self.wallet.sync(observation, expected_revision=revision)
        status = self.wallet.status()
        self.assertEqual(len(status["notes"]), 2)
        self.assertEqual({row["state"] for row in status["notes"]},
                         {"spent", "spendable"})
        payment = decode_canonical_json(
            self.wallet.export_capsule(approved["decision_id"], 0))
        self.assertEqual(payment["origin"]["txid"], winning_txid)
        with self.assertRaises(Protocol5WalletError):
            self.wallet.export_capsule(approved["decision_id"], 1)

    def test_equivalent_execution_rewrites_capsule_origin(self):
        imported = self.bootstrap()
        prepared = self.wallet.prepare(
            note_id=imported["capsule_id"],
            recipient_owner_key=field_text(10),
            value=20, valid_until=20)
        approved = self.wallet.approve(
            prepared["review"], prepared["confirmation"])
        observation, winning_txid = self.execution_observation(
            approved["decision_id"], mode="equivalent")
        revision = self.wallet.status()["revision"]
        self.wallet.sync(observation, expected_revision=revision)
        status = self.wallet.status()
        self.assertEqual(status["decisions"][0]["state"],
                         "executed_equivalent")
        payment = decode_canonical_json(
            self.wallet.export_capsule(approved["decision_id"], 0))
        self.assertEqual(payment["origin"]["txid"], winning_txid)
        change = next(row for row in status["notes"]
                      if row["state"] == "spendable")
        self.assertEqual(change["commitment"], field_text(72))

    def test_conflicting_spend_never_admits_or_exports_expected_outputs(self):
        imported = self.bootstrap()
        prepared = self.wallet.prepare(
            note_id=imported["capsule_id"],
            recipient_owner_key=field_text(10),
            value=20, valid_until=20)
        approved = self.wallet.approve(
            prepared["review"], prepared["confirmation"])
        observation, _ = self.execution_observation(
            approved["decision_id"], mode="conflict")
        revision = self.wallet.status()["revision"]
        self.wallet.sync(observation, expected_revision=revision)
        status = self.wallet.status()
        self.assertEqual(len(status["notes"]), 1)
        self.assertEqual(status["decisions"][0]["state"],
                         "conflicting_spend")
        with self.assertRaises(Protocol5WalletError):
            self.wallet.export_capsule(approved["decision_id"], 0)

    def test_unsuccessful_retained_result_cannot_reconcile(self):
        imported = self.bootstrap()
        prepared = self.wallet.prepare(
            note_id=imported["capsule_id"],
            recipient_owner_key=field_text(10),
            value=20, valid_until=20)
        approved = self.wallet.approve(
            prepared["review"], prepared["confirmation"])
        observation, _ = self.execution_observation(
            approved["decision_id"], mode="exact", result_code=5)
        before = self.wallet.status()["revision"]
        with self.assertRaises(Protocol5WalletError):
            self.wallet.sync(observation, expected_revision=before)
        self.assertEqual(self.wallet.status()["revision"], before)


    def test_reopen_rejects_unknown_schema_object(self):
        self.wallet.close()
        with sqlite3.connect(self.path) as database:
            database.execute(
                "CREATE INDEX unauthorized_note_index ON notes(chain_position)")
        with self.assertRaisesRegex(
                Protocol5WalletError, "unrecognized wallet schema"):
            Protocol5Wallet(
                self.path, self.genesis_raw, self.engine_genesis,
                self.controller)

    def test_semantic_audit_rejects_changed_decision_input_after_reseal(self):
        imported = self.bootstrap()
        prepared = self.wallet.prepare(
            note_id=imported["capsule_id"],
            recipient_owner_key=field_text(10),
            value=20, valid_until=20)
        approved = self.wallet.approve(
            prepared["review"], prepared["confirmation"])
        observation, _ = self.execution_observation(
            approved["decision_id"], mode="exact")
        revision = self.wallet.status()["revision"]
        self.wallet.sync(observation, expected_revision=revision)
        change_id = next(
            row["capsule_id"] for row in self.wallet.status()["notes"]
            if row["state"] == "spendable")
        self.wallet.db.execute(
            "UPDATE decisions SET input_capsule_id=? WHERE decision_id=?",
            (change_id, approved["decision_id"]))
        self.wallet._seal()
        with self.assertRaisesRegex(
                Protocol5WalletError, "stored decision lineage differs"):
            self.wallet.status()

    def test_cryptographic_audit_rejects_changed_note_nullifier_after_reseal(self):
        self.bootstrap()
        self.wallet.db.execute(
            "UPDATE notes SET nullifier=?", (field(99),))
        self.wallet._seal()
        with self.assertRaisesRegex(
                Protocol5WalletError, "stored note nullifier differs"):
            self.wallet.status()

    def test_approval_capacity_refuses_before_controller_or_prover(self):
        imported = self.bootstrap()
        prepared = self.wallet.prepare(
            note_id=imported["capsule_id"],
            recipient_owner_key=field_text(10),
            value=20, valid_until=20)
        before_client = self.controller.client_calls
        before_prove = self.controller.prove_calls
        with patch("protocol5_wallet.MAX_DECISIONS", 0):
            with self.assertRaisesRegex(
                    Protocol5WalletError, "decision capacity"):
                self.wallet.approve(
                    prepared["review"], prepared["confirmation"])
        self.assertEqual(self.controller.client_calls, before_client)
        self.assertEqual(self.controller.prove_calls, before_prove)
        self.assertEqual(self.wallet.status()["decisions"], [])

    def test_checkpoint_change_during_proving_prevents_decision_commit(self):
        imported = self.bootstrap()
        prepared = self.wallet.prepare(
            note_id=imported["capsule_id"],
            recipient_owner_key=field_text(10),
            value=20, valid_until=20)
        expected_revision = self.wallet.status()["revision"]
        changed = copy.deepcopy(self.observation)
        changed["state_witness"]["height"] = 1
        changed["state_witness"]["app_hash"] = "44" * 32
        changed["signed_header"] = {"fixture": "changed-during-proof"}
        changed_raw = canonical_json(changed)
        original_prove = self.controller.prove
        invoked = False

        def prove_after_checkpoint_change(genesis_raw, request):
            nonlocal invoked
            if not invoked:
                invoked = True
                self.wallet.sync(
                    changed_raw, expected_revision=expected_revision)
            return original_prove(genesis_raw, request)

        with patch.object(
                self.controller, "prove",
                side_effect=prove_after_checkpoint_change):
            with self.assertRaisesRegex(
                    Protocol5WalletError, "revision changed"):
                self.wallet.approve(
                    prepared["review"], prepared["confirmation"])
        self.assertTrue(invoked)
        self.assertEqual(self.controller.prove_calls, 1)
        self.assertEqual(self.wallet.status()["decisions"], [])

    def test_delivery_record_is_structural_closed_and_revision_bound(self):
        imported = self.bootstrap()
        prepared = self.wallet.prepare(
            note_id=imported["capsule_id"],
            recipient_owner_key=field_text(10),
            value=20, valid_until=20)
        approved = self.wallet.approve(
            prepared["review"], prepared["confirmation"])
        revision = self.wallet.status()["revision"]
        before_calls = self.controller.client_calls
        record = self.wallet.delivery_record(
            approved["decision_id"], expected_revision=revision)
        self.assertEqual(self.controller.client_calls, before_calls)
        self.assertEqual(record["wallet_id"],
                         self.wallet.status()["wallet_id"])
        self.assertEqual(record["wallet_revision"], revision)
        self.assertEqual(record["decision_state"], "ready")
        self.assertEqual(record["txid"], approved["txid"])
        self.assertEqual(
            record["transaction_sha256"],
            hashlib.sha256(record["transaction_bytes"]).hexdigest())
        self.assertEqual(
            set(record),
            {
                "wallet_id", "wallet_revision", "decision_id",
                "decision_state", "txid", "transaction_sha256",
                "transaction_bytes", "nullifier",
            })
        self.assertNotIn("capsule", repr(record))
        with self.assertRaisesRegex(
                Protocol5WalletError, "revision changed"):
            self.wallet.delivery_record(
                approved["decision_id"], expected_revision="00" * 32)

    def test_continuity_resolves_lost_return_without_controller(self):
        imported = self.bootstrap()
        prepared = self.wallet.prepare(
            note_id=imported["capsule_id"],
            recipient_owner_key=field_text(10),
            value=20, valid_until=20)
        approved = self.wallet.approve(
            prepared["review"], prepared["confirmation"])
        self.wallet.close()
        self.wallet = Protocol5Wallet(
            self.path, self.genesis_raw, self.engine_genesis,
            UnavailableController())
        value = self.wallet.continuity()
        self.assertEqual(
            set(value), {
                "format", "wallet_id", "owner_key", "revision",
                "state_height", "decisions", "cryptographic_audit",
            })
        self.assertFalse(value["cryptographic_audit"])
        self.assertEqual(len(value["decisions"]), 1)
        self.assertEqual(value["decisions"][0], {
            "decision_id": approved["decision_id"],
            "review_id": prepared["review"]["review_id"],
            "txid": approved["txid"],
            "state": "ready",
        })
        self.assertEqual(
            self.wallet.recover(value["decisions"][0]["decision_id"]),
            self.wallet.delivery_record(
                approved["decision_id"])["transaction_bytes"])


if __name__ == "__main__":
    unittest.main()
