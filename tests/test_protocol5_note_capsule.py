from __future__ import annotations

import base64
from copy import deepcopy
import hashlib
import json
from pathlib import Path
import unittest

from protocol5_encoding import canonical_json, field_hex, transaction_id
from protocol5_fixture import make_genesis, make_public_fields, make_tx
from protocol5_note_capsule import (
    MAX_NOTE_CAPSULE_BYTES,
    NOTE_CAPSULE_FORMAT,
    NoteCapsuleError,
    capsule_id,
    decode_capsule,
    verify_capsule,
)


def _field(number: int) -> str:
    return field_hex(number.to_bytes(32, "little"))


def _with_capsule_id(value: dict) -> bytes:
    projected = dict(value)
    projected.pop("capsule_id", None)
    value = dict(projected)
    value["capsule_id"] = hashlib.sha256(
        b"1soft/protocol5-note-capsule-id/v1\0" + canonical_json(projected)
    ).hexdigest()
    return canonical_json(value)


class _Controller:
    def __init__(self, *, spend_secret: bytes, owner_key: bytes,
                 commitment: str, prefix: dict | None = None) -> None:
        self.spend_secret = spend_secret
        self.owner_key = owner_key
        self.commitment = commitment
        self.prefix = prefix
        self.calls: list[str] = []

    def derive_owner_key(self, spend_secret: bytes) -> bytes:
        self.calls.append("derive")
        if spend_secret != self.spend_secret:
            raise ValueError("unexpected owner secret")
        return self.owner_key

    def commitments(self, notes):
        self.calls.append("commitments")
        if len(notes) != 1:
            raise ValueError("one note required")
        note = notes[0]
        if len(note.encode()) != 112:
            raise ValueError("encoded note length differs")
        if (
            note.expiry,
            note.value,
            note.owner_spend_secret,
            note.note_secret,
            note.blinding,
        ) != (
            32,
            11,
            self.spend_secret,
            bytes.fromhex(_field(3)),
            bytes.fromhex(_field(4)),
        ):
            raise ValueError("note opening differs")
        return [self.commitment], _field(9)


class Protocol5NoteCapsuleTests(unittest.TestCase):
    def _transaction_case(self):
        spend_secret = bytes.fromhex(_field(1))
        owner_key = bytes.fromhex(_field(2))
        commitment = _field(5)
        genesis = make_genesis(initial_commitments=[_field(6)])
        genesis_raw = canonical_json(genesis)
        fields = list(make_public_fields(genesis))
        fields[10] = _field(7)
        fields[11] = commitment
        transaction = make_tx(genesis, fields=tuple(fields))
        txid = transaction_id(transaction).hex()
        capsule = {
            "format": NOTE_CAPSULE_FORMAT,
            "version": 1,
            "capsule_id": "00" * 32,
            "genesis_sha256": hashlib.sha256(genesis_raw).hexdigest(),
            "profile_id": genesis["profile_id"],
            "deployment_id": genesis["deployment_id"],
            "origin": {
                "kind": "transaction",
                "txid": txid,
                "output_index": 1,
            },
            "commitment": commitment,
            "owner_key": owner_key.hex(),
            "expiry": 32,
            "value": 11,
            "note_secret": _field(3),
            "blinding": _field(4),
        }
        receipt = {
            "txid": txid,
            "profile_id": genesis["profile_id"],
            "deployment_id": genesis["deployment_id"],
            "height": 4,
            "tx_index": 0,
            "anchor_root": fields[8],
            "tree_root_before": _field(11),
            "tree_root_after": _field(12),
            "nullifier": fields[9],
            "output_commitment_0": fields[10],
            "output_commitment_1": fields[11],
            "output_position_0": 1,
            "output_position_1": 2,
            "fee": genesis["fee"],
        }
        blocks = [
            {"height": height, "transactions": [], "results": []}
            for height in range(1, 4)
        ]
        blocks.append({
            "height": 4,
            "transactions": [base64.b64encode(transaction).decode("ascii")],
            "results": [{"code": 0, "log": "", "data": txid}],
        })
        authenticated_state = {
            "genesis": genesis,
            "height": 4,
            "app_hash": "cd" * 32,
            "state": {
                "version": 1,
                "profile_id": genesis["profile_id"],
                "deployment_id": genesis["deployment_id"],
                "commitments": [_field(6), fields[10], commitment],
                "receipts": [receipt],
                "execution_blocks": blocks,
            },
        }
        controller = _Controller(
            spend_secret=spend_secret,
            owner_key=owner_key,
            commitment=commitment,
            prefix=genesis,
        )
        return (
            capsule, _with_capsule_id(capsule), spend_secret,
            authenticated_state, controller, genesis_raw,
        )

    def test_transaction_capsule_requires_exact_authenticated_output(self):
        capsule, raw, spend_secret, state, controller, genesis_raw = (
            self._transaction_case())

        verified = verify_capsule(raw, spend_secret, state, controller)

        self.assertEqual(verified, decode_capsule(raw, genesis_raw))
        self.assertEqual(controller.calls, ["derive", "commitments"])
        self.assertNotIn("output_position", verified["origin"])
        self.assertNotIn("spendable", verified)

    def test_transaction_capsule_requires_retained_successful_wire(self):
        _, raw, spend_secret, state, controller, _ = self._transaction_case()
        mutations = []
        missing = deepcopy(state)
        missing["state"].pop("execution_blocks")
        mutations.append(missing)
        failed = deepcopy(state)
        failed["state"]["execution_blocks"][3]["results"][0] = {
            "code": 9, "log": "invalid shielded proof", "data": ""}
        mutations.append(failed)
        wrong_wire = deepcopy(state)
        raw_wire = base64.b64decode(
            wrong_wire["state"]["execution_blocks"][3]["transactions"][0])
        wrong_wire["state"]["execution_blocks"][3]["transactions"][0] = (
            base64.b64encode(raw_wire[:-1] + bytes([raw_wire[-1] ^ 1])).decode())
        mutations.append(wrong_wire)
        for changed in mutations:
            with self.subTest(changed=changed["state"].keys()):
                with self.assertRaises(NoteCapsuleError):
                    verify_capsule(raw, spend_secret, changed, controller)

    def test_genesis_capsule_requires_exact_initial_position(self):
        spend_secret = bytes.fromhex(_field(1))
        owner_key = bytes.fromhex(_field(2))
        commitment = _field(5)
        genesis = make_genesis(
            initial_commitments=[_field(6), commitment])
        genesis_raw = canonical_json(genesis)
        value = {
            "format": NOTE_CAPSULE_FORMAT,
            "version": 1,
            "capsule_id": "00" * 32,
            "genesis_sha256": hashlib.sha256(genesis_raw).hexdigest(),
            "profile_id": genesis["profile_id"],
            "deployment_id": genesis["deployment_id"],
            "origin": {"kind": "genesis", "position": 1},
            "commitment": commitment,
            "owner_key": owner_key.hex(),
            "expiry": 32,
            "value": 11,
            "note_secret": _field(3),
            "blinding": _field(4),
        }
        raw = _with_capsule_id(value)
        state = {
            "genesis": genesis,
            "height": 0,
            "app_hash": "ef" * 32,
            "state": {
                "version": 1,
                "profile_id": genesis["profile_id"],
                "deployment_id": genesis["deployment_id"],
                "commitments": [_field(6), commitment],
                "receipts": [],
                "execution_blocks": [],
            },
        }
        controller = _Controller(
            spend_secret=spend_secret, owner_key=owner_key,
            commitment=commitment, prefix=genesis)

        self.assertEqual(
            verify_capsule(raw, spend_secret, state, controller)["origin"],
            {"kind": "genesis", "position": 1},
        )
        changed = deepcopy(value)
        changed["origin"]["position"] = 0
        with self.assertRaises(NoteCapsuleError):
            verify_capsule(
                _with_capsule_id(changed), spend_secret, state, controller)

    def test_capsule_schema_identity_and_integer_rules_are_strict(self):
        capsule, raw, _, _, _, genesis_raw = self._transaction_case()
        self.assertEqual(MAX_NOTE_CAPSULE_BYTES, 2048)
        decoded_value = json.loads(raw)
        self.assertEqual(
            capsule_id(decoded_value), decoded_value["capsule_id"])
        without_id = dict(decoded_value)
        without_id.pop("capsule_id")
        self.assertEqual(
            capsule_id(without_id), decoded_value["capsule_id"])

        stale = bytearray(raw)
        stale[-2] = ord("5") if stale[-2] != ord("5") else ord("6")
        with self.assertRaises(NoteCapsuleError):
            decode_capsule(bytes(stale), genesis_raw)

        mutations = []
        source = deepcopy(capsule)
        source["source"] = source.pop("origin")
        mutations.append(source)
        claimed_position = deepcopy(capsule)
        claimed_position["origin"]["output_position"] = 2
        mutations.append(claimed_position)
        missing = deepcopy(capsule)
        missing.pop("blinding")
        mutations.append(missing)
        boolean = deepcopy(capsule)
        boolean["value"] = True
        mutations.append(boolean)
        zero = deepcopy(capsule)
        zero["note_secret"] = "00" * 32
        mutations.append(zero)
        uppercase = deepcopy(capsule)
        uppercase["commitment"] = _field(10).upper()
        mutations.append(uppercase)
        wrong_genesis = deepcopy(capsule)
        wrong_genesis["genesis_sha256"] = "aa" * 32
        mutations.append(wrong_genesis)
        for changed in mutations:
            with self.subTest(keys=sorted(changed)):
                with self.assertRaises(NoteCapsuleError):
                    decode_capsule(_with_capsule_id(changed), genesis_raw)

        with self.assertRaises(NoteCapsuleError):
            decode_capsule(b" " + raw, genesis_raw)
        with self.assertRaises(NoteCapsuleError):
            decode_capsule(b"{" + b" " * MAX_NOTE_CAPSULE_BYTES, genesis_raw)

    def test_owner_opening_and_unique_receipt_are_required(self):
        capsule, raw, spend_secret, state, controller, _ = (
            self._transaction_case())
        with self.assertRaises(NoteCapsuleError):
            verify_capsule(
                raw, bytes.fromhex(_field(8)), state, controller)

        wrong_domain = _Controller(
            spend_secret=spend_secret,
            owner_key=controller.owner_key,
            commitment=controller.commitment,
            prefix=deepcopy(controller.prefix),
        )
        wrong_domain.prefix["context_field"] = _field(24)
        with self.assertRaises(NoteCapsuleError):
            verify_capsule(raw, spend_secret, state, wrong_domain)

        duplicate = deepcopy(state)
        duplicate["state"]["receipts"].append(
            deepcopy(duplicate["state"]["receipts"][0]))
        with self.assertRaises(NoteCapsuleError):
            verify_capsule(raw, spend_secret, duplicate, controller)

        wrong_opening = deepcopy(capsule)
        wrong_opening["note_secret"] = _field(8)
        with self.assertRaises(NoteCapsuleError):
            verify_capsule(
                _with_capsule_id(wrong_opening),
                spend_secret,
                state,
                controller,
            )

    def test_tracked_vector_is_canonical_and_decodes(self):
        vector = Path(
            "tools/protocol5-wallet/test-vectors/note-capsule-v1.json")
        raw = vector.read_bytes()
        value = json.loads(raw)
        self.assertEqual(raw, canonical_json(value) + b"\n")
        genesis_raw = canonical_json(value["app_genesis"])
        capsule_raw = canonical_json(value["capsule"])
        self.assertLessEqual(len(capsule_raw), MAX_NOTE_CAPSULE_BYTES)
        self.assertEqual(value["format"],
                         "1soft/protocol5-note-capsule-test-vector/v1")
        self.assertEqual(
            decode_capsule(capsule_raw, genesis_raw),
            value["capsule"],
        )


if __name__ == "__main__":
    unittest.main()
