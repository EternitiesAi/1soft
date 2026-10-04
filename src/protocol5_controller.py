"""Bounded controller-only adapter for Protocol 5 development binaries.

This module constructs only frozen controller request wires. Rust remains the
sole implementation of note commitments, owner-key derivation, Merkle paths,
nullifiers, the Halo2 witness, and proof generation.
"""
from __future__ import annotations

from dataclasses import dataclass
import hashlib
import os
from pathlib import Path
import struct
import subprocess

from protocol5_encoding import (
    PALLAS_BASE_MODULUS, Transaction, field_bytes, genesis_document,
)

CLIENT_MAGIC = b"1SFTCLI1"
CLIENT_GENESIS_MAGIC = b"1SFTGEN1"
CLIENT_OWNER_MAGIC = b"1SFTKEY1"
PROVER_MAGIC = b"1SFTPRV1"
CLIENT_VERSION = 1
GENESIS_OPCODE = 1
SPEND_OPCODE = 2
DERIVE_OWNER_KEY_OPCODE = 3
SPEND_TO_RECIPIENT_KEYS_OPCODE = 4
MAX_CLIENT_REQUEST_BYTES = 1966
PROVER_REQUEST_BYTES = 1010


def _field(value: bytes, label: str) -> bytes:
    if (type(value) is not bytes or len(value) != 32
            or not 0 < int.from_bytes(value, "little") < PALLAS_BASE_MODULUS):
        raise ValueError("invalid " + label)
    return value


def _u64(value: int, label: str) -> int:
    if type(value) is not int or not 1 <= value < 2**64:
        raise ValueError("invalid " + label)
    return value


@dataclass(frozen=True)
class SecretNote:
    expiry: int
    value: int
    owner_spend_secret: bytes
    note_secret: bytes
    blinding: bytes

    def encode(self) -> bytes:
        _u64(self.expiry, "development note expiry")
        _u64(self.value, "development note value")
        fields = (
            _field(self.owner_spend_secret, "development owner secret"),
            _field(self.note_secret, "development note secret"),
            _field(self.blinding, "development note blinding"),
        )
        return struct.pack("<QQ", self.expiry, self.value) + b"".join(fields)


@dataclass(frozen=True)
class RecipientOutput:
    expiry: int
    value: int
    owner_key: bytes
    note_secret: bytes
    blinding: bytes

    def encode(self) -> bytes:
        _u64(self.expiry, "recipient note expiry")
        _u64(self.value, "recipient note value")
        fields = (
            _field(self.owner_key, "recipient owner key"),
            _field(self.note_secret, "recipient note secret"),
            _field(self.blinding, "recipient note blinding"),
        )
        return struct.pack("<QQ", self.expiry, self.value) + b"".join(fields)


def random_field() -> bytes:
    while True:
        value = os.urandom(32)
        if 0 < int.from_bytes(value, "little") < PALLAS_BASE_MODULUS:
            return value


def development_note(expiry: int, value: int) -> SecretNote:
    return SecretNote(expiry, value, random_field(), random_field(), random_field())


def _sha(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as source:
        for chunk in iter(lambda: source.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _start_ticks(pid: int) -> int:
    fields = Path(f"/proc/{pid}/stat").read_text(encoding="ascii").split()
    return int(fields[21])


class DevelopmentController:
    """Controller-only Rust client/prover adapter; secrets use bounded stdin."""

    def __init__(self, client: Path, prover: Path, genesis_prefix: dict,
                 receipts: list[dict] | None = None):
        self.client = Path(client)
        self.prover = Path(prover)
        self.prefix = genesis_prefix
        self.receipts = receipts if receipts is not None else []

    def _run(self, role: str, binary: Path, request: bytearray,
             *, expected_length: int | None = None,
             maximum_length: int = 131_072) -> bytes:
        if type(request) is not bytearray or not request:
            raise ValueError("invalid controller request")
        if len(request) > MAX_CLIENT_REQUEST_BYTES and binary == self.client:
            raise ValueError("development client request exceeds bound")
        process = subprocess.Popen(
            [str(binary)], stdin=subprocess.PIPE, stdout=subprocess.PIPE,
            stderr=subprocess.PIPE, env={"PATH": "/usr/bin:/bin", "LC_ALL": "C"},
        )
        receipt = {
            "role": role,
            "node": None,
            "pid": process.pid,
            "start_ticks": _start_ticks(process.pid),
            "executable_sha256": _sha(binary),
        }
        self.receipts.append(receipt)
        output = b""
        error = b""
        try:
            output, error = process.communicate(bytes(request), timeout=120)
        except subprocess.TimeoutExpired:
            process.kill()
            output, error = process.communicate(timeout=10)
            raise RuntimeError(role + " exceeded its watchdog")
        finally:
            request[:] = b"\0" * len(request)
        receipt["exit_code"] = process.returncode
        receipt["stdout_sha256"] = hashlib.sha256(output).hexdigest()
        receipt["stderr_sha256"] = hashlib.sha256(error).hexdigest()
        if process.returncode != 0 or error:
            raise RuntimeError(role + " failed closed")
        if len(output) > maximum_length:
            raise RuntimeError(role + " output exceeded bound")
        if expected_length is not None and len(output) != expected_length:
            raise RuntimeError(role + " output length differs")
        return output

    def _domain_fields(self) -> tuple[bytes, ...]:
        return (
            field_bytes(self.prefix["genesis_field"]),
            field_bytes(self.prefix["asset_field"]),
            field_bytes(self.prefix["context_field"]),
            _u64(self.prefix["authority_epoch"], "authority epoch").to_bytes(32, "little"),
            field_bytes(self.prefix["policy_field"]),
        )

    def derive_owner_key(self, spend_secret: bytes) -> bytes:
        secret = _field(spend_secret, "owner spend secret")
        request = bytearray(
            CLIENT_MAGIC
            + struct.pack("<HH", CLIENT_VERSION, DERIVE_OWNER_KEY_OPCODE)
            + secret
        )
        output = self._run(
            "development-client-owner-key", self.client, request,
            expected_length=42, maximum_length=42,
        )
        if output[:8] != CLIENT_OWNER_MAGIC:
            raise RuntimeError("development client owner-key magic differs")
        version = struct.unpack_from("<H", output, 8)[0]
        if version != CLIENT_VERSION:
            raise RuntimeError("development client owner-key version differs")
        return _field(output[10:42], "derived owner key")

    def commitments(self, notes: list[SecretNote]) -> tuple[list[str], str]:
        if type(notes) is not list or not 1 <= len(notes) <= 16:
            raise ValueError("development genesis note count differs")
        request = bytearray(
            CLIENT_MAGIC
            + struct.pack("<HH", CLIENT_VERSION, GENESIS_OPCODE)
            + b"".join(self._domain_fields())
            + struct.pack("<H", len(notes))
            + b"".join(note.encode() for note in notes)
        )
        output = self._run(
            "development-client-genesis", self.client, request,
            expected_length=12 + 32 * len(notes) + 32, maximum_length=556,
        )
        if output[:8] != CLIENT_GENESIS_MAGIC:
            raise RuntimeError("development client genesis magic differs")
        version, count = struct.unpack_from("<HH", output, 8)
        if version != CLIENT_VERSION or count != len(notes):
            raise RuntimeError("development client genesis header differs")
        values = [
            output[12 + 32 * index:44 + 32 * index]
            for index in range(count)
        ]
        root = output[-32:]
        checked = [_field(item, "development commitment") for item in values]
        checked.append(_field(root, "development commitment root"))
        if len(set(values)) != len(values):
            raise RuntimeError("development client returned duplicate commitments")
        return [item.hex() for item in values], root.hex()

    def _spend_prefix(self, genesis_raw: bytes, commitments: list[str],
                      input_position: int, valid_from: int,
                      valid_until: int, opcode: int) -> tuple[bytes, object]:
        genesis = genesis_document(genesis_raw)
        if (type(commitments) is not list or not 1 <= len(commitments) <= 14
                or type(input_position) is not int
                or not 0 <= input_position < len(commitments)
                or type(valid_from) is not int or type(valid_until) is not int
                or not 0 <= valid_from < valid_until < 2**64):
            raise ValueError("invalid development spend request")
        fields = self._domain_fields() + (
            valid_from.to_bytes(32, "little"),
            valid_until.to_bytes(32, "little"),
            genesis.value["fee"].to_bytes(32, "little"),
        )
        prefix = (
            CLIENT_MAGIC
            + struct.pack("<HH", CLIENT_VERSION, opcode)
            + genesis.sha256
            + genesis.deployment.identity
            + b"".join(fields)
            + struct.pack("<H", len(commitments))
            + b"".join(field_bytes(item) for item in commitments)
            + struct.pack("<H", input_position)
        )
        return prefix, genesis

    def spend_request(self, genesis_raw: bytes, commitments: list[str],
                      input_position: int, input_note: SecretNote,
                      output_notes: tuple[SecretNote, SecretNote], *,
                      valid_from: int, valid_until: int) -> bytes:
        if (type(input_note) is not SecretNote
                or type(output_notes) is not tuple or len(output_notes) != 2
                or not all(type(note) is SecretNote for note in output_notes)):
            raise ValueError("invalid development spend notes")
        prefix, _ = self._spend_prefix(
            genesis_raw, commitments, input_position, valid_from,
            valid_until, SPEND_OPCODE,
        )
        request = bytearray(
            prefix + input_note.encode()
            + b"".join(note.encode() for note in output_notes)
        )
        return self._run(
            "development-client-spend", self.client, request,
            expected_length=PROVER_REQUEST_BYTES, maximum_length=PROVER_REQUEST_BYTES,
        )

    def spend_to_recipient_keys(
            self, genesis_raw: bytes, commitments: list[str],
            input_position: int, input_note: SecretNote,
            outputs: tuple[RecipientOutput, RecipientOutput], *,
            valid_from: int, valid_until: int) -> bytes:
        if (type(input_note) is not SecretNote
                or type(outputs) is not tuple or len(outputs) != 2
                or not all(type(note) is RecipientOutput for note in outputs)):
            raise ValueError("invalid public-recipient spend notes")
        prefix, _ = self._spend_prefix(
            genesis_raw, commitments, input_position, valid_from,
            valid_until, SPEND_TO_RECIPIENT_KEYS_OPCODE,
        )
        request = bytearray(
            prefix + input_note.encode()
            + b"".join(note.encode() for note in outputs)
        )
        return self._run(
            "development-client-recipient-spend", self.client, request,
            expected_length=PROVER_REQUEST_BYTES, maximum_length=PROVER_REQUEST_BYTES,
        )

    def prove(self, genesis_raw: bytes, prover_request: bytes) -> bytes:
        if (type(prover_request) is not bytes
                or len(prover_request) != PROVER_REQUEST_BYTES
                or prover_request[:8] != PROVER_MAGIC):
            raise ValueError("invalid development prover request")
        genesis = genesis_document(genesis_raw)
        request = bytearray(prover_request)
        transaction = self._run(
            "development-prover", self.prover, request,
            expected_length=534 + genesis.profile.proof_length,
            maximum_length=genesis.value["limits"]["max_tx_bytes"],
        )
        Transaction.decode(transaction, genesis)
        return transaction


Note = SecretNote
