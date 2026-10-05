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
import selectors
import stat
import struct
import subprocess
import time

from protocol5_encoding import (
    PALLAS_BASE_MODULUS, Transaction, field_bytes, genesis_document,
)

CLIENT_MAGIC = b"1SFTCLI1"
CLIENT_GENESIS_MAGIC = b"1SFTGEN1"
CLIENT_OWNER_MAGIC = b"1SFTKEY1"
CLIENT_NULLIFIER_MAGIC = b"1SFTNUL1"
PROVER_MAGIC = b"1SFTPRV1"
CLIENT_VERSION = 1
GENESIS_OPCODE = 1
SPEND_OPCODE = 2
DERIVE_OWNER_KEY_OPCODE = 3
SPEND_TO_RECIPIENT_KEYS_OPCODE = 4
DERIVE_NOTE_NULLIFIER_OPCODE = 5
MAX_CLIENT_REQUEST_BYTES = 1966
PROVER_REQUEST_BYTES = 1010
MAX_EXECUTABLE_BYTES = 256 * 1024 * 1024
MAX_STDERR_BYTES = 64 * 1024
CLIENT_TIMEOUT_SECONDS = 30.0
PROVER_TIMEOUT_SECONDS = 300.0


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


def _digest_pin(value: str | None, label: str) -> str | None:
    if value is not None and (
            type(value) is not str or len(value) != 64
            or any(character not in "0123456789abcdef"
                   for character in value)):
        raise ValueError("invalid expected " + label + " SHA-256")
    return value


def _open_executable(path: Path) -> tuple[int, str]:
    selected = Path(os.path.abspath(path))
    for parent in (selected.parent, *selected.parent.parents):
        if parent.is_symlink():
            raise ValueError("controller executable has a symlink parent")
    descriptor = os.open(
        selected,
        os.O_RDONLY | getattr(os, "O_CLOEXEC", 0)
        | getattr(os, "O_NOFOLLOW", 0),
    )
    try:
        metadata = os.fstat(descriptor)
        if (not stat.S_ISREG(metadata.st_mode)
                or metadata.st_uid not in {0, os.geteuid()}
                or metadata.st_mode & 0o022
                or not metadata.st_mode & 0o111
                or not 0 < metadata.st_size <= MAX_EXECUTABLE_BYTES):
            raise ValueError("unsafe controller executable")
        digest = hashlib.sha256()
        while True:
            chunk = os.read(descriptor, 1024 * 1024)
            if not chunk:
                break
            digest.update(chunk)
        os.lseek(descriptor, 0, os.SEEK_SET)
        return descriptor, digest.hexdigest()
    except BaseException:
        os.close(descriptor)
        raise


def _remaining(deadline: float) -> float:
    value = deadline - time.monotonic()
    if value <= 0:
        raise TimeoutError("controller process exceeded its watchdog")
    return value


def _bounded_exchange(
        process: subprocess.Popen, request: bytearray, *,
        maximum_length: int, timeout_seconds: float) -> tuple[bytes, bytes]:
    deadline = time.monotonic() + timeout_seconds
    selector = selectors.DefaultSelector()
    streams = {
        "stdin": process.stdin,
        "stdout": process.stdout,
        "stderr": process.stderr,
    }
    if any(stream is None for stream in streams.values()):
        raise RuntimeError("controller process pipes unavailable")
    for stream in streams.values():
        os.set_blocking(stream.fileno(), False)
    selector.register(streams["stdin"], selectors.EVENT_WRITE, "stdin")
    selector.register(streams["stdout"], selectors.EVENT_READ, "stdout")
    selector.register(streams["stderr"], selectors.EVENT_READ, "stderr")
    offset = 0
    output = bytearray()
    error = bytearray()

    def close_stream(name: str) -> None:
        stream = streams[name]
        if stream is None:
            return
        try:
            selector.unregister(stream)
        except KeyError:
            pass
        stream.close()
        streams[name] = None

    try:
        while selector.get_map():
            events = selector.select(_remaining(deadline))
            if not events:
                raise TimeoutError(
                    "controller process exceeded its watchdog")
            for key, _mask in events:
                name = key.data
                stream = key.fileobj
                if name == "stdin":
                    try:
                        written = os.write(
                            stream.fileno(), memoryview(request)[offset:])
                    except BrokenPipeError:
                        close_stream(name)
                        continue
                    if written <= 0:
                        raise RuntimeError("controller stdin write stalled")
                    offset += written
                    if offset == len(request):
                        close_stream(name)
                    continue
                limit = (maximum_length if name == "stdout"
                         else MAX_STDERR_BYTES)
                target = output if name == "stdout" else error
                chunk = os.read(
                    stream.fileno(), min(65_536, limit + 1 - len(target)))
                if not chunk:
                    close_stream(name)
                    continue
                target.extend(chunk)
                if len(target) > limit:
                    raise RuntimeError(
                        "controller " + name + " exceeded bound")
        process.wait(timeout=_remaining(deadline))
    except subprocess.TimeoutExpired as exc:
        raise TimeoutError(
            "controller process exceeded its watchdog") from exc
    finally:
        selector.close()
        for name in tuple(streams):
            stream = streams[name]
            if stream is not None:
                stream.close()
                streams[name] = None
    return bytes(output), bytes(error)


def _start_ticks(pid: int) -> int:
    fields = Path(f"/proc/{pid}/stat").read_text(encoding="ascii").split()
    return int(fields[21])


class DevelopmentController:
    """Controller-only Rust client/prover adapter; secrets use bounded stdin."""

    def __init__(self, client: Path, prover: Path, genesis_prefix: dict,
                 receipts: list[dict] | None = None, *,
                 expected_client_sha256: str | None = None,
                 expected_prover_sha256: str | None = None):
        self.client = Path(client)
        self.prover = Path(prover)
        self.prefix = genesis_prefix
        self.receipts = receipts if receipts is not None else []
        self.expected_client_sha256 = _digest_pin(
            expected_client_sha256, "client")
        self.expected_prover_sha256 = _digest_pin(
            expected_prover_sha256, "prover")

    def validate_executables(self) -> dict[str, str]:
        """Measure both controller binaries before any secret-bearing call."""
        result = {}
        for role, binary, expected in (
                ("client", self.client, self.expected_client_sha256),
                ("prover", self.prover, self.expected_prover_sha256)):
            descriptor = None
            try:
                descriptor, digest = _open_executable(binary)
                if expected is not None and digest != expected:
                    raise RuntimeError(
                        "development " + role + " executable digest differs")
                result[role + "_sha256"] = digest
            finally:
                if descriptor is not None:
                    os.close(descriptor)
        return result

    def _run(self, role: str, binary: Path, request: bytearray,
             *, expected_length: int | None = None,
             maximum_length: int = 131_072) -> bytes:
        if type(request) is not bytearray:
            raise ValueError("invalid controller request")
        descriptor = None
        process = None
        try:
            if not request:
                raise ValueError("invalid controller request")
            if (len(request) > MAX_CLIENT_REQUEST_BYTES
                    and binary == self.client):
                raise ValueError("development client request exceeds bound")
            descriptor, executable_sha256 = _open_executable(binary)
            is_prover = role == "development-prover"
            expected = (self.expected_prover_sha256
                        if is_prover
                        else self.expected_client_sha256)
            if expected is not None and executable_sha256 != expected:
                raise RuntimeError(role + " executable digest differs")
            process = subprocess.Popen(
                [f"/proc/self/fd/{descriptor}"],
                stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                env={"PATH": "/usr/bin:/bin", "LC_ALL": "C"},
                pass_fds=(descriptor,), close_fds=True,
            )
            receipt = {
                "role": role,
                "node": None,
                "pid": process.pid,
                "start_ticks": _start_ticks(process.pid),
                "executable_sha256": executable_sha256,
            }
            self.receipts.append(receipt)
            timeout_seconds = (
                PROVER_TIMEOUT_SECONDS
                if is_prover else CLIENT_TIMEOUT_SECONDS)
            output, error = _bounded_exchange(
                process, request, maximum_length=maximum_length,
                timeout_seconds=timeout_seconds)
            receipt["exit_code"] = process.returncode
            receipt["stdout_sha256"] = hashlib.sha256(output).hexdigest()
            receipt["stderr_sha256"] = hashlib.sha256(error).hexdigest()
            if process.returncode != 0 or error:
                raise RuntimeError(role + " failed closed")
            if expected_length is not None and len(output) != expected_length:
                raise RuntimeError(role + " output length differs")
            return output
        finally:
            request[:] = b"\0" * len(request)
            if process is not None and process.poll() is None:
                process.kill()
                try:
                    process.wait(timeout=10)
                except subprocess.TimeoutExpired:
                    pass
            if descriptor is not None:
                os.close(descriptor)

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

    def derive_note_nullifier(
            self, input_commitment: bytes, input_position: int,
            spend_secret: bytes, note_secret: bytes) -> bytes:
        if type(input_position) is not int or not 0 <= input_position < 16:
            raise ValueError("invalid note position")
        commitment = _field(input_commitment, "input commitment")
        spend = _field(spend_secret, "owner spend secret")
        note = _field(note_secret, "note secret")
        request = bytearray(
            CLIENT_MAGIC
            + struct.pack("<HH", CLIENT_VERSION, DERIVE_NOTE_NULLIFIER_OPCODE)
            + b"".join(self._domain_fields())
            + struct.pack("<H", input_position)
            + commitment + spend + note
        )
        output = self._run(
            "development-client-note-nullifier", self.client, request,
            expected_length=42, maximum_length=42,
        )
        if output[:8] != CLIENT_NULLIFIER_MAGIC:
            raise RuntimeError("development client note-nullifier magic differs")
        version = struct.unpack_from("<H", output, 8)[0]
        if version != CLIENT_VERSION:
            raise RuntimeError("development client note-nullifier version differs")
        return _field(output[10:42], "derived note nullifier")

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
