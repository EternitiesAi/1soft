"""Quarantining client for the Protocol 5 verifier-only worker."""
from __future__ import annotations

from dataclasses import dataclass
import hashlib
import os
from pathlib import Path
import select
import stat
import struct
import subprocess
import threading
import time
from typing import BinaryIO

from protocol5_encoding import (
    FIELD_DOMAIN, PALLAS_BASE_MODULUS, GenesisDocument, field_hex,
)

REQUEST_MAGIC = b"1SFTVRQ1"
RESPONSE_MAGIC = b"1SFTVRS1"
KAT_MAGIC = b"1SFTKAT1"
KAT_DOMAIN = b"1soft/shielded-kat/v1\0"
WORKER_VERSION = 1
PROFILE = 1
TREE_ROOT = 2
VERIFY_APPEND = 3
VERIFY_PROOF = 4
OK = 0
INVALID_STATEMENT = 1
INVALID_PROOF = 2
INTERNAL_FAILURE = 0xFFFF
REQUEST_HEADER = struct.Struct("<HHQ")
RESPONSE_HEADER = struct.Struct("<HHQ")
MAX_U64 = 2**64 - 1


class VerifierUnavailable(RuntimeError):
    """Node-local verifier failure. This never maps to a consensus tx result."""


@dataclass(frozen=True)
class Kat:
    fields: tuple[bytes, ...]
    proof: bytes
    mutation_offset: int
    mutation_xor: int

    @classmethod
    def decode(cls, raw: bytes, exact_proof_length: int) -> "Kat":
        def need(condition, message):
            if not condition:
                raise VerifierUnavailable(message)
        need(type(raw) is bytes and len(raw) >= 468, "invalid KAT length")
        need(raw[:8] == KAT_MAGIC, "invalid KAT magic")
        need(struct.unpack_from("<H", raw, 8)[0] == 1, "invalid KAT version")
        offset = 10
        fields = tuple(raw[i:i + 32] for i in range(offset, offset + 448, 32))
        need(len(fields) == 14 and all(
            len(item) == 32 and int.from_bytes(item, "little") < PALLAS_BASE_MODULUS
            for item in fields), "invalid KAT public fields")
        offset += 448
        proof_length = struct.unpack_from("<I", raw, offset)[0]; offset += 4
        need(proof_length == exact_proof_length, "KAT proof length differs")
        need(offset + proof_length + 6 == len(raw), "KAT length differs")
        proof = raw[offset:offset + proof_length]; offset += proof_length
        expected = raw[offset]; offset += 1
        mutation_offset = struct.unpack_from("<I", raw, offset)[0]; offset += 4
        mutation_xor = raw[offset]
        need(expected == OK, "KAT expected status differs")
        need(mutation_offset < proof_length and mutation_xor != 0,
             "invalid KAT proof mutation")
        return cls(fields, proof, mutation_offset, mutation_xor)


@dataclass(frozen=True)
class AppendResult:
    status: int
    root_before: bytes = b""
    root_after: bytes = b""
    position_0: int = 0
    position_1: int = 0


def _digest_path(path: Path) -> bytes:
    try:
        st = path.stat()
        if not stat.S_ISREG(st.st_mode):
            raise VerifierUnavailable("identity artifact is not a regular file")
        with path.open("rb") as handle:
            return hashlib.file_digest(handle, "sha256").digest()
    except OSError as exc:
        raise VerifierUnavailable("identity artifact unavailable") from exc


class WorkerClient:
    def __init__(self, worker_path: str | Path, genesis: GenesisDocument,
                 kat_bytes: bytes, toolchain_manifest_path: str | Path,
                 sandbox_policy_path: str | Path):
        self._lock = threading.Lock()
        self._process: subprocess.Popen | None = None
        self._fd = -1
        self.quarantined = False
        self.closed = False
        self.next_request_id = 1
        self.genesis = genesis
        self.profile_id = genesis.profile.identity
        self.max_frame = genesis.value["limits"]["max_worker_frame_bytes"]
        self.request_timeout = genesis.value["limits"]["worker_request_timeout_seconds"]
        self.startup_timeout = genesis.value["limits"]["worker_startup_timeout_seconds"]
        self._kat = Kat.decode(kat_bytes, genesis.profile.proof_length)
        if hashlib.sha256(KAT_DOMAIN + kat_bytes).digest() != genesis.profile.hashes[6]:
            raise VerifierUnavailable("KAT identity differs from profile")
        if _digest_path(Path(toolchain_manifest_path)) != genesis.deployment.toolchain_sha256:
            raise VerifierUnavailable("toolchain manifest identity differs")
        if _digest_path(Path(sandbox_policy_path)) != genesis.deployment.sandbox_policy_sha256:
            raise VerifierUnavailable("sandbox policy identity differs")
        try:
            self._open_and_launch(Path(worker_path))
            status, profile = self._request(PROFILE, b"", self.startup_timeout)
            if status != OK or profile != genesis.profile.raw:
                raise VerifierUnavailable("worker profile differs")
            status = self.verify_proof(self._kat.fields, self._kat.proof,
                                       timeout=self.startup_timeout)
            if status != OK:
                raise VerifierUnavailable("original KAT proof did not verify")
            mutation = bytearray(self._kat.proof)
            mutation[self._kat.mutation_offset] ^= self._kat.mutation_xor
            status = self.verify_proof(self._kat.fields, bytes(mutation),
                                       timeout=self.startup_timeout)
            if status != INVALID_PROOF:
                raise VerifierUnavailable("mutated KAT proof was not rejected")
        except BaseException as exc:
            self._quarantine()
            if isinstance(exc, VerifierUnavailable):
                raise
            raise VerifierUnavailable("verifier worker startup failed") from exc

    def _open_and_launch(self, path: Path) -> None:
        flags = os.O_RDONLY | os.O_CLOEXEC
        if hasattr(os, "O_NOFOLLOW"):
            flags |= os.O_NOFOLLOW
        try:
            lst = path.lstat()
            if stat.S_ISLNK(lst.st_mode):
                raise VerifierUnavailable("worker symlink refused")
            fd = os.open(path, flags)
            self._fd = fd
            fst = os.fstat(fd)
            if not stat.S_ISREG(fst.st_mode):
                raise VerifierUnavailable("worker is not a regular file")
            if (fst.st_dev, fst.st_ino) != (lst.st_dev, lst.st_ino):
                raise VerifierUnavailable("worker path changed during open")
            if fst.st_uid not in (0, os.getuid()):
                raise VerifierUnavailable("worker owner is unsafe")
            if fst.st_mode & 0o022 or not fst.st_mode & stat.S_IXUSR:
                raise VerifierUnavailable("worker mode is unsafe")
            with os.fdopen(os.dup(fd), "rb") as handle:
                measured = hashlib.file_digest(handle, "sha256").digest()
            if measured != self.genesis.deployment.worker_sha256:
                raise VerifierUnavailable("worker binary identity differs")
            now = path.lstat()
            if (now.st_dev, now.st_ino) != (fst.st_dev, fst.st_ino):
                raise VerifierUnavailable("worker path changed before launch")
            executable = "/proc/self/fd/" + str(fd)
            if not Path(executable).exists():
                raise VerifierUnavailable("open worker descriptor is not launchable")
            self._process = subprocess.Popen(
                [executable], stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                stderr=subprocess.DEVNULL, close_fds=True, pass_fds=(fd,),
                cwd="/", env={"PATH": "/usr/bin:/bin", "LANG": "C"},
                start_new_session=True,
            )
            assert self._process.stdin is not None
            os.set_blocking(self._process.stdin.fileno(), False)
        except VerifierUnavailable:
            raise
        except OSError as exc:
            raise VerifierUnavailable("worker open or launch failed") from exc

    def _read_exact(self, count: int, deadline: float) -> bytes:
        if self._process is None or self._process.stdout is None:
            raise VerifierUnavailable("worker is unavailable")
        fd = self._process.stdout.fileno()
        out = bytearray()
        while len(out) < count:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise VerifierUnavailable("worker response timeout")
            ready, _, _ = select.select([fd], [], [], remaining)
            if not ready:
                raise VerifierUnavailable("worker response timeout")
            piece = os.read(fd, count - len(out))
            if not piece:
                raise VerifierUnavailable("worker response truncated")
            out.extend(piece)
        return bytes(out)

    def _write_all(self, data: bytes, deadline: float) -> None:
        if self._process is None or self._process.stdin is None:
            raise VerifierUnavailable("worker is unavailable")
        fd = self._process.stdin.fileno()
        offset = 0
        while offset < len(data):
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise VerifierUnavailable("worker request timeout")
            _, ready, _ = select.select([], [fd], [], remaining)
            if not ready:
                raise VerifierUnavailable("worker request timeout")
            try:
                written = os.write(fd, data[offset:])
            except BlockingIOError:
                continue
            if written <= 0:
                raise VerifierUnavailable("worker request write failed")
            offset += written

    def _request(self, opcode: int, payload: bytes, timeout: int | None = None):
        with self._lock:
            if self.quarantined or self.closed or self._process is None:
                raise VerifierUnavailable("verifier worker is quarantined")
            request_id = self.next_request_id
            if request_id <= 0 or request_id > MAX_U64:
                self._quarantine()
                raise VerifierUnavailable("worker request identifier exhausted")
            body = (
                REQUEST_MAGIC + REQUEST_HEADER.pack(WORKER_VERSION, opcode, request_id)
                + self.profile_id + struct.pack("<I", len(payload)) + payload
            )
            if len(body) > self.max_frame:
                raise VerifierUnavailable("worker request exceeds frame bound")
            try:
                deadline = time.monotonic() + (
                    self.request_timeout if timeout is None else timeout)
                self._write_all(struct.pack("<I", len(body)) + body, deadline)
                size = struct.unpack("<I", self._read_exact(4, deadline))[0]
                if size > self.max_frame or size < 58:
                    raise VerifierUnavailable("worker response frame size differs")
                response = self._read_exact(size, deadline)
                if response[:8] != RESPONSE_MAGIC:
                    raise VerifierUnavailable("worker response magic differs")
                version, echoed_opcode, echoed_id = RESPONSE_HEADER.unpack_from(response, 8)
                profile_id = response[20:52]
                status, payload_length = struct.unpack_from("<HI", response, 52)
                response_payload = response[58:]
                if (version, echoed_opcode, echoed_id, profile_id) != (
                        WORKER_VERSION, opcode, request_id, self.profile_id):
                    raise VerifierUnavailable("worker response identity differs")
                if payload_length != len(response_payload):
                    raise VerifierUnavailable("worker response length differs")
                if status not in (OK, INVALID_STATEMENT, INVALID_PROOF):
                    raise VerifierUnavailable("worker returned fatal status")
                if status != OK and response_payload:
                    raise VerifierUnavailable("worker rejection carried payload")
                assert self._process.stdout is not None
                extra, _, _ = select.select(
                    [self._process.stdout.fileno()], [], [], 0)
                if extra:
                    raise VerifierUnavailable("worker emitted unsolicited bytes or exited")
                self.next_request_id += 1
                return status, response_payload
            except BaseException as exc:
                self._quarantine()
                if isinstance(exc, VerifierUnavailable):
                    raise
                raise VerifierUnavailable("worker request failed") from exc

    @staticmethod
    def _fields(fields: tuple[bytes, ...]) -> bytes:
        if type(fields) is not tuple or len(fields) != 14 or not all(
                type(item) is bytes and len(item) == 32
                and int.from_bytes(item, "little") < PALLAS_BASE_MODULUS
                for item in fields):
            raise VerifierUnavailable("invalid worker public fields")
        return b"".join(fields)

    def tree_root(self, commitments: list[bytes]) -> bytes:
        if type(commitments) is not list or len(commitments) > 16 or not all(
                type(item) is bytes and len(item) == 32
                and int.from_bytes(item, "little") < PALLAS_BASE_MODULUS
                for item in commitments):
            raise VerifierUnavailable("invalid worker commitment vector")
        status, payload = self._request(
            TREE_ROOT, struct.pack("<H", len(commitments)) + b"".join(commitments))
        if status != OK or len(payload) != 32                 or int.from_bytes(payload, "little") >= PALLAS_BASE_MODULUS:
            self._quarantine()
            raise VerifierUnavailable("worker tree root differs")
        return payload

    def verify_proof(self, fields: tuple[bytes, ...], proof: bytes,
                     *, timeout: int | None = None) -> int:
        if type(proof) is not bytes or len(proof) != self.genesis.profile.proof_length:
            raise VerifierUnavailable("invalid worker proof length")
        payload = self._fields(fields) + struct.pack("<I", len(proof)) + proof
        status, response = self._request(VERIFY_PROOF, payload, timeout)
        if status == OK and response:
            self._quarantine()
            raise VerifierUnavailable("worker proof response carried payload")
        return status

    def verify_and_append(self, commitments: list[bytes], fields: tuple[bytes, ...],
                          proof: bytes) -> AppendResult:
        if type(commitments) is not list or len(commitments) > 16 or not all(
                type(item) is bytes and len(item) == 32
                and int.from_bytes(item, "little") < PALLAS_BASE_MODULUS
                for item in commitments):
            raise VerifierUnavailable("invalid worker commitment vector")
        if type(proof) is not bytes or len(proof) != self.genesis.profile.proof_length:
            raise VerifierUnavailable("invalid worker proof length")
        payload = (struct.pack("<H", len(commitments)) + b"".join(commitments)
                   + self._fields(fields) + struct.pack("<I", len(proof)) + proof)
        status, response = self._request(VERIFY_APPEND, payload)
        if status != OK:
            return AppendResult(status)
        if len(response) != 68:
            self._quarantine()
            raise VerifierUnavailable("worker append response length differs")
        before, after = response[:32], response[32:64]
        position_0, position_1 = struct.unpack_from("<HH", response, 64)
        if int.from_bytes(before, "little") >= PALLAS_BASE_MODULUS                 or int.from_bytes(after, "little") >= PALLAS_BASE_MODULUS:
            self._quarantine()
            raise VerifierUnavailable("worker append returned noncanonical root")
        return AppendResult(status, before, after, position_0, position_1)

    def _quarantine(self) -> None:
        self.quarantined = True
        process, self._process = self._process, None
        if process is not None:
            try:
                process.kill()
            except OSError:
                pass
            try:
                process.wait(timeout=1)
            except (OSError, subprocess.TimeoutExpired):
                pass
            for stream in (process.stdin, process.stdout):
                if stream is not None:
                    try:
                        stream.close()
                    except OSError:
                        pass
        if self._fd >= 0:
            try:
                os.close(self._fd)
            except OSError:
                pass
            self._fd = -1

    def close(self) -> None:
        if self.closed:
            return
        self.closed = True
        process, self._process = self._process, None
        if process is not None:
            try:
                if process.stdin is not None:
                    process.stdin.close()
                process.wait(timeout=1)
            except (OSError, subprocess.TimeoutExpired):
                try:
                    process.kill()
                    process.wait(timeout=1)
                except OSError:
                    pass
            for stream in (process.stdin, process.stdout):
                if stream is not None and not stream.closed:
                    try:
                        stream.close()
                    except OSError:
                        pass
        if self._fd >= 0:
            os.close(self._fd)
            self._fd = -1

    def __enter__(self):
        return self

    def __exit__(self, *_):
        self.close()
