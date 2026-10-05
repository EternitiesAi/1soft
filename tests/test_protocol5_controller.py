from __future__ import annotations

import base64
import hashlib
import os
from pathlib import Path
import struct
import tempfile
import time
import unittest
from unittest.mock import patch

import protocol5_controller as controller_module

from protocol5_controller import (
    CLIENT_GENESIS_MAGIC, CLIENT_MAGIC, CLIENT_NULLIFIER_MAGIC,
    CLIENT_OWNER_MAGIC, PROVER_MAGIC, DevelopmentController, RecipientOutput,
    SecretNote,
)
from protocol5_encoding import genesis_document
from protocol5_fixture import make_genesis
from run_protocol5_engine import finalize_fresh_genesis


class CapturingController(DevelopmentController):
    def __init__(self, prefix):
        super().__init__(Path("/client"), Path("/prover"), prefix)
        self.captured = []

    def _run(self, role, binary, request, **kwargs):
        raw = bytes(request)
        self.captured.append((role, raw, kwargs))
        request[:] = b"\0" * len(request)
        if role == "development-client-owner-key":
            return CLIENT_OWNER_MAGIC + struct.pack("<H", 1) + (17).to_bytes(32, "little")
        if role == "development-client-note-nullifier":
            return CLIENT_NULLIFIER_MAGIC + struct.pack("<H", 1) + (19).to_bytes(32, "little")
        if role == "development-client-genesis":
            count = struct.unpack_from("<H", raw, 172)[0]
            values = [(index + 11).to_bytes(32, "little") for index in range(count)]
            return (
                CLIENT_GENESIS_MAGIC + struct.pack("<HH", 1, count)
                + b"".join(values) + (31).to_bytes(32, "little")
            )
        return PROVER_MAGIC + b"\0" * (1010 - len(PROVER_MAGIC))


def note(value=10, secret=3):
    return SecretNote(
        64, value, secret.to_bytes(32, "little"),
        (secret + 1).to_bytes(32, "little"),
        (secret + 2).to_bytes(32, "little"),
    )


class Protocol5ControllerTests(unittest.TestCase):
    def setUp(self):
        self.prefix = make_genesis()
        self.prefix["initial_commitments"] = []
        self.controller = CapturingController(self.prefix)

    def test_owner_key_wire_is_exact_and_stdin_only(self):
        secret = (9).to_bytes(32, "little")
        owner = self.controller.derive_owner_key(secret)
        role, raw, options = self.controller.captured[-1]
        self.assertEqual(role, "development-client-owner-key")
        self.assertEqual(raw, CLIENT_MAGIC + struct.pack("<HH", 1, 3) + secret)
        self.assertEqual(len(raw), 44)
        self.assertEqual(owner, (17).to_bytes(32, "little"))
        self.assertEqual(options, {"expected_length": 42, "maximum_length": 42})

    def test_note_nullifier_wire_is_exact_and_stdin_only(self):
        commitment = (41).to_bytes(32, "little")
        spend_secret = (43).to_bytes(32, "little")
        note_secret = (47).to_bytes(32, "little")
        nullifier = self.controller.derive_note_nullifier(
            commitment, 15, spend_secret, note_secret)
        role, raw, options = self.controller.captured[-1]
        self.assertEqual(role, "development-client-note-nullifier")
        self.assertEqual(
            raw,
            CLIENT_MAGIC + struct.pack("<HH", 1, 5)
            + b"".join(self.controller._domain_fields())
            + struct.pack("<H", 15)
            + commitment + spend_secret + note_secret,
        )
        self.assertEqual(len(raw), 270)
        self.assertEqual(nullifier, (19).to_bytes(32, "little"))
        self.assertEqual(options, {"expected_length": 42, "maximum_length": 42})

    def test_note_nullifier_invalid_fields_and_positions_fail_before_subprocess(self):
        valid = (7).to_bytes(32, "little")
        before = len(self.controller.captured)
        for position in (-1, 16, True, 1.0):
            with self.subTest(position=position), self.assertRaises(ValueError):
                self.controller.derive_note_nullifier(valid, position, valid, valid)
        for index in range(3):
            for bad in (b"", b"\0" * 32, b"\xff" * 32, bytearray(32)):
                fields = [valid, valid, valid]
                fields[index] = bad
                with self.subTest(index=index, value=repr(bad)), self.assertRaises(ValueError):
                    self.controller.derive_note_nullifier(
                        fields[0], 0, fields[1], fields[2])
        self.assertEqual(len(self.controller.captured), before)

    def test_public_recipient_wire_is_exact_and_stdin_only(self):
        commitments, _ = self.controller.commitments([note(10, 3), note(20, 6)])
        raw_genesis = finalize_fresh_genesis(self.prefix, commitments)
        recipient_secret = (43).to_bytes(32, "little")
        recipient_key = (47).to_bytes(32, "little")
        outputs = (
            RecipientOutput(64, 3, recipient_key, (51).to_bytes(32, "little"),
                            (52).to_bytes(32, "little")),
            RecipientOutput(64, 2, (53).to_bytes(32, "little"),
                            (54).to_bytes(32, "little"),
                            (55).to_bytes(32, "little")),
        )
        request = self.controller.spend_to_recipient_keys(
            raw_genesis, commitments, 0, note(10, 3), outputs,
            valid_from=1, valid_until=20,
        )
        role, raw, options = self.controller.captured[-1]
        self.assertEqual(role, "development-client-recipient-spend")
        self.assertEqual(raw[:12], CLIENT_MAGIC + struct.pack("<HH", 1, 4))
        self.assertEqual(len(raw), 736)
        self.assertIn(recipient_key, raw)
        self.assertNotIn(recipient_secret, raw)
        self.assertEqual(len(request), 1010)
        self.assertEqual(request[:8], PROVER_MAGIC)
        self.assertEqual(
            options, {"expected_length": 1010, "maximum_length": 1010})

    def test_legacy_wires_remain_exact(self):
        commitments, _ = self.controller.commitments([note(10, 3), note(20, 6)])
        genesis_request = self.controller.captured[0][1]
        self.assertEqual(len(genesis_request), 398)
        self.assertEqual(genesis_request[:12], CLIENT_MAGIC + struct.pack("<HH", 1, 1))
        raw_genesis = finalize_fresh_genesis(self.prefix, commitments)
        prover_request = self.controller.spend_request(
            raw_genesis, commitments, 0, note(10, 3),
            (note(3, 9), note(2, 12)), valid_from=1, valid_until=20,
        )
        spend_request = self.controller.captured[-1][1]
        self.assertEqual(len(spend_request), 736)
        self.assertEqual(spend_request[:12], CLIENT_MAGIC + struct.pack("<HH", 1, 2))
        self.assertEqual(len(prover_request), 1010)

    def test_invalid_fields_are_rejected_before_subprocess(self):
        before = len(self.controller.captured)
        for bad in (b"", b"\0" * 32, b"\xff" * 32, bytearray(32)):
            with self.subTest(value=repr(bad)), self.assertRaises(ValueError):
                self.controller.derive_owner_key(bad)
        self.assertEqual(len(self.controller.captured), before)

    def executable(self, root: Path, body: str) -> tuple[Path, str]:
        path = root / "controller"
        path.write_text("#!/usr/bin/python3\n" + body, encoding="utf-8")
        path.chmod(0o700)
        return path, hashlib.sha256(path.read_bytes()).hexdigest()

    def test_measured_inode_is_pinned_before_bounded_stdin_execution(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            root.chmod(0o700)
            binary, digest = self.executable(
                root,
                "import sys\n"
                "raw=sys.stdin.buffer.read()\n"
                "assert len(raw)==44 and raw[:8]==b'1SFTCLI1'\n"
                "sys.stdout.buffer.write(b'1SFTKEY1'+(1).to_bytes(2,'little')"
                "+(17).to_bytes(32,'little'))\n",
            )
            receipts = []
            controller = DevelopmentController(
                binary, binary, self.prefix, receipts,
                expected_client_sha256=digest,
                expected_prover_sha256=digest)
            result = controller.derive_owner_key(
                (9).to_bytes(32, "little"))
            self.assertEqual(result, (17).to_bytes(32, "little"))
            self.assertEqual(len(receipts), 1)
            self.assertEqual(receipts[0]["executable_sha256"], digest)
            self.assertEqual(receipts[0]["exit_code"], 0)

    def test_wrong_pin_and_overbound_output_wipe_request(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            root.chmod(0o700)
            binary, digest = self.executable(
                root,
                "import sys\n"
                "sys.stdin.buffer.read()\n"
                "sys.stdout.buffer.write(b'x'*4096)\n",
            )
            controller = DevelopmentController(
                binary, binary, self.prefix,
                expected_client_sha256="00" * 32,
                expected_prover_sha256=digest)
            request = bytearray(b"secret-request")
            with self.assertRaisesRegex(RuntimeError, "digest differs"):
                controller._run(
                    "development-client-test", binary, request,
                    maximum_length=8)
            self.assertEqual(request, b"\0" * len(request))
            controller = DevelopmentController(
                binary, binary, self.prefix,
                expected_client_sha256=digest,
                expected_prover_sha256=digest)
            request = bytearray(b"secret-request")
            with self.assertRaisesRegex(RuntimeError, "stdout exceeded"):
                controller._run(
                    "development-client-test", binary, request,
                    maximum_length=8)
            self.assertEqual(request, b"\0" * len(request))

    def test_overbound_client_request_is_wiped_before_open_or_launch(self):
        controller = DevelopmentController(
            Path("/must-not-open-client"), Path("/must-not-open-prover"),
            self.prefix)
        request = bytearray(b"x" * (
            controller_module.MAX_CLIENT_REQUEST_BYTES + 1))
        with patch.object(controller_module, "_open_executable") as opened:
            with self.assertRaisesRegex(ValueError, "request exceeds bound"):
                controller._run(
                    "development-client-test", controller.client, request)
        opened.assert_not_called()
        self.assertEqual(request, b"\0" * len(request))

    def test_client_watchdog_is_one_elapsed_deadline(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            root.chmod(0o700)
            binary, digest = self.executable(
                root,
                "import sys,time\n"
                "sys.stdin.buffer.read()\n"
                "time.sleep(2)\n",
            )
            controller = DevelopmentController(
                binary, binary, self.prefix,
                expected_client_sha256=digest,
                expected_prover_sha256=digest)
            request = bytearray(b"secret-request")
            started = time.monotonic()
            with patch.object(
                    controller_module, "CLIENT_TIMEOUT_SECONDS", 0.05):
                with self.assertRaisesRegex(
                        TimeoutError, "watchdog"):
                    controller._run(
                        "development-client-test", binary, request,
                        maximum_length=8)
            self.assertLess(time.monotonic() - started, 1.0)
            self.assertEqual(request, b"\0" * len(request))

    @unittest.skipUnless(
        os.environ.get("ONE_P5_CLIENT") and os.environ.get("ONE_P5_PROVER"),
        "exact Protocol 5 controller binaries not supplied",
    )
    def test_actual_binaries_build_public_recipient_transaction(self):
        profile = (
            Path(__file__).parents[1]
            / "tools/shielded-consensus/profile/profile-descriptor-v1.bin"
        ).read_bytes()
        profile_id = hashlib.sha256(
            b"1soft/shielded-profile/v1\0" + profile).digest()
        fixture_binding = base64.b64decode(make_genesis()["deployment_binding"])
        binding = fixture_binding[:12] + profile_id + fixture_binding[44:]
        deployment_id = hashlib.sha256(
            b"1soft/shielded-deployment/v1\0" + binding).hexdigest()
        prefix = make_genesis(
            profile_descriptor=base64.b64encode(profile).decode("ascii"),
            profile_id=profile_id.hex(),
            deployment_binding=base64.b64encode(binding).decode("ascii"),
            deployment_id=deployment_id,
        )
        prefix["initial_commitments"] = []
        controller = DevelopmentController(
            Path(os.environ["ONE_P5_CLIENT"]),
            Path(os.environ["ONE_P5_PROVER"]),
            prefix,
        )
        input_note = note(100, 3)
        commitments, _ = controller.commitments([input_note])
        raw_genesis = finalize_fresh_genesis(prefix, commitments)
        owner_a = controller.derive_owner_key((17).to_bytes(32, "little"))
        owner_b = controller.derive_owner_key((19).to_bytes(32, "little"))
        outputs = (
            RecipientOutput(64, 20, owner_b, (23).to_bytes(32, "little"),
                            (29).to_bytes(32, "little")),
            RecipientOutput(64, 75, owner_a, (31).to_bytes(32, "little"),
                            (37).to_bytes(32, "little")),
        )
        prover_request = controller.spend_to_recipient_keys(
            raw_genesis, commitments, 0, input_note, outputs,
            valid_from=1, valid_until=20,
        )
        nullifier = controller.derive_note_nullifier(
            bytes.fromhex(commitments[0]), 0,
            input_note.owner_spend_secret, input_note.note_secret,
        )
        self.assertEqual(nullifier, prover_request[370:402])
        transaction = controller.prove(raw_genesis, prover_request)
        decoded = genesis_document(raw_genesis)
        self.assertEqual(len(transaction), 534 + decoded.profile.proof_length)


if __name__ == "__main__":
    unittest.main()
