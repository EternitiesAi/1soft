"""Actual CLI processes with synthetic controller wires, never Halo2 evidence.

Journal persistence, argument/input/output handling and H+1 Ed25519 certificate
verification are real. Only the expensive Rust controller/prover boundary is
replaced by temporary executables; their proof bytes are codec fixtures. The
lost-return launcher changes only the post-commit fault seam in its child.
"""
from __future__ import annotations

import base64
import hashlib
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import importlib.util
import json
import os
from pathlib import Path
import pty
import select
import sqlite3
import stat
import subprocess
import sys
import tempfile
import threading
import time
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from certificate_fixture import make_commit, make_header
from commit_verifier import sha
from protocol5_certificate import trust_from_protocol5_genesis
from protocol5_encoding import canonical_json, genesis_document, h2f, transaction_id
from protocol5_fixture import make_genesis
from protocol5_state import application_hash, execute_block, initial_state
from protocol5_state_reader import STATE_OBSERVATION_FORMAT
from test_protocol5_state import FixtureWorker
from test_protocol5_wallet import capsule_bytes


ROOT = Path(__file__).resolve().parents[1]
CLI = ROOT / "scripts/protocol5_wallet.py"
SECRET = h2f(b"cli-test-only", b"owner-spend-secret")
NOTE_SECRET = h2f(b"cli-test-only", b"genesis-note-secret")
BLINDING = h2f(b"cli-test-only", b"genesis-note-blinding")
RECIPIENT_SECRET = h2f(b"cli-test-only", b"recipient-spend-secret")
OWNER_KEY = (4).to_bytes(32, "little")
COMMITMENT = (5).to_bytes(32, "little").hex()
CRYPTO_COMMANDS = {
    "init", "status", "sync", "import-note", "approve", "export-capsule",
    "delivery-reconcile",
}

# A complete zero-argument wire executable, rather than a mocked CLI dispatcher.
# Requests are never logged. Snapshots expose only argv/environment, allowing
# the parent test to check what an actual process observer could have read.
CONTROLLER_SOURCE = r'''
import base64
import hashlib
import json
import os
from pathlib import Path
import struct
import sys
sys.path.insert(0, __SOURCE_ROOT__)
from protocol5_encoding import h2f

root = Path(__file__).resolve().parent
raw = sys.stdin.buffer.read(1967)
def field(n):
    return n.to_bytes(32, "little")
def snapshot(pid, item):
    return Path(f"/proc/{pid}/{item}").read_bytes().decode("utf-8", "replace")
record = {
    "role": Path(__file__).resolve().name,
    "argv": sys.argv,
    "cmdline": snapshot(os.getpid(), "cmdline"),
    "environ": snapshot(os.getpid(), "environ"),
    "parent_cmdline": snapshot(os.getppid(), "cmdline"),
    "parent_environ": snapshot(os.getppid(), "environ"),
    "request_length": len(raw),
}
if raw[:8] == b"1SFTCLI1":
    record["opcode"] = struct.unpack_from("<H", raw, 10)[0]
with (root / "calls.jsonl").open("a", encoding="utf-8") as log:
    log.write(json.dumps(record, sort_keys=True) + "\n")
if (root / "fail-controller").exists():
    sys.stdout.buffer.write(__SECRET__)
    sys.stderr.buffer.write(__NOTE_SECRET__.hex().encode())
    raise SystemExit(17)
if raw[:8] == b"1SFTPRV1":
    if len(raw) != 1010:
        raise SystemExit(20)
    out = b"1SFTSHD1" + raw[8:530] + struct.pack("<I", 1024) + b"P" * 1024
else:
    if raw[:8] != b"1SFTCLI1" or raw[8:10] != b"\1\0":
        raise SystemExit(21)
    opcode = struct.unpack_from("<H", raw, 10)[0]
    if opcode == 3 and len(raw) == 44:
        out = b"1SFTKEY1" + struct.pack("<H", 1) + field(9 if raw[12:] == __RECIPIENT_SECRET__ else 4)
    elif opcode == 1:
        count = struct.unpack_from("<H", raw, 172)[0]
        if count != 1 or len(raw) != 286:
            raise SystemExit(22)
        commitment = field(5) if raw[222:254] == __NOTE_SECRET__ else field(71 if struct.unpack_from("<Q", raw, 182)[0] == 20 else 72)
        out = b"1SFTGEN1" + struct.pack("<HH", 1, 1) + commitment + field(90)
    elif opcode == 5 and len(raw) == 270:
        commitment = raw[174:206]
        out = b"1SFTNUL1" + struct.pack("<H", 1) + field(70 if commitment == field(5) else 75 if commitment == field(71) else 74)
    elif opcode == 4:
        count = struct.unpack_from("<H", raw, 332)[0]
        offset = 334 + count * 32
        if len(raw) != offset + 2 + 336:
            raise SystemExit(23)
        position = struct.unpack_from("<H", raw, offset)[0]
        input_note = raw[offset + 2:offset + 114]
        outputs = [raw[offset + 114:offset + 226], raw[offset + 226:offset + 338]]
        expiry, value = struct.unpack_from("<QQ", input_note)
        domains = [raw[76+i*32:108+i*32] for i in range(8)]
        public = [field(1), *domains[:4], domains[5], domains[6], domains[4],
                  h2f(b"fixture-tree", raw[334:offset]), field(70), field(71),
                  field(72), domains[7], field(73)]
        witness = (
            b"1SFTWIT1" + struct.pack("<HIHQQ", 1, 1, position, value, expiry)
            + input_note[80:112] + input_note[16:48] + input_note[48:80]
            + b"\0" * 128
            + b"".join(output[8:16] for output in outputs)
            + b"".join(output[:8] for output in outputs)
            + b"".join(output[16:48] for output in outputs)
            + b"".join(output[48:80] for output in outputs)
            + b"".join(output[80:112] for output in outputs)
        )
        out = b"1SFTPRV1" + struct.pack("<HHI", 1, 1, 1) + raw[12:76]
        out += struct.pack("<H", 14) + b"".join(public) + witness
    else:
        raise SystemExit(24)
sys.stdout.buffer.write(out)
'''


@unittest.skipUnless(os.name == "posix", "Protocol 5 CLI requires POSIX")
class Protocol5WalletCliTests(unittest.TestCase):
    def setUp(self):
        self.assertTrue(CLI.is_file(), "Task 7 CLI has not been implemented")
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.root.chmod(0o700)
        self.wallet = self.root / "wallet.sqlite"
        self.delivery = self.root / "delivery.sqlite"
        self.client = self.root / "fixture-client"
        self.prover = self.root / "fixture-prover"
        executable = (
            "#!" + sys.executable + "\n" + CONTROLLER_SOURCE
            .replace("__SOURCE_ROOT__", repr(str(ROOT / "src")))
            .replace("__SECRET__", repr(SECRET))
            .replace("__NOTE_SECRET__", repr(NOTE_SECRET))
            .replace("__RECIPIENT_SECRET__", repr(RECIPIENT_SECRET))
        ).encode()
        for path in (self.client, self.prover):
            path.write_bytes(executable)
            path.chmod(0o700)
        keys = [Ed25519PrivateKey.from_private_bytes(bytes([index + 61]) * 32)
                for index in range(4)]
        validators = []
        engine_validators = []
        for key in keys:
            public = key.public_key().public_bytes_raw()
            validators.append({"public_key": public.hex(), "power": 10})
            engine_validators.append({
                "address": sha(public)[:20].hex().upper(),
                "pub_key": {"type": "tendermint/PubKeyEd25519",
                            "value": base64.b64encode(public).decode("ascii")},
                "power": "10", "name": "CLI fixture",
            })
        validators.sort(key=lambda row: row["public_key"])
        genesis = make_genesis(validators=validators, initial_commitments=[COMMITMENT])
        self.genesis_raw = canonical_json(genesis)
        self.genesis = genesis_document(self.genesis_raw)
        self.engine = {"chain_id": genesis["chain_id"], "initial_height": "1",
                       "validators": engine_validators, "app_state": genesis}

        self.trust = trust_from_protocol5_genesis(self.engine, self.genesis_raw)
        keyed = {sha(key.public_key().public_bytes_raw())[:20]: key for key in keys}
        self.keys = [keyed[validator.address] for validator in self.trust.validators]
        self.worker = FixtureWorker()
        self.state = initial_state(self.genesis, self.worker)
        self.height = 0
        self.app_file = self.private_file("app-genesis.json", self.genesis_raw)
        self.engine_file = self.private_file("engine-genesis.json", canonical_json(self.engine))
        self.observation_file = self.private_file("observation.json", self.observation())
        self.capsule = capsule_bytes(
            self.genesis_raw, commitment=COMMITMENT, owner_key=OWNER_KEY,
            secret=NOTE_SECRET, blinding=BLINDING)
        self.note_id = json.loads(self.capsule)["capsule_id"]
        self.env = {"PATH": "/usr/bin:/bin", "LC_ALL": "C", "PYTHONDONTWRITEBYTECODE": "1",
                    "PYTHONPATH": os.pathsep.join(str(ROOT / name) for name in ("src", "tests", "scripts"))}
        self.captured = []

    def test_init_validates_controller_before_accepting_secret_input(self):
        spec = importlib.util.spec_from_file_location(
            "protocol5_wallet_cli_ordering", CLI)
        self.assertIsNotNone(spec)
        self.assertIsNotNone(spec.loader)
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        args = SimpleNamespace(command="init", input=self.root / "secret.json")
        with patch.object(
                module, "_load_trust", return_value=(b"genesis", {})), \
                patch.object(
                    module, "_controller",
                    side_effect=RuntimeError("controller pin differs")), \
                patch.object(module, "_private_payload") as private_payload:
            with self.assertRaisesRegex(RuntimeError, "pin differs"):
                module.dispatch(args)
        private_payload.assert_not_called()

    def private_file(self, name, raw):
        path = self.root / name
        if path.exists():
            path.chmod(0o600)
        path.write_bytes(raw)
        path.chmod(0o600)
        return path

    def observation(self):
        app_hash = application_hash(self.genesis, self.height, self.state)
        signed = make_commit(
            make_header(self.trust, self.height + 1, app_hash,
                        previous=None if self.height == 0 else self.initial_block_id),
            self.trust, self.keys)
        if self.height == 0:
            self.initial_block_id = signed["commit"]["block_id"]
        return canonical_json({
            "format": STATE_OBSERVATION_FORMAT,
            "state_witness": {"genesis": self.genesis.value, "height": self.height,
                              "app_hash": app_hash, "state": self.state},
            "signed_header": signed,
        })

    def command(self, operation, *args, crypto=None):
        command = [sys.executable, "-B", str(CLI), operation,
                   "--wallet", str(self.wallet),
                   "--app-genesis", str(self.app_file),
                   "--app-genesis-sha256", hashlib.sha256(self.genesis_raw).hexdigest(),
                   "--engine-genesis", str(self.engine_file),
                   "--engine-genesis-sha256", hashlib.sha256(canonical_json(self.engine)).hexdigest()]
        use_crypto = operation in CRYPTO_COMMANDS if crypto is None else crypto
        if use_crypto:
            for role in ("client", "prover"):
                path = getattr(self, role)
                command += ["--" + role, str(path), "--" + role + "-sha256",
                            hashlib.sha256(path.read_bytes()).hexdigest()]
        return [*command, *map(str, args)]

    def call(self, operation, *args, payload=b"", crypto=None, command=None):
        command = self.command(operation, *args, crypto=crypto) if command is None else command
        process = subprocess.run(command, input=payload, capture_output=True,
                                 cwd=ROOT, env=self.env, timeout=15)
        self.captured.append(process)
        return process

    def success(self, process):
        self.assertEqual(process.returncode, 0, process.stderr.decode("utf-8", "replace"))
        self.assertEqual(process.stderr, b"")
        value = json.loads(process.stdout)
        self.assertEqual(process.stdout, canonical_json(value) + b"\n")
        self.assertIsInstance(value, dict)
        return value

    def refused(self, process):
        self.assertEqual(process.returncode, 2, process.stderr.decode("utf-8", "replace"))
        self.assertEqual(process.stdout, b"")
        self.assertTrue(process.stderr.strip())
        self.assertNotIn(b"Traceback", process.stderr)
        self.assert_private(process.stdout + process.stderr)

    def assert_private(self, raw):
        for secret in (SECRET, NOTE_SECRET, BLINDING, RECIPIENT_SECRET):
            for representation in (secret, secret.hex().encode(), base64.b64encode(secret),
                                   str(int.from_bytes(secret, "little")).encode()):
                self.assertNotIn(representation, raw)

    def init(self):
        return self.success(self.call("init", payload=canonical_json({"owner_spend_secret": SECRET.hex()})))

    def status(self):
        return self.success(self.call("status"))

    def import_payload(self):
        return canonical_json({"capsule_base64": base64.b64encode(self.capsule).decode("ascii"),
                               "owner_spend_secret": SECRET.hex()})

    def bootstrap(self):
        self.init()
        revision = self.status()["revision"]
        self.success(self.call("sync", "--expected-revision", revision, "--input", self.observation_file))
        revision = self.status()["revision"]
        self.success(self.call("import-note", "--expected-revision", revision, payload=self.import_payload()))
        return self.status()

    def prepare(self):
        return self.success(self.call("prepare", "--note-id", self.note_id,
                                     "--recipient-owner-key", (9).to_bytes(32, "little").hex(),
                                     "--value", 20, "--valid-until", 20))

    def approved(self):
        self.bootstrap()
        review = self.prepare()
        return self.success(self.call("approve", payload=canonical_json({
            "review": review["review"], "confirmation": review["confirmation"]})))

    def journal_snapshot(self):
        with sqlite3.connect(f"file:{self.wallet}?mode=ro", uri=True) as database:
            return tuple(database.iterdump())

    def controller_records(self):
        path = self.root / "calls.jsonl"
        return [] if not path.exists() else [json.loads(line) for line in path.read_text().splitlines()]

    def test_init_owner_key_status_are_canonical_and_private(self):
        self.init()
        owner = self.success(self.call("owner-key"))
        self.assertEqual(owner["owner_key"], OWNER_KEY.hex())
        state = self.status()
        self.assertEqual(state["owner_key"], OWNER_KEY.hex())
        self.assertEqual(state["revision_counter"], 0)
        self.assertEqual(state["notes"], [])
        self.assertEqual(state["decisions"], [])
        self.assertFalse(state["latest_state_guaranteed"])
        self.assertFalse(state["real_funds"])
        for path in (self.wallet, Path(str(self.wallet) + ".lock")):
            self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o600)
        for process in self.captured:
            self.assert_private(process.stdout + process.stderr)
            self.assert_private(b"\0".join(item.encode() for item in process.args))
        records = self.controller_records()
        self.assertGreaterEqual(len(records), 1)
        for record in records:
            self.assertEqual(len(record["argv"]), 1)
            self.assert_private(canonical_json(record))
            environment = dict(item.split("=", 1) for item in record["environ"].split("\0") if item)
            self.assertEqual(environment, {"PATH": "/usr/bin:/bin", "LC_ALL": "C"})

    def test_init_refuses_existing_wallet_without_changing_authority(self):
        self.init()
        before = self.journal_snapshot()
        self.refused(self.call("init", payload=canonical_json({"owner_spend_secret": NOTE_SECRET.hex()})))
        self.assertEqual(self.journal_snapshot(), before)

    def test_empty_init_input_generates_owner_without_returning_secret(self):
        self.success(self.call("init"))
        state = self.status()
        self.assertEqual(state["owner_key"], OWNER_KEY.hex())
        self.assertNotIn("owner_spend_secret", state)
        with sqlite3.connect(self.wallet) as database:
            generated = database.execute("SELECT spend_secret FROM config").fetchone()[0]
        self.assertEqual(len(generated), 32)
        self.assertNotEqual(generated, SECRET)
        for process in self.captured:
            for representation in (generated, generated.hex().encode(), base64.b64encode(generated),
                                   str(int.from_bytes(generated, "little")).encode()):
                self.assertNotIn(representation, process.stdout + process.stderr)

    def test_strict_stdin_rejects_trailing_duplicate_unknown_and_noncanonical_input(self):
        good = canonical_json({"owner_spend_secret": SECRET.hex()})
        cases = [good + b"\n", good + b"{}", b" " + good,
                 b'{"owner_spend_secret":"' + SECRET.hex().encode() + b'","owner_spend_secret":"' + SECRET.hex().encode() + b'"}',
                 canonical_json({"owner_spend_secret": SECRET.hex(), "extra": 1}),
                 canonical_json({"owner_spend_secret": SECRET.hex().upper()}),
                 canonical_json({"owner_spend_secret": "00" * 32}),
                 b"[]", b"null", b"\xff", b"x" * 8193]
        for payload in cases:
            with self.subTest(case=cases.index(payload)):
                self.refused(self.call("init", payload=payload))
                self.assertFalse(self.wallet.exists())
                self.assertFalse(Path(str(self.wallet) + ".lock").exists())
        self.assertEqual(self.controller_records(), [])

    def test_private_file_input_requires_exact_mode_regular_owned_single_link(self):
        good = canonical_json({"owner_spend_secret": SECRET.hex()})
        for mode in (0o644, 0o640, 0o400, 0o700):
            with self.subTest(mode=oct(mode)):
                path = self.private_file("unsafe-secret.json", good)
                path.chmod(mode)
                self.refused(self.call("init", "--input", path))
                self.assertFalse(self.wallet.exists())
        target = self.private_file("secret-target.json", good)
        symlink = self.root / "secret-link.json"
        symlink.symlink_to(target)
        self.refused(self.call("init", "--input", symlink))
        hardlink = self.root / "secret-hardlink.json"
        os.link(target, hardlink)
        self.refused(self.call("init", "--input", hardlink))
        self.assertFalse(self.wallet.exists())
        self.refused(self.call("init", "--input", self.root))
        fifo = self.root / "secret-fifo"
        os.mkfifo(fifo, 0o600)
        self.refused(self.call("init", "--input", fifo))
        self.assertEqual(self.controller_records(), [])

    def test_private_file_refuses_symlink_parent(self):
        directory = self.root / "real"
        directory.mkdir(mode=0o700)
        target = directory / "secret.json"
        target.write_bytes(canonical_json({"owner_spend_secret": SECRET.hex()}))
        target.chmod(0o600)
        link = self.root / "alias"
        link.symlink_to(directory, target_is_directory=True)
        self.refused(self.call("init", "--input", link / "secret.json"))
        self.assertFalse(self.wallet.exists())

    def test_private_file_and_stdin_are_not_ambiguous_inputs(self):
        payload = canonical_json({"owner_spend_secret": SECRET.hex()})
        path = self.private_file("secret.json", payload)
        self.refused(self.call("init", "--input", path, payload=payload))
        self.assertFalse(self.wallet.exists())
        self.success(self.call("init", "--input", path))
        self.assertEqual(self.status()["revision_counter"], 0)

    def test_duplicate_missing_abbreviated_and_raw_secret_flags_are_sanitized(self):
        payload = canonical_json({"owner_spend_secret": SECRET.hex()})
        for extra in (("--wallet", str(self.wallet)),
                      ("--wallet=" + str(self.wallet),),
                      ("--app-genesis-sha256", hashlib.sha256(self.genesis_raw).hexdigest()),
                      ("--owner-spend-secret", SECRET.hex()),
                      ("--secret=" + SECRET.hex(),),
                      ("--input",), ("--in", "missing.json"),
                      (SECRET.hex(),)):
            with self.subTest(kind=extra[0].split("=")[0]):
                self.refused(self.call("init", *extra, payload=payload))
                self.assertFalse(self.wallet.exists())
        command = self.command("init")
        index = command.index("--app-genesis-sha256")
        del command[index:index + 2]
        self.refused(self.call("init", payload=payload, command=command))
        self.assertFalse(self.wallet.exists())
        self.assertEqual(self.controller_records(), [])

    def test_wrong_genesis_and_controller_pins_fail_before_initialization(self):
        for flag in ("--app-genesis-sha256", "--engine-genesis-sha256",
                     "--client-sha256", "--prover-sha256"):
            with self.subTest(flag=flag):
                command = self.command("init")
                command[command.index(flag) + 1] = "00" * 32
                self.refused(self.call("init", payload=canonical_json({"owner_spend_secret": SECRET.hex()}), command=command))
                self.assertFalse(self.wallet.exists())
        self.assertEqual(self.controller_records(), [])

    def test_controller_failure_sanitizes_private_stdout_and_stderr(self):
        self.private_file("fail-controller", b"fail")
        self.refused(self.call("init", payload=canonical_json({"owner_spend_secret": SECRET.hex()})))
        self.assertFalse(self.wallet.exists())
        self.assertEqual(len(self.controller_records()), 1)

    def test_authenticated_genesis_import_and_prepare_are_durable(self):
        state = self.bootstrap()
        self.assertEqual(state["state_height"], 0)
        self.assertEqual(state["revision_counter"], 2)
        self.assertEqual(state["values"]["spendable"], 100)
        self.assertEqual(state["notes"][0]["capsule_id"], self.note_id)
        self.assertEqual(state["notes"][0]["state"], "spendable")
        before = self.journal_snapshot()
        review = self.prepare()
        self.assertEqual(review["review"]["payment_value"], 20)
        self.assertEqual(review["review"]["change_value"], 75)
        self.assertEqual(review["review"]["fee"], 5)
        self.assertEqual(review["review"]["checkpoint_height"], 0)
        self.assertEqual(review["confirmation"], review["review"]["review_id"])
        self.assertFalse(review["reserved"])
        self.assertFalse(review["proved"])
        self.assertFalse(review["submitted"])
        self.assertEqual(self.journal_snapshot(), before)
        for process in self.captured:
            self.assert_private(process.stdout + process.stderr)
        for record in self.controller_records():
            self.assert_private(canonical_json(record))

    def test_wrong_revision_and_invalid_certificate_do_not_mutate(self):
        self.init()
        before = self.journal_snapshot()
        self.refused(self.call("sync", "--expected-revision", "00" * 32,
                               payload=self.observation()))
        self.assertEqual(self.journal_snapshot(), before)
        observation = json.loads(self.observation())
        observation["state_witness"]["app_hash"] = "22" * 32
        self.refused(self.call("sync", "--expected-revision", self.status()["revision"],
                               payload=canonical_json(observation)))
        self.assertEqual(self.journal_snapshot(), before)

    def test_missing_wrong_and_stale_confirmation_never_reserves_or_proves(self):
        self.bootstrap()
        prepared = self.prepare()
        review = prepared["review"]
        before = self.journal_snapshot()
        baseline = len([r for r in self.controller_records() if r["role"] == "fixture-prover"])
        for payload in (canonical_json({"review": review}),
                        canonical_json({"review": review, "confirmation": "00" * 32}),
                        canonical_json({"review": review, "confirmation": prepared["confirmation"], "extra": 1})):
            self.refused(self.call("approve", payload=payload))
            self.assertEqual(self.journal_snapshot(), before)
        stale = dict(review, wallet_revision=review["wallet_revision"] + 1)
        projected = {key: value for key, value in stale.items() if key != "review_id"}
        stale["review_id"] = hashlib.sha256(b"1soft/protocol5-wallet-review-id/v1\0" + canonical_json(projected)).hexdigest()
        self.refused(self.call("approve", payload=canonical_json({"review": stale, "confirmation": stale["review_id"]})))
        self.assertEqual(self.journal_snapshot(), before)
        self.assertEqual(len([r for r in self.controller_records() if r["role"] == "fixture-prover"]), baseline)

    def test_recover_outputs_exact_transaction_with_private_exclusive_creation(self):
        approved = self.approved()
        self.assertEqual(approved["status"], "proved_and_reserved")
        self.assertFalse(approved["transaction_exposed"])
        before = self.journal_snapshot()
        output = self.root / "transaction.bin"
        result = self.success(self.call("recover", "--decision-id", approved["decision_id"], "--output", output))
        self.assertEqual(stat.S_IMODE(output.stat().st_mode), 0o600)
        raw = output.read_bytes()
        self.assertEqual(transaction_id(raw).hex(), approved["txid"])
        self.assertEqual(len(raw), 1558)
        self.assertNotIn(base64.b64encode(raw), canonical_json(result))
        self.refused(self.call("recover", "--decision-id", approved["decision_id"], "--output", output))
        self.assertEqual(output.read_bytes(), raw)
        self.assertEqual(self.journal_snapshot(), before)

    def test_recover_refuses_symlink_hardlink_and_symlink_parent_outputs(self):
        approved = self.approved()
        before = self.journal_snapshot()
        target = self.private_file("target", b"preserve me")
        link = self.root / "link"
        link.symlink_to(target)
        self.refused(self.call("recover", "--decision-id", approved["decision_id"], "--output", link))
        hardlink = self.root / "hardlink"
        os.link(target, hardlink)
        self.refused(self.call("recover", "--decision-id", approved["decision_id"], "--output", hardlink))
        directory = self.root / "real-output"
        directory.mkdir(mode=0o700)
        alias = self.root / "alias-output"
        alias.symlink_to(directory, target_is_directory=True)
        self.refused(self.call("recover", "--decision-id", approved["decision_id"], "--output", alias / "new.bin"))
        self.assertFalse((directory / "new.bin").exists())
        self.assertEqual(target.read_bytes(), b"preserve me")
        self.assertEqual(self.journal_snapshot(), before)

    def test_recover_requires_one_identity_and_an_output_path(self):
        approved = self.approved()
        for args in (("--decision-id", approved["decision_id"]),
                     ("--output", self.root / "missing-id.bin"),
                     ("--decision-id", approved["decision_id"], "--review-id", "11" * 32,
                      "--output", self.root / "ambiguous.bin")):
            self.refused(self.call("recover", *args))
        self.assertFalse((self.root / "missing-id.bin").exists())
        self.assertFalse((self.root / "ambiguous.bin").exists())

    def test_owner_key_and_recover_do_not_invoke_controller(self):
        approved = self.approved()
        count = len(self.controller_records())
        self.client.unlink()
        self.prover.unlink()
        self.success(self.call("owner-key"))
        output = self.root / "offline-recovered.bin"
        self.success(self.call("recover", "--decision-id", approved["decision_id"], "--output", output))
        self.assertEqual(transaction_id(output.read_bytes()).hex(), approved["txid"])
        self.assertEqual(len(self.controller_records()), count)

    def test_capsule_release_requires_authenticated_execution_and_private_output(self):
        approved = self.approved()
        output = self.root / "payment-capsule.json"
        self.refused(self.call("export-capsule", "--decision-id", approved["decision_id"], "--output", output))
        self.assertFalse(output.exists())
        txfile = self.root / "transaction.bin"
        self.success(self.call("recover", "--decision-id", approved["decision_id"], "--output", txfile))
        self.state, results = execute_block(self.genesis, self.state, [txfile.read_bytes()], 1, self.worker)
        self.assertEqual(results[0]["code"], 0)
        self.height = 1
        self.success(self.call("sync", "--expected-revision", self.status()["revision"], payload=self.observation()))
        result = self.success(self.call("export-capsule", "--decision-id", approved["decision_id"], "--output", output))
        raw = output.read_bytes()
        capsule = json.loads(raw)
        self.assertEqual(stat.S_IMODE(output.stat().st_mode), 0o600)
        self.assertEqual(capsule["origin"], {"kind": "transaction", "txid": approved["txid"], "output_index": 0})
        self.assertEqual(capsule["value"], 20)
        self.assertEqual(capsule["commitment"], (71).to_bytes(32, "little").hex())
        for key in ("note_secret", "blinding"):
            self.assertNotIn(capsule[key].encode(), canonical_json(result))
        self.refused(self.call("export-capsule", "--decision-id", approved["decision_id"], "--output", output))
        self.assertEqual(output.read_bytes(), raw)

    def test_sensitive_stdin_is_refused_when_attached_to_a_terminal(self):
        self.bootstrap()
        before = self.journal_snapshot()
        master, slave = pty.openpty()
        try:
            process = subprocess.Popen(self.command("approve"), stdin=slave, stdout=subprocess.PIPE,
                                       stderr=subprocess.PIPE, cwd=ROOT, env=self.env)
            os.close(slave)
            slave = None
            stdout, stderr = process.communicate(timeout=10)
            result = subprocess.CompletedProcess(process.args, process.returncode, stdout, stderr)
            self.refused(result)
            self.assertEqual(self.journal_snapshot(), before)
        finally:
            if slave is not None:
                os.close(slave)
            os.close(master)
            if "process" in locals() and process.poll() is None:
                process.kill()
                process.wait(timeout=5)

    def test_terminal_lost_return_recovers_exact_transaction(self):
        self.bootstrap()
        prepared = self.prepare()
        approval = self.private_file("approval.json", canonical_json({
            "review": prepared["review"], "confirmation": prepared["confirmation"]}))
        real_command = self.command("approve", "--input", approval)
        launcher = (
            "import os,runpy,sys; import protocol5_wallet as wallet; "
            "wallet.Protocol5Wallet._approval_committed=lambda self,decision_id: os._exit(73); "
            "sys.argv=sys.argv[1:]; runpy.run_path(sys.argv[0],run_name='__main__')"
        )
        command = [sys.executable, "-B", "-c", launcher, *real_command[2:]]
        master, slave = pty.openpty()
        display = bytearray()
        try:
            process = subprocess.Popen(command, stdin=slave, stdout=slave, stderr=slave,
                                       cwd=ROOT, env=self.env, start_new_session=True)
            os.close(slave)
            slave = None
            deadline = time.monotonic() + 15
            while process.poll() is None:
                if time.monotonic() >= deadline:
                    self.fail("approval process did not reach its bounded post-commit fault seam")
                if select.select([master], [], [], 0.1)[0]:
                    try:
                        display.extend(os.read(master, 65536))
                    except OSError:
                        break
            process.wait(timeout=5)
            self.assertEqual(process.returncode, 73, bytes(display))
            self.assertEqual(display, b"")
        finally:
            if slave is not None:
                os.close(slave)
            os.close(master)
            if "process" in locals() and process.poll() is None:
                process.kill()
                process.wait(timeout=5)
        with sqlite3.connect(self.wallet) as database:
            rows = database.execute("SELECT decision_id,txid,transaction_bytes FROM decisions").fetchall()
        self.assertEqual(len(rows), 1)
        expected_id, expected_txid, expected_raw = rows[0]
        self.client.unlink()
        self.prover.unlink()
        output = self.root / "recovered-after-lost-return.bin"
        self.success(self.call("recover", "--review-id", prepared["confirmation"], "--output", output))
        self.assertEqual(output.read_bytes(), expected_raw)
        self.assertEqual(transaction_id(output.read_bytes()).hex(), expected_txid)
        second = self.root / "recovered-again.bin"
        self.success(self.call("recover", "--decision-id", expected_id, "--output", second))
        self.assertEqual(second.read_bytes(), expected_raw)
        before = self.journal_snapshot()
        self.refused(self.call("recover", "--review-id", "aa" * 32, "--output", self.root / "unknown.bin"))
        self.assertEqual(self.journal_snapshot(), before)
        self.assertFalse((self.root / "unknown.bin").exists())
        self.assertEqual(len([r for r in self.controller_records() if r["role"] == "fixture-prover"]), 1)


    def test_prepare_is_controller_free_and_malformed_values_do_not_mutate(self):
        self.bootstrap()
        before = self.journal_snapshot()
        count = len(self.controller_records())
        self.client.unlink()
        self.prover.unlink()
        self.prepare()
        for value in ("0", "-1", "+20", "020", "20.0", "true"):
            self.refused(self.call(
                "prepare", "--note-id", self.note_id,
                "--recipient-owner-key", OWNER_KEY.hex(), "--value", value,
                "--valid-until", "20"))
        self.assertEqual(self.journal_snapshot(), before)
        self.assertEqual(len(self.controller_records()), count)

    def test_exported_capsule_can_be_imported_by_its_recipient(self):
        approved = self.approved()
        txfile = self.root / "payment.bin"
        self.success(self.call("recover", "--decision-id", approved["decision_id"], "--output", txfile))
        self.state, results = execute_block(self.genesis, self.state, [txfile.read_bytes()], 1, self.worker)
        self.assertEqual(results[0]["code"], 0)
        self.height = 1
        observation = self.observation()
        self.success(self.call("sync", "--expected-revision", self.status()["revision"], payload=observation))
        capsule_file = self.root / "recipient-capsule.json"
        self.success(self.call("export-capsule", "--decision-id", approved["decision_id"], "--output", capsule_file))
        capsule_raw = capsule_file.read_bytes()
        capsule = json.loads(capsule_raw)
        self.assertEqual(capsule["owner_key"], (9).to_bytes(32, "little").hex())
        sender_before = self.journal_snapshot()
        sender_path = self.wallet
        self.wallet = self.root / "recipient-wallet.sqlite"
        self.success(self.call("init", payload=canonical_json({"owner_spend_secret": RECIPIENT_SECRET.hex()})))
        self.success(self.call("sync", "--expected-revision", self.status()["revision"], payload=observation))
        imported = self.success(self.call("import-note", "--expected-revision", self.status()["revision"], payload=canonical_json({
            "capsule_base64": base64.b64encode(capsule_raw).decode("ascii"),
            "owner_spend_secret": RECIPIENT_SECRET.hex()})))
        self.assertEqual(imported["capsule_id"], capsule["capsule_id"])
        state = self.status()
        self.assertEqual(state["values"]["spendable"], 20)
        self.assertEqual(state["notes"][0]["chain_position"], 1)
        self.assertEqual(state["notes"][0]["state"], "spendable")
        self.wallet = sender_path
        self.assertEqual(self.journal_snapshot(), sender_before)
        for process in self.captured:
            self.assert_private(process.stdout + process.stderr)
            for key in ("note_secret", "blinding"):
                opening = bytes.fromhex(capsule[key])
                for representation in (opening, opening.hex().encode(), base64.b64encode(opening),
                                       str(int.from_bytes(opening, "little")).encode()):
                    self.assertNotIn(representation, process.stdout + process.stderr)

    def test_delivery_is_one_attempt_until_authenticated_receipt_reconciles(self):
        approved = self.approved()
        test = self
        posts = []
        gets = []
        server_errors = []

        class Handler(BaseHTTPRequestHandler):
            protocol_version = "HTTP/1.1"

            def reply(self, value):
                body = canonical_json(value)
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(body)))
                self.send_header("Connection", "close")
                self.end_headers()
                self.wfile.write(body)

            def do_POST(self):
                try:
                    request = json.loads(self.rfile.read(int(self.headers["Content-Length"])))
                    raw = base64.b64decode(request["params"]["tx"], validate=True)
                    posts.append((self.path, request, raw))
                    test.state, results = execute_block(test.genesis, test.state, [raw], 1, test.worker)
                    if results[0]["code"] != 0:
                        raise AssertionError("synthetic transport transaction failed fixture execution")
                    test.height = 1
                    self.reply({"jsonrpc": "2.0", "id": request["id"], "result": {
                        "code": 0, "data": "", "log": "", "codespace": "",
                        "hash": hashlib.sha256(raw).hexdigest().upper()}})
                except Exception as error:
                    server_errors.append(repr(error))
                    self.close_connection = True

            def do_GET(self):
                gets.append(self.path)
                observation = json.loads(test.observation())
                witness = observation["state_witness"]
                if self.path.startswith("/abci_query?"):
                    result = {"response": {"code": 0, "log": "", "info": "", "index": "0",
                                           "key": None, "value": base64.b64encode(canonical_json(witness)).decode("ascii"),
                                           "proofOps": None, "height": str(witness["height"]), "codespace": ""}}
                else:
                    result = {"signed_header": observation["signed_header"], "canonical": True}
                self.reply({"jsonrpc": "2.0", "id": -1, "result": result})

            def log_message(self, *_):
                pass

        server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        endpoint = f"http://127.0.0.1:{server.server_address[1]}/"

        def delivery_call(operation, *args, payload=b""):
            return self.call(operation, "--delivery", self.delivery,
                             "--endpoint", endpoint, *args, payload=payload)

        try:
            initialized = self.success(delivery_call("delivery-init"))
            self.assertEqual(initialized["attempts"], 0)
            self.assertEqual(stat.S_IMODE(self.delivery.stat().st_mode), 0o600)
            prepared = self.success(delivery_call("delivery-prepare", "--decision-id", approved["decision_id"]))
            self.assertEqual(posts, [])
            self.assertEqual(prepared["review"]["txid"], approved["txid"])
            payload = canonical_json({"review": prepared["review"], "confirmation": prepared["confirmation"]})
            self.refused(delivery_call("delivery-send", payload=canonical_json({"review": prepared["review"]})))
            self.assertEqual(posts, [])
            sent = self.success(delivery_call("delivery-send", payload=payload))
            self.assertEqual(server_errors, [])
            self.assertEqual(len(posts), 1)
            self.assertEqual(posts[0][1]["method"], "broadcast_tx_sync")
            self.assertEqual(transaction_id(posts[0][2]).hex(), approved["txid"])
            self.assertEqual(sent["transport_state"], "endpoint_admitted")
            self.assertFalse(sent["execution_authenticated"])
            self.assertFalse(sent["endpoint_admission_is_execution"])
            self.assertFalse(sent["retry_available"])
            self.refused(delivery_call("delivery-send", payload=payload))
            self.assertEqual(len(posts), 1)
            inspected = self.success(delivery_call("delivery-inspect", "--decision-id", approved["decision_id"]))
            self.assertEqual(inspected["attempts"], 1)
            self.assertIsNone(inspected["decision_state"])
            observation = self.success(delivery_call("delivery-collect", "--timeout", "2"))
            self.assertEqual(len(gets), 2)
            self.assertTrue(gets[0].startswith("/abci_query?"))
            self.assertEqual(gets[1], "/commit?height=2")
            self.assertEqual(observation["state_height"], 1)
            before = self.journal_snapshot()
            self.refused(delivery_call("delivery-reconcile", "--decision-id", approved["decision_id"],
                                       "--observation-id", observation["observation_id"], "--expected-revision", "00" * 32))
            self.assertEqual(self.journal_snapshot(), before)
            reconciled = self.success(delivery_call("delivery-reconcile", "--decision-id", approved["decision_id"],
                                                    "--observation-id", observation["observation_id"],
                                                    "--expected-revision", self.status()["revision"]))
            self.assertEqual(reconciled["decision_state"], "executed_exact")
            self.assertTrue(reconciled["execution_authenticated"])
            current = self.status()
            self.assertEqual(current["values"]["spent"], 100)
            self.assertEqual(current["values"]["spendable"], 75)
            again = self.success(delivery_call("delivery-reconcile", "--decision-id", approved["decision_id"],
                                              "--observation-id", observation["observation_id"],
                                              "--expected-revision", current["revision"]))
            self.assertEqual(again["decision_state"], "executed_exact")
            self.assertEqual(again["revision"], reconciled["revision"])
            self.assertEqual(len(posts), 1)
            for process in self.captured:
                self.assert_private(process.stdout + process.stderr)
            for record in self.controller_records():
                self.assert_private(canonical_json(record))
        finally:
            server.shutdown()
            server.server_close()
            thread.join(timeout=2)


if __name__ == "__main__":
    unittest.main()
