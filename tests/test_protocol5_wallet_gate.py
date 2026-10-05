"""Strict checker tests using authored signatures and codec proofs, never engine evidence."""
from __future__ import annotations

import base64
import copy
import hashlib
import importlib
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from certificate_fixture import make_commit, make_header
from commit_verifier import sha
from protocol5_certificate import trust_from_protocol5_genesis
from protocol5_encoding import canonical_json, genesis_document, h2f, transaction_id
from protocol5_fixture import make_genesis, make_public_fields, make_tx
from protocol5_state import application_hash, execute_block, initial_state
from protocol5_state_reader import STATE_OBSERVATION_FORMAT
from protocol5_wallet import _SCHEMA as WALLET_SCHEMA
from protocol5_delivery import _SCHEMA as DELIVERY_SCHEMA
from test_protocol5_state import FixtureWorker

ROOT = Path(__file__).resolve().parents[1]
CHECKER = ROOT / "tools/release/check_protocol5_wallet.py"
SETTINGS_PATH = ROOT / "reference/protocol5-wallet-qualification-settings-v1.json"
SETTINGS = json.loads(SETTINGS_PATH.read_bytes())
INPUT_NAMES = ("engine", "worker", "client", "prover", "profile", "kat", "toolchain", "policy", "genesis")
SCHEMA = "1soft-protocol5-wallet-preflight-v1"
COMPLETE = "completed-awaiting-external-validation"


def digest(raw):
    return hashlib.sha256(raw).hexdigest()


def field(number):
    return number.to_bytes(32, "little").hex()


def unassessed():
    return {
        "schema": SCHEMA, "status": "unassessed", "source_commit": "1" * 40,
        "source_tree": "2" * 40, "source_dirty_before": False, "source_dirty_after": False,
        "source_files": {}, "settings_sha256": digest(SETTINGS_PATH.read_bytes()),
        "engine_version": "0.38.25", "inputs": dict.fromkeys(INPUT_NAMES),
        "expected_sha256": {"client": None, "prover": None}, "genesis_sha256": None,
        "profile_id": None, "deployment_id": None,
        "missing_inputs": [*INPUT_NAMES, "expected_client_sha256", "expected_prover_sha256"],
        "failures": [], "checks": [], "processes_started": False,
        "actual_proof_accepted": False, "processes": [], "wallet_manifests": [],
        "delivery_manifests": [], "artifacts": [],
        "claims": {name: False for name in SETTINGS["claims_false"]},
    }


class Fixture:
    """Complete contract fixture. It is not a real qualification run."""
    def __init__(self, root):
        self.root = root
        self.source = root / "source"
        self.source.mkdir()
        for name in SETTINGS["source_files"]:
            target = self.source / name
            target.parent.mkdir(parents=True, exist_ok=True)
            actual = ROOT / name
            target.write_bytes(actual.read_bytes() if actual.exists() else b"fixture source\n")
        self.git("init", "-q")
        self.git("add", ".")
        self.git("-c", "user.name=Checker fixture", "-c", "user.email=fixture@example.invalid",
                 "commit", "-qm", "authored checker fixture")
        self.artifacts = root / "report.json.artifacts"
        self.artifacts.mkdir(mode=0o700)
        self.value = unassessed()
        self.value.update(status=COMPLETE, missing_inputs=[], processes_started=True, actual_proof_accepted=True,
                          source_commit=self.git("rev-parse", "HEAD"), source_tree=self.git("rev-parse", "HEAD^{tree}"),
                          source_files={name: digest((self.source / name).read_bytes()) for name in SETTINGS["source_files"]},
                          expected_sha256={"client": "3" * 64, "prover": "4" * 64})
        self.raw = {}
        static = ROOT / "tools/shielded-consensus/profile"
        for name in ("profile-descriptor-v1.bin", "kat-v1.bin", "toolchain-manifest-v1.json", "sandbox-policy-v1.json"):
            self.raw[name] = (static / name).read_bytes()
        manifest = json.loads((ROOT / "tools/shielded-consensus/COMPONENT_MANIFEST.json").read_bytes())
        worker_hash = next(row["sha256"] for row in manifest["release_artifacts"] if row["name"] == "shielded-verifier-worker")
        profile = self.raw["profile-descriptor-v1.bin"]
        profile_id = digest(b"1soft/shielded-profile/v1\0" + profile)
        binding = (b"1SFTDEP1\1\0\1\0" + bytes.fromhex(profile_id) + bytes.fromhex(worker_hash)
                   + hashlib.sha256(self.raw["toolchain-manifest-v1.json"]).digest()
                   + hashlib.sha256(self.raw["sandbox-policy-v1.json"]).digest())
        keys = [Ed25519PrivateKey.from_private_bytes(bytes([index + 61]) * 32) for index in range(4)]
        validators, engine_validators = [], []
        for key in keys:
            public = key.public_key().public_bytes_raw()
            validators.append({"public_key": public.hex(), "power": 10})
            engine_validators.append({"address": sha(public)[:20].hex().upper(),
                                      "pub_key": {"type": "tendermint/PubKeyEd25519", "value": base64.b64encode(public).decode()},
                                      "power": "10", "name": "fixture"})
        validators.sort(key=lambda row: row["public_key"])
        genesis = make_genesis(profile_descriptor=base64.b64encode(profile).decode(), profile_id=profile_id,
                               deployment_binding=base64.b64encode(binding).decode(),
                               deployment_id=digest(b"1soft/shielded-deployment/v1\0" + binding),
                               validators=validators, initial_commitments=[field(91)])
        template = dict(genesis, initial_commitments=[])
        self.raw["genesis-template.json"] = canonical_json(template)
        self.raw["application-genesis.json"] = canonical_json(genesis)
        self.genesis = genesis_document(self.raw["application-genesis.json"])
        self.engine = {"chain_id": genesis["chain_id"], "initial_height": "1",
                       "validators": engine_validators, "app_state": genesis}
        self.raw["engine-genesis.json"] = canonical_json(self.engine)
        self.trust = trust_from_protocol5_genesis(self.engine, self.genesis.raw)
        keyed = {sha(key.public_key().public_bytes_raw())[:20]: key for key in keys}
        self.keys = [keyed[row.address] for row in self.trust.validators]
        self.worker = FixtureWorker()
        self.state = initial_state(self.genesis, self.worker)
        self.height = 0
        self.previous = None
        self.observations = {}
        self.transactions = {}
        for name, marker, height in (("payment", 1, 1), ("recipient", 2, 2)):
            self.transactions[name] = self.transaction(marker, height)
            self.accept(name, height)
        original = self.transaction(3, 3, proof_byte=b"Q")
        self.transactions["equivalent-original"] = original
        self.transactions["equivalent-winner"] = self.transaction(3, 3)
        self.accept("equivalent-winner", 3, observation_name="equivalent")
        self.transactions["conflict-original"] = self.transaction(4, 4, proof_byte=b"Q")
        self.transactions["conflict-winner"] = self.transaction(4, 4, outputs=(111, 112))
        self.accept("conflict-winner", 4, observation_name="conflict")
        self.transactions["expiry"] = self.transaction(5, 5, until=8)
        for height in (5, 6, 7):
            self.state, _ = execute_block(self.genesis, self.state, [], height, self.worker)
            self.height = height
        self.observations["expiry"] = self.observation()
        for name, raw in self.transactions.items():
            self.raw[name + "-transaction.bin"] = raw
        for name, observation in self.observations.items():
            self.raw[name + "-observation.json"] = canonical_json(observation)
        self.value.update(genesis_sha256=self.genesis.sha256.hex(), profile_id=profile_id,
                          deployment_id=self.genesis.deployment.identity.hex())
        observed = {"engine": SETTINGS["engine_sha256"], "worker": worker_hash, "client": "3" * 64, "prover": "4" * 64}
        input_artifacts = {"profile": "profile-descriptor-v1.bin", "kat": "kat-v1.bin",
                           "toolchain": "toolchain-manifest-v1.json", "policy": "sandbox-policy-v1.json",
                           "genesis": "genesis-template.json"}
        self.value["inputs"] = {name: {"name": name + ".bin", "sha256": item, "bytes": 100} for name, item in observed.items()}
        for name, artifact in input_artifacts.items():
            self.value["inputs"][name] = {"name": artifact, "sha256": digest(self.raw[artifact]), "bytes": len(self.raw[artifact])}
        self.processes()
        self.manifests()
        self.checks()
        self.raw["leakage-scan.json"] = canonical_json({
            "format": "1soft/protocol5-wallet-leakage-scan/v1", "known_secret_count": 32,
            "encodings": ["raw", "hex", "base64", "decimal"], "private_journals_excluded": True,
            "witness_present": False, "prover_request_present": False, "capsule_present": False,
            "surfaces": [{"id": name, "objects": 1, "bytes": 1, "matches": 0} for name in SETTINGS["leakage_surfaces"]]})
        self.sync_artifacts()

    def git(self, *args):
        result = subprocess.run(["git", *args], cwd=self.source, check=True, capture_output=True, text=True)
        return result.stdout.strip()

    def transaction(self, marker, valid_from, *, proof_byte=b"P", outputs=None, until=20):
        fields = list(make_public_fields(self.genesis.value))
        fields[5], fields[6] = field(valid_from), field(until)
        fields[8], fields[9] = self.state["current_root"], field(100 + marker)
        first, second = outputs or (200 + marker * 2, 201 + marker * 2)
        fields[10], fields[11] = field(first), field(second)
        return make_tx(self.genesis.value, proof=proof_byte * self.genesis.profile.proof_length, fields=fields)

    def observation(self):
        app_hash = application_hash(self.genesis, self.height, self.state)
        previous = self.previous or {"hash": "11" * 32, "parts": {"total": 1, "hash": "22" * 32}}
        signed = make_commit(make_header(self.trust, self.height + 1, app_hash, previous=previous), self.trust, self.keys)
        self.previous = signed["commit"]["block_id"]
        return {"format": STATE_OBSERVATION_FORMAT, "state_witness": {
            "genesis": self.genesis.value, "height": self.height, "app_hash": app_hash, "state": copy.deepcopy(self.state)},
                "signed_header": signed}

    def accept(self, name, height, *, observation_name=None):
        self.state, results = execute_block(self.genesis, self.state, [self.transactions[name]], height, self.worker)
        assert results[0]["code"] == 0, results
        self.height = height
        self.observations[observation_name or name] = self.observation()

    def processes(self):
        rows = []
        for node in range(4):
            for role, digest_value in (("engine", self.value["inputs"]["engine"]["sha256"]),
                                       ("application", "a" * 64), ("verifier-worker", self.value["inputs"]["worker"]["sha256"])):
                rows.append({"role": role, "node": node, "pid": 100 + len(rows), "start_ticks": 1000 + len(rows),
                             "executable_sha256": digest_value, "exit_code": None if role == "verifier-worker" else 0, "terminated": True})
        for role in ("development-client-genesis", "development-client-owner-key", "development-client-note-nullifier",
                     "development-client-recipient-spend", "development-prover", "wallet", "wallet-approval-before-commit",
                     "wallet-approval-lost-return", "wallet-delivery-after-claim", "wallet-delivery-after-sync"):
            digest_value = "3" * 64 if role.startswith("development-client") else "4" * 64 if role == "development-prover" else "a" * 64
            code = {"wallet-approval-before-commit": 72, "wallet-approval-lost-return": 73,
                    "wallet-delivery-after-claim": 74, "wallet-delivery-after-sync": 75}.get(role, 0)
            rows.append({"role": role, "node": None, "pid": 100 + len(rows), "start_ticks": 1000 + len(rows),
                         "executable_sha256": digest_value, "exit_code": code, "terminated": True,
                         "stdout_sha256": digest(b""), "stderr_sha256": digest(b"")})
        rows = [row for row in rows if row["role"] != "development-prover"]
        for index, wire in enumerate(self.transactions.values(), 1):
            rows.append({"role": "development-prover", "node": None, "pid": 300 + index, "start_ticks": 3000 + index,
                         "executable_sha256": "4" * 64, "exit_code": 0, "terminated": True,
                         "stdout_sha256": digest(wire), "stderr_sha256": digest(b"")})
        rows.append({"role": "wallet-refusal", "node": None, "pid": 500, "start_ticks": 5000,
                     "executable_sha256": "a" * 64, "exit_code": 2, "terminated": True,
                     "stdout_sha256": digest(b""), "stderr_sha256": digest(b"sanitized refusal")})
        self.value["processes"] = rows

    def manifests(self):
        wallets = []
        deliveries = []
        for label, owner in (("a", field(21)), ("b", field(22))):
            wallet_id = digest(b"1soft/protocol5-wallet-id/v1\0" + self.genesis.sha256 + bytes.fromhex(owner))
            status = {"format": "1soft/protocol5-wallet/v1", "wallet_id": wallet_id, "owner_key": owner,
                      "revision": field(31 if label == "a" else 32), "revision_counter": 8, "state_height": 7,
                      "notes": [], "values": {"spendable": 0, "reserved": 0, "spent": 0, "expired": 0, "unconfirmed": 0},
                      "decisions": [], "latest_state_guaranteed": False, "automatic_note_discovery": False,
                      "production_custody": False, "real_funds": False}
            note_id = field(81 if label == "a" else 82)
            note_value = 100 if label == "a" else 20
            position = 0 if label == "a" else 1
            status["notes"] = [{"capsule_id": note_id, "commitment": self.state["commitments"][position],
                                "value": note_value, "expiry": 32, "chain_position": position, "state": "spent"}]
            status["values"]["spent"] = note_value
            selections = (("payment", "executed_exact"), ("equivalent-original", "executed_equivalent"),
                          ("conflict-original", "conflicting_spend")) if label == "a" else (("recipient", "executed_exact"), ("expiry", "expired_unexecuted"))
            status["decisions"] = [{"decision_id": digest((label + name).encode()),
                                    "txid": transaction_id(self.transactions[name]).hex(),
                                    "input_capsule_id": note_id, "state": state} for name, state in selections]
            wallets.append({"name": "wallet-" + label, "sha256": field(41 if label == "a" else 42), "bytes": 32768,
                            "schema_sha256": digest(canonical_json(WALLET_SCHEMA)), "status": status})
            delivery_status = {"format": "1soft/protocol5-delivery/v1", "journal_id": field(51 if label == "a" else 52),
                               "wallet_id": wallet_id, "revision": field(61 if label == "a" else 62),
                               "endpoint": "http://127.0.0.1:26657/", "attempts": 1, "observations": 1}
            delivery_status["journal_id"] = digest(
                b"1soft/protocol5-delivery-id/v1\0" + bytes.fromhex(wallet_id) + self.genesis.sha256
                + hashlib.sha256(canonical_json(self.engine)).digest() + delivery_status["endpoint"].encode())
            deliveries.append({"name": "delivery-" + label, "sha256": field(71 if label == "a" else 72), "bytes": 32768,
                               "schema_sha256": digest(canonical_json(DELIVERY_SCHEMA)), "status": delivery_status})
        self.value["wallet_manifests"] = wallets
        self.value["delivery_manifests"] = deliveries

    def checks(self):
        txid = lambda name: transaction_id(self.transactions[name]).hex()
        nullifier = lambda name: self.transactions[name][370:402].hex()
        unchanged = {"refused": True, "state_unchanged": True}
        evidence = [
            {"validator_count": 4, "equal_power": True, "genesis_commitments": 1,
             "wallet_ids": [row["status"]["wallet_id"] for row in self.value["wallet_manifests"]],
             "recipient_initial_state": "unavailable", "validator_app_hashes": [self.observations["expiry"]["state_witness"]["app_hash"]] * 4},
            {"owner_keys_distinct": True, "sender_received_only_recipient_owner_key": True,
             "recipient_secret_in_sender": False, "owner_key_opcode": 3, "recipient_opcode": 4},
            {"txid": txid("payment"), "payment_value": 20, "fee": 5, "change_value": 75,
             "executed_exact": True, "actual_proof": True, "validator_count": 4},
            {"before_commit_empty": True, "crash_exit_code": 73, "after_commit_recovered": True,
             "transaction_sha256": digest(self.transactions["payment"]), "txid": txid("payment"), "nullifier": nullifier("payment"),
             "output_capsules_equal": True, "prover_invocations_before": 1, "prover_invocations_after": 1, "controller_unavailable": True},
            {"attempt_claimed_before_io": True, "network_calls": 1, "retry_refused": True, "endpoint_admission_is_execution": False,
             "subcases": {name: {"attempts": 1, "sends": 0 if name == "lost-after-claim" else 1, "retry_refused": True} for name in SETTINGS["attempt_subcases"]}},
            {"payment_state_height": 1, "payment_header_height": 2, "recipient_state_height": 2, "recipient_header_height": 3,
             "certificate_mutations": {name: dict(unchanged) for name in SETTINGS["certificate_mutations"]}},
            {"mutations": {name: dict(unchanged) for name in SETTINGS["capsule_mutations"]}},
            {"txid": txid("recipient"), "payment_value": 7, "fee": 5, "change_value": 8, "actual_proof": True,
             "recipient_import_position": 1, "return_imported_by_sender": True},
            {"original_txid": txid("conflict-original"), "winner_txid": txid("conflict-winner"), "nullifier": nullifier("conflict-original"),
             "winner_authenticated": True, "original_state": "conflicting_spend", "payment_export_refused": True,
             "equivalent_original_txid": txid("equivalent-original"), "equivalent_winner_txid": txid("equivalent-winner"), "equivalent_state": "executed_equivalent"},
            {"txid": txid("expiry"), "valid_until": 8, "hold_before_expiry": True, "no_receipt_before_expiry": True,
             "authenticated_height": 7, "decision_state": "expired_unexecuted", "winner_precedence": True},
            {"boundaries": {name: {"rows_equal": True, "implicit_network_calls": 0} for name in SETTINGS["restart_boundaries"]}},
            {"validator_count": 4, "controller_nodes_null": True, "controller_paths_in_validator_commands": 0,
             "controller_paths_in_validator_homes": 0, "validator_prover_processes": 0, "validator_client_processes": 0},
            {"artifact": "leakage-scan.json", "matches": 0, "private_journals_excluded": True},
        ]
        self.value["checks"] = [{"id": name, "passed": True, "evidence": value} for name, value in zip(SETTINGS["required_checks"], evidence)]

    def sync_artifacts(self):
        for key in ("wallet_manifests", "delivery_manifests", "checks", "processes"):
            self.raw[key.replace("_", "-") + ".json"] = canonical_json(self.value[key])
        self.raw["source-receipt.json"] = canonical_json({key: self.value[key] for key in
            ("source_commit", "source_tree", "source_dirty_before", "source_dirty_after", "source_files", "settings_sha256")})
        self.value["artifacts"] = [{"name": name, "sha256": digest(raw), "bytes": len(raw)} for name, raw in sorted(self.raw.items())]
        for name, raw in self.raw.items():
            (self.artifacts / name).write_bytes(raw)
        (self.artifacts / "manifest.json").write_bytes(canonical_json(self.value["artifacts"]))


class Protocol5WalletGateTests(unittest.TestCase):
    def setUp(self):
        self.assertTrue(CHECKER.is_file(), "Task 8 strict wallet checker is not implemented")
        self.gate = importlib.import_module("check_protocol5_wallet")

    def fixture(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        return Fixture(Path(temporary.name))

    def validate(self, fixture, value=None):
        return self.gate.validate_report(fixture.value if value is None else value,
                                        artifact_directory=fixture.artifacts, source_root=fixture.source)

    def test_truthful_missing_exact_pins_stays_unassessed(self):
        result = self.gate.validate_report(unassessed())
        self.assertFalse(result["qualified"])
        self.assertEqual(result["status"], "unassessed")

    def test_complete_authored_fixture_exercises_checker_only(self):
        fixture = self.fixture()
        result = self.validate(fixture)
        self.assertTrue(result["qualified"])
        self.assertEqual(result["check_ids"], SETTINGS["required_checks"])

    def test_every_top_level_omission_unknown_and_overclaim_fails(self):
        fixture = self.fixture()
        for key in fixture.value:
            changed = copy.deepcopy(fixture.value)
            del changed[key]
            with self.subTest(missing=key), self.assertRaises(ValueError):
                self.validate(fixture, changed)
        for key in SETTINGS["claims_false"]:
            changed = copy.deepcopy(fixture.value)
            changed["claims"][key] = True
            with self.subTest(claim=key), self.assertRaises(ValueError):
                self.validate(fixture, changed)
        for extra in ({"notes_secret": "private"}, {"independent_review": True}, {"extra": None}):
            with self.subTest(extra=next(iter(extra))), self.assertRaises(ValueError):
                self.validate(fixture, {**fixture.value, **extra})

    def test_exact_check_roster_rejects_every_omission_duplicate_skip_and_evidence_mutation(self):
        fixture = self.fixture()
        for index, row in enumerate(fixture.value["checks"]):
            for mutation in ("omit", "duplicate", "failed", "skipped", "unassessed", "empty", "unknown"):
                changed = copy.deepcopy(fixture.value)
                if mutation == "omit":
                    changed["checks"].pop(index)
                elif mutation == "duplicate":
                    changed["checks"].append(copy.deepcopy(row))
                elif mutation == "failed":
                    changed["checks"][index]["passed"] = False
                elif mutation in ("skipped", "unassessed"):
                    changed["checks"][index][mutation] = True
                elif mutation == "empty":
                    changed["checks"][index]["evidence"] = {}
                else:
                    changed["checks"][index]["evidence"]["extra"] = 0
                fixture.raw["checks.json"] = canonical_json(changed["checks"])
                self.rebind(changed, fixture, "checks.json")
                with self.subTest(check=row["id"], mutation=mutation), self.assertRaises(ValueError):
                    self.validate(fixture, changed)
        fixture.sync_artifacts()

    def rebind(self, value, fixture, name):
        raw = fixture.raw[name]
        (fixture.artifacts / name).write_bytes(raw)
        for receipt in value["artifacts"]:
            if receipt["name"] == name:
                receipt.update(sha256=digest(raw), bytes=len(raw))
        (fixture.artifacts / "manifest.json").write_bytes(canonical_json(value["artifacts"]))

    def test_source_commit_tree_cleanliness_settings_and_file_roster_are_bound(self):
        fixture = self.fixture()
        for key, replacement in (("source_commit", "f" * 40), ("source_tree", "e" * 40),
                                 ("source_dirty_before", True), ("source_dirty_after", True),
                                 ("settings_sha256", "0" * 64), ("source_files", {})):
            changed = copy.deepcopy(fixture.value)
            changed[key] = replacement
            fixture.raw["source-receipt.json"] = canonical_json({name: changed[name] for name in
                ("source_commit", "source_tree", "source_dirty_before", "source_dirty_after", "source_files", "settings_sha256")})
            self.rebind(changed, fixture, "source-receipt.json")
            with self.subTest(key=key), self.assertRaises(ValueError):
                self.validate(fixture, changed)
        fixture.sync_artifacts()
        changed = copy.deepcopy(fixture.value)
        changed["source_files"][SETTINGS["source_files"][0]] = "a" * 64
        with self.assertRaises(ValueError):
            self.validate(fixture, changed)

    def test_input_pins_and_identity_graph_reject_each_mutation(self):
        fixture = self.fixture()
        for role in INPUT_NAMES:
            changed = copy.deepcopy(fixture.value)
            changed["inputs"][role]["sha256"] = "0" * 64
            with self.subTest(role=role), self.assertRaises(ValueError):
                self.validate(fixture, changed)
        for role in ("client", "prover"):
            changed = copy.deepcopy(fixture.value)
            changed["expected_sha256"][role] = None
            with self.subTest(pin=role), self.assertRaises(ValueError):
                self.validate(fixture, changed)
        for name in ("genesis_sha256", "profile_id", "deployment_id"):
            changed = copy.deepcopy(fixture.value)
            changed[name] = "0" * 64
            with self.subTest(identity=name), self.assertRaises(ValueError):
                self.validate(fixture, changed)

    def test_process_receipts_require_exact_roles_nodes_identities_and_termination(self):
        fixture = self.fixture()
        for index, row in enumerate(fixture.value["processes"]):
            for mutation in ("omit", "duplicate", "wrong-node", "wrong-binary", "running", "unknown"):
                changed = copy.deepcopy(fixture.value)
                if mutation == "omit":
                    changed["processes"].pop(index)
                elif mutation == "duplicate":
                    changed["processes"].append(copy.deepcopy(row))
                elif mutation == "wrong-node":
                    changed["processes"][index]["node"] = 9
                elif mutation == "wrong-binary":
                    changed["processes"][index]["executable_sha256"] = "0" * 64
                elif mutation == "running":
                    changed["processes"][index]["terminated"] = False
                else:
                    changed["processes"][index]["argv"] = ["/private/controller"]
                fixture.raw["processes.json"] = canonical_json(changed["processes"])
                self.rebind(changed, fixture, "processes.json")
                with self.subTest(role=row["role"], mutation=mutation), self.assertRaises(ValueError):
                    self.validate(fixture, changed)
        fixture.sync_artifacts()

    def test_missing_extra_mutated_or_rehashed_private_artifacts_fail(self):
        fixture = self.fixture()
        for name in SETTINGS["artifact_names"]:
            path = fixture.artifacts / name
            original = path.read_bytes()
            path.write_bytes(original + b"x")
            with self.subTest(name=name), self.assertRaises(ValueError):
                self.validate(fixture)
            path.write_bytes(original)
        extra = fixture.artifacts / "wallet.sqlite"
        extra.write_bytes(b"private journal")
        with self.assertRaises(ValueError):
            self.validate(fixture)
        extra.unlink()
        changed = copy.deepcopy(fixture.value)
        leakage = json.loads(fixture.raw["leakage-scan.json"])
        leakage["private_key"] = "unredacted"
        fixture.raw["leakage-scan.json"] = canonical_json(leakage)
        self.rebind(changed, fixture, "leakage-scan.json")
        with self.assertRaises(ValueError):
            self.validate(fixture, changed)

    def test_engine_validator_public_key_base64_may_begin_with_slash(self):
        encoded = base64.b64encode(bytes([252]) + bytes(31)).decode()
        self.assertTrue(encoded.startswith("/"))
        value = {"validators": [{"pub_key": {"value": encoded}}]}
        self.assertEqual(self.gate.decode_report(canonical_json(value)), value)
        for rejected in ({"value": encoded},
                         {"validators": [{"pub_key": {"value": "/home/operator/private"}}]}):
            with self.subTest(rejected=rejected), self.assertRaises(ValueError):
                self.gate.decode_report(canonical_json(rejected))

    def test_private_paths_private_fields_and_noncanonical_json_are_rejected(self):
        fixture = self.fixture()
        for path in ("/home/operator/private/client", r"C:\Users\Operator\client", "../client", "file:///tmp/client", "https://host/client"):
            changed = copy.deepcopy(fixture.value)
            changed["inputs"]["client"]["name"] = path
            with self.subTest(path=path), self.assertRaises(ValueError):
                self.validate(fixture, changed)
        for raw in (b'{"schema":"x","schema":"y"}', b'{"a":1.0}', b'{"a":NaN}', b'{} {}'):
            with self.subTest(raw=raw), self.assertRaises(ValueError):
                self.gate.decode_report(raw)

    def test_authenticated_receipt_mutation_fails_even_after_rehash(self):
        fixture = self.fixture()
        for observation_name in ("payment", "recipient", "equivalent", "conflict", "expiry"):
            changed = copy.deepcopy(fixture.value)
            name = observation_name + "-observation.json"
            original = fixture.raw[name]
            value = json.loads(original)
            value["state_witness"]["app_hash"] = "00" * 32
            fixture.raw[name] = canonical_json(value)
            self.rebind(changed, fixture, name)
            with self.subTest(observation=observation_name), self.assertRaises(ValueError):
                self.validate(fixture, changed)
            fixture.raw[name] = original
            fixture.sync_artifacts()

    def test_unassessed_cannot_hide_missing_pins_or_claim_execution(self):
        for mutation in ("missing", "execution", "proof", "check", "claim", "duplicate", "private"):
            value = unassessed()
            if mutation == "missing":
                value["missing_inputs"] = []
            elif mutation == "execution":
                value["processes_started"] = True
            elif mutation == "proof":
                value["actual_proof_accepted"] = True
            elif mutation == "check":
                value["checks"] = [{"id": SETTINGS["required_checks"][0], "passed": True, "evidence": {}}]
            elif mutation == "claim":
                value["claims"]["production_ready"] = True
            elif mutation == "duplicate":
                value["missing_inputs"].append("client")
            else:
                value["failures"] = ["/home/operator/private"]
            with self.subTest(mutation=mutation), self.assertRaises(ValueError):
                self.gate.validate_report(value)


    def test_nested_check_evidence_leaf_mutations_fail_with_rebound_artifacts(self):
        fixture = self.fixture()
        def leaves(value, path=()):
            if isinstance(value, dict):
                for key, child in value.items():
                    yield from leaves(child, path + (key,))
            elif isinstance(value, list):
                for index, child in enumerate(value):
                    yield from leaves(child, path + (index,))
            else:
                yield path, value
        for index, row in enumerate(fixture.value["checks"]):
            for path, old in leaves(row["evidence"]):
                changed = copy.deepcopy(fixture.value)
                target = changed["checks"][index]["evidence"]
                for key in path[:-1]:
                    target = target[key]
                target[path[-1]] = not old if type(old) is bool else old + 1 if type(old) is int else "changed"
                fixture.raw["checks.json"] = canonical_json(changed["checks"])
                self.rebind(changed, fixture, "checks.json")
                with self.subTest(check=row["id"], path=path), self.assertRaises(ValueError):
                    self.validate(fixture, changed)
        fixture.sync_artifacts()

    def test_prover_output_provenance_and_single_payment_proof_are_required(self):
        fixture = self.fixture()
        original = copy.deepcopy(fixture.value)
        payment_hash = digest(fixture.transactions["payment"])
        for mutation in ("unbound", "reproved"):
            changed = copy.deepcopy(original)
            payment = next(row for row in changed["processes"] if row["role"] == "development-prover" and row["stdout_sha256"] == payment_hash)
            if mutation == "unbound":
                payment["stdout_sha256"] = "00" * 32
            else:
                payment = dict(payment, pid=9999, start_ticks=9999)
                changed["processes"].append(payment)
            fixture.raw["processes.json"] = canonical_json(changed["processes"])
            self.rebind(changed, fixture, "processes.json")
            with self.subTest(mutation=mutation), self.assertRaises(ValueError):
                self.validate(fixture, changed)

    def test_journal_public_manifests_reject_identity_schema_and_authority_drift(self):
        fixture = self.fixture()
        for collection in ("wallet_manifests", "delivery_manifests"):
            for mutation in ("duplicate", "schema", "identity", "extra"):
                changed = copy.deepcopy(fixture.value)
                if mutation == "duplicate":
                    changed[collection][1] = copy.deepcopy(changed[collection][0])
                elif mutation == "schema":
                    changed[collection][0]["schema_sha256"] = "00" * 32
                elif mutation == "identity":
                    changed[collection][0]["status"]["wallet_id"] = "00" * 32
                else:
                    changed[collection][0]["private_path"] = "/tmp/private-wallet"
                name = collection.replace("_", "-") + ".json"
                fixture.raw[name] = canonical_json(changed[collection])
                self.rebind(changed, fixture, name)
                with self.subTest(collection=collection, mutation=mutation), self.assertRaises(ValueError):
                    self.validate(fixture, changed)
                fixture.sync_artifacts()

    def test_artifact_symlink_hardlink_missing_and_duplicate_receipts_fail(self):
        fixture = self.fixture()
        path = fixture.artifacts / "payment-transaction.bin"
        original = path.read_bytes()
        outside = fixture.root / "outside.bin"
        outside.write_bytes(original)
        for kind in ("symlink", "hardlink", "missing"):
            path.unlink()
            if kind == "symlink":
                path.symlink_to(outside)
            elif kind == "hardlink":
                os.link(outside, path)
            with self.subTest(kind=kind), self.assertRaises(ValueError):
                self.validate(fixture)
            if path.exists() or path.is_symlink():
                path.unlink()
            path.write_bytes(original)
        changed = copy.deepcopy(fixture.value)
        changed["artifacts"][1] = copy.deepcopy(changed["artifacts"][0])
        with self.assertRaises(ValueError):
            self.validate(fixture, changed)

    def test_live_source_dirty_state_cannot_be_hidden_by_clean_declarations(self):
        fixture = self.fixture()
        source = fixture.source / "src/protocol5_wallet.py"
        source.write_bytes(source.read_bytes() + b"# drift")
        with self.assertRaises(ValueError):
            self.validate(fixture)

    def test_settings_contract_is_fixed_and_duplicate_settings_fail(self):
        self.assertEqual(self.gate.validate_settings(SETTINGS_PATH.read_bytes()), SETTINGS)
        changed = copy.deepcopy(SETTINGS)
        changed["required_checks"].pop()
        with self.assertRaises(ValueError):
            self.gate.validate_settings(canonical_json(changed) + bytes([10]))
        with self.assertRaises(ValueError):
            self.gate.validate_settings(b'{"version":1,"version":1}')

    def test_actual_checker_process_sanitizes_malformed_reports_and_keeps_unassessed_unqualified(self):
        with tempfile.TemporaryDirectory() as temporary:
            report = Path(temporary) / "report.json"
            report.write_bytes(canonical_json(unassessed()))
            process = subprocess.run([sys.executable, "-B", str(CHECKER), str(report)], capture_output=True, timeout=10)
            self.assertEqual(process.returncode, 2)
            self.assertEqual(process.stderr, b"")
            result = json.loads(process.stdout)
            self.assertEqual(result["status"], "unassessed")
            self.assertFalse(result["qualified"])
            private = b"private-secret-cannot-be-reflected"
            report.write_bytes(b'{"schema":"' + private + b'","schema":"duplicate"}')
            process = subprocess.run([sys.executable, "-B", str(CHECKER), str(report)], capture_output=True, timeout=10)
            self.assertEqual(process.returncode, 2)
            self.assertEqual(process.stderr, b"")
            self.assertEqual(json.loads(process.stdout), {"status": "refused", "qualified": False})
            self.assertNotIn(private, process.stdout + process.stderr)


    def test_wallet_refusals_require_their_own_role_and_exact_exit_code(self):
        fixture = self.fixture()
        try:
            result = self.validate(fixture)
        except ValueError as error:
            self.fail("measured wallet-refusal exit 2 must be accepted: " + str(error))
        self.assertTrue(result["qualified"])
        for mutation in ("refusal-zero", "refusal-one", "refusal-as-wallet", "wallet-two", "missing-refusal"):
            changed = copy.deepcopy(fixture.value)
            refusal = next(row for row in changed["processes"] if row["role"] == "wallet-refusal")
            if mutation == "refusal-zero":
                refusal["exit_code"] = 0
            elif mutation == "refusal-one":
                refusal["exit_code"] = 1
            elif mutation == "refusal-as-wallet":
                refusal["role"] = "wallet"
            elif mutation == "wallet-two":
                next(row for row in changed["processes"] if row["role"] == "wallet")["exit_code"] = 2
            else:
                changed["processes"].remove(refusal)
            fixture.raw["processes.json"] = canonical_json(changed["processes"])
            self.rebind(changed, fixture, "processes.json")
            with self.subTest(mutation=mutation), self.assertRaises(ValueError):
                self.validate(fixture, changed)


if __name__ == "__main__":
    unittest.main()
