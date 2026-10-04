#!/usr/bin/env python3
"""Strict, source-bound checker for finite Protocol 5 wallet qualification.

This checks a retained local execution receipt, not independent cryptographic
review. Private journals and note capsules must never be supplied as artifacts.
"""
from __future__ import annotations

import argparse
import base64
from functools import lru_cache
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "src"))
from protocol5_encoding import Transaction, canonical_json, field_bytes, genesis_document, transaction_id
from protocol5_state import STATE_KEYS
from protocol5_state_reader import authenticate_observation, extends_observation
from protocol5_wallet import _SCHEMA as WALLET_SCHEMA
from protocol5_delivery import _SCHEMA as DELIVERY_SCHEMA

SETTINGS_PATH = ROOT / "reference/protocol5-wallet-qualification-settings-v1.json"
SETTINGS_CONTRACT_SHA256 = '8a0d91f04beedef7605048d4ca65b69afce3602a20a21233af9a40e16f367445'

def validate_settings(raw):
    if type(raw) is not bytes or hashlib.sha256(raw).hexdigest() != SETTINGS_CONTRACT_SHA256:
        raise ValueError("Protocol 5 wallet qualification: frozen settings changed")
    return json.loads(raw)

SETTINGS_RAW = SETTINGS_PATH.read_bytes()
SETTINGS = validate_settings(SETTINGS_RAW)
SETTINGS_SHA256 = hashlib.sha256(SETTINGS_RAW).hexdigest()
SCHEMA = "1soft-protocol5-wallet-preflight-v1"
COMPLETE = "completed-awaiting-external-validation"
INPUT_NAMES = frozenset({"engine", "worker", "client", "prover", "profile", "kat", "toolchain", "policy", "genesis"})
REQUIRED_CHECKS = tuple(SETTINGS["required_checks"])
ENGINE_SHA256 = SETTINGS["engine_sha256"]
SOURCE_KEYS = {"source_commit", "source_tree", "source_dirty_before", "source_dirty_after", "source_files", "settings_sha256"}
REPORT_KEYS = SOURCE_KEYS | {"schema", "status", "engine_version", "inputs", "expected_sha256", "genesis_sha256",
    "profile_id", "deployment_id", "missing_inputs", "failures", "checks", "processes_started", "actual_proof_accepted",
    "processes", "wallet_manifests", "delivery_manifests", "artifacts", "claims"}
INPUT_ARTIFACTS = {"profile": "profile-descriptor-v1.bin", "kat": "kat-v1.bin", "toolchain": "toolchain-manifest-v1.json",
                   "policy": "sandbox-policy-v1.json", "genesis": "genesis-template.json"}
TX_NAMES = ("payment", "recipient", "equivalent-original", "equivalent-winner", "conflict-original", "conflict-winner", "expiry")
OBS_NAMES = ("payment", "recipient", "equivalent", "conflict", "expiry")
FAULT_EXITS = {"wallet-approval-before-commit": 72, "wallet-approval-lost-return": 73,
               "wallet-delivery-after-claim": 74, "wallet-delivery-after-sync": 75}
CLIENT_ROLES = {"development-client-genesis", "development-client-owner-key", "development-client-note-nullifier", "development-client-recipient-spend"}
CONTROLLER_ROLES = CLIENT_ROLES | {"development-prover", "wallet", "wallet-refusal"} | set(FAULT_EXITS)
FORBIDDEN_KEYS = {"spend_secret", "owner_spend_secret", "note_secret", "blinding", "input_blinding", "output_blinding",
                  "private_key", "secret_bytes", "capsule_base64", "witness", "witness_bytes", "prover_request", "prover_request_bytes",
                  "transaction_bytes", "unredacted", "argv", "environ", "private_path", "wallet_path", "delivery_path"}
NAME = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,127}\Z")


def _need(condition, reason):
    if not condition:
        raise ValueError("Protocol 5 wallet qualification: " + reason)


def _closed(value, keys, reason):
    _need(type(value) is dict and set(value) == set(keys), reason)
    return value


def _same(value, expected, reason):
    _need(canonical_json(value) == canonical_json(expected), reason)


def _hash(value, size=64):
    _need(type(value) is str and len(value) == size and all(c in "0123456789abcdef" for c in value), "invalid identity")
    return value


def _integer(value, low=0, high=2**63 - 1):
    _need(type(value) is int and low <= value <= high, "integer outside contract")
    return value


def _scan(value):
    if type(value) is dict:
        for key, item in value.items():
            _need(type(key) is str, "non-string key")
            # Capsule mutation *names* are permitted only as a closed case map;
            # none of its values may contain private material.
            if key in FORBIDDEN_KEYS:
                _need(type(item) is dict and set(item) == {"refused", "state_unchanged"}
                      and item["refused"] is True and item["state_unchanged"] is True,
                      "private material field")
            _scan(item)
    elif type(value) is list:
        for item in value:
            _scan(item)
    elif type(value) is str:
        slash = chr(92)
        _need(not (value.startswith(("/", "~/", "file:", slash + slash))
                   or (len(value) >= 3 and value[0].isalpha() and value[1] == ":" and value[2] in ("/", slash))
                   or "/home/" in value or "/tmp/" in value or slash + "Users" + slash in value),
              "absolute private path")
        _need(not any(0xD800 <= ord(c) <= 0xDFFF for c in value), "non-scalar string")
    else:
        _need(value is None or type(value) in (int, bool), "non-integer JSON scalar")


def decode_report(raw):
    _need(type(raw) is bytes and 0 < len(raw) <= SETTINGS["limits"]["report_bytes"], "report size differs")
    def pairs(items):
        result = {}
        for key, value in items:
            _need(key not in result, "duplicate JSON key")
            result[key] = value
        return result
    def noninteger(_):
        raise ValueError("Protocol 5 wallet qualification: non-integer JSON")
    try:
        value = json.loads(raw.decode("utf-8"), object_pairs_hook=pairs, parse_float=noninteger, parse_constant=noninteger)
    except (UnicodeError, json.JSONDecodeError, RecursionError) as error:
        raise ValueError("Protocol 5 wallet qualification: malformed JSON") from error
    _scan(value)
    return value


def _read(path, maximum):
    selected = Path(os.path.abspath(path))
    _need(not any(parent.is_symlink() for parent in (selected.parent, *selected.parent.parents)), "symlink artifact parent")
    try:
        metadata = selected.lstat()
        _need(stat.S_ISREG(metadata.st_mode) and metadata.st_nlink == 1 and metadata.st_size <= maximum,
              "unsafe or excessive artifact")
        descriptor = os.open(selected, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
        try:
            opened = os.fstat(descriptor)
            _need((opened.st_dev, opened.st_ino) == (metadata.st_dev, metadata.st_ino), "artifact changed during open")
            with os.fdopen(descriptor, "rb", closefd=False) as source:
                raw = source.read(maximum + 1)
            _need(len(raw) <= maximum, "artifact bound exceeded")
            return raw
        finally:
            os.close(descriptor)
    except OSError as error:
        raise ValueError("Protocol 5 wallet qualification: artifact unavailable") from error


@lru_cache(maxsize=4096)
def _git_object(root, commit, name):
    result = subprocess.run(["git", "show", commit + ":" + name], cwd=root, capture_output=True, timeout=15)
    _need(result.returncode == 0 and len(result.stdout) <= SETTINGS["limits"]["artifact_bytes"], "source object unavailable")
    return hashlib.sha256(result.stdout).hexdigest()


def _source(value, source_root):
    _hash(value["source_commit"], 40)
    _hash(value["source_tree"], 40)
    _need(value["source_dirty_before"] is False and value["source_dirty_after"] is False, "dirty source declaration")
    _closed(value["source_files"], SETTINGS["source_files"], "source file roster differs")
    _need(value["settings_sha256"] == SETTINGS_SHA256, "settings identity differs")
    root = str(Path(source_root).resolve())
    try:
        tree = subprocess.run(["git", "rev-parse", value["source_commit"] + "^{tree}"], cwd=root, capture_output=True, timeout=15)
        status = subprocess.run(["git", "status", "--porcelain", "--untracked-files=normal"], cwd=root, capture_output=True, timeout=15)
        _need(tree.returncode == 0 and tree.stdout.decode().strip() == value["source_tree"], "source commit/tree differs")
        _need(status.returncode == 0 and status.stdout == b"", "selected source checkout is dirty")
        for name, digest in value["source_files"].items():
            _hash(digest)
            _need(_git_object(root, value["source_commit"], name) == digest, "committed source file differs")
            _need(hashlib.sha256(_read(Path(root) / name, SETTINGS["limits"]["artifact_bytes"])).hexdigest() == digest,
                  "executed source differs from recorded commit")
        _need(value["source_files"]["reference/protocol5-wallet-qualification-settings-v1.json"] == SETTINGS_SHA256,
              "committed settings differs")
    except (OSError, subprocess.SubprocessError, UnicodeError) as error:
        raise ValueError("Protocol 5 wallet qualification: source binding unavailable") from error


def _artifacts(value, directory):
    _need(directory is not None, "sibling artifacts required")
    root = Path(directory)
    try:
        metadata = root.lstat()
        _need(stat.S_ISDIR(metadata.st_mode) and not stat.S_ISLNK(metadata.st_mode), "unsafe artifact directory")
        rows = value["artifacts"]
        _need(type(rows) is list and len(rows) == len(SETTINGS["artifact_names"]), "artifact roster differs")
        names = []
        raw = {}
        total = 0
        for row in rows:
            _closed(row, {"name", "sha256", "bytes"}, "artifact receipt keys differ")
            name = row["name"]
            _need(type(name) is str and name in SETTINGS["artifact_names"] and name not in names, "unknown or duplicate artifact")
            names.append(name)
            _hash(row["sha256"])
            _integer(row["bytes"], 1, SETTINGS["limits"]["artifact_bytes"])
            total += row["bytes"]
            _need(total <= SETTINGS["limits"]["total_artifact_bytes"], "aggregate artifacts exceed bound")
            data = _read(root / name, SETTINGS["limits"]["artifact_bytes"])
            _need(len(data) == row["bytes"] and hashlib.sha256(data).hexdigest() == row["sha256"], "artifact identity differs")
            _need(not any(magic in data for magic in (b"1SFTWIT1", b"1SFTPRV1", b"SQLite format 3")), "private wire or journal artifact")
            raw[name] = data
        _need(set(names) == set(SETTINGS["artifact_names"]), "artifact omission")
        _need({entry.name for entry in root.iterdir()} == set(names) | {"manifest.json"}, "extra artifact file")
        _same(decode_report(_read(root / "manifest.json", SETTINGS["limits"]["report_bytes"])), rows, "artifact manifest differs")
        for key in ("wallet_manifests", "delivery_manifests", "checks", "processes"):
            _same(decode_report(raw[key.replace("_", "-") + ".json"]), value[key], "public manifest differs")
        _same(decode_report(raw["source-receipt.json"]), {key: value[key] for key in SOURCE_KEYS}, "source receipt differs")
        return raw
    except OSError as error:
        raise ValueError("Protocol 5 wallet qualification: artifact directory unavailable") from error


def _processes(value):
    rows = value["processes"]
    _need(type(rows) is list and 0 < len(rows) <= SETTINGS["limits"]["processes"], "process bounds differ")
    identities = set()
    seen_roles = set()
    application_hashes = set()
    wallet_hashes = set()
    nodes = {name: set() for name in ("engine", "application", "verifier-worker")}
    for row in rows:
        _need(type(row) is dict and row.get("role") in set(nodes) | CONTROLLER_ROLES, "unknown process role")
        role = row["role"]
        keys = {"role", "node", "pid", "start_ticks", "executable_sha256", "exit_code", "terminated"}
        if role in CONTROLLER_ROLES:
            keys |= {"stdout_sha256", "stderr_sha256"}
        _closed(row, keys, "process receipt keys differ")
        identity = (_integer(row["pid"], 1), _integer(row["start_ticks"], 1))
        _need(identity not in identities, "duplicate process identity")
        identities.add(identity)
        seen_roles.add(role)
        digest = _hash(row["executable_sha256"])
        _need(row["terminated"] is True, "process still running or unassessed")
        if role in nodes:
            nodes[role].add(_integer(row["node"], 0, 3))
        else:
            _need(row["node"] is None, "controller assigned to validator")
            _hash(row["stdout_sha256"])
            _hash(row["stderr_sha256"])
        if role == "verifier-worker" and row["exit_code"] is None:
            pass  # Child of the application; disappearance is asserted, no invented exit status.
        else:
            _need(type(row["exit_code"]) is int, "unmeasured direct child exit")
        if role in FAULT_EXITS:
            _need(row["exit_code"] == FAULT_EXITS[role], "fault process exit differs")
        elif role == "wallet-refusal":
            _need(row["exit_code"] == 2, "wallet refusal exit differs")
        elif role in CONTROLLER_ROLES:
            _need(row["exit_code"] == 0, "controller command failed")
        else:
            _need(row["exit_code"] in (None, 0, -9, -15), "validator process failed")
        input_role = "engine" if role == "engine" else "worker" if role == "verifier-worker" else "client" if role in CLIENT_ROLES else "prover" if role == "development-prover" else None
        if input_role:
            _need(digest == value["inputs"][input_role]["sha256"], "process binary drift")
        elif role == "application":
            application_hashes.add(digest)
        else:
            wallet_hashes.add(digest)
    _need(all(actual == {0, 1, 2, 3} for actual in nodes.values()), "four-validator process roster incomplete")
    _need(CONTROLLER_ROLES <= seen_roles, "controller process roster incomplete")
    _need(len(application_hashes) == 1 and wallet_hashes == application_hashes, "Python process identity drift")


def _identity(value, raw):
    _need(value["engine_version"] == SETTINGS["engine_version"], "engine version differs")
    _closed(value["inputs"], INPUT_NAMES, "input roster differs")
    for role, receipt in value["inputs"].items():
        _closed(receipt, {"name", "sha256", "bytes"}, "input receipt differs")
        _need(type(receipt["name"]) is str and NAME.fullmatch(receipt["name"]) is not None, "input name is not a safe basename")
        _hash(receipt["sha256"])
        _integer(receipt["bytes"], 1, 256 * 1024 * 1024)
        if role in INPUT_ARTIFACTS:
            content = raw[INPUT_ARTIFACTS[role]]
            _need(receipt["sha256"] == hashlib.sha256(content).hexdigest() and receipt["bytes"] == len(content), "retained input differs")
    _need(value["inputs"]["engine"]["sha256"] == ENGINE_SHA256, "engine identity differs")
    for role in ("client", "prover"):
        _hash(value["expected_sha256"][role])
        _need(value["expected_sha256"][role] == value["inputs"][role]["sha256"], "controller pin differs")
    genesis = genesis_document(raw["application-genesis.json"])
    template = genesis_document(raw["genesis-template.json"])
    _need(template.value["initial_commitments"] == [] and len(genesis.value["initial_commitments"]) == 1, "fresh genesis commitment roster differs")
    # The runner replaces the template chain ID and validator keys before deriving
    # the real genesis field; economics, domains, limits, and deployment stay fixed.
    for key in set(genesis.value) - {"chain_id", "validators", "genesis_field", "initial_commitments"}:
        _same(genesis.value[key], template.value[key], "genesis template contract drift")
    _need(value["genesis_sha256"] == genesis.sha256.hex()
          and value["profile_id"] == genesis.profile.identity.hex() == SETTINGS["profile_id"]
          and value["deployment_id"] == genesis.deployment.identity.hex() == SETTINGS["deployment_id"], "profile/deployment/genesis identity differs")
    _need(raw["profile-descriptor-v1.bin"] == genesis.profile.raw, "descriptor bytes differ")
    _need(hashlib.sha256(b"1soft/shielded-kat/v1\0" + raw["kat-v1.bin"]).digest() == genesis.profile.hashes[6], "KAT identity differs")
    _need(genesis.deployment.worker_sha256.hex() == value["inputs"]["worker"]["sha256"]
          and genesis.deployment.toolchain_sha256.hex() == value["inputs"]["toolchain"]["sha256"]
          and genesis.deployment.sandbox_policy_sha256.hex() == value["inputs"]["policy"]["sha256"], "deployment inputs differ")
    engine = decode_report(raw["engine-genesis.json"])
    transactions = {name: Transaction.decode(raw[name + "-transaction.bin"], genesis) for name in TX_NAMES}
    observations, certificates = {}, {}
    previous = None
    for name in OBS_NAMES:
        observation, certificate = authenticate_observation(raw[name + "-observation.json"], engine, genesis.raw)
        _public_state(genesis, observation["state_witness"])
        if previous is not None:
            extends_observation(previous, observation)
        previous = observation
        observations[name], certificates[name] = observation, certificate
    return genesis, engine, transactions, observations, certificates


def _public_state(genesis, witness):
    """Check retained public effects; H+1 validators attest proof/root execution."""
    state = _closed(witness["state"], STATE_KEYS, "state schema differs")
    _need(type(state["version"]) is int and state["version"] == 1
          and state["profile_id"] == genesis.profile.identity.hex()
          and state["deployment_id"] == genesis.deployment.identity.hex(), "state identity differs")
    height = _integer(witness["height"], 1, genesis.value["limits"]["max_height"])
    for key in ("commitments", "spent_nullifiers", "root_history", "receipts", "execution_blocks"):
        _need(type(state[key]) is list, "state collection differs")
    commitments, spent, roots, receipts = (state[name] for name in ("commitments", "spent_nullifiers", "root_history", "receipts"))
    _need(commitments[:1] == genesis.value["initial_commitments"] and len(commitments) <= 16
          and len(set(commitments)) == len(commitments), "state commitments differ")
    for value in commitments + spent + [state["current_root"]]:
        _need(any(field_bytes(value)), "zero public field")
    _need(spent == sorted(set(spent)), "spent nullifier roster differs")
    count = _integer(state["accepted_transaction_count"], 1, genesis.value["limits"]["max_accepted_transactions"])
    _need(count == len(receipts) == len(spent) == len(roots) - 1
          and len(commitments) == 1 + 2 * count
          and type(state["fee_total"]) is int and state["fee_total"] == count * genesis.value["fee"], "public counters differ")
    _same(roots[0], {"kind": "genesis", "height": 0, "tx_index": 0, "root": roots[0].get("root")}, "genesis root history differs")
    _need(any(field_bytes(roots[0]["root"])) and roots[-1]["root"] == state["current_root"], "root history endpoint differs")
    blocks = state["execution_blocks"]
    _need(len(blocks) == height, "retained history height differs")
    successes, transaction_count, transaction_bytes = [], 0, 0
    for expected_height, block in enumerate(blocks, 1):
        _closed(block, {"height", "transactions", "results"}, "execution block schema differs")
        _need(type(block["height"]) is int and block["height"] == expected_height
              and type(block["transactions"]) is list and type(block["results"]) is list
              and len(block["transactions"]) == len(block["results"]), "execution block contents differ")
        for index, (encoded, result) in enumerate(zip(block["transactions"], block["results"])):
            _closed(result, {"code", "log", "data"}, "execution result schema differs")
            _integer(result["code"], 0, 2**32 - 1)
            _need(type(encoded) is str and type(result["log"]) is str and type(result["data"]) is str, "execution result types differ")
            try:
                wire = base64.b64decode(encoded, validate=True)
            except (ValueError, TypeError) as error:
                raise ValueError("Protocol 5 wallet qualification: retained wire invalid") from error
            _need(base64.b64encode(wire).decode() == encoded, "retained wire noncanonical")
            transaction_count += 1
            transaction_bytes += len(wire)
            if result["code"] == 0:
                _same(result, {"code": 0, "log": "", "data": transaction_id(wire).hex()}, "successful result differs")
                successes.append((wire, expected_height, index))
    _need(type(state["history_transaction_count"]) is int and state["history_transaction_count"] == transaction_count
          and transaction_count <= genesis.value["limits"]["max_history_transactions"]
          and type(state["history_transaction_bytes"]) is int and state["history_transaction_bytes"] == transaction_bytes
          and transaction_bytes <= genesis.value["limits"]["max_history_tx_bytes"], "retained history counters differ")
    _need(len(successes) == count, "successful receipt count differs")
    for number, (receipt, (wire, accepted_height, index)) in enumerate(zip(receipts, successes), 1):
        _closed(receipt, {"txid", "profile_id", "deployment_id", "height", "tx_index", "anchor_root", "tree_root_before",
                          "tree_root_after", "nullifier", "output_commitment_0", "output_commitment_1",
                          "output_position_0", "output_position_1", "fee"}, "receipt schema differs")
        transaction = Transaction.decode(wire, genesis)
        fields = transaction.public_fields
        first_position = 1 + 2 * (number - 1)
        expected = {"txid": transaction_id(wire).hex(), "profile_id": genesis.profile.identity.hex(),
                    "deployment_id": genesis.deployment.identity.hex(), "height": accepted_height, "tx_index": index,
                    "anchor_root": fields[8].hex(), "tree_root_before": roots[number - 1]["root"],
                    "tree_root_after": roots[number]["root"], "nullifier": fields[9].hex(),
                    "output_commitment_0": fields[10].hex(), "output_commitment_1": fields[11].hex(),
                    "output_position_0": first_position, "output_position_1": first_position + 1, "fee": genesis.value["fee"]}
        _same(receipt, expected, "receipt effects differ from transaction")
        _same(roots[number], {"kind": "transaction", "height": accepted_height, "tx_index": index,
                              "txid": expected["txid"], "root": receipt["tree_root_after"]}, "root receipt lineage differs")
        _need(commitments[first_position:first_position + 2] == [fields[10].hex(), fields[11].hex()]
              and fields[9].hex() in spent, "committed effects differ")
    _need({row["nullifier"] for row in receipts} == set(spent), "nullifier receipt roster differs")


def _receipt(observation, wire):
    txid = transaction_id(wire).hex()
    matches = [row for row in observation["state_witness"]["state"]["receipts"] if row["txid"] == txid]
    _need(len(matches) == 1, "required transaction lacks authenticated receipt")
    return matches[0]


def _manifests(value, genesis, engine, observations):
    all_decisions = {}
    owners = set()
    wallets = {}
    final_height = observations["expiry"]["state_witness"]["height"]
    for kind, names, schema in (("wallet", ("wallet-a", "wallet-b"), WALLET_SCHEMA),
                                ("delivery", ("delivery-a", "delivery-b"), DELIVERY_SCHEMA)):
        rows = value[kind + "_manifests"]
        _need(type(rows) is list and len(rows) == 2, "journal manifest count differs")
        _need([row.get("name") for row in rows if type(row) is dict] == list(names), "journal manifest roster differs")
        seen_hashes = set()
        for row in rows:
            _closed(row, {"name", "sha256", "bytes", "schema_sha256", "status"}, "journal manifest schema differs")
            digest = _hash(row["sha256"])
            _need(digest not in seen_hashes, "duplicate journal image")
            seen_hashes.add(digest)
            _integer(row["bytes"], 4096, 32 * 1024 * 1024)
            _need(row["bytes"] % 4096 == 0, "journal byte receipt differs")
            _need(row["schema_sha256"] == hashlib.sha256(canonical_json(schema)).hexdigest(), "journal SQL schema identity differs")
            status = row["status"]
            if kind == "wallet":
                _closed(status, {"format", "wallet_id", "owner_key", "revision", "revision_counter", "state_height", "notes", "values", "decisions",
                                  "latest_state_guaranteed", "automatic_note_discovery", "production_custody", "real_funds"}, "wallet public status schema differs")
                _need(status["format"] == "1soft/protocol5-wallet/v1", "wallet format differs")
                owner = field_bytes(status["owner_key"])
                _need(any(owner) and owner not in owners, "wallet owners are not distinct")
                owners.add(owner)
                wallet_id = hashlib.sha256(b"1soft/protocol5-wallet-id/v1\0" + genesis.sha256 + owner).hexdigest()
                _need(status["wallet_id"] == wallet_id, "wallet identity differs")
                wallets[row["name"][-1]] = status
                _hash(status["revision"])
                _integer(status["revision_counter"], 1)
                _need(type(status["state_height"]) is int and status["state_height"] == final_height, "wallet checkpoint differs from final authenticated state")
                for name in ("latest_state_guaranteed", "automatic_note_discovery", "production_custody", "real_funds"):
                    _need(status[name] is False, "wallet status overclaims")
                _closed(status["values"], {"spendable", "reserved", "spent", "expired", "unconfirmed"}, "wallet value buckets differ")
                sums = dict.fromkeys(status["values"], 0)
                _need(type(status["notes"]) is list and 0 < len(status["notes"]) <= 16, "wallet note roster differs")
                seen = set()
                for note in status["notes"]:
                    _closed(note, {"capsule_id", "commitment", "value", "expiry", "chain_position", "state"}, "public note schema differs")
                    capsule_id = _hash(note["capsule_id"])
                    _need(capsule_id not in seen and note["state"] in sums, "duplicate or invalid public note")
                    seen.add(capsule_id)
                    position = _integer(note["chain_position"], 0, 15)
                    commitments = observations["expiry"]["state_witness"]["state"]["commitments"]
                    _need(position < len(commitments) and commitments[position] == note["commitment"], "public note position differs")
                    _integer(note["expiry"], 1, 2**64 - 1)
                    sums[note["state"]] += _integer(note["value"], 1, 2**64 - 1)
                _same(status["values"], sums, "wallet value totals differ")
                _need(type(status["decisions"]) is list and 0 < len(status["decisions"]) <= 16, "wallet decision roster differs")
                seen_ids = set()
                for decision in status["decisions"]:
                    _closed(decision, {"decision_id", "txid", "input_capsule_id", "state"}, "public decision schema differs")
                    identity = _hash(decision["decision_id"])
                    txid = _hash(decision["txid"])
                    _hash(decision["input_capsule_id"])
                    _need(identity not in seen_ids and txid not in all_decisions, "duplicate wallet decision")
                    _need(decision["state"] in {"ready", "executed_exact", "executed_equivalent", "conflicting_spend", "expired_unexecuted"}, "decision state differs")
                    seen_ids.add(identity)
                    all_decisions[txid] = decision["state"]
            else:
                _closed(status, {"format", "journal_id", "wallet_id", "revision", "endpoint", "attempts", "observations"}, "delivery public status schema differs")
                _need(status["format"] == "1soft/protocol5-delivery/v1", "delivery format differs")
                label = row["name"][-1]
                _need(status["wallet_id"] == wallets[label]["wallet_id"], "delivery wallet identity differs")
                endpoint = status["endpoint"]
                _need(type(endpoint) is str and re.fullmatch(r"http://127[.]0[.]0[.]1:[1-9][0-9]{0,4}/", endpoint) is not None,
                      "non-loopback delivery endpoint")
                _integer(int(endpoint.split(":")[-1][:-1]), 1, 65535)
                journal_id = hashlib.sha256(b"1soft/protocol5-delivery-id/v1\0" + bytes.fromhex(status["wallet_id"])
                                            + genesis.sha256 + hashlib.sha256(canonical_json(engine)).digest() + endpoint.encode()).hexdigest()
                _need(status["journal_id"] == journal_id, "delivery journal identity differs")
                _hash(status["revision"])
                _integer(status["attempts"], 1, 16)
                _integer(status["observations"], 1, 32)
    return all_decisions


def _evidence(value, raw, genesis, transactions, observations, certificates, decisions):
    txid = {name: transaction_id(raw[name + "-transaction.bin"]).hex() for name in TX_NAMES}
    prover_outputs = [row["stdout_sha256"] for row in value["processes"] if row["role"] == "development-prover"]
    wire_hashes = {name: hashlib.sha256(raw[name + "-transaction.bin"]).hexdigest() for name in TX_NAMES}
    _need(all(digest in prover_outputs for digest in wire_hashes.values()), "retained transaction lacks measured prover provenance")
    _need(prover_outputs.count(wire_hashes["payment"]) == 1, "lost-return payment was proved more than once")
    fields = {name: item.public_fields for name, item in transactions.items()}
    for name, public in fields.items():
        _need(public[0] == (1).to_bytes(32, "little")
              and [item.hex() for item in public[1:4]] == [genesis.value[key] for key in ("genesis_field", "asset_field", "context_field")]
              and int.from_bytes(public[4], "little") == genesis.value["authority_epoch"]
              and public[7].hex() == genesis.value["policy_field"]
              and int.from_bytes(public[12], "little") == genesis.value["fee"], "transaction statement domain differs")
        _need(0 <= int.from_bytes(public[5], "little") < int.from_bytes(public[6], "little") <= genesis.value["limits"]["max_height"],
              "transaction validity differs")
    payment = _receipt(observations["payment"], raw["payment-transaction.bin"])
    _receipt(observations["recipient"], raw["recipient-transaction.bin"])
    _receipt(observations["equivalent"], raw["equivalent-winner-transaction.bin"])
    _receipt(observations["conflict"], raw["conflict-winner-transaction.bin"])
    _need(txid["equivalent-original"] != txid["equivalent-winner"]
          and fields["equivalent-original"] == fields["equivalent-winner"], "equivalent winner is not a distinct randomized wire")
    _need(txid["conflict-original"] != txid["conflict-winner"]
          and fields["conflict-original"][9] == fields["conflict-winner"][9]
          and fields["conflict-original"][10:12] != fields["conflict-winner"][10:12], "conflict does not change same-nullifier effects")
    expiry_height = observations["expiry"]["state_witness"]["height"]
    until = int.from_bytes(fields["expiry"][6], "little")
    _need(expiry_height + 1 >= until
          and fields["expiry"][9].hex() not in observations["expiry"]["state_witness"]["state"]["spent_nullifiers"], "expiry has no authenticated absence")
    for name, wanted in (("payment", "executed_exact"), ("recipient", "executed_exact"),
                         ("equivalent-original", "executed_equivalent"), ("conflict-original", "conflicting_spend"),
                         ("expiry", "expired_unexecuted")):
        _need(decisions.get(txid[name]) == wanted, "public wallet decision lacks required reconciliation")
    unchanged = {"refused": True, "state_unchanged": True}
    expected = [
        {"validator_count": 4, "equal_power": True, "genesis_commitments": 1,
         "wallet_ids": [row["status"]["wallet_id"] for row in value["wallet_manifests"]], "recipient_initial_state": "unavailable",
         "validator_app_hashes": [observations["expiry"]["state_witness"]["app_hash"]] * 4},
        {"owner_keys_distinct": True, "sender_received_only_recipient_owner_key": True, "recipient_secret_in_sender": False, "owner_key_opcode": 3, "recipient_opcode": 4},
        {"txid": txid["payment"], "payment_value": 20, "fee": 5, "change_value": 75, "executed_exact": True, "actual_proof": True, "validator_count": 4},
        {"before_commit_empty": True, "crash_exit_code": 73, "after_commit_recovered": True,
         "transaction_sha256": hashlib.sha256(raw["payment-transaction.bin"]).hexdigest(), "txid": txid["payment"], "nullifier": fields["payment"][9].hex(),
         "output_capsules_equal": True, "prover_invocations_before": 1, "prover_invocations_after": 1, "controller_unavailable": True},
        {"attempt_claimed_before_io": True, "network_calls": 1, "retry_refused": True, "endpoint_admission_is_execution": False,
         "subcases": {name: {"attempts": 1, "sends": 0 if name == "lost-after-claim" else 1, "retry_refused": True} for name in SETTINGS["attempt_subcases"]}},
        {"payment_state_height": certificates["payment"]["state_height"], "payment_header_height": certificates["payment"]["header_height"],
         "recipient_state_height": certificates["recipient"]["state_height"], "recipient_header_height": certificates["recipient"]["header_height"],
         "certificate_mutations": {name: dict(unchanged) for name in SETTINGS["certificate_mutations"]}},
        {"mutations": {name: dict(unchanged) for name in SETTINGS["capsule_mutations"]}},
        {"txid": txid["recipient"], "payment_value": 7, "fee": 5, "change_value": 8, "actual_proof": True,
         "recipient_import_position": payment["output_position_0"], "return_imported_by_sender": True},
        {"original_txid": txid["conflict-original"], "winner_txid": txid["conflict-winner"], "nullifier": fields["conflict-original"][9].hex(),
         "winner_authenticated": True, "original_state": "conflicting_spend", "payment_export_refused": True,
         "equivalent_original_txid": txid["equivalent-original"], "equivalent_winner_txid": txid["equivalent-winner"], "equivalent_state": "executed_equivalent"},
        {"txid": txid["expiry"], "valid_until": until, "hold_before_expiry": True, "no_receipt_before_expiry": True,
         "authenticated_height": expiry_height, "decision_state": "expired_unexecuted", "winner_precedence": True},
        {"boundaries": {name: {"rows_equal": True, "implicit_network_calls": 0} for name in SETTINGS["restart_boundaries"]}},
        {"validator_count": 4, "controller_nodes_null": True, "controller_paths_in_validator_commands": 0,
         "controller_paths_in_validator_homes": 0, "validator_prover_processes": 0, "validator_client_processes": 0},
        {"artifact": "leakage-scan.json", "matches": 0, "private_journals_excluded": True},
    ]
    for row, wanted in zip(value["checks"], expected):
        _same(row["evidence"], wanted, "check evidence differs: " + row["id"])
    leakage = decode_report(raw["leakage-scan.json"])
    _closed(leakage, {"format", "known_secret_count", "encodings", "private_journals_excluded", "witness_present",
                      "prover_request_present", "capsule_present", "surfaces"}, "leakage receipt schema differs")
    _need(leakage["format"] == "1soft/protocol5-wallet-leakage-scan/v1" and leakage["private_journals_excluded"] is True
          and leakage["witness_present"] is False and leakage["prover_request_present"] is False and leakage["capsule_present"] is False,
          "leakage scan failed or overclaimed")
    _integer(leakage["known_secret_count"], 12, 4096)
    _same(leakage["encodings"], ["raw", "hex", "base64", "decimal"], "secret representation roster differs")
    surfaces = leakage["surfaces"]
    _need(type(surfaces) is list and [row.get("id") for row in surfaces if type(row) is dict] == SETTINGS["leakage_surfaces"], "leakage surface roster differs")
    for row in surfaces:
        _closed(row, {"id", "objects", "bytes", "matches"}, "leakage surface schema differs")
        _integer(row["objects"], 1)
        _integer(row["bytes"], 1)
        _need(type(row["matches"]) is int and row["matches"] == 0, "private leakage detected")


def validate_report(value, *, artifact_directory=None, source_root=ROOT):
    _closed(value, REPORT_KEYS, "report keys differ")
    _scan(value)
    _need(value["schema"] == SCHEMA and value["status"] in {"unassessed", "failed", COMPLETE}, "report schema or status differs")
    _need(value["settings_sha256"] == SETTINGS_SHA256, "settings identity differs")
    _closed(value["claims"], SETTINGS["claims_false"], "claim roster differs")
    _need(all(item is False for item in value["claims"].values()), "unsupported claim")
    _closed(value["inputs"], INPUT_NAMES, "input roster differs")
    _closed(value["expected_sha256"], {"client", "prover"}, "pin roster differs")
    for key in ("source_dirty_before", "source_dirty_after", "processes_started", "actual_proof_accepted"):
        _need(type(value[key]) is bool, "evidence boolean missing")
    for key in ("missing_inputs", "failures", "checks", "processes", "wallet_manifests", "delivery_manifests", "artifacts"):
        _need(type(value[key]) is list, "evidence collection differs")
    missing = value["missing_inputs"]
    _need(all(type(item) is str for item in missing) and len(set(missing)) == len(missing)
          and set(missing) <= INPUT_NAMES | {"expected_client_sha256", "expected_prover_sha256"}, "missing input roster differs")
    _need(all(type(item) is str and re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9 .:_-]{0,159}", item) is not None for item in value["failures"]),
          "failure message is not sanitized")
    if value["status"] == "unassessed":
        expected_missing = {name for name, receipt in value["inputs"].items() if receipt is None}
        expected_missing |= {"expected_" + name + "_sha256" for name, pin in value["expected_sha256"].items() if pin is None}
        _need(set(missing) == expected_missing and bool(missing), "unassessed lacks exact unavailable inputs")
        _need(not value["failures"] and all(value[key] == [] for key in ("checks", "processes", "wallet_manifests", "delivery_manifests", "artifacts"))
              and value["processes_started"] is False and value["actual_proof_accepted"] is False
              and all(value[key] is None for key in ("genesis_sha256", "profile_id", "deployment_id")), "unassessed report overclaims")
        for receipt in value["inputs"].values():
            if receipt is not None:
                _closed(receipt, {"name", "sha256", "bytes"}, "preflight input receipt differs")
                _need(type(receipt["name"]) is str and NAME.fullmatch(receipt["name"]) is not None, "preflight input name differs")
                _hash(receipt["sha256"])
                _integer(receipt["bytes"], 1, 256 * 1024 * 1024)
        for pin in value["expected_sha256"].values():
            if pin is not None:
                _hash(pin)
        return {"status": "unassessed", "qualified": False, "missing_inputs": list(missing)}
    if value["status"] == "failed":
        _need(bool(value["failures"]) and not missing, "failed report lacks exact failure")
        return {"status": "failed", "qualified": False, "failures": list(value["failures"])}
    _need(not missing and not value["failures"] and value["processes_started"] is True and value["actual_proof_accepted"] is True,
          "completed report lacks actual execution")
    checks = value["checks"]
    _need(len(checks) == len(REQUIRED_CHECKS), "check roster differs")
    for row, name in zip(checks, REQUIRED_CHECKS):
        _closed(row, {"id", "passed", "evidence"}, "check schema differs")
        _need(row["id"] == name and row["passed"] is True and type(row["evidence"]) is dict, "omitted, duplicate, failed or reordered check")
    raw = _artifacts(value, artifact_directory)
    genesis, engine, transactions, observations, certificates = _identity(value, raw)
    _processes(value)
    decisions = _manifests(value, genesis, engine, observations)
    _evidence(value, raw, genesis, transactions, observations, certificates, decisions)
    _source(value, source_root)
    return {"status": COMPLETE, "qualified": True, "check_ids": list(REQUIRED_CHECKS)}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("report", type=Path)
    args = parser.parse_args()
    try:
        raw = _read(args.report, SETTINGS["limits"]["report_bytes"])
        value = decode_report(raw)
        result = validate_report(value, artifact_directory=args.report.with_name(args.report.name + ".artifacts"))
    except (ValueError, OSError, TypeError, KeyError, IndexError, RecursionError):
        result = {"status": "refused", "qualified": False}
    print(canonical_json(result).decode())
    return 0 if result["qualified"] else 2


if __name__ == "__main__":
    raise SystemExit(main())
