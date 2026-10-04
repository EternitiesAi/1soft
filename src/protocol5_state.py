"""Deterministic Protocol 5 state transitions and retained-history budgets."""
from __future__ import annotations

import base64
import copy
import hashlib
from typing import Any

from protocol5_encoding import (
    EncodingError, GenesisDocument, Transaction, TransactionIdentityError,
    canonical_json, decode_canonical_json, field_bytes, transaction_id,
)
from protocol5_worker import (
    INVALID_PROOF, INVALID_STATEMENT, OK, VerifierUnavailable,
)

STATE_DOMAIN = b"1soft/shielded-development/apphash/v1\0"
STATE_KEYS = {
    "version", "profile_id", "deployment_id", "commitments", "current_root",
    "root_history", "spent_nullifiers", "fee_total",
    "accepted_transaction_count", "history_transaction_count",
    "history_transaction_bytes", "execution_blocks", "receipts",
}
U64_MAX = 2**64 - 1

CODE_OK = 0
CODE_MALFORMED = 1
CODE_IDENTITY = 2
CODE_VALIDITY = 3
CODE_ANCHOR = 4
CODE_NULLIFIER = 5
CODE_OUTPUT = 6
CODE_CAPACITY = 7
CODE_STATEMENT = 8
CODE_PROOF = 9
LOGS = {
    CODE_OK: "",
    CODE_MALFORMED: "malformed shielded transaction",
    CODE_IDENTITY: "shielded transaction identity differs",
    CODE_VALIDITY: "shielded validity window differs",
    CODE_ANCHOR: "unknown shielded anchor root",
    CODE_NULLIFIER: "shielded nullifier already spent",
    CODE_OUTPUT: "invalid shielded output commitment",
    CODE_CAPACITY: "shielded development capacity exceeded",
    CODE_STATEMENT: "invalid shielded public statement",
    CODE_PROOF: "invalid shielded proof",
}


class StateError(ValueError):
    pass


class HistoryLimitError(StateError):
    pass


def _need(condition: bool, message: str) -> None:
    if not condition:
        raise StateError(message)


def result(code: int, data: str = "") -> dict:
    _need(type(code) is int and code in LOGS, "invalid transaction result code")
    _need(type(data) is str and (code == 0 or data == ""), "invalid transaction result data")
    return {"code": code, "log": LOGS[code], "data": data}


def _field_int(raw: bytes) -> int:
    return int.from_bytes(raw, "little")


def initial_state(genesis: GenesisDocument, worker) -> dict:
    commitments = [bytes.fromhex(item) for item in genesis.value["initial_commitments"]]
    root = worker.tree_root(commitments)
    state = {
        "version": 1,
        "profile_id": genesis.profile.identity.hex(),
        "deployment_id": genesis.deployment.identity.hex(),
        "commitments": [item.hex() for item in commitments],
        "current_root": root.hex(),
        "root_history": [{
            "kind": "genesis", "height": 0, "tx_index": 0, "root": root.hex(),
        }],
        "spent_nullifiers": [],
        "fee_total": 0,
        "accepted_transaction_count": 0,
        "history_transaction_count": 0,
        "history_transaction_bytes": 0,
        "execution_blocks": [],
        "receipts": [],
    }
    audit_state(genesis, state, 0, worker)
    return state


def application_hash(genesis: GenesisDocument, height: int, state: dict) -> str:
    _need(type(height) is int and 0 <= height <= genesis.value["limits"]["max_height"],
          "height exceeds Protocol 5 bound")
    material = {
        "genesis_sha256": genesis.sha256.hex(),
        "height": height,
        "state": state,
    }
    return hashlib.sha256(STATE_DOMAIN + canonical_json(material)).hexdigest()


def _canonical_b64(value: Any) -> bytes:
    _need(type(value) is str, "invalid retained transaction encoding")
    try:
        raw = base64.b64decode(value, validate=True)
    except Exception as exc:
        raise StateError("invalid retained transaction encoding") from exc
    _need(base64.b64encode(raw).decode("ascii") == value,
          "noncanonical retained transaction encoding")
    return raw


def audit_state(genesis: GenesisDocument, state: dict, height: int, worker) -> None:
    _need(type(state) is dict and set(state) == STATE_KEYS, "invalid closed Protocol 5 state")
    _need(state["version"] == 1, "invalid Protocol 5 state version")
    _need(state["profile_id"] == genesis.profile.identity.hex()
          and state["deployment_id"] == genesis.deployment.identity.hex(),
          "state identity differs")
    commitments = state["commitments"]
    _need(type(commitments) is list and len(commitments) <= 16,
          "invalid state commitments")
    commitment_bytes = [field_bytes(item) for item in commitments]
    _need(all(any(item) for item in commitment_bytes)
          and len(set(commitment_bytes)) == len(commitment_bytes),
          "state commitments differ")
    current_root = field_bytes(state["current_root"])
    _need(worker.tree_root(commitment_bytes) == current_root, "state tree root differs")
    roots = state["root_history"]
    _need(type(roots) is list and len(roots) >= 1, "root history missing")
    first = roots[0]
    _need(type(first) is dict and first == {
        "kind": "genesis", "height": 0, "tx_index": 0, "root": roots[0].get("root")
    }, "invalid genesis root history entry")
    _need(field_bytes(first["root"]) == worker.tree_root(
        [bytes.fromhex(item) for item in genesis.value["initial_commitments"]]),
        "genesis tree root differs")
    for entry in roots[1:]:
        _need(type(entry) is dict and set(entry) == {
            "kind", "height", "tx_index", "txid", "root"
        } and entry["kind"] == "transaction",
              "invalid transaction root history entry")
        _need(type(entry["height"]) is int and 1 <= entry["height"] <= height
              and type(entry["tx_index"]) is int and entry["tx_index"] >= 0,
              "invalid root history position")
        _need(type(entry["txid"]) is str and len(entry["txid"]) == 64
              and set(entry["txid"]) <= set("0123456789abcdef")
              and entry["txid"] != "00" * 32,
              "invalid root history transaction")
        field_bytes(entry["root"])
    _need(roots[-1]["root"] == state["current_root"], "current root is not latest")
    spent = state["spent_nullifiers"]
    _need(type(spent) is list and spent == sorted(spent)
          and len(spent) == len(set(spent)), "spent nullifiers differ")
    for item in spent:
        field_bytes(item)
    receipts = state["receipts"]
    accepted = state["accepted_transaction_count"]
    _need(type(receipts) is list and type(accepted) is int
          and accepted == len(receipts) == len(spent) == len(roots) - 1
          and 0 <= accepted <= genesis.value["limits"]["max_accepted_transactions"],
          "accepted transaction counters differ")
    _need(len(commitments) == len(genesis.value["initial_commitments"]) + 2 * accepted,
          "commitment count differs from accepted transactions")
    fee_total = state["fee_total"]
    _need(type(fee_total) is int and fee_total == accepted * genesis.value["fee"]
          and 0 <= fee_total <= genesis.value["limits"]["max_fee_total"],
          "fee total differs")
    blocks = state["execution_blocks"]
    _need(type(blocks) is list and len(blocks) == height, "execution history height differs")
    count = 0
    raw_bytes = 0
    receipt_index = 0
    for expected_height, block in enumerate(blocks, 1):
        _need(type(block) is dict and set(block) == {"height", "transactions", "results"}
              and block["height"] == expected_height
              and type(block["transactions"]) is list and type(block["results"]) is list
              and len(block["transactions"]) == len(block["results"]),
              "invalid execution block")
        for wire, tx_result in zip(block["transactions"], block["results"]):
            raw = _canonical_b64(wire)
            count += 1
            raw_bytes += len(raw)
            _need(type(tx_result) is dict and set(tx_result) == {"code", "log", "data"}
                  and type(tx_result["code"]) is int
                  and tx_result == result(tx_result["code"], tx_result["data"]),
                  "invalid retained transaction result")
            if tx_result["code"] == 0:
                _need(receipt_index < len(receipts)
                      and tx_result["data"] == receipts[receipt_index]["txid"],
                      "receipt order differs")
                receipt_index += 1
    _need(receipt_index == len(receipts), "receipt count differs")
    _need(state["history_transaction_count"] == count
          and count <= genesis.value["limits"]["max_history_transactions"],
          "history transaction count differs")
    _need(state["history_transaction_bytes"] == raw_bytes
          and raw_bytes <= genesis.value["limits"]["max_history_tx_bytes"],
          "history transaction bytes differ")
    for receipt in receipts:
        required = {
            "txid", "profile_id", "deployment_id", "height", "tx_index",
            "anchor_root", "tree_root_before", "tree_root_after", "nullifier",
            "output_commitment_0", "output_commitment_1",
            "output_position_0", "output_position_1", "fee",
        }
        _need(type(receipt) is dict and set(receipt) == required,
              "invalid Protocol 5 receipt")
        _need(receipt["profile_id"] == state["profile_id"]
              and receipt["deployment_id"] == state["deployment_id"],
              "receipt identity differs")
        for name in ("anchor_root", "tree_root_before", "tree_root_after", "nullifier",
                     "output_commitment_0", "output_commitment_1"):
            field_bytes(receipt[name])


def _identity_matches(genesis: GenesisDocument, tx: Transaction) -> bool:
    fields = tx.public_fields
    return (
        _field_int(fields[0]) == 1
        and fields[1] == bytes.fromhex(genesis.value["genesis_field"])
        and fields[2] == bytes.fromhex(genesis.value["asset_field"])
        and fields[3] == bytes.fromhex(genesis.value["context_field"])
        and _field_int(fields[4]) == genesis.value["authority_epoch"]
        and fields[7] == bytes.fromhex(genesis.value["policy_field"])
    )


def _evaluate(genesis: GenesisDocument, state: dict, raw: bytes, height: int,
              tx_index: int, accepted_roots: frozenset[bytes], worker):
    try:
        tx = Transaction.decode(raw, genesis)
    except TransactionIdentityError:
        return result(CODE_IDENTITY)
    except (EncodingError, ValueError, TypeError):
        return result(CODE_MALFORMED)
    fields = tx.public_fields
    if not _identity_matches(genesis, tx):
        return result(CODE_IDENTITY)
    relation = _field_int(fields[0])
    epoch = _field_int(fields[4])
    valid_from = _field_int(fields[5])
    valid_until = _field_int(fields[6])
    fee = _field_int(fields[12])
    if any(value > U64_MAX for value in (relation, epoch, valid_from, valid_until, fee))             or fee != genesis.value["fee"]:
        return result(CODE_STATEMENT)
    if not valid_from < valid_until or not valid_from <= height < valid_until:
        return result(CODE_VALIDITY)
    anchor = fields[8]
    if anchor not in accepted_roots:
        return result(CODE_ANCHOR)
    nullifier = fields[9]
    if nullifier.hex() in state["spent_nullifiers"]:
        return result(CODE_NULLIFIER)
    output_0, output_1 = fields[10], fields[11]
    committed = set(state["commitments"])
    if (not any(output_0) or not any(output_1) or output_0 == output_1
            or output_0.hex() in committed or output_1.hex() in committed):
        return result(CODE_OUTPUT)
    limits = genesis.value["limits"]
    if (len(state["commitments"]) + 2 > 16
            or state["accepted_transaction_count"] + 1 > limits["max_accepted_transactions"]
            or state["fee_total"] > limits["max_fee_total"] - fee):
        return result(CODE_CAPACITY)
    commitments = [bytes.fromhex(item) for item in state["commitments"]]
    append = worker.verify_and_append(commitments, fields, tx.proof)
    if append.status == INVALID_STATEMENT:
        return result(CODE_STATEMENT)
    if append.status == INVALID_PROOF:
        return result(CODE_PROOF)
    if append.status != OK:
        raise VerifierUnavailable("worker returned unsupported append status")
    if (append.root_before != bytes.fromhex(state["current_root"])
            or append.position_0 != len(commitments)
            or append.position_1 != len(commitments) + 1):
        raise VerifierUnavailable("worker append transition differs")
    updated_commitments = commitments + [output_0, output_1]
    if worker.tree_root(updated_commitments) != append.root_after:
        raise VerifierUnavailable("worker root cross-check differs")
    txid = transaction_id(raw).hex()
    receipt = {
        "txid": txid,
        "profile_id": genesis.profile.identity.hex(),
        "deployment_id": genesis.deployment.identity.hex(),
        "height": height,
        "tx_index": tx_index,
        "anchor_root": anchor.hex(),
        "tree_root_before": append.root_before.hex(),
        "tree_root_after": append.root_after.hex(),
        "nullifier": nullifier.hex(),
        "output_commitment_0": output_0.hex(),
        "output_commitment_1": output_1.hex(),
        "output_position_0": append.position_0,
        "output_position_1": append.position_1,
        "fee": fee,
    }
    state["commitments"] = [item.hex() for item in updated_commitments]
    state["current_root"] = append.root_after.hex()
    state["root_history"].append({
        "kind": "transaction", "height": height, "tx_index": tx_index,
        "txid": txid, "root": append.root_after.hex(),
    })
    state["spent_nullifiers"] = sorted(state["spent_nullifiers"] + [nullifier.hex()])
    state["fee_total"] += fee
    state["accepted_transaction_count"] += 1
    state["receipts"].append(receipt)
    return result(CODE_OK, txid)


def execute_block(genesis: GenesisDocument, committed_state: dict, txs: list[bytes],
                  height: int, worker) -> tuple[dict, list[dict]]:
    _need(type(height) is int and height == len(committed_state["execution_blocks"]) + 1
          and height <= genesis.value["limits"]["max_height"],
          "unexpected Protocol 5 block height")
    _need(type(txs) is list and all(type(raw) is bytes for raw in txs),
          "invalid Protocol 5 transaction container")
    limits = genesis.value["limits"]
    _need(len(txs) <= limits["max_txs_per_block"], "too many Protocol 5 transactions")
    next_count = committed_state["history_transaction_count"] + len(txs)
    next_bytes = committed_state["history_transaction_bytes"] + sum(map(len, txs))
    if next_count > limits["max_history_transactions"]             or next_bytes > limits["max_history_tx_bytes"]:
        raise HistoryLimitError("retained Protocol 5 history capacity exceeded")
    state = decode_canonical_json(canonical_json(committed_state))
    accepted_roots = frozenset(bytes.fromhex(row["root"]) for row in state["root_history"])
    results = []
    for tx_index, raw in enumerate(txs):
        results.append(_evaluate(
            genesis, state, raw, height, tx_index, accepted_roots, worker))
    state["history_transaction_count"] = next_count
    state["history_transaction_bytes"] = next_bytes
    state["execution_blocks"].append({
        "height": height,
        "transactions": [base64.b64encode(raw).decode("ascii") for raw in txs],
        "results": copy.deepcopy(results),
    })
    audit_state(genesis, state, height, worker)
    return state, results


def replay_state(genesis: GenesisDocument, expected_state: dict, height: int, worker) -> None:
    """Replay every retained wire through the worker and require exact state equality."""
    audit_state(genesis, expected_state, height, worker)
    blocks = expected_state["execution_blocks"]
    candidate = initial_state(genesis, worker)
    for expected_height, block in enumerate(blocks, 1):
        txs = [_canonical_b64(value) for value in block["transactions"]]
        candidate, results = execute_block(
            genesis, candidate, txs, expected_height, worker)
        _need(results == block["results"], "replayed transaction results differ")
    _need(canonical_json(candidate) == canonical_json(expected_state),
          "replayed Protocol 5 state differs")
