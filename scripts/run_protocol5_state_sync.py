#!/usr/bin/env python3
"""Run source-bound Protocol 5 state-sync and marker recovery qualification."""
from __future__ import annotations

import argparse
import base64
import binascii
import copy
import hashlib
import json
import os
from pathlib import Path
import sqlite3
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path[:0] = [str(ROOT / "src"), str(ROOT / "scripts")]

from protocol5_abci_wire import Request
from protocol5_encoding import (
    Transaction, canonical_json, decode_canonical_json, derive_genesis_field,
    field_hex, genesis_document,
)
from run_devnet import patch_toml, rpc, wait_until
from run_protocol5_engine import (
    INPUT_NAMES, DevelopmentController, Protocol5Network, _check,
    _make_outputs, _wait_accepted, development_note, finalize_fresh_genesis,
    preflight,
)
from state_sync import (
    APPLY_ABORT, APPLY_ACCEPT, APPLY_REJECT_SNAPSHOT, APPLY_RETRY,
    OFFER_ACCEPT, OFFER_REJECT,
)
from protocol5_state_sync import HASH_DOMAIN


def _repack_snapshot(snapshot: dict, payload: dict) -> tuple[dict, list[bytes]]:
    if type(snapshot) is not dict or type(payload) is not dict:
        raise ValueError("invalid Protocol 5 snapshot repack input")
    metadata = decode_canonical_json(snapshot["metadata"])
    chunk_bytes = metadata.get("chunk_bytes")
    if type(chunk_bytes) is not int or chunk_bytes <= 0:
        raise ValueError("invalid Protocol 5 snapshot chunk geometry")
    raw = canonical_json(payload)
    chunks = [raw[offset:offset + chunk_bytes]
              for offset in range(0, len(raw), chunk_bytes)]
    if not chunks:
        raise ValueError("empty Protocol 5 snapshot payload")
    digest = hashlib.sha256(HASH_DOMAIN + raw).digest()
    metadata.update(
        payload_bytes=len(raw), chunks=len(chunks),
        payload_sha256=digest.hex())
    result = dict(snapshot)
    result.update(
        chunks=len(chunks), hash=digest, metadata=canonical_json(metadata))
    return result, chunks


def _semantic_payload_variants(payload: dict) -> dict[str, dict]:
    if type(payload) is not dict or type(payload.get("state")) is not dict:
        raise ValueError("invalid Protocol 5 semantic payload")
    proof = copy.deepcopy(payload)
    transaction = None
    for block in proof["state"].get("execution_blocks", []):
        transactions = block.get("transactions") if type(block) is dict else None
        if type(transactions) is list and transactions:
            transaction = transactions
            break
    if transaction is None or type(transaction[0]) is not str:
        raise ValueError("Protocol 5 snapshot lacks replay transaction")
    try:
        wire = bytearray(base64.b64decode(transaction[0], validate=True))
    except (binascii.Error, ValueError) as exc:
        raise ValueError("invalid Protocol 5 replay transaction") from exc
    if not wire:
        raise ValueError("empty Protocol 5 replay transaction")
    wire[-1] ^= 1
    transaction[0] = base64.b64encode(wire).decode("ascii")

    nullifier = copy.deepcopy(payload)
    nullifiers = nullifier["state"].get("spent_nullifiers")
    if type(nullifiers) is not list or not nullifiers:
        raise ValueError("Protocol 5 snapshot lacks spent nullifier")
    nullifiers.pop(0)

    history = copy.deepcopy(payload)
    roots = history["state"].get("root_history")
    if type(roots) is not list or not roots or type(roots[0]) is not dict:
        raise ValueError("Protocol 5 snapshot lacks root history")
    try:
        changed = bytearray(bytes.fromhex(roots[0]["root"]))
    except (KeyError, TypeError, ValueError) as exc:
        raise ValueError("invalid Protocol 5 root history") from exc
    if len(changed) != 32:
        raise ValueError("invalid Protocol 5 root history")
    changed[0] ^= 1
    roots[0]["root"] = bytes(changed).hex()
    return {
        "altered_proof": proof,
        "removed_nullifier": nullifier,
        "changed_root_history": history,
    }


def _snapshot(network: Protocol5Network, index: int = 0) -> dict:
    request = Request()
    request.list_snapshots.SetInParent()
    rows = network.abci(index, request).list_snapshots.snapshots
    if len(rows) != 1:
        raise AssertionError("Protocol 5 source snapshot count differs")
    row = rows[0]
    return {
        "height": row.height, "format": row.format, "chunks": row.chunks,
        "hash": bytes(row.hash), "metadata": bytes(row.metadata),
    }


def _load(network: Protocol5Network, snapshot: dict,
          chunk: int, source: int = 0) -> bytes:
    request = Request()
    request.load_snapshot_chunk.height = snapshot["height"]
    request.load_snapshot_chunk.format = snapshot["format"]
    request.load_snapshot_chunk.chunk = chunk
    return bytes(network.abci(source, request).load_snapshot_chunk.chunk)


def _snapshot_payload(
        network: Protocol5Network, snapshot: dict, source: int = 0) -> dict:
    raw = b"".join(
        _load(network, snapshot, index, source)
        for index in range(snapshot["chunks"]))
    metadata = decode_canonical_json(snapshot["metadata"])
    if (len(raw) != metadata["payload_bytes"]
            or hashlib.sha256(HASH_DOMAIN + raw).digest() != snapshot["hash"]):
        raise AssertionError("Protocol 5 source snapshot payload differs")
    return decode_canonical_json(raw, max_bytes=metadata["payload_bytes"])


def _state_sync_events(path: Path) -> list[dict]:
    if not path.exists():
        return []
    try:
        return [
            json.loads(line)
            for line in path.read_text(encoding="utf-8").splitlines()
        ]
    except (OSError, UnicodeDecodeError, json.JSONDecodeError):
        return []


def _snapshot_engine_ready(
        network: Protocol5Network, target: int, snapshot_height: int,
        events: Path, event_offset: int) -> dict | None:
    process = network.engines.get(target)
    if process is None or process.poll() is not None:
        raise RuntimeError("Protocol 5 state-sync engine stopped unexpectedly")
    status = rpc(network.http[target], "status")["sync_info"]
    if status.get("catching_up") is not False:
        return None
    state = network.direct_state(target)
    if state.get("height") != snapshot_height:
        return None
    rows = _state_sync_events(events)
    if type(event_offset) is not int or event_offset < 0 or len(rows) < event_offset:
        raise RuntimeError("invalid Protocol 5 state-sync event offset")
    recent = rows[event_offset:]
    for offer_index, event in enumerate(recent):
        chunks = event.get("chunks")
        identity = (event.get("pid"), event.get("start_ticks"))
        if not (event.get("kind") == "offer_snapshot"
                and event.get("height") == snapshot_height
                and event.get("result") == OFFER_ACCEPT
                and type(chunks) is int and chunks > 0
                and all(type(item) is int and item > 0 for item in identity)):
            continue
        for commit_index in range(offer_index + 1, len(recent)):
            commit = recent[commit_index]
            if not (commit.get("kind") == "after_snapshot_commit"
                    and commit.get("height") == snapshot_height
                    and (commit.get("pid"), commit.get("start_ticks"))
                        == identity):
                continue
            if any(
                    completed.get("kind") == "apply_snapshot_chunk"
                    and completed.get("height") == snapshot_height
                    and completed.get("index") == chunks - 1
                    and completed.get("result") == APPLY_ACCEPT
                    and (completed.get("pid"), completed.get("start_ticks"))
                        == identity
                    for completed in recent[commit_index + 1:]):
                return state
    return None


def _different_digest(value: str) -> str:
    if (type(value) is not str or len(value) != 64
            or any(ch not in "0123456789abcdef" for ch in value)):
        raise ValueError("invalid Protocol 5 digest mutation input")
    changed = bytearray.fromhex(value)
    changed[0] ^= 1
    return changed.hex()


def _metadata_mutation(snapshot: dict, name: str, value) -> dict:
    metadata = decode_canonical_json(snapshot["metadata"])
    if name not in metadata:
        raise ValueError("unknown Protocol 5 snapshot metadata field")
    metadata[name] = value
    changed = dict(snapshot)
    changed["metadata"] = canonical_json(metadata)
    return changed


def _offer(network: Protocol5Network, target: int, snapshot: dict,
           app_hash: bytes | None = None) -> int:
    request = Request()
    row = request.offer_snapshot.snapshot
    row.height = snapshot["height"]
    row.format = snapshot["format"]
    row.chunks = snapshot["chunks"]
    row.hash = snapshot["hash"]
    row.metadata = snapshot["metadata"]
    request.offer_snapshot.app_hash = (
        app_hash if app_hash is not None
        else bytes.fromhex(decode_canonical_json(snapshot["metadata"])["app_hash"]))
    return network.abci(target, request).offer_snapshot.result


def _apply_response(network: Protocol5Network, target: int, chunk: int,
                    payload: bytes, sender: str = "protocol5-runner") -> dict:
    request = Request()
    request.apply_snapshot_chunk.index = chunk
    request.apply_snapshot_chunk.chunk = payload
    request.apply_snapshot_chunk.sender = sender
    response = network.abci(target, request).apply_snapshot_chunk
    return {
        "result": response.result,
        "refetch_chunks": list(response.refetch_chunks),
        "reject_senders": list(response.reject_senders),
    }


def _apply(network: Protocol5Network, target: int, chunk: int,
           payload: bytes, sender: str = "protocol5-runner") -> int:
    return _apply_response(network, target, chunk, payload, sender)["result"]


def _transfer_payload(
        network: Protocol5Network, target: int,
        snapshot: dict, chunks: list[bytes]) -> int:
    if _offer(network, target, snapshot) != OFFER_ACCEPT:
        raise AssertionError("Protocol 5 semantic snapshot offer was not accepted")
    result = None
    for index, chunk in enumerate(chunks):
        result = _apply(network, target, index, chunk)
    if result is None:
        raise AssertionError("Protocol 5 semantic snapshot had no chunks")
    return result


def _install_direct(network: Protocol5Network, target: int, snapshot: dict) -> None:
    if _offer(network, target, snapshot) != OFFER_ACCEPT:
        raise AssertionError("Protocol 5 direct snapshot offer was not accepted")
    for chunk in range(snapshot["chunks"]):
        if _apply(network, target, chunk, _load(network, snapshot, chunk)) != APPLY_ACCEPT:
            raise AssertionError("Protocol 5 direct snapshot chunk was not accepted")


def _set_persistent_peers(
        network: Protocol5Network, index: int, peers: tuple[int, ...]) -> None:
    config = network.homes / f"node{index}/config/config.toml"
    value = ",".join(
        f"{network.node_ids[peer]}@127.0.0.1:{network.p2p[peer]}"
        for peer in peers)
    config.write_text(patch_toml(
        config.read_text(), {"p2p.persistent_peers": value}), encoding="utf-8")


def _remove_addrbooks(
        network: Protocol5Network, indices: tuple[int, ...]) -> None:
    for index in indices:
        addrbook = network.homes / f"node{index}/config/addrbook.json"
        if addrbook.exists() or addrbook.is_symlink():
            if addrbook.is_symlink() or not addrbook.is_file():
                raise RuntimeError(
                    "unsafe Protocol 5 snapshot-provider address book")
            addrbook.unlink()


def _prepare_snapshot_provider(
        network: Protocol5Network, snapshot_height: int) -> None:
    if type(snapshot_height) is not int or snapshot_height <= 0:
        raise ValueError("invalid Protocol 5 snapshot-provider height")
    for index in range(4):
        if index in network.engines:
            network.stop_engine(index)
    _set_persistent_peers(network, 0, (4,))
    _set_persistent_peers(network, 4, (0,))
    for index in (1, 2, 3):
        _set_persistent_peers(
            network, index,
            tuple(peer for peer in (1, 2, 3) if peer != index))
    _remove_addrbooks(network, tuple(range(5)))
    for index in (1, 2, 3):
        network.start_engine(index)
    wait_until(lambda: all(
        network.height(index) >= snapshot_height + 2 for index in (1, 2, 3)), 90)
    network.start_engine(0)


def _restore_source_peers(network: Protocol5Network) -> None:
    running = tuple(sorted(network.engines))
    catchup_height = min(network.height(index) for index in (1, 2, 3))
    for index in running:
        network.stop_engine(index)
    for index in range(5):
        _set_persistent_peers(
            network, index, tuple(peer for peer in range(5) if peer != index))
    _remove_addrbooks(network, tuple(range(5)))
    for index in (1, 2, 3, 0, 4):
        if index in running:
            network.start_engine(index)
    wait_until(lambda: network.height(0) >= catchup_height, 90)


def _advance_sources(network: Protocol5Network, amount: int = 2) -> dict:
    network.stop_engine(4)
    for index in (2, 3):
        if index not in network.engines:
            network.start_engine(index)
    network.set_empty_blocks(True)
    start = max(network.height(index) for index in range(4))
    wait_until(lambda: min(network.height(index) for index in range(4))
               >= start + amount, 60)
    return network.hold_sources_without_quorum()


def run_state_sync_scenarios(paths: dict[str, Path], output: Path,
                             report: dict) -> None:
    network = Protocol5Network(paths, output, report, include_target=True)
    try:
        prefix = network.genesis_prefix(paths["genesis"].read_bytes())
        prefix["limits"].update(
            max_height=512,
            max_accepted_transactions=6,
            snapshot_chunk_bytes=1024,
            max_snapshot_bytes=128 * 1024,
            worker_request_timeout_seconds=min(
                2, prefix["limits"]["worker_request_timeout_seconds"]),
        )
        prefix["genesis_field"] = field_hex(derive_genesis_field(prefix))
        controller = DevelopmentController(
            paths["client"], paths["prover"], prefix, network.receipts)
        notes = [development_note(512, value) for value in (100, 90, 80, 70)]
        commitments, genesis_root = controller.commitments(notes)
        raw_genesis = finalize_fresh_genesis(prefix, commitments)
        genesis = genesis_document(raw_genesis)
        network.install_genesis(raw_genesis)
        _check(report, "four-source-never-started-target",
               not (network.runtime / "app4/state.sqlite").exists()
               and 4 not in network.apps and 4 not in network.engines,
               {"source_validators": 4, "target_started": False})
        network.start_sources()
        report["processes_started"] = True
        report["genesis_sha256"] = genesis.sha256.hex()
        report["profile_id"] = genesis.profile.identity.hex()
        report["deployment_id"] = genesis.deployment.identity.hex()

        outputs = _make_outputs(notes[0], genesis.value["fee"])
        transaction = controller.prove(raw_genesis, controller.spend_request(
            raw_genesis, commitments, 0, notes[0], outputs,
            valid_from=1, valid_until=500))
        if int(network.broadcast(0, transaction)["code"]) != 0:
            raise AssertionError("state-sync source proof was not admitted")
        source_states = _wait_accepted(network, 1)
        report["actual_proof_accepted"] = True
        notes.extend(outputs)
        commitments.extend(
            item.hex() for item in Transaction.decode(transaction, genesis).public_fields[10:12])
        regenerated, current_root = controller.commitments(notes)
        if (regenerated != commitments
                or current_root != source_states[0]["state"]["current_root"]):
            raise AssertionError("state-sync source root differs from Rust client")

        network.set_empty_blocks(True)
        wait_until(lambda: min(network.height(index) for index in range(4)) >= 4, 60)
        frozen = network.hold_sources_without_quorum()
        snapshot_height = frozen["height"]
        source_snapshot = _snapshot(network)
        if source_snapshot["height"] != snapshot_height:
            raise AssertionError("Protocol 5 frozen snapshot height differs")
        source_checkpoint = network.direct_state(0)
        _prepare_snapshot_provider(network, snapshot_height)
        trust_height = snapshot_height - 1
        trust_hash = rpc(network.http[1], "block", {
            "height": str(trust_height)})["block_id"]["hash"]
        config = network.homes / "node4/config/config.toml"
        config.write_text(patch_toml(config.read_text(), {
            "statesync.enable": True,
            "statesync.rpc_servers": (
                f"http://127.0.0.1:{network.http[1]},"
                f"http://127.0.0.1:{network.http[2]}"),
            "statesync.trust_height": trust_height,
            "statesync.trust_hash": trust_hash,
            "statesync.trust_period": "168h0m0s",
        }), encoding="utf-8")
        token = os.urandom(32).hex()
        token_sha = hashlib.sha256(token.encode("ascii")).hexdigest()
        events = network.runtime / "state-sync-events.jsonl"
        network.start_app(4, crash={
            "run_token": token, "run_token_sha256": token_sha,
            "crash_phase": "after_snapshot_commit", "event_log": events,
        })
        network.start_engine(4)
        wait_until(lambda: network.apps[4].poll() is not None, 120)
        if network.apps[4].returncode != 96:
            raise AssertionError("final Apply crash exit code differs")
        network.stop_engine(4)
        network.stop_app(4)
        network.start_app(4, crash={
            "run_token": token, "run_token_sha256": token_sha,
            "crash_phase": "observe", "event_log": events,
        })
        recovery_event_offset = len(_state_sync_events(events))
        network.start_engine(4)
        target = wait_until(
            lambda: _snapshot_engine_ready(
                network, 4, snapshot_height, events, recovery_event_offset),
            180)
        observed = _state_sync_events(events)
        offers = [row for row in observed
                  if row["kind"] == "offer_snapshot" and row["result"] == OFFER_ACCEPT]
        if len(offers) < 2:
            raise AssertionError("CometBFT did not re-offer after lost final Apply reply")

        if target["height"] != snapshot_height:
            raise AssertionError("state-sync target exceeded frozen snapshot")
        network.stop_engine(4)
        _check(report, "trusted-apphash-replay",
               source_checkpoint == target
               and target["state"]["current_root"] == current_root,
               {"height": target["height"], "app_hash": target["app_hash"],
                "root": current_root})
        report["state_sync_observed"] = True

        database = network.runtime / "app4/state.sqlite"
        with sqlite3.connect(database) as connection:
            block_count = connection.execute("SELECT count(*) FROM blocks").fetchone()[0]
            history_count = connection.execute("SELECT count(*) FROM history").fetchone()[0]
            marker_count = connection.execute(
                "SELECT count(*) FROM snapshot_marker").fetchone()[0]
        _check(report, "marker-no-historical-responses",
               block_count == 0 and history_count == target["height"]
               and marker_count == 1,
               {"height": target["height"], "blocks": block_count,
                "history": history_count, "markers": marker_count})

        exact = source_snapshot
        exact_payload = _snapshot_payload(network, exact)
        _install_direct(network, 4, exact)
        last_index = exact["chunks"] - 1
        last_chunk = _load(network, exact, last_index)
        duplicate_result = _apply(network, 4, last_index, last_chunk)
        _check(report, "duplicate-final-reoffer",
               duplicate_result == APPLY_ACCEPT and len(offers) >= 2,
               {"snapshot_height": snapshot_height,
                "accepted_offers": len(offers),
                "duplicate_final_result": duplicate_result,
                "crash_exit_code": 96})

        metadata = decode_canonical_json(exact["metadata"])
        subcases = {}
        for field, name in (
                ("genesis_sha256", "wrong_genesis"),
                ("profile_id", "wrong_profile"),
                ("deployment_id", "wrong_deployment")):
            changed = _metadata_mutation(
                exact, field, _different_digest(metadata[field]))
            subcases[name] = {
                "operation": "offer",
                "result": _offer(network, 4, changed),
            }

        wrong_trusted = bytes.fromhex(_different_digest(metadata["app_hash"]))
        subcases["wrong_trusted_apphash"] = {
            "operation": "offer",
            "result": _offer(network, 4, exact, wrong_trusted),
        }
        changed_app_hash = _different_digest(metadata["app_hash"])
        changed = _metadata_mutation(exact, "app_hash", changed_app_hash)
        subcases["same_height_different_apphash"] = {
            "operation": "offer",
            "result": _offer(network, 4, changed, bytes.fromhex(changed_app_hash)),
        }
        changed_payload = copy.deepcopy(exact_payload)
        changed_payload["state"]["fee_total"] += 1
        changed, _ = _repack_snapshot(exact, changed_payload)
        subcases["same_height_same_apphash_different_payload"] = {
            "operation": "offer",
            "result": _offer(network, 4, changed),
        }

        if _offer(network, 4, exact) != OFFER_ACCEPT:
            raise AssertionError("exact future-chunk offer was not accepted")
        future = _apply_response(network, 4, 1, _load(network, exact, 1))
        subcases["future_chunk"] = {"operation": "apply", **future}

        if _offer(network, 4, exact) != OFFER_ACCEPT:
            raise AssertionError("exact short-chunk offer was not accepted")
        subcases["short_chunk"] = {
            "operation": "apply",
            "result": _apply(network, 4, 0, _load(network, exact, 0)[:-1]),
        }

        if _offer(network, 4, exact) != OFFER_ACCEPT:
            raise AssertionError("exact excess-chunk offer was not accepted")
        subcases["excess_chunk"] = {
            "operation": "apply",
            "result": _apply(network, 4, 0, _load(network, exact, 0) + b"\0"),
        }

        if _offer(network, 4, exact) != OFFER_ACCEPT:
            raise AssertionError("exact corrupt-final offer was not accepted")
        corrupt_final = bytearray(last_chunk)
        corrupt_final[-1] ^= 1
        corrupt_result = None
        for index in range(exact["chunks"]):
            payload = (bytes(corrupt_final) if index == last_index
                       else _load(network, exact, index))
            corrupt_result = _apply(network, 4, index, payload)
        subcases["corrupt_final"] = {
            "operation": "apply", "result": corrupt_result,
        }

        if _offer(network, 4, exact) != OFFER_ACCEPT:
            raise AssertionError("exact duplicate-chunk offer was not accepted")
        first_chunk = _load(network, exact, 0)
        if _apply(network, 4, 0, first_chunk) != APPLY_ACCEPT:
            raise AssertionError("initial duplicate-chunk transfer was not accepted")
        conflicting_chunk = bytearray(first_chunk)
        conflicting_chunk[-1] ^= 1
        subcases["conflicting_duplicate"] = {
            "operation": "apply",
            "result": _apply(network, 4, 0, bytes(conflicting_chunk)),
        }

        if _offer(network, 4, exact) != OFFER_ACCEPT:
            raise AssertionError("exact partial-transfer offer was not accepted")
        if _apply(network, 4, 0, first_chunk) != APPLY_ACCEPT:
            raise AssertionError("partial transfer first chunk was not accepted")
        network.stop_app(4)
        network.start_app(4, crash={
            "run_token": token, "run_token_sha256": token_sha,
            "crash_phase": "observe", "event_log": events,
        })
        subcases["partial_restart"] = {
            "operation": "apply",
            "result": _apply(network, 4, 1, _load(network, exact, 1)),
        }

        _restore_source_peers(network)
        _advance_sources(network)
        newer = _snapshot(network)
        newer_payload = _snapshot_payload(network, newer)
        before_semantic_faults = network.direct_state(4)
        for name, payload in _semantic_payload_variants(newer_payload).items():
            changed, chunks = _repack_snapshot(newer, payload)
            subcases[name] = {
                "operation": "apply",
                "result": _transfer_payload(network, 4, changed, chunks),
            }
        semantic_state_preserved = (
            network.direct_state(4) == before_semantic_faults)
        _install_direct(network, 4, newer)
        rollback = _offer(network, 4, exact)
        subcases["rollback"] = {
            "operation": "offer", "result": rollback,
        }
        _check(report, "rollback-refusal", rollback == OFFER_REJECT,
               {"older_height": exact["height"],
                "newer_height": newer["height"], "result": rollback})

        _advance_sources(network)
        newest = _snapshot(network)
        before_failure = network.direct_state(4)
        with sqlite3.connect(database) as connection:
            connection.execute(
                "CREATE TRIGGER fail_p5_sync BEFORE INSERT ON committed "
                "BEGIN SELECT RAISE(ABORT, 'runner disk fault'); END")
        if _offer(network, 4, newest) != OFFER_ACCEPT:
            raise AssertionError("disk-fault offer was not accepted")
        disk_fault_seen = False
        try:
            for index in range(newest["chunks"]):
                _apply(network, 4, index, _load(network, newest, index))
        except (OSError, RuntimeError):
            disk_fault_seen = True
        wait_until(lambda: network.apps[4].poll() is not None, 20)
        application_failed = network.apps[4].returncode not in (None, 0)
        network.stop_app(4)
        with sqlite3.connect(database) as connection:
            connection.execute("DROP TRIGGER fail_p5_sync")
        network.start_app(4, crash={
            "run_token": token, "run_token_sha256": token_sha,
            "crash_phase": "observe", "event_log": events,
        })
        after_failure = network.direct_state(4)
        subcases["disk_failure"] = {
            "operation": "apply",
            "application_failed": application_failed,
            "state_preserved": after_failure == before_failure,
        }
        expected_subcases = {
            "wrong_genesis": {"operation": "offer", "result": OFFER_REJECT},
            "wrong_profile": {"operation": "offer", "result": OFFER_REJECT},
            "wrong_deployment": {"operation": "offer", "result": OFFER_REJECT},
            "wrong_trusted_apphash": {
                "operation": "offer", "result": OFFER_REJECT},
            "altered_proof": {
                "operation": "apply", "result": APPLY_REJECT_SNAPSHOT},
            "removed_nullifier": {
                "operation": "apply", "result": APPLY_REJECT_SNAPSHOT},
            "changed_root_history": {
                "operation": "apply", "result": APPLY_REJECT_SNAPSHOT},
            "future_chunk": {
                "operation": "apply", "result": APPLY_RETRY,
                "refetch_chunks": [0], "reject_senders": []},
            "short_chunk": {
                "operation": "apply", "result": APPLY_REJECT_SNAPSHOT},
            "excess_chunk": {
                "operation": "apply", "result": APPLY_REJECT_SNAPSHOT},
            "corrupt_final": {
                "operation": "apply", "result": APPLY_REJECT_SNAPSHOT},
            "conflicting_duplicate": {
                "operation": "apply", "result": APPLY_REJECT_SNAPSHOT},
            "same_height_different_apphash": {
                "operation": "offer", "result": OFFER_REJECT},
            "same_height_same_apphash_different_payload": {
                "operation": "offer", "result": OFFER_REJECT},
            "partial_restart": {
                "operation": "apply", "result": APPLY_ABORT},
            "rollback": {"operation": "offer", "result": OFFER_REJECT},
            "disk_failure": {
                "operation": "apply", "application_failed": True,
                "state_preserved": True},
        }
        _check(report, "hostile-offer-chunk-matrix",
               subcases == expected_subcases
               and semantic_state_preserved and disk_fault_seen,
               {"subcases": subcases})

        _install_direct(network, 4, newest)
        # A CometBFT state provider authenticates snapshot H with headers H+1
        # and H+2. Keep node0 isolated at H as the snapshot peer while the
        # independent light providers advance beyond it.
        _prepare_snapshot_provider(network, newest["height"])
        # The direct newer-marker exercises deliberately moved the application
        # ahead of the stopped nonvalidator engine. Reset only this owned,
        # disposable target home so CometBFT performs a same-height marker
        # recovery through its real state-sync caller before continuing.
        subprocess.run([
            str(paths["engine"]), "unsafe-reset-all", "--home",
            str(network.homes / "node4"), "--keep-addr-book"],
            check=True, capture_output=True, text=True, timeout=30)
        trust_height = newest["height"] - 1
        trust_hash = rpc(network.http[1], "block", {
            "height": str(trust_height)})["block_id"]["hash"]
        config = network.homes / "node4/config/config.toml"
        config.write_text(patch_toml(config.read_text(), {
            "statesync.enable": True,
            "statesync.rpc_servers": (
                f"http://127.0.0.1:{network.http[1]},"
                f"http://127.0.0.1:{network.http[2]}"),
            "statesync.trust_height": trust_height,
            "statesync.trust_hash": trust_hash,
        }), encoding="utf-8")
        recovery_event_offset = len(_state_sync_events(events))
        network.start_engine(4)
        recovered = wait_until(
            lambda: _snapshot_engine_ready(
                network, 4, newest["height"], events, recovery_event_offset),
            180)
        if recovered["height"] != newest["height"]:
            raise AssertionError("same-height marker recovery advanced unexpectedly")
        _restore_source_peers(network)
        post_outputs = _make_outputs(notes[1], genesis.value["fee"])
        post = controller.prove(raw_genesis, controller.spend_request(
            raw_genesis, commitments, 1, notes[1], post_outputs,
            valid_from=1, valid_until=500))
        network.stage_without_quorum([post])
        _wait_accepted(network, 2, nodes=(0, 1, 2, 3, 4), timeout=120)
        network.stop_engine(4)
        post_checkpoint = network.hold_sources_without_quorum()
        network.start_engine(4)
        wait_until(
            lambda: network.height(4) >= post_checkpoint["height"], 120)
        network.stop_engine(4)
        post_states = [network.direct_state(index) for index in range(5)]
        _check(report, "post-sync-continuation",
               len({state["app_hash"] for state in post_states}) == 1
               and all(state["state"]["spent_nullifiers"]
                       == post_states[0]["state"]["spent_nullifiers"]
                       for state in post_states),
               {"height": post_states[0]["height"],
                "app_hash": post_states[0]["app_hash"]})

        network.stop_node(4)
        network.start_app(4)
        network.start_engine(4)
        wait_until(
            lambda: network.height(4) >= post_checkpoint["height"], 90)
        network.stop_engine(4)
        restarted = network.direct_state(4)
        _check(report, "same-store-restart",
               restarted == network.direct_state(0),
               {"height": restarted["height"],
                "app_hash": restarted["app_hash"]})
    finally:
        network.close()


def preflight_state_sync(**kwargs):
    kwargs["profile_name"] = "state-sync"
    return preflight(**kwargs)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    for name in INPUT_NAMES:
        parser.add_argument("--" + name, type=Path, required=True)
    parser.add_argument("--expected-prover-sha256")
    parser.add_argument("--expected-client-sha256")
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    report = preflight_state_sync(
        output=args.output, expected_prover_sha256=args.expected_prover_sha256,
        expected_client_sha256=args.expected_client_sha256,
        **{name: getattr(args, name) for name in INPUT_NAMES})
    return 1 if report["status"] == "failed" else 0


if __name__ == "__main__":
    raise SystemExit(main())
