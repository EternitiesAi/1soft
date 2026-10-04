#!/usr/bin/env python3
"""Run source-bound Protocol 5 state-sync and marker recovery qualification."""
from __future__ import annotations

import argparse
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


def _apply(network: Protocol5Network, target: int, chunk: int,
           payload: bytes, sender: str = "protocol5-runner") -> int:
    request = Request()
    request.apply_snapshot_chunk.index = chunk
    request.apply_snapshot_chunk.chunk = payload
    request.apply_snapshot_chunk.sender = sender
    return network.abci(target, request).apply_snapshot_chunk.result


def _install_direct(network: Protocol5Network, target: int, snapshot: dict) -> None:
    if _offer(network, target, snapshot) != OFFER_ACCEPT:
        raise AssertionError("Protocol 5 direct snapshot offer was not accepted")
    for chunk in range(snapshot["chunks"]):
        if _apply(network, target, chunk, _load(network, snapshot, chunk)) != APPLY_ACCEPT:
            raise AssertionError("Protocol 5 direct snapshot chunk was not accepted")


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
        trust_height = snapshot_height - 1
        trust_hash = rpc(network.http[0], "block", {
            "height": str(trust_height)})["block_id"]["hash"]
        config = network.homes / "node4/config/config.toml"
        config.write_text(patch_toml(config.read_text(), {
            "statesync.enable": True,
            "statesync.rpc_servers": (
                f"http://127.0.0.1:{network.http[0]},"
                f"http://127.0.0.1:{network.http[1]}"),
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
        network.start_engine(4)
        wait_until(lambda: network.height(4) >= snapshot_height, 180)
        observed = [json.loads(line) for line in events.read_text().splitlines()]
        offers = [row for row in observed
                  if row["kind"] == "offer_snapshot" and row["result"] == OFFER_ACCEPT]
        if len(offers) < 2:
            raise AssertionError("CometBFT did not re-offer after lost final Apply reply")

        if network.height(4) != snapshot_height:
            raise AssertionError("state-sync target exceeded frozen snapshot")
        network.stop_engine(4)
        source = network.direct_state(0)
        target = network.direct_state(4)
        _check(report, "trusted-apphash-replay",
               source == target and target["state"]["current_root"] == current_root,
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

        exact = _snapshot(network)
        _install_direct(network, 4, exact)
        last_index = exact["chunks"] - 1
        last_chunk = _load(network, exact, last_index)
        duplicate_result = _apply(network, 4, last_index, last_chunk)
        _check(report, "duplicate-final-reoffer",
               duplicate_result == APPLY_ACCEPT and len(offers) >= 2,
               {"accepted_offers": len(offers),
                "duplicate_final_result": duplicate_result,
                "crash_exit_code": 96})

        metadata = decode_canonical_json(exact["metadata"])
        changed = dict(exact)
        changed_meta = dict(metadata)
        changed_meta["app_hash"] = "00" * 32
        changed["metadata"] = canonical_json(changed_meta)
        same_height_fork = _offer(network, 4, changed, b"\0" * 32)
        if _offer(network, 4, exact) != OFFER_ACCEPT:
            raise AssertionError("exact hostile-matrix offer was not accepted")
        future_chunk = _apply(network, 4, 1, _load(network, exact, 1))
        if _offer(network, 4, exact) != OFFER_ACCEPT:
            raise AssertionError("exact hostile-matrix reoffer was not accepted")
        short_chunk = _apply(network, 4, 0, _load(network, exact, 0)[:-1])
        if _offer(network, 4, exact) != OFFER_ACCEPT:
            raise AssertionError("exact corrupt-final reoffer was not accepted")
        corrupt_final = bytearray(last_chunk)
        corrupt_final[-1] ^= 1
        corrupt_result = None
        for index in range(exact["chunks"]):
            payload = (bytes(corrupt_final) if index == last_index
                       else _load(network, exact, index))
            corrupt_result = _apply(network, 4, index, payload)
        if _offer(network, 4, exact) != OFFER_ACCEPT:
            raise AssertionError("exact partial-transfer offer was not accepted")
        if _apply(network, 4, 0, _load(network, exact, 0)) != APPLY_ACCEPT:
            raise AssertionError("partial transfer first chunk was not accepted")
        network.stop_app(4)
        network.start_app(4, crash={
            "run_token": token, "run_token_sha256": token_sha,
            "crash_phase": "observe", "event_log": events,
        })
        partial_restart = _apply(network, 4, 1, _load(network, exact, 1))

        _advance_sources(network)
        newer = _snapshot(network)
        _install_direct(network, 4, newer)
        rollback = _offer(network, 4, exact)
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
        network.stop_app(4)
        with sqlite3.connect(database) as connection:
            connection.execute("DROP TRIGGER fail_p5_sync")
        network.start_app(4, crash={
            "run_token": token, "run_token_sha256": token_sha,
            "crash_phase": "observe", "event_log": events,
        })
        after_failure = network.direct_state(4)
        _check(report, "hostile-offer-chunk-matrix",
               same_height_fork == OFFER_REJECT
               and future_chunk == APPLY_RETRY
               and short_chunk == APPLY_REJECT_SNAPSHOT
               and corrupt_result == APPLY_REJECT_SNAPSHOT
               and partial_restart == APPLY_ABORT
               and disk_fault_seen and after_failure == before_failure,
               {"same_height_fork": same_height_fork,
                "future_chunk": future_chunk, "short_chunk": short_chunk,
                "corrupt_final": corrupt_result,
                "partial_restart": partial_restart,
                "disk_fault_seen": disk_fault_seen})

        _install_direct(network, 4, newest)
        # The direct newer-marker exercises deliberately moved the application
        # ahead of the stopped nonvalidator engine. Reset only this owned,
        # disposable target home so CometBFT performs a same-height marker
        # recovery through its real state-sync caller before continuing.
        subprocess.run([
            str(paths["engine"]), "unsafe-reset-all", "--home",
            str(network.homes / "node4"), "--keep-addr-book"],
            check=True, capture_output=True, text=True, timeout=30)
        trust_height = newest["height"] - 1
        trust_hash = rpc(network.http[0], "block", {
            "height": str(trust_height)})["block_id"]["hash"]
        config = network.homes / "node4/config/config.toml"
        config.write_text(patch_toml(config.read_text(), {
            "statesync.enable": True,
            "statesync.rpc_servers": (
                f"http://127.0.0.1:{network.http[0]},"
                f"http://127.0.0.1:{network.http[1]}"),
            "statesync.trust_height": trust_height,
            "statesync.trust_hash": trust_hash,
        }), encoding="utf-8")
        network.start_engine(4)
        wait_until(lambda: network.height(4) >= newest["height"], 180)
        if network.height(4) != newest["height"]:
            raise AssertionError("same-height marker recovery advanced unexpectedly")
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
