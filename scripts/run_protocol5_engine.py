#!/usr/bin/env python3
"""Source-bound Protocol 5 real-engine preflight and evidence scaffold."""
from __future__ import annotations

import argparse
import base64
import binascii
import concurrent.futures
from contextlib import closing
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import signal
import socket
import sqlite3
import subprocess
import sys
import tempfile
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))
from protocol5_encoding import (
    canonical_json, decode_canonical_json, derive_genesis_field, field_hex,
    genesis_document, Transaction,
)
from protocol5_abci_wire import Request, Response, read_frame, write_frame
from protocol5_certificate import (
    trust_from_protocol5_genesis, verify_protocol5_state_certificate,
)
from protocol5_encoding import comet_validator_set
from run_devnet import free_ports, patch_toml, rpc, wait_until

ENGINE_VERSION = "0.38.25"
ENGINE_SHA256 = "218628da07bed5d27e178d38d0bef9ecf46f21b214c8e9fea402fd215fccc024"
KAT_DOMAIN = b"1soft/shielded-kat/v1\0"
INPUT_NAMES = (
    "engine", "worker", "client", "prover", "profile", "kat",
    "toolchain", "policy", "genesis",
)
MAX_LOG_BYTES = 1_048_576
from protocol5_controller import (
    CLIENT_GENESIS_MAGIC, CLIENT_MAGIC, CLIENT_OWNER_MAGIC, PROVER_MAGIC,
    DevelopmentController, Note, RecipientOutput, development_note,
)

def fresh_genesis_prefix(template_raw: bytes, chain_id: str,
                         engine_validators: list[dict]) -> dict:
    """Build the nonrecursive genesis prefix before Rust derives commitments."""
    template = genesis_document(template_raw)
    if type(engine_validators) is not list or len(engine_validators) != 4:
        raise ValueError("exactly four engine validators required")
    validators = []
    powers = []
    for row in engine_validators:
        if type(row) is not dict or not set(row) >= {"pub_key", "power"}:
            raise ValueError("invalid engine validator record")
        public = row["pub_key"]
        if type(public) is not dict or set(public) != {"type", "value"}:
            raise ValueError("invalid engine validator public key")
        try:
            key = base64.b64decode(public["value"], validate=True)
            power = int(row["power"])
        except (binascii.Error, TypeError, ValueError) as exc:
            raise ValueError("invalid engine validator encoding") from exc
        if (public["type"] != "tendermint/PubKeyEd25519" or len(key) != 32
                or not any(key) or power <= 0):
            raise ValueError("unsupported engine validator")
        validators.append({"public_key": key.hex(), "power": power})
        powers.append(power)
    if len(set(powers)) != 1 or len({row["public_key"] for row in validators}) != 4:
        raise ValueError("engine validators must have unique keys and equal powers")
    value = decode_canonical_json(canonical_json(template.value))
    value["chain_id"] = chain_id
    value["validators"] = sorted(validators, key=lambda row: row["public_key"])
    value["initial_commitments"] = []
    value["genesis_field"] = field_hex(derive_genesis_field(value))
    return value


def finalize_fresh_genesis(prefix: dict, commitments: list[str]) -> bytes:
    if type(prefix) is not dict or type(commitments) is not list:
        raise ValueError("invalid fresh genesis inputs")
    value = decode_canonical_json(canonical_json(prefix))
    value["initial_commitments"] = list(commitments)
    raw = canonical_json(value)
    genesis_document(raw)
    return raw


def _app_start_timeout(genesis_raw: bytes) -> int:
    selected = genesis_document(genesis_raw).value["limits"][
        "worker_startup_timeout_seconds"]
    return min(150, selected + 30)


def _engine_consensus_ready(network: "Protocol5Network", index: int,
                            minimum_height: int) -> bool:
    status = rpc(network.http[index], "status")["sync_info"]
    return (int(status["latest_block_height"]) >= minimum_height
            and status.get("catching_up") is False)


def _application_ready(network: "Protocol5Network", index: int,
                       process, socket_path: Path) -> bool:
    if process.poll() is not None:
        raise ValueError(f"Protocol 5 application node{index} exited during startup")
    if not socket_path.exists():
        return False
    # A failed endpoint can leave its old socket inode behind. Only a live
    # Info response proves that the replacement application is listening.
    request = Request()
    request.info.SetInParent()
    return network.abci(index, request).WhichOneof("value") == "info"


def p5_app_command(paths: dict[str, Path], genesis: Path, genesis_sha256: str,
                   database: Path, socket: Path, *, crash: dict | None = None) -> list[str]:
    script = ROOT / "scripts" / (
        "serve_abci_p5_test.py" if crash is not None else "serve_abci_p5.py")
    command = [
        sys.executable, "-B", str(script),
        "--genesis", str(genesis), "--genesis-sha256", genesis_sha256,
        "--database", str(database), "--socket", str(socket),
        "--worker", str(paths["worker"]), "--kat", str(paths["kat"]),
        "--toolchain", str(paths["toolchain"]), "--policy", str(paths["policy"]),
    ]
    if crash is not None:
        if not {"run_token", "run_token_sha256", "crash_phase"} <= set(crash) \
                or set(crash) - {"run_token", "run_token_sha256", "crash_phase",
                                 "event_log"}:
            raise ValueError("invalid Protocol 5 crash controls")
        command.extend([
            "--run-token", crash["run_token"],
            "--run-token-sha256", crash["run_token_sha256"],
            "--crash-phase", crash["crash_phase"],
        ])
        if "event_log" in crash:
            command.extend(["--event-log", str(crash["event_log"])])
    return command


def _stop(process: subprocess.Popen | None) -> int | None:
    if process is None or process.poll() is not None:
        return None if process is None else process.returncode
    process.terminate()
    try:
        process.wait(timeout=10)
    except subprocess.TimeoutExpired:
        process.kill()
        process.wait(timeout=10)
    return process.returncode


def _start_ticks(pid: int) -> int:
    fields = Path(f"/proc/{pid}/stat").read_text(encoding="ascii").split()
    return int(fields[21])


def _children(pid: int) -> list[int]:
    path = Path(f"/proc/{pid}/task/{pid}/children")
    return [int(value) for value in path.read_text(encoding="ascii").split()]


def app_query(port: int, path: str) -> dict:
    response = rpc(port, "abci_query", {"path": path, "prove": False})["response"]
    if int(response["code"]) != 0:
        raise RuntimeError("Protocol 5 application query rejected: " + path)
    return json.loads(base64.b64decode(response["value"], validate=True))


def _check(report: dict, check_id: str, passed: bool,
           evidence: dict | None = None) -> None:
    report["checks"].append({
        "id": check_id, "passed": bool(passed), "evidence": evidence or {}})
    if not passed:
        raise AssertionError(check_id)


def _field_mutation(transaction: bytes, index: int, value: bytes) -> bytes:
    if type(value) is not bytes or len(value) != 32 or not 0 <= index < 14:
        raise ValueError("invalid transaction field mutation")
    result = bytearray(transaction)
    offset = 82 + 32 * index
    result[offset:offset + 32] = value
    return bytes(result)


def _backup_sqlite(source: Path, target: Path) -> dict:
    if target.exists() or target.is_symlink():
        raise FileExistsError("Protocol 5 retained database already exists")
    with closing(sqlite3.connect(
            f"file:{source}?mode=ro", uri=True)) as origin:
        with closing(sqlite3.connect(target)) as retained:
            origin.backup(retained)
            integrity = retained.execute("PRAGMA integrity_check").fetchone()
            if integrity != ("ok",):
                raise RuntimeError("retained Protocol 5 database is corrupt")
            committed = retained.execute(
                "SELECT height, app_hash FROM committed WHERE id=1").fetchone()
            if (committed is None or type(committed[0]) is not int
                    or type(committed[1]) is not str
                    or len(committed[1]) != 64
                    or any(ch not in "0123456789abcdef"
                           for ch in committed[1])):
                raise RuntimeError("retained Protocol 5 checkpoint differs")
    os.chmod(target, 0o600)
    return {"height": committed[0], "app_hash": committed[1]}


class Protocol5Network:
    """Owned one-host CometBFT and ABCI processes for a single qualification run."""

    def __init__(self, paths: dict[str, Path], output: Path, report: dict,
                 *, include_target: bool,
                 runtime_parent: Path | None = None):
        self.paths = paths
        self.output = output
        self.report = report
        self.include_target = include_target
        if runtime_parent is not None:
            runtime_parent = Path(runtime_parent)
            if runtime_parent.is_symlink() or not runtime_parent.is_dir():
                raise ValueError("unsafe Protocol 5 runtime parent")
        self.temp = tempfile.TemporaryDirectory(
            prefix="one-protocol5-engine-", dir=runtime_parent)
        self.runtime = Path(self.temp.name)
        self.homes = self.runtime / "nodes"
        self.apps: dict[int, subprocess.Popen] = {}
        self.engines: dict[int, subprocess.Popen] = {}
        self.handles = []
        self.receipts = []
        self.genesis_path = self.runtime / "protocol5-genesis.json"
        self.genesis_sha256 = ""
        self.chain_id = "one-p5-" + os.urandom(6).hex()
        self.p2p, self.http = ([], [])
        subprocess.run(
            [str(paths["engine"]), "testnet", "--v", "4", "--n", "1",
             "--o", str(self.homes), "--initial-height", "1"],
            check=True, capture_output=True, text=True, timeout=40)
        for item in self.homes.rglob("*"):
            os.chmod(item, 0o700 if item.is_dir() else 0o600)
        root = json.loads((self.homes / "node0/config/genesis.json").read_text())
        if len(root.get("validators", [])) != 4:
            raise AssertionError("engine testnet did not create four validators")
        for row in root["validators"]:
            row["power"] = "10"
        self.engine_genesis = root
        ports = free_ports(10)
        self.p2p, self.http = ports[:5], ports[5:]
        self.node_ids = [subprocess.check_output(
            [str(paths["engine"]), "show-node-id", "--home",
             str(self.homes / f"node{index}")], text=True, timeout=10).strip()
            for index in range(5)]

    def genesis_prefix(self, template_raw: bytes) -> dict:
        return fresh_genesis_prefix(
            template_raw, self.chain_id, self.engine_genesis["validators"])

    def install_genesis(self, raw: bytes) -> None:
        genesis = genesis_document(raw)
        expected = {
            base64.b64decode(row["pub_key"]["value"], validate=True).hex():
            int(row["power"])
            for row in self.engine_genesis["validators"]
        }
        if (genesis.value["chain_id"] != self.chain_id
                or {row["public_key"]: row["power"]
                    for row in genesis.value["validators"]} != expected):
            raise ValueError("fresh Protocol 5 genesis differs from engine identities")
        self.genesis_path.write_bytes(raw)
        os.chmod(self.genesis_path, 0o600)
        self.genesis_sha256 = hashlib.sha256(raw).hexdigest()
        self.engine_genesis.update(
            chain_id=self.chain_id, initial_height="1",
            app_state=genesis.value)
        self.engine_genesis["consensus_params"]["block"].update(
            max_bytes="1048576", max_gas="-1")
        encoded = json.dumps(
            self.engine_genesis, sort_keys=True,
            separators=(",", ":"), ensure_ascii=False) + "\n"
        for index in range(5):
            home = self.homes / f"node{index}"
            (home / "config/genesis.json").write_text(encoded, encoding="utf-8")
            os.chmod(home / "config/genesis.json", 0o600)
            app_dir = self.runtime / f"app{index}"
            app_dir.mkdir(mode=0o700)
            config = home / "config/config.toml"
            config.write_text(patch_toml(config.read_text(), {
                "proxy_app": f"unix://{app_dir / 'a.sock'}",
                "abci": "socket",
                "rpc.laddr": f"tcp://127.0.0.1:{self.http[index]}",
                "rpc.unsafe": False,
                "p2p.laddr": f"tcp://127.0.0.1:{self.p2p[index]}",
                "p2p.persistent_peers": ",".join(
                    f"{self.node_ids[other]}@127.0.0.1:{self.p2p[other]}"
                    for other in range(5) if other != index),
                "p2p.addr_book_strict": False,
                "p2p.allow_duplicate_ip": True,
                "p2p.pex": False,
                "consensus.timeout_commit": "500ms",
                "consensus.create_empty_blocks": False,
                "consensus.create_empty_blocks_interval": "0s",
                "mempool.max_tx_bytes": 65536,
            }), encoding="utf-8")

    def _record(self, role: str, index: int, process: subprocess.Popen,
                executable_sha256: str) -> None:
        self.receipts.append({
            "role": role, "node": index, "pid": process.pid,
            "start_ticks": _start_ticks(process.pid),
            "executable_sha256": executable_sha256,
        })

    def start_app(self, index: int, *, crash: dict | None = None) -> None:
        socket = self.runtime / f"app{index}/a.sock"
        if socket.exists() or socket.is_symlink():
            if index in self.apps and self.apps[index].poll() is None:
                raise AssertionError("existing Protocol 5 app still owns socket")
            socket.unlink()
        log = (self.runtime / f"app{index}.log").open("ab")
        self.handles.append(log)
        command = p5_app_command(
            self.paths, self.genesis_path, self.genesis_sha256,
            self.runtime / f"app{index}/state.sqlite", socket, crash=crash)
        process = subprocess.Popen(command, stdout=log, stderr=log)
        self.apps[index] = process

        def ready():
            return _application_ready(self, index, process, socket)

        wait_until(ready, _app_start_timeout(self.genesis_path.read_bytes()))
        self._record(
            "application", index, process,
            hashlib.sha256((ROOT / "scripts" / (
                "serve_abci_p5_test.py" if crash else "serve_abci_p5.py"
            )).read_bytes()).hexdigest())
        worker_children = wait_until(lambda: _children(process.pid), 10)
        if len(worker_children) != 1:
            raise AssertionError("Protocol 5 application worker count differs")
        self.receipts.append({
            "role": "verifier-worker", "node": index,
            "pid": worker_children[0],
            "start_ticks": _start_ticks(worker_children[0]),
            "executable_sha256": _sha(self.paths["worker"]),
        })

    def start_engine(self, index: int) -> None:
        log = (self.runtime / f"engine{index}.log").open("ab")
        self.handles.append(log)
        process = subprocess.Popen(
            [str(self.paths["engine"]), "start", "--home",
             str(self.homes / f"node{index}")], stdout=log, stderr=log)
        self.engines[index] = process
        self._record("engine", index, process, _sha(self.paths["engine"]))
        wait_until(lambda: self.height(index) >= 0, 90)

    def start_sources(self) -> None:
        if not self.genesis_sha256:
            raise RuntimeError("Protocol 5 genesis is not installed")
        for index in range(4):
            self.start_app(index)
        for index in range(4):
            self.start_engine(index)
        wait_until(lambda: all(
            self.state(index)["height"] >= 0 for index in range(4)), 90)

    def height(self, index: int) -> int:
        process = self.engines[index]
        if process.poll() is not None:
            raise RuntimeError(
                f"engine node{index} exited {process.returncode}")
        return int(rpc(self.http[index], "status")["sync_info"]["latest_block_height"])

    def abci(self, index: int, request: Request) -> Response:
        address = self.runtime / f"app{index}/a.sock"
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as connection:
            connection.settimeout(40)
            connection.connect(str(address))
            with connection.makefile("rwb", buffering=0) as stream:
                write_frame(stream, request)
                raw = read_frame(stream)
        if raw is None:
            raise RuntimeError("Protocol 5 ABCI endpoint closed without response")
        response = Response.FromString(raw)
        if response.WhichOneof("value") == "exception":
            raise RuntimeError("Protocol 5 ABCI endpoint returned an exception")
        return response

    def direct_check(self, index: int, transaction: bytes) -> int:
        request = Request()
        request.check_tx.tx = transaction
        return self.abci(index, request).check_tx.code

    def direct_process(self, index: int, transactions: list[bytes],
                       height: int, validator_hash: bytes) -> int:
        request = Request()
        request.process_proposal.txs.extend(transactions)
        request.process_proposal.height = height
        request.process_proposal.next_validators_hash = validator_hash
        return self.abci(index, request).process_proposal.status

    def direct_prepare(self, index: int, transactions: list[bytes],
                       height: int, max_bytes: int) -> list[bytes]:
        request = Request()
        request.prepare_proposal.txs.extend(transactions)
        request.prepare_proposal.height = height
        request.prepare_proposal.max_tx_bytes = max_bytes
        return list(self.abci(index, request).prepare_proposal.txs)

    def broadcast(self, index: int, transaction: bytes) -> dict:
        return rpc(self.http[index], "broadcast_tx_sync", {
            "tx": base64.b64encode(transaction).decode("ascii")})

    def mempool_transactions(self, index: int) -> list[bytes]:
        response = rpc(self.http[index], "unconfirmed_txs", {"limit": "100"})
        rows = response.get("txs") or []
        try:
            return [base64.b64decode(row, validate=True) for row in rows]
        except (binascii.Error, TypeError) as exc:
            raise RuntimeError("Protocol 5 mempool transaction differs") from exc

    def hold_sources_without_quorum(self, attempts: int = 8) -> dict:
        if not {0, 1, 2, 3} <= set(self.engines):
            raise RuntimeError("four running source engines required")
        for _ in range(attempts):
            def converged():
                with concurrent.futures.ThreadPoolExecutor(max_workers=4) as pool:
                    states = list(pool.map(self.direct_state, range(4)))
                identities = {(row["height"], row["app_hash"]) for row in states}
                return states[0] if len(identities) == 1 else None

            checkpoint = wait_until(converged, 30)
            self.stop_engine(3)
            self.stop_engine(2)
            held = [self.direct_state(index) for index in range(4)]
            identities = {(row["height"], row["app_hash"]) for row in held}
            if len(identities) == 1:
                return held[0]
            self.start_engine(2)
            self.start_engine(3)
        raise RuntimeError("could not hold Protocol 5 sources at one checkpoint")

    def stage_without_quorum(
            self, transactions: list[bytes], *,
            resume: tuple[int, ...] = (2, 3)) -> tuple[list[dict], dict]:
        if (type(transactions) is not list or not transactions
                or any(type(item) is not bytes or not item for item in transactions)):
            raise ValueError("invalid Protocol 5 staged transactions")
        if (type(resume) is not tuple or len(set(resume)) != len(resume)
                or any(index not in (2, 3) for index in resume)):
            raise ValueError("invalid Protocol 5 staged resume set")
        running_sources = set(self.engines) & {0, 1, 2, 3}
        if running_sources == {0, 1, 2, 3}:
            checkpoint = self.hold_sources_without_quorum()
        elif running_sources == {0, 1}:
            states = [self.direct_state(index) for index in range(4)]
            identities = {(row["height"], row["app_hash"]) for row in states}
            if len(identities) != 1:
                raise RuntimeError("held Protocol 5 sources differ")
            checkpoint = states[0]
        else:
            raise RuntimeError("Protocol 5 sources are not runnable or held")
        expected = set(transactions)
        try:
            admissions = [self.broadcast(0, item) for item in transactions]
            if any(int(row["code"]) != 0 for row in admissions):
                raise RuntimeError("Protocol 5 staged transaction was refused")

            def staged():
                observed = [
                    set(self.mempool_transactions(index)) for index in (0, 1)]
                return all(expected <= rows for rows in observed)

            wait_until(staged, 30)
        except Exception:
            for index in (2, 3):
                if index not in self.engines:
                    self.start_engine(index)
            raise
        for index in resume:
            self.start_engine(index)
        return admissions, checkpoint

    def state(self, index: int = 0) -> dict:
        return app_query(self.http[index], "/state")

    def direct_state(self, index: int) -> dict:
        request = Request()
        request.query.path = "/state"
        response = self.abci(index, request).query
        if response.code != 0:
            raise RuntimeError("Protocol 5 direct state query was rejected")
        return json.loads(bytes(response.value))

    def stop_node(self, index: int) -> None:
        for process in (
                self.engines.pop(index, None), self.apps.pop(index, None)):
            code = _stop(process)
            if process is not None:
                self._record_exit(process.pid, code)

    def stop_engine(self, index: int) -> None:
        process = self.engines.pop(index, None)
        if process is not None:
            self._record_exit(process.pid, _stop(process))

    def stop_app(self, index: int) -> None:
        process = self.apps.pop(index, None)
        if process is not None:
            self._record_exit(process.pid, _stop(process))

    def worker_pid(self, index: int) -> int:
        process = self.apps[index]
        children = _children(process.pid)
        if len(children) != 1:
            raise AssertionError("Protocol 5 application worker count differs")
        return children[0]

    def set_empty_blocks(self, enabled: bool, *,
                         commit_delay: str | None = None) -> None:
        if commit_delay not in (None, "60s"):
            raise ValueError("unsupported qualification commit delay")
        running = sorted(self.engines)
        for index in running:
            self.stop_engine(index)
        for index in range(5):
            config = self.homes / f"node{index}/config/config.toml"
            config.write_text(patch_toml(config.read_text(), {
                "consensus.create_empty_blocks": enabled,
                "consensus.create_empty_blocks_interval": "0s",
                "consensus.timeout_commit": commit_delay or ("2s" if enabled else "500ms"),
            }), encoding="utf-8")
        for index in running:
            self.start_engine(index)

    def _record_exit(self, pid: int, code: int | None) -> None:
        rows = [row for row in self.receipts if row["pid"] == pid]
        if len(rows) != 1:
            raise AssertionError("Protocol 5 process receipt identity differs")
        rows[0]["exit_code"] = code

    def close(self) -> None:
        for process in list(self.engines.values()) + list(self.apps.values()):
            self._record_exit(process.pid, _stop(process))
        for handle in self.handles:
            handle.close()
        artifacts = self.output.with_name(self.output.name + ".artifacts")
        if artifacts.exists():
            raise FileExistsError("Protocol 5 artifact directory already exists")
        artifacts.mkdir(mode=0o700)
        manifest = []
        bounded_logs = list(self.runtime.glob("*.log"))
        state_sync_events = self.runtime / "state-sync-events.jsonl"
        if state_sync_events.exists() or state_sync_events.is_symlink():
            if state_sync_events.is_symlink() or not state_sync_events.is_file():
                raise RuntimeError("unsafe Protocol 5 state-sync event log")
            bounded_logs.append(state_sync_events)
        for path in sorted(bounded_logs):
            raw = path.read_bytes()
            truncated = len(raw) > MAX_LOG_BYTES
            raw = raw[:MAX_LOG_BYTES]
            raw = raw.replace(str(self.runtime).encode(), b"<private-run>")
            target = artifacts / path.name
            target.write_bytes(raw)
            os.chmod(target, 0o600)
            manifest.append({
                "name": path.name, "sha256": hashlib.sha256(raw).hexdigest(),
                "bytes": len(raw), "truncated": truncated,
            })
        for index in range(5):
            database = self.runtime / f"app{index}/state.sqlite"
            if database.is_file():
                target = artifacts / f"state{index}.sqlite"
                checkpoint = _backup_sqlite(database, target)
                manifest.append({
                    "name": target.name, "sha256": _sha(target),
                    "bytes": target.stat().st_size, "truncated": False,
                    "height": checkpoint["height"],
                    "app_hash": checkpoint["app_hash"],
                })
        (artifacts / "manifest.json").write_text(
            json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        self.report["artifacts"] = manifest
        self.report["processes"] = self.receipts
        self.temp.cleanup()


def _wait_accepted(network: Protocol5Network, count: int,
                   nodes=(0, 1, 2, 3), timeout: int = 90) -> list[dict]:
    def ready():
        states = [network.state(index) for index in nodes]
        return states if all(
            state["state"]["accepted_transaction_count"] == count
            for state in states) else None
    return wait_until(ready, timeout)


def _make_outputs(note: Note, fee: int) -> tuple[Note, Note]:
    remaining = note.value - fee
    if remaining < 2:
        raise ValueError("development note cannot pay fee and two outputs")
    left = remaining // 2
    return (
        development_note(note.expiry, left),
        development_note(note.expiry, remaining - left),
    )


def _prepare_conflict_below_quorum(
        network: Protocol5Network, first: bytes, second: bytes,
        max_bytes: int,
        validator_hash: bytes) -> tuple[list[int], list[bytes], int, dict]:
    checkpoint = network.hold_sources_without_quorum()
    admissions = [
        network.direct_check(0, first),
        network.direct_check(1, second),
    ]
    prepared = network.direct_prepare(
        0, [first, second], checkpoint["height"] + 1, max_bytes)
    process_status = network.direct_process(
        0, [first, second], checkpoint["height"] + 1, validator_hash)
    return admissions, prepared, process_status, checkpoint


def _hold_transaction_height(network: Protocol5Network) -> dict:
    """Reserve the next height without letting an empty proposal consume it."""
    before = max(network.direct_state(index)["height"] for index in range(4))
    # A height-bound AppHash changes even on empty blocks. CometBFT therefore
    # needs another proof block despite create_empty_blocks=False. Reserve a
    # finite commit delay after observing a new block under the new config;
    # construct/stage the exact one-height transaction before the next proposal.
    # Preserve all WAL and validator signing state through ordinary restarts.
    network.set_empty_blocks(False, commit_delay="60s")
    wait_until(lambda: all(network.direct_state(index)["height"] > before
                           for index in range(4)), 90)
    return network.hold_sources_without_quorum()


def _process_probe_at_held_height(
        network: Protocol5Network, transactions: list[bytes],
        validator_hash: bytes) -> tuple[int, dict]:
    checkpoint = network.hold_sources_without_quorum()
    try:
        result = network.direct_process(
            0, transactions, checkpoint["height"] + 1, validator_hash)
    finally:
        for index in (2, 3):
            if index not in network.engines:
                network.start_engine(index)
    return result, checkpoint


def _check_tx_at_held_state(
        network: Protocol5Network,
        transactions: list[bytes]) -> tuple[list[int], dict, dict]:
    if (type(transactions) is not list or not transactions
            or any(type(item) is not bytes or not item for item in transactions)):
        raise ValueError("invalid Protocol 5 direct CheckTx probes")
    checkpoint = network.hold_sources_without_quorum()
    try:
        before = network.direct_state(0)
        if before != checkpoint:
            raise RuntimeError("held Protocol 5 checkpoint changed before CheckTx")
        codes = [network.direct_check(0, item) for item in transactions]
        after = network.direct_state(0)
    finally:
        for index in (2, 3):
            if index not in network.engines:
                network.start_engine(index)
    return codes, before, after


def _run_consensus_scenarios(paths: dict[str, Path], output: Path,
                             report: dict) -> None:
    network = Protocol5Network(paths, output, report, include_target=False)
    try:
        prefix = network.genesis_prefix(paths["genesis"].read_bytes())
        prefix["limits"]["max_height"] = 512
        prefix["limits"]["max_accepted_transactions"] = 6
        prefix["limits"]["worker_request_timeout_seconds"] = min(
            2, prefix["limits"]["worker_request_timeout_seconds"])
        prefix["genesis_field"] = field_hex(derive_genesis_field(prefix))
        controller = DevelopmentController(
            paths["client"], paths["prover"], prefix, network.receipts)
        notes = [development_note(512, value) for value in (100, 100, 100, 70)]
        commitments, genesis_root = controller.commitments(notes)
        raw_genesis = finalize_fresh_genesis(prefix, commitments)
        genesis = genesis_document(raw_genesis)
        network.install_genesis(raw_genesis)
        network.start_sources()
        report["processes_started"] = True
        report["genesis_sha256"] = genesis.sha256.hex()
        report["profile_id"] = genesis.profile.identity.hex()
        report["deployment_id"] = genesis.deployment.identity.hex()
        report["engine_genesis_sha256"] = hashlib.sha256(
            json.dumps(network.engine_genesis, sort_keys=True,
                       separators=(",", ":")).encode()).hexdigest()

        initial_states = [network.state(index) for index in range(4)]
        validator_set = comet_validator_set(genesis.value["validators"])
        validator_hash = bytes.fromhex(validator_set.hash)
        _check(report, "four-validator-init",
               len({state["app_hash"] for state in initial_states}) == 1
               and all(state["state"]["current_root"] == genesis_root
                       for state in initial_states)
               and all(state["genesis"] == genesis.value for state in initial_states),
               {"height": initial_states[0]["height"],
                "app_hash": initial_states[0]["app_hash"],
                "root": genesis_root})
        powers = [row["power"] for row in genesis.value["validators"]]
        _check(report, "four-equal-power-quorum",
               len(powers) == 4 and len(set(powers)) == 1
               and sum(powers[:3]) * 3 > sum(powers) * 2,
               {"powers": powers, "three_power": sum(powers[:3]),
                "total_power": sum(powers)})

        broad_from, broad_until = 1, 500
        first_outputs = _make_outputs(notes[0], genesis.value["fee"])
        first_request = controller.spend_request(
            raw_genesis, commitments, 0, notes[0], first_outputs,
            valid_from=broad_from, valid_until=broad_until)
        first_a = controller.prove(raw_genesis, first_request)
        first_b = controller.prove(raw_genesis, first_request)
        if first_a == first_b:
            raise AssertionError("development proofs were not randomized")
        admissions, prepared, conflict_status, conflict_checkpoint = (
            _prepare_conflict_below_quorum(
                network, first_a, first_b,
                genesis.value["limits"]["max_block_bytes"], validator_hash))
        _check(report, "randomized-proof-conflict",
               admissions == [0, 0] and prepared == [first_a]
               and conflict_status == 2,
               {"proof_a_sha256": hashlib.sha256(first_a).hexdigest(),
                "proof_b_sha256": hashlib.sha256(first_b).hexdigest(),
                "prepared_count": len(prepared),
                "conflict_process_status": conflict_status,
                "proposal_height": conflict_checkpoint["height"] + 1})
        network.stage_without_quorum([first_a])
        states = _wait_accepted(network, 1)
        winning = states[0]["state"]["receipts"][-1]
        _check(report, "actual-proof-commit",
               all(state["app_hash"] == states[0]["app_hash"] for state in states)
               and winning["txid"]
               == hashlib.sha256(
                   b"1soft/shielded-txid/v1\0" + first_a).hexdigest(),
               {"height": winning["height"], "txid": winning["txid"],
                "app_hash": states[0]["app_hash"]})
        report["actual_proof_accepted"] = True
        _check(report, "post-commit-replay-refusal",
               network.direct_check(0, first_a) == 5
               and network.direct_check(1, first_b) == 5,
               {"result_code": 5})
        notes.extend(first_outputs)
        commitments.extend([
            item.hex() for item in Transaction.decode(first_a, genesis).public_fields[10:12]
        ])
        regenerated, current_root = controller.commitments(notes)
        if regenerated != commitments or current_root != states[0]["state"]["current_root"]:
            raise AssertionError("Rust client and committed tree diverged")

        # Existing-output reuse is rejected before proof verification.
        across_request = controller.spend_request(
            raw_genesis, commitments, 1, notes[1], first_outputs,
            valid_from=broad_from, valid_until=broad_until)
        across = controller.prove(raw_genesis, across_request)
        existing_output_refused = network.direct_check(0, across) == 6

        shared_outputs = _make_outputs(notes[1], genesis.value["fee"])
        within_a = controller.prove(raw_genesis, controller.spend_request(
            raw_genesis, commitments, 1, notes[1], shared_outputs,
            valid_from=broad_from, valid_until=broad_until))
        within_b = controller.prove(raw_genesis, controller.spend_request(
            raw_genesis, commitments, 2, notes[2], shared_outputs,
            valid_from=broad_from, valid_until=broad_until))
        within_status, _ = _process_probe_at_held_height(
            network, [within_a, within_b], validator_hash)
        within_refused = within_status == 2
        _check(report, "global-nullifier-output-uniqueness",
               existing_output_refused and within_refused,
               {"existing_output_result": 6, "within_block_status": 2})

        outputs_one = _make_outputs(notes[1], genesis.value["fee"])
        outputs_two = _make_outputs(notes[2], genesis.value["fee"])
        same_root_one = controller.prove(raw_genesis, controller.spend_request(
            raw_genesis, commitments, 1, notes[1], outputs_one,
            valid_from=broad_from, valid_until=broad_until))
        same_root_two = controller.prove(raw_genesis, controller.spend_request(
            raw_genesis, commitments, 2, notes[2], outputs_two,
            valid_from=broad_from, valid_until=broad_until))
        same_admissions, staged_checkpoint = network.stage_without_quorum(
            [same_root_one, same_root_two])
        states = _wait_accepted(network, 3)
        recent = states[0]["state"]["receipts"][-2:]
        same_height = recent[0]["height"] == recent[1]["height"]
        same_anchor = recent[0]["anchor_root"] == recent[1]["anchor_root"]
        sequential = (
            recent[1]["output_position_0"]
            == recent[0]["output_position_1"] + 1)
        _check(report, "same-root-sequential-appends",
               same_height and same_anchor and sequential,
               {"height": recent[0]["height"],
                "staged_from_height": staged_checkpoint["height"],
                "admission_codes": [int(row["code"]) for row in same_admissions],
                "anchor_root": recent[0]["anchor_root"],
                "positions": [recent[0]["output_position_0"],
                              recent[1]["output_position_1"]]})
        staged = {
            hashlib.sha256(b"1soft/shielded-txid/v1\0" + transaction).hexdigest():
            (transaction, outputs)
            for transaction, outputs in (
                (same_root_one, outputs_one), (same_root_two, outputs_two))
        }
        if [row["txid"] for row in recent] != list(staged):
            if set(row["txid"] for row in recent) != set(staged):
                raise AssertionError("same-root committed transaction set differs")
        for row in recent:
            transaction, outputs = staged[row["txid"]]
            decoded = Transaction.decode(transaction, genesis)
            notes.extend(outputs)
            commitments.extend(item.hex() for item in decoded.public_fields[10:12])
        regenerated, current_root = controller.commitments(notes)
        if regenerated != commitments or current_root != states[0]["state"]["current_root"]:
            raise AssertionError("same-root append projection differs")

        producer_outputs = _make_outputs(notes[3], genesis.value["fee"])
        producer = controller.prove(raw_genesis, controller.spend_request(
            raw_genesis, commitments, 3, notes[3], producer_outputs,
            valid_from=broad_from, valid_until=broad_until))
        producer_decoded = Transaction.decode(producer, genesis)
        hypothetical_notes = notes + list(producer_outputs)
        hypothetical_commitments, _ = controller.commitments(hypothetical_notes)
        chained_outputs = _make_outputs(
            producer_outputs[0], genesis.value["fee"])
        chained = controller.prove(raw_genesis, controller.spend_request(
            raw_genesis, hypothetical_commitments, len(commitments),
            producer_outputs[0], chained_outputs,
            valid_from=broad_from, valid_until=broad_until))
        frozen_status, _ = _process_probe_at_held_height(
            network, [producer, chained], validator_hash)
        frozen_refusal = frozen_status == 2
        if int(network.broadcast(0, producer)["code"]) != 0:
            raise AssertionError("producer transaction was not admitted")
        states = _wait_accepted(network, 4)
        notes = hypothetical_notes
        commitments = hypothetical_commitments
        if int(network.broadcast(0, chained)["code"]) != 0:
            raise AssertionError("post-commit chained transaction was not admitted")
        states = _wait_accepted(network, 5)
        notes.extend(chained_outputs)
        commitments.extend(
            item.hex() for item in Transaction.decode(chained, genesis).public_fields[10:12])
        regenerated, current_root = controller.commitments(notes)
        _check(report, "same-block-root-freeze",
               frozen_refusal and regenerated == commitments
               and current_root == states[0]["state"]["current_root"],
               {"same_block_status": 2,
                "eligible_height": states[0]["state"]["receipts"][-1]["height"]})

        # A valid proof for a different tree is an unknown anchor; direct field
        # tampering is rejected at the same earlier boundary without mutation.
        alternative_notes = list(notes)
        alternative_notes[0] = development_note(512, notes[0].value)
        alternative_commitments, _ = controller.commitments(alternative_notes)
        unknown_outputs = _make_outputs(notes[5], genesis.value["fee"])
        unknown = controller.prove(raw_genesis, controller.spend_request(
            raw_genesis, alternative_commitments, 5, notes[5], unknown_outputs,
            valid_from=broad_from, valid_until=broad_until))
        tampered_root = bytearray(Transaction.decode(unknown, genesis).public_fields[8])
        tampered_root[0] ^= 1
        tampered = _field_mutation(unknown, 8, bytes(tampered_root))
        refusal_codes, before_check, after_check = _check_tx_at_held_state(
            network, [unknown, tampered])
        _check(report, "unknown-root-refusal",
               refusal_codes == [4, 4] and after_check == before_check,
               {"unknown_code": refusal_codes[0],
                "tampered_code": refusal_codes[1],
                "held_height": before_check["height"],
                "held_app_hash": before_check["app_hash"]})

        recovery_outputs = _make_outputs(notes[4], genesis.value["fee"])
        recovery_transaction = controller.prove(
            raw_genesis, controller.spend_request(
                raw_genesis, commitments, 4, notes[4], recovery_outputs,
                valid_from=broad_from, valid_until=broad_until))

        wrong_deployment = bytearray(recovery_transaction)
        wrong_deployment[48] ^= 1
        wrong_fee = _field_mutation(
            recovery_transaction, 12,
            (genesis.value["fee"] + 1).to_bytes(32, "little"))
        bad_proof = bytearray(recovery_transaction)
        bad_proof[-1] ^= 1
        wrong_hash_status, _ = _process_probe_at_held_height(
            network, [], b"\0" * 32)
        _check(report, "identity-proof-validator-hash-faults",
               network.direct_check(0, bytes(wrong_deployment)) == 2
               and network.direct_check(0, wrong_fee) == 8
               and network.direct_check(0, bytes(bad_proof)) == 9
               and wrong_hash_status == 2,
               {"identity": 2, "statement": 8, "proof": 9,
                "proposal_status": wrong_hash_status})

        # Controlled empty blocks give recovery cases a source checkpoint to
        # catch up to without consuming the final spend or changing roots.
        network.set_empty_blocks(True)
        recovery_base = max(network.height(index) for index in range(4))
        wait_until(lambda: min(network.height(index) for index in range(4))
                   >= recovery_base + 2, 60)
        certificate_witness = network.state(0)
        certificate_height = certificate_witness["height"]
        wait_until(lambda: network.height(0) >= certificate_height + 1, 30)
        signed_header = rpc(network.http[0], "commit", {
            "height": str(certificate_height + 1)})["signed_header"]
        trust = trust_from_protocol5_genesis(
            network.engine_genesis, raw_genesis)
        certificate = verify_protocol5_state_certificate(
            certificate_witness, signed_header, trust)
        _check(report, "signed-next-header",
               certificate["state_height"] == certificate_height
               and certificate["app_hash"] == certificate_witness["app_hash"],
               {"state_height": certificate_height,
                "header_height": certificate["header_height"],
                "app_hash": certificate["app_hash"]})

        failure_evidence = []
        # Stall one exact worker after successful traffic. The request watchdog
        # quarantines the app; the remaining three validators advance.
        stalled_height = network.state(1)["height"]
        network.stop_engine(1)
        stalled_pid = network.worker_pid(1)
        os.kill(stalled_pid, signal.SIGSTOP)
        try:
            network.direct_check(1, recovery_transaction)
            raise AssertionError("stalled worker returned an ABCI response")
        except (OSError, RuntimeError, TimeoutError):
            pass
        wait_until(lambda: network.apps[1].poll() is not None, 15)
        network.stop_app(1)
        wait_until(lambda: min(
            network.height(index) for index in (0, 2, 3)) >= stalled_height + 1, 30)
        advanced = min(network.height(index) for index in (0, 2, 3))
        network.start_app(1)
        network.start_engine(1)
        wait_until(lambda: _engine_consensus_ready(network, 1, advanced), 60)
        failure_evidence.append({
            "kind": "stall", "node": 1, "worker_pid": stalled_pid,
            "height_before": stalled_height, "height_after": network.height(1)})

        # Kill a second exact worker and require the same durable-state recovery.
        killed_height = network.state(2)["height"]
        network.stop_engine(2)
        killed_pid = network.worker_pid(2)
        os.kill(killed_pid, signal.SIGKILL)
        try:
            network.direct_check(2, recovery_transaction)
            raise AssertionError("killed worker returned an ABCI response")
        except (OSError, RuntimeError, TimeoutError):
            pass
        wait_until(lambda: network.apps[2].poll() is not None, 15)
        network.stop_app(2)
        wait_until(lambda: min(
            network.height(index) for index in (0, 1, 3)) >= killed_height + 1, 30)
        advanced = min(network.height(index) for index in (0, 1, 3))
        network.start_app(2)
        network.start_engine(2)
        wait_until(lambda: _engine_consensus_ready(network, 2, advanced), 60)
        failure_evidence.append({
            "kind": "kill", "node": 2, "worker_pid": killed_pid,
            "height_before": killed_height, "height_after": network.height(2)})
        _check(report, "worker-kill-stall",
               all(network.state(index)["state"]["accepted_transaction_count"] == 5
                   for index in range(4)),
               {"recoveries": failure_evidence})

        crash_evidence = []
        for phase, exit_code in (("before_commit", 94), ("after_commit", 95)):
            node = 0
            network.stop_engine(node)
            network.stop_app(node)
            db = network.runtime / f"app{node}/state.sqlite"
            with sqlite3.connect(db) as connection:
                durable_before = connection.execute(
                    "SELECT height FROM committed WHERE id=1").fetchone()[0]
            token = os.urandom(32).hex()
            network.start_app(node, crash={
                "run_token": token,
                "run_token_sha256": hashlib.sha256(token.encode("ascii")).hexdigest(),
                "crash_phase": phase,
            })
            network.start_engine(node)
            wait_until(lambda: network.apps[node].poll() is not None, 30)
            observed_exit = network.apps[node].returncode
            network.stop_engine(node)
            network.stop_app(node)
            with sqlite3.connect(db) as connection:
                durable_after = connection.execute(
                    "SELECT height FROM committed WHERE id=1").fetchone()[0]
            if (observed_exit != exit_code
                    or (phase == "before_commit" and durable_after != durable_before)
                    or (phase == "after_commit" and durable_after <= durable_before)):
                raise AssertionError("Protocol 5 crash boundary differs")
            network.start_app(node)
            network.start_engine(node)
            target_height = max(network.height(index) for index in (1, 2, 3))
            wait_until(lambda: _engine_consensus_ready(network, node, target_height), 60)
            crash_evidence.append({
                "phase": phase, "exit_code": observed_exit,
                "durable_before": durable_before, "durable_after": durable_after,
                "recovered_height": network.height(node),
            })
        _check(report, "atomic-commit-faults", True,
               {"crashes": crash_evidence})

        restart_height = network.state(3)["height"]
        network.stop_node(3)
        network.start_app(3)
        network.start_engine(3)
        target_height = max(network.height(index) for index in (0, 1, 2))
        wait_until(lambda: network.height(3) >= target_height, 60)
        _check(report, "application-engine-restart",
               network.state(3)["state"]["accepted_transaction_count"] == 5,
               {"height_before": restart_height,
                "height_after": network.state(3)["height"]})
        _check(report, "worker-sandbox-probes",
               all(len(_children(network.apps[index].pid)) == 1
                   for index in range(4)),
               {"startup_contract":
                "worker self-test, KAT, confinement probes and framed stdout required"})

        # Stop producing empty proposals before holding quorum. Otherwise a
        # pending empty proposal can consume this exact one-height validity
        # interval when the third validator returns, even though both live
        # mempools already contain the transaction.
        # Hold two validators below quorum while constructing and staging the
        # exact one-height validity case. Starting validator 2 releases exactly
        # the three-validator quorum; validator 3 remains stopped.
        held = _hold_transaction_height(network)
        boundary_height = held["height"] + 1
        boundary_outputs = _make_outputs(notes[4], genesis.value["fee"])
        boundary = controller.prove(raw_genesis, controller.spend_request(
            raw_genesis, commitments, 4, notes[4], boundary_outputs,
            valid_from=boundary_height, valid_until=boundary_height + 1))
        if network.direct_check(0, boundary) != 0:
            raise AssertionError("valid_from boundary was not eligible")
        network.stage_without_quorum([boundary], resume=(2,))
        states = _wait_accepted(network, 6, nodes=(0, 1, 2))
        network.stop_engine(2)
        boundary_receipts = [
            row for row in states[0]["state"]["receipts"]
            if row["txid"] == hashlib.sha256(
                b"1soft/shielded-txid/v1\0" + boundary).hexdigest()]
        _check(report, "three-validator-continuation",
               len(states) == 3 and all(
                   state["state"]["accepted_transaction_count"] == 6
                   for state in states),
               {"height": states[0]["height"], "stopped_node": 3})
        _check(report, "validity-boundaries",
               len(boundary_receipts) == 1
               and boundary_receipts[0]["height"] == boundary_height
               and network.direct_check(0, boundary) == 3,
               {"valid_from": boundary_height,
                "valid_until": boundary_height + 1,
                "committed_height": boundary_receipts[0]["height"],
                "observed_height": network.direct_state(0)["height"],
                "valid_until_code": 3})
        network.start_engine(2)
        network.start_engine(3)
        wait_until(lambda: network.state(3)["height"] >= states[0]["height"], 60)

        private_notes = (notes + list(boundary_outputs) + list(shared_outputs)
                         + list(unknown_outputs) + list(recovery_outputs))
        secret_values = []
        for note in private_notes:
            secret_values.extend((
                note.owner_spend_secret, note.note_secret, note.blinding))
        needles = [str(paths["client"]).encode(), str(paths["prover"]).encode()]
        for secret in secret_values:
            needles.extend((
                secret, secret.hex().encode(), base64.b64encode(secret)))
        inspected = []
        for path in sorted(network.runtime.glob("*.log")):
            inspected.append((path.name, path.read_bytes()))
        for path in sorted(network.runtime.glob("app*/*")):
            if path.is_file() and not path.is_symlink():
                inspected.append((str(path.relative_to(network.runtime)), path.read_bytes()))
        for index, process in list(network.apps.items()) + list(network.engines.items()):
            inspected.append((
                f"process-{process.pid}-cmdline",
                Path(f"/proc/{process.pid}/cmdline").read_bytes()))
        listing = Request()
        listing.list_snapshots.SetInParent()
        snapshots = network.abci(0, listing).list_snapshots.snapshots
        for snapshot in snapshots:
            for chunk_index in range(snapshot.chunks):
                load = Request()
                load.load_snapshot_chunk.height = snapshot.height
                load.load_snapshot_chunk.format = snapshot.format
                load.load_snapshot_chunk.chunk = chunk_index
                inspected.append((
                    f"snapshot-{snapshot.height}-{chunk_index}",
                    bytes(network.abci(0, load).load_snapshot_chunk.chunk)))
        inspected.append((
            "process-receipts",
            json.dumps(network.receipts, sort_keys=True).encode("utf-8")))
        leaks = [name for name, payload in inspected
                 if any(needle and needle in payload for needle in needles)]
        _check(report, "secret-leakage-scan", not leaks,
               {"inspected_objects": len(inspected), "leaks": leaks})
    finally:
        network.close()


def _git(*args):
    return subprocess.check_output(
        ["git", "-C", str(ROOT), *args], text=True, timeout=10).strip()


def _sha(path: Path) -> str:
    with path.open("rb") as handle:
        return hashlib.file_digest(handle, "sha256").hexdigest()


def _write_new(path: Path, value: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("x", encoding="utf-8") as handle:
        json.dump(value, handle, sort_keys=True, indent=2)
        handle.write("\n")
        handle.flush()


def preflight(*, output: str | Path, engine: str | Path, worker: str | Path,
              prover: str | Path, profile: str | Path, kat: str | Path,
              toolchain: str | Path, policy: str | Path, genesis: str | Path,
              client: str | Path | None = None,
              expected_prover_sha256: str | None = None,
              expected_client_sha256: str | None = None,
              profile_name: str = "consensus") -> dict:
    output = Path(output).resolve()
    if output.exists():
        raise FileExistsError("Protocol 5 report path already exists")
    locations = {
        "engine": engine, "worker": worker, "client": client,
        "prover": prover, "profile": profile,
        "kat": kat, "toolchain": toolchain, "policy": policy, "genesis": genesis,
    }
    paths = {name: Path(loc).resolve() for name, loc in locations.items()
             if loc is not None}
    missing = [name for name, loc in locations.items()
               if loc is None or not paths[name].is_file() or paths[name].is_symlink()]
    source_dirty = bool(_git("status", "--porcelain"))
    report = {
        "schema": "1soft-protocol5-engine-preflight-v1",
        "status": "unassessed",
        "profile": profile_name,
        "source_commit": _git("rev-parse", "HEAD"),
        "source_tree": _git("rev-parse", "HEAD^{tree}"),
        "source_dirty": source_dirty,
        "source_dirty_before": source_dirty,
        "engine_required_version": ENGINE_VERSION,
        "engine_required_sha256": ENGINE_SHA256,
        "inputs": {name: str(paths[name]) if name in paths else None
                   for name in INPUT_NAMES},
        "missing_inputs": missing,
        "failures": [],
        "checks": [],
        "processes_started": False,
        "processes": [],
        "state_sync_observed": False,
        "actual_proof_accepted": False,
        "public_network_ready": False,
        "real_funds_ready": False,
        "cryptographic_review_complete": False,
    }
    if missing:
        report["reason"] = "exact Protocol 5 input files unavailable"
        _write_new(output, report)
        return report
    missing_pins = [name for name, value in (
        ("expected_client_sha256", expected_client_sha256),
        ("expected_prover_sha256", expected_prover_sha256),
    ) if value is None]
    if missing_pins:
        report["missing_inputs"].extend(missing_pins)
        report["reason"] = "development controller identity pin unavailable"
        _write_new(output, report)
        return report
    for name, value in (
            ("client", expected_client_sha256), ("prover", expected_prover_sha256)):
        if (type(value) is not str or len(value) != 64
                or any(ch not in "0123456789abcdef" for ch in value)):
            raise ValueError(f"expected {name} SHA-256 must be lowercase hex")
    observed = {name: _sha(path) for name, path in paths.items()}
    report["observed_sha256"] = observed
    if observed["engine"] != ENGINE_SHA256:
        report["failures"].append("engine binary differs")
    try:
        genesis_doc = genesis_document(paths["genesis"].read_bytes())
        if paths["profile"].read_bytes() != genesis_doc.profile.raw:
            report["failures"].append("profile descriptor differs")
        if observed["worker"] != genesis_doc.deployment.worker_sha256.hex():
            report["failures"].append("worker binary differs")
        if observed["toolchain"] != genesis_doc.deployment.toolchain_sha256.hex():
            report["failures"].append("toolchain manifest differs")
        if observed["policy"] != genesis_doc.deployment.sandbox_policy_sha256.hex():
            report["failures"].append("sandbox policy differs")
        kat_identity = hashlib.sha256(
            KAT_DOMAIN + paths["kat"].read_bytes()).hexdigest()
        if kat_identity != genesis_doc.profile.hashes[6].hex():
            report["failures"].append("KAT differs")
        if observed["prover"] != expected_prover_sha256:
            report["failures"].append("development prover differs")
        if observed["client"] != expected_client_sha256:
            report["failures"].append("development client differs")
        report.update(
            genesis_sha256=genesis_doc.sha256.hex(),
            profile_id=genesis_doc.profile.identity.hex(),
            deployment_id=genesis_doc.deployment.identity.hex(),
        )
    except Exception as exc:
        report["failures"].append(
            "genesis or identity graph invalid: " + type(exc).__name__)
    if report["failures"]:
        report["status"] = "failed"
        report["reason"] = "source-bound preflight failed before process launch"
        _write_new(output, report)
        return report
    version = subprocess.check_output(
        [str(paths["engine"]), "version"], text=True, timeout=10).strip()
    if version.lstrip("v") != ENGINE_VERSION:
        report["status"] = "failed"
        report["failures"].append("engine version differs")
        report["reason"] = "source-bound preflight failed before process launch"
    else:
        report["engine_version"] = version
        try:
            if profile_name == "consensus":
                _run_consensus_scenarios(paths, output, report)
            else:
                from run_protocol5_state_sync import run_state_sync_scenarios
                run_state_sync_scenarios(paths, output, report)
            report["source_dirty_after"] = bool(_git("status", "--porcelain"))
            report["source_dirty"] = (
                report["source_dirty_before"] or report["source_dirty_after"])
            if report["source_dirty"]:
                raise RuntimeError("source worktree changed during qualification")
            report["status"] = "completed-awaiting-external-validation"
            report["reason"] = "all source-bound Protocol 5 scenarios completed"
        except BaseException as exc:
            report["status"] = "failed"
            report["failures"].append(type(exc).__name__ + ": " + str(exc))
            report["reason"] = "source-bound Protocol 5 execution failed"
    _write_new(output, report)
    return report


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    for name in INPUT_NAMES:
        parser.add_argument("--" + name, type=Path, required=True)
    parser.add_argument("--expected-prover-sha256")
    parser.add_argument("--expected-client-sha256")
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    report = preflight(
        output=args.output, expected_prover_sha256=args.expected_prover_sha256,
        expected_client_sha256=args.expected_client_sha256,
        **{name: getattr(args, name) for name in INPUT_NAMES})
    return 1 if report["status"] == "failed" else 0


if __name__ == "__main__":
    raise SystemExit(main())
