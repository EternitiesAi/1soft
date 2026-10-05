#!/usr/bin/env python3
"""Source-bound, four-validator synthetic Protocol 5 wallet qualification.

Only an exact clean-source run with the pinned binaries can complete. Unit
fixtures exercise boundaries and are never substituted for missing real inputs.
Private journals and capsules stay in the fresh sibling .private directory.
"""
from __future__ import annotations

import argparse
import base64
import copy
import hashlib
import json
import os
from pathlib import Path
import re
import signal
import selectors
import socket
import sqlite3
import stat
import subprocess
import sys
import threading
import time
from contextlib import closing
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

ROOT = Path(__file__).resolve().parents[1]
sys.path[:0] = [str(ROOT / "src"), str(ROOT / "scripts")]
from protocol5_controller import (
    DevelopmentController, RecipientOutput, SecretNote, random_field,
    _bounded_exchange,
)
from protocol5_encoding import (
    Transaction, canonical_json, decode_canonical_json, derive_genesis_field,
    field_hex, genesis_document, transaction_id,
)
from protocol5_note_capsule import NOTE_CAPSULE_FORMAT, capsule_id, decode_capsule
from protocol5_state_reader import authenticate_observation, read_state_observation
from protocol5_wallet import Protocol5Wallet, _prover_witness
from protocol5_delivery import Protocol5Delivery
from protocol5_abci_wire import Request
from run_devnet import rpc, wait_until
from run_protocol5_engine import (
    INPUT_NAMES, KAT_DOMAIN, Protocol5Network, finalize_fresh_genesis,
    p5_app_command, _start_ticks, _stop,
)

SETTINGS_PATH = ROOT / "reference/protocol5-wallet-qualification-settings-v1.json"
SCHEMA = "1soft-protocol5-wallet-preflight-v1"
SAFE_NAME = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,95}\Z")
CRYPTO_COMMANDS = {"init", "status", "sync", "import-note", "approve",
                   "export-capsule", "delivery-reconcile"}
EXPIRY_WINDOW_BLOCKS = 64
EXPIRY_WAIT_SECONDS = 300

def _sha(path: Path) -> str:
    with path.open("rb") as handle:
        return hashlib.file_digest(handle, "sha256").hexdigest()

def _git(*arguments: str) -> str:
    return subprocess.check_output(
        ["git", "-C", str(ROOT), *arguments], text=True, timeout=10).strip()

def _settings() -> dict:
    return decode_canonical_json(SETTINGS_PATH.read_bytes().removesuffix(b"\n"), max_bytes=65_536)

def _source(settings: dict) -> dict:
    return {name: _sha(ROOT / name) for name in settings["source_files"]
            if (ROOT / name).is_file()}

def _new_output(path: str | Path) -> Path:
    selected = Path(os.path.abspath(path))
    if selected.is_relative_to(ROOT.resolve()):
        raise ValueError("qualification output must be external")
    for parent in (selected.parent, *selected.parent.parents):
        if parent.is_symlink():
            raise ValueError("qualification output has a symlink parent")
    for suffix in ("", ".artifacts", ".private"):
        target = selected.with_name(selected.name + suffix)
        if os.path.lexists(target):
            raise FileExistsError("qualification output is not fresh")
    return selected

def _write_bytes(path: Path, raw: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL
                         | getattr(os, "O_NOFOLLOW", 0), 0o600)
    try:
        with os.fdopen(descriptor, "wb") as handle:
            handle.write(raw)
            handle.flush()
            os.fsync(handle.fileno())
    except BaseException:
        raise

def _write_json(path: Path, value: object) -> None:
    _write_bytes(path, canonical_json(value) + b"\n")

def validator_command(paths: dict, genesis: Path, digest: str,
                      database: Path, address: Path) -> list[str]:
    return p5_app_command(paths, genesis, digest, database, address)

def stop_owned(process: subprocess.Popen | None) -> int | None:
    return _stop(process)

def scan_objects(objects: list[tuple[str, bytes]], secrets: list[bytes],
                 *, forbidden: list[bytes] = ()) -> dict:
    needles = list(forbidden)
    for secret in secrets:
        if type(secret) is not bytes or not secret:
            raise ValueError("invalid private scan material")
        needles.extend((secret, secret.hex().encode(), base64.b64encode(secret),
                        str(int.from_bytes(secret, "little")).encode()))
    matches = sum(any(needle and needle in raw for needle in needles)
                  for _name, raw in objects)
    return {"objects": len(objects), "bytes": sum(len(raw) for _, raw in objects),
            "matches": matches}

def journal_manifest(path: Path, name: str, status: dict) -> dict:
    with closing(sqlite3.connect(f"file:{path}?mode=ro", uri=True)) as connection:
        schema = {name: sql for name, sql in connection.execute(
            "SELECT name,sql FROM sqlite_master WHERE type='table' "
            "AND name NOT LIKE 'sqlite_%' ORDER BY name")}
        if connection.execute("PRAGMA integrity_check").fetchone() != ("ok",):
            raise RuntimeError("private journal integrity differs")
    return {"name": name, "sha256": _sha(path), "bytes": path.stat().st_size,
            "schema_sha256": hashlib.sha256(canonical_json(schema)).hexdigest(),
            "status": status}

def _changed_hex(value: str) -> str:
    raw = bytearray.fromhex(value)
    raw[0] ^= 1
    if not any(raw):
        raw[0] = 2
    return raw.hex()


def qualification_valid_until(maximum_height: int, current_height: int) -> int:
    """Keep ordinary qualification transfers live through the finite run.

    Protocol 5 binds the current height into each app hash, so a local CometBFT
    network can continue advancing even when ordinary empty-block production is
    disabled.  Only the dedicated expiry scenario intentionally uses a short
    validity window.
    """
    if (type(maximum_height) is not int or type(current_height) is not int
            or current_height < 0 or maximum_height <= current_height):
        raise ValueError("qualification validity window is unavailable")
    return maximum_height


def same_nullifier_conflict(original: tuple[bytes, ...],
                            winner: tuple[bytes, ...]) -> bool:
    """Recognize a different authorized statement for one spent input."""
    return (
        len(original) == 14
        and len(winner) == 14
        and original[:10] == winner[:10]
        and original[10:12] != winner[10:12]
        and original[12] == winner[12]
        and original[13] != winner[13]
    )


def qualification_expiry_until(maximum_height: int,
                               current_height: int) -> int:
    """Reserve enough blocks for a real proof before crossing expiry."""
    if (type(maximum_height) is not int or type(current_height) is not int
            or current_height < 0
            or current_height + EXPIRY_WINDOW_BLOCKS > maximum_height):
        raise ValueError("qualification expiry window is unavailable")
    return current_height + EXPIRY_WINDOW_BLOCKS

def capsule_mutations(raw: bytes) -> dict[str, bytes]:
    original = decode_canonical_json(raw)
    variants = {}
    for name in original:
        value = copy.deepcopy(original)
        if name == "capsule_id":
            value[name] = _changed_hex(value[name])
        elif name in ("version", "expiry", "value"):
            value[name] += 1
        elif name == "format":
            value[name] += "/wrong"
        elif name == "origin":
            value[name] = {"kind": "genesis", "position": 0}
        else:
            value[name] = _changed_hex(value[name])
        if name != "capsule_id":
            value["capsule_id"] = capsule_id(value)
        variants[name] = canonical_json(value)
    for name, replacement in (
            ("kind", "wrong"), ("txid", _changed_hex(original["origin"]["txid"])),
            ("output_index", 1)):
        value = copy.deepcopy(original)
        value["origin"][name] = replacement
        value["capsule_id"] = capsule_id(value)
        variants["origin." + name] = canonical_json(value)
    wrong = copy.deepcopy(original)
    wrong["origin"]["output_index"] = 1
    wrong["capsule_id"] = capsule_id(wrong)
    variants["wrong-position"] = canonical_json(wrong)
    extra = copy.deepcopy(original)
    extra["unexpected"] = True
    variants["unknown-key"] = canonical_json(extra)
    variants["duplicate-key"] = b'{"version":1,' + raw[1:]
    variants["oversize"] = raw + b" " * 2049
    variants["noncanonical"] = raw + b"\n"
    return variants


def certificate_mutations(raw: bytes) -> dict[str, bytes]:
    """Malformed certificates; authentic rollback/fork/revision are separate."""
    original = decode_canonical_json(raw)
    changes = {}
    def changed(name, operation):
        value = copy.deepcopy(original)
        operation(value)
        changes[name] = canonical_json(value)
    changed("state", lambda v: v["state_witness"]["state"]["commitments"].pop())
    changed("receipt", lambda v: v["state_witness"]["state"]["receipts"][0].update(fee=6))
    def transaction(v):
        blocks = v["state_witness"]["state"]["execution_blocks"]
        block = next(row for row in blocks if row["transactions"])
        encoded = bytearray(base64.b64decode(block["transactions"][0]))
        encoded[-1] ^= 1
        block["transactions"][0] = base64.b64encode(encoded).decode()
    changed("transaction", transaction)
    changed("app_hash", lambda v: v["state_witness"].update(
        app_hash=_changed_hex(v["state_witness"]["app_hash"])))
    changed("header", lambda v: v["signed_header"]["header"].update(
        data_hash=_changed_hex(v["signed_header"]["header"]["data_hash"])))
    def signature(v):
        row = next(row for row in v["signed_header"]["commit"]["signatures"]
                   if row["signature"])
        value = bytearray(base64.b64decode(row["signature"]))
        value[0] ^= 1
        row["signature"] = base64.b64encode(value).decode()
    changed("signature", signature)
    changed("validator", lambda v: v["signed_header"]["header"].update(
        validators_hash=_changed_hex(v["signed_header"]["header"]["validators_hash"])))
    changed("chain", lambda v: v["signed_header"]["header"].update(
        chain_id=v["signed_header"]["header"]["chain_id"]+"-wrong"))
    changed("height", lambda v: v["signed_header"]["header"].update(
        height=str(int(v["signed_header"]["header"]["height"])+1)))
    changed("genesis", lambda v: v["state_witness"]["genesis"].update(
        chain_id=v["state_witness"]["genesis"]["chain_id"]+"-wrong"))
    for name in ("profile", "deployment"):
        key = name+"_id"
        changed(name, lambda v, key=key: v["state_witness"]["state"].update(
            {key: _changed_hex(v["state_witness"]["state"][key])}))
    changed("unsigned", lambda v: v["signed_header"]["commit"].update(signatures=[]))
    return changes



def _base_report(settings: dict) -> dict:
    dirty = bool(_git("status", "--porcelain"))
    return {
        "schema": SCHEMA, "status": "unassessed",
        "source_commit": _git("rev-parse", "HEAD"),
        "source_tree": _git("rev-parse", "HEAD^{tree}"),
        "source_dirty_before": dirty, "source_dirty_after": dirty,
        "source_files": _source(settings), "settings_sha256": _sha(SETTINGS_PATH),
        "engine_version": None,
        "inputs": {name: None for name in INPUT_NAMES},
        "expected_sha256": {"client": None, "prover": None},
        "genesis_sha256": None, "profile_id": None, "deployment_id": None,
        "missing_inputs": [], "failures": [], "checks": [],
        "processes_started": False, "actual_proof_accepted": False,
        "processes": [], "wallet_manifests": [], "delivery_manifests": [],
        "artifacts": [],
        "claims": {name: False for name in settings["claims_false"]},
    }

def _input_path(value: str | Path) -> Path:
    path = Path(os.path.abspath(value))
    for parent in (path.parent, *path.parent.parents):
        if parent.is_symlink():
            raise ValueError("unsafe qualification input")
    metadata = path.lstat()
    if not stat.S_ISREG(metadata.st_mode) or metadata.st_mode & 0o022:
        raise ValueError("unsafe qualification input")
    return path

def preflight(*, output: str | Path,
              expected_client_sha256: str | None = None,
              expected_prover_sha256: str | None = None,
              **locations) -> dict:
    selected = _new_output(output)
    settings = _settings()
    report = _base_report(settings)
    paths = {}
    for name in INPUT_NAMES:
        value = locations.get(name)
        if value is None or not os.path.lexists(value):
            report["missing_inputs"].append(name)
            continue
        try:
            paths[name] = _input_path(value)
            basename = paths[name].name
            if SAFE_NAME.fullmatch(basename) is None:
                raise ValueError("unsafe input name")
            report["inputs"][name] = {
                "name": basename, "sha256": _sha(paths[name]),
                "bytes": paths[name].stat().st_size}
        except (OSError, ValueError):
            report["failures"].append("unsafe " + name + " input")
    for name, value in (("client", expected_client_sha256),
                        ("prover", expected_prover_sha256)):
        if value is None:
            report["missing_inputs"].append("expected_" + name + "_sha256")
        elif (type(value) is not str or len(value) != 64
              or any(character not in "0123456789abcdef" for character in value)):
            report["failures"].append("invalid " + name + " identity pin")
        else:
            report["expected_sha256"][name] = value
    # Include both absent pins together when all files are available.
    if all(name in paths for name in INPUT_NAMES):
        report["missing_inputs"] = [
            "expected_" + name + "_sha256"
            for name, value in (("client", expected_client_sha256),
                               ("prover", expected_prover_sha256)) if value is None]
    if report["failures"]:
        report["status"] = "failed"
    elif report["missing_inputs"]:
        _write_json(selected, report)
        return report
    else:
        observed = {name: row["sha256"] for name, row in report["inputs"].items()}
        if observed["engine"] != settings["engine_sha256"]:
            report["failures"].append("engine binary differs")
        for name in ("client", "prover"):
            if observed[name] != report["expected_sha256"][name]:
                report["failures"].append("development " + name + " differs")
        try:
            genesis = genesis_document(paths["genesis"].read_bytes())
            if genesis.value["initial_commitments"]:
                report["failures"].append("genesis template is not empty")
            if genesis.value["fee"] != 5:
                report["failures"].append("qualification fee differs")
            if paths["profile"].read_bytes() != genesis.profile.raw:
                report["failures"].append("profile descriptor differs")
            if genesis.profile.identity.hex() != settings["profile_id"]:
                report["failures"].append("profile identity differs")
            if genesis.deployment.identity.hex() != settings["deployment_id"]:
                report["failures"].append("deployment identity differs")
            for name, digest in (
                    ("worker", genesis.deployment.worker_sha256.hex()),
                    ("toolchain", genesis.deployment.toolchain_sha256.hex()),
                    ("policy", genesis.deployment.sandbox_policy_sha256.hex())):
                if observed[name] != digest:
                    report["failures"].append(name + " identity differs")
            if hashlib.sha256(KAT_DOMAIN + paths["kat"].read_bytes()).digest() != genesis.profile.hashes[6]:
                report["failures"].append("KAT identity differs")
        except (ValueError, OSError):
            report["failures"].append("invalid qualification identity graph")
        if report["source_dirty_before"]:
            report["failures"].append("source worktree is dirty")
        if set(report["source_files"]) != set(settings["source_files"]):
            report["failures"].append("qualification source is incomplete")
        if not report["failures"]:
            try:
                version = subprocess.check_output(
                    [str(paths["engine"]), "version"], text=True, timeout=10).strip()
                if version.lstrip("v") != settings["engine_version"]:
                    raise ValueError("engine version differs")
                report["engine_version"] = version.lstrip("v")
                run_wallet_scenarios(paths, selected, report, settings)
                report["source_dirty_after"] = bool(_git("status", "--porcelain"))
                if (report["source_dirty_after"] or
                        _source(settings) != report["source_files"]):
                    raise RuntimeError("qualification source changed")
                report["status"] = "completed-awaiting-external-validation"
            except BaseException as error:
                report["failures"].append("wallet execution failed: " + type(error).__name__)
        if report["failures"]:
            report["status"] = "failed"
    report["source_dirty_after"] = bool(_git("status", "--porcelain"))
    _write_json(selected, report)
    return report


# This child launcher changes only named durable fault seams. It does not change
# proof bytes, verification, certificate trust, transaction fields, or transport.
CHILD_CODE = r"""
import base64, json, os, pathlib, runpy, socket, subprocess, sys
receipt_file, snapshot_file, request_dir, fault, cli = sys.argv[1:6]
sys.path[:0] = [str(pathlib.Path(cli).parents[1] / "src"),
                str(pathlib.Path(cli).parent)]
import protocol5_controller as controller
import protocol5_wallet as wallet
import protocol5_delivery as delivery

def append(path, value):
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_APPEND | os.O_NOFOLLOW, 0o600)
    try:
        os.write(fd, (json.dumps(value, sort_keys=True, separators=(",",":")) + "\n").encode())
        os.fsync(fd)
    finally:
        os.close(fd)

real_popen = subprocess.Popen
def observed_popen(*args, **kwargs):
    process = real_popen(*args, **kwargs)
    values = {}
    for name in ("cmdline", "environ"):
        try:
            values[name] = base64.b64encode(
                pathlib.Path("/proc", str(process.pid), name).read_bytes()).decode()
        except FileNotFoundError:
            values[name] = ""
    # Actual launch arguments/environment also cover children that exit before
    # /proc can be read. No request stdin is recorded in these public surfaces.
    values["launch_argv"] = base64.b64encode(
        b"\0".join(os.fsencode(item) for item in args[0])).decode()
    values["launch_environ"] = base64.b64encode(
        b"\0".join((key+"="+value).encode()
                   for key,value in sorted(kwargs.get("env", {}).items()))).decode()
    append(snapshot_file, values)
    return process
subprocess.Popen = observed_popen
real_run = controller.DevelopmentController._run
counter = 0
def observed_run(self, role, binary, request, **kwargs):
    global counter
    if role == "development-prover":
        counter += 1
        path = pathlib.Path(request_dir) / (str(os.getpid())+"-"+str(counter)+".bin")
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
        try:
            os.write(fd, request)
            os.fsync(fd)
        finally:
            os.close(fd)
    before = len(self.receipts)
    try:
        return real_run(self, role, binary, request, **kwargs)
    finally:
        for value in self.receipts[before:]:
            append(receipt_file, value)
controller.DevelopmentController._run = observed_run
if fault == "before-commit":
    original_seal = wallet.Protocol5Wallet._seal
    def seal(self):
        original_seal(self)
        if self.db.execute("SELECT COUNT(*) FROM decisions").fetchone()[0]:
            os._exit(72)
    wallet.Protocol5Wallet._seal = seal
elif fault == "after-commit":
    wallet.Protocol5Wallet._approval_committed = lambda self, decision: os._exit(73)
elif fault == "after-claim":
    delivery.Protocol5Delivery._dispatch_guard = lambda self, decision: os._exit(74)
elif fault == "after-sync":
    delivery.Protocol5Delivery._reconcile_guard = lambda self, *args: os._exit(75)
elif fault == "no-network":
    def forbidden_socket(*args, **kwargs):
        raise RuntimeError("structural restart attempted network I/O")
    socket.socket = forbidden_socket
elif fault:
    raise SystemExit(76)
sys.argv = [cli, *sys.argv[6:]]
runpy.run_path(cli, run_name="__main__")
"""


def _wallet_exchange(process: subprocess.Popen, request: bytearray,
                     timeout: float) -> tuple[bytes, bytes]:
    """Concurrent capture with an elapsed deadline, including empty stdin."""
    deadline = time.monotonic() + timeout
    selector = selectors.DefaultSelector()
    buffers = {"stdout": bytearray(), "stderr": bytearray()}
    offset = 0
    streams = {"stdin": process.stdin, "stdout": process.stdout, "stderr": process.stderr}
    for name, stream in streams.items():
        os.set_blocking(stream.fileno(), False)
        if name == "stdin" and not request:
            stream.close()
            continue
        selector.register(stream, selectors.EVENT_WRITE if name == "stdin" else selectors.EVENT_READ, name)
    try:
        while selector.get_map():
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise TimeoutError("wallet caller exceeded watchdog")
            events = selector.select(remaining)
            if not events:
                raise TimeoutError("wallet caller exceeded watchdog")
            for key, _ in events:
                stream, name = key.fileobj, key.data
                if name == "stdin":
                    try:
                        count = os.write(stream.fileno(), memoryview(request)[offset:])
                    except BrokenPipeError:
                        count = len(request) - offset
                    if count <= 0:
                        raise RuntimeError("wallet stdin stalled")
                    offset += count
                    if offset == len(request):
                        selector.unregister(stream)
                        stream.close()
                else:
                    limit = 1_048_576 if name == "stdout" else 65_536
                    chunk = os.read(stream.fileno(), min(65_536, limit+1-len(buffers[name])))
                    if not chunk:
                        selector.unregister(stream)
                        stream.close()
                    else:
                        buffers[name].extend(chunk)
                        if len(buffers[name]) > limit:
                            raise RuntimeError("wallet child output exceeded bound")
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise TimeoutError("wallet caller exceeded watchdog")
        process.wait(timeout=remaining)
        return bytes(buffers["stdout"]), bytes(buffers["stderr"])
    finally:
        selector.close()
        for stream in streams.values():
            if not stream.closed:
                stream.close()



class WalletProcesses:
    """Actual CLI callers with private stdin and measured child exits."""
    def __init__(self, paths: dict, runtime: Path, app_genesis: Path,
                 engine_genesis: dict, pins: dict, receipts: list):
        self.paths, self.runtime, self.app_genesis = paths, runtime, app_genesis
        self.pins, self.receipts = pins, receipts
        self.engine_file = runtime / "wallet-engine-genesis.json"
        _write_bytes(self.engine_file, canonical_json(engine_genesis))
        self.app_hash = _sha(app_genesis)
        self.engine_hash = _sha(self.engine_file)
        self.receipt_file = runtime / "wallet-controller-receipts.jsonl"
        self.snapshot_file = runtime / "wallet-process-snapshots.jsonl"
        self.request_dir = runtime / "prover-requests"
        self.request_dir.mkdir(mode=0o700)
        self.seen_receipts = 0
        self.outputs = []
        self.launches = []
        self.env = {"PATH": "/usr/bin:/bin", "LC_ALL": "C",
                    "PYTHONPATH": os.pathsep.join(str(ROOT/name) for name in ("src", "scripts")),
                    "PYTHONDONTWRITEBYTECODE": "1"}

    def call(self, owner: str, operation: str, *arguments,
             payload: dict | bytes | None = None, fault: str = "",
             expected_code: int = 0, timeout: float = 650.0) -> dict | None:
        command = [operation, "--wallet", str(self.runtime / (owner + ".sqlite")),
                   "--app-genesis", str(self.app_genesis),
                   "--app-genesis-sha256", self.app_hash,
                   "--engine-genesis", str(self.engine_file),
                   "--engine-genesis-sha256", self.engine_hash]
        if operation in CRYPTO_COMMANDS:
            for role in ("client", "prover"):
                command += ["--"+role, str(self.paths[role]),
                            "--"+role+"-sha256", self.pins[role]]
        command.extend(map(str, arguments))
        launch = [sys.executable, "-B", "-c", CHILD_CODE, str(self.receipt_file),
                  str(self.snapshot_file), str(self.request_dir), fault,
                  str(ROOT / "scripts/protocol5_wallet.py"), *command]
        raw = bytearray(payload if type(payload) is bytes else
                        b"" if payload is None else canonical_json(payload))
        process = None
        role = {"before-commit": "wallet-approval-before-commit",
                "after-commit": "wallet-approval-lost-return",
                "after-claim": "wallet-delivery-after-claim",
                "after-sync": "wallet-delivery-after-sync"}.get(fault, "wallet")
        if expected_code == 2:
            role = "wallet-refusal"
        receipt = None
        try:
            process = subprocess.Popen(
                launch, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                stderr=subprocess.PIPE, env=self.env, cwd=ROOT)
            receipt = {"role": role, "node": None, "pid": process.pid,
                       "start_ticks": _start_ticks(process.pid),
                       "executable_sha256": _sha(Path(sys.executable).resolve())}
            self.launches.append((b"\0".join(os.fsencode(item) for item in launch),
                                  b"\0".join((key+"="+value).encode()
                                             for key,value in sorted(self.env.items()))))
            output, error = _wallet_exchange(process, raw, timeout)
            receipt.update(exit_code=process.returncode, terminated=True,
                           stdout_sha256=hashlib.sha256(output).hexdigest(),
                           stderr_sha256=hashlib.sha256(error).hexdigest())
            self.outputs.append((output, error))
            if process.returncode != expected_code:
                raise RuntimeError("wallet child exited unexpectedly")
            if expected_code:
                if output:
                    raise RuntimeError("wallet refusal or crash exposed output")
                return None
            if error:
                raise RuntimeError("wallet child success has stderr")
            value = json.loads(output)
            if type(value) is not dict or output != canonical_json(value)+b"\n":
                raise RuntimeError("wallet child output is not closed canonical JSON")
            return value
        finally:
            raw[:] = b"\0" * len(raw)
            if process is not None and process.poll() is None:
                stop_owned(process)
            if receipt is not None:
                receipt.setdefault("exit_code", process.returncode)
                receipt.setdefault("terminated", process.poll() is not None)
                receipt.setdefault("stdout_sha256", hashlib.sha256(b"").hexdigest())
                receipt.setdefault("stderr_sha256", hashlib.sha256(b"").hexdigest())
                self.receipts.append(receipt)
            if self.receipt_file.exists():
                values = [json.loads(line) for line in self.receipt_file.read_text().splitlines()]
                for value in values[self.seen_receipts:]:
                    value["terminated"] = True
                    self.receipts.append(value)
                self.seen_receipts = len(values)

class DeliveryProxy:
    """One owned loopback forwarding endpoint for measured transport faults."""
    def __init__(self, origin: str):
        from protocol5_transport import _endpoint_port
        self.port = _endpoint_port(origin)
        self.origin = origin
        self.mode = "normal"
        self.requests = 0
        self.forwarded = 0
        self.raw_urls = []
        self.retained_query = None
        self.closed = threading.Event()
        owner = self
        class Handler(BaseHTTPRequestHandler):
            protocol_version = "HTTP/1.1"
            def do_GET(self):
                self.forward()
            def do_POST(self):
                self.forward()
            def forward(self):
                import http.client
                owner.requests += 1
                owner.raw_urls.append(self.path.encode())
                length = int(self.headers.get("Content-Length", "0"))
                if not (self.path == "/" or (self.command == "GET" and (self.path == "/abci_query?path=%22%2Fstate%22&prove=false" or re.fullmatch(r"/commit\?height=[1-9][0-9]*", self.path)))):
                    self.send_error(400)
                    return
                if length > 65_536:
                    self.send_error(413)
                    return
                body = self.rfile.read(length)
                if self.command == "GET" and self.path.startswith("/abci_query?") and owner.retained_query is not None:
                    raw = owner.retained_query
                    self.send_response(200)
                    self.send_header("Content-Type", "application/json")
                    self.send_header("Content-Length", str(len(raw)))
                    self.end_headers()
                    self.wfile.write(raw)
                    return
                mode = owner.mode
                if mode == "timeout" and self.command == "POST":
                    owner.closed.wait(16.0)
                    self.close_connection = True
                    return
                connection = http.client.HTTPConnection("127.0.0.1", owner.port, timeout=15)
                try:
                    headers = {"Content-Type": "application/json"} if body else {}
                    connection.request(self.command, self.path, body=body, headers=headers)
                    response = connection.getresponse()
                    raw = response.read(12_582_913)
                    owner.forwarded += 1
                    if mode == "lost-response" and self.command == "POST":
                        self.close_connection = True
                        return
                    self.send_response(response.status)
                    self.send_header("Content-Type", "application/json")
                    self.send_header("Content-Length", str(len(raw)))
                    self.end_headers()
                    self.wfile.write(raw)
                except (OSError, TimeoutError):
                    self.close_connection = True
                finally:
                    connection.close()
            def log_message(self, *_args):
                pass
        self.server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self.server.daemon_threads = True
        self.endpoint = "http://127.0.0.1:"+str(self.server.server_port)+"/"
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()

    def close(self):
        self.closed.set()
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(timeout=5)
        if self.thread.is_alive():
            raise RuntimeError("owned delivery proxy did not stop")



def journal_rows(path: Path) -> tuple:
    with closing(sqlite3.connect(f"file:{path}?mode=ro", uri=True)) as database:
        return tuple(database.iterdump())

def artifact_manifest(directory: Path, settings: dict) -> list[dict]:
    names = {path.name for path in directory.iterdir()}
    if names != set(settings["artifact_names"]):
        raise ValueError("public artifact closure differs")
    rows = []
    total = 0
    for name in settings["artifact_names"]:
        path = directory / name
        metadata = path.lstat()
        if not stat.S_ISREG(metadata.st_mode) or metadata.st_nlink != 1:
            raise ValueError("unsafe public artifact")
        if metadata.st_size > settings["limits"]["artifact_bytes"]:
            raise ValueError("public artifact exceeds bound")
        total += metadata.st_size
        rows.append({"name": name, "sha256": _sha(path), "bytes": metadata.st_size})
    if total > settings["limits"]["total_artifact_bytes"]:
        raise ValueError("public artifacts exceed total bound")
    return rows

def _same_process(pid: int, ticks: int) -> bool:
    try:
        return _start_ticks(pid) == ticks
    except (FileNotFoundError, ProcessLookupError):
        return False

class WalletNetwork(Protocol5Network):
    """The existing real four-node launcher, retaining this run's private data."""
    def __init__(self, paths, output, report, private: Path):
        # Build the disposable engine tree beside its retained private target.
        # A default /tmp runtime may be a different filesystem, where rename(2)
        # cannot atomically transfer ownership into the evidence directory.
        super().__init__(paths, output, report, include_target=False,
                         runtime_parent=private)
        target = private / "network"
        os.rename(self.runtime, target)
        self.runtime = target
        self.homes = target / "nodes"
        self.genesis_path = target / "protocol5-genesis.json"
        self.process_surfaces = []
        self.snapshot_objects = []
        self.closed = False

    def _record(self, role, index, process, executable_sha256):
        if role == "application":
            executable_sha256 = _sha(Path(f"/proc/{process.pid}/exe").resolve())
        super()._record(role, index, process, executable_sha256)

    def process_snapshot(self):
        for row in self.receipts:
            if row["role"] not in {"engine", "application", "verifier-worker"}:
                continue
            if not _same_process(row["pid"], row["start_ticks"]):
                continue
            values = {}
            for surface in ("cmdline", "environ"):
                values[surface] = Path(f"/proc/{row['pid']}/{surface}").read_bytes()
            self.process_surfaces.append((row["role"], row["node"], values))

    def snapshot_material(self):
        request = Request()
        request.list_snapshots.SetInParent()
        snapshots = self.abci(0, request).list_snapshots.snapshots
        if not snapshots:
            raise RuntimeError("real snapshot evidence unavailable")
        for snapshot in snapshots:
            for chunk in range(snapshot.chunks):
                load = Request()
                load.load_snapshot_chunk.height = snapshot.height
                load.load_snapshot_chunk.format = snapshot.format
                load.load_snapshot_chunk.chunk = chunk
                raw = bytes(self.abci(0, load).load_snapshot_chunk.chunk)
                self.snapshot_objects.append((f"snapshot-{snapshot.height}-{chunk}", raw))

    def close(self):
        if self.closed:
            return
        self.process_snapshot()
        for process in list(self.engines.values()):
            self._record_exit(process.pid, stop_owned(process))
        for process in list(self.apps.values()):
            self._record_exit(process.pid, stop_owned(process))
        for row in self.receipts:
            if row["role"] == "verifier-worker":
                wait_until(lambda row=row: not _same_process(row["pid"], row["start_ticks"]), 15)
                row["exit_code"] = None
            if row["role"] in {"engine", "application", "verifier-worker"}:
                row["terminated"] = not _same_process(row["pid"], row["start_ticks"])
                if not row["terminated"]:
                    raise RuntimeError("owned validator process remains alive")
            else:
                row["terminated"] = True
        for handle in self.handles:
            handle.close()
        # The original temporary path was moved into the owned private sibling.
        self.temp.cleanup()
        self.closed = True

def _origin_response(port: int, path: str) -> bytes:
    import http.client
    connection = http.client.HTTPConnection("127.0.0.1", port, timeout=15)
    try:
        connection.request("GET", path)
        response = connection.getresponse()
        if response.status != 200:
            raise RuntimeError("real state response unavailable")
        raw = response.read(12_582_913)
        if len(raw) > 12_582_912:
            raise RuntimeError("real state response exceeds bound")
        return raw
    finally:
        connection.close()

def collect_retained_observation(network: WalletNetwork, proxies: list[DeliveryProxy],
                                 app_raw: bytes) -> bytes:
    """Freeze an exact real query at H, then obtain the real commit at H+1."""
    checkpoint = network.hold_sources_without_quorum()
    network.retained_app_hashes = [checkpoint["app_hash"]] * 4
    path = "/abci_query?path=%22%2Fstate%22&prove=false"
    raw_response = _origin_response(network.http[0], path)
    response = json.loads(raw_response)["result"]["response"]
    witness_raw = base64.b64decode(response["value"], validate=True)
    witness = decode_canonical_json(witness_raw)
    height = witness["height"]
    if height != checkpoint["height"] or witness["app_hash"] != checkpoint["app_hash"]:
        raise RuntimeError("held real state response differs")
    for proxy in proxies:
        proxy.retained_query = raw_response
    network.set_empty_blocks(True)
    for index in (2, 3):
        if index not in network.engines:
            network.start_engine(index)
    wait_until(lambda: network.height(0) >= height+1, 90)
    network.set_empty_blocks(False)
    # set_empty_blocks restarts every running engine.  Wait for each RPC
    # listener to return before asking the proxy for the retained H/H+1 pair.
    wait_until(lambda: all(
        network.height(index) >= height+1 for index in range(4)), 90)
    raw = read_state_observation(proxies[0].endpoint, network.engine_genesis, app_raw)
    observation, certificate = authenticate_observation(raw, network.engine_genesis, app_raw)
    if certificate["state_height"] != height:
        raise RuntimeError("retained H+1 observation differs")
    return raw

def _authentic_same_height_fork(raw: bytes, network: WalletNetwork) -> bytes:
    """Locally sign a conflicting header with this run's disposable validators.

    This hostile certificate is explicitly constructed locally; primary evidence
    observations continue to contain only the real engine's retained commits.
    """
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    from commit_verifier import header_hash, vote_sign_bytes, sha
    from protocol5_certificate import trust_from_protocol5_genesis
    value = decode_canonical_json(raw)
    trust = trust_from_protocol5_genesis(network.engine_genesis, network.genesis_path.read_bytes())
    keys = {}
    for index in range(4):
        row = json.loads((network.homes/f"node{index}/config/priv_validator_key.json").read_bytes())
        secret = base64.b64decode(row["priv_key"]["value"], validate=True)
        public = base64.b64decode(row["pub_key"]["value"], validate=True)
        keys[sha(public)[:20]] = Ed25519PrivateKey.from_private_bytes(secret[:32])
    signed = value["signed_header"]
    header, commit = signed["header"], signed["commit"]
    header["data_hash"] = _changed_hex(header["data_hash"].lower()).upper()
    commit["block_id"]["hash"] = header_hash(header).hex().upper()
    stamp = header["time"]
    signatures = []
    for validator in trust.validators:
        wire = vote_sign_bytes(trust.chain_id, int(header["height"]),
                               commit["round"], commit["block_id"], stamp)
        signatures.append({
            "block_id_flag": 2, "validator_address": validator.address.hex().upper(),
            "timestamp": stamp, "signature": base64.b64encode(keys[validator.address].sign(wire)).decode()})
    commit["signatures"] = signatures
    result = canonical_json(value)
    authenticate_observation(result, network.engine_genesis, network.genesis_path.read_bytes())
    return result



def run_wallet_scenarios(paths: dict, output: Path, report: dict,
                         settings: dict) -> None:
    pins = report.get("expected_sha256")
    if (_sha(paths["engine"]) != settings["engine_sha256"]
            or type(pins) is not dict
            or any(pins.get(name) != _sha(paths[name])
                   for name in ("client", "prover"))):
        raise ValueError("real engine/controller identity is not pinned")

    private = output.with_name(output.name + ".private")
    private.mkdir(mode=0o700)
    runtime = private / "wallets"
    runtime.mkdir(mode=0o700)
    network = None
    proxies: list[DeliveryProxy] = []
    try:
        network = WalletNetwork(
            paths, private / "network-report.json", report, private)
        prefix = network.genesis_prefix(paths["genesis"].read_bytes())
        controller = DevelopmentController(
            paths["client"], paths["prover"], prefix, network.receipts,
            expected_client_sha256=pins["client"],
            expected_prover_sha256=pins["prover"])
        controller.validate_executables()

        spend_a, spend_b = random_field(), random_field()
        genesis_note_secret, genesis_blinding = random_field(), random_field()
        maximum_height = prefix["limits"]["max_height"]
        genesis_note = SecretNote(
            maximum_height, 100, spend_a,
            genesis_note_secret, genesis_blinding)
        owner_a = controller.derive_owner_key(spend_a)
        commitments, genesis_root = controller.commitments([genesis_note])
        app_raw = finalize_fresh_genesis(prefix, commitments)
        genesis = genesis_document(app_raw)
        network.install_genesis(app_raw)
        network.start_sources()
        report["processes_started"] = True
        report["genesis_sha256"] = genesis.sha256.hex()
        report["profile_id"] = genesis.profile.identity.hex()
        report["deployment_id"] = genesis.deployment.identity.hex()

        proxy_a = DeliveryProxy(
            f"http://127.0.0.1:{network.http[0]}/")
        proxy_b = DeliveryProxy(
            f"http://127.0.0.1:{network.http[0]}/")
        proxies.extend((proxy_a, proxy_b))
        session = WalletProcesses(
            paths, runtime, network.genesis_path,
            network.engine_genesis, pins, network.receipts)

        def write_private(name: str, raw: bytes) -> Path:
            target = runtime / name
            _write_bytes(target, raw)
            return target

        def status(owner: str) -> dict:
            value = session.call(owner, "status")
            assert value is not None
            return value

        def decision(review_id: str) -> dict:
            with closing(sqlite3.connect(runtime / "wallet-a.sqlite")) as db:
                db.row_factory = sqlite3.Row
                rows = db.execute(
                    "SELECT * FROM decisions WHERE review_id=?",
                    (review_id,)).fetchall()
                if len(rows) != 1:
                    raise RuntimeError("wallet decision lookup differs")
                return dict(rows[0])

        def database_rows() -> dict[str, tuple]:
            return {
                path.name: journal_rows(path)
                for path in sorted(runtime.glob("*.sqlite"))
                if path.is_file()
            }

        restart_results: dict[str, dict] = {}

        def restart_boundary(name: str, operation) -> None:
            before = database_rows()
            requests = sum(len(proxy.raw_urls) for proxy in proxies)
            operation()
            after = database_rows()
            request_delta = sum(
                len(proxy.raw_urls) for proxy in proxies) - requests
            if before != after or request_delta != 0:
                raise RuntimeError("wallet restart boundary changed authority")
            restart_results[name] = {
                "rows_equal": True, "implicit_network_calls": 0}

        def owner_reopen(owner: str):
            return lambda: session.call(owner, "owner-key", fault="no-network")

        def post_count(proxy: DeliveryProxy) -> int:
            return sum(path == b"/" for path in proxy.raw_urls)

        def delivery_args(path: Path, endpoint: str) -> tuple:
            return ("--delivery", path, "--endpoint", endpoint)

        def wait_accepted(count: int) -> list[dict]:
            def complete():
                states = [network.state(index) for index in range(4)]
                return states if all(
                    item["state"]["accepted_transaction_count"] == count
                    for item in states) else None
            return wait_until(complete, 120)

        def collect(name: str) -> tuple[bytes, Path, dict]:
            raw = collect_retained_observation(network, proxies, app_raw)
            observation, certificate = authenticate_observation(
                raw, network.engine_genesis, app_raw)
            path = write_private(name + "-observation.json", raw)
            return raw, path, certificate

        init_a = session.call(
            "wallet-a", "init",
            payload={"owner_spend_secret": spend_a.hex()})
        init_b = session.call(
            "wallet-b", "init",
            payload={"owner_spend_secret": spend_b.hex()})
        if (init_a is None or init_b is None
                or init_a["owner_key"] != owner_a.hex()
                or init_a["owner_key"] == init_b["owner_key"]):
            raise RuntimeError("distinct wallet initialization differs")
        restart_boundary("initialized", owner_reopen("wallet-a"))

        initial_raw, initial_file, _ = collect("initial")
        for owner in ("wallet-a", "wallet-b"):
            current = status(owner)
            session.call(
                owner, "sync", "--expected-revision", current["revision"],
                "--input", initial_file)
        restart_boundary("synced", owner_reopen("wallet-a"))

        capsule = {
            "format": NOTE_CAPSULE_FORMAT, "version": 1,
            "capsule_id": "00" * 32,
            "genesis_sha256": genesis.sha256.hex(),
            "profile_id": genesis.profile.identity.hex(),
            "deployment_id": genesis.deployment.identity.hex(),
            "origin": {"kind": "genesis", "position": 0},
            "commitment": commitments[0], "owner_key": owner_a.hex(),
            "expiry": maximum_height, "value": 100,
            "note_secret": genesis_note_secret.hex(),
            "blinding": genesis_blinding.hex(),
        }
        capsule["capsule_id"] = capsule_id(capsule)
        genesis_capsule = canonical_json(capsule)
        current_a = status("wallet-a")
        imported = session.call(
            "wallet-a", "import-note",
            "--expected-revision", current_a["revision"],
            payload={
                "capsule_base64": base64.b64encode(
                    genesis_capsule).decode("ascii"),
                "owner_spend_secret": spend_a.hex(),
            })
        if imported is None or imported["capsule_id"] != capsule["capsule_id"]:
            raise RuntimeError("genesis capsule import differs")
        restart_boundary("imported", owner_reopen("wallet-a"))

        initial_height = status("wallet-a")["state_height"]
        payment_review = session.call(
            "wallet-a", "prepare",
            "--note-id", capsule["capsule_id"],
            "--recipient-owner-key", init_b["owner_key"],
            "--value", 20,
            "--valid-until", qualification_valid_until(
                maximum_height, initial_height))
        if payment_review is None:
            raise RuntimeError("payment review unavailable")
        restart_boundary("prepared", owner_reopen("wallet-a"))
        approval_payload = {
            key: payment_review[key] for key in ("review", "confirmation")}
        before_rollback = database_rows()["wallet-a.sqlite"]
        session.call(
            "wallet-a", "approve", payload=approval_payload,
            fault="before-commit", expected_code=72)
        with closing(sqlite3.connect(runtime / "wallet-a.sqlite")) as db:
            before_commit_empty = (
                db.execute("SELECT COUNT(*) FROM decisions").fetchone()[0] == 0)
        if (not before_commit_empty
                or journal_rows(runtime / "wallet-a.sqlite") != before_rollback):
            raise RuntimeError("precommit approval crash mutated wallet")
        session.call(
            "wallet-a", "approve", payload=approval_payload,
            fault="after-commit", expected_code=73)
        payment_row = decision(payment_review["confirmation"])
        payment_wire = bytes(payment_row["transaction_bytes"])
        payment_sha = hashlib.sha256(payment_wire).hexdigest()
        before_recovery_proofs = sum(
            row["role"] == "development-prover"
            and row.get("stdout_sha256") == payment_sha
            for row in network.receipts)
        payment_capsules_before = (
            bytes(payment_row["payment_capsule"]),
            bytes(payment_row["change_capsule"]))
        saved_paths = session.paths
        session.paths = {
            "client": runtime / "controller-unavailable-client",
            "prover": runtime / "controller-unavailable-prover"}
        payment_file = runtime / "payment-transaction.bin"
        try:
            recovered = session.call(
                "wallet-a", "recover", "--review-id",
                payment_review["confirmation"], "--output", payment_file,
                fault="no-network")
        finally:
            session.paths = saved_paths
        if (recovered is None or payment_file.read_bytes() != payment_wire):
            raise RuntimeError("lost-return recovery differs")
        payment_row_after = decision(payment_review["confirmation"])
        after_recovery_proofs = sum(
            row["role"] == "development-prover"
            and row.get("stdout_sha256") == payment_sha
            for row in network.receipts)
        payment_capsules_equal = payment_capsules_before == (
            bytes(payment_row_after["payment_capsule"]),
            bytes(payment_row_after["change_capsule"]))
        if (before_recovery_proofs != 1 or after_recovery_proofs != 1
                or not payment_capsules_equal):
            raise RuntimeError("lost-return recovery re-proved or mutated outputs")
        restart_boundary("approved", owner_reopen("wallet-a"))

        capsule_results: dict[str, dict] = {}
        uncommitted_rows = database_rows()["wallet-b.sqlite"]
        current_b = status("wallet-b")
        session.call(
            "wallet-b", "import-note",
            "--expected-revision", current_b["revision"],
            payload={
                "capsule_base64": base64.b64encode(
                    payment_capsules_before[0]).decode("ascii"),
                "owner_spend_secret": spend_b.hex(),
            }, expected_code=2)
        if journal_rows(runtime / "wallet-b.sqlite") != uncommitted_rows:
            raise RuntimeError("uncommitted capsule changed recipient wallet")
        capsule_results["uncommitted"] = {
            "refused": True, "state_unchanged": True}

        lost_claim = runtime / "delivery-lost-claim.sqlite"
        session.call(
            "wallet-a", "delivery-init",
            *delivery_args(lost_claim, proxy_a.endpoint))
        lost_claim_review = session.call(
            "wallet-a", "delivery-prepare",
            *delivery_args(lost_claim, proxy_a.endpoint),
            "--decision-id", payment_row["decision_id"])
        if lost_claim_review is None:
            raise RuntimeError("lost-claim delivery review unavailable")
        lost_claim_posts = post_count(proxy_a)
        session.call(
            "wallet-a", "delivery-send",
            *delivery_args(lost_claim, proxy_a.endpoint),
            payload={key: lost_claim_review[key]
                     for key in ("review", "confirmation")},
            fault="after-claim", expected_code=74)
        session.call(
            "wallet-a", "delivery-send",
            *delivery_args(lost_claim, proxy_a.endpoint),
            payload={key: lost_claim_review[key]
                     for key in ("review", "confirmation")},
            expected_code=2)
        lost_claim_sends = post_count(proxy_a) - lost_claim_posts
        restart_boundary(
            "attempt-claimed",
            lambda: session.call(
                "wallet-a", "delivery-inspect",
                *delivery_args(lost_claim, proxy_a.endpoint),
                "--decision-id", payment_row["decision_id"],
                fault="no-network"))

        timeout_delivery = runtime / "delivery-timeout.sqlite"
        session.call(
            "wallet-a", "delivery-init",
            *delivery_args(timeout_delivery, proxy_a.endpoint))
        timeout_review = session.call(
            "wallet-a", "delivery-prepare",
            *delivery_args(timeout_delivery, proxy_a.endpoint),
            "--decision-id", payment_row["decision_id"])
        if timeout_review is None:
            raise RuntimeError("timeout delivery review unavailable")
        timeout_posts = post_count(proxy_a)
        proxy_a.mode = "timeout"
        timeout_result = session.call(
            "wallet-a", "delivery-send",
            *delivery_args(timeout_delivery, proxy_a.endpoint),
            payload={key: timeout_review[key]
                     for key in ("review", "confirmation")},
            timeout=30)
        proxy_a.mode = "normal"
        if (timeout_result is None
                or timeout_result["transport_state"] != "unresolved"):
            raise RuntimeError("timeout delivery was not unresolved")
        session.call(
            "wallet-a", "delivery-send",
            *delivery_args(timeout_delivery, proxy_a.endpoint),
            payload={key: timeout_review[key]
                     for key in ("review", "confirmation")},
            expected_code=2)
        timeout_sends = post_count(proxy_a) - timeout_posts

        delivery_a = runtime / "delivery-a.sqlite"
        session.call(
            "wallet-a", "delivery-init",
            *delivery_args(delivery_a, proxy_a.endpoint))
        delivery_review = session.call(
            "wallet-a", "delivery-prepare",
            *delivery_args(delivery_a, proxy_a.endpoint),
            "--decision-id", payment_row["decision_id"])
        if delivery_review is None:
            raise RuntimeError("payment delivery review unavailable")
        lost_response_posts = post_count(proxy_a)
        proxy_a.mode = "lost-response"
        delivery_result = session.call(
            "wallet-a", "delivery-send",
            *delivery_args(delivery_a, proxy_a.endpoint),
            payload={key: delivery_review[key]
                     for key in ("review", "confirmation")})
        proxy_a.mode = "normal"
        if (delivery_result is None
                or delivery_result["transport_state"] != "unresolved"):
            raise RuntimeError("lost response was not unresolved")
        session.call(
            "wallet-a", "delivery-send",
            *delivery_args(delivery_a, proxy_a.endpoint),
            payload={key: delivery_review[key]
                     for key in ("review", "confirmation")},
            expected_code=2)
        lost_response_sends = post_count(proxy_a) - lost_response_posts
        restart_boundary(
            "submitted",
            lambda: session.call(
                "wallet-a", "delivery-inspect",
                *delivery_args(delivery_a, proxy_a.endpoint),
                "--decision-id", payment_row["decision_id"],
                fault="no-network"))
        payment_states = wait_accepted(1)
        payment_observation, payment_observation_file, payment_certificate = (
            collect("payment"))
        collected = session.call(
            "wallet-a", "delivery-collect",
            *delivery_args(delivery_a, proxy_a.endpoint))
        if collected is None:
            raise RuntimeError("payment receipt collection failed")
        restart_boundary(
            "receipt-collected",
            lambda: session.call(
                "wallet-a", "delivery-inspect",
                *delivery_args(delivery_a, proxy_a.endpoint),
                "--decision-id", payment_row["decision_id"],
                fault="no-network"))
        before_sync_revision = status("wallet-a")["revision"]
        session.call(
            "wallet-a", "delivery-reconcile",
            *delivery_args(delivery_a, proxy_a.endpoint),
            "--decision-id", payment_row["decision_id"],
            "--observation-id", collected["observation_id"],
            "--expected-revision", before_sync_revision,
            fault="after-sync", expected_code=75)
        after_sync_revision = status("wallet-a")["revision"]
        reconciled = session.call(
            "wallet-a", "delivery-reconcile",
            *delivery_args(delivery_a, proxy_a.endpoint),
            "--decision-id", payment_row["decision_id"],
            "--observation-id", collected["observation_id"],
            "--expected-revision", after_sync_revision)
        if (reconciled is None
                or reconciled["decision_state"] != "executed_exact"):
            raise RuntimeError("payment did not reconcile exactly")
        restart_boundary(
            "reconciled",
            lambda: session.call(
                "wallet-a", "delivery-inspect",
                *delivery_args(delivery_a, proxy_a.endpoint),
                "--decision-id", payment_row["decision_id"],
                fault="no-network"))
        report["actual_proof_accepted"] = True

        payment_capsule_file = runtime / "payment-capsule.json"
        exported = session.call(
            "wallet-a", "export-capsule",
            "--decision-id", payment_row["decision_id"],
            "--output", payment_capsule_file)
        if (exported is None
                or payment_capsule_file.read_bytes()
                    != payment_capsules_before[0]):
            raise RuntimeError("payment capsule export differs")
        restart_boundary("capsule-exported", owner_reopen("wallet-a"))

        current_b = status("wallet-b")
        certificate_results: dict[str, dict] = {}
        for name, changed in certificate_mutations(
                payment_observation).items():
            before = journal_rows(runtime / "wallet-b.sqlite")
            changed_file = write_private(
                "certificate-" + name + ".json", changed)
            session.call(
                "wallet-b", "sync",
                "--expected-revision", current_b["revision"],
                "--input", changed_file, expected_code=2)
            if journal_rows(runtime / "wallet-b.sqlite") != before:
                raise RuntimeError("certificate mutation changed wallet")
            certificate_results[name] = {
                "refused": True, "state_unchanged": True}
        session.call(
            "wallet-b", "sync",
            "--expected-revision", current_b["revision"],
            "--input", payment_observation_file)
        current_b = status("wallet-b")
        same_height = _authentic_same_height_fork(
            payment_observation, network)
        same_height_file = write_private(
            "certificate-same-height-fork.json", same_height)
        for name, candidate, revision in (
                ("same-height-fork", same_height_file, current_b["revision"]),
                ("rollback", initial_file, current_b["revision"]),
                ("stale-revision", payment_observation_file, "00" * 32)):
            before = journal_rows(runtime / "wallet-b.sqlite")
            session.call(
                "wallet-b", "sync", "--expected-revision", revision,
                "--input", candidate, expected_code=2)
            if journal_rows(runtime / "wallet-b.sqlite") != before:
                raise RuntimeError("certificate authority case changed wallet")
            certificate_results[name] = {
                "refused": True, "state_unchanged": True}
        if set(certificate_results) != set(settings["certificate_mutations"]):
            raise RuntimeError("certificate mutation roster differs")

        current_b = status("wallet-b")
        for name, changed in capsule_mutations(
                payment_capsules_before[0]).items():
            before = journal_rows(runtime / "wallet-b.sqlite")
            session.call(
                "wallet-b", "import-note",
                "--expected-revision", current_b["revision"],
                payload={
                    "capsule_base64": base64.b64encode(
                        changed).decode("ascii"),
                    "owner_spend_secret": spend_b.hex(),
                }, expected_code=2)
            if journal_rows(runtime / "wallet-b.sqlite") != before:
                raise RuntimeError("capsule mutation changed recipient wallet")
            capsule_results[name] = {
                "refused": True, "state_unchanged": True}
        valid_import = session.call(
            "wallet-b", "import-note",
            "--expected-revision", current_b["revision"],
            payload={
                "capsule_base64": base64.b64encode(
                    payment_capsules_before[0]).decode("ascii"),
                "owner_spend_secret": spend_b.hex(),
            })
        if valid_import is None:
            raise RuntimeError("recipient did not import payment capsule")
        restart_boundary("recipient-imported", owner_reopen("wallet-b"))

        recipient_height = status("wallet-b")["state_height"]
        recipient_review = session.call(
            "wallet-b", "prepare",
            "--note-id", valid_import["capsule_id"],
            "--recipient-owner-key", init_a["owner_key"],
            "--value", 7,
            "--valid-until", qualification_valid_until(
                maximum_height, recipient_height))
        if recipient_review is None:
            raise RuntimeError("recipient return review unavailable")
        recipient_approved = session.call(
            "wallet-b", "approve",
            payload={key: recipient_review[key]
                     for key in ("review", "confirmation")})
        if recipient_approved is None:
            raise RuntimeError("recipient return approval unavailable")
        recipient_file = runtime / "recipient-transaction.bin"
        session.call(
            "wallet-b", "recover", "--decision-id",
            recipient_approved["decision_id"], "--output", recipient_file)
        recipient_wire = recipient_file.read_bytes()

        delivery_b = runtime / "delivery-b.sqlite"
        session.call(
            "wallet-b", "delivery-init",
            *delivery_args(delivery_b, proxy_b.endpoint))
        recipient_delivery = session.call(
            "wallet-b", "delivery-prepare",
            *delivery_args(delivery_b, proxy_b.endpoint),
            "--decision-id", recipient_approved["decision_id"])
        if recipient_delivery is None:
            raise RuntimeError("recipient delivery review unavailable")
        recipient_sent = session.call(
            "wallet-b", "delivery-send",
            *delivery_args(delivery_b, proxy_b.endpoint),
            payload={key: recipient_delivery[key]
                     for key in ("review", "confirmation")})
        if (recipient_sent is None
                or recipient_sent["transport_state"] != "endpoint_admitted"):
            raise RuntimeError("recipient transaction was not admitted")
        session.call(
            "wallet-b", "delivery-send",
            *delivery_args(delivery_b, proxy_b.endpoint),
            payload={key: recipient_delivery[key]
                     for key in ("review", "confirmation")},
            expected_code=2)
        wait_accepted(2)
        recipient_observation, recipient_observation_file, recipient_certificate = (
            collect("recipient"))
        recipient_collected = session.call(
            "wallet-b", "delivery-collect",
            *delivery_args(delivery_b, proxy_b.endpoint))
        if recipient_collected is None:
            raise RuntimeError("recipient receipt collection failed")
        recipient_revision = status("wallet-b")["revision"]
        recipient_reconciled = session.call(
            "wallet-b", "delivery-reconcile",
            *delivery_args(delivery_b, proxy_b.endpoint),
            "--decision-id", recipient_approved["decision_id"],
            "--observation-id", recipient_collected["observation_id"],
            "--expected-revision", recipient_revision)
        if (recipient_reconciled is None
                or recipient_reconciled["decision_state"] != "executed_exact"):
            raise RuntimeError("recipient return did not execute exactly")
        current_a = status("wallet-a")
        session.call(
            "wallet-a", "sync",
            "--expected-revision", current_a["revision"],
            "--input", recipient_observation_file)
        return_capsule_file = runtime / "return-capsule.json"
        session.call(
            "wallet-b", "export-capsule",
            "--decision-id", recipient_approved["decision_id"],
            "--output", return_capsule_file)
        current_a = status("wallet-a")
        return_import = session.call(
            "wallet-a", "import-note",
            "--expected-revision", current_a["revision"],
            payload={
                "capsule_base64": base64.b64encode(
                    return_capsule_file.read_bytes()).decode("ascii"),
                "owner_spend_secret": spend_a.hex(),
            })
        if return_import is None:
            raise RuntimeError("sender did not import returned capsule")

        # The recipient's imported payment is now authentically spent. A new
        # spend review must refuse without changing the recipient journal.
        spent_before = journal_rows(runtime / "wallet-b.sqlite")
        spent_status = status("wallet-b")
        session.call(
            "wallet-b", "prepare",
            "--note-id", valid_import["capsule_id"],
            "--recipient-owner-key", init_a["owner_key"],
            "--value", 1,
            "--valid-until", min(
                maximum_height, spent_status["state_height"] + 12),
            expected_code=2)
        if journal_rows(runtime / "wallet-b.sqlite") != spent_before:
            raise RuntimeError("spent capsule refusal changed recipient wallet")
        capsule_results["spent"] = {
            "refused": True, "state_unchanged": True}
        if set(capsule_results) != set(settings["capsule_mutations"]):
            raise RuntimeError("capsule mutation roster differs")

        def spendable(owner: str, value: int) -> dict:
            matches = [
                row for row in status(owner)["notes"]
                if row["state"] == "spendable" and row["value"] == value]
            if len(matches) != 1:
                raise RuntimeError("expected one spendable wallet note")
            return matches[0]

        def captured_request(before: set[Path]) -> tuple[Path, bytes]:
            after = set(session.request_dir.glob("*.bin"))
            created = sorted(after - before)
            if len(created) != 1:
                raise RuntimeError("approval prover request attribution differs")
            raw = created[0].read_bytes()
            _prover_witness(raw)
            return created[0], raw

        def claim_without_io(decision_id: str) -> int:
            prepared = session.call(
                "wallet-a", "delivery-prepare",
                *delivery_args(delivery_a, proxy_a.endpoint),
                "--decision-id", decision_id)
            if prepared is None:
                raise RuntimeError("delivery claim review unavailable")
            posts = post_count(proxy_a)
            payload = {
                key: prepared[key] for key in ("review", "confirmation")}
            session.call(
                "wallet-a", "delivery-send",
                *delivery_args(delivery_a, proxy_a.endpoint),
                payload=payload, fault="after-claim", expected_code=74)
            session.call(
                "wallet-a", "delivery-send",
                *delivery_args(delivery_a, proxy_a.endpoint),
                payload=payload, expected_code=2)
            delta = post_count(proxy_a) - posts
            if delta != 0:
                raise RuntimeError("claimed delivery performed network I/O")
            return delta

        def collect_and_reconcile(decision_id: str, name: str):
            raw, retained, certificate = collect(name)
            imported = session.call(
                "wallet-a", "delivery-collect",
                *delivery_args(delivery_a, proxy_a.endpoint))
            if imported is None:
                raise RuntimeError(name + " receipt collection failed")
            revision = status("wallet-a")["revision"]
            result = session.call(
                "wallet-a", "delivery-reconcile",
                *delivery_args(delivery_a, proxy_a.endpoint),
                "--decision-id", decision_id,
                "--observation-id", imported["observation_id"],
                "--expected-revision", revision)
            if result is None:
                raise RuntimeError(name + " reconciliation failed")
            return raw, retained, certificate, result

        # Re-prove one exact statement. Randomized proof bytes and txid differ,
        # while the authenticated public effects remain byte-for-byte equal.
        equivalent_input = spendable("wallet-a", 75)
        equivalent_height = status("wallet-a")["state_height"]
        equivalent_review = session.call(
            "wallet-a", "prepare",
            "--note-id", equivalent_input["capsule_id"],
            "--recipient-owner-key", init_b["owner_key"],
            "--value", 10,
            "--valid-until", qualification_valid_until(
                maximum_height, equivalent_height))
        if equivalent_review is None:
            raise RuntimeError("equivalent review unavailable")
        requests_before = set(session.request_dir.glob("*.bin"))
        equivalent_approved = session.call(
            "wallet-a", "approve",
            payload={key: equivalent_review[key]
                     for key in ("review", "confirmation")})
        if equivalent_approved is None:
            raise RuntimeError("equivalent approval unavailable")
        _equivalent_request_file, equivalent_request = captured_request(
            requests_before)
        equivalent_original_file = runtime / "equivalent-original-transaction.bin"
        session.call(
            "wallet-a", "recover", "--decision-id",
            equivalent_approved["decision_id"],
            "--output", equivalent_original_file)
        equivalent_original = equivalent_original_file.read_bytes()
        equivalent_winner = controller.prove(app_raw, equivalent_request)
        equivalent_original_tx = Transaction.decode(
            equivalent_original, genesis)
        equivalent_winner_tx = Transaction.decode(equivalent_winner, genesis)
        if (equivalent_original == equivalent_winner
                or transaction_id(equivalent_original)
                    == transaction_id(equivalent_winner)
                or equivalent_original_tx.public_fields
                    != equivalent_winner_tx.public_fields):
            raise RuntimeError("randomized equivalent proof differs")
        write_private("equivalent-winner-transaction.bin", equivalent_winner)
        equivalent_claim_sends = claim_without_io(
            equivalent_approved["decision_id"])
        network.stage_without_quorum([equivalent_winner])
        wait_accepted(3)
        (equivalent_observation, equivalent_observation_file,
         equivalent_certificate, equivalent_reconciled) = (
            collect_and_reconcile(
                equivalent_approved["decision_id"], "equivalent"))
        if equivalent_reconciled["decision_state"] != "executed_equivalent":
            raise RuntimeError("randomized winner did not reconcile equivalently")
        equivalent_capsule_file = runtime / "equivalent-capsule.json"
        session.call(
            "wallet-a", "export-capsule", "--decision-id",
            equivalent_approved["decision_id"],
            "--output", equivalent_capsule_file)
        current_b = status("wallet-b")
        session.call(
            "wallet-b", "sync",
            "--expected-revision", current_b["revision"],
            "--input", equivalent_observation_file)
        current_b = status("wallet-b")
        equivalent_import = session.call(
            "wallet-b", "import-note",
            "--expected-revision", current_b["revision"],
            payload={
                "capsule_base64": base64.b64encode(
                    equivalent_capsule_file.read_bytes()).decode("ascii"),
                "owner_spend_secret": spend_b.hex(),
            })
        if equivalent_import is None:
            raise RuntimeError("equivalent winner capsule was not imported")

        # Prove a different statement for the same authenticated input. Only
        # this winner is staged, so the wallet must classify its original as a
        # conflicting spend and refuse payment-capsule export.
        conflict_input = spendable("wallet-a", 60)
        conflict_height = status("wallet-a")["state_height"]
        conflict_review = session.call(
            "wallet-a", "prepare",
            "--note-id", conflict_input["capsule_id"],
            "--recipient-owner-key", init_b["owner_key"],
            "--value", 9,
            "--valid-until", qualification_valid_until(
                maximum_height, conflict_height))
        if conflict_review is None:
            raise RuntimeError("conflict review unavailable")
        conflict_approved = session.call(
            "wallet-a", "approve",
            payload={key: conflict_review[key]
                     for key in ("review", "confirmation")})
        if conflict_approved is None:
            raise RuntimeError("conflict approval unavailable")
        conflict_original_file = runtime / "conflict-original-transaction.bin"
        session.call(
            "wallet-a", "recover", "--decision-id",
            conflict_approved["decision_id"],
            "--output", conflict_original_file)
        conflict_original = conflict_original_file.read_bytes()
        with closing(sqlite3.connect(runtime / "wallet-a.sqlite")) as database:
            database.row_factory = sqlite3.Row
            note_rows = database.execute(
                "SELECT payload,chain_position FROM notes WHERE capsule_id=?",
                (conflict_input["capsule_id"],)).fetchall()
        if len(note_rows) != 1:
            raise RuntimeError("conflict input note lookup differs")
        conflict_capsule = decode_capsule(
            bytes(note_rows[0]["payload"]), app_raw)
        conflict_input_note = SecretNote(
            conflict_capsule["expiry"], conflict_capsule["value"], spend_a,
            bytes.fromhex(conflict_capsule["note_secret"]),
            bytes.fromhex(conflict_capsule["blinding"]))
        conflict_payment_secret = random_field()
        conflict_payment_blinding = random_field()
        conflict_change_secret = random_field()
        conflict_change_blinding = random_field()
        equivalent_state = decode_canonical_json(
            equivalent_observation)["state_witness"]["state"]
        conflict_position = int(note_rows[0]["chain_position"])
        if (conflict_position >= len(equivalent_state["commitments"])
                or equivalent_state["commitments"][conflict_position]
                    != conflict_capsule["commitment"]):
            raise RuntimeError("conflict input is not in authenticated state")
        conflict_request = controller.spend_to_recipient_keys(
            app_raw, equivalent_state["commitments"],
            conflict_position, conflict_input_note,
            (
                RecipientOutput(
                    conflict_capsule["expiry"], 11,
                    bytes.fromhex(init_b["owner_key"]),
                    conflict_payment_secret, conflict_payment_blinding),
                RecipientOutput(
                    conflict_capsule["expiry"], 44, owner_a,
                    conflict_change_secret, conflict_change_blinding),
            ),
            valid_from=conflict_review["review"]["valid_from"],
            valid_until=conflict_review["review"]["valid_until"])
        write_private("conflict-winner-request.bin", conflict_request)
        conflict_winner = controller.prove(app_raw, conflict_request)
        write_private("conflict-winner-transaction.bin", conflict_winner)
        conflict_original_tx = Transaction.decode(conflict_original, genesis)
        conflict_winner_tx = Transaction.decode(conflict_winner, genesis)
        if not same_nullifier_conflict(
                conflict_original_tx.public_fields,
                conflict_winner_tx.public_fields):
            raise RuntimeError("same-nullifier conflicting proof differs")
        claim_without_io(conflict_approved["decision_id"])
        network.stage_without_quorum([conflict_winner])
        wait_accepted(4)
        (conflict_observation, conflict_observation_file,
         conflict_certificate, conflict_reconciled) = collect_and_reconcile(
            conflict_approved["decision_id"], "conflict")
        if conflict_reconciled["decision_state"] != "conflicting_spend":
            raise RuntimeError("conflicting winner was not authoritative")
        conflict_export_before = journal_rows(runtime / "wallet-a.sqlite")
        session.call(
            "wallet-a", "export-capsule", "--decision-id",
            conflict_approved["decision_id"],
            "--output", runtime / "refused-conflict-capsule.json",
            expected_code=2)
        if (journal_rows(runtime / "wallet-a.sqlite")
                != conflict_export_before
                or (runtime / "refused-conflict-capsule.json").exists()):
            raise RuntimeError("conflict capsule refusal changed authority")
        current_b = status("wallet-b")
        session.call(
            "wallet-b", "sync",
            "--expected-revision", current_b["revision"],
            "--input", conflict_observation_file)

        # Reserve A's returned seven-unit note, then cross its real validity
        # boundary without executing the transaction. Its one network attempt
        # is a measured nonzero CheckTx response from the actual endpoint.
        expiry_input = spendable("wallet-a", 7)
        expiry_height_before = status("wallet-a")["state_height"]
        expiry_until = qualification_expiry_until(
            maximum_height, expiry_height_before)
        expiry_review = session.call(
            "wallet-a", "prepare",
            "--note-id", expiry_input["capsule_id"],
            "--recipient-owner-key", init_b["owner_key"],
            "--value", 1, "--valid-until", expiry_until)
        if expiry_review is None:
            raise RuntimeError("expiry review unavailable")
        expiry_approved = session.call(
            "wallet-a", "approve",
            payload={key: expiry_review[key]
                     for key in ("review", "confirmation")})
        if expiry_approved is None:
            raise RuntimeError("expiry approval unavailable")
        expiry_file = runtime / "expiry-transaction.bin"
        session.call(
            "wallet-a", "recover", "--decision-id",
            expiry_approved["decision_id"], "--output", expiry_file)
        expiry_wire = expiry_file.read_bytes()
        expiry_tx = Transaction.decode(expiry_wire, genesis)
        expiry_nullifier = expiry_tx.public_fields[9].hex()
        expiry_status_before = status("wallet-a")
        expiry_decision_before = next(
            row for row in expiry_status_before["decisions"]
            if row["decision_id"] == expiry_approved["decision_id"])
        expiry_note_before = next(
            row for row in expiry_status_before["notes"]
            if row["capsule_id"] == expiry_input["capsule_id"])
        state_before_expiry = network.state(0)["state"]
        hold_before_expiry = (
            expiry_decision_before["state"] == "ready"
            and expiry_note_before["state"] == "reserved")
        no_receipt_before_expiry = (
            expiry_nullifier not in state_before_expiry["spent_nullifiers"]
            and not any(row["nullifier"] == expiry_nullifier
                        for row in state_before_expiry["receipts"]))
        if (not hold_before_expiry or not no_receipt_before_expiry
                or network.direct_check(0, expiry_wire) != 0):
            raise RuntimeError("pre-expiry hold or admission differs")
        expiry_delivery = session.call(
            "wallet-a", "delivery-prepare",
            *delivery_args(delivery_a, proxy_a.endpoint),
            "--decision-id", expiry_approved["decision_id"])
        if expiry_delivery is None:
            raise RuntimeError("expiry delivery review unavailable")
        network.set_empty_blocks(True)
        try:
            wait_until(
                lambda: all(
                    network.state(index)["height"] >= expiry_until - 1
                    for index in range(4)), EXPIRY_WAIT_SECONDS)
        finally:
            network.set_empty_blocks(False)
        wait_until(
            lambda: all(
                network.height(index) >= expiry_until - 1
                for index in range(4)), 90)
        nonzero_posts_before = post_count(proxy_a)
        nonzero_forwarded_before = proxy_a.forwarded
        expiry_sent = session.call(
            "wallet-a", "delivery-send",
            *delivery_args(delivery_a, proxy_a.endpoint),
            payload={key: expiry_delivery[key]
                     for key in ("review", "confirmation")})
        if (expiry_sent is None
                or expiry_sent["transport_state"] != "endpoint_declined"
                or not isinstance(expiry_sent["check_tx_code"], int)
                or expiry_sent["check_tx_code"] == 0):
            raise RuntimeError("expired endpoint did not decline transaction")
        session.call(
            "wallet-a", "delivery-send",
            *delivery_args(delivery_a, proxy_a.endpoint),
            payload={key: expiry_delivery[key]
                     for key in ("review", "confirmation")},
            expected_code=2)
        nonzero_sends = post_count(proxy_a) - nonzero_posts_before
        nonzero_forwarded = proxy_a.forwarded - nonzero_forwarded_before
        if nonzero_sends != 1 or nonzero_forwarded != 1:
            raise RuntimeError("expired endpoint attempt count differs")
        (expiry_observation, expiry_observation_file, expiry_certificate,
         expiry_reconciled) = collect_and_reconcile(
            expiry_approved["decision_id"], "expiry")
        expiry_state = decode_canonical_json(
            expiry_observation)["state_witness"]
        if expiry_state["height"] + 1 < expiry_until:
            raise RuntimeError("expiry observation precedes validity boundary")
        if expiry_reconciled["decision_state"] != "expired_unexecuted":
            raise RuntimeError("expired decision did not release its hold")
        current_b = status("wallet-b")
        session.call(
            "wallet-b", "sync",
            "--expected-revision", current_b["revision"],
            "--input", expiry_observation_file)
        final_a = status("wallet-a")
        final_b = status("wallet-b")
        if (final_a["state_height"] != expiry_state["height"]
                or final_b["state_height"] != expiry_state["height"]
                or set(restart_results) != set(settings["restart_boundaries"])):
            raise RuntimeError("final wallet checkpoint or restart roster differs")
        final_states = {row["txid"]: row["state"]
                        for row in final_a["decisions"]}
        winner_precedence = (
            final_states.get(payment_row["txid"]) == "executed_exact"
            and final_states.get(equivalent_approved["txid"])
                == "executed_equivalent"
            and final_states.get(conflict_approved["txid"])
                == "conflicting_spend")
        if not winner_precedence:
            raise RuntimeError("authenticated winner precedence changed")

        # Capture every private surface while the owned validators still exist,
        # then terminate them before publishing process receipts or manifests.
        network.snapshot_material()
        home_objects = [
            (str(path.relative_to(network.homes)), path.read_bytes())
            for path in sorted(network.homes.rglob("*")) if path.is_file()]
        database_objects = [
            (str(path.relative_to(network.runtime)), path.read_bytes())
            for path in sorted(network.runtime.glob("app*/state.sqlite*"))
            if path.is_file()]
        log_objects = [
            (str(path.relative_to(network.runtime)), path.read_bytes())
            for path in sorted(network.runtime.rglob("*.log"))
            if path.is_file()]
        report_objects = [
            ("node-" + str(index), canonical_json(network.state(index)))
            for index in range(4)]
        network.close()

        wallet_manifests = [
            journal_manifest(runtime / "wallet-a.sqlite", "wallet-a", final_a),
            journal_manifest(runtime / "wallet-b.sqlite", "wallet-b", final_b),
        ]
        with Protocol5Delivery(
                delivery_a, final_a["wallet_id"], app_raw,
                network.engine_genesis, proxy_a.endpoint) as opened_a:
            delivery_a_status = opened_a.status()
        with Protocol5Delivery(
                delivery_b, final_b["wallet_id"], app_raw,
                network.engine_genesis, proxy_b.endpoint) as opened_b:
            delivery_b_status = opened_b.status()
        delivery_manifests = [
            journal_manifest(
                delivery_a, "delivery-a", delivery_a_status),
            journal_manifest(
                delivery_b, "delivery-b", delivery_b_status),
        ]
        report["wallet_manifests"] = wallet_manifests
        report["delivery_manifests"] = delivery_manifests
        report["processes"] = network.receipts

        payment_value = decode_canonical_json(
            payment_observation)["state_witness"]["state"]
        payment_receipts = [
            row for row in payment_value["receipts"]
            if row["txid"] == transaction_id(payment_wire).hex()]
        if len(payment_receipts) != 1:
            raise RuntimeError("payment receipt lookup differs")
        payment_receipt = payment_receipts[0]
        attempt_evidence = {
            "lost-response": {
                "attempts": 1, "sends": lost_response_sends,
                "retry_refused": True},
            "timeout": {
                "attempts": 1, "sends": timeout_sends,
                "retry_refused": True},
            "nonzero-checktx": {
                "attempts": 1, "sends": nonzero_sends,
                "retry_refused": True},
            "lost-after-claim": {
                "attempts": 1, "sends": lost_claim_sends,
                "retry_refused": True},
        }
        if (lost_response_sends != 1 or timeout_sends != 1
                or lost_claim_sends != 0 or equivalent_claim_sends != 0
                or [name for name in attempt_evidence]
                    != settings["attempt_subcases"]):
            raise RuntimeError("delivery subcase measurements differ")
        validator_command_objects = [
            (role + "-" + str(node), values["cmdline"])
            for role, node, values in network.process_surfaces]
        controller_needles = [
            str(paths[name]).encode() for name in ("client", "prover")]
        controller_paths_in_commands = sum(
            any(needle in raw for needle in controller_needles)
            for _name, raw in validator_command_objects)
        controller_paths_in_homes = sum(
            any(needle in raw for needle in controller_needles)
            for _name, raw in home_objects)
        controller_processes = [
            row for row in network.receipts
            if row["role"].startswith("development-")]
        controller_nodes_null = all(
            row["node"] is None for row in controller_processes)
        validator_controller_processes = sum(
            row["node"] is not None
            and row["role"] in {
                "development-prover", "development-client-genesis",
                "development-client-owner-key",
                "development-client-note-nullifier",
                "development-client-recipient-spend"}
            for row in network.receipts)
        if (not controller_nodes_null or controller_paths_in_commands
                or controller_paths_in_homes
                or validator_controller_processes):
            raise RuntimeError("validator/controller boundary differs")

        check_evidence = [
            {
                "validator_count": 4, "equal_power": True,
                "genesis_commitments": 1,
                "wallet_ids": [row["status"]["wallet_id"]
                               for row in wallet_manifests],
                "recipient_initial_state": "unavailable",
                "validator_app_hashes": network.retained_app_hashes,
            },
            {
                "owner_keys_distinct": True,
                "sender_received_only_recipient_owner_key": True,
                "recipient_secret_in_sender": False,
                "owner_key_opcode": 3, "recipient_opcode": 4,
            },
            {
                "txid": transaction_id(payment_wire).hex(),
                "payment_value": 20, "fee": 5, "change_value": 75,
                "executed_exact": True, "actual_proof": True,
                "validator_count": 4,
            },
            {
                "before_commit_empty": before_commit_empty,
                "crash_exit_code": 73,
                "after_commit_recovered": True,
                "transaction_sha256": payment_sha,
                "txid": transaction_id(payment_wire).hex(),
                "nullifier": Transaction.decode(
                    payment_wire, genesis).public_fields[9].hex(),
                "output_capsules_equal": payment_capsules_equal,
                "prover_invocations_before": before_recovery_proofs,
                "prover_invocations_after": after_recovery_proofs,
                "controller_unavailable": True,
            },
            {
                "attempt_claimed_before_io": True,
                "network_calls": lost_response_sends,
                "retry_refused": True,
                "endpoint_admission_is_execution": False,
                "subcases": attempt_evidence,
            },
            {
                "payment_state_height": payment_certificate["state_height"],
                "payment_header_height": payment_certificate["header_height"],
                "recipient_state_height": recipient_certificate["state_height"],
                "recipient_header_height": recipient_certificate["header_height"],
                "certificate_mutations": {
                    name: certificate_results[name]
                    for name in settings["certificate_mutations"]},
            },
            {
                "mutations": {
                    name: capsule_results[name]
                    for name in settings["capsule_mutations"]},
            },
            {
                "txid": transaction_id(recipient_wire).hex(),
                "payment_value": 7, "fee": 5, "change_value": 8,
                "actual_proof": True,
                "recipient_import_position": payment_receipt[
                    "output_position_0"],
                "return_imported_by_sender": True,
            },
            {
                "original_txid": transaction_id(conflict_original).hex(),
                "winner_txid": transaction_id(conflict_winner).hex(),
                "nullifier": conflict_original_tx.public_fields[9].hex(),
                "winner_authenticated": True,
                "original_state": "conflicting_spend",
                "payment_export_refused": True,
                "equivalent_original_txid": transaction_id(
                    equivalent_original).hex(),
                "equivalent_winner_txid": transaction_id(
                    equivalent_winner).hex(),
                "equivalent_state": "executed_equivalent",
            },
            {
                "txid": transaction_id(expiry_wire).hex(),
                "valid_until": expiry_until,
                "hold_before_expiry": hold_before_expiry,
                "no_receipt_before_expiry": no_receipt_before_expiry,
                "authenticated_height": expiry_state["height"],
                "decision_state": "expired_unexecuted",
                "winner_precedence": winner_precedence,
            },
            {
                "boundaries": {
                    name: restart_results[name]
                    for name in settings["restart_boundaries"]},
            },
            {
                "validator_count": 4,
                "controller_nodes_null": controller_nodes_null,
                "controller_paths_in_validator_commands":
                    controller_paths_in_commands,
                "controller_paths_in_validator_homes":
                    controller_paths_in_homes,
                "validator_prover_processes": 0,
                "validator_client_processes": 0,
            },
            {
                "artifact": "leakage-scan.json", "matches": 0,
                "private_journals_excluded": True,
            },
        ]
        report["checks"] = [
            {"id": identity, "passed": True, "evidence": evidence}
            for identity, evidence in zip(
                settings["required_checks"], check_evidence)]

        # Build the public payloads first, then scan every retained non-private
        # surface against all known wallet secrets, request witnesses, and note
        # capsules. Only aggregate zero-match receipts become public.
        source_receipt = {
            key: report[key] for key in (
                "source_commit", "source_tree", "source_dirty_before",
                "source_dirty_after", "source_files", "settings_sha256")}
        public_payloads = {
            "application-genesis.json": app_raw,
            "checks.json": canonical_json(report["checks"]) + b"\n",
            "conflict-observation.json": conflict_observation,
            "conflict-original-transaction.bin": conflict_original,
            "conflict-winner-transaction.bin": conflict_winner,
            "delivery-manifests.json": canonical_json(
                delivery_manifests) + b"\n",
            "engine-genesis.json": canonical_json(
                network.engine_genesis) + b"\n",
            "equivalent-observation.json": equivalent_observation,
            "equivalent-original-transaction.bin": equivalent_original,
            "equivalent-winner-transaction.bin": equivalent_winner,
            "expiry-observation.json": expiry_observation,
            "expiry-transaction.bin": expiry_wire,
            "genesis-template.json": paths["genesis"].read_bytes(),
            "kat-v1.bin": paths["kat"].read_bytes(),
            "payment-observation.json": payment_observation,
            "payment-transaction.bin": payment_wire,
            "processes.json": canonical_json(report["processes"]) + b"\n",
            "profile-descriptor-v1.bin": paths["profile"].read_bytes(),
            "recipient-observation.json": recipient_observation,
            "recipient-transaction.bin": recipient_wire,
            "sandbox-policy-v1.json": paths["policy"].read_bytes(),
            "source-receipt.json": canonical_json(source_receipt) + b"\n",
            "toolchain-manifest-v1.json": paths["toolchain"].read_bytes(),
            "wallet-manifests.json": canonical_json(wallet_manifests) + b"\n",
        }
        request_objects = [
            (path.name, path.read_bytes())
            for path in sorted(session.request_dir.glob("*.bin"))]
        request_objects.append(("conflict-winner-request.bin", conflict_request))
        if not request_objects:
            raise RuntimeError("private prover request evidence unavailable")
        known_secrets = [
            spend_a, spend_b, genesis_note_secret, genesis_blinding,
            conflict_payment_secret, conflict_payment_blinding,
            conflict_change_secret, conflict_change_blinding,
        ]
        for _name, raw in request_objects:
            witness = _prover_witness(raw)
            known_secrets.extend((
                witness["input_blinding"], witness["spend_secret"],
                witness["note_secret"],
                *witness["output_note_secrets"],
                *witness["output_blindings"],
            ))
        capsule_objects = []
        for wallet_name in ("wallet-a", "wallet-b"):
            with closing(sqlite3.connect(
                    runtime / (wallet_name + ".sqlite"))) as database:
                rows = database.execute(
                    "SELECT payload FROM notes UNION ALL "
                    "SELECT payment_capsule FROM decisions UNION ALL "
                    "SELECT change_capsule FROM decisions").fetchall()
            for index, (raw,) in enumerate(rows):
                raw = bytes(raw)
                capsule_objects.append((wallet_name + "-" + str(index), raw))
                value = decode_capsule(raw, app_raw)
                known_secrets.extend((
                    bytes.fromhex(value["note_secret"]),
                    bytes.fromhex(value["blinding"])))
        known_secrets = list(dict.fromkeys(known_secrets))
        if len(known_secrets) < 12:
            raise RuntimeError("known private scan roster is incomplete")
        sender_objects = [
            ("wallet-a", (runtime / "wallet-a.sqlite").read_bytes()),
            *[(name, raw) for name, raw in request_objects
              if _prover_witness(raw)["spend_secret"] == spend_a],
        ]
        if scan_objects(sender_objects, [spend_b])["matches"]:
            raise RuntimeError("recipient secret entered sender authority")

        child_argv, child_environ = [], []
        if session.snapshot_file.exists():
            for number, line in enumerate(
                    session.snapshot_file.read_text().splitlines()):
                value = json.loads(line)
                for key in ("cmdline", "launch_argv"):
                    child_argv.append((
                        "child-" + str(number) + "-" + key,
                        base64.b64decode(value[key])))
                for key in ("environ", "launch_environ"):
                    child_environ.append((
                        "child-" + str(number) + "-" + key,
                        base64.b64decode(value[key])))
        process_argv = [
            (role + "-" + str(node), values["cmdline"])
            for role, node, values in network.process_surfaces]
        process_argv.extend(
            ("wallet-launch-" + str(index), pair[0])
            for index, pair in enumerate(session.launches))
        process_argv.extend(child_argv)
        process_environ = [
            (role + "-" + str(node), values["environ"])
            for role, node, values in network.process_surfaces]
        process_environ.extend(
            ("wallet-env-" + str(index), pair[1])
            for index, pair in enumerate(session.launches))
        process_environ.extend(child_environ)
        transaction_objects = [
            (name, raw) for name, raw in (
                ("payment", payment_wire), ("recipient", recipient_wire),
                ("equivalent-original", equivalent_original),
                ("equivalent-winner", equivalent_winner),
                ("conflict-original", conflict_original),
                ("conflict-winner", conflict_winner),
                ("expiry", expiry_wire))]
        manifest_objects = [
            ("checks", public_payloads["checks.json"]),
            ("wallets", public_payloads["wallet-manifests.json"]),
            ("deliveries", public_payloads["delivery-manifests.json"]),
            ("processes", public_payloads["processes.json"]),
            ("source", public_payloads["source-receipt.json"]),
        ]
        url_objects = [
            ("endpoint-a", proxy_a.endpoint.encode()),
            ("endpoint-b", proxy_b.endpoint.encode()),
            *(("request-a-" + str(index), raw)
              for index, raw in enumerate(proxy_a.raw_urls)),
            *(("request-b-" + str(index), raw)
              for index, raw in enumerate(proxy_b.raw_urls)),
        ]
        output_objects = [
            ("wallet-output-" + str(index) + "-stdout", pair[0])
            for index, pair in enumerate(session.outputs)] + [
            ("wallet-output-" + str(index) + "-stderr", pair[1])
            for index, pair in enumerate(session.outputs)]
        surfaces = {
            "validator-homes": home_objects,
            "node-databases": database_objects,
            "snapshots": network.snapshot_objects,
            "reports": report_objects + [(
                "report", canonical_json({
                    "checks": report["checks"],
                    "claims": report["claims"]}))],
            "artifacts": list(public_payloads.items()),
            "logs": log_objects,
            "process-argv": process_argv,
            "process-environ": process_environ,
            "transaction-v1": transaction_objects,
            "public-manifests": manifest_objects,
            "urls": url_objects,
            "receipts": [("receipts", canonical_json(network.receipts))],
            "public-output": output_objects,
        }
        forbidden = [
            b"1SFTWIT1", b"1SFTPRV1", NOTE_CAPSULE_FORMAT.encode(),
            *(raw for _name, raw in request_objects),
            *(raw for _name, raw in capsule_objects),
        ]
        leakage_surfaces = []
        for identity in settings["leakage_surfaces"]:
            objects = surfaces[identity]
            if not objects or sum(len(raw) for _name, raw in objects) == 0:
                raise RuntimeError("empty leakage scan surface")
            result = scan_objects(
                objects, known_secrets, forbidden=forbidden)
            leakage_surfaces.append({"id": identity, **result})
        if any(row["matches"] for row in leakage_surfaces):
            raise RuntimeError("private material leaked into public surfaces")
        leakage = {
            "format": "1soft/protocol5-wallet-leakage-scan/v1",
            "known_secret_count": len(known_secrets),
            "encodings": ["raw", "hex", "base64", "decimal"],
            "private_journals_excluded": True,
            "witness_present": False,
            "prover_request_present": False,
            "capsule_present": False,
            "surfaces": leakage_surfaces,
        }
        public_payloads["leakage-scan.json"] = canonical_json(leakage) + b"\n"
        if set(public_payloads) != set(settings["artifact_names"]):
            raise RuntimeError("public artifact roster differs")
        artifact_directory = output.with_name(output.name + ".artifacts")
        artifact_directory.mkdir(mode=0o700)
        for name in settings["artifact_names"]:
            _write_bytes(artifact_directory / name, public_payloads[name])
        report["artifacts"] = artifact_manifest(
            artifact_directory, settings)
        _write_json(artifact_directory / "manifest.json", report["artifacts"])
    finally:
        for proxy in proxies:
            proxy.close()
        if network is not None:
            network.close()

def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__, allow_abbrev=False)
    for name in INPUT_NAMES:
        parser.add_argument("--" + name, type=Path)
    parser.add_argument("--expected-client-sha256")
    parser.add_argument("--expected-prover-sha256")
    parser.add_argument("--output", type=Path, required=True)
    try:
        args = parser.parse_args()
        report = preflight(
            output=args.output,
            expected_client_sha256=args.expected_client_sha256,
            expected_prover_sha256=args.expected_prover_sha256,
            **{name: getattr(args, name) for name in INPUT_NAMES})
        return 1 if report["status"] == "failed" else 0
    except (OSError, ValueError, RuntimeError, subprocess.SubprocessError):
        print("Protocol 5 wallet qualification refused", file=sys.stderr)
        return 2

if __name__ == "__main__":
    raise SystemExit(main())
