#!/usr/bin/env python3
"""Source-bound offline verifier for the isolated privacy proof benchmark."""
from __future__ import annotations

import argparse
import hashlib
import io
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import tempfile
import time
import unittest


ROOT = Path(__file__).resolve().parents[1]
REPO = ROOT.parents[1]
SRC = ROOT / "src"
TESTS = ROOT / "tests"
GO = ROOT / "go"
sys.path.insert(0, str(SRC))

from privacy_proof_benchmark import (  # noqa: E402
    EXPECTED_CLAIMS,
    EXPECTED_UNASSESSED,
    QualificationError,
    load_unique_json_bytes,
    validate_backend_receipt,
)


HEX40 = re.compile(r"[0-9a-f]{40}\Z")
HEX64 = re.compile(r"[0-9a-f]{64}\Z")
TEST_ID = re.compile(r"[A-Za-z_]\w*(?:\.[A-Za-z_]\w*)+\Z")
RUST_TEST_ID = re.compile(r"[A-Za-z_]\w*(?:::[A-Za-z_]\w*)+\Z")
NETWORK_POLICY = "linux-user-and-network-namespace"
NAMESPACE_MARKER = "ONE_SOFT_PRIVACY_PROOF_OFFLINE"
PARENT_NET_NAMESPACE = "ONE_SOFT_PRIVACY_PROOF_PARENT_NET_NAMESPACE"
PARENT_USER_NAMESPACE = "ONE_SOFT_PRIVACY_PROOF_PARENT_USER_NAMESPACE"
MAX_LOG_BYTES = 8 * 1024 * 1024
MIN_GO_VERSION = (1, 25, 7)
GO_VERSION = re.compile(r"go version go(\d+)\.(\d+)\.(\d+) linux/[a-z0-9_]+\Z")


class VerificationError(RuntimeError):
    pass


def fail(message):
    raise VerificationError(message)


def digest_bytes(data):
    return hashlib.sha256(data).hexdigest()


def digest_file(path):
    return digest_bytes(path.read_bytes())


def load_file_json(path):
    try:
        return load_unique_json_bytes(path.read_bytes())
    except (OSError, QualificationError) as exc:
        raise VerificationError("invalid JSON: " + path.name) from exc


def checked_git(*arguments):
    result = subprocess.run(
        ["git", "-C", str(REPO), *arguments],
        capture_output=True,
        text=True,
        check=False,
        timeout=30,
    )
    if result.returncode != 0:
        fail("git command failed")
    return result.stdout


def source_identity():
    commit = checked_git("rev-parse", "HEAD").strip()
    tree = checked_git("rev-parse", "HEAD^{tree}").strip()
    if not HEX40.fullmatch(commit) or not HEX40.fullmatch(tree):
        fail("invalid Git identity")
    if checked_git("rev-parse", "--is-shallow-repository").strip() != "false":
        fail("shallow repository refused")
    if checked_git("status", "--porcelain=v1", "--untracked-files=all"):
        fail("repository is not clean")
    return {"commit": commit, "tree": tree}


def _safe_relative(value):
    path = Path(value) if type(value) is str else None
    return (
        path is not None
        and bool(value)
        and not path.is_absolute()
        and "\\" not in value
        and ".." not in path.parts
        and "." not in path.parts
        and path.as_posix() == value
        and value != "SOURCE_MANIFEST.json"
    )


def validate_manifest(manifest):
    fields = {
        "format",
        "package",
        "files",
        "python_tests",
        "go_tests",
        "rust_tests",
        "circuit_files",
        "halo2_circuit_files",
    }
    if (
        type(manifest) is not dict
        or set(manifest) != fields
        or type(manifest.get("format")) is not int
        or manifest["format"] != 2
        or manifest.get("package") != "privacy-proof-benchmark"
    ):
        fail("invalid manifest schema")
    files = manifest["files"]
    if type(files) is not list or not files:
        fail("empty manifest")
    seen = []
    for entry in files:
        if type(entry) is not dict or set(entry) != {"path", "bytes", "sha256"}:
            fail("invalid manifest entry")
        relative = entry["path"]
        if not _safe_relative(relative) or relative in seen:
            fail("unsafe or duplicate manifest path")
        if (
            type(entry["bytes"]) is not int
            or entry["bytes"] < 0
            or type(entry["sha256"]) is not str
            or not HEX64.fullmatch(entry["sha256"])
        ):
            fail("invalid manifest digest")
        seen.append(relative)
    actual = []
    manifest_path = ROOT / "SOURCE_MANIFEST.json"
    for path in ROOT.rglob("*"):
        if path.is_symlink():
            fail("symlink present in component")
        if path.name.endswith(".pyc") or "__pycache__" in path.parts:
            fail("Python bytecode present in component")
        if path.is_file() and path != manifest_path:
            actual.append(path.relative_to(ROOT).as_posix())
    if sorted(seen) != sorted(actual):
        fail("manifest membership mismatch")

    python_tests = manifest["python_tests"]
    go_tests = manifest["go_tests"]
    rust_tests = manifest["rust_tests"]
    if (
        type(python_tests) is not list
        or not python_tests
        or len(set(python_tests)) != len(python_tests)
        or any(type(item) is not str or not TEST_ID.fullmatch(item) for item in python_tests)
        or type(go_tests) is not list
        or not go_tests
        or len(set(go_tests)) != len(go_tests)
        or any(type(item) is not str or not item.startswith("Test") for item in go_tests)
        or type(rust_tests) is not list
        or not rust_tests
        or len(set(rust_tests)) != len(rust_tests)
        or any(type(item) is not str or not RUST_TEST_ID.fullmatch(item) for item in rust_tests)
    ):
        fail("invalid test inventory")

    circuit_files = manifest["circuit_files"]
    if (
        type(circuit_files) is not list
        or not circuit_files
        or circuit_files != sorted(set(circuit_files))
        or any(
            not _safe_relative(item)
            or not item.startswith("go/")
            or not item.endswith(".go")
            or item.endswith("_test.go")
            or item not in seen
            for item in circuit_files
        )
    ):
        fail("invalid Groth16 circuit source inventory")

    halo2_circuit_files = manifest["halo2_circuit_files"]
    if (
        type(halo2_circuit_files) is not list
        or not halo2_circuit_files
        or halo2_circuit_files != sorted(set(halo2_circuit_files))
        or any(
            not _safe_relative(item)
            or not item.startswith("halo2/src/")
            or not item.endswith(".rs")
            or item not in seen
            for item in halo2_circuit_files
        )
    ):
        fail("invalid Halo2 circuit source inventory")
    return manifest


def verify_manifest_files(manifest):
    for entry in manifest["files"]:
        path = ROOT / entry["path"]
        if (
            not path.is_file()
            or path.is_symlink()
            or path.stat().st_size != entry["bytes"]
            or digest_file(path) != entry["sha256"]
        ):
            fail("component changed: " + entry["path"])


def circuit_digest(manifest):
    value = hashlib.sha256()
    for relative in manifest["circuit_files"]:
        data = (ROOT / relative).read_bytes()
        value.update(relative.encode("utf-8"))
        value.update(b"\0")
        value.update(str(len(data)).encode("ascii"))
        value.update(b"\0")
        value.update(data)
    return value.hexdigest()


def flatten(suite):
    for item in suite:
        if isinstance(item, unittest.TestSuite):
            yield from flatten(item)
        else:
            yield item


class Result(unittest.TextTestResult):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.successful_ids = []

    def addSuccess(self, test):
        super().addSuccess(test)
        self.successful_ids.append(test.id())


def run_python_tests(expected, log_path):
    previous = sys.dont_write_bytecode
    sys.dont_write_bytecode = True
    try:
        suite = unittest.TestLoader().discover(str(TESTS), pattern="test_*.py")
        observed = [test.id() for test in flatten(suite)]
        if observed != expected:
            fail("Python test inventory differs")
        stream = io.StringIO()
        result = unittest.TextTestRunner(
            stream=stream, verbosity=2, resultclass=Result
        ).run(suite)
        raw = stream.getvalue().encode("utf-8")
        write_exclusive(log_path, raw)
        if (
            not result.wasSuccessful()
            or result.testsRun != len(expected)
            or result.successful_ids != expected
        ):
            fail("Python contract tests failed")
        return expected
    finally:
        sys.dont_write_bytecode = previous


def write_exclusive(path, data):
    if len(data) > MAX_LOG_BYTES:
        fail("log exceeds bound")
    path.parent.mkdir(parents=True, exist_ok=True)
    try:
        with path.open("xb") as handle:
            handle.write(data)
    except FileExistsError as exc:
        raise VerificationError("output already exists: " + path.name) from exc


def run_logged(command, cwd, log_path, timeout):
    started = time.monotonic_ns()
    try:
        result = subprocess.run(
            command,
            cwd=cwd,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            check=False,
            timeout=timeout,
            env=os.environ.copy(),
        )
    except subprocess.TimeoutExpired as exc:
        raw = (exc.stdout or b"") + (exc.stderr or b"")
        write_exclusive(log_path, raw[:MAX_LOG_BYTES])
        fail("process timed out: " + command[0])
    raw = result.stdout
    write_exclusive(log_path, raw)
    return {
        "returncode": result.returncode,
        "seconds_ns": time.monotonic_ns() - started,
        "log": log_path.name,
        "log_sha256": digest_bytes(raw),
        "log_bytes": len(raw),
    }, raw


def parse_go_tests(raw, expected):
    passed = []
    for line in raw.splitlines():
        try:
            event = json.loads(line)
        except json.JSONDecodeError as exc:
            raise VerificationError("invalid Go JSON test log") from exc
        if event.get("Action") == "pass" and type(event.get("Test")) is str:
            passed.append(event["Test"])
        if event.get("Action") == "fail" and event.get("Test"):
            fail("Go test failed: " + str(event["Test"]))
    if passed != expected:
        fail("Go test inventory differs")
    return passed


def output_paths(report):
    report = Path(os.path.abspath(report))
    try:
        if report.is_relative_to(REPO.resolve()):
            fail("report must be outside repository")
    except ValueError:
        pass
    for parent in (report.parent, *report.parent.parents):
        if parent.is_symlink():
            fail("output ancestor symlink refused")
    if report.exists():
        fail("report already exists")
    stem = report.stem
    paths = {
        "report": report,
        "python": report.with_name(stem + ".python.log"),
        "go_test": report.with_name(stem + ".go-test.log"),
        "go_build": report.with_name(stem + ".go-build.log"),
        "benchmark": report.with_name(stem + ".benchmark.log"),
        "backend": report.with_name(stem + ".backend.json"),
    }
    if any(path.exists() for path in paths.values()):
        fail("owned output already exists")
    return paths


def validate_go_version(value):
    match = GO_VERSION.fullmatch(value)
    if match is None or tuple(int(part) for part in match.groups()) < MIN_GO_VERSION:
        fail("Go toolchain is older than go1.25.7 or is not a stable Linux release")
    return value


def go_version():
    result = subprocess.run(
        ["go", "version"], capture_output=True, text=True, check=False, timeout=30
    )
    value = result.stdout.strip()
    if result.returncode != 0:
        fail("Go toolchain unavailable")
    return validate_go_version(value)


def namespace_identity(kind):
    if kind not in {"net", "user"}:
        fail("invalid namespace kind")
    value = os.readlink("/proc/self/ns/" + kind)
    if not re.fullmatch(kind + r":\[[0-9]+\]", value):
        fail("invalid " + kind + " namespace identity")
    return value


def require_offline_worker():
    if os.name != "posix" or os.environ.get(NAMESPACE_MARKER) != "1":
        fail("offline namespace worker required")
    parent_net = os.environ.get(PARENT_NET_NAMESPACE)
    parent_user = os.environ.get(PARENT_USER_NAMESPACE)
    if (
        parent_net is None
        or parent_user is None
        or namespace_identity("net") == parent_net
        or namespace_identity("user") == parent_user
    ):
        fail("fresh Linux user and network namespaces were not established")


def verify(report, iterations, timeout):
    require_offline_worker()
    if type(iterations) is not int or not 1 <= iterations <= 10:
        fail("invalid benchmark iterations")
    paths = output_paths(report)
    source = source_identity()
    manifest_path = ROOT / "SOURCE_MANIFEST.json"
    manifest_bytes = manifest_path.read_bytes()
    manifest = validate_manifest(load_unique_json_bytes(manifest_bytes))
    verify_manifest_files(manifest)
    circuit_source_digest = circuit_digest(manifest)
    python_tests = run_python_tests(manifest["python_tests"], paths["python"])

    go_test, go_test_raw = run_logged(
        ["go", "test", "-json", "-count=1", "-mod=readonly", "./..."],
        GO,
        paths["go_test"],
        timeout,
    )
    if go_test["returncode"] != 0:
        fail("Go tests failed")
    go_tests = parse_go_tests(go_test_raw, manifest["go_tests"])

    with tempfile.TemporaryDirectory(prefix="1soft-proof-benchmark-") as temp:
        binary = Path(temp) / "privacy-proof-benchmark"
        go_build, _ = run_logged(
            ["go", "build", "-mod=readonly", "-trimpath", "-o", str(binary), "./cmd/benchmark"],
            GO,
            paths["go_build"],
            timeout,
        )
        if go_build["returncode"] != 0 or not binary.is_file():
            fail("Go benchmark build failed")
        benchmark, _ = run_logged(
            [
                str(binary),
                "--report",
                str(paths["backend"]),
                "--commit",
                source["commit"],
                "--tree",
                source["tree"],
                "--circuit-digest",
                circuit_source_digest,
                "--iterations",
                str(iterations),
            ],
            GO,
            paths["benchmark"],
            timeout,
        )
        if benchmark["returncode"] != 0:
            fail("benchmark execution failed")

    if (
        not paths["backend"].is_file()
        or paths["backend"].is_symlink()
        or paths["backend"].stat().st_size > 1_048_576
    ):
        fail("invalid backend receipt file")
    backend_bytes = paths["backend"].read_bytes()
    backend = validate_backend_receipt(
        load_unique_json_bytes(backend_bytes),
        expected_commit=source["commit"],
        expected_tree=source["tree"],
        expected_circuit_digest=circuit_source_digest,
    )
    if backend["metrics"]["iterations"] != iterations:
        fail("benchmark iteration count differs")
    if source_identity() != source:
        fail("source changed during verification")

    dependency_bytes = (ROOT / "DEPENDENCIES.json").read_bytes()
    record = {
        "format": 1,
        "status": "passed",
        **source,
        "manifest_sha256": digest_bytes(manifest_bytes),
        "source_id": digest_bytes(manifest_bytes + dependency_bytes),
        "circuit_source_digest": circuit_source_digest,
        "python": sys.version,
        "go": go_version(),
        "python_tests": python_tests,
        "go_tests": go_tests,
        "logs": {
            "python": {
                "path": paths["python"].name,
                "sha256": digest_file(paths["python"]),
                "bytes": paths["python"].stat().st_size,
            },
            "go_test": go_test,
            "go_build": go_build,
            "benchmark": benchmark,
        },
        "backend_receipt": {
            "path": paths["backend"].name,
            "sha256": digest_bytes(backend_bytes),
            "bytes": len(backend_bytes),
            "value": backend,
        },
        "network_policy": NETWORK_POLICY,
        "network_used": False,
        "claims": dict(EXPECTED_CLAIMS),
        "unassessed": list(EXPECTED_UNASSESSED),
    }
    write_exclusive(
        paths["report"],
        (json.dumps(record, sort_keys=True, separators=(",", ":")) + "\n").encode("utf-8"),
    )
    print(json.dumps({"status": "passed", "tests": len(python_tests) + len(go_tests)}))
    return 0


def relaunch_in_namespace(arguments):
    environment = os.environ.copy()
    environment.update(
        {
            NAMESPACE_MARKER: "1",
            PARENT_NET_NAMESPACE: namespace_identity("net"),
            PARENT_USER_NAMESPACE: namespace_identity("user"),
            "PYTHONDONTWRITEBYTECODE": "1",
            "PYTHONNOUSERSITE": "1",
            "GOTOOLCHAIN": "local",
            "GOPROXY": "off",
            "GOSUMDB": "off",
            "GOVCS": "*:off",
            "GOENV": "off",
        }
    )
    result = subprocess.run(
        ["unshare", "-Urn", "--", sys.executable, "-B", str(Path(__file__).resolve()),
         "--namespace-worker", *arguments],
        env=environment,
        check=False,
    )
    return result.returncode


def main(argv=None):
    parser = argparse.ArgumentParser()
    parser.add_argument("--namespace-worker", action="store_true", help=argparse.SUPPRESS)
    parser.add_argument("--report", required=True)
    parser.add_argument("--iterations", type=int, default=3)
    parser.add_argument("--timeout", type=int, default=600)
    args = parser.parse_args(argv)
    if not args.namespace_worker:
        forwarded = [
            "--report",
            args.report,
            "--iterations",
            str(args.iterations),
            "--timeout",
            str(args.timeout),
        ]
        return relaunch_in_namespace(forwarded)
    try:
        if not 30 <= args.timeout <= 1800:
            fail("invalid timeout")
        return verify(args.report, args.iterations, args.timeout)
    except (OSError, VerificationError, QualificationError, subprocess.SubprocessError) as exc:
        print(type(exc).__name__ + ": " + str(exc), file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
