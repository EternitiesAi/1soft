#!/usr/bin/env python3
"""Source-bound offline verifier for the Halo2/Pasta privacy proof benchmark."""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys
import tempfile

import verify as base

ROOT = base.ROOT
REPO = base.REPO
RUST = ROOT / "halo2"
sys.path.insert(0, str(ROOT / "src"))

from privacy_proof_benchmark import (  # noqa: E402
    EXPECTED_CLAIMS,
    EXPECTED_HALO2_UNASSESSED,
    QualificationError,
    load_unique_json_bytes,
    validate_halo2_backend_receipt,
)

RUST_TEST = re.compile(r"^test ([A-Za-z_]\w*(?:::[A-Za-z_]\w*)+) \.\.\. ok$", re.MULTILINE)
RUSTC_VERSION = re.compile(
    r"rustc (\d+)\.(\d+)\.(\d+) \([0-9a-f]+ \d{4}-\d{2}-\d{2}\)\Z"
)
CARGO_VERSION = re.compile(
    r"cargo (\d+)\.(\d+)\.(\d+) \([0-9a-f]+ \d{4}-\d{2}-\d{2}\)\Z"
)
MIN_RUST = (1, 88, 0)
PINNED_RUST_TOOLCHAIN = "1.97.1"


def digest_bytes(data):
    return hashlib.sha256(data).hexdigest()


def rust_tool(name):
    candidate = shutil.which(name)
    if candidate is None:
        local = Path.home() / ".cargo/bin" / name
        if local.exists():
            candidate = str(local)
    if candidate is None:
        base.fail(name + " toolchain unavailable")
    return candidate


def checked_version(name, pattern):
    executable = rust_tool(name)
    result = subprocess.run(
        [executable, "--version"],
        capture_output=True,
        text=True,
        check=False,
        timeout=30,
    )
    value = result.stdout.strip()
    match = pattern.fullmatch(value)
    if (
        result.returncode != 0
        or match is None
        or tuple(int(part) for part in match.groups()) < MIN_RUST
    ):
        base.fail(name + " is older than 1.88.0 or is not a stable Linux release")
    return executable, value


def halo2_circuit_digest(manifest):
    value = hashlib.sha256()
    for relative in manifest["halo2_circuit_files"]:
        data = (ROOT / relative).read_bytes()
        value.update(relative.encode("utf-8"))
        value.update(b"\0")
        value.update(str(len(data)).encode("ascii"))
        value.update(b"\0")
        value.update(data)
    return value.hexdigest()


def output_paths(report):
    report = Path(os.path.abspath(report))
    try:
        if report.is_relative_to(REPO.resolve()):
            base.fail("report must be outside repository")
    except ValueError:
        pass
    for parent in (report.parent, *report.parent.parents):
        if parent.is_symlink():
            base.fail("output ancestor symlink refused")
    if report.exists():
        base.fail("report already exists")
    stem = report.stem
    paths = {
        "report": report,
        "python": report.with_name(stem + ".python.log"),
        "rust_test": report.with_name(stem + ".rust-test.log"),
        "rust_build": report.with_name(stem + ".rust-build.log"),
        "benchmark": report.with_name(stem + ".benchmark.log"),
        "backend": report.with_name(stem + ".backend.json"),
    }
    if any(path.exists() for path in paths.values()):
        base.fail("owned output already exists")
    return paths


def parse_rust_tests(raw, expected):
    text = raw.decode("utf-8", errors="strict")
    observed = RUST_TEST.findall(text)
    if len(observed) != len(set(observed)) or sorted(observed) != sorted(expected):
        base.fail("Rust test inventory differs")
    summary = re.search(
        r"test result: ok\. (\d+) passed; 0 failed; 0 ignored; 0 measured; 0 filtered out;",
        text,
    )
    if summary is None or int(summary.group(1)) != len(expected):
        base.fail("Rust test summary differs")
    return sorted(observed)


def evidence_file(path, expected_name, sha256, size):
    return (
        type(path) is str
        and path == expected_name
        and Path(path).name == path
        and type(sha256) is str
        and base.HEX64.fullmatch(sha256) is not None
        and type(size) is int
        and size >= 0
    )


def verify(report, iterations, timeout):
    base.require_offline_worker()
    if type(iterations) is not int or not 1 <= iterations <= 10:
        base.fail("invalid benchmark iterations")
    paths = output_paths(report)
    source = base.source_identity()
    manifest_path = ROOT / "SOURCE_MANIFEST.json"
    manifest_bytes = manifest_path.read_bytes()
    manifest = base.validate_manifest(load_unique_json_bytes(manifest_bytes))
    base.verify_manifest_files(manifest)
    circuit_source_digest = halo2_circuit_digest(manifest)
    python_tests = base.run_python_tests(manifest["python_tests"], paths["python"])

    environment = os.environ
    environment["CARGO_NET_OFFLINE"] = "true"
    environment["RUSTUP_TOOLCHAIN"] = PINNED_RUST_TOOLCHAIN
    environment["RUST_BACKTRACE"] = "0"
    _, rustc_version = checked_version("rustc", RUSTC_VERSION)
    cargo_executable, cargo_version = checked_version("cargo", CARGO_VERSION)

    with tempfile.TemporaryDirectory(prefix="1soft-halo2-target-") as temp:
        environment["CARGO_TARGET_DIR"] = str(Path(temp) / "target")
        rust_test, rust_test_raw = base.run_logged(
            [
                cargo_executable,
                "test",
                "--locked",
                "--offline",
                "--lib",
                "--",
                "--nocapture",
                "--test-threads=1",
            ],
            RUST,
            paths["rust_test"],
            timeout,
        )
        if rust_test["returncode"] != 0:
            base.fail("Rust tests failed")
        rust_tests = parse_rust_tests(rust_test_raw, manifest["rust_tests"])

        rust_build, _ = base.run_logged(
            [
                cargo_executable,
                "build",
                "--locked",
                "--offline",
                "--release",
                "--bin",
                "privacy-proof-benchmark-halo2",
            ],
            RUST,
            paths["rust_build"],
            timeout,
        )
        binary = Path(environment["CARGO_TARGET_DIR"]) / "release" / (
            "privacy-proof-benchmark-halo2"
        )
        if rust_build["returncode"] != 0 or not binary.is_file():
            base.fail("Rust benchmark build failed")

        benchmark, _ = base.run_logged(
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
            RUST,
            paths["benchmark"],
            timeout,
        )
        if benchmark["returncode"] != 0:
            base.fail("Halo2 benchmark execution failed")

    if (
        not paths["backend"].is_file()
        or paths["backend"].is_symlink()
        or paths["backend"].stat().st_size > 1_048_576
    ):
        base.fail("invalid Halo2 backend receipt file")
    backend_bytes = paths["backend"].read_bytes()
    backend = validate_halo2_backend_receipt(
        load_unique_json_bytes(backend_bytes),
        expected_commit=source["commit"],
        expected_tree=source["tree"],
        expected_circuit_digest=circuit_source_digest,
    )
    if backend["metrics"]["iterations"] != iterations:
        base.fail("Halo2 benchmark iteration count differs")
    if base.source_identity() != source:
        base.fail("source changed during Halo2 verification")

    dependency_bytes = (ROOT / "DEPENDENCIES_HALO2.json").read_bytes()
    record = {
        "format": 1,
        "status": "passed",
        **source,
        "manifest_sha256": digest_bytes(manifest_bytes),
        "source_id": digest_bytes(manifest_bytes + dependency_bytes),
        "circuit_source_digest": circuit_source_digest,
        "python": sys.version,
        "rustc": rustc_version,
        "cargo": cargo_version,
        "python_tests": python_tests,
        "rust_tests": rust_tests,
        "logs": {
            "python": {
                "path": paths["python"].name,
                "sha256": base.digest_file(paths["python"]),
                "bytes": paths["python"].stat().st_size,
            },
            "rust_test": rust_test,
            "rust_build": rust_build,
            "benchmark": benchmark,
        },
        "backend_receipt": {
            "path": paths["backend"].name,
            "sha256": digest_bytes(backend_bytes),
            "bytes": len(backend_bytes),
            "value": backend,
        },
        "network_policy": base.NETWORK_POLICY,
        "network_used": False,
        "claims": dict(EXPECTED_CLAIMS),
        "unassessed": list(EXPECTED_HALO2_UNASSESSED),
    }
    base.write_exclusive(
        paths["report"],
        (json.dumps(record, sort_keys=True, separators=(",", ":")) + "\n").encode(
            "utf-8"
        ),
    )
    print(
        json.dumps(
            {
                "status": "passed",
                "tests": len(python_tests) + len(rust_tests),
                "proof_bytes": backend["artifacts"]["proof_bytes"],
            }
        )
    )
    return 0


def relaunch_in_namespace(arguments):
    environment = os.environ.copy()
    environment.update(
        {
            base.NAMESPACE_MARKER: "1",
            base.PARENT_NET_NAMESPACE: base.namespace_identity("net"),
            base.PARENT_USER_NAMESPACE: base.namespace_identity("user"),
            "PYTHONDONTWRITEBYTECODE": "1",
            "PYTHONNOUSERSITE": "1",
            "CARGO_NET_OFFLINE": "true",
            "RUSTUP_TOOLCHAIN": PINNED_RUST_TOOLCHAIN,
            "RUST_BACKTRACE": "0",
        }
    )
    result = subprocess.run(
        [
            "unshare",
            "-Urn",
            "--",
            sys.executable,
            "-B",
            str(Path(__file__).resolve()),
            "--namespace-worker",
            *arguments,
        ],
        env=environment,
        check=False,
    )
    return result.returncode


def main(argv=None):
    parser = argparse.ArgumentParser()
    parser.add_argument("--namespace-worker", action="store_true", help=argparse.SUPPRESS)
    parser.add_argument("--report", required=True)
    parser.add_argument("--iterations", type=int, default=3)
    parser.add_argument("--timeout", type=int, default=900)
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
        return verify(args.report, args.iterations, args.timeout)
    except (
        OSError,
        ValueError,
        TypeError,
        UnicodeDecodeError,
        json.JSONDecodeError,
        QualificationError,
        base.VerificationError,
        subprocess.SubprocessError,
    ) as exc:
        print(
            json.dumps({"status": "failed", "error_type": type(exc).__name__}),
            file=sys.stderr,
        )
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
