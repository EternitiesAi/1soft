"""Strict verifier for the isolated shielded-note transition laboratory.

This verifier is an evidence harness, not an operating-system sandbox.  It
refuses Python socket/DNS APIs in the test process, restricts spawned processes
to the current Python interpreter, and injects the same deny policy into those
children before user code runs.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import socket
import subprocess
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
REPO = ROOT.parents[1]
SRC = ROOT / "src"
OFFLINE_POLICY = "python-process-and-python-child-deny"
NETWORK_TEST_NAME = "test_network_access_is_denied"
HEX40 = re.compile(r"[0-9a-f]{40}\Z")
HEX64 = re.compile(r"[0-9a-f]{64}\Z")
TEST_ID = re.compile(r"[A-Za-z_]\w*(?:\.[A-Za-z_]\w*)+\Z")
UNASSESSED = [
    "independent cryptographic review",
    "consensus integration",
    "network anonymity",
    "production custody",
    "external audit",
]
CLAIMS = {
    "production_privacy": False,
    "zero_knowledge": False,
    "consensus_integrated": False,
    "public_network": False,
    "real_funds": False,
}
blocked_attempts = [0]


class VerificationError(RuntimeError):
    pass


def fail(message: str) -> None:
    raise VerificationError(message)


def digest(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def load_json(path: Path):
    def unique_object(pairs):
        value = {}
        for key, item in pairs:
            if key in value:
                fail("duplicate JSON key: " + key)
            value[key] = item
        return value

    try:
        return json.loads(path.read_text(encoding="utf-8"),
                          object_pairs_hook=unique_object)
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise VerificationError("invalid JSON: " + path.name) from exc


def checked_git(*arguments: str) -> str:
    result = subprocess.run(
        ["git", "-C", str(REPO), *arguments],
        capture_output=True,
        text=True,
        check=False,
    )
    if result.returncode != 0:
        fail("git command failed")
    return result.stdout


def git_identity() -> tuple[str, str]:
    commit = checked_git("rev-parse", "HEAD").strip()
    tree = checked_git("rev-parse", "HEAD^{tree}").strip()
    if not HEX40.fullmatch(commit) or not HEX40.fullmatch(tree):
        fail("invalid git identity")
    return commit, tree


def require_clean(label: str) -> None:
    status = checked_git(
        "status", "--porcelain=v1", "--untracked-files=all"
    )
    if status:
        fail("repository is not clean " + label)


def inventory(manifest: dict) -> list[str]:
    required = {"format", "package", "files", "tests"}
    if (
        type(manifest) is not dict
        or set(manifest) != required
        or manifest["format"] != 2
        or manifest["package"] != "shielded-note-lab"
        or type(manifest["files"]) is not list
        or not manifest["files"]
        or type(manifest["tests"]) is not list
        or not manifest["tests"]
    ):
        fail("invalid manifest schema")

    seen: list[str] = []
    for entry in manifest["files"]:
        if type(entry) is not dict or set(entry) != {"path", "bytes", "sha256"}:
            fail("invalid manifest entry")
        relative = entry["path"]
        candidate = Path(relative) if type(relative) is str else None
        if (
            candidate is None
            or not relative
            or candidate.is_absolute()
            or "\\" in relative
            or ".." in candidate.parts
            or "." in candidate.parts
            or candidate.as_posix() != relative
            or relative == "SOURCE_MANIFEST.json"
            or relative in seen
        ):
            fail("unsafe or duplicate manifest path")
        if (
            type(entry["bytes"]) is not int
            or entry["bytes"] < 0
            or type(entry["sha256"]) is not str
            or not HEX64.fullmatch(entry["sha256"])
        ):
            fail("invalid manifest digest")
        seen.append(relative)

    actual: list[str] = []
    root_manifest = ROOT / "SOURCE_MANIFEST.json"
    for path in ROOT.rglob("*"):
        if path.is_symlink():
            fail("symlink present in component")
        if path.name.endswith(".pyc") or "__pycache__" in path.parts:
            fail("bytecode present in component")
        if path.is_file() and path != root_manifest:
            actual.append(path.relative_to(ROOT).as_posix())
    if sorted(seen) != sorted(actual):
        fail("manifest membership mismatch")

    tests = manifest["tests"]
    if (
        any(type(test) is not str or not TEST_ID.fullmatch(test) for test in tests)
        or len(set(tests)) != len(tests)
    ):
        fail("invalid or duplicate test inventory")
    return seen


def check_files(manifest: dict) -> None:
    for entry in manifest["files"]:
        path = ROOT / entry["path"]
        if (
            not path.is_file()
            or path.is_symlink()
            or path.stat().st_size != entry["bytes"]
            or digest(path) != entry["sha256"]
        ):
            fail("component changed: " + entry["path"])


def flatten(suite):
    for item in suite:
        if isinstance(item, unittest.TestSuite):
            yield from flatten(item)
        else:
            yield item


def deny_network(*_args, **_kwargs):
    blocked_attempts[0] += 1
    raise RuntimeError("network blocked by 1soft verifier")


CHILD_DENY_SOURCE = r'''"""Injected by the 1soft verifier before child user code."""
import os
import socket
import subprocess
import sys

def _deny(*_args, **_kwargs):
    raise RuntimeError("network blocked by 1soft verifier child")

class _BlockedSocket(socket.socket):
    connect = connect_ex = send = sendall = sendto = sendmsg = _deny
    bind = listen = accept = accept4 = _deny

socket.socket = _BlockedSocket
for _name in (
    "create_connection", "create_server", "getaddrinfo", "gethostbyname",
    "gethostbyname_ex", "gethostbyaddr", "getnameinfo",
):
    if hasattr(socket, _name):
        setattr(socket, _name, _deny)

_real_popen = subprocess.Popen
_safe_pythonpath = os.environ.get("PYTHONPATH", "")
class _PythonOnly(_real_popen):
    def __init__(self, args, *positional, **kwargs):
        if (
            not isinstance(args, (list, tuple))
            or not args
            or positional
            or any(type(arg) is not str for arg in args)
            or os.path.realpath(args[0]) != os.path.realpath(sys.executable)
            or kwargs.get("shell")
            or kwargs.get("executable") is not None
            or any(
                arg.startswith("-")
                and any(flag in arg[1:] for flag in "SIE")
                for arg in args[1:]
            )
        ):
            _deny()
        child_env = dict(
            os.environ if kwargs.get("env") is None else kwargs["env"]
        )
        child_env["PYTHONPATH"] = _safe_pythonpath
        child_env["PYTHONDONTWRITEBYTECODE"] = "1"
        child_env["PYTHONNOUSERSITE"] = "1"
        child_env["1SOFT_SHIELDED_OFFLINE"] = "1"
        kwargs["env"] = child_env
        if os.name == "posix":
            if kwargs.get("preexec_fn") is not None:
                _deny()
            kwargs["preexec_fn"] = lambda: None
        super().__init__(args, *positional, **kwargs)

subprocess.Popen = _PythonOnly
os.system = _deny
for _name in (
    "fork", "forkpty", "posix_spawn", "posix_spawnp",
    "spawnl", "spawnle", "spawnlp", "spawnlpe",
    "spawnv", "spawnve", "spawnvp", "spawnvpe",
    "execl", "execle", "execlp", "execlpe",
    "execv", "execve", "execvp", "execvpe",
):
    if hasattr(os, _name):
        setattr(os, _name, _deny)
'''


class OfflineHarness:
    SOCKET_FUNCTIONS = (
        "create_connection",
        "create_server",
        "getaddrinfo",
        "gethostbyname",
        "gethostbyname_ex",
        "gethostbyaddr",
        "getnameinfo",
    )
    OS_FUNCTIONS = (
        "fork",
        "forkpty",
        "posix_spawn",
        "posix_spawnp",
        "spawnl",
        "spawnle",
        "spawnlp",
        "spawnlpe",
        "spawnv",
        "spawnve",
        "spawnvp",
        "spawnvpe",
        "execl",
        "execle",
        "execlp",
        "execlpe",
        "execv",
        "execve",
        "execvp",
        "execvpe",
    )
    ENVIRONMENT = (
        "PYTHONPATH",
        "PYTHONDONTWRITEBYTECODE",
        "PYTHONNOUSERSITE",
        "1SOFT_SHIELDED_OFFLINE",
    )

    def __init__(self):
        self._old: dict[tuple[str, str], object] = {}
        self._env: dict[str, str | None] = {}
        self._temporary = None
        self._dont_write_bytecode = None
        self.child_probe = None

    def __enter__(self):
        try:
            return self._enter()
        except BaseException:
            self.__exit__(*sys.exc_info())
            raise

    def _enter(self):
        blocked_attempts[0] = 0
        self._dont_write_bytecode = sys.dont_write_bytecode
        sys.dont_write_bytecode = True
        self._temporary = tempfile.TemporaryDirectory(prefix="1soft-offline-")
        deny_dir = Path(self._temporary.name)
        (deny_dir / "sitecustomize.py").write_text(
            CHILD_DENY_SOURCE, encoding="utf-8"
        )
        safe_path = os.pathsep.join((str(deny_dir), str(SRC)))

        for name in self.ENVIRONMENT:
            self._env[name] = os.environ.get(name)
        os.environ["PYTHONPATH"] = safe_path
        os.environ["PYTHONDONTWRITEBYTECODE"] = "1"
        os.environ["PYTHONNOUSERSITE"] = "1"
        os.environ["1SOFT_SHIELDED_OFFLINE"] = "1"

        self._old[("socket", "socket")] = socket.socket

        class BlockedSocket(socket.socket):
            connect = connect_ex = send = sendall = sendto = sendmsg = deny_network
            bind = listen = accept = accept4 = deny_network

        socket.socket = BlockedSocket
        for name in self.SOCKET_FUNCTIONS:
            if hasattr(socket, name):
                self._old[("socket", name)] = getattr(socket, name)
                setattr(socket, name, deny_network)

        self._old[("subprocess", "Popen")] = subprocess.Popen
        real_popen = subprocess.Popen
        current_python = os.path.realpath(sys.executable)

        class PythonOnly(real_popen):
            def __init__(self, args, *positional, **kwargs):
                forbidden_flag = any(
                    isinstance(arg, str)
                    and arg.startswith("-")
                    and any(flag in arg[1:] for flag in "SIE")
                    for arg in (args[1:] if isinstance(args, (list, tuple)) else ())
                )
                if (
                    not isinstance(args, (list, tuple))
                    or not args
                    or positional
                    or any(type(arg) is not str for arg in args)
                    or os.path.realpath(args[0]) != current_python
                    or kwargs.get("shell")
                    or kwargs.get("executable") is not None
                    or forbidden_flag
                ):
                    deny_network()
                child_env = dict(
                    os.environ if kwargs.get("env") is None else kwargs["env"]
                )
                child_env["PYTHONPATH"] = safe_path
                child_env["PYTHONDONTWRITEBYTECODE"] = "1"
                child_env["PYTHONNOUSERSITE"] = "1"
                child_env["1SOFT_SHIELDED_OFFLINE"] = "1"
                kwargs["env"] = child_env
                if os.name == "posix":
                    if kwargs.get("preexec_fn") is not None:
                        deny_network()
                    kwargs["preexec_fn"] = lambda: None
                super().__init__(args, *positional, **kwargs)

        subprocess.Popen = PythonOnly

        self._old[("os", "system")] = os.system
        os.system = deny_network
        for name in self.OS_FUNCTIONS:
            if hasattr(os, name):
                self._old[("os", name)] = getattr(os, name)
                setattr(os, name, deny_network)

        probe = subprocess.run(
            [
                sys.executable,
                "-c",
                "import socket; socket.getaddrinfo('example.invalid', 443)",
            ],
            capture_output=True,
            text=True,
            check=False,
        )
        if (
            probe.returncode == 0
            or "network blocked by 1soft verifier child" not in probe.stderr
        ):
            fail("child offline probe was not refused")
        self.child_probe = "blocked-before-child-user-network"
        return self

    def __exit__(self, _exc_type, _exc, _traceback):
        for (module, name), value in reversed(list(self._old.items())):
            target = socket if module == "socket" else (
                subprocess if module == "subprocess" else os
            )
            setattr(target, name, value)
        for name, value in self._env.items():
            if value is None:
                os.environ.pop(name, None)
            else:
                os.environ[name] = value
        if self._dont_write_bytecode is not None:
            sys.dont_write_bytecode = self._dont_write_bytecode
        if self._temporary is not None:
            self._temporary.cleanup()
        return False


def validate_dependencies() -> str:
    requirement_lines = (REPO / "requirements.txt").read_text(
        encoding="utf-8"
    ).splitlines()
    pins = [
        line.split("==", 1)[1]
        for line in requirement_lines
        if line.lower().startswith("cryptography==")
    ]
    import cryptography

    dependency = load_json(ROOT / "DEPENDENCIES.json")
    if (
        type(dependency) is not dict
        or set(dependency)
        != {
            "format",
            "python_minimum",
            "stdlib_only",
            "cryptography_version",
            "offline_policy",
        }
        or type(dependency["format"]) is not int
        or dependency["format"] != 1
        or dependency["python_minimum"] != "3.11+"
        or dependency["stdlib_only"] is not False
        or dependency["offline_policy"] != OFFLINE_POLICY
        or sys.version_info < (3, 11)
        or len(pins) != 1
        or dependency["cryptography_version"] != pins[0]
        or dependency["cryptography_version"] != cryptography.__version__
    ):
        fail("dependency contract mismatch")
    return cryptography.__version__


def report_target(raw_value: str) -> Path:
    raw = Path(raw_value)
    if any(part == ".." for part in raw.parts):
        fail("report path contains parent traversal")
    lexical = raw if raw.is_absolute() else Path.cwd() / raw
    for candidate in (lexical, lexical.parent, *lexical.parent.parents):
        if candidate.is_symlink():
            fail("report path has symlink ancestor")
    target = lexical.resolve(strict=False)
    if target.is_relative_to(ROOT) or target.is_relative_to(REPO):
        fail("report must be outside component and repository")
    if not target.parent.is_dir():
        fail("report parent must already exist")
    if target.exists() or target.is_symlink():
        fail("report already exists")
    return target


def publish_report(target: Path, report: dict) -> None:
    descriptor, temporary = tempfile.mkstemp(
        prefix=".1soft-shielded-verify-", dir=target.parent
    )
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8", newline="\n") as handle:
            json.dump(report, handle, sort_keys=True, indent=2)
            handle.write("\n")
            handle.flush()
            os.fsync(handle.fileno())
        os.link(temporary, target)
    except FileExistsError as exc:
        raise VerificationError("report already exists") from exc
    finally:
        Path(temporary).unlink(missing_ok=True)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--report")
    arguments = parser.parse_args()

    require_clean("before verification")
    identity_before = git_identity()
    manifest = load_json(ROOT / "SOURCE_MANIFEST.json")
    inventory(manifest)
    check_files(manifest)
    manifest_hash = digest(ROOT / "SOURCE_MANIFEST.json")
    expected = set(manifest["tests"])

    source_root = SRC.resolve()
    filtered_path = []
    for entry in sys.path:
        try:
            candidate = Path(entry or Path.cwd()).resolve()
        except (OSError, RuntimeError):
            candidate = None
        if candidate != source_root:
            filtered_path.append(entry)
    sys.path[:] = [str(SRC), *filtered_path]
    sys.modules.pop("shielded_note_lab", None)
    sys.modules.pop("test_note_lab", None)

    with OfflineHarness() as offline:
        suite = unittest.defaultTestLoader.discover(
            str(ROOT / "tests"), pattern="test_*.py"
        )
        source_module = sys.modules.get("shielded_note_lab")
        test_module = sys.modules.get("test_note_lab")
        if (
            source_module is None
            or test_module is None
            or Path(source_module.__file__).resolve()
            != (SRC / "shielded_note_lab.py").resolve()
            or Path(test_module.__file__).resolve()
            != (ROOT / "tests/test_note_lab.py").resolve()
        ):
            fail("test import escaped the manifest-bound source")
        ids = [test.id() for test in flatten(suite)]
        if (
            len(ids) != len(set(ids))
            or set(ids) != expected
            or sum(
                test_id.rsplit(".", 1)[-1] == NETWORK_TEST_NAME
                for test_id in ids
            )
            != 1
        ):
            fail("test inventory mismatch")
        result = unittest.TestResult()
        suite.run(result)

    log = (
        "tests="
        + json.dumps(ids, sort_keys=True)
        + " failures="
        + repr(result.failures)
        + " errors="
        + repr(result.errors)
        + " skips="
        + repr(result.skipped)
    )
    if (
        result.failures
        or result.errors
        or result.skipped
        or getattr(result, "expectedFailures", [])
        or getattr(result, "unexpectedSuccesses", [])
        or result.testsRun != len(expected)
    ):
        fail("test result was not clean: " + log)
    if blocked_attempts[0] < 1:
        fail("required network-refusal test made no blocked attempt")

    inventory(manifest)
    check_files(manifest)
    if digest(ROOT / "SOURCE_MANIFEST.json") != manifest_hash:
        fail("manifest changed during verification")

    cryptography_version = validate_dependencies()
    require_clean("after verification")
    identity_after = git_identity()
    if identity_after != identity_before:
        fail("git identity changed during verification")

    report = {
        "format": 1,
        "status": "passed",
        "tests": sorted(ids),
        "test_log": log,
        "test_log_sha256": hashlib.sha256(log.encode("utf-8")).hexdigest(),
        "manifest_sha256": manifest_hash,
        "source_id": hashlib.sha256(
            (ROOT / "SOURCE_MANIFEST.json").read_bytes()
            + (ROOT / "DEPENDENCIES.json").read_bytes()
        ).hexdigest(),
        "commit": identity_after[0],
        "tree": identity_after[1],
        "python": sys.version,
        "cryptography": cryptography_version,
        "network_policy": OFFLINE_POLICY,
        "network_scope": (
            "Python socket and DNS APIs in verifier process and Python children; "
            "non-Python child and direct os spawn/exec entrypoints refused"
        ),
        "network_used": False,
        "blocked_attempts": blocked_attempts[0],
        "child_network_probe": offline.child_probe,
        "claims": CLAIMS,
        "unassessed": UNASSESSED,
    }
    if arguments.report:
        publish_report(report_target(arguments.report), report)
    print(json.dumps(report, sort_keys=True, indent=2))
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except VerificationError as exc:
        raise SystemExit(str(exc)) from exc
