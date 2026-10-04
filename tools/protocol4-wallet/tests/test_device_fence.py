"""Local registry authority, storage, and real multi-process serialization."""
from contextlib import closing
import hashlib
import multiprocessing
import os
from pathlib import Path
import queue
import sqlite3
import tempfile
import unittest
from unittest.mock import patch

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from device_fence import (
    APPLICATION_ID, SCHEMA_V1, DeviceFence, DeviceFenceError, MAX_INTEGER,
    authority_lane, reservation_message, rotation_message,
)


def reserve_worker(path, start, results, request):
    key = Ed25519PrivateKey.from_private_bytes(b"a" * 32)
    body = {"sender": "payer", "grant_id": "", "nonce": 0, "wire": "x"}
    lane = authority_lane(body)
    try:
        with DeviceFence(path) as fence:
            start.wait(10)
            signature = key.sign(reservation_message("p", "a", 0, lane, 0, request, body))
            result = fence.reserve("p", "a", 0, lane, 0, request, body, signature)
            results.put(result["status"])
    except DeviceFenceError as exc:
        results.put(str(exc))


def rotate_worker(path, started, results):
    old = Ed25519PrivateKey.from_private_bytes(b"a" * 32)
    new = Ed25519PrivateKey.from_private_bytes(b"b" * 32)
    public = new.public_key().public_bytes_raw()
    message = rotation_message("p", "a", "b", public, epoch=0)
    try:
        with DeviceFence(path) as fence:
            started.set()
            result = fence.rotate("p", "a", "b", public, old.sign(message),
                                  new.sign(message), epoch=0)
            results.put(result)
    except DeviceFenceError as exc:
        results.put(str(exc))


class DeviceFenceTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        self.path = self.root / "fence.sqlite"
        self.key = Ed25519PrivateKey.from_private_bytes(b"a" * 32)
        self.new = Ed25519PrivateKey.from_private_bytes(b"b" * 32)
        self.fence = DeviceFence(self.path)
        self.fence.enroll("p", "a", self.key.public_key().public_bytes_raw())

    def tearDown(self):
        self.fence.close()
        self.tmp.cleanup()

    def body(self, *, nonce=0, grant="", wire="x", sender="payer"):
        return {"sender": sender, "grant_id": grant, "nonce": nonce, "wire": wire}

    def reserve(self, *, request="r", body=None, device="a", epoch=0, key=None,
                fence=None, lane=None, nonce=None):
        body = self.body() if body is None else body
        lane = authority_lane(body) if lane is None else lane
        nonce = body["nonce"] if nonce is None else nonce
        signature = (key or self.key).sign(
            reservation_message("p", device, epoch, lane, nonce, request, body),
        )
        return (fence or self.fence).reserve(
            "p", device, epoch, lane, nonce, request, body, signature,
        )

    def rotate(self, *, old="a", new="b", key=None, epoch=0, old_key=None):
        key = key or self.new
        public = key.public_key().public_bytes_raw()
        message = rotation_message("p", old, new, public, epoch=epoch)
        return self.fence.rotate(
            "p", old, new, public, (old_key or self.key).sign(message),
            key.sign(message), epoch=epoch,
        )

    def test_idempotent_request(self):
        self.assertEqual(self.reserve()["status"], "reserved")
        self.assertEqual(self.reserve()["status"], "already_reserved")
        self.assertEqual(self.fence.db.execute("SELECT count(*) FROM reservations").fetchone()[0], 1)

    def test_changed_request_body_rejected(self):
        self.reserve()
        with self.assertRaisesRegex(DeviceFenceError, "request reused"):
            self.reserve(body=self.body(wire="different"))

    def test_request_cannot_move_to_another_lane_or_nonce(self):
        self.reserve()
        for body in (self.body(grant="raven"), self.body(nonce=1)):
            with self.subTest(body=body), self.assertRaisesRegex(DeviceFenceError, "request reused"):
                self.reserve(body=body)

    def test_same_lane_nonce_conflicts_across_connections(self):
        self.reserve()
        with DeviceFence(self.path) as second:
            with self.assertRaisesRegex(DeviceFenceError, "already reserved"):
                self.reserve(request="other", fence=second)

    def test_distinct_payer_grant_and_nonce_keys(self):
        self.reserve()
        for request, body in (
            ("grant", self.body(grant="raven")),
            ("other_payer", self.body(sender="different")),
            ("next_nonce", self.body(nonce=1)),
        ):
            self.assertEqual(self.reserve(request=request, body=body)["status"], "reserved")
        self.assertNotEqual(authority_lane(self.body()), authority_lane(self.body(grant="owner")))

    def test_lane_and_nonce_are_derived_from_body(self):
        body = self.body()
        for lane, nonce in (("alias", 0), (authority_lane(body), 1)):
            with self.subTest(lane=lane, nonce=nonce):
                with self.assertRaisesRegex(DeviceFenceError, "lane or nonce"):
                    self.fence.reserve("p", "a", 0, lane, nonce, "r", body, b"x" * 64)

    def test_authorization_binds_every_reservation_field(self):
        body = self.body()
        lane = authority_lane(body)
        signature = self.key.sign(reservation_message("p", "a", 0, lane, 0, "r", body))
        for request, changed in (("other", body), ("r", self.body(wire="other"))):
            with self.subTest(request=request, changed=changed):
                with self.assertRaisesRegex(DeviceFenceError, "authorization"):
                    self.fence.reserve("p", "a", 0, lane, 0, request, changed, signature)

    def test_forged_and_malformed_signatures(self):
        body = self.body()
        for signature in (b"x" * 64, b"x", "x", None):
            with self.subTest(signature=signature), self.assertRaisesRegex(DeviceFenceError, "authorization"):
                self.fence.reserve("p", "a", 0, authority_lane(body), 0, "r", body, signature)

    def test_stale_device_or_epoch_fails_even_on_idempotent_request(self):
        self.reserve()
        self.rotate()
        with self.assertRaisesRegex(DeviceFenceError, "fenced"):
            self.reserve()
        with self.assertRaisesRegex(DeviceFenceError, "fenced"):
            self.reserve(request="stale", epoch=1)

    def test_rotation_requires_both_current_epoch_consents(self):
        public = self.new.public_key().public_bytes_raw()
        message = rotation_message("p", "a", "b", public, epoch=0)
        for old_sig, new_sig in ((b"x" * 64, self.new.sign(message)),
                                 (self.key.sign(message), b"x" * 64)):
            with self.subTest(old_sig=old_sig), self.assertRaisesRegex(DeviceFenceError, "consent"):
                self.fence.rotate("p", "a", "b", public, old_sig, new_sig, epoch=0)
        self.assertEqual(self.rotate(), 1)

    def test_rotation_replay_and_future_epoch_rejected(self):
        public = self.new.public_key().public_bytes_raw()
        message = rotation_message("p", "a", "b", public, epoch=0)
        signatures = self.key.sign(message), self.new.sign(message)
        with self.assertRaisesRegex(DeviceFenceError, "fenced"):
            self.fence.rotate("p", "a", "b", public, *signatures, epoch=1)
        self.assertEqual(self.fence.rotate("p", "a", "b", public, *signatures, epoch=0), 1)
        with self.assertRaisesRegex(DeviceFenceError, "fenced"):
            self.fence.rotate("p", "a", "b", public, *signatures, epoch=0)

    def test_rotation_consent_cannot_be_replayed_when_key_returns_at_later_epoch(self):
        # A key may return under a fresh device label. The old consent is still
        # invalid: both signatures must bind the epoch of the later transition.
        public = self.new.public_key().public_bytes_raw()
        old_message = rotation_message("p", "c", "d", public, epoch=0)
        old_sig, new_sig = self.key.sign(old_message), self.new.sign(old_message)
        self.rotate()
        self.rotate(old="b", new="c", key=self.key, old_key=self.new, epoch=1)
        with self.assertRaisesRegex(DeviceFenceError, "consent"):
            self.fence.rotate("p", "c", "d", public, old_sig, new_sig, epoch=2)
        self.assertEqual(self.rotate(old="c", new="d", epoch=2), 3)

    def test_retired_device_labels_and_active_key_are_not_reused(self):
        with self.assertRaisesRegex(DeviceFenceError, "already active"):
            self.rotate(new="b", key=self.key)
        self.rotate()
        with self.assertRaisesRegex(DeviceFenceError, "already enrolled"):
            self.rotate(old="b", new="a", key=self.key, old_key=self.new, epoch=1)

    def test_rotation_preserves_existing_lane_reservation(self):
        self.reserve()
        self.rotate()
        with self.assertRaisesRegex(DeviceFenceError, "already reserved"):
            self.reserve(request="new", device="b", epoch=1, key=self.new)
        self.assertEqual(self.reserve(request="distinct", body=self.body(grant="raven"),
                                      device="b", epoch=1, key=self.new)["status"], "reserved")

    def test_integer_and_text_inputs_are_bounded(self):
        body = self.body()
        for epoch in (True, -1, MAX_INTEGER + 1):
            with self.subTest(epoch=epoch), self.assertRaisesRegex(DeviceFenceError, "epoch"):
                reservation_message("p", "a", epoch, authority_lane(body), 0, "r", body)
        for value in ("", "bad label", "a" * 129, None):
            with self.subTest(value=value), self.assertRaises(DeviceFenceError):
                reservation_message("p", "a", 0, authority_lane(body), 0, value, body)
        with self.assertRaisesRegex(DeviceFenceError, "exhausted"):
            rotation_message("p", "a", "b", self.new.public_key().public_bytes_raw(),
                             epoch=MAX_INTEGER)

    def test_noncanonical_and_oversized_bodies_are_refused(self):
        for value in (float("nan"), 1.5, b"x", {"nested": {1: "x"}}, "x" * 16384):
            body = self.body()
            body["wire"] = value
            with self.subTest(value=type(value)), self.assertRaises(DeviceFenceError):
                reservation_message("p", "a", 0, authority_lane(body), 0, "r", body)
        nested = {}
        for _ in range(34):
            nested = {"nested": nested}
        body = self.body(wire=nested)
        with self.assertRaisesRegex(DeviceFenceError, "nesting"):
            reservation_message("p", "a", 0, authority_lane(body), 0, "r", body)

    def test_enrollment_does_not_replace_existing_identity(self):
        with self.assertRaisesRegex(DeviceFenceError, "already enrolled"):
            self.fence.enroll("p", "other", self.new.public_key().public_bytes_raw())
        self.assertEqual(self.reserve()["status"], "reserved")

    def test_closed_registry_and_nested_transaction_are_normalized(self):
        with self.fence._write():
            with self.assertRaisesRegex(DeviceFenceError, "already active"):
                self.reserve()
        self.fence.close()
        self.fence.close()
        with self.assertRaisesRegex(DeviceFenceError, "closed"):
            self.reserve()

    def test_sqlite_failure_rolls_back_and_normalizes(self):
        def authorizer(action, table, *_):
            return sqlite3.SQLITE_DENY if action == sqlite3.SQLITE_INSERT and table == "reservations" else sqlite3.SQLITE_OK
        self.fence.db.set_authorizer(authorizer)
        with self.assertRaisesRegex(DeviceFenceError, "transaction failed"):
            self.reserve()
        self.assertFalse(self.fence.db.in_transaction)
        self.fence.db.set_authorizer(None)
        self.assertEqual(self.reserve()["status"], "reserved")

    def test_busy_writer_begin_is_normalized(self):
        with DeviceFence(self.path) as second:
            second.db.execute("PRAGMA busy_timeout=10")
            with self.fence._write():
                with self.assertRaisesRegex(DeviceFenceError, "transaction failed"):
                    self.reserve(fence=second)
                self.assertFalse(second.db.in_transaction)
            self.assertEqual(self.reserve(fence=second)["status"], "reserved")

    def test_rollback_failure_closes_registry(self):
        def authorizer(action, name, *_):
            deny_insert = action == sqlite3.SQLITE_INSERT and name == "reservations"
            deny_rollback = action == sqlite3.SQLITE_TRANSACTION and name == "ROLLBACK"
            return sqlite3.SQLITE_DENY if deny_insert or deny_rollback else sqlite3.SQLITE_OK
        self.fence.db.set_authorizer(authorizer)
        with self.assertRaisesRegex(DeviceFenceError, "transaction failed"):
            self.reserve()
        self.assertIsNone(self.fence.db)
        with DeviceFence(self.path) as reopened:
            self.assertEqual(self.reserve(fence=reopened)["status"], "reserved")

    def test_failed_commit_retains_no_partial_write(self):
        def authorizer(action, name, *_):
            return sqlite3.SQLITE_DENY if action == sqlite3.SQLITE_TRANSACTION and name == "COMMIT" else sqlite3.SQLITE_OK
        self.fence.db.set_authorizer(authorizer)
        with self.assertRaisesRegex(DeviceFenceError, "transaction failed"):
            self.reserve()
        self.assertFalse(self.fence.db.in_transaction)
        self.fence.db.set_authorizer(None)
        self.assertEqual(self.reserve()["status"], "reserved")

    def make_v1(self, path):
        body = self.body()
        lane = authority_lane(body)
        digest = hashlib.sha256(
            reservation_message("p", "a", 0, lane, 0, "r", body),
        ).hexdigest()
        with closing(sqlite3.connect(path)) as db:
            self.assertEqual(db.execute("PRAGMA journal_mode=WAL").fetchone()[0], "wal")
            for statement in SCHEMA_V1:
                db.execute(statement)
            db.execute(f"PRAGMA application_id={APPLICATION_ID}")
            db.execute("PRAGMA user_version=1")
            db.execute("INSERT INTO wallets VALUES (?,?,?,?)", (
                "p", 0, "a", self.key.public_key().public_bytes_raw(),
            ))
            db.execute("INSERT INTO devices VALUES (?,?,?,?)", (
                "p", "a", self.key.public_key().public_bytes_raw(), None,
            ))
            db.execute("INSERT INTO reservations VALUES (?,?,?,?,?,?,?,?)", (
                "p", lane, 0, "r", "a", 0, digest, "reserved",
            ))
            db.commit()
        path.chmod(0o600)
        return digest

    def test_exact_v1_registry_migrates_once_without_releasing_rows(self):
        path = self.root / "v1.sqlite"
        digest = self.make_v1(path)
        with DeviceFence(path) as migrated:
            self.assertEqual(migrated.db.execute("PRAGMA user_version").fetchone()[0], 2)
            row = migrated.inspect("p", "r")
            self.assertEqual(row["digest"], digest)
            self.assertEqual(row["state"], "reserved")
            self.assertIsNone(row["decision_id"])
            self.assertIsNone(row["wire_sha256"])
            self.assertEqual(
                migrated.db.execute("SELECT count(*) FROM fence_events").fetchone()[0], 0,
            )
        with DeviceFence(path) as reopened:
            self.assertEqual(reopened.inspect("p", "r")["state"], "reserved")
            self.assertEqual(
                reopened.db.execute("SELECT count(*) FROM reservations").fetchone()[0], 1,
            )

    def test_altered_v1_registry_is_refused_without_migration(self):
        path = self.root / "altered-v1.sqlite"
        self.make_v1(path)
        with closing(sqlite3.connect(path)) as db:
            db.execute("CREATE TABLE unexpected(value TEXT)")
        with self.assertRaisesRegex(DeviceFenceError, "unrecognized registry"):
            DeviceFence(path)
        with closing(sqlite3.connect(path)) as db:
            self.assertEqual(db.execute("PRAGMA user_version").fetchone()[0], 1)
            self.assertEqual(
                tuple(row[1] for row in db.execute("PRAGMA table_info(reservations)")),
                ("wallet", "lane", "nonce", "request", "device", "epoch", "digest", "state"),
            )

    def test_failed_v1_migration_rolls_back_exact_original_schema(self):
        path = self.root / "failed-v1.sqlite"
        digest = self.make_v1(path)
        real_connect = sqlite3.connect

        def connect(*args, **kwargs):
            db = real_connect(*args, **kwargs)
            def authorizer(action, name, *_):
                if action == sqlite3.SQLITE_CREATE_TABLE and name == "fence_events":
                    return sqlite3.SQLITE_DENY
                return sqlite3.SQLITE_OK
            db.set_authorizer(authorizer)
            return db

        with patch("device_fence.sqlite3.connect", side_effect=connect):
            with self.assertRaisesRegex(DeviceFenceError, "transaction failed"):
                DeviceFence(path)
        with closing(real_connect(path)) as db:
            self.assertEqual(db.execute("PRAGMA user_version").fetchone()[0], 1)
            objects = set(db.execute(
                "SELECT type,name FROM sqlite_master WHERE name NOT LIKE 'sqlite_%'",
            ))
            self.assertEqual(objects, {
                ("table", "wallets"), ("table", "devices"), ("table", "reservations"),
            })
            self.assertEqual(
                db.execute("SELECT digest,state FROM reservations").fetchone(),
                (digest, "reserved"),
            )

    def test_existing_unrelated_database_is_not_repaired(self):
        path = self.root / "unrelated.sqlite"
        with closing(sqlite3.connect(path)) as db:
            db.execute("CREATE TABLE unrelated(value TEXT)")
        path.chmod(0o600)
        with self.assertRaisesRegex(DeviceFenceError, "unrecognized registry"):
            DeviceFence(path)
        with closing(sqlite3.connect(path)) as db:
            self.assertEqual(db.execute("PRAGMA application_id").fetchone()[0], 0)
            self.assertEqual(db.execute("SELECT name FROM sqlite_master WHERE type='table'").fetchall(),
                             [("unrelated",)])

    def test_schema_change_refuses_authority(self):
        self.fence.db.execute("CREATE TRIGGER changed BEFORE INSERT ON reservations BEGIN SELECT 1; END")
        with self.assertRaisesRegex(DeviceFenceError, "unrecognized registry"):
            self.reserve()

    def test_symlink_and_dangling_symlink_are_refused(self):
        for target in (self.path, self.root / "missing"):
            alias = self.root / "alias"
            alias.symlink_to(target)
            with self.subTest(target=target), self.assertRaisesRegex(DeviceFenceError, "unsafe registry"):
                DeviceFence(alias)
            alias.unlink()

    def test_parent_symlink_is_refused(self):
        alias = self.root / "alias"
        alias.symlink_to(self.root, target_is_directory=True)
        with self.assertRaisesRegex(DeviceFenceError, "symlink parent"):
            DeviceFence(alias / "other.sqlite")

    def test_broad_file_permissions_are_refused_without_chmod(self):
        self.fence.close()
        self.path.chmod(0o644)
        with self.assertRaisesRegex(DeviceFenceError, "unsafe registry"):
            DeviceFence(self.path)
        self.assertEqual(self.path.stat().st_mode & 0o777, 0o644)

    def test_broad_parent_permissions_are_refused(self):
        parent = self.root / "public"
        parent.mkdir(mode=0o755)
        parent.chmod(0o755)  # The qualifier intentionally runs under umask 077.
        with self.assertRaisesRegex(DeviceFenceError, "private owned"):
            DeviceFence(parent / "other.sqlite")
        self.assertFalse((parent / "other.sqlite").exists())

    def test_writable_nonsticky_ancestor_is_refused(self):
        parent = self.root / "public"
        parent.mkdir(mode=0o777)
        parent.chmod(0o777)
        private = parent / "private"
        private.mkdir(mode=0o700)
        with self.assertRaisesRegex(DeviceFenceError, "writable registry ancestor"):
            DeviceFence(private / "other.sqlite")

    def test_hardlinks_and_unsafe_sidecars_are_refused(self):
        alias = self.root / "linked.sqlite"
        os.link(self.path, alias)
        with self.assertRaisesRegex(DeviceFenceError, "unsafe registry"):
            self.reserve()
        alias.unlink()
        # -journal is unused in WAL mode; a dangling sidecar must still refuse.
        journal = Path(str(self.path) + "-journal")
        journal.symlink_to(self.root / "missing")
        with self.assertRaisesRegex(DeviceFenceError, "unsafe registry"):
            self.reserve()

    def test_replaced_database_is_refused_before_mutation(self):
        moved = self.root / "moved.sqlite"
        self.path.rename(moved)
        self.path.write_bytes(b"replacement")
        self.path.chmod(0o600)
        with self.assertRaisesRegex(DeviceFenceError, "replaced"):
            self.reserve()
        self.assertEqual(self.fence.db.execute("SELECT count(*) FROM reservations").fetchone()[0], 0)

    def test_private_mode_on_database_and_sidecars(self):
        self.reserve()
        for suffix in ("", "-wal", "-shm"):
            info = Path(str(self.path) + suffix).stat()
            self.assertEqual(info.st_mode & 0o077, 0)
            self.assertEqual(info.st_uid, os.geteuid())

    def run_process_reservations(self, requests):
        context = multiprocessing.get_context("spawn")
        start, results = context.Event(), context.Queue()
        workers = [context.Process(target=reserve_worker,
                                   args=(str(self.path), start, results, request))
                   for request in requests]
        for worker in workers:
            worker.start()
            self.addCleanup(lambda p=worker: p.terminate() if p.is_alive() else None)
        start.set()
        outcomes = [results.get(timeout=15) for _ in workers]
        for worker in workers:
            worker.join(15)
            self.assertEqual(worker.exitcode, 0)
        results.close()
        return outcomes

    def test_processes_cannot_reserve_conflicting_lane(self):
        outcomes = self.run_process_reservations(("left", "right"))
        self.assertEqual(outcomes.count("reserved"), 1)
        self.assertEqual(sum("already reserved" in result for result in outcomes), 1)

    def test_processes_share_idempotent_request(self):
        self.assertCountEqual(self.run_process_reservations(("same", "same")),
                              ["reserved", "already_reserved"])

    def test_rotation_waits_for_signing_authority_transaction(self):
        reservation = self.reserve()
        context = multiprocessing.get_context("spawn")
        started, results = context.Event(), context.Queue()
        worker = context.Process(target=rotate_worker,
                                 args=(str(self.path), started, results))
        self.addCleanup(lambda: worker.terminate() if worker.is_alive() else None)
        with self.fence.signing_authority("p", "a", 0, "r", reservation["digest"]):
            worker.start()
            self.assertTrue(started.wait(10))
            with self.assertRaises(queue.Empty):
                results.get(timeout=0.2)
            self.assertEqual(self.fence.db.execute("SELECT epoch FROM wallets").fetchone()[0], 0)
        self.assertEqual(results.get(timeout=10), 1)
        worker.join(10)
        self.assertEqual(worker.exitcode, 0)
        results.close()

    def test_rotation_between_reservation_and_signing_refuses(self):
        reservation = self.reserve()
        self.rotate()
        with self.assertRaisesRegex(DeviceFenceError, "fenced"):
            with self.fence.signing_authority("p", "a", 0, "r", reservation["digest"]):
                self.fail("retired device reached signing")
        self.assertEqual(self.fence.db.execute("SELECT count(*) FROM reservations").fetchone()[0], 1)


if __name__ == "__main__":
    unittest.main()
