from __future__ import annotations

import os
from pathlib import Path
import sqlite3
import tempfile
import unittest

from protocol5_application import Protocol5Application, Protocol5Error
from protocol5_encoding import canonical_json
from protocol5_fixture import make_genesis
from test_protocol5_state import FixtureWorker

class Protocol5StorageTests(unittest.TestCase):
    def setUp(self):
        self.raw = canonical_json(make_genesis())

    def test_database_and_lock_symlinks_are_refused(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            real = root / "real"
            real.write_bytes(b"")
            link = root / "state.sqlite"
            link.symlink_to(real)
            with self.assertRaises(Protocol5Error):
                Protocol5Application(link, FixtureWorker(), expected_genesis=self.raw)
            link.unlink()
            lock_target = root / "lock-target"
            lock_target.write_bytes(b"")
            (root / "state.sqlite.lock").symlink_to(lock_target)
            with self.assertRaises(Protocol5Error):
                Protocol5Application(
                    root / "state.sqlite", FixtureWorker(),
                    expected_genesis=self.raw)

    def test_unknown_view_trigger_or_table_is_refused_on_reopen(self):
        for sql in (
            "CREATE VIEW surprise AS SELECT 1 AS value",
            "CREATE TABLE surprise(value INTEGER)",
            "CREATE TRIGGER surprise AFTER INSERT ON history BEGIN SELECT 1; END",
        ):
            with self.subTest(sql=sql), tempfile.TemporaryDirectory() as td:
                db = Path(td) / "state.sqlite"
                app = Protocol5Application(
                    db, FixtureWorker(), expected_genesis=self.raw)
                app.close()
                connection = sqlite3.connect(db)
                connection.execute(sql)
                connection.commit()
                connection.close()
                with self.assertRaises(Protocol5Error):
                    Protocol5Application(
                        db, FixtureWorker(), expected_genesis=self.raw)

    def test_missing_table_is_refused_without_schema_repair(self):
        with tempfile.TemporaryDirectory() as td:
            db = Path(td) / "state.sqlite"
            app = Protocol5Application(
                db, FixtureWorker(), expected_genesis=self.raw)
            app.close()
            connection = sqlite3.connect(db)
            connection.execute("DROP TABLE history")
            connection.commit()
            connection.close()
            with self.assertRaises(Protocol5Error):
                Protocol5Application(db, FixtureWorker(), expected_genesis=self.raw)

    def test_changed_column_semantics_and_constraints_are_refused(self):
        replacements = (
            """CREATE TABLE history (
                height TEXT PRIMARY KEY,
                txs BLOB NOT NULL
            )""",
            """CREATE TABLE history (
                height INTEGER PRIMARY KEY,
                txs BLOB
            )""",
            """CREATE TABLE history (
                height INTEGER PRIMARY KEY CHECK(height > 0),
                txs BLOB NOT NULL
            )""",
        )
        for replacement in replacements:
            with self.subTest(replacement=replacement), tempfile.TemporaryDirectory() as td:
                db = Path(td) / "state.sqlite"
                app = Protocol5Application(
                    db, FixtureWorker(), expected_genesis=self.raw)
                app.close()
                connection = sqlite3.connect(db)
                connection.execute("DROP TABLE history")
                connection.execute(replacement)
                connection.commit()
                connection.close()
                with self.assertRaises(Protocol5Error):
                    Protocol5Application(
                        db, FixtureWorker(), expected_genesis=self.raw)

    def test_broadly_writable_parent_is_refused(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            root.chmod(0o777)
            try:
                with self.assertRaises(Protocol5Error):
                    Protocol5Application(
                        root / "state.sqlite", FixtureWorker(),
                        expected_genesis=self.raw)
            finally:
                root.chmod(0o700)

if __name__ == "__main__":
    unittest.main()
