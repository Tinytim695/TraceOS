import json
import os
import tempfile
import unittest
from pathlib import Path
from unittest import mock

import sys
sys.path.insert(
    0,
    str(
        Path(__file__).parent.parent
        / "config/includes.chroot/usr/local/bin"
    ),
)

from traceos_case import (
    CaseError,
    CaseStore,
    CorruptCase,
    CorruptCaseState,
    UnsafeCasePath,
)


class CaseStoreTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.home = Path(self.tmp.name)
        self.store = CaseStore(
            home=self.home,
            cases_root=self.home / "Cases",
            state_path=self.home / ".config" / "traceos" / "current_case",
        )

    def tearDown(self):
        self.tmp.cleanup()

    def test_two_cases_collision_and_selection_agreement(self):
        first = self.store.create("Alice Case", "first case")
        second = self.store.create("Alice Case", "second case")
        self.assertNotEqual(first.case_id, second.case_id)
        self.assertEqual(first.path.name, "alice-case")
        self.assertEqual(second.path.name, "alice-case-2")
        self.assertEqual(self.store.current(), second)
        self.store.select(first.path)
        self.assertEqual(self.store.current(), first)
        rows = self.store.list_cases()
        self.assertEqual(
            [row.status for row in rows],
            ["OK", "OK"],
        )

    def test_invalid_names(self):
        for value in (
            "",
            "   ",
            ".",
            "..",
            "../escape",
            "a/b",
            "a\\\\b",
            "\x01bad",
        ):
            with self.assertRaises(CaseError):
                self.store.create(value)

    def test_outside_root_symlink_rejected(self):
        outside = self.home / "outside"
        outside.mkdir()
        (outside / "case-data").mkdir()
        self.store.cases_root.mkdir(mode=0o700)
        os.symlink(
            outside / "case-data",
            self.store.cases_root / "evil",
        )
        with self.assertRaises(UnsafeCasePath):
            self.store.select(self.store.cases_root / "evil")
        entries = self.store.list_cases()
        self.assertEqual(len(entries), 1)
        self.assertEqual(entries[0].status, "ERROR")

    def test_corrupt_manifest_and_incomplete_new_case(self):
        record = self.store.create("Good Case")
        manifest = record.path / "case.json"
        manifest.write_text("{broken", encoding="utf-8")
        with self.assertRaises(CorruptCase):
            self.store.read(record.path)
        manifest.write_text(
            json.dumps({"schema_version": 1}),
            encoding="utf-8",
        )
        with self.assertRaises(CorruptCase):
            self.store.read(record.path)

        bad = self.store.cases_root / "incomplete"
        bad.mkdir(mode=0o700)
        for name in ("evidence", "working"):
            (bad / name).mkdir(mode=0o700)
        (bad / "case.json").write_text(
            json.dumps(
                {
                    "case_id": "00000000-0000-4000-8000-000000000000",
                    "title": "Incomplete",
                    "description": "",
                    "created_utc": "2026-10-02T00:00:00Z",
                    "schema_version": 1,
                }
            ),
            encoding="utf-8",
        )
        with self.assertRaises(CorruptCase):
            self.store.read(bad)

    def test_atomic_state_replacement_survives_interrupted_replace(self):
        first = self.store.create("First")
        second = self.store.create("Second")
        self.store.select(first.path)
        original = self.store.state_path.read_text(encoding="utf-8")
        with mock.patch(
            "traceos_case.os.replace",
            side_effect=OSError("simulated interruption"),
        ):
            with self.assertRaises(OSError):
                self.store.select(second.path)
        self.assertEqual(
            self.store.state_path.read_text(encoding="utf-8"),
            original,
        )
        self.assertEqual(self.store.current(), first)

    def test_private_permissions(self):
        record = self.store.create("Private Case")
        private_dirs = [
            self.store.cases_root,
            record.path,
            *[
                record.path / name
                for name in (
                    "evidence",
                    "working",
                    "exports",
                    "reports",
                    "hashes",
                    "notes",
                )
            ],
        ]
        for path in private_dirs:
            self.assertEqual(
                path.stat().st_mode & 0o777,
                0o700,
            )
        private_files = (
            record.path / "case.json",
            record.path / "CASE.md",
            record.path / "hashes" / "evidence.tsv",
            self.store.state_path,
        )
        for path in private_files:
            self.assertEqual(
                path.stat().st_mode & 0o777,
                0o600,
            )

    def test_legacy_case_is_read_compatible_without_migration(self):
        legacy = self.store.cases_root / "legacy-folder"
        legacy.mkdir(parents=True, mode=0o700)
        (legacy / "CASE.md").write_text(
            "# Legacy Investigation\n\nOlder notes.\n",
            encoding="utf-8",
        )
        record = self.store.read(legacy)
        self.assertTrue(record.legacy)
        self.assertEqual(record.schema_version, 0)
        self.assertIsNone(record.case_id)
        self.assertEqual(record.title, "Legacy Investigation")
        self.assertFalse((legacy / "case.json").exists())
        selected = self.store.select(legacy)
        self.assertEqual(selected, record)
        self.assertEqual(self.store.current(), record)

    def test_broken_current_state_symlink(self):
        outside = self.home / "outside-state"
        outside.write_text("not-a-case\\n", encoding="utf-8")
        self.store.state_path.parent.mkdir(parents=True)
        os.symlink(outside, self.store.state_path)
        with self.assertRaises(CorruptCaseState):
            self.store.current()

    def test_corrupt_current_state(self):
        self.store.state_path.parent.mkdir(parents=True)
        self.store.state_path.write_text(
            "not-a-case\n",
            encoding="utf-8",
        )
        with self.assertRaises(CorruptCaseState):
            self.store.current()

    def test_restart_selection_agreement(self):
        record = self.store.create(
            "Restart Case",
            "persist selection in state",
        )
        restarted = CaseStore(
            home=self.home,
            cases_root=self.home / "Cases",
            state_path=self.home / ".config" / "traceos" / "current_case",
        )
        current = restarted.current()
        self.assertIsNotNone(current)
        self.assertEqual(current.case_id, record.case_id)
        self.assertEqual(current.title, record.title)
        self.assertEqual(
            restarted.read(record.path).case_id,
            record.case_id,
        )


if __name__ == "__main__":
    unittest.main(verbosity=2)
