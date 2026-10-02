import json
import os
import shutil
import subprocess
import sys
import tempfile
import unittest
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from unittest import mock

sys.path.insert(
    0,
    str(
        Path(__file__).parent.parent
        / "config/includes.chroot/usr/local/bin"
    ),
)

from traceos_case import (
    CaseCreatedButNotSelected,
    CaseError,
    CaseStore,
    CorruptCase,
    CorruptCaseState,
    UnsafeCasePath,
    _rename_no_replace,
)


CLI = (
    Path(__file__).parent.parent
    / "config/includes.chroot/usr/local/bin/traceos"
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
        self.assertEqual([row.status for row in rows], ["OK", "OK"])

    def test_invalid_names(self):
        for value in (
            "",
            "   ",
            ".",
            "..",
            "../escape",
            "a/b",
            "a\\b",
            "bad",
        ):
            with self.assertRaises(CaseError):
                self.store.create(value)

    def test_no_clobber_publication_preserves_existing_objects(self):
        cases = self.store.cases_root
        cases.mkdir(parents=True, exist_ok=True)
        for kind in ("empty-dir", "nonempty-dir", "file", "symlink"):
            source = cases / f".incoming-{kind}"
            target = cases / f"target-{kind}"
            outside = self.home / f"outside-{kind}"
            if kind == "empty-dir":
                target.mkdir()
            elif kind == "nonempty-dir":
                target.mkdir()
                (target / "sentinel").write_text("keep", encoding="utf-8")
            elif kind == "file":
                target.write_text("keep", encoding="utf-8")
            else:
                outside.write_text("outside", encoding="utf-8")
                os.symlink(outside, target)
            source.mkdir()
            (source / "new").write_text("new", encoding="utf-8")

            with self.assertRaises(FileExistsError):
                _rename_no_replace(source, target)

            if kind == "empty-dir":
                self.assertTrue(target.is_dir())
                self.assertFalse((target / "new").exists())
            elif kind == "nonempty-dir":
                self.assertEqual(
                    (target / "sentinel").read_text(encoding="utf-8"),
                    "keep",
                )
                self.assertFalse((target / "new").exists())
            elif kind == "file":
                self.assertEqual(target.read_text(encoding="utf-8"), "keep")
            else:
                self.assertTrue(target.is_symlink())
                self.assertEqual(outside.read_text(encoding="utf-8"), "outside")

            self.assertTrue(source.exists())

            if source.is_dir():
                shutil.rmtree(source)
            if target.is_dir() and not target.is_symlink():
                shutil.rmtree(target)
            else:
                target.unlink()
            if outside.exists():
                outside.unlink()

    def test_create_handles_publish_race_with_existing_empty_directory(self):
        original = __import__("traceos_case")._rename_no_replace
        injected = {"done": False}

        def raced(source, destination):
            if not injected["done"]:
                injected["done"] = True
                destination.mkdir()
            return original(source, destination)

        with mock.patch("traceos_case._rename_no_replace", side_effect=raced):
            record = self.store.create("Race Case")

        self.assertEqual(record.path.name, "race-case-2")
        self.assertTrue((self.store.cases_root / "race-case").is_dir())
        self.assertFalse((self.store.cases_root / "race-case" / "case.json").exists())
        self.assertTrue(record.case_id)

    def test_create_handles_publish_races_for_file_and_symlink(self):
        original = __import__("traceos_case")._rename_no_replace
        for kind in ("file", "symlink", "nonempty-dir"):
            with self.subTest(kind=kind):
                self.tearDown()
                self.setUp()
                injected = {"done": False}
                outside = self.home / "outside"
                base_target = self.store.cases_root / "race-case"
                self.store.cases_root.mkdir(parents=True, exist_ok=True)

                def raced(source, destination):
                    if not injected["done"]:
                        injected["done"] = True
                        if kind == "file":
                            destination.write_text("keep", encoding="utf-8")
                        elif kind == "symlink":
                            outside.write_text("outside", encoding="utf-8")
                            os.symlink(outside, destination)
                        else:
                            destination.mkdir()
                            (destination / "sentinel").write_text("keep", encoding="utf-8")
                    return original(source, destination)

                with mock.patch("traceos_case._rename_no_replace", side_effect=raced):
                    record = self.store.create("Race Case")

                self.assertEqual(record.path.name, "race-case-2")
                if kind == "file":
                    self.assertEqual(base_target.read_text(encoding="utf-8"), "keep")
                elif kind == "symlink":
                    self.assertTrue(base_target.is_symlink())
                    self.assertEqual(outside.read_text(encoding="utf-8"), "outside")
                else:
                    self.assertEqual(
                        (base_target / "sentinel").read_text(encoding="utf-8"),
                        "keep",
                    )

    def test_two_concurrent_creators_get_distinct_cases(self):
        root = self.store.cases_root
        state = self.store.state_path

        def worker():
            store = CaseStore(
                home=self.home,
                cases_root=root,
                state_path=state,
            )
            return store.create("Concurrent Investigation")

        with ThreadPoolExecutor(max_workers=2) as pool:
            records = list(pool.map(lambda _: worker(), range(2)))

        self.assertNotEqual(records[0].path, records[1].path)
        self.assertNotEqual(records[0].case_id, records[1].case_id)
        self.assertTrue(records[0].path.is_dir())
        self.assertTrue(records[1].path.is_dir())

        rows = self.store.list_cases()
        self.assertEqual(
            [row.status for row in rows],
            ["OK", "OK"],
        )

    def test_required_dir_open_rejects_case_inode_swap(self):
        record = self.store.create("Swap Boundary")
        moved = self.store.cases_root / "swap-boundary-moved"
        injected = {"done": False}
        original_open = os.open

        def raced_open(path, flags, mode=0o777, *, dir_fd=None):
            if (
                not injected["done"]
                and dir_fd is not None
                and str(path) == record.path.name
            ):
                injected["done"] = True
                record.path.rename(moved)
                replacement = record.path
                replacement.mkdir(mode=0o700)
                (replacement / "evidence").mkdir(mode=0o700)
            return original_open(path, flags, mode, dir_fd=dir_fd)

        with mock.patch("traceos_case.os.open", side_effect=raced_open):
            with self.assertRaises(CorruptCase):
                self.store.open_required_dir(record.path, "evidence")

        self.assertTrue(moved.is_dir())
        self.assertTrue((moved / "case.json").is_file())
        self.assertTrue((record.path / "evidence").is_dir())

    def test_required_subdir_symlink_rejected_at_write_boundary(self):
        record = self.store.create("Boundary Case")
        outside = self.home / "outside"
        outside.mkdir()
        sentinel = outside / "sentinel.txt"
        sentinel.write_text("untouched", encoding="utf-8")

        evidence = record.path / "evidence"
        shutil.rmtree(evidence)
        os.symlink(outside, evidence)

        with self.assertRaises(CorruptCase):
            self.store.open_required_dir(record.path, "evidence")

        self.assertEqual(sentinel.read_text(encoding="utf-8"), "untouched")

    def test_corrupt_manifest_and_incomplete_case_are_errors(self):
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
        (bad / "evidence").mkdir(mode=0o700)
        with self.assertRaises(CorruptCase):
            self.store.read(bad)

    def test_legacy_case_is_read_compatible_without_migration(self):
        legacy = self.store.cases_root / "legacy-folder"
        for name in (
            "evidence",
            "working",
            "exports",
            "reports",
            "hashes",
            "notes",
        ):
            (legacy / name).mkdir(parents=True, exist_ok=True)
        legacy.mkdir(exist_ok=True) if not legacy.exists() else None
        (legacy / "CASE.md").write_text(
            "# Legacy Investigation\n\nOlder notes.\n",
            encoding="utf-8",
        )
        (legacy / "hashes" / "evidence.tsv").write_text(
            "timestamp_utc\tsource\tvault_copy\tsha256\tsize_bytes\tmime\n",
            encoding="utf-8",
        )
        record = self.store.read(legacy)
        self.assertTrue(record.legacy)
        self.assertEqual(record.schema_version, 0)
        self.assertIsNone(record.case_id)
        self.assertEqual(record.title, "Legacy Investigation")
        self.assertFalse((legacy / "case.json").exists())
        self.assertEqual(self.store.select(legacy), record)
        self.assertEqual(self.store.current(), record)

    def test_unknown_folder_without_legacy_markers_is_error(self):
        unknown = self.store.cases_root / "unknown-folder"
        unknown.mkdir(parents=True)
        with self.assertRaises(CorruptCase):
            self.store.read(unknown)
        entries = self.store.list_cases()
        self.assertEqual(entries[0].status, "ERROR")

    def test_legacy_case_md_symlink_fifo_and_size_are_rejected(self):
        cases = self.store.cases_root
        cases.mkdir(parents=True, exist_ok=True)

        for kind in ("symlink", "fifo", "large"):
            with self.subTest(kind=kind):
                case = cases / f"legacy-{kind}"
                for name in (
                    "evidence",
                    "working",
                    "exports",
                    "reports",
                    "hashes",
                    "notes",
                ):
                    (case / name).mkdir(parents=True, exist_ok=True)
                ledger = case / "hashes" / "evidence.tsv"
                ledger.write_text("legacy\n", encoding="utf-8")

                if kind == "symlink":
                    outside = self.home / "legacy-outside"
                    outside.write_text("# Outside\n", encoding="utf-8")
                    os.symlink(outside, case / "CASE.md")
                elif kind == "fifo":
                    os.mkfifo(case / "CASE.md")
                else:
                    (case / "CASE.md").write_text(
                        "x" * (1024 * 1024 + 1),
                        encoding="utf-8",
                    )

                with self.assertRaises(CorruptCase):
                    self.store.read(case)

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

    def test_creation_reports_case_not_selected_when_state_write_fails(self):
        previous = self.store.create("Existing")
        self.store.select(previous.path)
        with mock.patch.object(
            self.store,
            "_write_current",
            side_effect=OSError("simulated state failure"),
        ):
            with self.assertRaises(CaseCreatedButNotSelected) as ctx:
                self.store.create("Published Case")
        record = ctx.exception.record
        self.assertTrue(record.path.is_dir())
        self.assertNotEqual(record.path, previous.path)
        self.assertEqual(self.store.current(), previous)
        self.assertIn(str(record.path), str(ctx.exception))
        self.assertIn(record.case_id, str(ctx.exception))
        self.assertTrue((record.path / "case.json").exists())

    def test_current_state_symlink_and_corruption(self):
        outside = self.home / "outside-state"
        outside.write_text("not-a-case\n", encoding="utf-8")
        self.store.state_path.parent.mkdir(parents=True)
        os.symlink(outside, self.store.state_path)
        with self.assertRaises(CorruptCaseState):
            self.store.current()

        self.store.state_path.unlink()
        self.store.state_path.write_text("not-a-case\n", encoding="utf-8")
        with self.assertRaises(CorruptCaseState):
            self.store.current()

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
            self.assertEqual(path.stat().st_mode & 0o777, 0o700)
        private_files = (
            record.path / "case.json",
            record.path / "CASE.md",
            record.path / "hashes" / "evidence.tsv",
            self.store.state_path,
        )
        for path in private_files:
            self.assertEqual(path.stat().st_mode & 0o777, 0o600)

    def test_real_cli_refuses_unsafe_evidence_at_actual_write_boundary(self):
        temp_home = self.home / "cli-home"
        temp_home.mkdir()
        env = os.environ.copy()
        env["HOME"] = str(temp_home)
        env["XDG_CONFIG_HOME"] = str(temp_home / ".config")

        created = subprocess.run(
            [sys.executable, str(CLI), "case", "new", "CLI Boundary"],
            env=env,
            text=True,
            capture_output=True,
            check=False,
        )
        self.assertEqual(created.returncode, 0, created.stderr or created.stdout)

        state = temp_home / ".config" / "traceos" / "current_case"
        case_path = Path(state.read_text(encoding="utf-8").strip())
        outside = temp_home / "outside"
        outside.mkdir()
        sentinel = outside / "sentinel.txt"
        sentinel.write_text("untouched", encoding="utf-8")
        evidence = case_path / "evidence"
        shutil.rmtree(evidence)
        os.symlink(outside, evidence)

        source = temp_home / "source.txt"
        source.write_text("synthetic evidence\n", encoding="utf-8")
        attempted = subprocess.run(
            [sys.executable, str(CLI), "evidence", "add", str(source)],
            env=env,
            text=True,
            capture_output=True,
            check=False,
        )
        self.assertNotEqual(attempted.returncode, 0)
        self.assertEqual(sentinel.read_text(encoding="utf-8"), "untouched")

    def test_ui_diag_does_not_include_real_case_title(self):
        control_text = (
            Path(__file__).parent.parent
            / "config/includes.chroot/usr/local/bin/traceos-control"
        ).read_text(encoding="utf-8")
        self.assertNotIn(
            'case_id=record.case_id or "legacy",\n                title=record.title',
            control_text,
        )

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
