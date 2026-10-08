import os
import stat
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parents[1] / "config/includes.chroot/usr/local/bin"))
from traceos_case import CaseStore

CLI = Path(__file__).parents[1] / "config/includes.chroot/usr/local/bin/traceos-purple"

class PurpleLedgerTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.home = Path(self.tmp.name)
        self.store = CaseStore(
            home=self.home,
            cases_root=self.home / "Cases",
            state_path=self.home / ".config/traceos/current_case",
        )
        self.env = os.environ.copy()
        self.env["HOME"] = str(self.home)
        self.env["XDG_CONFIG_HOME"] = str(self.home / ".config")

    def tearDown(self):
        self.tmp.cleanup()

    def run_cli(self, *args):
        return subprocess.run(
            [sys.executable, str(CLI), *args],
            env=self.env, text=True, capture_output=True, timeout=10
        )

    def test_real_cli_selection_writes_only_selected_case(self):
        first = self.store.create("Purple First")
        second = self.store.create("Purple Second")
        self.store.select(first.path)
        result = self.run_cli("plan", "T1059", "example.test", "shell telemetry")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertTrue((first.path / "notes/purple-exercises.jsonl").is_file())
        self.assertFalse((second.path / "notes/purple-exercises.jsonl").exists())
        self.assertIn(first.case_id, result.stdout)

    def test_list_does_not_create_new_ledger(self):
        case = self.store.create("Purple List")
        ledger = case.path / "notes/purple-exercises.jsonl"
        result = self.run_cli("list")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertFalse(ledger.exists())

    def test_legacy_ledger_is_preserved_without_migration(self):
        case = self.store.create("Purple Legacy")
        legacy = case.path / "purple"
        legacy.mkdir()
        old = legacy / "exercises.jsonl"
        old.write_text('{"legacy":true}\n', encoding="utf-8")
        before = old.read_bytes()
        result = self.run_cli("plan", "T1005", "example.test", "expected telemetry")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(old.read_bytes(), before)
        self.assertTrue((case.path / "notes/purple-exercises.jsonl").is_file())

    def test_ledger_symlink_is_rejected(self):
        case = self.store.create("Purple Symlink")
        sentinel = self.home / "sentinel.txt"
        sentinel.write_text("untouched", encoding="utf-8")
        ledger = case.path / "notes/purple-exercises.jsonl"
        ledger.symlink_to(sentinel)
        result = self.run_cli("plan", "T1005", "example.test", "expected telemetry")
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(sentinel.read_text(encoding="utf-8"), "untouched")

    def test_ledger_fifo_is_rejected_without_blocking(self):
        case = self.store.create("Purple FIFO")
        ledger = case.path / "notes/purple-exercises.jsonl"
        os.mkfifo(ledger, 0o600)
        result = self.run_cli("plan", "T1059", "example.test", "expected telemetry")
        self.assertNotEqual(result.returncode, 0)
        self.assertTrue(stat.S_ISFIFO(ledger.stat().st_mode))

    def test_notes_directory_symlink_is_rejected(self):
        case = self.store.create("Purple Notes Symlink")
        outside = self.home / "outside-notes"
        outside.mkdir()
        notes = case.path / "notes"
        notes.rmdir()
        notes.symlink_to(outside, target_is_directory=True)
        result = self.run_cli("plan", "T1059", "example.test", "expected telemetry")
        self.assertNotEqual(result.returncode, 0)
        self.assertFalse((outside / "purple-exercises.jsonl").exists())

    def test_private_modes(self):
        case = self.store.create("Purple Modes")
        result = self.run_cli("plan", "T1059", "example.test", "expected telemetry")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(stat.S_IMODE((case.path / "notes").stat().st_mode), 0o700)
        self.assertEqual(stat.S_IMODE((case.path / "notes/purple-exercises.jsonl").stat().st_mode), 0o600)

if __name__ == "__main__":
    unittest.main()
