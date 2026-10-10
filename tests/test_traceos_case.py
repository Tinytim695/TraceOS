import importlib.machinery
import importlib.util
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

    def test_required_subdir_real_directory_swap_rejected_at_write_boundary(self):
        record = self.store.create("Directory Swap Boundary")
        moved = self.home / "moved-evidence"
        injected = {"case_fd": None, "done": False}
        original_open = os.open

        def raced_open(path, flags, mode=0o777, *, dir_fd=None):
            if (
                dir_fd is not None
                and str(path) == record.path.name
                and injected["case_fd"] is None
            ):
                fd = original_open(path, flags, mode, dir_fd=dir_fd)
                injected["case_fd"] = fd
                return fd
            if (
                not injected["done"]
                and injected["case_fd"] is not None
                and dir_fd == injected["case_fd"]
                and str(path) == "evidence"
            ):
                injected["done"] = True
                evidence = record.path / "evidence"
                evidence.rename(moved)
                replacement = record.path / "evidence"
                replacement.mkdir(mode=0o700)
                (replacement / "replacement-sentinel").write_text(
                    "must remain untouched",
                    encoding="utf-8",
                )
            return original_open(path, flags, mode, dir_fd=dir_fd)

        with mock.patch("traceos_case.os.open", side_effect=raced_open):
            with self.assertRaises(CorruptCase):
                self.store.open_required_dir(record.path, "evidence")

        self.assertTrue(moved.is_dir())
        self.assertFalse((moved / "replacement-sentinel").exists())
        self.assertTrue(
            (record.path / "evidence" / "replacement-sentinel").is_file()
        )

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

    def _load_cli_for_evidence_test(self, module_name):
        loader = importlib.machinery.SourceFileLoader(module_name, str(CLI))
        spec = importlib.util.spec_from_loader(loader.name, loader)
        cli = importlib.util.module_from_spec(spec)
        loader.exec_module(cli)
        cli.CASE_STORE = self.store
        return cli

    def test_evidence_source_fifo_is_rejected_without_blocking(self):
        cli = self._load_cli_for_evidence_test("traceos_cli_source_fifo_test")
        self.store.create("Source FIFO")
        source = self.home / "source.fifo"
        os.mkfifo(source)

        self.assertEqual(cli.add_evidence(str(source)), 2)
        self.assertEqual(
            list((self.store.current().path / "evidence").iterdir()),
            [],
        )

    def test_evidence_ledger_fifo_is_rejected_without_blocking(self):
        cli = self._load_cli_for_evidence_test("traceos_cli_ledger_fifo_test")
        self.store.create("Ledger FIFO")
        source = self.home / "ledger-source.txt"
        source.write_text("synthetic evidence\n", encoding="utf-8")
        ledger = self.store.current().path / "hashes" / "evidence.tsv"
        ledger.unlink()
        os.mkfifo(ledger)

        self.assertEqual(cli.add_evidence(str(source)), 1)
        self.assertEqual(
            list((self.store.current().path / "evidence").iterdir()),
            [],
        )

    def test_ledger_short_write_failure_is_not_reported_as_success(self):
        cli = self._load_cli_for_evidence_test("traceos_cli_ledger_short_write_test")
        self.store.create("Ledger Short Write")
        source = self.home / "short-write-source.txt"
        source.write_text("synthetic evidence\n", encoding="utf-8")

        original_write = cli.os.write
        state = {"first": True}

        def partial_then_fail(fd, data):
            if state["first"]:
                state["first"] = False
                prefix = data[:8]
                original_write(fd, prefix)
                raise OSError("simulated ledger write failure")
            return original_write(fd, data)

        with mock.patch.object(cli.os, "write", side_effect=partial_then_fail):
            self.assertEqual(cli.add_evidence(str(source)), 1)

        ledger = self.store.current().path / "hashes" / "evidence.tsv"
        header = (
            b"timestamp_utc\tsource\tvault_copy\tsha256\tsize_bytes\tmime\n"
        )
        self.assertEqual(ledger.read_bytes(), header)
        self.assertEqual(cli.verify_evidence(), 0)
        self.assertEqual(
            list((self.store.current().path / "evidence").iterdir()),
            [],
        )

    def test_report_and_timeline_reject_headerless_ledger(self):
        cli = self._load_cli_for_evidence_test("traceos_cli_headerless_ledger_test")
        record = self.store.create("Headerless Ledger")
        ledger = record.path / "hashes" / "evidence.tsv"
        ledger.write_text("2026-10-10T12:00:00Z\tsource\tvault\n", encoding="utf-8")
        reports = record.path / "reports"
        before = list(reports.iterdir())
        self.assertEqual(cli.report(), 1)
        self.assertEqual(cli.timeline(), 1)
        self.assertEqual(list(reports.iterdir()), before)

    def test_report_and_timeline_reject_malformed_ledger_row(self):
        cli = self._load_cli_for_evidence_test("traceos_cli_malformed_ledger_test")
        record = self.store.create("Malformed Ledger")
        ledger = record.path / "hashes" / "evidence.tsv"
        ledger.write_text(
            "timestamp_utc\tsource\tvault_copy\tsha256\tsize_bytes\tmime\n"
            "2026-10-10T12:00:00Z\ttoo-few-fields\n",
            encoding="utf-8",
        )
        reports = record.path / "reports"
        before = list(reports.iterdir())
        self.assertEqual(cli.report(), 1)
        self.assertEqual(cli.timeline(), 1)
        self.assertEqual(list(reports.iterdir()), before)

    def test_header_only_ledger_is_valid_and_produces_empty_report(self):
        cli = self._load_cli_for_evidence_test("traceos_cli_header_only_ledger_test")
        record = self.store.create("Header Only Ledger")
        ledger = record.path / "hashes" / "evidence.tsv"
        ledger.write_text(
            "timestamp_utc\tsource\tvault_copy\tsha256\tsize_bytes\tmime\n",
            encoding="utf-8",
        )
        self.assertEqual(cli.report(), 0)
        self.assertEqual(cli.timeline(), 0)
        reports = list((record.path / "reports").glob("TraceOS-report-*.md"))
        self.assertEqual(len(reports), 1)
        self.assertIn("## Evidence", reports[0].read_text(encoding="utf-8"))

    def test_report_does_not_follow_existing_symlink(self):
        cli = self._load_cli_for_evidence_test("traceos_cli_report_symlink_test")
        record = self.store.create("Report Symlink")
        stamp = "20300101T000000Z"
        reports = record.path / "reports"
        outside = self.home / "outside-report.md"
        sentinel = "outside report must remain untouched\n"
        outside.write_text(sentinel, encoding="utf-8")
        symlink = reports / f"TraceOS-report-{stamp}.md"
        symlink.symlink_to(outside)

        with mock.patch.object(cli, "_report_stamp", return_value=stamp):
            self.assertEqual(cli.report(), 0)

        self.assertTrue(symlink.is_symlink())
        self.assertEqual(outside.read_text(encoding="utf-8"), sentinel)
        published = reports / f"TraceOS-report-{stamp}-2.md"
        self.assertTrue(published.is_file())
        self.assertFalse(published.is_symlink())
        self.assertIn("# TraceOS Investigation Report", published.read_text(encoding="utf-8"))
        self.assertEqual(published.stat().st_mode & 0o777, 0o600)

    def test_verify_evidence_accepts_real_vault_copy_and_detects_tampering(self):
        cli = self._load_cli_for_evidence_test("traceos_cli_verify_test")
        record = self.store.create("Verify Evidence")
        source = self.home / "verify-source.txt"
        source.write_text("verify me\n", encoding="utf-8")

        self.assertEqual(cli.add_evidence(str(source)), 0)
        self.assertEqual(cli.verify_evidence(), 0)

        vault_files = list((record.path / "evidence").iterdir())
        self.assertEqual(len(vault_files), 1)
        os.chmod(vault_files[0], 0o600)
        vault_files[0].write_text("tampered\n", encoding="utf-8")
        self.assertEqual(cli.verify_evidence(), 1)

    def test_open_required_dirs_stays_pinned_across_case_swap(self):
        record = self.store.create("Pinned Child FDs")
        moved = self.store.cases_root / "pinned-child-fds-moved"
        injected = {"case_fd": None, "done": False}
        original_open = os.open

        original_evidence = os.stat(
            record.path / "evidence",
            follow_symlinks=False,
        )
        original_hashes = os.stat(
            record.path / "hashes",
            follow_symlinks=False,
        )

        def raced_open(path, flags, mode=0o777, *, dir_fd=None):
            if (
                dir_fd is not None
                and str(path) == record.path.name
                and injected["case_fd"] is None
            ):
                fd = original_open(path, flags, mode, dir_fd=dir_fd)
                injected["case_fd"] = fd
                return fd
            if (
                not injected["done"]
                and injected["case_fd"] is not None
                and dir_fd == injected["case_fd"]
                and str(path) == "hashes"
            ):
                injected["done"] = True
                record.path.rename(moved)
                replacement = record.path
                replacement.mkdir(mode=0o700)
                for name in ("evidence", "working", "exports", "reports", "hashes", "notes"):
                    (replacement / name).mkdir(mode=0o700)
                return original_open(path, flags, mode, dir_fd=dir_fd)
            return original_open(path, flags, mode, dir_fd=dir_fd)

        with mock.patch("traceos_case.os.open", side_effect=raced_open):
            evidence_fd, hashes_fd = self.store.open_required_dirs(
                record.path,
                ("evidence", "hashes"),
            )

        try:
            self.assertEqual(
                (os.fstat(evidence_fd).st_dev, os.fstat(evidence_fd).st_ino),
                (original_evidence.st_dev, original_evidence.st_ino),
            )
            self.assertEqual(
                (os.fstat(hashes_fd).st_dev, os.fstat(hashes_fd).st_ino),
                (original_hashes.st_dev, original_hashes.st_ino),
            )
        finally:
            os.close(evidence_fd)
            os.close(hashes_fd)

        self.assertTrue(moved.is_dir())
        self.assertTrue(record.path.is_dir())
        self.assertTrue((record.path / "hashes").is_dir())

    def test_verify_missing_ledger_is_unverifiable(self):
        cli = self._load_cli_for_evidence_test("traceos_cli_missing_ledger_test")
        self.store.create("Missing Ledger")
        source = self.home / "missing-ledger-source.txt"
        source.write_text("synthetic evidence\n", encoding="utf-8")

        self.assertEqual(cli.add_evidence(str(source)), 0)
        ledger = self.store.current().path / "hashes" / "evidence.tsv"
        self.assertTrue(ledger.is_file())
        ledger.unlink()

        self.assertEqual(cli.verify_evidence(), 1)

    def test_verify_unsafe_hashes_directory_is_unverifiable(self):
        cli = self._load_cli_for_evidence_test("traceos_cli_unsafe_hashes_test")
        self.store.create("Unsafe Hashes")
        outside = self.home / "outside-hashes"
        outside.mkdir()
        hashes = self.store.current().path / "hashes"
        shutil.rmtree(hashes)
        os.symlink(outside, hashes)

        with self.assertRaises(CorruptCaseState):
            cli.verify_evidence()

    def test_evidence_rejects_ledger_delimiter_source_names(self):
        cli = self._load_cli_for_evidence_test("traceos_cli_ledger_delimiter_name_test")
        self.store.create("Delimiter Names")

        for index, bad in enumerate(("tab\tname", "cr\rname", "lf\nname")):
            with self.subTest(bad=repr(bad)):
                source = self.home / f"synthetic-{index}-{bad}"
                source.write_text("synthetic evidence\n", encoding="utf-8")
                self.assertEqual(cli.add_evidence(str(source)), 2)

        evidence = self.store.current().path / "evidence"
        self.assertEqual(list(evidence.iterdir()), [])

    def test_real_cli_end_to_end_evidence_report_timeline_workflow(self):
        temp_home = self.home / "cli-e2e-home"
        temp_home.mkdir()
        env = os.environ.copy()
        env["HOME"] = str(temp_home)
        env["XDG_CONFIG_HOME"] = str(temp_home / ".config")

        def run_cli(*args):
            result = subprocess.run(
                [sys.executable, str(CLI), *args],
                env=env,
                text=True,
                capture_output=True,
                check=False,
            )
            self.assertEqual(
                result.returncode,
                0,
                result.stderr or result.stdout,
            )
            return result

        run_cli("case", "new", "Synthetic E2E Case")
        source = temp_home / "synthetic-source.txt"
        payload = b"TraceOS deterministic synthetic evidence\n"
        source.write_bytes(payload)
        expected_hash = __import__("hashlib").sha256(payload).hexdigest()

        added = run_cli("evidence", "add", str(source))
        self.assertIn(expected_hash, added.stdout)

        case_path = Path(
            (temp_home / ".config" / "traceos" / "current_case").read_text(
                encoding="utf-8"
            ).strip()
        )
        ledger = case_path / "hashes" / "evidence.tsv"
        rows = ledger.read_text(encoding="utf-8").splitlines()[1:]
        self.assertEqual(len(rows), 1)
        fields = rows[0].split("\t")
        self.assertEqual(len(fields), 6)
        self.assertEqual(fields[3], expected_hash)

        vault_files = list((case_path / "evidence").iterdir())
        self.assertEqual(len(vault_files), 1)
        self.assertEqual(vault_files[0].read_bytes(), payload)

        verified = run_cli("evidence", "verify")
        self.assertIn("1 checked, 0 failed", verified.stdout)

        os.chmod(vault_files[0], 0o600)
        vault_files[0].write_bytes(b"TAMPERED\n")
        tampered = subprocess.run(
            [sys.executable, str(CLI), "evidence", "verify"],
            env=env,
            text=True,
            capture_output=True,
            check=False,
        )
        self.assertNotEqual(tampered.returncode, 0)
        self.assertIn("expected=", tampered.stdout)

        report_result = run_cli("report")
        report_lines = list((case_path / "reports").glob("TraceOS-report-*.md"))
        self.assertEqual(len(report_lines), 1)
        report_text = report_lines[0].read_text(encoding="utf-8")
        self.assertIn(vault_files[0].name, report_text)
        self.assertIn(expected_hash, report_text)

        timeline_result = run_cli("timeline")
        self.assertIn(vault_files[0].name, timeline_result.stdout)

    def test_evidence_permission_change_is_fd_bound(self):
        loader = importlib.machinery.SourceFileLoader(
            "traceos_cli_permission_test",
            str(CLI),
        )
        spec = importlib.util.spec_from_loader(loader.name, loader)
        cli = importlib.util.module_from_spec(spec)
        loader.exec_module(cli)
        cli.CASE_STORE = self.store
        self.store.create("Permission Case")

        source = self.home / "permission-source.txt"
        source.write_text("permission test\n", encoding="utf-8")
        original_fchmod = os.fchmod
        with mock.patch.object(
            cli.os,
            "chmod",
            wraps=cli.os.chmod,
        ) as chmod_mock:
            with mock.patch.object(
                cli.os,
                "fchmod",
                wraps=original_fchmod,
            ) as fchmod_mock:
                self.assertEqual(cli.add_evidence(str(source)), 0)

        self.assertEqual(fchmod_mock.call_count, 1)
        self.assertEqual(fchmod_mock.call_args.args[1], 0o444)
        evidence_files = list(
            (self.store.current().path / "evidence").iterdir()
        )
        self.assertEqual(
            [
                Path(call.args[0])
                for call in chmod_mock.call_args_list
                if call.args and Path(call.args[0]) in evidence_files
            ],
            [],
        )
        self.assertEqual(len(evidence_files), 1)
        self.assertEqual(evidence_files[0].stat().st_mode & 0o777, 0o444)

    def test_evidence_source_swap_before_open_uses_opened_inode(self):
        loader = importlib.machinery.SourceFileLoader(
            "traceos_cli_source_swap_test",
            str(CLI),
        )
        spec = importlib.util.spec_from_loader(loader.name, loader)
        cli = importlib.util.module_from_spec(spec)
        loader.exec_module(cli)
        cli.CASE_STORE = self.store

        self.store.create("Source Swap Case")
        source = self.home / "selected-source.txt"
        original_bytes = b"original source bytes\n"
        replacement_bytes = b"replacement source bytes\n"
        source.write_bytes(original_bytes)
        replacement = self.home / "replacement-source.txt"
        injected = {"done": False}
        original_open = os.open

        def raced_open(path, flags, mode=0o777, *, dir_fd=None):
            if (
                not injected["done"]
                and dir_fd is None
                and Path(path) == source
            ):
                injected["done"] = True
                original_path = self.home / "original-selected-source.txt"
                source.rename(original_path)
                source.write_bytes(replacement_bytes)
            return original_open(path, flags, mode, dir_fd=dir_fd)

        expected_hash = __import__("hashlib").sha256(replacement_bytes).hexdigest()

        with mock.patch.object(cli.os, "open", side_effect=raced_open):
            self.assertEqual(cli.add_evidence(str(source)), 0)

        current = self.store.current()
        self.assertIsNotNone(current)
        ledger = current.path / "hashes" / "evidence.tsv"
        row = ledger.read_text(encoding="utf-8").splitlines()[1].split("\t")
        self.assertEqual(row[3], expected_hash)
        self.assertEqual(int(row[4]), len(replacement_bytes))

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
        for name in ("evidence", "working", "exports", "reports"):
            (legacy / name).mkdir(parents=True, exist_ok=True)
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
        self.assertEqual(self.store.select(legacy), record)
        self.assertEqual(self.store.current(), record)

        (legacy / "hashes").mkdir()
        (legacy / "notes").mkdir()
        (legacy / "hashes" / "evidence.tsv").write_text(
            "timestamp_utc\tsource\tvault_copy\tsha256\tsize_bytes\tmime\n",
            encoding="utf-8",
        )
        record = self.store.read(legacy)
        self.assertTrue(record.legacy)

    def test_legacy_case_md_inode_swap_is_rejected(self):
        legacy = self.store.cases_root / "legacy-case-md-race"
        for name in ("evidence", "working", "exports", "reports"):
            (legacy / name).mkdir(parents=True, exist_ok=True)
        case_md = legacy / "CASE.md"
        case_md.write_text("# Original Legacy\n", encoding="utf-8")
        moved = self.home / "moved-CASE.md"
        replacement_text = "# Replacement Legacy\n"
        original_open = os.open
        injected = {"done": False}

        def raced_open(path, flags, mode=0o777, *, dir_fd=None):
            if not injected["done"] and Path(path) == case_md and dir_fd is None:
                injected["done"] = True
                case_md.rename(moved)
                case_md.write_text(replacement_text, encoding="utf-8")
            return original_open(path, flags, mode, dir_fd=dir_fd)

        with mock.patch("traceos_case.os.open", side_effect=raced_open):
            with self.assertRaises(CorruptCase):
                self.store.read(legacy)

        self.assertEqual(moved.read_text(encoding="utf-8"), "# Original Legacy\n")
        self.assertEqual(case_md.read_text(encoding="utf-8"), replacement_text)

    def test_legacy_optional_entries_must_be_safe_when_present(self):
        for kind in ("notes-symlink", "hashes-file", "ledger-symlink", "ledger-fifo"):
            with self.subTest(kind=kind):
                case = self.store.cases_root / f"legacy-unsafe-{kind}"
                for name in ("evidence", "working", "exports", "reports"):
                    (case / name).mkdir(parents=True, exist_ok=True)
                (case / "CASE.md").write_text(
                    "# Unsafe Legacy\n",
                    encoding="utf-8",
                )

                if kind == "notes-symlink":
                    outside = self.home / "legacy-notes-outside"
                    outside.mkdir()
                    os.symlink(outside, case / "notes")
                elif kind == "hashes-file":
                    (case / "hashes").write_text("not-a-directory", encoding="utf-8")
                else:
                    (case / "hashes").mkdir()
                    ledger = case / "hashes" / "evidence.tsv"
                    if kind == "ledger-symlink":
                        outside = self.home / "legacy-ledger-outside"
                        outside.write_text("outside", encoding="utf-8")
                        os.symlink(outside, ledger)
                    else:
                        os.mkfifo(ledger)

                with self.assertRaises(CorruptCase):
                    self.store.read(case)

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
