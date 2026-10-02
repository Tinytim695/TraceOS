#!/usr/bin/env python3
"""Authoritative local case-management interface for TraceOS.

Schema v1 metadata for new cases is stored in case.json. Legacy folders that
do not have case.json remain readable without a silent migration.
"""
from __future__ import annotations

import ctypes
import datetime as dt
import errno
import json
import os
import shutil
import stat
import tempfile
import uuid
from dataclasses import dataclass
from pathlib import Path
from typing import Optional

SCHEMA_VERSION = 1
MANIFEST_NAME = "case.json"
REQUIRED_DIRS = ("evidence", "working", "exports", "reports", "hashes", "notes")
LEGACY_REQUIRED_DIRS = ("evidence", "working", "exports", "reports")
LEGACY_OPTIONAL_DIRS = ("hashes", "notes")


class CaseError(RuntimeError):
    """Base error for case and selection state problems."""


class CaseCreatedButNotSelected(CaseError):
    """The case directory was published but the active-case state failed."""
    def __init__(self, record: "CaseRecord", cause: BaseException) -> None:
        self.record = record
        self.cause = cause
        super().__init__(
            f"Case created but not selected: {record.path} "
            f"(ID {record.case_id}). Reason: {cause}"
        )


class UnsafeCasePath(CaseError):
    """A case path is outside the allowed root or uses an unsafe symlink."""


class InvalidCaseName(CaseError):
    """A requested new-case title is invalid."""


class CorruptCase(CaseError):
    """A case manifest or required new-case state is corrupt/incomplete."""


class CorruptCaseState(CaseError):
    """The current-case state file is corrupt or unavailable."""


@dataclass(frozen=True)
class CaseRecord:
    path: Path
    case_id: Optional[str]
    title: str
    description: str
    created_utc: Optional[str]
    schema_version: int
    legacy: bool


@dataclass(frozen=True)
class CaseEntry:
    path: Path
    record: Optional[CaseRecord] = None
    error: Optional[str] = None

    @property
    def status(self) -> str:
        if self.error:
            return "ERROR"
        if self.record and self.record.legacy:
            return "LEGACY"
        return "OK"


def utc_now() -> str:
    return (
        dt.datetime.now(dt.timezone.utc)
        .replace(microsecond=0)
        .isoformat()
        .replace("+00:00", "Z")
    )


def _safe_mode(path: Path, mode: int) -> None:
    try:
        os.chmod(path, mode, follow_symlinks=False)
    except (OSError, NotImplementedError) as exc:
        raise CaseError(
            f"Unable to apply private permissions to {path}: {exc}"
        ) from exc


def _read_regular_text(path: Path, max_bytes: int) -> str:
    try:
        path_info = os.lstat(path)
    except OSError as exc:
        raise CorruptCase(f"Unable to inspect required file: {path}") from exc
    if stat.S_ISLNK(path_info.st_mode) or not stat.S_ISREG(path_info.st_mode):
        raise CorruptCase(f"Required file is not a regular file: {path}")
    if path_info.st_size > max_bytes:
        raise CorruptCase(
            f"Required file is too large: {path} ({path_info.st_size} bytes)"
        )
    try:
        fd = os.open(
            path,
            os.O_RDONLY
            | getattr(os, "O_CLOEXEC", 0)
            | getattr(os, "O_NOFOLLOW", 0),
        )
    except OSError as exc:
        raise CorruptCase(f"Unable to open required file: {path}") from exc
    try:
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode):
            raise CorruptCase(f"Required file is not a regular file: {path}")
        if info.st_size > max_bytes:
            raise CorruptCase(
                f"Required file is too large: {path} ({info.st_size} bytes)"
            )
        with os.fdopen(fd, "r", encoding="utf-8") as handle:
            fd = None
            return handle.read()
    except UnicodeError as exc:
        raise CorruptCase(f"Required file is not valid UTF-8: {path}") from exc
    finally:
        if fd is not None:
            os.close(fd)


def _rename_no_replace(source: Path, destination: Path) -> None:
    """Atomically publish a path without ever replacing an existing object."""
    libc = ctypes.CDLL(None, use_errno=True)
    try:
        renameat2 = libc.renameat2
    except AttributeError as exc:
        raise CaseError(
            "Atomic no-clobber case publication is unavailable on this Linux system."
        ) from exc

    renameat2.argtypes = [
        ctypes.c_int,
        ctypes.c_char_p,
        ctypes.c_int,
        ctypes.c_char_p,
        ctypes.c_uint,
    ]
    renameat2.restype = ctypes.c_int
    result = renameat2(
        -100,
        os.fsencode(source),
        -100,
        os.fsencode(destination),
        1,
    )
    if result == 0:
        return
    error = ctypes.get_errno()
    if error == errno.EEXIST:
        raise FileExistsError(
            errno.EEXIST,
            os.strerror(error),
            str(destination),
        )
    raise OSError(error, os.strerror(error), str(destination))


def atomic_write_text(path: Path, text: str, mode: int = 0o600) -> None:
    """Atomically replace a UTF-8 text file and keep it private."""
    path = Path(path)
    parent = path.parent
    parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    _safe_mode(parent, 0o700)
    fd, tmp_name = tempfile.mkstemp(
        prefix=f".{path.name}.tmp-",
        dir=str(parent),
        text=True,
    )
    tmp = Path(tmp_name)
    try:
        os.fchmod(fd, mode)
        with os.fdopen(fd, "w", encoding="utf-8", newline="") as handle:
            handle.write(text)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(tmp, path)
        _safe_mode(path, mode)
        try:
            dir_fd = os.open(
                parent,
                os.O_RDONLY | getattr(os, "O_DIRECTORY", 0),
            )
        except OSError:
            dir_fd = None
        if dir_fd is not None:
            try:
                os.fsync(dir_fd)
            finally:
                os.close(dir_fd)
    except BaseException:
        tmp.unlink(missing_ok=True)
        raise


class CaseStore:
    """Single authoritative API used by the TraceOS CLI and Control Centre."""

    def __init__(
        self,
        home: Optional[Path] = None,
        cases_root: Optional[Path] = None,
        state_path: Optional[Path] = None,
    ) -> None:
        self.home = Path(home or Path.home()).expanduser()
        self.cases_root = Path(
            cases_root or (self.home / "Cases")
        ).expanduser()
        if state_path is not None:
            self.state_path = Path(state_path).expanduser()
        else:
            xdg = Path(
                os.environ.get("XDG_CONFIG_HOME", self.home / ".config")
            ).expanduser()
            self.state_path = xdg / "traceos" / "current_case"

    @staticmethod
    def validate_title(value: str) -> str:
        title = " ".join(str(value).split()).strip()
        if not title:
            raise InvalidCaseName("Case name must not be empty.")
        if len(title) > 160:
            raise InvalidCaseName(
                "Case name is too long (maximum 160 characters)."
            )
        if any(ord(char) < 32 for char in title):
            raise InvalidCaseName(
                "Case name must contain printable characters."
            )
        if any(sep in title for sep in ("/", "\\")) or "\x00" in title:
            raise InvalidCaseName(
                "Case name must not contain path separators."
            )
        if title in {".", ".."}:
            raise InvalidCaseName("Case name must not be . or ..")
        return title

    @staticmethod
    def _slugify(title: str) -> str:
        out: list[str] = []
        for char in title.lower():
            if char.isalnum() or char in "._-":
                out.append(char)
            elif not out or out[-1] != "-":
                out.append("-")
        slug = "".join(out).strip("-")
        return slug or "case"

    def _ensure_cases_root(self) -> Path:
        root = self.cases_root
        if root.exists() and root.is_symlink():
            raise UnsafeCasePath("~/Cases must not be a symlink.")
        if root.exists() and not root.is_dir():
            raise CaseError(f"Cases root is not a directory: {root}")
        root.mkdir(parents=True, exist_ok=True, mode=0o700)
        _safe_mode(root, 0o700)
        return root.resolve(strict=True)

    def validate_path(self, path: Path) -> Path:
        """Validate a case directory is a direct non-symlink child of ~/Cases."""
        root = self._ensure_cases_root()
        candidate = Path(path).expanduser()
        try:
            candidate_stat = os.lstat(candidate)
        except OSError as exc:
            raise CaseError(
                f"Case path cannot be resolved: {candidate}"
            ) from exc
        if stat.S_ISLNK(candidate_stat.st_mode):
            raise UnsafeCasePath(
                "Refusing a symlink as a case directory."
            )
        try:
            resolved = candidate.resolve(strict=True)
        except (OSError, RuntimeError) as exc:
            raise CaseError(
                f"Case path cannot be resolved: {candidate}"
            ) from exc
        try:
            resolved_stat = os.lstat(resolved)
        except OSError as exc:
            raise CaseError(
                f"Case path cannot be resolved: {candidate}"
            ) from exc
        if (
            resolved.parent != root
            or not stat.S_ISDIR(resolved_stat.st_mode)
        ):
            raise UnsafeCasePath(
                "Case must be a direct directory inside ~/Cases."
            )
        return resolved

    @staticmethod
    def _validate_required_dirs(case_path: Path) -> None:
        unsafe = []
        for name in REQUIRED_DIRS:
            target = case_path / name
            try:
                info = os.lstat(target)
            except FileNotFoundError:
                unsafe.append(f"{name} (missing)")
                continue
            except OSError as exc:
                raise CorruptCase(
                    f"Unable to inspect required directory: {target}"
                ) from exc
            if stat.S_ISLNK(info.st_mode):
                unsafe.append(f"{name} (symlink)")
            elif not stat.S_ISDIR(info.st_mode):
                unsafe.append(f"{name} (not a directory)")
        if unsafe:
            raise CorruptCase(
                "Case contains unsafe or incomplete required directories: "
                + ", ".join(unsafe)
            )

    @staticmethod
    def _legacy_title(case_path: Path) -> str:
        case_md = case_path / "CASE.md"
        text = _read_regular_text(case_md, 1024 * 1024)
        for line in text.splitlines():
            if line.startswith("# "):
                title = line[2:].strip()
                if title:
                    return title
        return case_path.name

    @staticmethod
    def _validate_legacy_layout(case_path: Path) -> None:
        case_md = case_path / "CASE.md"
        try:
            _read_regular_text(case_md, 1024 * 1024)
        except CorruptCase as exc:
            raise CorruptCase(
                f"Case does not match the recognized legacy format: {case_path}"
            ) from exc

        unsafe = []
        for name in LEGACY_REQUIRED_DIRS:
            target = case_path / name
            try:
                info = os.lstat(target)
            except FileNotFoundError:
                unsafe.append(f"{name} (missing)")
                continue
            except OSError as exc:
                raise CorruptCase(
                    f"Unable to inspect legacy case directory: {target}"
                ) from exc
            if stat.S_ISLNK(info.st_mode):
                unsafe.append(f"{name} (symlink)")
            elif not stat.S_ISDIR(info.st_mode):
                unsafe.append(f"{name} (not a directory)")

        for name in LEGACY_OPTIONAL_DIRS:
            target = case_path / name
            try:
                info = os.lstat(target)
            except FileNotFoundError:
                continue
            except OSError as exc:
                raise CorruptCase(
                    f"Unable to inspect legacy case directory: {target}"
                ) from exc
            if stat.S_ISLNK(info.st_mode):
                unsafe.append(f"{name} (symlink)")
            elif not stat.S_ISDIR(info.st_mode):
                unsafe.append(f"{name} (not a directory)")

        ledger = case_path / "hashes" / "evidence.tsv"
        try:
            ledger_info = os.lstat(ledger)
        except FileNotFoundError:
            ledger_info = None
        except OSError as exc:
            raise CorruptCase(
                f"Unable to inspect legacy evidence ledger: {ledger}"
            ) from exc

        if ledger_info is not None:
            if stat.S_ISLNK(ledger_info.st_mode) or not stat.S_ISREG(ledger_info.st_mode):
                unsafe.append("hashes/evidence.tsv (unsafe file)")
            else:
                _read_regular_text(ledger, 1024 * 1024)

        if unsafe:
            raise CorruptCase(
                "Legacy case contains unsafe or incomplete entries: "
                + ", ".join(unsafe)
            )

    def open_required_dir(self, path: Path, name: str) -> int:
        """Open a required subdirectory with no-follow checks at the write boundary."""
        if name not in REQUIRED_DIRS:
            raise ValueError(f"Unsupported case directory: {name}")
        record = self.read(path)
        root = self._ensure_cases_root()
        try:
            expected_info = os.lstat(record.path)
            expected_subdir_info = os.lstat(record.path / name)
        except OSError as exc:
            raise CorruptCase(
                f"Unable to inspect case directory boundary: {record.path / name}"
            ) from exc
        flags = (
            os.O_RDONLY
            | getattr(os, "O_DIRECTORY", 0)
            | getattr(os, "O_CLOEXEC", 0)
            | getattr(os, "O_NOFOLLOW", 0)
        )
        root_fd = os.open(root, flags)
        case_fd = None
        try:
            case_fd = os.open(record.path.name, flags, dir_fd=root_fd)
            actual_info = os.fstat(case_fd)
            if (
                actual_info.st_dev != expected_info.st_dev
                or actual_info.st_ino != expected_info.st_ino
            ):
                raise CorruptCase(
                    "Case directory changed during secure open."
                )
            subdir_fd = os.open(name, flags, dir_fd=case_fd)
            try:
                actual_subdir_info = os.fstat(subdir_fd)
                if (
                    actual_subdir_info.st_dev != expected_subdir_info.st_dev
                    or actual_subdir_info.st_ino != expected_subdir_info.st_ino
                ):
                    raise CorruptCase(
                        f"Required directory changed during secure open: {record.path / name}"
                    )
                return subdir_fd
            except BaseException:
                os.close(subdir_fd)
                raise
        except OSError as exc:
            raise CorruptCase(
                f"Unsafe required directory at write boundary: "
                f"{record.path / name}"
            ) from exc
        finally:
            if case_fd is not None:
                os.close(case_fd)
            os.close(root_fd)

    @staticmethod
    def _validate_manifest(data: object, case_path: Path) -> CaseRecord:
        if not isinstance(data, dict):
            raise CorruptCase(
                f"Case manifest is not an object: {case_path / MANIFEST_NAME}"
            )
        required = {
            "case_id",
            "title",
            "description",
            "created_utc",
            "schema_version",
        }
        missing = sorted(required - data.keys())
        if missing:
            raise CorruptCase(
                "Case manifest is incomplete; missing: "
                + ", ".join(missing)
            )
        version = data["schema_version"]
        if type(version) is not int or version != SCHEMA_VERSION:
            raise CorruptCase(
                f"Unsupported case schema_version: {version!r}"
            )
        case_id = data["case_id"]
        try:
            parsed_id = uuid.UUID(str(case_id))
        except (ValueError, AttributeError, TypeError) as exc:
            raise CorruptCase(
                "Case manifest contains an invalid case_id."
            ) from exc
        canonical_id = str(parsed_id)
        if canonical_id != str(case_id).lower():
            raise CorruptCase(
                "Case manifest case_id is not canonical UUID text."
            )
        title = data["title"]
        if not isinstance(title, str):
            raise CorruptCase("Case manifest title is not text.")
        try:
            title = CaseStore.validate_title(title)
        except InvalidCaseName as exc:
            raise CorruptCase(
                f"Case manifest title is invalid: {exc}"
            ) from exc
        description = data["description"]
        if not isinstance(description, str):
            raise CorruptCase("Case manifest description is not text.")
        created = data["created_utc"]
        if not isinstance(created, str):
            raise CorruptCase("Case manifest created_utc is not text.")
        try:
            stamp = dt.datetime.fromisoformat(
                created.replace("Z", "+00:00")
            )
        except ValueError as exc:
            raise CorruptCase(
                "Case manifest created_utc is not valid ISO-8601."
            ) from exc
        if stamp.tzinfo is None or stamp.utcoffset() is None:
            raise CorruptCase(
                "Case manifest created_utc must include timezone information."
            )
        if stamp.utcoffset() != dt.timedelta(0):
            raise CorruptCase(
                "Case manifest created_utc must be UTC."
            )
        CaseStore._validate_required_dirs(case_path)
        return CaseRecord(
            path=case_path,
            case_id=canonical_id,
            title=title,
            description=description,
            created_utc=created,
            schema_version=SCHEMA_VERSION,
            legacy=False,
        )

    def read(self, path: Path) -> CaseRecord:
        case_path = self.validate_path(path)
        manifest = case_path / MANIFEST_NAME
        try:
            manifest_info = os.lstat(manifest)
        except FileNotFoundError:
            self._validate_legacy_layout(case_path)
            return CaseRecord(
                path=case_path,
                case_id=None,
                title=self._legacy_title(case_path),
                description="",
                created_utc=None,
                schema_version=0,
                legacy=True,
            )
        except OSError as exc:
            raise CorruptCase(
                f"Unable to inspect case manifest: {manifest}"
            ) from exc

        if (
            stat.S_ISLNK(manifest_info.st_mode)
            or not stat.S_ISREG(manifest_info.st_mode)
        ):
            raise CorruptCase(
                f"Case manifest must be a regular file: {manifest}"
            )
        try:
            data = json.loads(
                _read_regular_text(manifest, 64 * 1024)
            )
        except (UnicodeError, json.JSONDecodeError, CorruptCase) as exc:
            if isinstance(exc, CorruptCase):
                raise
            raise CorruptCase(
                f"Unable to read case manifest: {manifest}"
            ) from exc
        return self._validate_manifest(data, case_path)

    def list_cases(self) -> list[CaseEntry]:
        root = self._ensure_cases_root()
        entries: list[CaseEntry] = []
        for child in sorted(
            root.iterdir(),
            key=lambda p: p.name.lower(),
        ):
            if child.name.startswith(".traceos-new-"):
                continue
            if not child.is_dir() and not child.is_symlink():
                continue
            try:
                record = self.read(child)
                entries.append(
                    CaseEntry(path=record.path, record=record)
                )
            except CaseError as exc:
                entries.append(
                    CaseEntry(path=child, error=str(exc))
                )
        return entries

    def _ensure_state_parent(self) -> None:
        parent = self.state_path.parent
        if parent.exists() and parent.is_symlink():
            raise CorruptCaseState(
                "TraceOS current-case state directory must not be a symlink."
            )
        parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        _safe_mode(parent, 0o700)

    def current(self) -> Optional[CaseRecord]:
        state = self.state_path
        if state.is_symlink():
            raise CorruptCaseState(
                "Current-case state must not be a symlink."
            )
        if not state.exists():
            return None
        if not state.is_file():
            raise CorruptCaseState(
                "Current-case state is not a regular file."
            )
        try:
            raw = state.read_text(encoding="utf-8")
        except (OSError, UnicodeError) as exc:
            raise CorruptCaseState(
                f"Unable to read current-case state: {state}"
            ) from exc
        lines = raw.splitlines()
        if len(lines) != 1 or not lines[0].strip():
            raise CorruptCaseState(
                "Current-case state must contain exactly one case path."
            )
        selected = Path(lines[0].strip()).expanduser()
        try:
            return self.read(selected)
        except CaseError as exc:
            raise CorruptCaseState(
                f"Current case is unavailable: {exc}"
            ) from exc

    def _write_current(self, record: CaseRecord) -> None:
        self._ensure_state_parent()
        atomic_write_text(
            self.state_path,
            f"{record.path}\n",
            0o600,
        )

    def select(self, path: Path) -> CaseRecord:
        record = self.read(path)
        self._write_current(record)
        return record

    def create(self, title: str, description: str = "") -> CaseRecord:
        title = self.validate_title(title)
        description = str(description).strip()
        if any(
            ord(char) < 32 and char not in "\n\t"
            for char in description
        ):
            raise InvalidCaseName(
                "Case description contains unsupported control characters."
            )

        root = self._ensure_cases_root()
        base = self._slugify(title)
        case_id = str(uuid.uuid4())
        created = utc_now()
        temp_case = Path(
            tempfile.mkdtemp(
                prefix=".traceos-new-",
                dir=str(root),
            )
        )
        try:
            _safe_mode(temp_case, 0o700)
            for name in REQUIRED_DIRS:
                subdir = temp_case / name
                subdir.mkdir(mode=0o700)
                _safe_mode(subdir, 0o700)

            manifest = {
                "case_id": case_id,
                "title": title,
                "description": description,
                "created_utc": created,
                "schema_version": SCHEMA_VERSION,
            }
            atomic_write_text(
                temp_case / MANIFEST_NAME,
                json.dumps(
                    manifest,
                    ensure_ascii=False,
                    indent=2,
                ) + "\n",
                0o600,
            )
            atomic_write_text(
                temp_case / "CASE.md",
                (
                    f"# {title}\n\n"
                    "This is a human-readable case note.\n\n"
                    f"Authoritative metadata: {MANIFEST_NAME}.\n"
                ),
                0o600,
            )
            atomic_write_text(
                temp_case / "hashes" / "evidence.tsv",
                "timestamp_utc\tsource\tvault_copy\tsha256\tsize_bytes\tmime\n",
                0o600,
            )

            suffix = 1
            while True:
                candidate_name = (
                    base if suffix == 1 else f"{base}-{suffix}"
                )
                candidate = root / candidate_name
                try:
                    _rename_no_replace(temp_case, candidate)
                except FileExistsError:
                    suffix += 1
                    continue
                break

            _safe_mode(candidate, 0o700)
            record = self.read(candidate)
            try:
                self._write_current(record)
            except BaseException as exc:
                raise CaseCreatedButNotSelected(record, exc) from exc
            return record
        except BaseException:
            if temp_case.exists():
                shutil.rmtree(temp_case, ignore_errors=True)
            raise
