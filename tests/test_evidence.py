"""Tests for the evidence trust boundary.

Fixtures are built in pytest's ``tmp_path`` rather than read from
``sample_evidence/``, so these run identically in any checkout and in CI.
"""

from __future__ import annotations

import os
import sys
from pathlib import Path

import pytest

from sentrytrace.core.evidence import Evidence
from sentrytrace.exceptions import EvidenceError


@pytest.fixture
def sample_file(tmp_path: Path) -> Path:
    path = tmp_path / "notes.txt"
    path.write_bytes(b"hello")
    return path


class TestAcceptance:
    def test_accepts_a_regular_readable_file(self, sample_file: Path) -> None:
        evidence = Evidence.from_path(sample_file)

        assert evidence.path == sample_file.resolve()
        assert evidence.name == "notes.txt"
        assert evidence.size_bytes == 5

    def test_path_is_always_absolute(self, sample_file: Path, monkeypatch) -> None:
        """A relative path must be resolved, so the report is unambiguous."""
        monkeypatch.chdir(sample_file.parent)

        evidence = Evidence.from_path("notes.txt")

        assert evidence.path.is_absolute()
        assert evidence.path == sample_file.resolve()

    def test_traversal_segments_are_collapsed(self, sample_file: Path) -> None:
        # Create "sub" itself, not "sub/..". The latter asks the OS to make a
        # directory named ".." inside a directory that does not exist: Windows
        # collapses it lexically and silently succeeds, POSIX raises ENOENT.
        (sample_file.parent / "sub").mkdir(exist_ok=True)
        awkward = sample_file.parent / "sub" / ".." / sample_file.name

        evidence = Evidence.from_path(awkward)

        assert ".." not in evidence.path.parts
        assert evidence.path == sample_file.resolve()

    def test_accepts_an_empty_file(self, tmp_path: Path) -> None:
        """Zero bytes is valid evidence, and a meaningful finding later on."""
        empty = tmp_path / "empty.bin"
        empty.touch()

        evidence = Evidence.from_path(empty)

        assert evidence.size_bytes == 0

    def test_evidence_is_immutable(self, sample_file: Path) -> None:
        evidence = Evidence.from_path(sample_file)

        with pytest.raises(AttributeError):
            evidence.path = Path("something_else")  # type: ignore[misc]


class TestExtension:
    @pytest.mark.parametrize(
        ("filename", "expected"),
        [
            ("notes.txt", ".txt"),
            ("INVOICE.EXE", ".exe"),
            ("invoice.pdf.exe", ".exe"),
            ("archive.tar.gz", ".gz"),
            ("README", ""),
            (".bashrc", ""),
        ],
    )
    def test_extension_is_the_lower_cased_final_suffix(
        self, tmp_path: Path, filename: str, expected: str
    ) -> None:
        path = tmp_path / filename
        path.write_bytes(b"x")

        assert Evidence.from_path(path).extension == expected


class TestRejection:
    def test_rejects_a_missing_file(self, tmp_path: Path) -> None:
        with pytest.raises(EvidenceError, match="no such file"):
            Evidence.from_path(tmp_path / "does_not_exist.bin")

    def test_rejects_a_directory(self, tmp_path: Path) -> None:
        with pytest.raises(EvidenceError, match="is a directory"):
            Evidence.from_path(tmp_path)

    @pytest.mark.parametrize("raw", ["", "   "])
    def test_rejects_an_empty_path(self, raw: str) -> None:
        with pytest.raises(EvidenceError, match="no evidence path"):
            Evidence.from_path(raw)

    def test_rejection_messages_name_the_path(self, tmp_path: Path) -> None:
        """An analyst reading stderr should not have to guess which file failed."""
        missing = tmp_path / "mystery.bin"

        with pytest.raises(EvidenceError) as exc_info:
            Evidence.from_path(missing)

        assert "mystery.bin" in str(exc_info.value)


class TestSymlinks:
    @staticmethod
    def _make_symlink(link: Path, target: Path) -> None:
        try:
            link.symlink_to(target)
        except (OSError, NotImplementedError):
            # Windows only permits this for administrators or with Developer
            # Mode enabled, so the capability is checked rather than assumed.
            pytest.skip("this platform does not allow creating symbolic links")

    def test_symlinks_are_refused_by_default(self, tmp_path: Path, sample_file: Path) -> None:
        link = tmp_path / "shortcut.txt"
        self._make_symlink(link, sample_file)

        with pytest.raises(EvidenceError, match="symbolic link"):
            Evidence.from_path(link)

    def test_symlinks_are_followed_when_explicitly_requested(
        self, tmp_path: Path, sample_file: Path
    ) -> None:
        """Following is opt-in, and the report records the resolved target."""
        link = tmp_path / "shortcut.txt"
        self._make_symlink(link, sample_file)

        evidence = Evidence.from_path(link, follow_symlinks=True)

        assert evidence.path == sample_file.resolve()
        assert evidence.name == sample_file.name


@pytest.mark.skipif(sys.platform == "win32", reason="POSIX file modes and FIFOs only")
class TestPosixOnlyRejection:
    def test_rejects_an_unreadable_file(self, sample_file: Path) -> None:
        sample_file.chmod(0o000)

        if os.geteuid() == 0:
            pytest.skip("root bypasses file permissions")

        with pytest.raises(EvidenceError, match="cannot read"):
            Evidence.from_path(sample_file)

    def test_rejects_a_fifo(self, tmp_path: Path) -> None:
        """Reading a FIFO blocks until a writer appears; it must never be hashed."""
        fifo = tmp_path / "pipe"
        os.mkfifo(fifo)

        with pytest.raises(EvidenceError, match="not a regular file"):
            Evidence.from_path(fifo)
