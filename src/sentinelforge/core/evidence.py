"""Evidence intake: the trust boundary between the analyst and the engine.

Everything SentinelForge analyses arrives as a path typed by a human or handed
over by another program. This module is the one place that turns such a path
into something the rest of the codebase is allowed to touch.

Validating in exactly one place matters for two reasons. Analysers stay simple,
because they can assume their input is a real, readable, regular file. And the
security rules that make this tool safe to point at hostile material live
together, where they can be read, reviewed and tested as a set rather than
rediscovered in every module that happens to open a file.
"""

from __future__ import annotations

import logging
import os
import stat as stat_module
from dataclasses import dataclass
from pathlib import Path

from sentinelforge.exceptions import EvidenceError

log = logging.getLogger(__name__)


@dataclass(frozen=True)
class Evidence:
    """A file that has passed validation and been accepted for analysis.

    Holding this object is a promise: at the moment of intake the path existed,
    pointed at a regular file, and could be opened for reading.

    ``frozen=True`` makes it immutable. An analyser cannot quietly repoint
    ``path`` at something else halfway through an investigation, so the file
    named in the final report is the file that was validated.

    Only the facts established during validation live here. Richer filesystem
    metadata is the job of :mod:`sentinelforge.analyzers.metadata`.
    """

    path: Path
    """Absolute, symlink-resolved path to the file that was accepted."""

    size_bytes: int
    """Size recorded by the ``stat`` call performed during validation."""

    @property
    def name(self) -> str:
        """The file name, without any directory component."""
        return self.path.name

    @property
    def extension(self) -> str:
        """The final extension, lower-cased, including the dot.

        Empty string when there is no extension. Lower-cased because
        ``INVOICE.EXE`` and ``invoice.exe`` are the same thing to Windows, and
        matching case-sensitively would be a trivial way to evade a rule.

        Note this is only the *final* extension: ``invoice.pdf.exe`` gives
        ``.exe``. Detecting the misleading ``.pdf`` in front of it is a
        heuristic, and belongs in the heuristics analyser.
        """
        return self.path.suffix.lower()

    @classmethod
    def from_path(
        cls,
        raw_path: str | os.PathLike[str],
        *,
        follow_symlinks: bool = False,
    ) -> Evidence:
        """Validate ``raw_path`` and return accepted :class:`Evidence`.

        Raises :class:`~sentinelforge.exceptions.EvidenceError` with a message
        written for an analyst, not a stack trace, whenever the path cannot be
        accepted.

        By default a symbolic link is refused rather than followed. A link
        means the name you typed and the bytes you would hash are two different
        things, and a report that records one while analysing the other is
        misleading. Pass ``follow_symlinks=True`` to accept the target instead,
        in which case the resolved target is what gets recorded.
        """
        text = os.fspath(raw_path)
        if not text.strip():
            raise EvidenceError("no evidence path was provided")

        # expanduser handles a leading "~", which some shells leave alone.
        candidate = Path(text).expanduser()

        # Checked before resolve(), because resolve() erases the distinction.
        # This only inspects the final component; links in parent directories
        # are resolved silently, and the resolved path is what we record.
        if candidate.is_symlink() and not follow_symlinks:
            raise EvidenceError(
                f"{candidate} is a symbolic link; analyse its target directly, "
                "so the report names the file that was actually read"
            )

        # resolve() makes the path absolute and collapses "..", so a traversal
        # attempt cannot leave one meaning here and a different one at open().
        path = candidate.resolve()

        stat_result = cls._stat_or_reject(path)
        cls._reject_if_not_a_regular_file(path, stat_result.st_mode)
        cls._reject_if_unreadable(path)

        log.debug("accepted evidence: %s (%d bytes)", path, stat_result.st_size)
        return cls(path=path, size_bytes=stat_result.st_size)

    @staticmethod
    def _stat_or_reject(path: Path) -> os.stat_result:
        """Stat the path, translating OS errors into analyst-readable ones."""
        try:
            return path.stat()
        except FileNotFoundError:
            raise EvidenceError(f"no such file: {path}") from None
        except PermissionError:
            raise EvidenceError(f"permission denied: {path}") from None
        except OSError as exc:
            # Covers the awkward rest: a path segment that is not a directory,
            # a name too long for the filesystem, a dead network mount.
            raise EvidenceError(f"cannot access {path}: {exc}") from exc

    @staticmethod
    def _reject_if_not_a_regular_file(path: Path, mode: int) -> None:
        """Reject directories and anything that is not a plain file.

        This is a safety check, not a tidiness one. Reading a FIFO blocks until
        a writer appears, so hashing one would hang the investigation forever,
        and character devices such as ``/dev/zero`` are endless. A forensics
        tool must not be stoppable by handing it the wrong kind of path.
        """
        if stat_module.S_ISDIR(mode):
            raise EvidenceError(f"{path} is a directory; SentinelForge analyses one file at a time")
        if not stat_module.S_ISREG(mode):
            raise EvidenceError(
                f"{path} is not a regular file; sockets, pipes and device files "
                "cannot be analysed as evidence"
            )

    @staticmethod
    def _reject_if_unreadable(path: Path) -> None:
        """Confirm the file can actually be opened for reading.

        Deliberately an ``open`` attempt rather than ``os.access``.
        ``os.access`` answers using the real user ID and does not understand
        Windows ACLs, so it can cheerfully report success on a file that then
        refuses to open. Opening is the only honest test.

        Failing here, rather than partway through hashing, means a permission
        problem is reported before the report has half-formed content in it.
        """
        try:
            with path.open("rb"):
                pass
        except OSError as exc:
            raise EvidenceError(f"cannot read {path}: {exc}") from exc
