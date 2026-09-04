"""Cryptographic hashing of evidence.

A hash is the identifier an investigation is built on. It is how you say "this
exact file" in a report, how you check that evidence has not changed since it
was collected, and how you ask a threat intelligence service about a sample
without sending the sample anywhere.

**SHA-256 is the primary identifier.** MD5 and SHA-1 are computed as well, and
the reason is entirely practical: existing tooling, published indicators of
compromise, and threat intelligence feeds still index by them, so an analyst
needs those values to look anything up. Both are broken for security purposes.
Two different files can be made to share an MD5 or SHA-1 digest deliberately, so
neither is evidence that two files are identical. Only SHA-256 is used that way
here.
"""

from __future__ import annotations

import hashlib
import logging
from collections.abc import Iterable, Mapping

from sentrytrace.core.evidence import Evidence
from sentrytrace.exceptions import EvidenceError

log = logging.getLogger(__name__)

PRIMARY_ALGORITHM = "sha256"
"""The digest SentryTrace treats as the file's forensic identity."""

DEFAULT_ALGORITHMS: tuple[str, ...] = ("md5", "sha1", "sha256")
"""Digests computed for every investigation, in report order."""

CHUNK_SIZE = 1024 * 1024
"""Bytes read per iteration (1 MiB).

Evidence can be a multi-gigabyte disk image, and ``handle.read()`` with no
argument would pull all of it into memory at once. Reading in fixed-size chunks
keeps memory flat regardless of file size, which is the difference between a
tool that works on real evidence and one that only works on samples.
"""


def hash_file(
    evidence: Evidence,
    *,
    algorithms: Iterable[str] = DEFAULT_ALGORITHMS,
    chunk_size: int = CHUNK_SIZE,
) -> dict[str, str]:
    """Compute digests of ``evidence`` and return them as ``{name: hexdigest}``.

    Every algorithm is fed from a single pass over the file. Hashing three times
    would mean reading the bytes three times, and on a large image held on a
    slow or write-blocked forensic disk, I/O is the entire cost of the operation.

    Takes :class:`~sentrytrace.core.evidence.Evidence` rather than a path, so
    the type signature itself records that this function only ever runs on input
    that has already cleared validation.

    Raises :class:`~sentrytrace.exceptions.EvidenceError` if the file becomes
    unreadable mid-read, and ``ValueError`` for an unknown algorithm name.
    """
    hashers = {name: _new_hasher(name) for name in algorithms}
    if not hashers:
        raise ValueError("at least one hash algorithm must be requested")

    if chunk_size <= 0:
        raise ValueError(f"chunk_size must be positive, got {chunk_size}")

    log.info("hashing %s (%s)", evidence.name, ", ".join(hashers))

    bytes_read = 0
    try:
        with evidence.path.open("rb") as handle:
            # The walrus operator assigns and tests in one step; the loop ends
            # when read() returns an empty bytes object at end of file.
            while chunk := handle.read(chunk_size):
                bytes_read += len(chunk)
                for hasher in hashers.values():
                    hasher.update(chunk)
    except OSError as exc:
        # Validation proved the file was readable at intake. Reaching here means
        # it changed underneath us: removed, unmounted, or locked by something
        # else. That is worth reporting plainly rather than crashing.
        raise EvidenceError(f"failed while reading {evidence.path}: {exc}") from exc

    digests = {name: hasher.hexdigest() for name, hasher in hashers.items()}
    log.info(
        "hashed %d bytes; %s=%s", bytes_read, PRIMARY_ALGORITHM, digests.get(PRIMARY_ALGORITHM)
    )
    return digests


def primary_digest(digests: Mapping[str, str]) -> str | None:
    """Return the SHA-256 digest from a result, or ``None`` if absent.

    A named helper so that report code never hard-codes the string ``"sha256"``
    and, more importantly, never silently falls back to a weaker digest as the
    file's identity.
    """
    return digests.get(PRIMARY_ALGORITHM)


def _new_hasher(name: str):
    """Create a hash object, rejecting unknown algorithm names clearly.

    ``usedforsecurity=False`` is the interesting argument. It declares that MD5
    and SHA-1 are being used as identifiers rather than as security primitives.
    That is not decoration: on a system running in FIPS mode the interpreter
    refuses to construct an MD5 hasher without it, so omitting it would make
    SentryTrace fail outright on exactly the kind of hardened machine a
    responder is likely to be working from.
    """
    try:
        return hashlib.new(name, usedforsecurity=False)
    except ValueError as exc:
        available = ", ".join(sorted(hashlib.algorithms_available))
        raise ValueError(f"unknown hash algorithm {name!r}; available: {available}") from exc
