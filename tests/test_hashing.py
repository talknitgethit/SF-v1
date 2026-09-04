"""Tests for the hashing analyser.

Expected digests are hard-coded published values rather than results computed
with :mod:`hashlib` inside the test. Comparing hashlib against hashlib would
prove only that it agrees with itself; these constants are independently
verifiable with ``sha256sum`` or any other tool, which is the property that
matters for a forensic identifier.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from sentrytrace.analyzers.hashing import (
    DEFAULT_ALGORITHMS,
    PRIMARY_ALGORITHM,
    hash_file,
    primary_digest,
)
from sentrytrace.core.evidence import Evidence
from sentrytrace.exceptions import EvidenceError

EMPTY_DIGESTS = {
    "md5": "d41d8cd98f00b204e9800998ecf8427e",
    "sha1": "da39a3ee5e6b4b0d3255bfef95601890afd80709",
    "sha256": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
}

HELLO_DIGESTS = {
    "md5": "5d41402abc4b2a76b9719d911017c592",
    "sha1": "aaf4c61ddcc5e8a2dabede0f3b482cd9aea9434d",
    "sha256": "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824",
}


def make_evidence(tmp_path: Path, name: str, content: bytes) -> Evidence:
    path = tmp_path / name
    path.write_bytes(content)
    return Evidence.from_path(path)


def test_hashes_known_content(tmp_path: Path) -> None:
    evidence = make_evidence(tmp_path, "hello.txt", b"hello")

    assert hash_file(evidence) == HELLO_DIGESTS


def test_hashes_an_empty_file(tmp_path: Path) -> None:
    """Zero bytes still has a digest, and the read loop must not hang on it."""
    evidence = make_evidence(tmp_path, "empty.bin", b"")

    assert hash_file(evidence) == EMPTY_DIGESTS


def test_computes_every_default_algorithm(tmp_path: Path) -> None:
    evidence = make_evidence(tmp_path, "hello.txt", b"hello")

    assert tuple(hash_file(evidence)) == DEFAULT_ALGORITHMS


@pytest.mark.parametrize("chunk_size", [1, 3, 7, 1024])
def test_chunk_size_does_not_change_the_digest(tmp_path: Path, chunk_size: int) -> None:
    """The core guarantee of chunked hashing.

    Content is deliberately not a multiple of any chunk size, so the final
    short read is exercised. A digest that varied with buffer size would make
    every report unreproducible.
    """
    evidence = make_evidence(tmp_path, "blob.bin", b"forensics" * 1000)

    digests = hash_file(evidence, chunk_size=chunk_size)

    assert digests == hash_file(evidence)


def test_reads_a_file_larger_than_one_chunk(tmp_path: Path) -> None:
    content = bytes(range(256)) * 500  # 128 000 bytes
    evidence = make_evidence(tmp_path, "large.bin", content)

    digests = hash_file(evidence, chunk_size=4096)

    assert len(digests[PRIMARY_ALGORITHM]) == 64


def test_can_request_a_subset_of_algorithms(tmp_path: Path) -> None:
    evidence = make_evidence(tmp_path, "hello.txt", b"hello")

    digests = hash_file(evidence, algorithms=["sha256"])

    assert digests == {"sha256": HELLO_DIGESTS["sha256"]}


def test_unknown_algorithm_is_rejected_with_a_useful_message(tmp_path: Path) -> None:
    evidence = make_evidence(tmp_path, "hello.txt", b"hello")

    with pytest.raises(ValueError, match="unknown hash algorithm"):
        hash_file(evidence, algorithms=["sha255"])


def test_empty_algorithm_list_is_rejected(tmp_path: Path) -> None:
    evidence = make_evidence(tmp_path, "hello.txt", b"hello")

    with pytest.raises(ValueError, match="at least one hash algorithm"):
        hash_file(evidence, algorithms=[])


def test_non_positive_chunk_size_is_rejected(tmp_path: Path) -> None:
    """Guards against an infinite loop: read(0) returns b'' forever."""
    evidence = make_evidence(tmp_path, "hello.txt", b"hello")

    with pytest.raises(ValueError, match="chunk_size must be positive"):
        hash_file(evidence, chunk_size=0)


def test_file_removed_after_validation_raises_evidence_error(tmp_path: Path) -> None:
    """Validation and hashing are separate moments; the file can change between."""
    evidence = make_evidence(tmp_path, "vanishing.bin", b"here for now")
    evidence.path.unlink()

    with pytest.raises(EvidenceError, match="failed while reading"):
        hash_file(evidence)


class TestPrimaryDigest:
    def test_returns_the_sha256_value(self) -> None:
        assert primary_digest(HELLO_DIGESTS) == HELLO_DIGESTS["sha256"]

    def test_returns_none_rather_than_falling_back_to_a_weak_digest(self) -> None:
        assert primary_digest({"md5": HELLO_DIGESTS["md5"]}) is None
