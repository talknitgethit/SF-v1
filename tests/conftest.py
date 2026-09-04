"""Shared pytest fixtures.

``conftest.py`` is discovered automatically by pytest; anything defined here is
available to every test module in this directory without being imported.
"""

from __future__ import annotations

from dataclasses import dataclass

import pytest

from sentrytrace.cli import main


@dataclass(frozen=True)
class CliResult:
    """What a CLI invocation produced: exit code plus each output stream.

    A dataclass rather than a tuple so assertions read as
    ``result.stderr`` instead of ``result[2]``. ``frozen=True`` makes it
    read-only, which prevents a test from accidentally mutating a result and
    confusing whatever asserts next.
    """

    exit_code: int
    stdout: str
    stderr: str


@pytest.fixture
def run_cli(capsys: pytest.CaptureFixture[str]):
    """Run the CLI in-process and capture its exit code and output.

    In-process rather than via ``subprocess`` because it is far faster, gives
    real tracebacks when something breaks, and does not depend on the package
    being installed on PATH.

    ``main`` normally returns an exit code, but argparse raises ``SystemExit``
    for ``--help``, ``--version`` and usage errors. Both are normalised here so
    tests can assert on ``exit_code`` either way.
    """

    def _run(*argv: str) -> CliResult:
        try:
            exit_code = main(list(argv))
        except SystemExit as exc:
            if exc.code is None:
                exit_code = 0
            elif isinstance(exc.code, int):
                exit_code = exc.code
            else:  # argparse can exit with a message string
                exit_code = 1
        captured = capsys.readouterr()
        return CliResult(exit_code=exit_code, stdout=captured.out, stderr=captured.err)

    return _run
