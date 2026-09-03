"""Tests for the command-line interface.

These cover the CLI contract: what exit code each kind of invocation produces,
and which stream the output lands on.
"""

from __future__ import annotations

import logging

import pytest

import sentinelforge
from sentinelforge.cli import EXIT_ERROR, EXIT_USAGE, build_parser, main


def test_help_exits_cleanly_and_lists_analyze(run_cli) -> None:
    result = run_cli("--help")

    assert result.exit_code == 0
    assert "analyze" in result.stdout
    assert "sentinelforge" in result.stdout


def test_version_reports_the_package_version(run_cli) -> None:
    result = run_cli("--version")

    assert result.exit_code == 0
    assert sentinelforge.__version__ in result.stdout


def test_no_arguments_prints_help_and_signals_usage_error(run_cli) -> None:
    """Bare ``sentinelforge`` should teach, not fail silently."""
    result = run_cli()

    assert result.exit_code == EXIT_USAGE
    assert "usage:" in result.stdout


def test_unknown_command_is_rejected(run_cli) -> None:
    result = run_cli("exfiltrate")

    assert result.exit_code == EXIT_USAGE
    assert "invalid choice" in result.stderr


def test_verbose_and_quiet_cannot_be_combined(run_cli) -> None:
    result = run_cli("-v", "-q", "analyze", "evidence.bin")

    assert result.exit_code == EXIT_USAGE
    assert "not allowed with" in result.stderr


def test_analyze_stub_fails_gracefully(run_cli) -> None:
    """The unimplemented handler must produce a clean error, not a traceback."""
    result = run_cli("analyze", "evidence.bin")

    assert result.exit_code == EXIT_ERROR
    assert "not implemented yet" in result.stderr
    assert "evidence.bin" in result.stderr


def test_errors_never_contaminate_stdout(run_cli) -> None:
    """stdout is reserved for report output so it stays machine-parseable."""
    result = run_cli("analyze", "evidence.bin")

    assert result.stdout == ""


def test_unexpected_exceptions_are_not_swallowed(monkeypatch, run_cli) -> None:
    """Only SentinelForgeError is handled; real bugs must stay loud.

    A forensics tool that catches everything can report "no findings" when it
    actually crashed, and the analyst cannot tell the difference.
    """

    def exploding_handler(_args):
        raise RuntimeError("engine fault")

    monkeypatch.setattr("sentinelforge.cli.handle_analyze", exploding_handler)

    with pytest.raises(RuntimeError, match="engine fault"):
        main(["analyze", "evidence.bin"])


def test_parser_defaults_are_sane() -> None:
    parser = build_parser()
    args = parser.parse_args(["analyze", "evidence.bin"])

    assert args.command == "analyze"
    assert args.verbose == 0
    assert args.quiet is False
    assert args.path.name == "evidence.bin"


@pytest.mark.parametrize(
    ("argv", "expected_level"),
    [
        (["analyze", "e.bin"], logging.WARNING),
        (["-v", "analyze", "e.bin"], logging.INFO),
        (["-vv", "analyze", "e.bin"], logging.DEBUG),
        (["-q", "analyze", "e.bin"], logging.ERROR),
    ],
)
def test_verbosity_flags_set_the_log_level(run_cli, argv, expected_level) -> None:
    run_cli(*argv)

    assert logging.getLogger("sentinelforge").level == expected_level
