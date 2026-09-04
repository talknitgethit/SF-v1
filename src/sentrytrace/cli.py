"""Command-line interface for SentryTrace.

This module only parses arguments, configures logging, and dispatches to a
handler. Analysis lives in :mod:`sentrytrace.analyzers` and rendering lives in
:mod:`sentrytrace.reporting`, so the CLI stays a thin, readable shell around
an engine that can also be driven from Python.

Built on :mod:`argparse` from the standard library. Sub-commands already model
what the roadmap needs (``analyze`` now; ``logs`` and ``pcap`` later), and a
security tool with zero runtime dependencies is easier to trust and to install.
"""

from __future__ import annotations

import argparse
import logging
from collections.abc import Sequence
from pathlib import Path

from sentrytrace import __version__
from sentrytrace.analyzers.hashing import hash_file
from sentrytrace.core.evidence import Evidence
from sentrytrace.exceptions import SentryTraceError
from sentrytrace.reporting.console import render_sections
from sentrytrace.utils.logging_config import configure_logging

log = logging.getLogger(__name__)

# Distinct exit codes so scripts can tell "you asked wrong" from "it went
# wrong". argparse already exits 2 on usage errors, so that value is reserved.
EXIT_OK = 0
EXIT_ERROR = 1
EXIT_USAGE = 2

DESCRIPTION = "Analyse untrusted evidence and produce a structured investigation result."

EPILOG = (
    "SentryTrace reads evidence as bytes. It never executes, imports, or opens "
    "the files it analyses, and it never uploads them anywhere."
)


def build_parser() -> argparse.ArgumentParser:
    """Construct the top-level parser and its sub-commands.

    Kept separate from :func:`main` so tests can inspect the parser directly
    and so ``--help`` output can be checked without running an investigation.
    """
    parser = argparse.ArgumentParser(
        prog="sentrytrace",
        description=DESCRIPTION,
        epilog=EPILOG,
    )
    parser.add_argument(
        "--version",
        action="version",
        version=f"sentrytrace {__version__}",
    )

    # Mutually exclusive: "-q -v" is a contradiction, so argparse should reject
    # it rather than leave us guessing which one the analyst meant.
    verbosity = parser.add_mutually_exclusive_group()
    verbosity.add_argument(
        "-v",
        "--verbose",
        action="count",
        default=0,
        help="increase log detail (-v for progress, -vv for debug)",
    )
    verbosity.add_argument(
        "-q",
        "--quiet",
        action="store_true",
        help="suppress everything except errors",
    )

    subparsers = parser.add_subparsers(dest="command", metavar="<command>")

    analyze = subparsers.add_parser(
        "analyze",
        help="analyse a single file of evidence",
        description="Analyse a single file and report hashes, metadata and findings.",
        epilog=EPILOG,
    )
    analyze.add_argument(
        "path",
        type=Path,
        help="path to the file to analyse",
    )
    analyze.add_argument(
        "--follow-symlinks",
        action="store_true",
        help="analyse the target of a symbolic link instead of refusing it",
    )
    analyze.set_defaults(handler=handle_analyze)

    return parser


def handle_analyze(args: argparse.Namespace) -> int:
    """Handle ``sentrytrace analyze <path>``.

    Validate the path, run the analysers, print the result. Assembling the
    sections here is temporary: it moves into the investigator once there is an
    ``InvestigationResult`` for the analysers to contribute to.
    """
    log.info("investigation started: %s", args.path)

    evidence = Evidence.from_path(args.path, follow_symlinks=args.follow_symlinks)
    digests = hash_file(evidence)

    print(
        render_sections(
            {
                "File Information": {
                    "Name": evidence.name,
                    "Path": str(evidence.path),
                    "Extension": evidence.extension or "(none)",
                    "Size": f"{evidence.size_bytes:,} bytes",
                },
                "Hashes": {name.upper(): digest for name, digest in digests.items()},
            }
        )
    )

    log.info("investigation complete")
    return EXIT_OK


def main(argv: Sequence[str] | None = None) -> int:
    """Run the CLI and return a process exit code.

    Returns rather than calls ``sys.exit`` so tests can invoke it as an ordinary
    function; ``__main__.py`` turns the return value into the real exit status.

    ``argv`` defaults to ``None``, which lets argparse read ``sys.argv``.
    """
    parser = build_parser()
    args = parser.parse_args(argv)

    configure_logging(args.verbose, quiet=args.quiet)

    handler = getattr(args, "handler", None)
    if handler is None:
        parser.print_help()
        return EXIT_USAGE

    try:
        return handler(args)
    except SentryTraceError as exc:
        # Expected failures get one clear line. Unexpected exceptions are
        # deliberately not caught: a bug in the engine must be loud, because a
        # forensics tool that hides its own faults cannot be trusted to say
        # "nothing suspicious found".
        log.error("%s", exc)
        return EXIT_ERROR
