"""Logging setup for the SentryTrace command-line application.

Two rules drive this module.

**Logs go to stderr, never stdout.** stdout belongs to investigation output. Once
``analyze --json`` exists, ``sentrytrace analyze evidence.bin --json | jq``
has to stay valid no matter how much logging is switched on. Mixing a log line
into that stream corrupts the report.

**Never log file contents.** Evidence is untrusted and may contain credentials,
personal data, or terminal escape sequences. Log paths, sizes, digests and rule
names: facts *about* the evidence, not the evidence itself.
"""

from __future__ import annotations

import logging
import sys
from typing import TextIO

PACKAGE_LOGGER = "sentrytrace"

LOG_FORMAT = "%(asctime)s %(levelname)-8s %(name)s: %(message)s"
DATE_FORMAT = "%Y-%m-%dT%H:%M:%S"


def resolve_level(verbosity: int = 0, *, quiet: bool = False) -> int:
    """Map CLI verbosity flags onto a :mod:`logging` level.

    ``quiet`` wins over ``verbosity``: an explicit ``--quiet`` should never be
    overridden by a stray ``-v``.

    ==================  =========
    Flags               Level
    ==================  =========
    ``--quiet``         ERROR
    (none)              WARNING
    ``-v``              INFO
    ``-vv`` or more     DEBUG
    ==================  =========

    The default is WARNING rather than INFO so a plain run prints only the
    report. Investigation progress ("hashing started", "analyser finished") is
    INFO and appears with ``-v``.
    """
    if quiet:
        return logging.ERROR
    if verbosity <= 0:
        return logging.WARNING
    if verbosity == 1:
        return logging.INFO
    return logging.DEBUG


def configure_logging(
    verbosity: int = 0,
    *,
    quiet: bool = False,
    stream: TextIO | None = None,
) -> logging.Logger:
    """Attach a stderr handler to the ``sentrytrace`` logger and return it.

    Configures the package logger rather than the root logger. Reconfiguring
    the root logger would silently change logging for anything else running in
    the same process, which matters because the analysis engine is meant to be
    importable by the web dashboard and other callers later on.

    ``stream`` exists so tests can capture output; production callers leave it
    at ``None`` to get the ``sys.stderr`` in effect at call time.
    """
    logger = logging.getLogger(PACKAGE_LOGGER)
    logger.setLevel(resolve_level(verbosity, quiet=quiet))

    # Calling main() twice in one process (tests do exactly this) would
    # otherwise stack handlers and duplicate every line.
    for existing in list(logger.handlers):
        logger.removeHandler(existing)

    handler = logging.StreamHandler(stream if stream is not None else sys.stderr)
    handler.setFormatter(logging.Formatter(LOG_FORMAT, datefmt=DATE_FORMAT))
    logger.addHandler(handler)

    # Without this, records also travel to the root logger and print twice for
    # anyone who has called logging.basicConfig().
    logger.propagate = False

    return logger
