"""Exception types raised deliberately by SentryTrace.

Every error SentryTrace raises on purpose inherits from
:class:`SentryTraceError`. That gives the CLI a single, narrow thing to catch:

    try:
        return handler(args)
    except SentryTraceError as exc:
        log.error("%s", exc)
        return 1

An expected failure (the evidence file does not exist, the report directory is
not writable) becomes one clear line for the analyst. Anything else, a genuine
bug in SentryTrace, is left to propagate as a traceback.

That distinction matters more here than in most applications. A forensics tool
that silently swallows its own bugs and reports "no findings" is worse than one
that crashes, because the analyst cannot tell the difference between "clean" and
"broken".
"""


class SentryTraceError(Exception):
    """Base class for all errors SentryTrace raises on purpose."""


class EvidenceError(SentryTraceError):
    """Raised when a piece of evidence cannot be accepted for analysis.

    Covers the whole intake path: the path does not exist, points at something
    that is not a regular file, or cannot be read by the current user.
    """


class ReportError(SentryTraceError):
    """Raised when an investigation result cannot be rendered or written."""
