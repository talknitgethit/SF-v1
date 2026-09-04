"""SentryTrace: a security investigation and digital forensics platform.

SentryTrace inspects untrusted evidence (currently individual files) and
produces a structured investigation result: identifying hashes, filesystem
metadata, and rule-based findings with an explained severity.

The engine is deterministic. Every finding states the rule that produced it and
why it triggered, so a result can be reviewed and disputed by a human analyst.

Evidence is always treated as hostile: it is read as bytes and never executed,
imported, evaluated, or opened by the operating system.
"""

__version__ = "0.1.0.dev0"

__all__ = ["__version__"]
