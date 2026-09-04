"""Analysers: components that examine validated evidence and report facts.

An analyser receives already-validated evidence and returns data. It never
resolves paths, never prompts, and never executes what it is looking at.

Planned modules:

``hashing.py``
    Chunked MD5, SHA-1 and SHA-256 digests. SHA-256 is the primary forensic
    identifier; MD5 and SHA-1 are computed because threat intelligence sources
    still index by them, not because they are cryptographically sound.
``metadata.py``
    Filesystem metadata: size, extension, and timestamps, with honest handling
    of the fields a given operating system cannot actually provide.
``heuristics.py``
    Rule-based suspicion analysis producing explained findings.
"""
