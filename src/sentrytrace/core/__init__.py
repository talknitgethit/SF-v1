"""Core investigation domain: evidence intake, data models, orchestration.

This package owns *what an investigation is*, independent of how evidence is
analysed or how results are displayed.

Planned modules:

``evidence.py``
    The ``Evidence`` type and its validating factory. The single place where an
    untrusted, user-supplied path is checked and resolved before any other code
    is allowed to touch it.
``models.py``
    ``Finding``, ``Severity`` and ``InvestigationResult``: the structured result
    that every report format renders from.
``investigator.py``
    Orchestration. Takes validated evidence, runs the analysers, assembles the
    result.
"""
