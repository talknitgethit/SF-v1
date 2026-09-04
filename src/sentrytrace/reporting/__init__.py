"""Reporting: rendering an investigation result into an output format.

Reporters read the structured result and write it out. They never analyse and
never mutate the result, so adding a format cannot change a verdict.

Planned modules:

``console.py``
    Human-readable terminal output for an analyst reading along.
``json_report.py``
    Machine-readable JSON, complete enough for another tool to consume.
"""
