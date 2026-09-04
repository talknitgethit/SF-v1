"""Human-readable terminal rendering.

Pure formatting. This module knows how to lay out titled sections of labelled
values; it knows nothing about hashes, severity, or what any of it means. That
separation is what stops presentation choices from ever changing a result.

Every report format SentryTrace produces is ultimately a sequence of titled
sections, so this shape holds as the investigation result grows.
"""

from __future__ import annotations

from collections.abc import Mapping

INDENT = "  "


def render_sections(sections: Mapping[str, Mapping[str, str]]) -> str:
    """Render titled sections of ``label: value`` pairs as plain text.

    Labels within a section are padded to a common width so values line up and
    a long digest can be compared against another by eye. Empty sections are
    skipped rather than printed as a bare heading with nothing under it.
    """
    blocks: list[str] = []

    for title, values in sections.items():
        if not values:
            continue
        blocks.append(_render_section(title, values))

    return "\n\n".join(blocks)


def _render_section(title: str, values: Mapping[str, str]) -> str:
    label_width = max(len(label) for label in values)
    lines = [title, "-" * len(title)]
    lines.extend(f"{INDENT}{label:<{label_width}}  {value}" for label, value in values.items())
    return "\n".join(lines)
