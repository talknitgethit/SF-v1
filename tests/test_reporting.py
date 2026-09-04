"""Tests for console rendering."""

from __future__ import annotations

from sentrytrace.reporting.console import render_sections


def test_renders_a_titled_section_with_underline() -> None:
    output = render_sections({"Hashes": {"SHA256": "abc"}})

    assert output.splitlines()[:2] == ["Hashes", "------"]


def test_includes_every_label_and_value() -> None:
    output = render_sections({"File Information": {"Name": "notes.txt", "Size": "5 bytes"}})

    assert "Name" in output
    assert "notes.txt" in output
    assert "Size" in output
    assert "5 bytes" in output


def test_labels_are_padded_to_a_common_width() -> None:
    """Aligned columns let an analyst compare two digests by eye."""
    output = render_sections({"Hashes": {"MD5": "aaa", "SHA256": "bbb"}})

    value_lines = output.splitlines()[2:]
    value_columns = {
        line.index(value) for line, value in zip(value_lines, ["aaa", "bbb"], strict=True)
    }

    assert len(value_columns) == 1


def test_sections_are_separated_by_a_blank_line() -> None:
    output = render_sections({"One": {"a": "1"}, "Two": {"b": "2"}})

    assert "\n\n" in output


def test_empty_sections_are_omitted() -> None:
    """A heading with nothing beneath it reads like something went wrong."""
    output = render_sections({"Findings": {}, "Hashes": {"MD5": "aaa"}})

    assert "Findings" not in output
    assert "Hashes" in output


def test_no_sections_renders_nothing() -> None:
    assert render_sections({}) == ""
