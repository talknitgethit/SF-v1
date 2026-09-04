"""Sanity checks on the package itself and its packaging metadata."""

from __future__ import annotations

from importlib import metadata

import sentrytrace


def test_version_is_a_non_empty_string() -> None:
    assert isinstance(sentrytrace.__version__, str)
    assert sentrytrace.__version__


def test_installed_version_matches_source() -> None:
    """The version in ``__init__.py`` is the one pip actually installed.

    ``pyproject.toml`` declares the version as dynamic and points hatchling at
    ``src/sentrytrace/__init__.py``. If that wiring ever breaks, the installed
    distribution and the source drift apart silently. This catches it.
    """
    assert metadata.version("sentrytrace") == sentrytrace.__version__


def test_subpackages_are_importable() -> None:
    """The src layout is wired up correctly and every subpackage ships."""
    import sentrytrace.analyzers  # noqa: F401
    import sentrytrace.core  # noqa: F401
    import sentrytrace.reporting  # noqa: F401
    import sentrytrace.utils  # noqa: F401
