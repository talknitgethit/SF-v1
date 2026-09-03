"""Sanity checks on the package itself and its packaging metadata."""

from __future__ import annotations

from importlib import metadata

import sentinelforge


def test_version_is_a_non_empty_string() -> None:
    assert isinstance(sentinelforge.__version__, str)
    assert sentinelforge.__version__


def test_installed_version_matches_source() -> None:
    """The version in ``__init__.py`` is the one pip actually installed.

    ``pyproject.toml`` declares the version as dynamic and points hatchling at
    ``src/sentinelforge/__init__.py``. If that wiring ever breaks, the installed
    distribution and the source drift apart silently. This catches it.
    """
    assert metadata.version("sentinelforge") == sentinelforge.__version__


def test_subpackages_are_importable() -> None:
    """The src layout is wired up correctly and every subpackage ships."""
    import sentinelforge.analyzers  # noqa: F401
    import sentinelforge.core  # noqa: F401
    import sentinelforge.reporting  # noqa: F401
    import sentinelforge.utils  # noqa: F401
