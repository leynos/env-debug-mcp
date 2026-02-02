"""Pytest fixtures for env-debug-mcp tests.

Provides shared test fixtures for environment variable patching and other
common test setup.

"""

from __future__ import annotations

import os
import typing as typ
from unittest import mock

import pytest

if typ.TYPE_CHECKING:
    import collections.abc as cabc


@pytest.fixture
def patched_environ() -> cabc.Generator[dict[str, str]]:
    """Provide a clean, isolated environment for testing.

    Clears os.environ and yields it for direct manipulation. Changes made to
    the yielded dict are reflected in os.environ, and the original environment
    is restored after the test completes.

    Yields
    ------
    dict[str, str]
        The os.environ dict, cleared and ready for test data.

    """
    with mock.patch.dict(os.environ, clear=True):
        yield os.environ  # type: ignore[misc]
