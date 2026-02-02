"""Pytest fixtures for env-debug-mcp tests.

Provides shared test fixtures for environment variable patching and other
common test setup.

Example usage::

    def test_with_clean_env(patched_environ: cabc.MutableMapping[str, str]) -> None:
        patched_environ["MY_VAR"] = "value"
        # os.environ now contains only MY_VAR

"""

from __future__ import annotations

import os
import typing as typ
from unittest import mock

import pytest

if typ.TYPE_CHECKING:
    import collections.abc as cabc


@pytest.fixture
def patched_environ() -> cabc.Generator[cabc.MutableMapping[str, str]]:
    """Provide a clean, isolated environment for testing.

    Clears os.environ and yields it for direct manipulation. Changes made to
    the yielded dict are reflected in os.environ, and the original environment
    is restored after the test completes.

    Yields
    ------
    collections.abc.MutableMapping[str, str]
        The os.environ object, cleared and ready for test data.

    """
    with mock.patch.dict(os.environ, clear=True):
        yield os.environ
