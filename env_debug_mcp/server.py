"""MCP server for debugging environment variables.

This module provides a FastMCP-based stdio server that exposes a `debug_env`
tool for safely inspecting environment variables. Sensitive values (those
containing KEY, TOKEN, CRED, SECRET, AUTH, PASSWORD, or PASSPHRASE) are
automatically redacted to prevent accidental exposure of secrets.

Example usage::

    # Run as an MCP server
    python -m env_debug_mcp.server

    # Or via the installed entrypoint
    env-debug-mcp

"""

from __future__ import annotations

import os
import re
import typing as typ

if typ.TYPE_CHECKING:
    import collections.abc as cabc

from fastmcp import FastMCP

mcp = FastMCP("env-debug-mcp")

# Match sensitive patterns at word boundaries (underscore or start/end of string).
# - KEY, TOKEN, CRED, SECRET, AUTH: match after ^ or _ (allows CREDENTIALS, etc.)
# - PASSWORD, PASSPHRASE: match explicitly to distinguish from PASSPORT
# - PASS: match only at complete word boundaries (e.g., DB_PASS but not COMPASS)
_SENSITIVE_PATTERN = re.compile(
    r"(^|_)(KEY|TOKEN|CRED|SECRET|AUTH|PASSWORD|PASSPHRASE)|(^|_)PASS(_|$)",
    re.IGNORECASE,
)


def _redact_value(value: str) -> str:
    """Replace alphanumeric characters with asterisks."""
    return re.sub(r"[a-zA-Z0-9]", "*", value)


def _is_sensitive_key(key: str) -> bool:
    """Check if key contains sensitive patterns at word boundaries."""
    return _SENSITIVE_PATTERN.search(key) is not None


def _get_debug_env(env: cabc.Mapping[str, str] | None = None) -> dict[str, str]:
    """Return environment variables with sensitive values redacted."""
    if env is None:
        env = os.environ
    return {
        key: _redact_value(value) if _is_sensitive_key(key) else value
        for key, value in env.items()
    }


@mcp.tool
def debug_env() -> dict[str, str]:
    """Return environment variables with sensitive values redacted.

    Variables with KEY, TOKEN, CRED, SECRET, AUTH, PASSWORD, or PASSPHRASE at
    word boundaries have alphanumeric characters replaced with asterisks.

    Returns
    -------
    dict[str, str]
        Environment variables with sensitive values redacted.

    """
    return _get_debug_env()


def main() -> None:
    """Run the MCP server.

    Starts the FastMCP server with stdio transport, allowing MCP clients
    to connect and invoke the debug_env tool.

    Returns
    -------
    None

    """
    mcp.run()


if __name__ == "__main__":
    main()
