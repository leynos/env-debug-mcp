"""MCP server for debugging environment variables."""

from __future__ import annotations

import os
import re

from fastmcp import FastMCP

mcp = FastMCP("env-debug-mcp")

_SENSITIVE_PATTERN = re.compile(r"(KEY|TOKEN|CRED|PASS)", re.IGNORECASE)


def _redact_value(value: str) -> str:
    """Replace alphanumeric characters with asterisks."""
    return re.sub(r"[a-zA-Z0-9]", "*", value)


def _is_sensitive_key(key: str) -> bool:
    """Check if environment variable key contains sensitive patterns."""
    return _SENSITIVE_PATTERN.search(key) is not None


def _get_debug_env() -> dict[str, str]:
    """Return environment variables with sensitive values redacted.

    Variables with KEY, TOKEN, CRED, or PASS in their name have alphanumeric
    characters in their values replaced with asterisks.
    """
    result: dict[str, str] = {}
    for key, value in os.environ.items():
        if _is_sensitive_key(key):
            result[key] = _redact_value(value)
        else:
            result[key] = value
    return result


@mcp.tool
def debug_env() -> dict[str, str]:
    """Return environment variables with sensitive values redacted.

    Variables with KEY, TOKEN, CRED, or PASS in their name have alphanumeric
    characters in their values replaced with asterisks.
    """
    return _get_debug_env()


def main() -> None:
    """Run the MCP server."""
    mcp.run()
