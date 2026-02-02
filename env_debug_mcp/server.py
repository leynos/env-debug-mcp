"""MCP server for debugging environment variables."""

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
    """Check if environment variable key contains sensitive patterns.

    Matches KEY, TOKEN, CRED, SECRET, AUTH, PASSWORD, or PASSPHRASE after
    underscore or string start. Matches PASS only at complete word boundaries
    to avoid false positives like COMPASS or PASSPORT.
    """
    return _SENSITIVE_PATTERN.search(key) is not None


def _get_debug_env(
    env: cabc.Mapping[str, str] | None = None,
) -> dict[str, str]:
    """Return environment variables with sensitive values redacted.

    Args:
        env: Environment mapping to process. Defaults to os.environ.

    Returns:
        Dictionary with sensitive values redacted. Variables with KEY, TOKEN,
        CRED, SECRET, AUTH, PASSWORD, or PASSPHRASE in their name have
        alphanumeric characters replaced with asterisks.

    """
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
    """
    return _get_debug_env()


def main() -> None:
    """Run the MCP server."""
    mcp.run()


if __name__ == "__main__":
    main()
