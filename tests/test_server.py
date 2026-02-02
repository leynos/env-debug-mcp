"""Tests for the MCP server redaction logic.

This module contains unit tests for the env-debug-mcp server, covering:
- Value redaction logic (_redact_value)
- Sensitive key detection (_is_sensitive_key)
- Environment variable processing (_get_debug_env)
- MCP tool integration (debug_env)

Run tests with::

    make test

Or directly with pytest::

    pytest tests/test_server.py -v

"""

from __future__ import annotations

import pytest

from env_debug_mcp.server import (
    _get_debug_env,
    _is_sensitive_key,
    _redact_value,
    debug_env,
)


class TestRedactValue:
    """Tests for _redact_value function."""

    @pytest.mark.parametrize(
        ("input_value", "expected"),
        [
            ("abc123", "******"),
            ("key=value!", "***=*****!"),
            ("my_api-key", "**_***-***"),
            ("", ""),
        ],
    )
    def test_redact_value(self, input_value: str, expected: str) -> None:
        """Alphanumeric chars replaced with asterisks, special chars preserved."""
        assert _redact_value(input_value) == expected, (
            f"Expected {input_value!r} to be redacted as {expected!r}"
        )


class TestIsSensitiveKey:
    """Tests for _is_sensitive_key function."""

    @pytest.mark.parametrize(
        "key",
        [
            "API_KEY",
            "api_key",
            "KEY",
            "MY_SECRET_KEY",
        ],
    )
    def test_matches_key_pattern(self, key: str) -> None:
        """Keys with KEY as a word boundary should be sensitive."""
        assert _is_sensitive_key(key) is True, (
            f"{key!r} should be detected as sensitive"
        )

    @pytest.mark.parametrize(
        "key",
        [
            "ACCESS_TOKEN",
            "access_token",
            "TOKEN",
            "GITHUB_TOKEN",
        ],
    )
    def test_matches_token_pattern(self, key: str) -> None:
        """Keys with TOKEN as a word boundary should be sensitive."""
        assert _is_sensitive_key(key) is True, (
            f"{key!r} should be detected as sensitive"
        )

    @pytest.mark.parametrize(
        "key",
        [
            "AWS_CREDENTIALS",
            "CREDENTIAL_PATH",
            "CRED",
            "credentials",
        ],
    )
    def test_matches_cred_pattern(self, key: str) -> None:
        """Keys with CRED at a start boundary should be sensitive."""
        assert _is_sensitive_key(key) is True, (
            f"{key!r} should be detected as sensitive"
        )

    @pytest.mark.parametrize(
        "key",
        [
            "PASSWORD",
            "DB_PASSWORD",
            "PASS",
            "PASSPHRASE",
            "password",
        ],
    )
    def test_matches_pass_pattern(self, key: str) -> None:
        """Keys with PASSWORD/PASSPHRASE or PASS at word boundaries."""
        assert _is_sensitive_key(key) is True, (
            f"{key!r} should be detected as sensitive"
        )

    @pytest.mark.parametrize(
        "key",
        [
            "SECRET",
            "AWS_SECRET_KEY",
            "SECRET_VALUE",
            "my_secret",
        ],
    )
    def test_matches_secret_pattern(self, key: str) -> None:
        """Keys with SECRET at a word boundary should be sensitive."""
        assert _is_sensitive_key(key) is True, (
            f"{key!r} should be detected as sensitive"
        )

    @pytest.mark.parametrize(
        "key",
        [
            "AUTH",
            "AUTH_TOKEN",
            "BASIC_AUTH",
            "authorization",
        ],
    )
    def test_matches_auth_pattern(self, key: str) -> None:
        """Keys with AUTH at a word boundary should be sensitive."""
        assert _is_sensitive_key(key) is True, (
            f"{key!r} should be detected as sensitive"
        )

    @pytest.mark.parametrize(
        "key",
        [
            "HOME",
            "PATH",
            "USER",
            "SHELL",
            "HOSTNAME",
            "COMPASS",
            "MONKEY",
            "PASSPORT_NUMBER",
            "SUBTOKEN_ID",
        ],
    )
    def test_non_sensitive_keys(self, key: str) -> None:
        """Keys without sensitive patterns at word boundaries should not match."""
        assert _is_sensitive_key(key) is False, (
            f"{key!r} should not be detected as sensitive"
        )


class TestGetDebugEnv:
    """Tests for _get_debug_env function."""

    def test_redacts_sensitive_values(self) -> None:
        """Sensitive environment variables should have values redacted."""
        test_env = {
            "API_KEY": "secret123",
            "HOME": "/home/user",
        }
        result = _get_debug_env(test_env)

        assert result["API_KEY"] == "*********", "API_KEY value should be redacted"
        assert result["HOME"] == "/home/user", "HOME value should be preserved"

    def test_preserves_non_sensitive_values(self) -> None:
        """Non-sensitive environment variables should be unchanged."""
        test_env = {
            "PATH": "/usr/bin:/bin",
            "SHELL": "/bin/bash",
        }
        result = _get_debug_env(test_env)

        assert result["PATH"] == "/usr/bin:/bin", "PATH value should be preserved"
        assert result["SHELL"] == "/bin/bash", "SHELL value should be preserved"

    def test_returns_expected_content(self) -> None:
        """_get_debug_env should return env with expected content."""
        test_env = {"HOME": "/home/user", "SHELL": "/bin/bash"}
        result = _get_debug_env(test_env)

        assert result == test_env, "Result should match input for non-sensitive keys"

    def test_handles_multiple_sensitive_patterns(self) -> None:
        """Multiple sensitive patterns should all be redacted."""
        test_env = {
            "API_KEY": "key123",
            "ACCESS_TOKEN": "tok456",
            "DB_PASSWORD": "pass789",
            "AWS_CREDENTIALS": "cred000",
        }
        result = _get_debug_env(test_env)

        assert result["API_KEY"] == "******", "API_KEY value should be redacted"
        assert result["ACCESS_TOKEN"] == "******", (
            "ACCESS_TOKEN value should be redacted"
        )
        assert result["DB_PASSWORD"] == "*******", (
            "DB_PASSWORD value should be redacted"
        )
        assert result["AWS_CREDENTIALS"] == "*******", (
            "AWS_CREDENTIALS value should be redacted"
        )

    def test_defaults_to_os_environ(
        self,
        patched_environ: dict[str, str],
    ) -> None:
        """When no env is provided, should use os.environ."""
        patched_environ["TEST_VAR"] = "value"
        result = _get_debug_env()

        assert result.get("TEST_VAR") == "value", (
            "Should return os.environ when no env provided"
        )

    def test_does_not_match_embedded_patterns(self) -> None:
        """Patterns embedded in larger words should not trigger redaction."""
        test_env = {
            "COMPASS": "north",
            "MONKEY": "banana",
            "PASSPORT_NUMBER": "AB123456",
        }
        result = _get_debug_env(test_env)

        assert result["COMPASS"] == "north", "COMPASS should not trigger PASS redaction"
        assert result["MONKEY"] == "banana", "MONKEY should not trigger KEY redaction"
        assert result["PASSPORT_NUMBER"] == "AB123456", (
            "PASSPORT_NUMBER should not trigger PASS redaction"
        )


class TestDebugEnvTool:
    """Tests for the public debug_env MCP tool."""

    def test_delegates_to_get_debug_env(
        self,
        patched_environ: dict[str, str],
    ) -> None:
        """debug_env MCP tool should return the same mapping as _get_debug_env."""
        patched_environ["OPENAI_API_KEY"] = "super-secret-key"
        patched_environ["DATABASE_URL"] = "postgres://user:pass@localhost/db"
        patched_environ["NON_SENSITIVE_VAR"] = "visible"

        # Access the underlying function via the .fn attribute
        result = debug_env.fn()
        expected = _get_debug_env()

        assert result == expected, "debug_env should delegate to _get_debug_env"
