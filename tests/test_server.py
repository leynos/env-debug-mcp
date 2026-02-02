"""Tests for the MCP server redaction logic."""

from __future__ import annotations

import os
from unittest import mock

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
        assert _redact_value(input_value) == expected


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
        assert _is_sensitive_key(key) is True

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
        assert _is_sensitive_key(key) is True

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
        assert _is_sensitive_key(key) is True

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
        assert _is_sensitive_key(key) is True

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
        assert _is_sensitive_key(key) is True

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
        assert _is_sensitive_key(key) is True

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
        assert _is_sensitive_key(key) is False


class TestGetDebugEnv:
    """Tests for _get_debug_env function."""

    def test_redacts_sensitive_values(self) -> None:
        """Sensitive environment variables should have values redacted."""
        test_env = {
            "API_KEY": "secret123",
            "HOME": "/home/user",
        }
        result = _get_debug_env(test_env)

        assert result["API_KEY"] == "*********"
        assert result["HOME"] == "/home/user"

    def test_preserves_non_sensitive_values(self) -> None:
        """Non-sensitive environment variables should be unchanged."""
        test_env = {
            "PATH": "/usr/bin:/bin",
            "SHELL": "/bin/bash",
        }
        result = _get_debug_env(test_env)

        assert result["PATH"] == "/usr/bin:/bin"
        assert result["SHELL"] == "/bin/bash"

    def test_returns_expected_content(self) -> None:
        """_get_debug_env should return env with expected content."""
        test_env = {"HOME": "/home/user", "SHELL": "/bin/bash"}
        result = _get_debug_env(test_env)

        assert result == test_env

    def test_handles_multiple_sensitive_patterns(self) -> None:
        """Multiple sensitive patterns should all be redacted."""
        test_env = {
            "API_KEY": "key123",
            "ACCESS_TOKEN": "tok456",
            "DB_PASSWORD": "pass789",
            "AWS_CREDENTIALS": "cred000",
        }
        result = _get_debug_env(test_env)

        assert result["API_KEY"] == "******"
        assert result["ACCESS_TOKEN"] == "******"
        assert result["DB_PASSWORD"] == "*******"
        assert result["AWS_CREDENTIALS"] == "*******"

    def test_defaults_to_os_environ(self) -> None:
        """When no env is provided, should use os.environ."""
        test_env = {"TEST_VAR": "value"}
        with mock.patch.dict(os.environ, test_env, clear=True):
            result = _get_debug_env()

        assert result == {"TEST_VAR": "value"}

    def test_does_not_match_embedded_patterns(self) -> None:
        """Patterns embedded in larger words should not trigger redaction."""
        test_env = {
            "COMPASS": "north",
            "MONKEY": "banana",
            "PASSPORT_NUMBER": "AB123456",
        }
        result = _get_debug_env(test_env)

        assert result["COMPASS"] == "north"
        assert result["MONKEY"] == "banana"
        assert result["PASSPORT_NUMBER"] == "AB123456"


class TestDebugEnvTool:
    """Tests for the public debug_env MCP tool."""

    def test_delegates_to_get_debug_env(self) -> None:
        """debug_env MCP tool should return the same mapping as _get_debug_env."""
        test_env = {
            "OPENAI_API_KEY": "super-secret-key",
            "DATABASE_URL": "postgres://user:pass@localhost/db",
            "NON_SENSITIVE_VAR": "visible",
        }
        with mock.patch.dict(os.environ, test_env, clear=True):
            # Access the underlying function via the .fn attribute
            result = debug_env.fn()
            expected = _get_debug_env()

        assert result == expected
