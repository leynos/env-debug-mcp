"""Tests for the MCP server redaction logic."""

from __future__ import annotations

import os
from unittest import mock

import pytest

from env_debug_mcp.server import _get_debug_env, _is_sensitive_key, _redact_value


class TestRedactValue:
    """Tests for _redact_value function."""

    def test_replaces_alphanumeric_with_asterisks(self) -> None:
        """Alphanumeric characters should be replaced with asterisks."""
        assert _redact_value("abc123") == "******"

    def test_preserves_special_characters(self) -> None:
        """Special characters should remain unchanged."""
        assert _redact_value("key=value!") == "***=*****!"

    def test_preserves_hyphens_and_underscores(self) -> None:
        """Hyphens and underscores should remain unchanged."""
        assert _redact_value("my_api-key") == "**_***-***"

    def test_empty_string(self) -> None:
        """Empty string should return empty string."""
        assert _redact_value("") == ""


class TestIsSensitiveKey:
    """Tests for _is_sensitive_key function."""

    @pytest.mark.parametrize(
        "key",
        [
            "API_KEY",
            "api_key",
            "ApiKey",
            "MY_SECRET_KEY",
        ],
    )
    def test_matches_key_pattern(self, key: str) -> None:
        """Keys containing KEY (case-insensitive) should be sensitive."""
        assert _is_sensitive_key(key) is True

    @pytest.mark.parametrize(
        "key",
        [
            "ACCESS_TOKEN",
            "access_token",
            "AccessToken",
            "GITHUB_TOKEN",
        ],
    )
    def test_matches_token_pattern(self, key: str) -> None:
        """Keys containing TOKEN (case-insensitive) should be sensitive."""
        assert _is_sensitive_key(key) is True

    @pytest.mark.parametrize(
        "key",
        [
            "AWS_CREDENTIALS",
            "CREDENTIAL_PATH",
            "credentials",
        ],
    )
    def test_matches_cred_pattern(self, key: str) -> None:
        """Keys containing CRED (case-insensitive) should be sensitive."""
        assert _is_sensitive_key(key) is True

    @pytest.mark.parametrize(
        "key",
        [
            "PASSWORD",
            "DB_PASSWORD",
            "password",
            "PASSPHRASE",
        ],
    )
    def test_matches_pass_pattern(self, key: str) -> None:
        """Keys containing PASS (case-insensitive) should be sensitive."""
        assert _is_sensitive_key(key) is True

    @pytest.mark.parametrize(
        "key",
        [
            "HOME",
            "PATH",
            "USER",
            "SHELL",
            "HOSTNAME",
        ],
    )
    def test_non_sensitive_keys(self, key: str) -> None:
        """Non-sensitive keys should return False."""
        assert _is_sensitive_key(key) is False


class TestGetDebugEnv:
    """Tests for _get_debug_env function."""

    def test_redacts_sensitive_values(self) -> None:
        """Sensitive environment variables should have values redacted."""
        test_env = {
            "API_KEY": "secret123",
            "HOME": "/home/user",
        }
        with mock.patch.dict(os.environ, test_env, clear=True):
            result = _get_debug_env()

        assert result["API_KEY"] == "*********"
        assert result["HOME"] == "/home/user"

    def test_preserves_non_sensitive_values(self) -> None:
        """Non-sensitive environment variables should be unchanged."""
        test_env = {
            "PATH": "/usr/bin:/bin",
            "SHELL": "/bin/bash",
        }
        with mock.patch.dict(os.environ, test_env, clear=True):
            result = _get_debug_env()

        assert result["PATH"] == "/usr/bin:/bin"
        assert result["SHELL"] == "/bin/bash"

    def test_returns_dict(self) -> None:
        """_get_debug_env should return a dictionary."""
        test_env = {"HOME": "/home/user"}
        with mock.patch.dict(os.environ, test_env, clear=True):
            result = _get_debug_env()

        assert isinstance(result, dict)

    def test_handles_multiple_sensitive_patterns(self) -> None:
        """Multiple sensitive patterns should all be redacted."""
        test_env = {
            "API_KEY": "key123",
            "ACCESS_TOKEN": "tok456",
            "DB_PASSWORD": "pass789",
            "AWS_CREDENTIALS": "cred000",
        }
        with mock.patch.dict(os.environ, test_env, clear=True):
            result = _get_debug_env()

        assert result["API_KEY"] == "******"
        assert result["ACCESS_TOKEN"] == "******"
        assert result["DB_PASSWORD"] == "*******"
        assert result["AWS_CREDENTIALS"] == "*******"
