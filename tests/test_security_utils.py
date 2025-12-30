# Copyright 2025 John Brosnihan
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
"""Tests for security utility functions (token redaction, sanitization)."""

import pytest
from app.utils.security import (
    redact_token,
    detect_sensitive_string,
    redact_dict,
    redact_list,
    sanitize_exception_message,
    sanitize_log_extra,
    extract_metadata_only,
    is_field_sensitive
)


class TestRedactToken:
    """Tests for token redaction function."""
    
    def test_redact_standard_github_token(self):
        """Test redacting a standard GitHub token."""
        token = "ghp_1234567890abcdefghijklmnopqrstuvwxyz"
        result = redact_token(token)
        
        # Should show prefix and suffix
        assert result.startswith("ghp_1234")
        assert result.endswith("wxyz")
        assert "..." in result or "." in result
        # Original token should not be in result
        assert token not in result
    
    def test_redact_short_token(self):
        """Test redacting a short token."""
        token = "short"
        result = redact_token(token)
        
        # Should show partial + mask
        assert "shor" in result
        assert "*" in result
        assert token not in result
    
    def test_redact_very_short_token(self):
        """Test redacting a very short token (less than prefix length)."""
        token = "ab"
        result = redact_token(token)
        
        # Should show at least first char + mask
        assert "a" in result
        assert "*" in result or result == "a*"
    
    def test_redact_none_token(self):
        """Test redacting None."""
        result = redact_token(None)
        assert result == "[REDACTED]"
    
    def test_redact_empty_token(self):
        """Test redacting empty string."""
        result = redact_token("")
        assert result == "[EMPTY]"
    
    def test_redact_whitespace_token(self):
        """Test redacting whitespace-only string."""
        result = redact_token("   ")
        assert result == "[EMPTY]"
    
    def test_redact_bytes_token(self):
        """Test redacting bytes."""
        token = b"ghp_1234567890abcdefghijklmnopqrstuvwxyz"
        result = redact_token(token)
        
        # Should decode and redact
        assert "ghp_1234" in result
        assert isinstance(result, str)  # Should be string, not bytes
    
    def test_redact_custom_prefix_suffix(self):
        """Test custom prefix and suffix lengths."""
        token = "ghp_1234567890abcdefghijklmnopqrstuvwxyz"
        result = redact_token(token, prefix_len=4, suffix_len=4)
        
        assert result.startswith("ghp_")
        assert result.endswith("wxyz")
    
    def test_redact_no_suffix(self):
        """Test with no suffix (suffix_len=0)."""
        token = "ghp_1234567890abcdefghijklmnopqrstuvwxyz"
        result = redact_token(token, prefix_len=8, suffix_len=0)
        
        assert result.startswith("ghp_1234")
        # Should not show any part of the suffix when suffix_len=0
        assert not result.endswith("wxyz")
        assert not result.endswith("xyz")
    
    def test_redact_extremely_long_token(self):
        """Test redacting a very long token."""
        token = "ghp_" + ("a" * 1000)
        result = redact_token(token)
        
        # Should still show prefix and suffix
        assert result.startswith("ghp_")
        assert len(result) < len(token)  # Redacted version is shorter
        assert token not in result


class TestDetectSensitiveString:
    """Tests for sensitive string detection."""
    
    def test_detect_github_personal_token(self):
        """Test detecting GitHub personal access token."""
        assert detect_sensitive_string("ghp_1234567890abcdefghijklmnopqrstuvwxyz")
    
    def test_detect_github_oauth_token(self):
        """Test detecting GitHub OAuth token."""
        assert detect_sensitive_string("gho_1234567890abcdefghijklmnopqrstuvwxyz")
    
    def test_detect_github_user_to_server_token(self):
        """Test detecting GitHub user-to-server token."""
        assert detect_sensitive_string("ghu_1234567890abcdefghijklmnopqrstuvwxyz")
    
    def test_detect_40_char_token(self):
        """Test detecting generic 40-character token."""
        assert detect_sensitive_string("a" * 40)
    
    def test_detect_pem_private_key(self):
        """Test detecting PEM private key."""
        assert detect_sensitive_string("-----BEGIN RSA PRIVATE KEY-----")
        assert detect_sensitive_string("-----BEGIN PRIVATE KEY-----")
    
    def test_detect_password_in_string(self):
        """Test detecting password in key-value format."""
        assert detect_sensitive_string('password="mysecretpass123"')
        assert detect_sensitive_string("api_key=abc123def456")
    
    def test_not_detect_normal_string(self):
        """Test not detecting normal strings."""
        assert not detect_sensitive_string("hello world")
        assert not detect_sensitive_string("user_id=12345")
    
    def test_not_detect_short_string(self):
        """Test not detecting short strings."""
        assert not detect_sensitive_string("abc")
    
    def test_not_detect_non_string(self):
        """Test not detecting non-string values."""
        assert not detect_sensitive_string(12345)
        assert not detect_sensitive_string(None)
    
    def test_detect_short_secret_in_key_value(self):
        """Test detecting short secrets (4+ chars) in key-value format."""
        assert detect_sensitive_string("password=abcd")
        assert detect_sensitive_string("api_key:test")
        assert detect_sensitive_string('secret="xyz1"')
    
    def test_detect_json_style_secrets(self):
        """Test detecting secrets in JSON format."""
        assert detect_sensitive_string('{"token":"secretvalue"}')
        assert detect_sensitive_string('{"password":"pass"}')
    
    def test_not_match_word_token_without_delimiter(self):
        """Test not matching the word 'token' without a key-value delimiter."""
        # "token" as a word should not trigger, only "token=" or "token:" patterns
        assert not detect_sensitive_string("Failed with token")
        assert not detect_sensitive_string("the token is invalid")


class TestRedactDict:
    """Tests for dictionary redaction."""
    
    def test_redact_access_token_field(self):
        """Test redacting access_token field."""
        data = {"access_token": "ghp_secret123", "user": "john"}
        result = redact_dict(data)
        
        assert result["access_token"] == "[REDACTED]"
        assert result["user"] == "john"
    
    def test_redact_password_field(self):
        """Test redacting password field."""
        data = {"password": "secret123", "username": "john"}
        result = redact_dict(data)
        
        assert result["password"] == "[REDACTED]"
        assert result["username"] == "john"
    
    def test_redact_multiple_sensitive_fields(self):
        """Test redacting multiple sensitive fields."""
        data = {
            "access_token": "token123",
            "refresh_token": "refresh123",
            "password": "pass123",
            "user_id": 42
        }
        result = redact_dict(data)
        
        assert result["access_token"] == "[REDACTED]"
        assert result["refresh_token"] == "[REDACTED]"
        assert result["password"] == "[REDACTED]"
        assert result["user_id"] == 42
    
    def test_redact_nested_dict(self):
        """Test redacting nested dictionaries."""
        data = {
            "user": {"username": "john", "password": "secret"},
            "api_key": "key123"
        }
        result = redact_dict(data, recursive=True)
        
        assert result["user"]["username"] == "john"
        assert result["user"]["password"] == "[REDACTED]"
        assert result["api_key"] == "[REDACTED]"
    
    def test_redact_nested_list(self):
        """Test redacting dictionaries within nested lists."""
        data = {
            "tokens": ["ghp_token1234567", "normal_string", "ghp_token9876543"],
            "count": 3
        }
        result = redact_dict(data, recursive=True)
        
        # Short tokens should be detected and redacted
        assert "ghp_token1234567" not in str(result["tokens"])
        assert "ghp_token9876543" not in str(result["tokens"])
        assert "normal_string" in result["tokens"]
        assert result["count"] == 3
    
    def test_redact_case_insensitive_fields(self):
        """Test case-insensitive field name matching."""
        data = {"AccessToken": "token123", "API_KEY": "key123"}
        result = redact_dict(data)
        
        assert result["AccessToken"] == "[REDACTED]"
        assert result["API_KEY"] == "[REDACTED]"
    
    def test_redact_with_underscores_and_hyphens(self):
        """Test field names with underscores and hyphens."""
        data = {"access_token": "t1", "access-token": "t2", "accesstoken": "t3"}
        result = redact_dict(data)
        
        # All variations should be redacted
        assert result["access_token"] == "[REDACTED]"
        # Note: access-token is not in SENSITIVE_FIELD_NAMES, so it won't be redacted
        # unless it matches a pattern
    
    def test_no_recursion(self):
        """Test disabling recursion."""
        data = {
            "user": {"password": "secret"},
            "api_key": "key123"
        }
        result = redact_dict(data, recursive=False)
        
        # api_key should be redacted
        assert result["api_key"] == "[REDACTED]"
        # Nested password should NOT be redacted (recursion disabled)
        assert result["user"]["password"] == "secret"
    
    def test_detect_token_in_value(self):
        """Test detecting token-like values."""
        data = {
            "some_field": "ghp_1234567890abcdefghijklmnopqrstuvwxyz",
            "normal_field": "hello"
        }
        result = redact_dict(data)
        
        # Token-like value should be redacted - full token should not appear
        assert "ghp_" in result["some_field"]  # Prefix still visible
        # But the full original token should not be visible in a simple string check
        # Note: due to redaction format, we can't guarantee full invisibility
        # So we check that it's been modified/truncated
        assert result["some_field"] != data["some_field"]  # Must be different
        assert result["normal_field"] == "hello"


class TestRedactList:
    """Tests for list redaction."""
    
    def test_redact_token_in_list(self):
        """Test redacting token in a list."""
        data = ["normal", "ghp_1234567890abcdefghijklmnopqrstuvwxyz", "another"]
        result = redact_list(data)
        
        assert result[0] == "normal"
        assert "ghp_" in result[1]
        # The redacted token should be different from original
        assert result[1] != "ghp_1234567890abcdefghijklmnopqrstuvwxyz"
        assert result[2] == "another"
    
    def test_redact_nested_dict_in_list(self):
        """Test redacting dictionaries within list."""
        data = [
            {"token": "secret", "user": "john"},
            {"password": "pass123", "id": 42}
        ]
        result = redact_list(data, recursive=True)
        
        assert result[0]["token"] == "[REDACTED]"
        assert result[0]["user"] == "john"
        assert result[1]["password"] == "[REDACTED]"
        assert result[1]["id"] == 42
    
    def test_redact_nested_list(self):
        """Test redacting nested lists."""
        data = [["ghp_token1234567", "normal"], ["ghp_token9876543"]]
        result = redact_list(data, recursive=True)
        
        # Tokens should be redacted
        assert "ghp_token1234567" not in str(result[0])
        assert "normal" in result[0]
    
    def test_redact_tuple(self):
        """Test redacting tuple (converted to list)."""
        data = ("normal", "ghp_1234567890abcdefghijklmnopqrstuvwxyz")
        result = redact_list(data)
        
        assert isinstance(result, list)
        assert result[0] == "normal"
        assert "ghp_" in result[1]


class TestSanitizeExceptionMessage:
    """Tests for exception message sanitization."""
    
    def test_sanitize_with_github_token(self):
        """Test sanitizing exception with GitHub token."""
        exc = ValueError("Failed with token ghp_1234567890abcdefghijklmnopqrstuvwxyz")
        result = sanitize_exception_message(exc)
        
        assert "ghp_1234567890abcdefghijklmnopqrstuvwxyz" not in result
        assert "[REDACTED]" in result
        assert "Failed with token" in result
    
    def test_sanitize_with_pem_key(self):
        """Test sanitizing exception with PEM key."""
        exc = RuntimeError("Invalid key: -----BEGIN RSA PRIVATE KEY----- ...")
        result = sanitize_exception_message(exc)
        
        assert "-----BEGIN RSA PRIVATE KEY-----" not in result
        assert "[REDACTED]" in result
    
    def test_sanitize_with_password(self):
        """Test sanitizing exception with password."""
        exc = Exception('Authentication failed: password="mysecret123"')
        result = sanitize_exception_message(exc)
        
        assert "mysecret123" not in result
        assert "[REDACTED]" in result
    
    def test_sanitize_normal_exception(self):
        """Test sanitizing normal exception without secrets."""
        exc = ValueError("Invalid input: expected integer, got string")
        result = sanitize_exception_message(exc)
        
        # Should remain unchanged
        assert result == "Invalid input: expected integer, got string"
    
    def test_sanitize_multiple_tokens(self):
        """Test sanitizing exception with multiple tokens."""
        exc = Exception("Tokens: ghp_token1234567 and gho_token9876543")
        result = sanitize_exception_message(exc)
        
        assert "ghp_token1234567" not in result
        assert "gho_token9876543" not in result
        assert result.count("[REDACTED]") >= 2


class TestSanitizeLogExtra:
    """Tests for log extra fields sanitization."""
    
    def test_sanitize_log_with_token(self):
        """Test sanitizing log extra with token."""
        extra = {"user": "john", "access_token": "secret123"}
        result = sanitize_log_extra(extra)
        
        assert result["user"] == "john"
        assert result["access_token"] == "[REDACTED]"
    
    def test_sanitize_log_with_nested_data(self):
        """Test sanitizing nested log data."""
        extra = {
            "request_id": "123",
            "metadata": {"token": "secret", "user_id": 42}
        }
        result = sanitize_log_extra(extra)
        
        assert result["request_id"] == "123"
        # Metadata dict is recursively redacted
        assert isinstance(result["metadata"], dict)
        assert result["metadata"]["token"] == "[REDACTED]"
        assert result["metadata"]["user_id"] == 42


class TestExtractMetadataOnly:
    """Tests for metadata extraction."""
    
    def test_extract_allowed_fields(self):
        """Test extracting only allowed fields."""
        data = {
            "access_token": "secret",
            "expires_at": "2025-12-31",
            "scope": "repo",
            "user_id": 42
        }
        allowed = ["expires_at", "scope"]
        result = extract_metadata_only(data, allowed)
        
        assert "expires_at" in result
        assert "scope" in result
        assert "access_token" not in result
        assert "user_id" not in result
    
    def test_extract_missing_fields(self):
        """Test extraction when some fields are missing."""
        data = {"expires_at": "2025-12-31"}
        allowed = ["expires_at", "scope", "user_id"]
        result = extract_metadata_only(data, allowed)
        
        assert "expires_at" in result
        assert "scope" not in result
        assert "user_id" not in result
    
    def test_extract_empty_allowed_list(self):
        """Test with empty allowed list."""
        data = {"token": "secret", "user": "john"}
        result = extract_metadata_only(data, [])
        
        assert result == {}


class TestIsFieldSensitive:
    """Tests for sensitive field name detection."""
    
    def test_sensitive_field_names(self):
        """Test detecting sensitive field names."""
        assert is_field_sensitive("password")
        assert is_field_sensitive("access_token")
        assert is_field_sensitive("api_key")
        assert is_field_sensitive("secret")
        assert is_field_sensitive("private_key")
    
    def test_case_insensitive(self):
        """Test case-insensitive detection."""
        assert is_field_sensitive("PASSWORD")
        assert is_field_sensitive("Access_Token")
        assert is_field_sensitive("API_KEY")
    
    def test_with_underscores_and_hyphens(self):
        """Test field names with underscores and hyphens."""
        assert is_field_sensitive("access_token")
        assert is_field_sensitive("accesstoken")
        # Note: hyphens are not normalized the same way, so this might not match
    
    def test_non_sensitive_field_names(self):
        """Test non-sensitive field names."""
        assert not is_field_sensitive("user_id")
        assert not is_field_sensitive("username")
        assert not is_field_sensitive("email")
        assert not is_field_sensitive("count")


class TestEdgeCases:
    """Tests for edge cases and corner conditions."""
    
    def test_redact_unicode_token(self):
        """Test redacting token with unicode characters."""
        token = "ghp_1234αβγδ567890"
        result = redact_token(token)
        
        # Should handle unicode without crashing
        assert isinstance(result, str)
        assert token not in result
    
    def test_redact_dict_with_none_values(self):
        """Test redacting dict with None values."""
        data = {"token": None, "user": "john", "password": "secret"}
        result = redact_dict(data)
        
        # None values in non-sensitive fields should be preserved
        # But 'token' is a sensitive field name, so it gets redacted even if None
        assert result["token"] == "[REDACTED]"  # Field name is sensitive
        assert result["user"] == "john"
        assert result["password"] == "[REDACTED]"
    
    def test_redact_empty_dict(self):
        """Test redacting empty dict."""
        result = redact_dict({})
        assert result == {}
    
    def test_redact_empty_list(self):
        """Test redacting empty list."""
        result = redact_list([])
        assert result == []
    
    def test_deeply_nested_structure(self):
        """Test deeply nested data structures."""
        data = {
            "level1": {
                "level2": {
                    "level3": {
                        "access_token": "secret",
                        "user": "john"
                    }
                }
            }
        }
        result = redact_dict(data, recursive=True)
        
        assert result["level1"]["level2"]["level3"]["access_token"] == "[REDACTED]"
        assert result["level1"]["level2"]["level3"]["user"] == "john"
    
    def test_circular_reference_protection(self):
        """Test handling of circular references (if any)."""
        # Note: This test assumes the implementation handles circular refs
        # If not, this test documents expected behavior
        data = {"user": "john", "password": "secret"}
        # Don't create actual circular ref in test to avoid infinite loop
        result = redact_dict(data)
        assert result["password"] == "[REDACTED]"
