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
"""Tests for configuration management."""

import pytest

from app.config import Settings


class TestSettings:
    """Test suite for Settings configuration."""
    
    def test_default_settings(self, monkeypatch):
        """Test that default settings are loaded correctly."""
        # Clear all relevant env vars
        for key in ['APP_ENV', 'PORT', 'REGION', 'GCP_PROJECT_ID', 'GITHUB_APP_ID', 
                    'GITHUB_APP_PRIVATE_KEY_PEM', 'GITHUB_CLIENT_ID', 'GITHUB_CLIENT_SECRET', 
                    'GITHUB_WEBHOOK_SECRET', 'GITHUB_OAUTH_REDIRECT_URI', 'LOG_LEVEL', 'ENABLE_CORS']:
            monkeypatch.delenv(key, raising=False)
        
        settings = Settings(_env_file=None)
        
        assert settings.app_env == "dev"
        assert settings.port == 8000
        assert settings.region == "us-central"
        assert settings.log_level == "INFO"
        assert settings.enable_cors is False
    
    def test_dev_validation_does_not_require_github_fields(self, monkeypatch):
        """Test that dev environment does not require GitHub fields."""
        monkeypatch.setenv("APP_ENV", "dev")
        
        settings = Settings(_env_file=None)
        # Should not raise
        settings.validate_production_settings()
        assert settings.app_env == "dev"
    
    def test_region_defaults_to_us_central(self, monkeypatch):
        """Test that region defaults to us-central."""
        monkeypatch.delenv("REGION", raising=False)
        
        settings = Settings(_env_file=None)
        assert settings.region == "us-central"
    
    def test_production_validation_with_missing_fields(self):
        """Test that production validation detects missing GitHub fields."""
        # Create a settings instance directly with prod env
        settings = Settings(_env_file=None, app_env="prod")
        
        # Should raise because GitHub fields are not set
        with pytest.raises(ValueError, match="Production environment requires"):
            settings.validate_production_settings()
    
    def test_production_validation_with_all_required_fields(self, monkeypatch):
        """Test that production validation passes with all required fields."""
        monkeypatch.setenv("APP_ENV", "prod")
        monkeypatch.setenv("GITHUB_APP_ID", "123456")
        monkeypatch.setenv("GITHUB_APP_PRIVATE_KEY_PEM", "-----BEGIN RSA PRIVATE KEY-----\nMIIE...\n-----END RSA PRIVATE KEY-----")
        monkeypatch.setenv("GITHUB_CLIENT_ID", "Iv1.abc123")
        monkeypatch.setenv("GITHUB_CLIENT_SECRET", "secret123")
        monkeypatch.setenv("GITHUB_OAUTH_REDIRECT_URI", "https://example.com/callback")
        
        settings = Settings(_env_file=None)
        # Should not raise
        settings.validate_production_settings()
        
        assert settings.github_app_id == "123456"
        assert "BEGIN RSA PRIVATE KEY" in settings.github_app_private_key_pem
        assert settings.github_client_id == "Iv1.abc123"
        assert settings.github_client_secret == "secret123"
        assert settings.github_oauth_redirect_uri == "https://example.com/callback"
    
    def test_production_validation_logs_warning_for_missing_webhook_secret(self, monkeypatch, caplog):
        """Test that missing webhook secret logs a warning but doesn't fail."""
        import logging
        
        monkeypatch.setenv("APP_ENV", "prod")
        monkeypatch.setenv("GITHUB_APP_ID", "123456")
        monkeypatch.setenv("GITHUB_APP_PRIVATE_KEY_PEM", "-----BEGIN RSA PRIVATE KEY-----\nMIIE...\n-----END RSA PRIVATE KEY-----")
        monkeypatch.setenv("GITHUB_CLIENT_ID", "Iv1.abc123")
        monkeypatch.setenv("GITHUB_CLIENT_SECRET", "secret123")
        monkeypatch.setenv("GITHUB_OAUTH_REDIRECT_URI", "https://example.com/callback")
        
        with caplog.at_level(logging.WARNING):
            settings = Settings(_env_file=None)
            settings.validate_production_settings()
        
        # Check that warning was logged
        assert any("GITHUB_WEBHOOK_SECRET" in record.message for record in caplog.records)
        assert settings.github_webhook_secret is None
    
    def test_github_app_id_whitespace_trimming(self, monkeypatch):
        """Test that GitHub App ID whitespace is trimmed."""
        monkeypatch.setenv("GITHUB_APP_ID", "  123456  ")
        
        settings = Settings(_env_file=None)
        assert settings.github_app_id == "123456"
    
    def test_github_app_id_empty_after_trim_becomes_none(self, monkeypatch):
        """Test that empty GitHub App ID after trimming becomes None."""
        monkeypatch.setenv("GITHUB_APP_ID", "   ")
        
        settings = Settings(_env_file=None)
        assert settings.github_app_id is None
    
    def test_pem_key_with_escaped_newlines(self, monkeypatch):
        """Test PEM key with escaped newlines is properly parsed."""
        pem_key = "-----BEGIN RSA PRIVATE KEY-----\\nMIIEpAIBAAKCAQEA1234\\n-----END RSA PRIVATE KEY-----"
        monkeypatch.setenv("GITHUB_APP_PRIVATE_KEY_PEM", pem_key)
        
        settings = Settings(_env_file=None)
        
        # Check that escaped newlines were converted to actual newlines
        assert "\n" in settings.github_app_private_key_pem
        assert "\\n" not in settings.github_app_private_key_pem
        assert settings.github_app_private_key_pem.startswith("-----BEGIN RSA PRIVATE KEY-----")
        assert settings.github_app_private_key_pem.endswith("-----END RSA PRIVATE KEY-----")
    
    def test_pem_key_with_literal_newlines(self, monkeypatch):
        """Test PEM key with literal newlines is properly parsed."""
        pem_key = """-----BEGIN RSA PRIVATE KEY-----
MIIEpAIBAAKCAQEA1234
-----END RSA PRIVATE KEY-----"""
        monkeypatch.setenv("GITHUB_APP_PRIVATE_KEY_PEM", pem_key)
        
        settings = Settings(_env_file=None)
        
        assert settings.github_app_private_key_pem.startswith("-----BEGIN RSA PRIVATE KEY-----")
        assert settings.github_app_private_key_pem.endswith("-----END RSA PRIVATE KEY-----")
    
    def test_pem_key_missing_begin_marker_raises_error(self, monkeypatch):
        """Test that PEM key without BEGIN marker raises validation error."""
        pem_key = "MIIEpAIBAAKCAQEA1234\n-----END RSA PRIVATE KEY-----"
        monkeypatch.setenv("GITHUB_APP_PRIVATE_KEY_PEM", pem_key)
        
        with pytest.raises(ValueError, match="must start with a PEM header"):
            Settings(_env_file=None)
    
    def test_pem_key_missing_end_marker_raises_error(self, monkeypatch):
        """Test that PEM key without END marker raises validation error."""
        pem_key = "-----BEGIN RSA PRIVATE KEY-----\nMIIEpAIBAAKCAQEA1234"
        monkeypatch.setenv("GITHUB_APP_PRIVATE_KEY_PEM", pem_key)
        
        with pytest.raises(ValueError, match="must end with a PEM footer"):
            Settings(_env_file=None)
    
    def test_pem_key_empty_after_strip_becomes_none(self, monkeypatch):
        """Test that empty PEM key after stripping becomes None."""
        monkeypatch.setenv("GITHUB_APP_PRIVATE_KEY_PEM", "   ")
        
        settings = Settings(_env_file=None)
        assert settings.github_app_private_key_pem is None
    
    def test_production_fails_with_missing_oauth_redirect_uri(self, monkeypatch):
        """Test that production validation requires OAuth redirect URI."""
        monkeypatch.setenv("APP_ENV", "prod")
        monkeypatch.setenv("GITHUB_APP_ID", "123456")
        monkeypatch.setenv("GITHUB_APP_PRIVATE_KEY_PEM", "-----BEGIN RSA PRIVATE KEY-----\nMIIE...\n-----END RSA PRIVATE KEY-----")
        monkeypatch.setenv("GITHUB_CLIENT_ID", "Iv1.abc123")
        monkeypatch.setenv("GITHUB_CLIENT_SECRET", "secret123")
        # Intentionally omit GITHUB_OAUTH_REDIRECT_URI
        
        settings = Settings(_env_file=None)
        
        with pytest.raises(ValueError, match="GITHUB_OAUTH_REDIRECT_URI"):
            settings.validate_production_settings()
