"""Tests for configuration management."""

import pytest

from app.config import Settings


class TestSettings:
    """Test suite for Settings configuration."""
    
    def test_default_settings(self, monkeypatch):
        """Test that default settings are loaded correctly."""
        # Clear all relevant env vars
        for key in ['APP_ENV', 'PORT', 'REGION', 'GCP_PROJECT_ID', 'GITHUB_APP_ID', 
                    'GITHUB_PRIVATE_KEY', 'GITHUB_CLIENT_ID', 'GITHUB_CLIENT_SECRET', 
                    'GITHUB_WEBHOOK_SECRET', 'LOG_LEVEL', 'ENABLE_CORS']:
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
