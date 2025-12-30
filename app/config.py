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
"""Configuration management for the GitHub App token minting service."""

import logging
from typing import Optional
from pydantic import Field, ValidationError, field_validator, model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict

logger = logging.getLogger(__name__)


class Settings(BaseSettings):
    """Application settings with environment variable support.
    
    All settings can be provided via environment variables.
    For production environments (APP_ENV=prod), GitHub secrets are required.
    """
    
    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        case_sensitive=False,  # Allow GITHUB_APP_ID to match github_app_id field
        extra="ignore",
        env_ignore_empty=True
    )
    
    # Application environment
    app_env: str = Field(default="dev", description="Application environment (dev/prod)")
    port: int = Field(default=8000, description="Server port")
    
    # GCP Configuration
    gcp_project_id: Optional[str] = Field(default=None, description="GCP Project ID")
    google_application_credentials: Optional[str] = Field(
        default=None, 
        description="Path to GCP service account credentials JSON"
    )
    region: str = Field(default="us-central", description="GCP region")
    
    # GitHub App Configuration
    github_app_id: Optional[str] = Field(default=None, description="GitHub App ID")
    github_app_private_key_pem: Optional[str] = Field(default=None, description="GitHub App private key in PEM format")
    github_client_id: Optional[str] = Field(default=None, description="GitHub App OAuth client ID")
    github_client_secret: Optional[str] = Field(default=None, description="GitHub App OAuth client secret")
    github_webhook_secret: Optional[str] = Field(default=None, description="GitHub webhook secret (optional)")
    github_oauth_redirect_uri: Optional[str] = Field(default=None, description="GitHub OAuth redirect URI")
    
    # Logging
    log_level: str = Field(default="INFO", description="Logging level")
    
    # CORS (disabled by default)
    enable_cors: bool = Field(default=False, description="Enable CORS middleware")
    
    # Token Storage Configuration
    github_token_encryption_key: Optional[str] = Field(
        default=None, 
        description="Symmetric encryption key for GitHub tokens (32-byte hex string)"
    )
    github_tokens_collection: str = Field(
        default="github_tokens", 
        description="Firestore collection name for GitHub tokens"
    )
    github_tokens_doc_id: str = Field(
        default="primary_user", 
        description="Document ID for the primary GitHub token"
    )
    
    # Token Refresh Configuration
    token_refresh_threshold_minutes: int = Field(
        default=30,
        description="Minutes before expiry to consider a token near-expiry and eligible for refresh"
    )
    token_refresh_cooldown_seconds: int = Field(
        default=300,
        description="Minimum seconds to wait between token refresh attempts (cooldown period)"
    )
    
    # Logging and Instrumentation Configuration
    enable_request_logging: bool = Field(
        default=False,
        description="Enable request logging middleware (disabled by default for production)"
    )
    enable_metrics: bool = Field(
        default=False,
        description="Enable Prometheus metrics endpoint (disabled by default)"
    )
    
    @field_validator("app_env")
    @classmethod
    def validate_app_env(cls, v: str) -> str:
        """Validate app_env is either dev or prod."""
        if v not in ["dev", "prod"]:
            raise ValueError("app_env must be 'dev' or 'prod'")
        return v
    
    @field_validator("github_app_id", mode="before")
    @classmethod
    def validate_github_app_id(cls, v: Optional[str]) -> Optional[str]:
        """Trim whitespace from GitHub App ID."""
        if v is not None and isinstance(v, str):
            v = v.strip()
            # Return None only if completely empty after trimming
            if not v:
                return None
        return v
    
    @field_validator("github_app_private_key_pem", mode="before")
    @classmethod
    def validate_github_app_private_key_pem(cls, v: Optional[str]) -> Optional[str]:
        """Validate and normalize PEM private key format.
        
        Accepts PEM keys with either literal newlines or escaped \\n sequences.
        Raises ValueError if the format appears invalid.
        """
        if v is None:
            return None
        
        # Strip outer whitespace
        v = v.strip()
        if not v:
            return None
        
        # Replace escaped newlines with actual newlines
        v = v.replace('\\n', '\n')
        
        # Validate basic PEM structure
        if not v.startswith('-----BEGIN'):
            raise ValueError(
                "GITHUB_APP_PRIVATE_KEY_PEM must start with a PEM header (e.g., '-----BEGIN RSA PRIVATE KEY-----'). "
                "Ensure the key is properly formatted and includes the BEGIN/END markers."
            )
        
        if not v.endswith('-----') or '-----END' not in v:
            raise ValueError(
                "GITHUB_APP_PRIVATE_KEY_PEM must end with a PEM footer (e.g., '-----END RSA PRIVATE KEY-----'). "
                "Ensure the key is properly formatted and includes the BEGIN/END markers."
            )
        
        return v
    
    @field_validator("token_refresh_threshold_minutes")
    @classmethod
    def validate_token_refresh_threshold_minutes(cls, v: int) -> int:
        """Validate token refresh threshold is a positive integer.
        
        Raises:
            ValueError: If the value is not positive.
        """
        if v <= 0:
            raise ValueError(
                f"TOKEN_REFRESH_THRESHOLD_MINUTES must be a positive integer, got {v}. "
                "This value determines how many minutes before expiry a token is considered "
                "near-expiry and eligible for refresh."
            )
        return v
    
    @field_validator("token_refresh_cooldown_seconds")
    @classmethod
    def validate_token_refresh_cooldown_seconds(cls, v: int) -> int:
        """Validate token refresh cooldown is a positive integer.
        
        Raises:
            ValueError: If the value is not positive.
        """
        if v <= 0:
            raise ValueError(
                f"TOKEN_REFRESH_COOLDOWN_SECONDS must be a positive integer, got {v}. "
                "This value determines the minimum seconds to wait between token refresh attempts "
                "to prevent excessive API calls."
            )
        return v
    
    @field_validator("github_token_encryption_key", mode="before")
    @classmethod
    def validate_github_token_encryption_key(cls, v: Optional[str]) -> Optional[str]:
        """Validate encryption key format.
        
        Ensures the key is a valid hex string of appropriate length (32 bytes = 64 hex chars).
        """
        if v is None:
            return None
        
        v = v.strip()
        if not v:
            raise ValueError(
                "GITHUB_TOKEN_ENCRYPTION_KEY cannot be empty or whitespace-only. "
                "Generate a valid key with: python -c 'import secrets; print(secrets.token_hex(32))'"
            )
        
        # Validate hex format
        try:
            bytes.fromhex(v)
        except ValueError:
            raise ValueError(
                "GITHUB_TOKEN_ENCRYPTION_KEY must be a valid hexadecimal string. "
                "Generate one with: python -c 'import secrets; print(secrets.token_hex(32))'"
            )
        
        # Check length (32 bytes = 64 hex characters for AES-256)
        if len(v) != 64:
            raise ValueError(
                "GITHUB_TOKEN_ENCRYPTION_KEY must be exactly 64 hex characters (32 bytes) for AES-256 encryption. "
                f"Provided key is {len(v)} characters. "
                "Generate one with: python -c 'import secrets; print(secrets.token_hex(32))'"
            )
        
        return v
    
    @model_validator(mode='after')
    def validate_production_settings(self) -> "Settings":
        """Validate that required settings are present for production.
        
        Raises:
            ValueError: If required production settings are missing.
        """
        if self.app_env != "prod":
            return self
        
        # Required fields for production (webhook_secret is optional)
        required_fields = {
            "github_app_id": self.github_app_id,
            "github_app_private_key_pem": self.github_app_private_key_pem,
            "github_client_id": self.github_client_id,
            "github_client_secret": self.github_client_secret,
            "github_oauth_redirect_uri": self.github_oauth_redirect_uri,
            "github_token_encryption_key": self.github_token_encryption_key,
        }
        
        missing_fields = [
            field_name for field_name, value in required_fields.items()
            if value is None or (isinstance(value, str) and not value.strip())
        ]
        
        if missing_fields:
            raise ValueError(
                f"Production environment requires the following settings: "
                f"{', '.join(f.upper() for f in missing_fields)}"
            )
        
        # Log warning if webhook secret is not set
        if not self.github_webhook_secret:
            logger.warning(
                "GITHUB_WEBHOOK_SECRET is not set. Webhook validation will not be available. "
                "This is acceptable for development but should be configured for production webhook endpoints."
            )
        return self


def get_settings() -> Settings:
    """Factory function to create and validate settings.
    
    Returns:
        Settings: Validated application settings.
        
    Raises:
        ValueError: If production validation fails.
    """
    return Settings()
