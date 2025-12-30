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

from typing import Optional
from pydantic import Field, ValidationError, field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    """Application settings with environment variable support.
    
    All settings can be provided via environment variables.
    For production environments (APP_ENV=prod), GitHub secrets are required.
    """
    
    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        case_sensitive=True,
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
    github_private_key: Optional[str] = Field(default=None, description="GitHub App private key")
    github_client_id: Optional[str] = Field(default=None, description="GitHub App OAuth client ID")
    github_client_secret: Optional[str] = Field(default=None, description="GitHub App OAuth client secret")
    github_webhook_secret: Optional[str] = Field(default=None, description="GitHub webhook secret")
    
    # Logging
    log_level: str = Field(default="INFO", description="Logging level")
    
    # CORS (disabled by default)
    enable_cors: bool = Field(default=False, description="Enable CORS middleware")
    
    @field_validator("app_env")
    @classmethod
    def validate_app_env(cls, v: str) -> str:
        """Validate app_env is either dev or prod."""
        if v not in ["dev", "prod"]:
            raise ValueError("app_env must be 'dev' or 'prod'")
        return v
    
    def validate_production_settings(self) -> None:
        """Validate that required settings are present for production.
        
        Raises:
            ValueError: If required production settings are missing.
        """
        if self.app_env != "prod":
            return
        
        required_fields = {
            "github_app_id": self.github_app_id,
            "github_private_key": self.github_private_key,
            "github_client_id": self.github_client_id,
            "github_client_secret": self.github_client_secret,
            "github_webhook_secret": self.github_webhook_secret,
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


def get_settings() -> Settings:
    """Factory function to create and validate settings.
    
    Returns:
        Settings: Validated application settings.
        
    Raises:
        ValueError: If production validation fails.
    """
    settings = Settings()
    settings.validate_production_settings()
    return settings
