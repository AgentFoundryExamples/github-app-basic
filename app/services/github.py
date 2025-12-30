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
"""GitHub App JWT and OAuth token management service.

Provides functionality for:
- Generating GitHub App JWTs for API authentication
- Exchanging OAuth authorization codes for access tokens
- Managing OAuth state tokens for CSRF protection
"""

import time
import secrets
from typing import Dict, Optional, Any
from datetime import datetime, timedelta

import jwt
import httpx
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend

from app.utils.logging import get_logger

logger = get_logger(__name__)


class GitHubAppJWTError(Exception):
    """Base exception for GitHub App JWT operations."""
    pass


class GitHubOAuthError(Exception):
    """Base exception for GitHub OAuth operations."""
    pass


class GitHubAppJWT:
    """GitHub App JWT token generator.
    
    Generates signed JWTs for authenticating as a GitHub App.
    Uses RS256 algorithm with the configured private key.
    """
    
    def __init__(self, app_id: str, private_key_pem: str):
        """Initialize JWT generator.
        
        Args:
            app_id: GitHub App ID (numeric string)
            private_key_pem: Private key in PEM format
            
        Raises:
            GitHubAppJWTError: If private key is invalid or cannot be loaded
        """
        self.app_id = app_id
        self._private_key = self._load_private_key(private_key_pem)
        
    def _load_private_key(self, private_key_pem: str) -> Any:
        """Load and validate the private key.
        
        Args:
            private_key_pem: Private key in PEM format
            
        Returns:
            Loaded private key object
            
        Raises:
            GitHubAppJWTError: If key cannot be loaded or is invalid
        """
        try:
            private_key = serialization.load_pem_private_key(
                private_key_pem.encode('utf-8'),
                password=None,
                backend=default_backend()
            )
            logger.info("GitHub App private key loaded successfully")
            return private_key
        except Exception as e:
            logger.error(
                "Failed to load GitHub App private key",
                extra={"extra_fields": {"error": str(e)}}
            )
            raise GitHubAppJWTError(f"Invalid private key: {str(e)}")
    
    def generate_jwt(self, expiration_seconds: int = 600) -> str:
        """Generate a signed JWT for GitHub App authentication.
        
        Args:
            expiration_seconds: JWT expiration time in seconds (default: 600, max: 600)
            
        Returns:
            Signed JWT token string
            
        Raises:
            GitHubAppJWTError: If JWT generation fails
        """
        # GitHub allows max 10 minutes (600 seconds) expiration
        if expiration_seconds > 600:
            logger.warning(
                "Requested expiration exceeds GitHub maximum, capping at 600 seconds",
                extra={"extra_fields": {"requested": expiration_seconds}}
            )
            expiration_seconds = 600
        
        now = int(time.time())
        # Subtract 60 seconds to account for clock skew
        issued_at = now - 60
        expires_at = now + expiration_seconds
        
        payload = {
            'iat': issued_at,
            'exp': expires_at,
            'iss': self.app_id
        }
        
        try:
            token = jwt.encode(
                payload,
                self._private_key,
                algorithm='RS256'
            )
            
            logger.info(
                "GitHub App JWT generated successfully",
                extra={"extra_fields": {
                    "app_id": self.app_id,
                    "expires_at": datetime.fromtimestamp(expires_at).isoformat(),
                    "duration_seconds": expiration_seconds
                }}
            )
            
            return token
        except Exception as e:
            logger.error(
                "Failed to generate GitHub App JWT",
                extra={"extra_fields": {"error": str(e)}}
            )
            raise GitHubAppJWTError(f"JWT generation failed: {str(e)}")


class GitHubOAuthManager:
    """Manager for GitHub OAuth flows with CSRF protection."""
    
    # In-memory state storage for CSRF tokens
    # In production, consider using Redis or similar for multi-instance deployments
    _state_tokens: Dict[str, float] = {}
    
    # State token expiration time (5 minutes)
    STATE_EXPIRATION_SECONDS = 300
    
    @classmethod
    def generate_state_token(cls) -> str:
        """Generate a cryptographically strong state token for CSRF protection.
        
        Returns:
            URL-safe random state token (32 bytes hex = 64 characters)
        """
        state = secrets.token_urlsafe(32)
        # Store with expiration timestamp
        cls._state_tokens[state] = time.time() + cls.STATE_EXPIRATION_SECONDS
        
        logger.info(
            "OAuth state token generated",
            extra={"extra_fields": {
                "state_prefix": state[:8] + "...",
                "expires_in_seconds": cls.STATE_EXPIRATION_SECONDS
            }}
        )
        
        return state
    
    @classmethod
    def verify_state_token(cls, state: str) -> bool:
        """Verify and consume a state token.
        
        Args:
            state: State token to verify
            
        Returns:
            True if token is valid and not expired, False otherwise
        """
        # Clean up expired tokens
        cls._cleanup_expired_tokens()
        
        expiration = cls._state_tokens.get(state)
        
        if expiration is None:
            logger.warning(
                "OAuth state token not found",
                extra={"extra_fields": {"state_prefix": state[:8] + "..." if state else "None"}}
            )
            return False
        
        if time.time() > expiration:
            logger.warning(
                "OAuth state token expired",
                extra={"extra_fields": {"state_prefix": state[:8] + "..."}}
            )
            # Remove expired token
            cls._state_tokens.pop(state, None)
            return False
        
        # Token is valid, consume it (one-time use)
        cls._state_tokens.pop(state)
        
        logger.info(
            "OAuth state token verified successfully",
            extra={"extra_fields": {"state_prefix": state[:8] + "..."}}
        )
        
        return True
    
    @classmethod
    def _cleanup_expired_tokens(cls) -> None:
        """Remove expired state tokens from memory."""
        now = time.time()
        expired = [state for state, exp in cls._state_tokens.items() if now > exp]
        
        for state in expired:
            cls._state_tokens.pop(state, None)
        
        if expired:
            logger.debug(
                "Cleaned up expired OAuth state tokens",
                extra={"extra_fields": {"count": len(expired)}}
            )
    
    @staticmethod
    async def exchange_code_for_token(
        code: str,
        client_id: str,
        client_secret: str,
        redirect_uri: Optional[str] = None
    ) -> Dict[str, Any]:
        """Exchange OAuth authorization code for access token.
        
        Args:
            code: Authorization code from GitHub callback
            client_id: GitHub OAuth client ID
            client_secret: GitHub OAuth client secret
            redirect_uri: OAuth redirect URI (optional)
            
        Returns:
            Dictionary containing token data:
            - access_token: The OAuth access token
            - token_type: Type of token (typically "bearer")
            - scope: Granted scopes
            - expires_in: Token expiration time in seconds (if applicable)
            
        Raises:
            GitHubOAuthError: If token exchange fails
        """
        url = "https://github.com/login/oauth/access_token"
        
        payload = {
            "client_id": client_id,
            "client_secret": client_secret,
            "code": code
        }
        
        if redirect_uri:
            payload["redirect_uri"] = redirect_uri
        
        headers = {
            "Accept": "application/json"
        }
        
        logger.info(
            "Exchanging OAuth code for access token",
            extra={"extra_fields": {"client_id": client_id}}
        )
        
        try:
            async with httpx.AsyncClient(timeout=30.0) as client:
                response = await client.post(url, json=payload, headers=headers)
                
                if response.status_code != 200:
                    logger.error(
                        "GitHub OAuth token exchange failed",
                        extra={"extra_fields": {
                            "status_code": response.status_code,
                            "response_body": response.text[:500]  # Truncate for security
                        }}
                    )
                    raise GitHubOAuthError(
                        f"Token exchange failed with status {response.status_code}"
                    )
                
                data = response.json()
                
                # Check for error in response
                if "error" in data:
                    error_description = data.get("error_description", "Unknown error")
                    logger.error(
                        "GitHub OAuth returned error",
                        extra={"extra_fields": {
                            "error": data["error"],
                            "description": error_description
                        }}
                    )
                    raise GitHubOAuthError(
                        f"OAuth error: {data['error']} - {error_description}"
                    )
                
                # Validate required fields
                if "access_token" not in data:
                    logger.error(
                        "GitHub OAuth response missing access_token",
                        extra={"extra_fields": {"response_keys": list(data.keys())}}
                    )
                    raise GitHubOAuthError("Response missing access_token field")
                
                # Log success with masked token
                token = data["access_token"]
                masked_token = token[:8] + "..." + token[-4:] if len(token) > 12 else "***"
                
                logger.info(
                    "OAuth token exchange successful",
                    extra={"extra_fields": {
                        "masked_token": masked_token,
                        "token_type": data.get("token_type", "unknown"),
                        "scope": data.get("scope", "unknown"),
                        "has_expiry": "expires_in" in data
                    }}
                )
                
                return data
                
        except httpx.HTTPError as e:
            logger.error(
                "HTTP error during token exchange",
                extra={"extra_fields": {"error": str(e)}}
            )
            raise GitHubOAuthError(f"HTTP error: {str(e)}")
        except Exception as e:
            if isinstance(e, GitHubOAuthError):
                raise
            logger.error(
                "Unexpected error during token exchange",
                extra={"extra_fields": {"error": str(e)}}
            )
            raise GitHubOAuthError(f"Unexpected error: {str(e)}")
