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


class GitHubTokenRefreshError(Exception):
    """Base exception for GitHub token refresh operations."""
    pass


class GitHubTokenRefreshCooldownError(GitHubTokenRefreshError):
    """Exception raised when token refresh is attempted during cooldown period."""
    
    def __init__(self, message: str, seconds_until_retry: float):
        """Initialize cooldown error.
        
        Args:
            message: Error message
            seconds_until_retry: Seconds remaining until cooldown expires
        """
        super().__init__(message)
        self.seconds_until_retry = seconds_until_retry


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
        # Iterate over a copy of items to avoid RuntimeError in concurrent scenarios
        expired = [state for state, exp in list(cls._state_tokens.items()) if now > exp]
        
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
                # Show prefix (first 8) and last 4 characters for better context
                if len(token) >= 16:
                    masked_token = token[:8] + "..." + token[-4:]
                else:
                    # For shorter tokens, mask more conservatively
                    masked_token = token[:4] + "..."
                
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


class GitHubTokenRefreshManager:
    """Manager for GitHub user token refresh operations.
    
    Provides functionality for refreshing user-to-server tokens using either:
    1. OAuth refresh_token grant (if supported by GitHub App)
    2. Reissue via GitHub App JWT and installation access token
    
    Includes cooldown enforcement to prevent excessive API calls.
    """
    
    @staticmethod
    async def refresh_user_token(
        current_token_data: Dict[str, Any],
        github_app_jwt: GitHubAppJWT,
        client_id: str,
        client_secret: str,
        cooldown_seconds: int = 300,
        force_refresh: bool = False,
        max_retries: int = 3
    ) -> Dict[str, Any]:
        """Refresh a GitHub user token using refresh_token grant or reissue.
        
        This method attempts to refresh the user token in the following order:
        1. If refresh_token exists and not expired, use OAuth refresh grant
        2. If refresh_token missing/rejected, reissue token via GitHub App
        
        Implements cooldown enforcement to prevent excessive API calls after failures.
        
        Args:
            current_token_data: Current token data including:
                - access_token: Current access token (for logging)
                - refresh_token: Optional refresh token
                - last_refresh_attempt: ISO datetime of last refresh attempt
                - last_refresh_status: Status of last refresh ("success", "failed")
                - last_refresh_error: Error from last refresh attempt
            github_app_jwt: GitHub App JWT generator for reissue fallback
            client_id: GitHub OAuth client ID
            client_secret: GitHub OAuth client secret
            cooldown_seconds: Minimum seconds between refresh attempts (default: 300)
            force_refresh: If True, bypass cooldown check (default: False)
            max_retries: Maximum retries for transient errors (default: 3)
            
        Returns:
            Dictionary containing:
            - access_token: New access token
            - token_type: Token type (typically "bearer")
            - scope: Granted scopes
            - expires_in: Token expiration seconds (if available)
            - refresh_token: New refresh token (if available)
            - refresh_status: "success"
            - refresh_method: "refresh_grant" or "reissue"
            
        Raises:
            GitHubTokenRefreshCooldownError: If cooldown period has not elapsed
            GitHubTokenRefreshError: If refresh fails after all retries
        """
        from datetime import datetime, timezone
        
        now = datetime.now(timezone.utc)
        
        # Check cooldown unless force_refresh is True
        if not force_refresh:
            last_attempt_str = current_token_data.get("last_refresh_attempt")
            last_status = current_token_data.get("last_refresh_status")
            
            if last_attempt_str and last_status == "failed":
                from app.dao.firestore_dao import FirestoreDAO
                last_attempt = FirestoreDAO.parse_iso_datetime(last_attempt_str)
                
                if last_attempt:
                    time_since_last_attempt = (now - last_attempt).total_seconds()
                    
                    if time_since_last_attempt < cooldown_seconds:
                        seconds_until_retry = cooldown_seconds - time_since_last_attempt
                        error_msg = (
                            f"Token refresh attempted too soon after previous failure. "
                            f"Cooldown period: {cooldown_seconds}s. "
                            f"Time since last attempt: {time_since_last_attempt:.1f}s. "
                            f"Retry in: {seconds_until_retry:.1f}s"
                        )
                        logger.warning(
                            "Token refresh blocked by cooldown",
                            extra={"extra_fields": {
                                "cooldown_seconds": cooldown_seconds,
                                "time_since_last_attempt": time_since_last_attempt,
                                "seconds_until_retry": seconds_until_retry
                            }}
                        )
                        raise GitHubTokenRefreshCooldownError(error_msg, seconds_until_retry)
        
        # Try refresh_token grant first if available
        refresh_token = current_token_data.get("refresh_token")
        
        if refresh_token:
            logger.info("Attempting token refresh using refresh_token grant")
            
            try:
                result = await GitHubTokenRefreshManager._refresh_with_token(
                    refresh_token=refresh_token,
                    client_id=client_id,
                    client_secret=client_secret,
                    max_retries=max_retries
                )
                
                result["refresh_status"] = "success"
                result["refresh_method"] = "refresh_grant"
                
                logger.info(
                    "Token refresh successful using refresh_token grant",
                    extra={"extra_fields": {
                        "has_new_refresh_token": "refresh_token" in result,
                        "token_type": result.get("token_type", "unknown")
                    }}
                )
                
                return result
                
            except GitHubTokenRefreshError as e:
                # Check if error indicates revoked/invalid refresh token (not 401/422)
                error_str = str(e).lower()
                
                # 401/422 are permanent failures that shouldn't fallback
                if "401" in error_str or "422" in error_str:
                    logger.error(
                        "Refresh token permanently invalid (401/422), not attempting fallback",
                        extra={"extra_fields": {"error": str(e)}}
                    )
                    raise
                
                # For other errors (revoked, invalid, expired), attempt fallback
                if any(keyword in error_str for keyword in ["revoked", "invalid", "expired"]):
                    logger.warning(
                        "Refresh token invalid/revoked, falling back to reissue",
                        extra={"extra_fields": {"error": str(e)}}
                    )
                    # Fall through to reissue
                else:
                    # Other errors should be raised
                    raise
        else:
            logger.info("No refresh_token available, using reissue method")
        
        # Fallback: Reissue token via GitHub App
        logger.info("Attempting token reissue via GitHub App")
        
        try:
            result = await GitHubTokenRefreshManager._reissue_via_app(
                github_app_jwt=github_app_jwt,
                max_retries=max_retries
            )
            
            result["refresh_status"] = "success"
            result["refresh_method"] = "reissue"
            
            logger.info(
                "Token refresh successful using reissue method",
                extra={"extra_fields": {
                    "token_type": result.get("token_type", "unknown")
                }}
            )
            
            return result
            
        except Exception as e:
            logger.error(
                "Token reissue failed",
                extra={"extra_fields": {"error": str(e)}}
            )
            raise GitHubTokenRefreshError(f"Token reissue failed: {str(e)}")
    
    @staticmethod
    async def _refresh_with_token(
        refresh_token: str,
        client_id: str,
        client_secret: str,
        max_retries: int = 3
    ) -> Dict[str, Any]:
        """Refresh token using OAuth refresh_token grant.
        
        Args:
            refresh_token: The refresh token
            client_id: GitHub OAuth client ID
            client_secret: GitHub OAuth client secret
            max_retries: Maximum retries for transient errors
            
        Returns:
            Dictionary with new token data
            
        Raises:
            GitHubTokenRefreshError: If refresh fails
        """
        url = "https://github.com/login/oauth/access_token"
        
        payload = {
            "client_id": client_id,
            "client_secret": client_secret,
            "grant_type": "refresh_token",
            "refresh_token": refresh_token
        }
        
        headers = {
            "Accept": "application/json"
        }
        
        last_exception = None
        
        for attempt in range(max_retries):
            try:
                async with httpx.AsyncClient(timeout=30.0) as client:
                    response = await client.post(url, json=payload, headers=headers)
                    
                    # Log response at debug level (sanitized)
                    logger.debug(
                        "GitHub refresh token response",
                        extra={"extra_fields": {
                            "status_code": response.status_code,
                            "attempt": attempt + 1
                        }}
                    )
                    
                    if response.status_code != 200:
                        error_msg = f"GitHub refresh failed with status {response.status_code}"
                        
                        # Log truncated response for debugging (avoid full token exposure)
                        response_preview = response.text[:200] if response.text else "empty"
                        logger.error(
                            "GitHub refresh token failed",
                            extra={"extra_fields": {
                                "status_code": response.status_code,
                                "response_preview": response_preview,
                                "attempt": attempt + 1
                            }}
                        )
                        
                        # Don't retry on 401/422 - these indicate permanent failures
                        if response.status_code in [401, 422]:
                            raise GitHubTokenRefreshError(error_msg)
                        
                        # For other errors, raise on last attempt
                        if attempt == max_retries - 1:
                            raise GitHubTokenRefreshError(error_msg)
                        
                        # Otherwise, retry with exponential backoff
                        import asyncio
                        backoff = min(2 ** attempt, 8)  # Cap at 8 seconds
                        logger.info(
                            f"Retrying refresh after {backoff}s backoff",
                            extra={"extra_fields": {"attempt": attempt + 1, "backoff_seconds": backoff}}
                        )
                        await asyncio.sleep(backoff)
                        continue
                    
                    data = response.json()
                    
                    # Check for error in response
                    if "error" in data:
                        error_description = data.get("error_description", "Unknown error")
                        logger.error(
                            "GitHub refresh returned error",
                            extra={"extra_fields": {
                                "error": data["error"],
                                "description": error_description
                            }}
                        )
                        raise GitHubTokenRefreshError(
                            f"OAuth error: {data['error']} - {error_description}"
                        )
                    
                    # Validate required fields
                    if "access_token" not in data:
                        logger.error(
                            "GitHub refresh response missing access_token",
                            extra={"extra_fields": {"response_keys": list(data.keys())}}
                        )
                        raise GitHubTokenRefreshError("Response missing access_token field")
                    
                    return data
                    
            except httpx.HTTPError as e:
                last_exception = e
                logger.warning(
                    "HTTP error during token refresh",
                    extra={"extra_fields": {
                        "error": str(e),
                        "attempt": attempt + 1
                    }}
                )
                
                # Retry on network errors
                if attempt < max_retries - 1:
                    import asyncio
                    backoff = min(2 ** attempt, 8)
                    await asyncio.sleep(backoff)
                    continue
                
        # All retries exhausted
        raise GitHubTokenRefreshError(f"Token refresh failed after {max_retries} attempts: {str(last_exception)}")
    
    @staticmethod
    async def _reissue_via_app(
        github_app_jwt: GitHubAppJWT,
        max_retries: int = 3
    ) -> Dict[str, Any]:
        """Reissue user token via GitHub App installation access.
        
        This method uses the GitHub App's JWT to authenticate and reissue
        a user-to-server token. This is a fallback when refresh_token is
        not available or has been revoked.
        
        Note: This implementation is a placeholder and requires additional
        context (installation_id, user authorization) to work properly.
        For now, it raises NotImplementedError to indicate the need for
        full implementation based on stored user authorization data.
        
        Args:
            github_app_jwt: GitHub App JWT generator
            max_retries: Maximum retries for transient errors
            
        Returns:
            Dictionary with new token data
            
        Raises:
            NotImplementedError: Placeholder - requires installation_id and user auth
            GitHubTokenRefreshError: If reissue fails
        """
        # This is a placeholder implementation
        # Full implementation requires:
        # 1. installation_id (from when user authorized the app)
        # 2. User authorization data stored in Firestore
        # 3. POST to /app/installations/{installation_id}/access_tokens
        #    with proper JWT authentication
        
        logger.warning(
            "Token reissue via GitHub App is not fully implemented. "
            "Requires installation_id and user authorization data."
        )
        
        raise NotImplementedError(
            "Token reissue via GitHub App requires installation_id and user "
            "authorization data. This feature needs full OAuth flow implementation "
            "to store and retrieve installation context."
        )
