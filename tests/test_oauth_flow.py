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
"""Tests for GitHub OAuth flows and JWT generation."""

import time
import pytest
from unittest.mock import Mock, patch, AsyncMock
from datetime import datetime, timedelta

import jwt
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.backends import default_backend
from fastapi.testclient import TestClient

from app.main import create_app
from app.services.github import (
    GitHubAppJWT,
    GitHubAppJWTError,
    GitHubOAuthManager,
    GitHubOAuthError
)


def generate_test_private_key() -> tuple[str, str]:
    """Generate a test RSA private key pair.
    
    Returns:
        Tuple of (private_key_pem, public_key_pem)
    """
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )
    
    private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    ).decode('utf-8')
    
    public_key = private_key.public_key()
    public_pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    ).decode('utf-8')
    
    return private_pem, public_pem


class TestGitHubAppJWT:
    """Test suite for GitHub App JWT generation."""
    
    def test_jwt_initialization_with_valid_key(self):
        """Test JWT generator initializes with valid private key."""
        private_pem, _ = generate_test_private_key()
        
        jwt_generator = GitHubAppJWT(app_id="12345", private_key_pem=private_pem)
        
        assert jwt_generator.app_id == "12345"
        assert jwt_generator._private_key is not None
    
    def test_jwt_initialization_with_invalid_key(self):
        """Test JWT generator fails with invalid private key."""
        with pytest.raises(GitHubAppJWTError, match="Invalid private key"):
            GitHubAppJWT(app_id="12345", private_key_pem="invalid-key")
    
    def test_jwt_generation_success(self):
        """Test successful JWT generation."""
        private_pem, public_pem = generate_test_private_key()
        jwt_generator = GitHubAppJWT(app_id="12345", private_key_pem=private_pem)
        
        token = jwt_generator.generate_jwt(expiration_seconds=300)
        
        assert isinstance(token, str)
        assert len(token) > 0
        
        # Verify token can be decoded
        decoded = jwt.decode(
            token,
            public_pem,
            algorithms=['RS256'],
            options={"verify_exp": True}
        )
        
        assert decoded['iss'] == "12345"
        assert 'iat' in decoded
        assert 'exp' in decoded
    
    def test_jwt_expiration_time(self):
        """Test JWT has correct expiration time."""
        private_pem, public_pem = generate_test_private_key()
        jwt_generator = GitHubAppJWT(app_id="12345", private_key_pem=private_pem)
        
        now = int(time.time())
        token = jwt_generator.generate_jwt(expiration_seconds=300)
        
        decoded = jwt.decode(
            token,
            public_pem,
            algorithms=['RS256'],
            options={"verify_exp": False}
        )
        
        # Check expiration is approximately 300 seconds from now
        exp_time = decoded['exp']
        assert abs(exp_time - (now + 300)) < 5  # Allow 5 second tolerance
    
    def test_jwt_issued_at_with_clock_skew(self):
        """Test JWT issued_at accounts for clock skew."""
        private_pem, public_pem = generate_test_private_key()
        jwt_generator = GitHubAppJWT(app_id="12345", private_key_pem=private_pem)
        
        now = int(time.time())
        token = jwt_generator.generate_jwt(expiration_seconds=300)
        
        decoded = jwt.decode(
            token,
            public_pem,
            algorithms=['RS256'],
            options={"verify_exp": False}
        )
        
        # issued_at should be 60 seconds in the past to account for clock skew
        iat_time = decoded['iat']
        assert abs(iat_time - (now - 60)) < 5  # Allow 5 second tolerance
    
    def test_jwt_max_expiration_capped(self):
        """Test JWT expiration is capped at GitHub's 600 second maximum."""
        private_pem, public_pem = generate_test_private_key()
        jwt_generator = GitHubAppJWT(app_id="12345", private_key_pem=private_pem)
        
        # Request expiration longer than GitHub's max
        token = jwt_generator.generate_jwt(expiration_seconds=1000)
        
        decoded = jwt.decode(
            token,
            public_pem,
            algorithms=['RS256'],
            options={"verify_exp": False}
        )
        
        # Should be capped at 600 seconds
        now = int(time.time())
        exp_time = decoded['exp']
        assert abs(exp_time - (now + 600)) < 5
    
    def test_jwt_algorithm_is_rs256(self):
        """Test JWT uses RS256 algorithm."""
        private_pem, public_pem = generate_test_private_key()
        jwt_generator = GitHubAppJWT(app_id="12345", private_key_pem=private_pem)
        
        token = jwt_generator.generate_jwt()
        
        # Decode header without verification
        header = jwt.get_unverified_header(token)
        assert header['alg'] == 'RS256'
    
    def test_jwt_with_malformed_pem_begin_marker(self):
        """Test JWT fails gracefully with missing BEGIN marker."""
        malformed_pem = "MIIEvQIBADANBgkqhkiG9w0BAQEFAASC..."
        
        with pytest.raises(GitHubAppJWTError):
            GitHubAppJWT(app_id="12345", private_key_pem=malformed_pem)
    
    def test_jwt_with_malformed_pem_end_marker(self):
        """Test JWT fails gracefully with missing END marker."""
        malformed_pem = "-----BEGIN PRIVATE KEY-----\nMIIEvQIBADANBgkqhkiG9w0BAQEFAASC..."
        
        with pytest.raises(GitHubAppJWTError):
            GitHubAppJWT(app_id="12345", private_key_pem=malformed_pem)


class TestGitHubOAuthManager:
    """Test suite for GitHub OAuth state management."""
    
    def setup_method(self):
        """Clear state tokens before each test."""
        GitHubOAuthManager._state_tokens.clear()
    
    def test_generate_state_token(self):
        """Test state token generation."""
        state = GitHubOAuthManager.generate_state_token()
        
        assert isinstance(state, str)
        assert len(state) > 0
        assert state in GitHubOAuthManager._state_tokens
    
    def test_state_token_is_cryptographically_strong(self):
        """Test state tokens are unique and random."""
        tokens = {GitHubOAuthManager.generate_state_token() for _ in range(100)}
        
        # All tokens should be unique
        assert len(tokens) == 100
    
    def test_verify_valid_state_token(self):
        """Test verification of valid state token."""
        state = GitHubOAuthManager.generate_state_token()
        
        assert GitHubOAuthManager.verify_state_token(state) is True
    
    def test_verify_invalid_state_token(self):
        """Test verification fails for non-existent token."""
        result = GitHubOAuthManager.verify_state_token("invalid-token")
        
        assert result is False
    
    def test_state_token_one_time_use(self):
        """Test state tokens can only be used once."""
        state = GitHubOAuthManager.generate_state_token()
        
        # First verification succeeds
        assert GitHubOAuthManager.verify_state_token(state) is True
        
        # Second verification fails (token consumed)
        assert GitHubOAuthManager.verify_state_token(state) is False
    
    def test_state_token_expiration(self):
        """Test state tokens expire after configured time."""
        state = GitHubOAuthManager.generate_state_token()
        
        # Manually set expiration to the past
        GitHubOAuthManager._state_tokens[state] = time.time() - 10
        
        assert GitHubOAuthManager.verify_state_token(state) is False
        assert state not in GitHubOAuthManager._state_tokens
    
    def test_expired_tokens_cleanup(self):
        """Test expired tokens are cleaned up."""
        # Generate some tokens
        state1 = GitHubOAuthManager.generate_state_token()
        state2 = GitHubOAuthManager.generate_state_token()
        
        # Expire state1
        GitHubOAuthManager._state_tokens[state1] = time.time() - 10
        
        # Trigger cleanup
        GitHubOAuthManager._cleanup_expired_tokens()
        
        # state1 should be removed, state2 should remain
        assert state1 not in GitHubOAuthManager._state_tokens
        assert state2 in GitHubOAuthManager._state_tokens
    
    @pytest.mark.asyncio
    async def test_exchange_code_success(self):
        """Test successful OAuth code exchange."""
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.json.return_value = {
            "access_token": "gho_test_token_1234567890",
            "token_type": "bearer",
            "scope": "user:email,read:org"
        }
        
        with patch('httpx.AsyncClient') as mock_client:
            mock_client.return_value.__aenter__.return_value.post = AsyncMock(
                return_value=mock_response
            )
            
            result = await GitHubOAuthManager.exchange_code_for_token(
                code="test_code",
                client_id="test_client_id",
                client_secret="test_client_secret"
            )
        
        assert result["access_token"] == "gho_test_token_1234567890"
        assert result["token_type"] == "bearer"
        assert result["scope"] == "user:email,read:org"
    
    @pytest.mark.asyncio
    async def test_exchange_code_missing_access_token(self):
        """Test exchange fails when response missing access_token."""
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.json.return_value = {
            "token_type": "bearer",
            "scope": "user:email"
        }
        
        with patch('httpx.AsyncClient') as mock_client:
            mock_client.return_value.__aenter__.return_value.post = AsyncMock(
                return_value=mock_response
            )
            
            with pytest.raises(GitHubOAuthError, match="missing access_token"):
                await GitHubOAuthManager.exchange_code_for_token(
                    code="test_code",
                    client_id="test_client_id",
                    client_secret="test_client_secret"
                )
    
    @pytest.mark.asyncio
    async def test_exchange_code_github_error_response(self):
        """Test exchange handles GitHub error responses."""
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.json.return_value = {
            "error": "bad_verification_code",
            "error_description": "The code passed is incorrect or expired"
        }
        
        with patch('httpx.AsyncClient') as mock_client:
            mock_client.return_value.__aenter__.return_value.post = AsyncMock(
                return_value=mock_response
            )
            
            with pytest.raises(GitHubOAuthError, match="bad_verification_code"):
                await GitHubOAuthManager.exchange_code_for_token(
                    code="invalid_code",
                    client_id="test_client_id",
                    client_secret="test_client_secret"
                )
    
    @pytest.mark.asyncio
    async def test_exchange_code_non_200_status(self):
        """Test exchange handles non-200 HTTP status codes."""
        mock_response = Mock()
        mock_response.status_code = 401
        mock_response.text = "Unauthorized"
        
        with patch('httpx.AsyncClient') as mock_client:
            mock_client.return_value.__aenter__.return_value.post = AsyncMock(
                return_value=mock_response
            )
            
            with pytest.raises(GitHubOAuthError, match="status 401"):
                await GitHubOAuthManager.exchange_code_for_token(
                    code="test_code",
                    client_id="invalid_client",
                    client_secret="invalid_secret"
                )
    
    @pytest.mark.asyncio
    async def test_exchange_code_http_error(self):
        """Test exchange handles HTTP errors."""
        with patch('httpx.AsyncClient') as mock_client:
            mock_client.return_value.__aenter__.return_value.post = AsyncMock(
                side_effect=Exception("Connection timeout")
            )
            
            with pytest.raises(GitHubOAuthError, match="Unexpected error"):
                await GitHubOAuthManager.exchange_code_for_token(
                    code="test_code",
                    client_id="test_client_id",
                    client_secret="test_client_secret"
                )


class TestOAuthEndpoints:
    """Test suite for OAuth HTTP endpoints."""
    
    @pytest.fixture
    def client(self, monkeypatch):
        """Create test client with OAuth configuration."""
        import secrets
        monkeypatch.setenv("APP_ENV", "dev")
        monkeypatch.setenv("GITHUB_CLIENT_ID", "Iv1.test123")
        monkeypatch.setenv("GITHUB_CLIENT_SECRET", "test_secret")
        monkeypatch.setenv("GITHUB_APP_ID", "12345")
        monkeypatch.setenv("GITHUB_OAUTH_REDIRECT_URI", "http://localhost:8000/oauth/callback")
        monkeypatch.setenv("GCP_PROJECT_ID", "test-project")
        monkeypatch.setenv("GITHUB_TOKEN_ENCRYPTION_KEY", secrets.token_hex(32))
        
        from app import config
        original_settings = config.Settings
        monkeypatch.setattr(
            config,
            "Settings",
            lambda **kwargs: original_settings(_env_file=None, **kwargs)
        )
        
        # Clear state tokens before each test
        GitHubOAuthManager._state_tokens.clear()
        
        # Create app and override Firestore DAO dependency
        app = create_app()
        
        # Override the get_firestore_dao dependency with a mock
        from app.dependencies.firestore import get_firestore_dao
        mock_dao = Mock()
        mock_dao.save_github_token = AsyncMock()
        app.dependency_overrides[get_firestore_dao] = lambda: mock_dao
        
        return TestClient(app)
    
    def test_github_install_redirect(self, client):
        """Test /github/install redirects to GitHub with state."""
        response = client.get("/github/install", follow_redirects=False)
        
        assert response.status_code == 302
        
        location = response.headers.get("location")
        assert location is not None
        assert "github.com/login/oauth/authorize" in location
        assert "client_id=Iv1.test123" in location
        assert "state=" in location
        assert "redirect_uri=" in location
        assert "scope=" in location
        
        # Check state cookie is set
        assert "oauth_state" in response.cookies
    
    def test_github_install_custom_scopes(self, client):
        """Test /github/install with custom scopes."""
        response = client.get(
            "/github/install?scopes=repo,user",
            follow_redirects=False
        )
        
        assert response.status_code == 302
        location = response.headers.get("location")
        assert "scope=repo%2Cuser" in location or "scope=repo,user" in location
    
    def test_github_install_missing_client_id(self, monkeypatch):
        """Test /github/install fails without client ID."""
        monkeypatch.setenv("APP_ENV", "dev")
        monkeypatch.delenv("GITHUB_CLIENT_ID", raising=False)
        
        from app import config
        original_settings = config.Settings
        monkeypatch.setattr(
            config,
            "Settings",
            lambda **kwargs: original_settings(_env_file=None, **kwargs)
        )
        
        app = create_app()
        client = TestClient(app)
        
        response = client.get("/github/install")
        assert response.status_code == 500
    
    def test_oauth_callback_missing_parameters(self, client):
        """Test /oauth/callback fails without code or state."""
        response = client.get("/oauth/callback")
        
        assert response.status_code == 400
        assert b"Missing required parameters" in response.content
    
    def test_oauth_callback_invalid_state(self, client):
        """Test /oauth/callback fails with invalid state."""
        # Provide cookie to pass first check, but state is invalid in server store
        response = client.get(
            "/oauth/callback?code=test_code&state=invalid_state",
            cookies={"oauth_state": "invalid_state"}
        )
        
        assert response.status_code == 400
        assert b"Invalid or expired state token" in response.content
    
    def test_oauth_callback_expired_state(self, client):
        """Test /oauth/callback fails with expired state."""
        # Generate state and manually expire it
        state = GitHubOAuthManager.generate_state_token()
        GitHubOAuthManager._state_tokens[state] = time.time() - 10
        
        # Provide cookie to pass first check
        response = client.get(
            f"/oauth/callback?code=test_code&state={state}",
            cookies={"oauth_state": state}
        )
        
        assert response.status_code == 400
        assert b"Invalid or expired state token" in response.content
    
    def test_oauth_callback_state_already_used(self, client):
        """Test /oauth/callback fails when state is reused."""
        state = GitHubOAuthManager.generate_state_token()
        
        # First use succeeds (mocked)
        with patch.object(
            GitHubOAuthManager,
            'exchange_code_for_token',
            new_callable=AsyncMock
        ) as mock_exchange:
            mock_exchange.return_value = {
                "access_token": "gho_test_token",
                "token_type": "bearer",
                "scope": "user:email"
            }
            
            response1 = client.get(
                f"/oauth/callback?code=test_code&state={state}",
                cookies={"oauth_state": state}
            )
            assert response1.status_code == 200
        
        # Second use fails (state consumed)
        response2 = client.get(f"/oauth/callback?code=test_code&state={state}")
        assert response2.status_code == 400
    
    def test_oauth_callback_success(self, client):
        """Test successful OAuth callback flow."""
        state = GitHubOAuthManager.generate_state_token()
        
        with patch.object(
            GitHubOAuthManager,
            'exchange_code_for_token',
            new_callable=AsyncMock
        ) as mock_exchange:
            mock_exchange.return_value = {
                "access_token": "gho_test_token_1234567890",
                "token_type": "bearer",
                "scope": "user:email,read:org",
                "expires_in": 28800
            }
            
            response = client.get(
                f"/oauth/callback?code=test_code&state={state}",
                cookies={"oauth_state": state}
            )
        
        assert response.status_code == 200
        assert b"Authorization Successful" in response.content
        assert b"bearer" in response.content
        assert b"user:email,read:org" in response.content
        
        # State cookie should be cleared
        cookies = response.cookies
        assert cookies.get("oauth_state", "") == "" or "oauth_state" not in cookies
    
    def test_oauth_callback_github_error(self, client):
        """Test OAuth callback with GitHub error parameter."""
        response = client.get(
            "/oauth/callback?error=access_denied&error_description=User+denied+access"
        )
        
        assert response.status_code == 400
        assert b"Authorization Failed" in response.content
        assert b"access_denied" in response.content
    
    def test_oauth_callback_exchange_failure(self, client):
        """Test OAuth callback when token exchange fails."""
        state = GitHubOAuthManager.generate_state_token()
        
        with patch.object(
            GitHubOAuthManager,
            'exchange_code_for_token',
            new_callable=AsyncMock
        ) as mock_exchange:
            mock_exchange.side_effect = GitHubOAuthError("Exchange failed")
            
            response = client.get(
                f"/oauth/callback?code=test_code&state={state}",
                cookies={"oauth_state": state}
            )
        
        assert response.status_code == 500
        assert b"Token Exchange Failed" in response.content
    
    def test_oauth_callback_state_cookie_mismatch(self, client):
        """Test OAuth callback fails when state doesn't match cookie."""
        state = GitHubOAuthManager.generate_state_token()
        wrong_state = GitHubOAuthManager.generate_state_token()
        
        response = client.get(
            f"/oauth/callback?code=test_code&state={state}",
            cookies={"oauth_state": wrong_state}
        )
        
        assert response.status_code == 400
        assert b"State token mismatch" in response.content


class TestOAuthIntegration:
    """Integration tests for complete OAuth flow."""
    
    def test_full_oauth_flow(self, monkeypatch):
        """Test complete OAuth flow from install to callback."""
        import secrets
        monkeypatch.setenv("APP_ENV", "dev")
        monkeypatch.setenv("GITHUB_CLIENT_ID", "Iv1.test123")
        monkeypatch.setenv("GITHUB_CLIENT_SECRET", "test_secret")
        monkeypatch.setenv("GITHUB_APP_ID", "12345")
        monkeypatch.setenv("GITHUB_OAUTH_REDIRECT_URI", "http://localhost:8000/oauth/callback")
        monkeypatch.setenv("GCP_PROJECT_ID", "test-project")
        monkeypatch.setenv("GITHUB_TOKEN_ENCRYPTION_KEY", secrets.token_hex(32))
        
        from app import config
        original_settings = config.Settings
        monkeypatch.setattr(
            config,
            "Settings",
            lambda **kwargs: original_settings(_env_file=None, **kwargs)
        )
        
        GitHubOAuthManager._state_tokens.clear()
        
        app = create_app()
        
        # Override the get_firestore_dao dependency with a mock
        from app.dependencies.firestore import get_firestore_dao
        mock_dao = Mock()
        mock_dao.save_github_token = AsyncMock()
        app.dependency_overrides[get_firestore_dao] = lambda: mock_dao
        
        client = TestClient(app)
        
        # Step 1: Request installation redirect
        response = client.get("/github/install", follow_redirects=False)
        assert response.status_code == 302
        
        # Extract state from redirect URL
        location = response.headers.get("location")
        state_param = [p for p in location.split("&") if p.startswith("state=")][0]
        state = state_param.split("=")[1]
        
        # Get state cookie
        state_cookie = response.cookies.get("oauth_state")
        
        # Step 2: Simulate GitHub callback with the state
        with patch.object(
            GitHubOAuthManager,
            'exchange_code_for_token',
            new_callable=AsyncMock
        ) as mock_exchange:
            mock_exchange.return_value = {
                "access_token": "gho_test_token_abc123",
                "token_type": "bearer",
                "scope": "user:email,read:org"
            }
            
            callback_response = client.get(
                f"/oauth/callback?code=auth_code_123&state={state}",
                cookies={"oauth_state": state_cookie}
            )
        
        assert callback_response.status_code == 200
        assert b"Authorization Successful" in callback_response.content


class TestOAuthFirestorePersistence:
    """Test suite for OAuth token persistence to Firestore."""
    
    @pytest.fixture
    def client(self, monkeypatch):
        """Create test client with OAuth and Firestore configuration."""
        import secrets
        monkeypatch.setenv("APP_ENV", "dev")
        monkeypatch.setenv("GITHUB_CLIENT_ID", "Iv1.test123")
        monkeypatch.setenv("GITHUB_CLIENT_SECRET", "test_secret")
        monkeypatch.setenv("GITHUB_APP_ID", "12345")
        monkeypatch.setenv("GITHUB_OAUTH_REDIRECT_URI", "http://localhost:8000/oauth/callback")
        monkeypatch.setenv("GCP_PROJECT_ID", "test-project")
        monkeypatch.setenv("GITHUB_TOKEN_ENCRYPTION_KEY", secrets.token_hex(32))
        
        from app import config
        original_settings = config.Settings
        monkeypatch.setattr(
            config,
            "Settings",
            lambda **kwargs: original_settings(_env_file=None, **kwargs)
        )
        
        # Clear state tokens before each test
        GitHubOAuthManager._state_tokens.clear()
        
        app = create_app()
        return TestClient(app)
    
    @pytest.mark.asyncio
    async def test_oauth_callback_persists_token_to_firestore(self, client, monkeypatch):
        """Test that successful OAuth callback persists token to Firestore."""
        import secrets
        
        # Setup
        state = GitHubOAuthManager.generate_state_token()
        
        # Mock Firestore DAO
        mock_dao = Mock()
        mock_dao.save_github_token = AsyncMock()
        
        # Mock token exchange
        with patch.object(
            GitHubOAuthManager,
            'exchange_code_for_token',
            new_callable=AsyncMock
        ) as mock_exchange, \
             patch('app.dependencies.firestore.get_firestore_client') as mock_get_client, \
             patch('app.dependencies.firestore.FirestoreDAO') as mock_dao_class:
            
            mock_exchange.return_value = {
                "access_token": "gho_test_token_1234567890",
                "token_type": "bearer",
                "scope": "user:email,read:org",
                "expires_in": 28800  # 8 hours
            }
            
            # Setup mock DAO
            mock_client = Mock()
            mock_get_client.return_value = mock_client
            mock_dao_class.return_value = mock_dao
            
            response = client.get(
                f"/oauth/callback?code=test_code&state={state}",
                cookies={"oauth_state": state}
            )
        
        # Verify response
        assert response.status_code == 200
        assert b"Authorization Successful" in response.content
        
        # Verify DAO was called to save token
        mock_dao.save_github_token.assert_called_once()
        call_kwargs = mock_dao.save_github_token.call_args[1]
        
        assert call_kwargs["collection"] == "github_tokens"
        assert call_kwargs["doc_id"] == "primary_user"
        assert call_kwargs["access_token"] == "gho_test_token_1234567890"
        assert call_kwargs["token_type"] == "bearer"
        assert call_kwargs["scope"] == "user:email,read:org"
        assert call_kwargs["expires_at"] is not None
        assert call_kwargs["refresh_token"] is None
    
    @pytest.mark.asyncio
    async def test_oauth_callback_calculates_expires_at_from_expires_in(self, client, monkeypatch):
        """Test that expires_at is calculated from expires_in."""
        from datetime import datetime, timezone, timedelta
        
        state = GitHubOAuthManager.generate_state_token()
        mock_dao = Mock()
        mock_dao.save_github_token = AsyncMock()
        
        with patch.object(
            GitHubOAuthManager,
            'exchange_code_for_token',
            new_callable=AsyncMock
        ) as mock_exchange, \
             patch('app.dependencies.firestore.get_firestore_client') as mock_get_client, \
             patch('app.dependencies.firestore.FirestoreDAO') as mock_dao_class:
            
            mock_exchange.return_value = {
                "access_token": "gho_test_token",
                "token_type": "bearer",
                "scope": "repo",
                "expires_in": 3600  # 1 hour
            }
            
            mock_client = Mock()
            mock_get_client.return_value = mock_client
            mock_dao_class.return_value = mock_dao
            
            before_call = datetime.now(timezone.utc)
            response = client.get(
                f"/oauth/callback?code=test_code&state={state}",
                cookies={"oauth_state": state}
            )
            after_call = datetime.now(timezone.utc)
        
        assert response.status_code == 200
        
        # Verify expires_at was calculated correctly
        call_kwargs = mock_dao.save_github_token.call_args[1]
        expires_at = call_kwargs["expires_at"]
        
        assert expires_at is not None
        # expires_at should be approximately 1 hour from now (allowing for small time differences)
        expected_min = before_call + timedelta(seconds=3600)
        expected_max = after_call + timedelta(seconds=3600)
        assert expected_min <= expires_at <= expected_max
    
    @pytest.mark.asyncio
    async def test_oauth_callback_handles_missing_expires_in(self, client, monkeypatch):
        """Test that missing expires_in is handled gracefully."""
        state = GitHubOAuthManager.generate_state_token()
        mock_dao = Mock()
        mock_dao.save_github_token = AsyncMock()
        
        with patch.object(
            GitHubOAuthManager,
            'exchange_code_for_token',
            new_callable=AsyncMock
        ) as mock_exchange, \
             patch('app.dependencies.firestore.get_firestore_client') as mock_get_client, \
             patch('app.dependencies.firestore.FirestoreDAO') as mock_dao_class:
            
            # Token response without expires_in
            mock_exchange.return_value = {
                "access_token": "gho_test_token",
                "token_type": "bearer",
                "scope": "user"
            }
            
            mock_client = Mock()
            mock_get_client.return_value = mock_client
            mock_dao_class.return_value = mock_dao
            
            response = client.get(
                f"/oauth/callback?code=test_code&state={state}",
                cookies={"oauth_state": state}
            )
        
        assert response.status_code == 200
        
        # Verify expires_at is None when expires_in is not provided
        call_kwargs = mock_dao.save_github_token.call_args[1]
        assert call_kwargs["expires_at"] is None
    
    @pytest.mark.asyncio
    async def test_oauth_callback_handles_missing_scope(self, client, monkeypatch):
        """Test that missing scope is handled gracefully."""
        state = GitHubOAuthManager.generate_state_token()
        mock_dao = Mock()
        mock_dao.save_github_token = AsyncMock()
        
        with patch.object(
            GitHubOAuthManager,
            'exchange_code_for_token',
            new_callable=AsyncMock
        ) as mock_exchange, \
             patch('app.dependencies.firestore.get_firestore_client') as mock_get_client, \
             patch('app.dependencies.firestore.FirestoreDAO') as mock_dao_class:
            
            # Token response without scope
            mock_exchange.return_value = {
                "access_token": "gho_test_token",
                "token_type": "bearer"
            }
            
            mock_client = Mock()
            mock_get_client.return_value = mock_client
            mock_dao_class.return_value = mock_dao
            
            response = client.get(
                f"/oauth/callback?code=test_code&state={state}",
                cookies={"oauth_state": state}
            )
        
        assert response.status_code == 200
        
        # Verify scope is None when not provided
        call_kwargs = mock_dao.save_github_token.call_args[1]
        assert call_kwargs["scope"] is None
    
    @pytest.mark.asyncio
    async def test_oauth_callback_includes_refresh_token_if_present(self, client, monkeypatch):
        """Test that refresh_token is saved if provided."""
        state = GitHubOAuthManager.generate_state_token()
        mock_dao = Mock()
        mock_dao.save_github_token = AsyncMock()
        
        with patch.object(
            GitHubOAuthManager,
            'exchange_code_for_token',
            new_callable=AsyncMock
        ) as mock_exchange, \
             patch('app.dependencies.firestore.get_firestore_client') as mock_get_client, \
             patch('app.dependencies.firestore.FirestoreDAO') as mock_dao_class:
            
            mock_exchange.return_value = {
                "access_token": "gho_test_token",
                "token_type": "bearer",
                "scope": "repo",
                "expires_in": 28800,
                "refresh_token": "ghr_refresh_token_xyz"
            }
            
            mock_client = Mock()
            mock_get_client.return_value = mock_client
            mock_dao_class.return_value = mock_dao
            
            response = client.get(
                f"/oauth/callback?code=test_code&state={state}",
                cookies={"oauth_state": state}
            )
        
        assert response.status_code == 200
        
        # Verify refresh_token was saved
        call_kwargs = mock_dao.save_github_token.call_args[1]
        assert call_kwargs["refresh_token"] == "ghr_refresh_token_xyz"
    
    @pytest.mark.asyncio
    async def test_oauth_callback_firestore_failure_returns_503(self, client, monkeypatch):
        """Test that Firestore write failure returns 503 error."""
        state = GitHubOAuthManager.generate_state_token()
        mock_dao = Mock()
        # Simulate Firestore failure
        mock_dao.save_github_token = AsyncMock(side_effect=Exception("Firestore unavailable"))
        
        with patch.object(
            GitHubOAuthManager,
            'exchange_code_for_token',
            new_callable=AsyncMock
        ) as mock_exchange, \
             patch('app.dependencies.firestore.get_firestore_client') as mock_get_client, \
             patch('app.dependencies.firestore.FirestoreDAO') as mock_dao_class:
            
            mock_exchange.return_value = {
                "access_token": "gho_test_token",
                "token_type": "bearer",
                "scope": "user"
            }
            
            mock_client = Mock()
            mock_get_client.return_value = mock_client
            mock_dao_class.return_value = mock_dao
            
            response = client.get(
                f"/oauth/callback?code=test_code&state={state}",
                cookies={"oauth_state": state}
            )
        
        # Verify 503 error is returned
        assert response.status_code == 503
        assert b"Token Storage Failed" in response.content
        assert b"could not be saved" in response.content
    
    @pytest.mark.asyncio
    async def test_oauth_callback_does_not_redirect_success_on_firestore_failure(self, client, monkeypatch):
        """Test that callback does not claim success when Firestore fails."""
        state = GitHubOAuthManager.generate_state_token()
        mock_dao = Mock()
        mock_dao.save_github_token = AsyncMock(side_effect=Exception("Firestore error"))
        
        with patch.object(
            GitHubOAuthManager,
            'exchange_code_for_token',
            new_callable=AsyncMock
        ) as mock_exchange, \
             patch('app.dependencies.firestore.get_firestore_client') as mock_get_client, \
             patch('app.dependencies.firestore.FirestoreDAO') as mock_dao_class:
            
            mock_exchange.return_value = {
                "access_token": "gho_test_token",
                "token_type": "bearer"
            }
            
            mock_client = Mock()
            mock_get_client.return_value = mock_client
            mock_dao_class.return_value = mock_dao
            
            response = client.get(
                f"/oauth/callback?code=test_code&state={state}",
                cookies={"oauth_state": state}
            )
        
        # Should NOT show success message
        assert b"Authorization Successful" not in response.content
        # Should show error instead
        assert response.status_code == 503
        assert b"Token Storage Failed" in response.content
    
    @pytest.mark.asyncio
    async def test_oauth_callback_repeated_calls_overwrite_token(self, client, monkeypatch):
        """Test that repeated callbacks overwrite the token deterministically."""
        mock_dao = Mock()
        mock_dao.save_github_token = AsyncMock()
        
        with patch.object(
            GitHubOAuthManager,
            'exchange_code_for_token',
            new_callable=AsyncMock
        ) as mock_exchange, \
             patch('app.dependencies.firestore.get_firestore_client') as mock_get_client, \
             patch('app.dependencies.firestore.FirestoreDAO') as mock_dao_class:
            
            mock_exchange.return_value = {
                "access_token": "gho_test_token_1",
                "token_type": "bearer"
            }
            
            mock_client = Mock()
            mock_get_client.return_value = mock_client
            mock_dao_class.return_value = mock_dao
            
            # First callback
            state1 = GitHubOAuthManager.generate_state_token()
            response1 = client.get(
                f"/oauth/callback?code=code1&state={state1}",
                cookies={"oauth_state": state1}
            )
            
            # Update token for second call
            mock_exchange.return_value["access_token"] = "gho_test_token_2"
            
            # Second callback
            state2 = GitHubOAuthManager.generate_state_token()
            response2 = client.get(
                f"/oauth/callback?code=code2&state={state2}",
                cookies={"oauth_state": state2}
            )
        
        # Both should succeed
        assert response1.status_code == 200
        assert response2.status_code == 200
        
        # Verify both writes occurred
        assert mock_dao.save_github_token.call_count == 2
        
        # Verify tokens are different
        call1_token = mock_dao.save_github_token.call_args_list[0][1]["access_token"]
        call2_token = mock_dao.save_github_token.call_args_list[1][1]["access_token"]
        assert call1_token == "gho_test_token_1"
        assert call2_token == "gho_test_token_2"
    
    @pytest.mark.asyncio
    async def test_token_masking_in_logs(self, client, monkeypatch, caplog):
        """Test that sensitive token data is masked in logs."""
        import logging
        caplog.set_level(logging.INFO)
        
        state = GitHubOAuthManager.generate_state_token()
        mock_dao = Mock()
        mock_dao.save_github_token = AsyncMock()
        
        with patch.object(
            GitHubOAuthManager,
            'exchange_code_for_token',
            new_callable=AsyncMock
        ) as mock_exchange, \
             patch('app.dependencies.firestore.get_firestore_client') as mock_get_client, \
             patch('app.dependencies.firestore.FirestoreDAO') as mock_dao_class:
            
            # Use a recognizable token
            full_token = "gho_test_token_should_be_masked_1234567890"
            mock_exchange.return_value = {
                "access_token": full_token,
                "token_type": "bearer",
                "scope": "repo"
            }
            
            mock_client = Mock()
            mock_get_client.return_value = mock_client
            mock_dao_class.return_value = mock_dao
            
            response = client.get(
                f"/oauth/callback?code=test_code&state={state}",
                cookies={"oauth_state": state}
            )
        
        assert response.status_code == 200
        
        # Verify full token is NOT in logs (tokens are masked in service layer)
        log_text = caplog.text
        # The service layer should mask the token, so full token shouldn't appear
        # Note: GitHubOAuthManager.exchange_code_for_token already masks tokens in logs
        assert "should_be_masked_1234567890" not in log_text or "gho_test_t..." in log_text
