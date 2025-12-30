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
"""Integration tests for POST /api/token endpoint."""

import pytest
from unittest.mock import Mock, patch, AsyncMock
from datetime import datetime, timezone, timedelta
from fastapi.testclient import TestClient

from app.main import create_app
from app.config import Settings
from app.services.github import GitHubTokenRefreshCooldownError, GitHubTokenRefreshError


def generate_test_private_key() -> str:
    """Generate a test RSA private key for testing."""
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.backends import default_backend
    
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
    
    return private_pem


@pytest.fixture
def test_settings():
    """Create test settings with all required fields."""
    import secrets
    return Settings(
        app_env="dev",
        gcp_project_id="test-project",
        github_app_id="12345",
        github_app_private_key_pem=generate_test_private_key(),
        github_client_id="test_client_id",
        github_client_secret="test_client_secret",
        github_oauth_redirect_uri="http://localhost:8000/oauth/callback",
        github_token_encryption_key=secrets.token_hex(32),
        token_refresh_threshold_minutes=30,
        token_refresh_cooldown_seconds=300
    )


@pytest.fixture
def mock_firestore_client():
    """Create a mock Firestore client."""
    from google.cloud import firestore
    return Mock(spec=firestore.AsyncClient)


@pytest.fixture
def test_app(test_settings, mock_firestore_client):
    """Create test FastAPI app with mocked dependencies."""
    app = create_app()
    app.state.settings = test_settings
    
    # Mock Firestore client creation
    with patch('app.dependencies.firestore.get_firestore_client', return_value=mock_firestore_client):
        yield app


@pytest.fixture
def client(test_app):
    """Create test client."""
    return TestClient(test_app)


class TestTokenEndpointSuccess:
    """Test successful token retrieval scenarios."""
    
    def test_get_token_success_no_refresh_needed(self, client, mock_firestore_client, test_settings):
        """Test successful token retrieval when token is not near expiry."""
        # Setup: Mock Firestore to return a valid token
        from app.dao.firestore_dao import FirestoreDAO
        
        dao = FirestoreDAO(mock_firestore_client, encryption_key=test_settings.github_token_encryption_key)
        
        access_token = "gho_test_token_123"
        encrypted_token = dao._encrypt_token(access_token)
        expires_at = datetime.now(timezone.utc) + timedelta(hours=8)
        
        mock_doc = Mock()
        mock_doc.exists = True
        mock_doc.to_dict.return_value = {
            "access_token": encrypted_token,
            "token_type": "bearer",
            "scope": "repo,user",
            "expires_at": expires_at.isoformat(),
            "refresh_token": None,
            "last_refresh_attempt": None,
            "last_refresh_status": None,
            "last_refresh_error": None,
            "updated_at": datetime.now(timezone.utc).isoformat()
        }
        
        mock_firestore_client.collection.return_value.document.return_value.get = AsyncMock(return_value=mock_doc)
        
        # Execute
        response = client.post("/api/token")
        
        # Assert
        assert response.status_code == 200
        data = response.json()
        assert data["access_token"] == access_token
        assert data["token_type"] == "bearer"
        assert data["expires_at"] == expires_at.isoformat()
    
    def test_get_token_with_query_param_force_refresh_false(self, client, mock_firestore_client, test_settings):
        """Test token retrieval with force_refresh=false in query param."""
        from app.dao.firestore_dao import FirestoreDAO
        
        dao = FirestoreDAO(mock_firestore_client, encryption_key=test_settings.github_token_encryption_key)
        
        access_token = "gho_test_token_456"
        encrypted_token = dao._encrypt_token(access_token)
        expires_at = datetime.now(timezone.utc) + timedelta(hours=8)
        
        mock_doc = Mock()
        mock_doc.exists = True
        mock_doc.to_dict.return_value = {
            "access_token": encrypted_token,
            "token_type": "bearer",
            "scope": "repo",
            "expires_at": expires_at.isoformat(),
            "refresh_token": None,
            "last_refresh_attempt": None,
            "last_refresh_status": None,
            "last_refresh_error": None,
            "updated_at": datetime.now(timezone.utc).isoformat()
        }
        
        mock_firestore_client.collection.return_value.document.return_value.get = AsyncMock(return_value=mock_doc)
        
        # Execute
        response = client.post("/api/token?force_refresh=false")
        
        # Assert
        assert response.status_code == 200
        data = response.json()
        assert data["access_token"] == access_token
    
    def test_get_token_non_expiring_no_refresh(self, client, mock_firestore_client, test_settings):
        """Test token retrieval for non-expiring token without force_refresh."""
        from app.dao.firestore_dao import FirestoreDAO
        
        dao = FirestoreDAO(mock_firestore_client, encryption_key=test_settings.github_token_encryption_key)
        
        access_token = "gho_non_expiring_token"
        encrypted_token = dao._encrypt_token(access_token)
        
        mock_doc = Mock()
        mock_doc.exists = True
        mock_doc.to_dict.return_value = {
            "access_token": encrypted_token,
            "token_type": "bearer",
            "scope": "repo",
            "expires_at": None,  # Non-expiring
            "refresh_token": None,
            "last_refresh_attempt": None,
            "last_refresh_status": None,
            "last_refresh_error": None,
            "updated_at": datetime.now(timezone.utc).isoformat()
        }
        
        mock_firestore_client.collection.return_value.document.return_value.get = AsyncMock(return_value=mock_doc)
        
        # Execute
        response = client.post("/api/token")
        
        # Assert
        assert response.status_code == 200
        data = response.json()
        assert data["access_token"] == access_token
        assert data["expires_at"] is None


class TestTokenEndpointMissingToken:
    """Test missing token scenarios."""
    
    def test_get_token_not_found(self, client, mock_firestore_client):
        """Test 404 response when token document doesn't exist."""
        # Setup: Mock Firestore to return no document
        mock_doc = Mock()
        mock_doc.exists = False
        
        mock_firestore_client.collection.return_value.document.return_value.get = AsyncMock(return_value=mock_doc)
        
        # Execute
        response = client.post("/api/token")
        
        # Assert
        assert response.status_code == 404
        assert response.json()["detail"] == "User has not completed authorization"


class TestTokenEndpointForcedRefresh:
    """Test forced refresh scenarios."""
    
    @patch('app.routes.token.GitHubTokenRefreshManager.refresh_user_token')
    def test_force_refresh_via_query_param(
        self, mock_refresh, client, mock_firestore_client, test_settings
    ):
        """Test forced refresh via query parameter."""
        from app.dao.firestore_dao import FirestoreDAO
        
        dao = FirestoreDAO(mock_firestore_client, encryption_key=test_settings.github_token_encryption_key)
        
        old_token = "gho_old_token"
        new_token = "gho_new_token"
        encrypted_old_token = dao._encrypt_token(old_token)
        
        # Far future expiry - wouldn't normally refresh
        expires_at = datetime.now(timezone.utc) + timedelta(hours=8)
        
        mock_doc = Mock()
        mock_doc.exists = True
        mock_doc.to_dict.return_value = {
            "access_token": encrypted_old_token,
            "token_type": "bearer",
            "scope": "repo",
            "expires_at": expires_at.isoformat(),
            "refresh_token": None,
            "last_refresh_attempt": None,
            "last_refresh_status": None,
            "last_refresh_error": None,
            "updated_at": datetime.now(timezone.utc).isoformat()
        }
        
        mock_firestore_client.collection.return_value.document.return_value.get = AsyncMock(return_value=mock_doc)
        
        # Mock successful refresh
        mock_refresh.return_value = {
            "access_token": new_token,
            "token_type": "bearer",
            "scope": "repo",
            "expires_in": 28800,
            "refresh_method": "refresh_grant"
        }
        
        # Mock save
        mock_firestore_client.collection.return_value.document.return_value.set = AsyncMock()
        
        # Execute
        response = client.post("/api/token?force_refresh=true")
        
        # Assert
        assert response.status_code == 200
        data = response.json()
        assert data["access_token"] == new_token
        assert data["token_type"] == "bearer"
        assert data["expires_at"] is not None
        
        # Verify refresh was called with force_refresh=True
        mock_refresh.assert_called_once()
        call_kwargs = mock_refresh.call_args.kwargs
        assert call_kwargs["force_refresh"] is True
    
    @patch('app.routes.token.GitHubTokenRefreshManager.refresh_user_token')
    def test_force_refresh_via_request_body(
        self, mock_refresh, client, mock_firestore_client, test_settings
    ):
        """Test forced refresh via JSON request body."""
        from app.dao.firestore_dao import FirestoreDAO
        
        dao = FirestoreDAO(mock_firestore_client, encryption_key=test_settings.github_token_encryption_key)
        
        old_token = "gho_old_token_body"
        new_token = "gho_new_token_body"
        encrypted_old_token = dao._encrypt_token(old_token)
        
        expires_at = datetime.now(timezone.utc) + timedelta(hours=8)
        
        mock_doc = Mock()
        mock_doc.exists = True
        mock_doc.to_dict.return_value = {
            "access_token": encrypted_old_token,
            "token_type": "bearer",
            "scope": "repo",
            "expires_at": expires_at.isoformat(),
            "refresh_token": None,
            "last_refresh_attempt": None,
            "last_refresh_status": None,
            "last_refresh_error": None,
            "updated_at": datetime.now(timezone.utc).isoformat()
        }
        
        mock_firestore_client.collection.return_value.document.return_value.get = AsyncMock(return_value=mock_doc)
        
        # Mock successful refresh
        mock_refresh.return_value = {
            "access_token": new_token,
            "token_type": "bearer",
            "scope": "repo",
            "expires_in": 28800,
            "refresh_method": "refresh_grant"
        }
        
        # Mock save
        mock_firestore_client.collection.return_value.document.return_value.set = AsyncMock()
        
        # Execute
        response = client.post("/api/token", json={"force_refresh": True})
        
        # Assert
        assert response.status_code == 200
        data = response.json()
        assert data["access_token"] == new_token


class TestTokenEndpointNearExpiry:
    """Test near-expiry automatic refresh scenarios."""
    
    @patch('app.routes.token.GitHubTokenRefreshManager.refresh_user_token')
    def test_auto_refresh_near_expiry(
        self, mock_refresh, client, mock_firestore_client, test_settings
    ):
        """Test automatic refresh when token is near expiry."""
        from app.dao.firestore_dao import FirestoreDAO
        
        dao = FirestoreDAO(mock_firestore_client, encryption_key=test_settings.github_token_encryption_key)
        
        old_token = "gho_expiring_soon"
        new_token = "gho_refreshed"
        encrypted_old_token = dao._encrypt_token(old_token)
        
        # Token expires in 20 minutes (within 30-minute threshold)
        expires_at = datetime.now(timezone.utc) + timedelta(minutes=20)
        
        mock_doc = Mock()
        mock_doc.exists = True
        mock_doc.to_dict.return_value = {
            "access_token": encrypted_old_token,
            "token_type": "bearer",
            "scope": "repo",
            "expires_at": expires_at.isoformat(),
            "refresh_token": dao._encrypt_token("ghr_refresh_token"),
            "last_refresh_attempt": None,
            "last_refresh_status": None,
            "last_refresh_error": None,
            "updated_at": datetime.now(timezone.utc).isoformat()
        }
        
        mock_firestore_client.collection.return_value.document.return_value.get = AsyncMock(return_value=mock_doc)
        
        # Mock successful refresh
        mock_refresh.return_value = {
            "access_token": new_token,
            "token_type": "bearer",
            "scope": "repo",
            "expires_in": 28800,
            "refresh_method": "refresh_grant"
        }
        
        # Mock save
        mock_firestore_client.collection.return_value.document.return_value.set = AsyncMock()
        
        # Execute
        response = client.post("/api/token")
        
        # Assert
        assert response.status_code == 200
        data = response.json()
        assert data["access_token"] == new_token
        
        # Verify refresh was called (not forced, but due to near-expiry)
        mock_refresh.assert_called_once()
        call_kwargs = mock_refresh.call_args.kwargs
        assert call_kwargs["force_refresh"] is False


class TestTokenEndpointCooldown:
    """Test cooldown scenarios."""
    
    @patch('app.routes.token.GitHubTokenRefreshManager.refresh_user_token')
    def test_cooldown_returns_current_token(
        self, mock_refresh, client, mock_firestore_client, test_settings
    ):
        """Test that cooldown error returns current token instead of failing."""
        from app.dao.firestore_dao import FirestoreDAO
        
        dao = FirestoreDAO(mock_firestore_client, encryption_key=test_settings.github_token_encryption_key)
        
        current_token = "gho_current_token"
        encrypted_token = dao._encrypt_token(current_token)
        
        # Token near expiry but refresh in cooldown
        expires_at = datetime.now(timezone.utc) + timedelta(minutes=20)
        last_refresh_attempt = datetime.now(timezone.utc) - timedelta(seconds=60)
        
        mock_doc = Mock()
        mock_doc.exists = True
        mock_doc.to_dict.return_value = {
            "access_token": encrypted_token,
            "token_type": "bearer",
            "scope": "repo",
            "expires_at": expires_at.isoformat(),
            "refresh_token": None,
            "last_refresh_attempt": last_refresh_attempt.isoformat(),
            "last_refresh_status": "failed",
            "last_refresh_error": "Previous refresh failed",
            "updated_at": datetime.now(timezone.utc).isoformat()
        }
        
        mock_firestore_client.collection.return_value.document.return_value.get = AsyncMock(return_value=mock_doc)
        
        # Mock cooldown error
        mock_refresh.side_effect = GitHubTokenRefreshCooldownError(
            "Cooldown active",
            seconds_until_retry=240
        )
        
        # Execute
        response = client.post("/api/token")
        
        # Assert - should return 200 with current token, not 500
        assert response.status_code == 200
        data = response.json()
        assert data["access_token"] == current_token


class TestTokenEndpointGitHubFailure:
    """Test GitHub API failure scenarios."""
    
    @patch('app.routes.token.GitHubTokenRefreshManager.refresh_user_token')
    def test_refresh_failure_returns_500(
        self, mock_refresh, client, mock_firestore_client, test_settings
    ):
        """Test that refresh failure returns 500 with sanitized error."""
        from app.dao.firestore_dao import FirestoreDAO
        
        dao = FirestoreDAO(mock_firestore_client, encryption_key=test_settings.github_token_encryption_key)
        
        current_token = "gho_token_before_fail"
        encrypted_token = dao._encrypt_token(current_token)
        
        # Force refresh to trigger the failure
        expires_at = datetime.now(timezone.utc) + timedelta(hours=8)
        
        mock_doc = Mock()
        mock_doc.exists = True
        mock_doc.to_dict.return_value = {
            "access_token": encrypted_token,
            "token_type": "bearer",
            "scope": "repo",
            "expires_at": expires_at.isoformat(),
            "refresh_token": None,
            "last_refresh_attempt": None,
            "last_refresh_status": None,
            "last_refresh_error": None,
            "updated_at": datetime.now(timezone.utc).isoformat()
        }
        
        mock_firestore_client.collection.return_value.document.return_value.get = AsyncMock(return_value=mock_doc)
        
        # Mock refresh failure
        mock_refresh.side_effect = GitHubTokenRefreshError("GitHub API returned 401: Unauthorized")
        
        # Mock save for failure metadata
        mock_firestore_client.collection.return_value.document.return_value.set = AsyncMock()
        
        # Execute
        response = client.post("/api/token?force_refresh=true")
        
        # Assert
        assert response.status_code == 500
        assert response.json()["detail"] == "Failed to refresh GitHub token"
        # Ensure no sensitive data leaked
        assert "401" not in response.json()["detail"]
        assert "Unauthorized" not in response.json()["detail"]
    
    @patch('app.routes.token.GitHubTokenRefreshManager.refresh_user_token')
    def test_refresh_failure_persists_metadata(
        self, mock_refresh, client, mock_firestore_client, test_settings
    ):
        """Test that refresh failure metadata is persisted."""
        from app.dao.firestore_dao import FirestoreDAO
        
        dao = FirestoreDAO(mock_firestore_client, encryption_key=test_settings.github_token_encryption_key)
        
        current_token = "gho_token"
        encrypted_token = dao._encrypt_token(current_token)
        expires_at = datetime.now(timezone.utc) + timedelta(hours=8)
        
        mock_doc = Mock()
        mock_doc.exists = True
        mock_doc.to_dict.return_value = {
            "access_token": encrypted_token,
            "token_type": "bearer",
            "scope": "repo",
            "expires_at": expires_at.isoformat(),
            "refresh_token": None,
            "last_refresh_attempt": None,
            "last_refresh_status": None,
            "last_refresh_error": None,
            "updated_at": datetime.now(timezone.utc).isoformat()
        }
        
        mock_firestore_client.collection.return_value.document.return_value.get = AsyncMock(return_value=mock_doc)
        
        # Mock refresh failure
        error_msg = "GitHub API error"
        mock_refresh.side_effect = GitHubTokenRefreshError(error_msg)
        
        # Mock save
        mock_save = AsyncMock()
        mock_firestore_client.collection.return_value.document.return_value.set = mock_save
        
        # Execute
        response = client.post("/api/token?force_refresh=true")
        
        # Assert
        assert response.status_code == 500
        
        # Verify save was called to persist failure
        assert mock_save.called
        saved_data = mock_save.call_args[0][0]
        assert saved_data["last_refresh_status"] == "failed"
        assert error_msg in saved_data["last_refresh_error"]


class TestTokenEndpointParameterPrecedence:
    """Test parameter precedence between query and body."""
    
    @patch('app.routes.token.GitHubTokenRefreshManager.refresh_user_token')
    def test_query_param_takes_precedence_over_body(
        self, mock_refresh, client, mock_firestore_client, test_settings
    ):
        """Test that query parameter takes precedence over request body."""
        from app.dao.firestore_dao import FirestoreDAO
        
        dao = FirestoreDAO(mock_firestore_client, encryption_key=test_settings.github_token_encryption_key)
        
        token = "gho_test_precedence"
        encrypted_token = dao._encrypt_token(token)
        expires_at = datetime.now(timezone.utc) + timedelta(hours=8)
        
        mock_doc = Mock()
        mock_doc.exists = True
        mock_doc.to_dict.return_value = {
            "access_token": encrypted_token,
            "token_type": "bearer",
            "scope": "repo",
            "expires_at": expires_at.isoformat(),
            "refresh_token": None,
            "last_refresh_attempt": None,
            "last_refresh_status": None,
            "last_refresh_error": None,
            "updated_at": datetime.now(timezone.utc).isoformat()
        }
        
        mock_firestore_client.collection.return_value.document.return_value.get = AsyncMock(return_value=mock_doc)
        
        # Execute: query param says false, body says true
        # Query param should win
        response = client.post("/api/token?force_refresh=false", json={"force_refresh": True})
        
        # Assert - no refresh should have been attempted
        assert response.status_code == 200
        mock_refresh.assert_not_called()
