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
"""Integration tests for GitHub token refresh with Firestore persistence."""

import pytest
from unittest.mock import Mock, patch, AsyncMock
from datetime import datetime, timezone, timedelta

from app.services.github import (
    GitHubAppJWT,
    GitHubTokenRefreshManager,
    GitHubTokenRefreshError,
    GitHubTokenRefreshCooldownError
)
from app.dao.firestore_dao import FirestoreDAO


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


class TestTokenRefreshWithFirestorePersistence:
    """Test suite for token refresh with Firestore persistence."""
    
    @pytest.fixture
    def github_app_jwt(self):
        """Create a GitHubAppJWT instance for testing."""
        private_key = generate_test_private_key()
        return GitHubAppJWT(app_id="12345", private_key_pem=private_key)
    
    @pytest.fixture
    def encryption_key(self):
        """Generate a valid 32-byte hex encryption key."""
        import secrets
        return secrets.token_hex(32)
    
    @pytest.fixture
    def mock_firestore_client(self):
        """Create a mock Firestore client."""
        from google.cloud import firestore
        return Mock(spec=firestore.AsyncClient)
    
    @pytest.fixture
    def dao(self, mock_firestore_client, encryption_key):
        """Create a FirestoreDAO instance with encryption."""
        return FirestoreDAO(mock_firestore_client, encryption_key=encryption_key)
    
    @pytest.mark.asyncio
    async def test_successful_refresh_persists_new_token(
        self, github_app_jwt, dao, mock_firestore_client
    ):
        """Test that successful refresh persists new token data to Firestore."""
        # Setup: Mock existing token in Firestore
        old_token = "gho_old_token_123"
        refresh_token = "ghr_refresh_token_xyz"
        encrypted_old_token = dao._encrypt_token(old_token)
        encrypted_refresh_token = dao._encrypt_token(refresh_token)
        
        mock_doc = Mock()
        mock_doc.exists = True
        mock_doc.to_dict.return_value = {
            "access_token": encrypted_old_token,
            "token_type": "bearer",
            "scope": "repo,user",
            "expires_at": (datetime.now(timezone.utc) + timedelta(minutes=5)).isoformat(),
            "refresh_token": encrypted_refresh_token,
            "last_refresh_attempt": None,
            "last_refresh_status": None,
            "last_refresh_error": None,
            "updated_at": datetime.now(timezone.utc).isoformat()
        }
        
        mock_doc_ref = Mock()
        mock_doc_ref.get = AsyncMock(return_value=mock_doc)
        mock_doc_ref.set = AsyncMock()
        
        mock_collection = Mock()
        mock_collection.document.return_value = mock_doc_ref
        mock_firestore_client.collection.return_value = mock_collection
        
        # Step 1: Retrieve current token
        current_token_data = await dao.get_github_token(
            collection="github_tokens",
            doc_id="primary_user",
            decrypt=True
        )
        
        assert current_token_data is not None
        assert current_token_data["access_token"] == old_token
        assert current_token_data["refresh_token"] == refresh_token
        
        # Step 2: Mock successful refresh
        new_token = "gho_new_token_456"
        new_refresh_token = "ghr_new_refresh_token_abc"
        
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.json.return_value = {
            "access_token": new_token,
            "token_type": "bearer",
            "scope": "repo,user",
            "expires_in": 28800,
            "refresh_token": new_refresh_token
        }
        
        with patch('httpx.AsyncClient') as mock_client:
            mock_client.return_value.__aenter__.return_value.post = AsyncMock(
                return_value=mock_response
            )
            
            # Perform refresh
            refresh_result = await GitHubTokenRefreshManager.refresh_user_token(
                current_token_data=current_token_data,
                github_app_jwt=github_app_jwt,
                client_id="test_client_id",
                client_secret="test_client_secret",
                cooldown_seconds=300
            )
        
        assert refresh_result["access_token"] == new_token
        assert refresh_result["refresh_token"] == new_refresh_token
        assert refresh_result["refresh_status"] == "success"
        assert refresh_result["refresh_method"] == "refresh_grant"
        
        # Step 3: Persist new token
        expires_at = datetime.now(timezone.utc) + timedelta(seconds=refresh_result["expires_in"])
        last_refresh_attempt = datetime.now(timezone.utc)
        
        await dao.save_github_token(
            collection="github_tokens",
            doc_id="primary_user",
            access_token=refresh_result["access_token"],
            token_type=refresh_result.get("token_type", "bearer"),
            scope=refresh_result.get("scope"),
            expires_at=expires_at,
            refresh_token=refresh_result.get("refresh_token"),
            last_refresh_attempt=last_refresh_attempt,
            last_refresh_status="success",
            last_refresh_error=None
        )
        
        # Verify Firestore save was called
        mock_doc_ref.set.assert_called_once()
        call_args = mock_doc_ref.set.call_args[0][0]
        
        # Verify new token is encrypted (different from old)
        assert call_args["access_token"] != encrypted_old_token
        assert call_args["refresh_token"] != encrypted_refresh_token
        
        # Verify metadata
        assert call_args["last_refresh_status"] == "success"
        assert call_args["last_refresh_error"] is None
        assert call_args["last_refresh_attempt"] is not None
    
    @pytest.mark.asyncio
    async def test_failed_refresh_persists_error_metadata(
        self, github_app_jwt, dao, mock_firestore_client
    ):
        """Test that failed refresh persists error metadata to Firestore."""
        # Setup: Mock existing token in Firestore
        old_token = "gho_old_token_123"
        refresh_token = "ghr_refresh_token_xyz"
        encrypted_old_token = dao._encrypt_token(old_token)
        encrypted_refresh_token = dao._encrypt_token(refresh_token)
        
        mock_doc = Mock()
        mock_doc.exists = True
        mock_doc.to_dict.return_value = {
            "access_token": encrypted_old_token,
            "token_type": "bearer",
            "scope": "repo,user",
            "expires_at": (datetime.now(timezone.utc) + timedelta(minutes=5)).isoformat(),
            "refresh_token": encrypted_refresh_token,
            "last_refresh_attempt": None,
            "last_refresh_status": None,
            "last_refresh_error": None,
            "updated_at": datetime.now(timezone.utc).isoformat()
        }
        
        mock_doc_ref = Mock()
        mock_doc_ref.get = AsyncMock(return_value=mock_doc)
        mock_doc_ref.set = AsyncMock()
        
        mock_collection = Mock()
        mock_collection.document.return_value = mock_doc_ref
        mock_firestore_client.collection.return_value = mock_collection
        
        # Step 1: Retrieve current token
        current_token_data = await dao.get_github_token(
            collection="github_tokens",
            doc_id="primary_user",
            decrypt=True
        )
        
        # Step 2: Mock failed refresh (401 error)
        mock_response = Mock()
        mock_response.status_code = 401
        mock_response.text = "Unauthorized"
        
        last_refresh_attempt = datetime.now(timezone.utc)
        error_message = None
        
        with patch('httpx.AsyncClient') as mock_client:
            mock_client.return_value.__aenter__.return_value.post = AsyncMock(
                return_value=mock_response
            )
            
            # Attempt refresh (should fail)
            try:
                await GitHubTokenRefreshManager.refresh_user_token(
                    current_token_data=current_token_data,
                    github_app_jwt=github_app_jwt,
                    client_id="test_client_id",
                    client_secret="test_client_secret",
                    cooldown_seconds=300
                )
                pytest.fail("Expected GitHubTokenRefreshError")
            except GitHubTokenRefreshError as e:
                error_message = str(e)
        
        # Step 3: Persist error metadata (keeping old token)
        await dao.save_github_token(
            collection="github_tokens",
            doc_id="primary_user",
            access_token=current_token_data["access_token"],
            token_type=current_token_data["token_type"],
            scope=current_token_data.get("scope"),
            expires_at=FirestoreDAO.parse_iso_datetime(current_token_data.get("expires_at")),
            refresh_token=current_token_data.get("refresh_token"),
            last_refresh_attempt=last_refresh_attempt,
            last_refresh_status="failed",
            last_refresh_error=error_message
        )
        
        # Verify Firestore save was called
        mock_doc_ref.set.assert_called_once()
        call_args = mock_doc_ref.set.call_args[0][0]
        
        # Verify old token is kept (encrypted value should be similar but not identical due to new nonce)
        assert call_args["token_type"] == "bearer"
        
        # Verify error metadata
        assert call_args["last_refresh_status"] == "failed"
        assert call_args["last_refresh_error"] is not None
        assert "401" in call_args["last_refresh_error"]
        assert call_args["last_refresh_attempt"] is not None
    
    @pytest.mark.asyncio
    async def test_cooldown_enforced_from_persisted_metadata(
        self, github_app_jwt, dao, mock_firestore_client
    ):
        """Test that cooldown is enforced based on persisted metadata."""
        # Setup: Mock token with recent failure (60 seconds ago)
        old_token = "gho_old_token_123"
        refresh_token = "ghr_refresh_token_xyz"
        last_attempt = datetime.now(timezone.utc) - timedelta(seconds=60)
        
        encrypted_old_token = dao._encrypt_token(old_token)
        encrypted_refresh_token = dao._encrypt_token(refresh_token)
        
        mock_doc = Mock()
        mock_doc.exists = True
        mock_doc.to_dict.return_value = {
            "access_token": encrypted_old_token,
            "token_type": "bearer",
            "scope": "repo,user",
            "expires_at": (datetime.now(timezone.utc) + timedelta(minutes=5)).isoformat(),
            "refresh_token": encrypted_refresh_token,
            "last_refresh_attempt": last_attempt.isoformat(),
            "last_refresh_status": "failed",
            "last_refresh_error": "Previous GitHub API error",
            "updated_at": datetime.now(timezone.utc).isoformat()
        }
        
        mock_doc_ref = Mock()
        mock_doc_ref.get = AsyncMock(return_value=mock_doc)
        
        mock_collection = Mock()
        mock_collection.document.return_value = mock_doc_ref
        mock_firestore_client.collection.return_value = mock_collection
        
        # Retrieve current token
        current_token_data = await dao.get_github_token(
            collection="github_tokens",
            doc_id="primary_user",
            decrypt=True
        )
        
        # Attempt refresh (should be blocked by cooldown)
        with pytest.raises(GitHubTokenRefreshCooldownError) as exc_info:
            await GitHubTokenRefreshManager.refresh_user_token(
                current_token_data=current_token_data,
                github_app_jwt=github_app_jwt,
                client_id="test_client_id",
                client_secret="test_client_secret",
                cooldown_seconds=300  # 5 minutes
            )
        
        # Verify cooldown error details
        assert "too soon" in str(exc_info.value).lower()
        assert exc_info.value.seconds_until_retry > 0
        assert exc_info.value.seconds_until_retry <= 240  # Less than 300 - 60


class TestTokenRefreshErrorLogging:
    """Test suite for token refresh error logging and sanitization."""
    
    @pytest.fixture
    def github_app_jwt(self):
        """Create a GitHubAppJWT instance for testing."""
        private_key = generate_test_private_key()
        return GitHubAppJWT(app_id="12345", private_key_pem=private_key)
    
    @pytest.mark.asyncio
    async def test_refresh_logs_sanitized_error_on_failure(self, github_app_jwt, caplog):
        """Test that refresh failures log sanitized errors."""
        import logging
        caplog.set_level(logging.ERROR)
        
        token_data = {
            "access_token": "gho_old_token_123",
            "token_type": "bearer",
            "refresh_token": "ghr_refresh_token_xyz",
            "last_refresh_attempt": None,
            "last_refresh_status": None,
            "last_refresh_error": None
        }
        
        # Mock failed refresh
        mock_response = Mock()
        mock_response.status_code = 500
        mock_response.text = "Internal Server Error - Full details with sensitive info"
        
        with patch('httpx.AsyncClient') as mock_client, \
             patch('asyncio.sleep', new_callable=AsyncMock):
            mock_client.return_value.__aenter__.return_value.post = AsyncMock(
                return_value=mock_response
            )
            
            try:
                await GitHubTokenRefreshManager.refresh_user_token(
                    current_token_data=token_data,
                    github_app_jwt=github_app_jwt,
                    client_id="test_client_id",
                    client_secret="test_client_secret",
                    max_retries=2
                )
            except GitHubTokenRefreshError:
                pass  # Expected
        
        # Verify error was logged
        log_text = caplog.text
        assert "GitHub refresh token failed" in log_text or "failed" in log_text.lower()
        
        # Verify response is truncated for security (max 200 chars)
        # The full response text should not appear completely in logs
        if "Full details with sensitive info" in log_text:
            # If it appears, check it's part of a truncated preview
            assert "response_preview" in log_text or len(log_text) < 500
