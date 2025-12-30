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
"""Tests for Firestore DAO functionality.

This test suite covers Firestore DAO operations including:
- Document retrieval (happy path and missing documents)
- Document persistence
- Error handling for permissions and API errors
- Integration with FastAPI dependency injection
- Encrypted token storage and retrieval
- Logging mask utilities
"""

import pytest
from unittest.mock import Mock, MagicMock, patch, AsyncMock
from datetime import datetime, timezone, timedelta
from google.api_core import exceptions as gcp_exceptions
from google.cloud import firestore
from fastapi import HTTPException, Depends
from fastapi.testclient import TestClient

from app.dao.firestore_dao import FirestoreDAO
from app.services.firestore import get_firestore_client, reset_firestore_client
from app.dependencies.firestore import get_firestore_dao
from app.config import Settings
from app.main import create_app
from app.utils.logging import mask_sensitive_data


class TestFirestoreDAO:
    """Test suite for FirestoreDAO class."""
    
    @pytest.fixture
    def mock_client(self):
        """Create a mock Firestore async client."""
        return Mock(spec=firestore.AsyncClient)
    
    @pytest.fixture
    def dao(self, mock_client):
        """Create a FirestoreDAO instance with mock client."""
        return FirestoreDAO(mock_client)
    
    @pytest.mark.asyncio
    async def test_get_document_success(self, dao, mock_client):
        """Test successful document retrieval."""
        # Setup mock
        mock_doc = Mock()
        mock_doc.exists = True
        mock_doc.to_dict.return_value = {"name": "test", "value": 123}
        
        mock_doc_ref = Mock()
        mock_doc_ref.get = AsyncMock(return_value=mock_doc)
        
        mock_collection = Mock()
        mock_collection.document.return_value = mock_doc_ref
        
        mock_client.collection.return_value = mock_collection
        
        # Execute
        result = await dao.get_document("test_collection", "test_doc")
        
        # Verify
        assert result == {"name": "test", "value": 123}
        mock_client.collection.assert_called_once_with("test_collection")
        mock_collection.document.assert_called_once_with("test_doc")
        mock_doc_ref.get.assert_called_once()
    
    @pytest.mark.asyncio
    async def test_get_document_not_found(self, dao, mock_client):
        """Test document retrieval when document doesn't exist."""
        # Setup mock
        mock_doc = Mock()
        mock_doc.exists = False
        
        mock_doc_ref = Mock()
        mock_doc_ref.get = AsyncMock(return_value=mock_doc)
        
        mock_collection = Mock()
        mock_collection.document.return_value = mock_doc_ref
        
        mock_client.collection.return_value = mock_collection
        
        # Execute
        result = await dao.get_document("test_collection", "nonexistent_doc")
        
        # Verify
        assert result is None
        mock_client.collection.assert_called_once_with("test_collection")
        mock_collection.document.assert_called_once_with("nonexistent_doc")
    
    @pytest.mark.asyncio
    async def test_get_document_permission_denied(self, dao, mock_client):
        """Test document retrieval with permission denied error."""
        # Setup mock to raise PermissionDenied
        mock_collection = Mock()
        mock_client.collection.return_value = mock_collection
        mock_collection.document.side_effect = gcp_exceptions.PermissionDenied("Access denied")
        
        # Execute and verify
        with pytest.raises(PermissionError) as exc_info:
            await dao.get_document("test_collection", "test_doc")
        
        assert "Permission denied" in str(exc_info.value)
    
    @pytest.mark.asyncio
    async def test_set_document_success(self, dao, mock_client):
        """Test successful document persistence."""
        # Setup mock
        mock_doc_ref = Mock()
        mock_doc_ref.set = AsyncMock()
        mock_collection = Mock()
        mock_collection.document.return_value = mock_doc_ref
        mock_client.collection.return_value = mock_collection
        
        test_data = {"name": "test", "value": 456}
        
        # Execute
        result = await dao.set_document("test_collection", "test_doc", test_data)
        
        # Verify
        assert result == test_data
        mock_client.collection.assert_called_once_with("test_collection")
        mock_collection.document.assert_called_once_with("test_doc")
        mock_doc_ref.set.assert_called_once_with(test_data, merge=False)
    
    @pytest.mark.asyncio
    async def test_set_document_with_merge(self, dao, mock_client):
        """Test document persistence with merge option."""
        # Setup mock
        mock_doc_ref = Mock()
        mock_doc_ref.set = AsyncMock()
        mock_collection = Mock()
        mock_collection.document.return_value = mock_doc_ref
        mock_client.collection.return_value = mock_collection
        
        test_data = {"field": "value"}
        
        # Execute
        result = await dao.set_document("test_collection", "test_doc", test_data, merge=True)
        
        # Verify
        assert result == test_data
        mock_doc_ref.set.assert_called_once_with(test_data, merge=True)
    
    @pytest.mark.asyncio
    async def test_set_document_empty_data(self, dao, mock_client):
        """Test that setting document with empty data raises ValueError."""
        with pytest.raises(ValueError, match="Cannot set document with empty data"):
            await dao.set_document("test_collection", "test_doc", {})
    
    @pytest.mark.asyncio
    async def test_set_document_permission_denied(self, dao, mock_client):
        """Test document persistence with permission denied error."""
        # Setup mock to raise PermissionDenied
        mock_collection = Mock()
        mock_client.collection.return_value = mock_collection
        mock_collection.document.side_effect = gcp_exceptions.PermissionDenied("Access denied")
        
        # Execute and verify
        with pytest.raises(PermissionError) as exc_info:
            await dao.set_document("test_collection", "test_doc", {"data": "test"})
        
        assert "Permission denied" in str(exc_info.value)


class TestFirestoreService:
    """Test suite for Firestore service initialization."""
    
    def setup_method(self):
        """Reset Firestore client before each test."""
        reset_firestore_client()
    
    def teardown_method(self):
        """Reset Firestore client after each test."""
        reset_firestore_client()
    
    def test_get_firestore_client_missing_project_id(self):
        """Test that missing GCP_PROJECT_ID raises ValueError."""
        settings = Settings(_env_file=None, app_env="dev", gcp_project_id=None)
        
        with pytest.raises(ValueError, match="GCP_PROJECT_ID is not configured"):
            get_firestore_client(settings)
    
    @patch('app.services.firestore.firestore.AsyncClient')
    def test_get_firestore_client_success(self, mock_firestore_client):
        """Test successful Firestore client initialization."""
        # Setup
        mock_client_instance = Mock()
        mock_firestore_client.return_value = mock_client_instance
        
        settings = Settings(
            _env_file=None,
            app_env="dev",
            gcp_project_id="test-project"
        )
        
        # Execute
        client = get_firestore_client(settings)
        
        # Verify
        assert client == mock_client_instance
        mock_firestore_client.assert_called_once_with(project="test-project")
    
    @patch('app.services.firestore.firestore.AsyncClient')
    def test_get_firestore_client_caches_instance(self, mock_firestore_client):
        """Test that Firestore client is cached after first initialization."""
        # Setup
        mock_client_instance = Mock()
        mock_firestore_client.return_value = mock_client_instance
        
        settings = Settings(
            _env_file=None,
            app_env="dev",
            gcp_project_id="test-project"
        )
        
        # Execute multiple times
        client1 = get_firestore_client(settings)
        client2 = get_firestore_client(settings)
        
        # Verify client is cached (only initialized once)
        assert client1 == client2
        mock_firestore_client.assert_called_once()
    
    @patch('app.services.firestore.firestore.AsyncClient')
    def test_get_firestore_client_api_error(self, mock_firestore_client):
        """Test handling of Google API errors during initialization."""
        # Setup mock to raise GoogleAPICallError
        mock_firestore_client.side_effect = gcp_exceptions.GoogleAPICallError("API Error")
        
        settings = Settings(
            _env_file=None,
            app_env="dev",
            gcp_project_id="test-project"
        )
        
        # Execute and verify
        with pytest.raises(Exception, match="Failed to initialize Firestore client"):
            get_firestore_client(settings)
    
    @patch('app.services.firestore.firestore.AsyncClient')
    def test_get_firestore_client_thread_safe(self, mock_firestore_client):
        """Test thread-safe initialization with concurrent access."""
        import threading
        
        # Setup
        mock_client_instance = Mock()
        mock_firestore_client.return_value = mock_client_instance
        
        settings = Settings(
            _env_file=None,
            app_env="dev",
            gcp_project_id="test-project"
        )
        
        clients = []
        
        def get_client():
            client = get_firestore_client(settings)
            clients.append(client)
        
        # Execute multiple threads attempting to initialize concurrently
        threads = [threading.Thread(target=get_client) for _ in range(5)]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join()
        
        # Verify all threads got the same client instance (only initialized once)
        assert len(clients) == 5
        assert all(client == clients[0] for client in clients)
        mock_firestore_client.assert_called_once()


class TestFirestoreDependencyInjection:
    """Test suite for Firestore FastAPI dependency injection."""
    
    def setup_method(self):
        """Reset Firestore client before each test."""
        reset_firestore_client()
    
    def teardown_method(self):
        """Reset Firestore client after each test."""
        reset_firestore_client()
    
    @patch('app.services.firestore.firestore.AsyncClient')
    def test_firestore_dao_dependency_success(self, mock_firestore_client):
        """Test successful FirestoreDAO dependency injection."""
        # Setup
        mock_client_instance = Mock()
        mock_firestore_client.return_value = mock_client_instance
        
        settings = Settings(
            _env_file=None,
            app_env="dev",
            gcp_project_id="test-project"
        )
        
        # Execute
        dao = get_firestore_dao(settings)
        
        # Verify
        assert isinstance(dao, FirestoreDAO)
        assert dao.client == mock_client_instance
    
    def test_firestore_dao_dependency_missing_config(self):
        """Test that missing configuration raises HTTPException."""
        settings = Settings(_env_file=None, app_env="dev", gcp_project_id=None)
        
        with pytest.raises(HTTPException) as exc_info:
            get_firestore_dao(settings)
        
        assert exc_info.value.status_code == 503
        assert "configuration error" in exc_info.value.detail.lower()
    
    @patch('app.services.firestore.firestore.AsyncClient')
    def test_firestore_dao_dependency_detailed_error_in_dev(self, mock_firestore_client):
        """Test that detailed errors are exposed in dev environment."""
        # Setup mock to raise an error during initialization
        mock_firestore_client.side_effect = Exception("Detailed error message")
        
        settings = Settings(
            _env_file=None,
            app_env="dev",
            gcp_project_id="test-project"
        )
        
        # Execute and verify
        with pytest.raises(HTTPException) as exc_info:
            get_firestore_dao(settings)
        
        assert exc_info.value.status_code == 503
        # In dev, detailed error should be exposed
        assert "Detailed error message" in exc_info.value.detail
    
    @patch('app.services.firestore.firestore.AsyncClient')
    def test_firestore_dao_dependency_generic_error_in_prod(self, mock_firestore_client):
        """Test that generic errors are shown in production environment."""
        # Setup mock to raise an error during initialization
        mock_firestore_client.side_effect = Exception("Detailed error message")
        
        import secrets
        settings = Settings(
            _env_file=None,
            app_env="prod",
            gcp_project_id="test-project",
            # Add required prod fields to pass validation
            github_app_id="test",
            github_app_private_key_pem="-----BEGIN RSA PRIVATE KEY-----\ntest\n-----END RSA PRIVATE KEY-----",
            github_client_id="test",
            github_client_secret="test",
            github_oauth_redirect_uri="https://example.com/callback",
            github_webhook_secret="test",
            github_token_encryption_key=secrets.token_hex(32)
        )
        
        # Execute and verify
        with pytest.raises(HTTPException) as exc_info:
            get_firestore_dao(settings)
        
        assert exc_info.value.status_code == 503
        # In prod, generic error should be shown
        assert exc_info.value.detail == "Firestore service is temporarily unavailable"
        assert "Detailed error message" not in exc_info.value.detail
    
    @patch('app.services.firestore.firestore.AsyncClient')
    @patch('app.dependencies.firestore.get_firestore_client')
    def test_firestore_dao_in_fastapi_app(self, mock_get_client, mock_firestore_client, monkeypatch):
        """Test Firestore DAO integration in FastAPI application."""
        # Setup mocks
        mock_client_instance = Mock()
        mock_firestore_client.return_value = mock_client_instance
        mock_get_client.return_value = mock_client_instance
        
        # Setup environment
        monkeypatch.setenv("APP_ENV", "dev")
        
        from app import config
        original_settings = config.Settings
        monkeypatch.setattr(
            config, 
            "Settings", 
            lambda **kwargs: original_settings(_env_file=None, **kwargs)
        )
        
        # Create app with test route
        app = create_app()
        
        from fastapi import APIRouter
        from app.dependencies.firestore import get_firestore_dao
        
        test_router = APIRouter()
        
        @test_router.get("/test-firestore")
        async def test_firestore_endpoint(dao: FirestoreDAO = Depends(get_firestore_dao)):
            """Test endpoint that uses Firestore DAO."""
            return {"status": "ok", "has_dao": dao is not None}
        
        app.include_router(test_router)
        
        # Test the endpoint
        client = TestClient(app)
        response = client.get("/test-firestore")
        
        # Verify
        assert response.status_code == 200
        assert response.json()["status"] == "ok"
        assert response.json()["has_dao"] is True


class TestFirestoreEmulatorCompatibility:
    """Test suite for Firestore emulator compatibility."""
    
    def setup_method(self):
        """Reset Firestore client before each test."""
        reset_firestore_client()
    
    def teardown_method(self):
        """Reset Firestore client after each test."""
        reset_firestore_client()
    
    @pytest.mark.integration
    @patch('app.services.firestore.firestore.AsyncClient')
    def test_dao_operations_with_emulator(self, mock_firestore_client):
        """Test that DAO operations work with Firestore emulator.
        
        This test demonstrates how the DAO would work with an emulator.
        In a real integration test, you would set FIRESTORE_EMULATOR_HOST
        environment variable to connect to an actual emulator.
        """
        # Setup mock client
        mock_client_instance = Mock()
        mock_firestore_client.return_value = mock_client_instance
        
        # Setup mock document operations
        mock_doc = Mock()
        mock_doc.exists = True
        mock_doc.to_dict.return_value = {"test": "data"}
        
        mock_doc_ref = Mock()
        mock_doc_ref.get = AsyncMock(return_value=mock_doc)
        
        mock_collection = Mock()
        mock_collection.document.return_value = mock_doc_ref
        mock_client_instance.collection.return_value = mock_collection
        
        settings = Settings(
            _env_file=None,
            app_env="dev",
            gcp_project_id="test-project"
        )
        
        # Get client and create DAO
        client = get_firestore_client(settings)
        dao = FirestoreDAO(client)
        
        # Verify we can perform operations
        assert client is not None
        assert dao is not None


class TestLoggingUtilities:
    """Test suite for logging utility functions."""
    
    def test_mask_sensitive_data_default(self):
        """Test mask_sensitive_data with default visible chars."""
        result = mask_sensitive_data("secret_token_12345")
        assert result == "secr**************"
        assert len(result) == len("secret_token_12345")
    
    def test_mask_sensitive_data_custom_visible(self):
        """Test mask_sensitive_data with custom visible chars."""
        result = mask_sensitive_data("secret_token_12345", visible_chars=6)
        assert result == "secret************"
    
    def test_mask_sensitive_data_short_string(self):
        """Test mask_sensitive_data with string shorter than visible chars."""
        result = mask_sensitive_data("abc", visible_chars=4)
        assert result == "abc"
    
    def test_mask_sensitive_data_empty_string(self):
        """Test mask_sensitive_data with empty string."""
        result = mask_sensitive_data("")
        assert result == "****"
    
    def test_mask_sensitive_data_exact_length(self):
        """Test mask_sensitive_data with exact visible length."""
        result = mask_sensitive_data("test", visible_chars=4)
        assert result == "test"


class TestEncryptionDecryption:
    """Test suite for encryption and decryption methods."""
    
    @pytest.fixture
    def encryption_key(self):
        """Generate a valid 32-byte hex encryption key."""
        import secrets
        return secrets.token_hex(32)
    
    @pytest.fixture
    def mock_client(self):
        """Create a mock Firestore async client."""
        return Mock(spec=firestore.AsyncClient)
    
    @pytest.fixture
    def dao_with_encryption(self, mock_client, encryption_key):
        """Create a FirestoreDAO instance with encryption enabled."""
        return FirestoreDAO(mock_client, encryption_key=encryption_key)
    
    @pytest.fixture
    def dao_without_encryption(self, mock_client):
        """Create a FirestoreDAO instance without encryption."""
        return FirestoreDAO(mock_client, encryption_key=None)
    
    def test_dao_initialization_with_valid_key(self, mock_client, encryption_key):
        """Test DAO initializes with valid encryption key."""
        dao = FirestoreDAO(mock_client, encryption_key=encryption_key)
        assert dao._encryption_key_bytes is not None
        assert len(dao._encryption_key_bytes) == 32
    
    def test_dao_initialization_with_invalid_key_format(self, mock_client):
        """Test DAO raises error with invalid hex format."""
        with pytest.raises(ValueError, match="Invalid encryption key format"):
            FirestoreDAO(mock_client, encryption_key="not_hex")
    
    def test_dao_initialization_with_wrong_length_key(self, mock_client):
        """Test DAO raises error with wrong key length."""
        short_key = "a" * 32  # 16 bytes, not 32
        with pytest.raises(ValueError, match="must be 32 bytes"):
            FirestoreDAO(mock_client, encryption_key=short_key)
    
    def test_dao_initialization_without_key(self, mock_client):
        """Test DAO initializes without encryption key."""
        dao = FirestoreDAO(mock_client, encryption_key=None)
        assert dao._encryption_key_bytes is None
    
    def test_encrypt_decrypt_roundtrip(self, dao_with_encryption):
        """Test encryption and decryption round-trip."""
        original_token = "ghs_1234567890abcdefghijklmnopqrstuvwxyz"
        
        # Encrypt
        encrypted = dao_with_encryption._encrypt_token(original_token)
        assert encrypted != original_token
        assert len(encrypted) > 0
        
        # Decrypt
        decrypted = dao_with_encryption._decrypt_token(encrypted)
        assert decrypted == original_token
    
    def test_encrypt_produces_different_ciphertext(self, dao_with_encryption):
        """Test that encrypting same token twice produces different ciphertext."""
        token = "ghs_test_token"
        
        encrypted1 = dao_with_encryption._encrypt_token(token)
        encrypted2 = dao_with_encryption._encrypt_token(token)
        
        # Different IVs should produce different ciphertext
        assert encrypted1 != encrypted2
        
        # But both should decrypt to the same value
        assert dao_with_encryption._decrypt_token(encrypted1) == token
        assert dao_with_encryption._decrypt_token(encrypted2) == token
    
    def test_encrypt_without_key_raises_error(self, dao_without_encryption):
        """Test encryption fails without encryption key."""
        with pytest.raises(ValueError, match="Encryption key not configured"):
            dao_without_encryption._encrypt_token("test_token")
    
    def test_decrypt_without_key_raises_error(self, dao_without_encryption):
        """Test decryption fails without encryption key."""
        with pytest.raises(ValueError, match="Encryption key not configured"):
            dao_without_encryption._decrypt_token("fake_encrypted_data")
    
    def test_decrypt_invalid_data_raises_error(self, dao_with_encryption):
        """Test decryption fails with invalid encrypted data."""
        with pytest.raises(ValueError, match="Failed to decrypt"):
            dao_with_encryption._decrypt_token("not_valid_base64_encrypted_data!")
    
    def test_encrypt_empty_token(self, dao_with_encryption):
        """Test encryption handles empty token."""
        encrypted = dao_with_encryption._encrypt_token("")
        decrypted = dao_with_encryption._decrypt_token(encrypted)
        assert decrypted == ""
    
    def test_encrypt_unicode_token(self, dao_with_encryption):
        """Test encryption handles unicode characters."""
        token = "test_token_with_unicode_😀_chars"
        encrypted = dao_with_encryption._encrypt_token(token)
        decrypted = dao_with_encryption._decrypt_token(encrypted)
        assert decrypted == token


class TestGitHubTokenStorage:
    """Test suite for GitHub token storage methods."""
    
    @pytest.fixture
    def encryption_key(self):
        """Generate a valid 32-byte hex encryption key."""
        import secrets
        return secrets.token_hex(32)
    
    @pytest.fixture
    def mock_client(self):
        """Create a mock Firestore async client."""
        return Mock(spec=firestore.AsyncClient)
    
    @pytest.fixture
    def dao(self, mock_client, encryption_key):
        """Create a FirestoreDAO instance with encryption."""
        return FirestoreDAO(mock_client, encryption_key=encryption_key)
    
    @pytest.mark.asyncio
    async def test_save_github_token_success(self, dao, mock_client):
        """Test saving GitHub token with encryption."""
        # Setup mock
        mock_doc_ref = Mock()
        mock_doc_ref.set = AsyncMock()
        mock_collection = Mock()
        mock_collection.document.return_value = mock_doc_ref
        mock_client.collection.return_value = mock_collection
        
        access_token = "ghs_test_access_token_12345"
        expires_at = datetime.now(timezone.utc) + timedelta(hours=8)
        
        # Execute
        result = await dao.save_github_token(
            collection="github_tokens",
            doc_id="primary_user",
            access_token=access_token,
            token_type="bearer",
            scope="repo,user",
            expires_at=expires_at,
            refresh_token="ghr_refresh_token_xyz"
        )
        
        # Verify
        assert result["token_type"] == "bearer"
        assert result["scope"] == "repo,user"
        assert result["has_refresh_token"] is True
        assert "updated_at" in result
        assert "access_token" not in result  # Should not return decrypted token
        
        # Verify Firestore was called
        mock_doc_ref.set.assert_called_once()
        call_args = mock_doc_ref.set.call_args[0][0]
        
        # Verify token is encrypted (not equal to original)
        assert call_args["access_token"] != access_token
        assert call_args["refresh_token"] != "ghr_refresh_token_xyz"
        
        # Verify other fields
        assert call_args["token_type"] == "bearer"
        assert call_args["scope"] == "repo,user"
        assert call_args["expires_at"] == expires_at.isoformat()
    
    @pytest.mark.asyncio
    async def test_save_github_token_without_optional_fields(self, dao, mock_client):
        """Test saving GitHub token with minimal required fields."""
        # Setup mock
        mock_doc_ref = Mock()
        mock_doc_ref.set = AsyncMock()
        mock_collection = Mock()
        mock_collection.document.return_value = mock_doc_ref
        mock_client.collection.return_value = mock_collection
        
        # Execute with only required fields
        result = await dao.save_github_token(
            collection="github_tokens",
            doc_id="primary_user",
            access_token="ghs_test_token"
        )
        
        # Verify
        assert result["token_type"] == "bearer"
        assert result["scope"] is None
        assert result["has_refresh_token"] is False
        assert "updated_at" in result
        
        # Verify Firestore call
        call_args = mock_doc_ref.set.call_args[0][0]
        assert call_args["refresh_token"] is None
        assert call_args["expires_at"] is None
    
    @pytest.mark.asyncio
    async def test_save_github_token_empty_access_token_raises_error(self, dao, mock_client):
        """Test saving with empty access token raises ValueError."""
        with pytest.raises(ValueError, match="access_token is required"):
            await dao.save_github_token(
                collection="github_tokens",
                doc_id="primary_user",
                access_token=""
            )
    
    @pytest.mark.asyncio
    async def test_get_github_token_with_decryption(self, dao, mock_client):
        """Test retrieving and decrypting GitHub token."""
        # Setup: First encrypt a token
        access_token = "ghs_test_access_token"
        refresh_token = "ghr_test_refresh_token"
        encrypted_access = dao._encrypt_token(access_token)
        encrypted_refresh = dao._encrypt_token(refresh_token)
        
        # Setup mock to return encrypted data
        mock_doc = Mock()
        mock_doc.exists = True
        mock_doc.to_dict.return_value = {
            "access_token": encrypted_access,
            "token_type": "bearer",
            "scope": "repo",
            "expires_at": "2025-12-31T23:59:59+00:00",
            "refresh_token": encrypted_refresh,
            "updated_at": "2025-12-30T12:00:00+00:00"
        }
        
        mock_doc_ref = Mock()
        mock_doc_ref.get = AsyncMock(return_value=mock_doc)
        mock_collection = Mock()
        mock_collection.document.return_value = mock_doc_ref
        mock_client.collection.return_value = mock_collection
        
        # Execute
        result = await dao.get_github_token(
            collection="github_tokens",
            doc_id="primary_user",
            decrypt=True
        )
        
        # Verify
        assert result is not None
        assert result["access_token"] == access_token  # Decrypted
        assert result["refresh_token"] == refresh_token  # Decrypted
        assert result["token_type"] == "bearer"
        assert result["scope"] == "repo"
    
    @pytest.mark.asyncio
    async def test_get_github_token_without_decryption(self, dao, mock_client):
        """Test retrieving GitHub token without decryption."""
        encrypted_token = "encrypted_data_base64"
        
        # Setup mock
        mock_doc = Mock()
        mock_doc.exists = True
        mock_doc.to_dict.return_value = {
            "access_token": encrypted_token,
            "token_type": "bearer",
            "scope": "repo",
            "expires_at": None,
            "refresh_token": None,
            "updated_at": "2025-12-30T12:00:00+00:00"
        }
        
        mock_doc_ref = Mock()
        mock_doc_ref.get = AsyncMock(return_value=mock_doc)
        mock_collection = Mock()
        mock_collection.document.return_value = mock_doc_ref
        mock_client.collection.return_value = mock_collection
        
        # Execute
        result = await dao.get_github_token(
            collection="github_tokens",
            doc_id="primary_user",
            decrypt=False
        )
        
        # Verify token is still encrypted
        assert result["access_token"] == encrypted_token
    
    @pytest.mark.asyncio
    async def test_get_github_token_not_found(self, dao, mock_client):
        """Test retrieving non-existent token returns None."""
        # Setup mock for non-existent document
        mock_doc = Mock()
        mock_doc.exists = False
        
        mock_doc_ref = Mock()
        mock_doc_ref.get = AsyncMock(return_value=mock_doc)
        mock_collection = Mock()
        mock_collection.document.return_value = mock_doc_ref
        mock_client.collection.return_value = mock_collection
        
        # Execute
        result = await dao.get_github_token(
            collection="github_tokens",
            doc_id="nonexistent",
            decrypt=True
        )
        
        # Verify
        assert result is None
    
    @pytest.mark.asyncio
    async def test_get_github_token_metadata(self, dao, mock_client):
        """Test retrieving token metadata without decryption."""
        encrypted_token = "encrypted_data"
        
        # Setup mock
        mock_doc = Mock()
        mock_doc.exists = True
        mock_doc.to_dict.return_value = {
            "access_token": encrypted_token,
            "token_type": "bearer",
            "scope": "repo,user",
            "expires_at": "2025-12-31T23:59:59+00:00",
            "refresh_token": "encrypted_refresh",
            "updated_at": "2025-12-30T12:00:00+00:00"
        }
        
        mock_doc_ref = Mock()
        mock_doc_ref.get = AsyncMock(return_value=mock_doc)
        mock_collection = Mock()
        mock_collection.document.return_value = mock_doc_ref
        mock_client.collection.return_value = mock_collection
        
        # Execute
        result = await dao.get_github_token_metadata(
            collection="github_tokens",
            doc_id="primary_user"
        )
        
        # Verify metadata only (no tokens)
        assert result is not None
        assert "access_token" not in result
        assert "refresh_token" not in result
        assert result["token_type"] == "bearer"
        assert result["scope"] == "repo,user"
        assert result["expires_at"] == "2025-12-31T23:59:59+00:00"
        assert result["has_refresh_token"] is True
        assert result["updated_at"] == "2025-12-30T12:00:00+00:00"
    
    @pytest.mark.asyncio
    async def test_get_github_token_metadata_not_found(self, dao, mock_client):
        """Test metadata retrieval for non-existent token returns None."""
        # Setup mock for non-existent document
        mock_doc = Mock()
        mock_doc.exists = False
        
        mock_doc_ref = Mock()
        mock_doc_ref.get = AsyncMock(return_value=mock_doc)
        mock_collection = Mock()
        mock_collection.document.return_value = mock_doc_ref
        mock_client.collection.return_value = mock_collection
        
        # Execute
        result = await dao.get_github_token_metadata(
            collection="github_tokens",
            doc_id="nonexistent"
        )
        
        # Verify
        assert result is None
    
    @pytest.mark.asyncio
    async def test_save_token_firestore_permission_denied(self, dao, mock_client):
        """Test token save handles Firestore permission errors."""
        # Setup mock to raise PermissionDenied
        mock_collection = Mock()
        mock_client.collection.return_value = mock_collection
        mock_collection.document.side_effect = gcp_exceptions.PermissionDenied("Access denied")
        
        # Execute and verify
        with pytest.raises(PermissionError, match="Permission denied"):
            await dao.save_github_token(
                collection="github_tokens",
                doc_id="primary_user",
                access_token="test_token"
            )
    
    @pytest.mark.asyncio
    async def test_concurrent_token_writes_last_write_wins(self, dao, mock_client):
        """Test that concurrent writes don't corrupt ciphertext (last write wins)."""
        # Setup mock
        mock_doc_ref = Mock()
        mock_doc_ref.set = AsyncMock()
        mock_collection = Mock()
        mock_collection.document.return_value = mock_doc_ref
        mock_client.collection.return_value = mock_collection
        
        # Simulate two concurrent writes
        token1 = "ghs_token_first"
        token2 = "ghs_token_second"
        
        await dao.save_github_token(
            collection="github_tokens",
            doc_id="primary_user",
            access_token=token1
        )
        
        await dao.save_github_token(
            collection="github_tokens",
            doc_id="primary_user",
            access_token=token2
        )
        
        # Verify both writes succeeded independently
        assert mock_doc_ref.set.call_count == 2
        
        # Verify each write had different encrypted data
        call1_data = mock_doc_ref.set.call_args_list[0][0][0]
        call2_data = mock_doc_ref.set.call_args_list[1][0][0]
        
        # Encrypted tokens should be different
        assert call1_data["access_token"] != call2_data["access_token"]


class TestConfigValidation:
    """Test suite for configuration validation of encryption key."""
    
    def test_valid_encryption_key(self):
        """Test configuration with valid encryption key."""
        import secrets
        valid_key = secrets.token_hex(32)
        
        settings = Settings(
            _env_file=None,
            app_env="dev",
            github_token_encryption_key=valid_key
        )
        
        assert settings.github_token_encryption_key == valid_key
    
    def test_invalid_encryption_key_format(self):
        """Test configuration fails with invalid hex format."""
        with pytest.raises(ValueError, match="valid hexadecimal string"):
            Settings(
                _env_file=None,
                app_env="dev",
                github_token_encryption_key="not_valid_hex!"
            )
    
    def test_invalid_encryption_key_length(self):
        """Test configuration fails with wrong key length."""
        short_key = "a" * 32  # 16 bytes, not 32
        
        with pytest.raises(ValueError, match="exactly 64 hex characters"):
            Settings(
                _env_file=None,
                app_env="dev",
                github_token_encryption_key=short_key
            )
    
    def test_production_requires_encryption_key(self):
        """Test production environment requires encryption key."""
        with pytest.raises(ValueError, match="GITHUB_TOKEN_ENCRYPTION_KEY"):
            Settings(
                _env_file=None,
                app_env="prod",
                gcp_project_id="test-project",
                github_app_id="123456",
                github_app_private_key_pem="-----BEGIN RSA PRIVATE KEY-----\ntest\n-----END RSA PRIVATE KEY-----",
                github_client_id="Iv1.test",
                github_client_secret="secret",
                github_oauth_redirect_uri="https://example.com/callback",
                # Missing github_token_encryption_key
            )
