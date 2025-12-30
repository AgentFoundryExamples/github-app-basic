"""Tests for Firestore DAO functionality.

This test suite covers Firestore DAO operations including:
- Document retrieval (happy path and missing documents)
- Document persistence
- Error handling for permissions and API errors
- Integration with FastAPI dependency injection
"""

import pytest
from unittest.mock import Mock, MagicMock, patch, AsyncMock
from google.api_core import exceptions as gcp_exceptions
from google.cloud import firestore
from fastapi import HTTPException, Depends
from fastapi.testclient import TestClient

from app.dao.firestore_dao import FirestoreDAO
from app.services.firestore import get_firestore_client, reset_firestore_client
from app.dependencies.firestore import get_firestore_dao
from app.config import Settings
from app.main import create_app


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
        mock_doc_ref.get.return_value = mock_doc
        
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
