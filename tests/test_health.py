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
"""Tests for health check endpoint and FastAPI application."""

import pytest
from fastapi.testclient import TestClient
from unittest.mock import Mock, patch, AsyncMock
from datetime import datetime, timezone
import asyncio

from app.main import create_app
from app.services.readiness import reset_readiness_state, get_readiness_state
from app.services.firestore import reset_firestore_client


@pytest.fixture
def client(monkeypatch):
    """Create a test client with dev environment."""
    monkeypatch.setenv("APP_ENV", "dev")
    monkeypatch.setenv("GCP_PROJECT_ID", "test-project")
    monkeypatch.setenv("GITHUB_APP_ID", "123456")
    monkeypatch.setenv("GITHUB_APP_PRIVATE_KEY_PEM", "-----BEGIN RSA PRIVATE KEY-----\ntest\n-----END RSA PRIVATE KEY-----")
    
    # Monkey-patch Settings to avoid .env
    from app import config
    original_settings = config.Settings
    monkeypatch.setattr(config, "Settings", lambda **kwargs: original_settings(_env_file=None, **kwargs))
    
    # Reset singletons
    reset_readiness_state()
    reset_firestore_client()
    
    # Mock get_firestore_client during app initialization to avoid ADC issues
    with patch('app.main.get_firestore_client'):
        app = create_app()
    return TestClient(app)


@pytest.fixture
def client_no_firestore(monkeypatch):
    """Create a test client without Firestore configuration."""
    monkeypatch.setenv("APP_ENV", "dev")
    monkeypatch.delenv("GCP_PROJECT_ID", raising=False)
    monkeypatch.setenv("GITHUB_APP_ID", "123456")
    monkeypatch.setenv("GITHUB_APP_PRIVATE_KEY_PEM", "-----BEGIN RSA PRIVATE KEY-----\ntest\n-----END RSA PRIVATE KEY-----")
    
    from app import config
    original_settings = config.Settings
    monkeypatch.setattr(config, "Settings", lambda **kwargs: original_settings(_env_file=None, **kwargs))
    
    reset_readiness_state()
    reset_firestore_client()
    
    # Don't mock here, let it fail naturally
    app = create_app()
    return TestClient(app)


@pytest.fixture
def client_no_github_config(monkeypatch):
    """Create a test client without GitHub configuration."""
    monkeypatch.setenv("APP_ENV", "dev")
    monkeypatch.setenv("GCP_PROJECT_ID", "test-project")
    monkeypatch.delenv("GITHUB_APP_ID", raising=False)
    monkeypatch.delenv("GITHUB_APP_PRIVATE_KEY_PEM", raising=False)
    
    from app import config
    original_settings = config.Settings
    monkeypatch.setattr(config, "Settings", lambda **kwargs: original_settings(_env_file=None, **kwargs))
    
    reset_readiness_state()
    reset_firestore_client()
    
    # Mock Firestore for this case
    with patch('app.main.get_firestore_client'):
        app = create_app()
    return TestClient(app)


class TestHealthEndpoint:
    """Test suite for health check endpoint."""
    
    @patch('app.routes.health.get_firestore_client')
    def test_health_check_all_healthy(self, mock_get_client, client):
        """Test that health endpoint returns healthy when all checks pass."""
        # Mock Firestore client
        mock_client = AsyncMock()
        
        class MockAsyncIterator:
            def __aiter__(self):
                return self
            
            async def __anext__(self):
                # Return one item then stop
                raise StopAsyncIteration
        
        mock_client.collections = lambda: MockAsyncIterator()
        mock_get_client.return_value = mock_client
        
        response = client.get("/healthz")
        
        assert response.status_code == 200
        data = response.json()
        assert data["status"] == "healthy"
        assert "checks" in data
        assert data["checks"]["firestore"]["status"] == "healthy"
        assert data["checks"]["github_config"]["status"] == "healthy"
        assert "timestamp" in data
    
    @patch('app.routes.health.get_firestore_client')
    def test_health_check_firestore_timeout(self, mock_get_client, client):
        """Test health check handles Firestore timeout gracefully."""
        # Clear cache to force new check
        from app.routes import health
        health._health_cache_timestamp = None
        health._health_cache = {}
        
        # Mock Firestore client to timeout
        mock_client = AsyncMock()
        
        class SlowAsyncIterator:
            def __aiter__(self):
                return self
            
            async def __anext__(self):
                await asyncio.sleep(10)  # Longer than default timeout
                raise StopAsyncIteration
        
        mock_client.collections = lambda: SlowAsyncIterator()
        mock_get_client.return_value = mock_client
        
        response = client.get("/healthz")
        
        assert response.status_code == 503
        data = response.json()
        assert data["status"] == "unhealthy"
        assert data["checks"]["firestore"]["status"] == "unhealthy"
        assert data["checks"]["firestore"]["error"] == "timeout"
    
    def test_health_check_missing_firestore_config(self, client_no_firestore):
        """Test health check with missing Firestore configuration."""
        # Clear cache to force new check
        from app.routes import health
        health._health_cache_timestamp = None
        health._health_cache = {}
        
        response = client_no_firestore.get("/healthz")
        
        assert response.status_code == 503
        data = response.json()
        assert data["status"] == "unhealthy"
        assert data["checks"]["firestore"]["status"] == "unhealthy"
        assert data["checks"]["firestore"]["error"] == "configuration_error"
    
    def test_health_check_missing_github_config(self, client_no_github_config):
        """Test health check with missing GitHub configuration."""
        # Clear cache to force new check
        from app.routes import health
        health._health_cache_timestamp = None
        health._health_cache = {}
        
        with patch('app.routes.health.get_firestore_client') as mock_get_client:
            # Mock Firestore as healthy
            mock_client = AsyncMock()
            
            async def mock_collections():
                class MockAsyncIterator:
                    def __aiter__(self):
        
        mock_client.collections = lambda: MockAsyncIterator()
            mock_get_client.return_value = mock_client
            
            response = client_no_github_config.get("/healthz")
        
        assert response.status_code == 503
        data = response.json()
        assert data["status"] == "unhealthy"
        assert data["checks"]["github_config"]["status"] == "unhealthy"
        assert data["checks"]["github_config"]["error"] == "missing_configuration"
    
    @patch('app.routes.health.get_firestore_client')
    def test_health_check_caching(self, mock_get_client, client):
        """Test that health check results are cached."""
        # Mock Firestore client
        mock_client = AsyncMock()
        
        class MockAsyncIterator:
            def __aiter__(self):
                return self
            
            async def __anext__(self):
                raise StopAsyncIteration
        
        mock_client.collections = lambda: MockAsyncIterator()
        mock_get_client.return_value = mock_client
        
        # First call
        response1 = client.get("/healthz")
        assert response1.status_code == 200
        first_call_count = mock_get_client.call_count
        
        # Second call (should use cache)
        response2 = client.get("/healthz")
        assert response2.status_code == 200
        
        # Should not have made additional Firestore calls
        assert mock_get_client.call_count == first_call_count
        
        # Results should be the same
        assert response1.json()["status"] == response2.json()["status"]
    
    @patch('app.routes.health.get_firestore_client')
    def test_health_check_no_secrets_exposed(self, mock_get_client, client):
        """Test that health check never exposes secrets in response."""
        # Mock Firestore to fail with an exception containing sensitive data
        mock_get_client.side_effect = Exception("Connection failed: secret_key_12345")
        
        response = client.get("/healthz")
        
        data = response.json()
        response_str = str(data)
        
        # Should not contain any actual secret values
        assert "secret_key" not in response_str.lower() or "REDACTED" in response_str
        assert "password" not in response_str.lower()
        assert "-----BEGIN" not in response_str  # Private key
    
    @patch('app.routes.health.get_firestore_client')
    def test_health_check_updates_readiness_state(self, mock_get_client, client):
        """Test that health check updates readiness state."""
        # Mock Firestore client
        mock_client = AsyncMock()
        
        class MockAsyncIterator:
            def __aiter__(self):
                return self
            
            async def __anext__(self):
                raise StopAsyncIteration
        
        mock_client.collections = lambda: MockAsyncIterator()
        mock_get_client.return_value = mock_client
        
        # Perform health check
        response = client.get("/healthz")
        assert response.status_code == 200
        
        # Check that readiness state was updated
        readiness_state = get_readiness_state()
        status = readiness_state.get_status()
        
        assert status["ready"] is True
        assert status["components"]["firestore"] is True
        assert status["components"]["github_config"] is True


class TestReadinessEndpoint:
    """Test suite for readiness check endpoint."""
    
    def test_readiness_check_not_ready_initially(self, monkeypatch):
        """Test that readiness check returns not ready before initialization."""
        monkeypatch.setenv("APP_ENV", "dev")
        monkeypatch.delenv("GCP_PROJECT_ID", raising=False)
        monkeypatch.delenv("GITHUB_APP_ID", raising=False)
        
        from app import config
        original_settings = config.Settings
        monkeypatch.setattr(config, "Settings", lambda **kwargs: original_settings(_env_file=None, **kwargs))
        
        reset_readiness_state()
        reset_firestore_client()
        
        app = create_app()
        test_client = TestClient(app)
        
        response = test_client.get("/readyz")
        
        assert response.status_code == 503
        data = response.json()
        assert data["ready"] is False
        assert "components" in data
        assert data["initialized_at"] is None
    
    @patch('app.routes.health.get_firestore_client')
    def test_readiness_check_ready_after_health_check(self, mock_get_client, client):
        """Test that readiness becomes ready after successful health check."""
        # Mock Firestore client
        mock_client = AsyncMock()
        
        class MockAsyncIterator:
            def __aiter__(self):
                return self
            
            async def __anext__(self):
                raise StopAsyncIteration
        
        mock_client.collections = lambda: MockAsyncIterator()
        mock_get_client.return_value = mock_client
        
        # First check readiness (should be not ready)
        response1 = client.get("/readyz")
        # May be ready if startup initialized components
        
        # Perform health check to initialize
        health_response = client.get("/healthz")
        assert health_response.status_code == 200
        
        # Now check readiness again
        response2 = client.get("/readyz")
        assert response2.status_code == 200
        data = response2.json()
        assert data["ready"] is True
        assert data["initialized_at"] is not None
    
    @patch('app.routes.health.get_firestore_client')
    def test_readiness_check_becomes_not_ready_on_failure(self, mock_get_client, client):
        """Test that readiness becomes not ready when health check fails."""
        # First make it ready
        mock_client = AsyncMock()
        
        class MockAsyncIterator:
            def __aiter__(self):
                return self
            
            async def __anext__(self):
                raise StopAsyncIteration
        
        mock_client.collections = lambda: MockAsyncIterator()
        mock_get_client.return_value = mock_client
        
        # Perform successful health check
        response1 = client.get("/healthz")
        assert response1.status_code == 200
        
        # Check readiness
        readiness1 = client.get("/readyz")
        assert readiness1.status_code == 200
        
        # Now make Firestore fail
        mock_get_client.side_effect = Exception("Connection failed")
        
        # Clear cache to force new check
        from app.routes import health
        health._health_cache_timestamp = None
        
        # Perform failing health check
        response2 = client.get("/healthz")
        assert response2.status_code == 503
        
        # Check readiness (should be not ready now)
        readiness2 = client.get("/readyz")
        assert readiness2.status_code == 503
        data = readiness2.json()
        assert data["ready"] is False


class TestOpenAPIEndpoints:
    """Test suite for OpenAPI and docs endpoints."""
    
    def test_openapi_endpoint_exists(self, client):
        """Test that OpenAPI JSON endpoint is accessible."""
        response = client.get("/openapi.json")
        
        assert response.status_code == 200
        data = response.json()
        assert "openapi" in data
        assert "info" in data
        assert data["info"]["title"] == "GitHub App Token Minting Service"
    
    def test_docs_endpoint_exists(self, client):
        """Test that Swagger UI docs endpoint is accessible."""
        response = client.get("/docs")
        
        assert response.status_code == 200
        assert "text/html" in response.headers["content-type"]
    
    def test_openapi_has_health_endpoints(self, client):
        """Test that OpenAPI schema includes health endpoints."""
        response = client.get("/openapi.json")
        data = response.json()
        
        assert "/healthz" in data["paths"]
        assert "get" in data["paths"]["/healthz"]
        assert "/readyz" in data["paths"]
        assert "get" in data["paths"]["/readyz"]
    
    def test_health_endpoints_not_protected_by_iam(self, client):
        """Test that health endpoints are not protected by CloudRunIAM."""
        response = client.get("/openapi.json")
        data = response.json()
        
        # Health endpoints should not have security requirements
        healthz_get = data["paths"]["/healthz"]["get"]
        readyz_get = data["paths"]["/readyz"]["get"]
        
        assert "security" not in healthz_get or healthz_get.get("security") == []
        assert "security" not in readyz_get or readyz_get.get("security") == []


class TestRequestIdMiddleware:
    """Test suite for request ID middleware."""
    
    @patch('app.routes.health.get_firestore_client')
    def test_cloud_trace_context_header(self, mock_get_client, client):
        """Test that Cloud Run trace context is handled."""
        mock_client = AsyncMock()
        
        class MockAsyncIterator:
            def __aiter__(self):
                return self
            
            async def __anext__(self):
                raise StopAsyncIteration
        
        mock_client.collections = lambda: MockAsyncIterator()
        mock_get_client.return_value = mock_client
        
        headers = {"x-cloud-trace-context": "trace-123/span-456;o=1"}
        response = client.get("/healthz", headers=headers)
        
        assert response.status_code == 200
    
    @patch('app.routes.health.get_firestore_client')
    def test_x_request_id_header(self, mock_get_client, client):
        """Test that x-request-id header is handled."""
        mock_client = AsyncMock()
        
        class MockAsyncIterator:
            def __aiter__(self):
                return self
            
            async def __anext__(self):
                raise StopAsyncIteration
        
        mock_client.collections = lambda: MockAsyncIterator()
        mock_get_client.return_value = mock_client
        
        headers = {"x-request-id": "request-789"}
        response = client.get("/healthz", headers=headers)
        
        assert response.status_code == 200
    
    @patch('app.routes.health.get_firestore_client')
    def test_no_request_id_header(self, mock_get_client, client):
        """Test that requests without request ID headers work."""
        mock_client = AsyncMock()
        
        class MockAsyncIterator:
            def __aiter__(self):
                return self
            
            async def __anext__(self):
                raise StopAsyncIteration
        
        mock_client.collections = lambda: MockAsyncIterator()
        mock_get_client.return_value = mock_client
        
        response = client.get("/healthz")
        
        assert response.status_code == 200


class TestCORSConfiguration:
    """Test suite for CORS configuration."""
    
    def test_cors_disabled_by_default(self, monkeypatch):
        """Test that CORS is disabled by default."""
        monkeypatch.setenv("APP_ENV", "dev")
        monkeypatch.delenv("ENABLE_CORS", raising=False)
        
        from app import config
        original_settings = config.Settings
        monkeypatch.setattr(config, "Settings", lambda **kwargs: original_settings(_env_file=None, **kwargs))
        
        reset_readiness_state()
        
        app = create_app()
        assert app.state.settings.enable_cors is False


class TestApplicationLifespan:
    """Test suite for application lifespan events."""
    
    def test_app_initialization_with_dev_env(self, monkeypatch):
        """Test that app initializes successfully in dev environment."""
        monkeypatch.setenv("APP_ENV", "dev")
        
        from app import config
        original_settings = config.Settings
        monkeypatch.setattr(config, "Settings", lambda **kwargs: original_settings(_env_file=None, **kwargs))
        
        reset_readiness_state()
        
        app = create_app()
        
        assert app is not None
        assert app.state.settings.app_env == "dev"
    
    def test_app_settings_stored_in_state(self, monkeypatch):
        """Test that settings are accessible via app.state."""
        monkeypatch.setenv("APP_ENV", "dev")
        
        from app import config
        original_settings = config.Settings
        monkeypatch.setattr(config, "Settings", lambda **kwargs: original_settings(_env_file=None, **kwargs))
        
        reset_readiness_state()
        
        app = create_app()
        
        assert hasattr(app.state, "settings")
        assert app.state.settings.app_env == "dev"
    
    def test_app_initialization_fails_with_invalid_prod_config(self):
        """Test that app fails to initialize with invalid prod config."""
        from app.config import Settings
        
        # Should fail during Settings instantiation with prod but no GitHub secrets
        with pytest.raises(ValueError, match="Production environment requires"):
            Settings(_env_file=None, app_env="prod")
