"""Tests for health check endpoint and FastAPI application."""

import pytest
from fastapi.testclient import TestClient

from app.main import create_app


@pytest.fixture
def client(monkeypatch):
    """Create a test client with dev environment."""
    monkeypatch.setenv("APP_ENV", "dev")
    
    # Monkey-patch Settings to avoid .env
    from app import config
    original_settings = config.Settings
    monkeypatch.setattr(config, "Settings", lambda **kwargs: original_settings(_env_file=None, **kwargs))
    
    app = create_app()
    return TestClient(app)


class TestHealthEndpoint:
    """Test suite for health check endpoint."""
    
    def test_health_check_returns_ok(self, client):
        """Test that health endpoint returns status ok."""
        response = client.get("/healthz")
        
        assert response.status_code == 200
        assert response.json() == {"status": "ok"}
    
    def test_health_check_content_type(self, client):
        """Test that health endpoint returns JSON content type."""
        response = client.get("/healthz")
        
        assert response.headers["content-type"] == "application/json"
    
    def test_health_check_multiple_calls(self, client):
        """Test that health endpoint is idempotent."""
        for _ in range(3):
            response = client.get("/healthz")
            assert response.status_code == 200
            assert response.json() == {"status": "ok"}


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
    
    def test_openapi_has_health_endpoint(self, client):
        """Test that OpenAPI schema includes health endpoint."""
        response = client.get("/openapi.json")
        data = response.json()
        
        assert "/healthz" in data["paths"]
        assert "get" in data["paths"]["/healthz"]


class TestRequestIdMiddleware:
    """Test suite for request ID middleware."""
    
    def test_cloud_trace_context_header(self, client):
        """Test that Cloud Run trace context is handled."""
        headers = {"x-cloud-trace-context": "trace-123/span-456;o=1"}
        response = client.get("/healthz", headers=headers)
        
        assert response.status_code == 200
    
    def test_x_request_id_header(self, client):
        """Test that x-request-id header is handled."""
        headers = {"x-request-id": "request-789"}
        response = client.get("/healthz", headers=headers)
        
        assert response.status_code == 200
    
    def test_no_request_id_header(self, client):
        """Test that requests without request ID headers work."""
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
        
        app = create_app()
        
        assert app is not None
        assert app.state.settings.app_env == "dev"
    
    def test_app_settings_stored_in_state(self, monkeypatch):
        """Test that settings are accessible via app.state."""
        monkeypatch.setenv("APP_ENV", "dev")
        
        from app import config
        original_settings = config.Settings
        monkeypatch.setattr(config, "Settings", lambda **kwargs: original_settings(_env_file=None, **kwargs))
        
        app = create_app()
        
        assert hasattr(app.state, "settings")
        assert app.state.settings.app_env == "dev"
    
    def test_app_initialization_fails_with_invalid_prod_config(self):
        """Test that app fails to initialize with invalid prod config."""
        from app.config import Settings
        
        # Create settings directly with prod but no GitHub secrets
        settings = Settings(_env_file=None, app_env="prod")
        
        # Validation should fail
        with pytest.raises(ValueError, match="Production environment requires"):
            settings.validate_production_settings()
