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
"""Tests for structured logging and metrics functionality."""

import pytest
import json
from io import StringIO
from unittest.mock import patch, MagicMock
from fastapi.testclient import TestClient

from app.main import create_app
from app.utils.logging import log_structured_event, get_logger
from app.utils.metrics import (
    MetricsCollector,
    init_metrics,
    get_metrics,
    is_metrics_enabled,
    increment_counter,
    METRIC_TOKEN_REFRESH_ATTEMPTS,
    METRIC_TOKEN_REFRESH_SUCCESSES,
    METRIC_OAUTH_FLOWS_STARTED
)


class TestStructuredLogging:
    """Test suite for structured logging functionality."""
    
    def test_log_structured_event_basic(self, caplog):
        """Test that log_structured_event emits structured logs."""
        logger = get_logger(__name__)
        
        with caplog.at_level("INFO"):
            log_structured_event(
                logger,
                "info",
                "test_event",
                "Test message",
                key1="value1",
                key2=42
            )
        
        # Verify log was emitted
        assert len(caplog.records) == 1
        record = caplog.records[0]
        
        # Verify message
        assert record.message == "Test message"
        
        # Verify extra fields
        assert hasattr(record, "extra_fields")
        assert record.extra_fields["event"] == "test_event"
        assert record.extra_fields["key1"] == "value1"
        assert record.extra_fields["key2"] == 42
    
    def test_log_structured_event_with_outcome(self, caplog):
        """Test structured logging with outcome field."""
        logger = get_logger(__name__)
        
        with caplog.at_level("INFO"):
            log_structured_event(
                logger,
                "info",
                "token_refresh_success",
                "Token refreshed successfully",
                outcome="success",
                duration_ms=150
            )
        
        record = caplog.records[0]
        assert record.extra_fields["event"] == "token_refresh_success"
        assert record.extra_fields["outcome"] == "success"
        assert record.extra_fields["duration_ms"] == 150
    
    def test_log_structured_event_handles_missing_fields(self, caplog):
        """Test that structured logging gracefully handles missing optional fields."""
        logger = get_logger(__name__)
        
        with caplog.at_level("INFO"):
            # Log without installation_id or other optional fields
            log_structured_event(
                logger,
                "info",
                "health_check",
                "Health check performed"
            )
        
        record = caplog.records[0]
        assert record.extra_fields["event"] == "health_check"
        # Should not have installation_id
        assert "installation_id" not in record.extra_fields


class TestMetricsCollector:
    """Test suite for MetricsCollector functionality."""
    
    def test_metrics_collector_increment(self):
        """Test basic counter increment."""
        collector = MetricsCollector()
        
        collector.increment("test_counter")
        assert collector.get_counter("test_counter") == 1
        
        collector.increment("test_counter", value=5)
        assert collector.get_counter("test_counter") == 6
    
    def test_metrics_collector_with_labels(self):
        """Test counter increment with labels."""
        collector = MetricsCollector()
        
        collector.increment("http_requests", labels={"method": "GET", "status": "200"})
        collector.increment("http_requests", labels={"method": "POST", "status": "201"})
        collector.increment("http_requests", labels={"method": "GET", "status": "200"})
        
        assert collector.get_counter("http_requests", labels={"method": "GET", "status": "200"}) == 2
        assert collector.get_counter("http_requests", labels={"method": "POST", "status": "201"}) == 1
    
    def test_metrics_collector_export_prometheus(self):
        """Test Prometheus format export."""
        collector = MetricsCollector()
        
        collector.increment("test_counter", value=10)
        collector.increment("other_counter", value=5)
        collector.increment("labeled_counter", labels={"label": "value"})
        
        export = collector.export_prometheus()
        
        # Verify format
        assert "# HELP test_counter" in export
        assert "# TYPE test_counter counter" in export
        assert "test_counter 10" in export
        
        assert "# HELP other_counter" in export
        assert "other_counter 5" in export
        
        assert 'labeled_counter{label="value"} 1' in export
    
    def test_metrics_collector_reset(self):
        """Test resetting all counters."""
        collector = MetricsCollector()
        
        collector.increment("test_counter", value=10)
        assert collector.get_counter("test_counter") == 10
        
        collector.reset()
        assert collector.get_counter("test_counter") == 0
    
    def test_metrics_collector_thread_safety(self):
        """Test that metrics collector is thread-safe."""
        import threading
        
        collector = MetricsCollector()
        
        def increment_many():
            for _ in range(1000):
                collector.increment("concurrent_counter")
        
        threads = [threading.Thread(target=increment_many) for _ in range(10)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        
        # Should have incremented 10,000 times total
        assert collector.get_counter("concurrent_counter") == 10000


class TestMetricsGlobalFunctions:
    """Test suite for global metrics functions."""
    
    def test_init_metrics_enabled(self):
        """Test initializing metrics when enabled."""
        init_metrics(enabled=True)
        
        assert is_metrics_enabled() is True
        assert get_metrics() is not None
        
        # Clean up
        init_metrics(enabled=False)
    
    def test_init_metrics_disabled(self):
        """Test initializing metrics when disabled."""
        init_metrics(enabled=False)
        
        assert is_metrics_enabled() is False
        assert get_metrics() is None
    
    def test_increment_counter_when_enabled(self):
        """Test increment_counter when metrics are enabled."""
        init_metrics(enabled=True)
        
        increment_counter("test_metric")
        increment_counter("test_metric", value=5)
        
        collector = get_metrics()
        assert collector.get_counter("test_metric") == 6
        
        # Clean up
        init_metrics(enabled=False)
    
    def test_increment_counter_when_disabled(self):
        """Test increment_counter is no-op when metrics are disabled."""
        init_metrics(enabled=False)
        
        # Should not raise an error
        increment_counter("test_metric")
        increment_counter("test_metric", value=5)
        
        assert get_metrics() is None


class TestRequestLoggingMiddleware:
    """Test suite for request logging middleware."""
    
    @pytest.fixture
    def client_with_logging(self, monkeypatch):
        """Create a test client with request logging enabled."""
        monkeypatch.setenv("APP_ENV", "dev")
        monkeypatch.setenv("ENABLE_REQUEST_LOGGING", "true")
        
        from app import config
        original_settings = config.Settings
        monkeypatch.setattr(config, "Settings", lambda **kwargs: original_settings(_env_file=None, **kwargs))
        
        app = create_app()
        return TestClient(app)
    
    @pytest.fixture
    def client_without_logging(self, monkeypatch):
        """Create a test client with request logging disabled."""
        monkeypatch.setenv("APP_ENV", "dev")
        monkeypatch.setenv("ENABLE_REQUEST_LOGGING", "false")
        
        from app import config
        original_settings = config.Settings
        monkeypatch.setattr(config, "Settings", lambda **kwargs: original_settings(_env_file=None, **kwargs))
        
        app = create_app()
        return TestClient(app)
    
    def test_request_logging_enabled(self, client_with_logging, caplog):
        """Test that request logging middleware logs when enabled."""
        with caplog.at_level("INFO"):
            response = client_with_logging.get("/healthz")
        
        assert response.status_code == 200
        
        # Should have log entries with http_request event
        http_logs = [r for r in caplog.records if hasattr(r, "extra_fields") and r.extra_fields.get("event") == "http_request"]
        assert len(http_logs) > 0
        
        # Verify structured fields
        log = http_logs[0]
        assert log.extra_fields["method"] == "GET"
        assert log.extra_fields["path"] == "/healthz"
        assert log.extra_fields["status_code"] == 200
        assert "duration_ms" in log.extra_fields
    
    def test_request_logging_disabled(self, client_without_logging, caplog):
        """Test that request logging middleware does not log when disabled."""
        with caplog.at_level("INFO"):
            response = client_without_logging.get("/healthz")
        
        assert response.status_code == 200
        
        # Should not have http_request event logs
        http_logs = [r for r in caplog.records if hasattr(r, "extra_fields") and r.extra_fields.get("event") == "http_request"]
        assert len(http_logs) == 0
    
    def test_request_logging_includes_request_id(self, client_with_logging, caplog):
        """Test that request logging includes request_id when provided."""
        with caplog.at_level("INFO"):
            response = client_with_logging.get(
                "/healthz",
                headers={"x-request-id": "test-request-123"}
            )
        
        assert response.status_code == 200
        
        # Find http_request log
        http_logs = [r for r in caplog.records if hasattr(r, "extra_fields") and r.extra_fields.get("event") == "http_request"]
        assert len(http_logs) > 0
        
        # Verify request_id is included
        log = http_logs[0]
        assert log.extra_fields.get("request_id") == "test-request-123"


class TestMetricsEndpoint:
    """Test suite for /metrics endpoint."""
    
    @pytest.fixture
    def client_with_metrics(self, monkeypatch):
        """Create a test client with metrics enabled."""
        monkeypatch.setenv("APP_ENV", "dev")
        monkeypatch.setenv("ENABLE_METRICS", "true")
        
        from app import config
        original_settings = config.Settings
        monkeypatch.setattr(config, "Settings", lambda **kwargs: original_settings(_env_file=None, **kwargs))
        
        # Manually initialize metrics since TestClient doesn't trigger lifespan
        from app.utils.metrics import init_metrics
        init_metrics(enabled=True)
        
        app = create_app()
        return TestClient(app)
    
    @pytest.fixture
    def client_without_metrics(self, monkeypatch):
        """Create a test client with metrics disabled."""
        monkeypatch.setenv("APP_ENV", "dev")
        monkeypatch.setenv("ENABLE_METRICS", "false")
        
        from app import config
        original_settings = config.Settings
        monkeypatch.setattr(config, "Settings", lambda **kwargs: original_settings(_env_file=None, **kwargs))
        
        # Ensure metrics are disabled
        from app.utils.metrics import init_metrics
        init_metrics(enabled=False)
        
        app = create_app()
        return TestClient(app)
    
    def test_metrics_endpoint_exists_when_enabled(self, client_with_metrics):
        """Test that /metrics endpoint exists when metrics are enabled."""
        response = client_with_metrics.get("/metrics")
        
        assert response.status_code == 200
        assert "text/plain" in response.headers["content-type"]
    
    def test_metrics_endpoint_not_found_when_disabled(self, client_without_metrics):
        """Test that /metrics endpoint returns 404 when metrics are disabled."""
        response = client_without_metrics.get("/metrics")
        
        assert response.status_code == 404
    
    def test_metrics_endpoint_exports_prometheus_format(self, client_with_metrics):
        """Test that /metrics endpoint exports Prometheus format."""
        # Verify metrics are initialized
        collector = get_metrics()
        assert collector is not None, "Metrics should be initialized"
        
        # Reset and add some metrics
        collector.reset()
        increment_counter(METRIC_TOKEN_REFRESH_ATTEMPTS)
        increment_counter(METRIC_TOKEN_REFRESH_SUCCESSES)
        
        response = client_with_metrics.get("/metrics")
        
        assert response.status_code == 200
        content = response.text
        
        # Verify Prometheus format elements are present
        assert "# HELP" in content
        assert "# TYPE" in content
        assert "counter" in content
    
    def test_metrics_endpoint_updates_after_increment(self, client_with_metrics):
        """Test that metrics endpoint reflects incremented counters."""
        # Verify metrics are initialized
        collector = get_metrics()
        assert collector is not None, "Metrics should be initialized"
        
        # Reset metrics
        collector.reset()
        
        # Increment a counter
        increment_counter("test_metric", value=42)
        
        response = client_with_metrics.get("/metrics")
        assert response.status_code == 200
        
        # Verify counter value in export
        assert "test_metric 42" in response.text


class TestMetricsIntegrationWithTokenRefresh:
    """Test suite for metrics integration with token refresh flows."""
    
    def test_metrics_counters_in_token_refresh_flow(self, monkeypatch):
        """Test that token refresh increments appropriate metrics counters."""
        # This is a simplified test - full integration tests would mock GitHub API
        monkeypatch.setenv("APP_ENV", "dev")
        monkeypatch.setenv("ENABLE_METRICS", "true")
        
        from app import config
        original_settings = config.Settings
        monkeypatch.setattr(config, "Settings", lambda **kwargs: original_settings(_env_file=None, **kwargs))
        
        # Manually initialize metrics
        init_metrics(enabled=True)
        
        # Initialize app to set up metrics
        app = create_app()
        
        # Get metrics collector (should be initialized now)
        collector = get_metrics()
        assert collector is not None, "Metrics should be initialized"
        
        # Reset metrics
        collector.reset()
        
        # Simulate token refresh metrics
        increment_counter(METRIC_TOKEN_REFRESH_ATTEMPTS)
        increment_counter(METRIC_TOKEN_REFRESH_SUCCESSES)
        
        # Verify counters
        assert collector.get_counter(METRIC_TOKEN_REFRESH_ATTEMPTS) == 1
        assert collector.get_counter(METRIC_TOKEN_REFRESH_SUCCESSES) == 1
    
    def test_metrics_labels_for_oauth_failures(self, monkeypatch):
        """Test that OAuth failure metrics include reason labels."""
        monkeypatch.setenv("APP_ENV", "dev")
        monkeypatch.setenv("ENABLE_METRICS", "true")
        
        from app import config
        original_settings = config.Settings
        monkeypatch.setattr(config, "Settings", lambda **kwargs: original_settings(_env_file=None, **kwargs))
        
        # Manually initialize metrics
        init_metrics(enabled=True)
        
        app = create_app()
        
        collector = get_metrics()
        assert collector is not None, "Metrics should be initialized"
        
        # Reset metrics
        collector.reset()
        
        # Simulate different failure types
        from app.utils.metrics import METRIC_OAUTH_FLOWS_FAILED
        increment_counter(METRIC_OAUTH_FLOWS_FAILED, labels={"reason": "user_denied"})
        increment_counter(METRIC_OAUTH_FLOWS_FAILED, labels={"reason": "token_exchange_failed"})
        
        # Verify labeled counters
        assert collector.get_counter(METRIC_OAUTH_FLOWS_FAILED, labels={"reason": "user_denied"}) == 1
        assert collector.get_counter(METRIC_OAUTH_FLOWS_FAILED, labels={"reason": "token_exchange_failed"}) == 1


class TestConfigurationSettings:
    """Test suite for new configuration settings."""
    
    def test_enable_request_logging_default(self, monkeypatch):
        """Test that request logging is disabled by default."""
        monkeypatch.setenv("APP_ENV", "dev")
        monkeypatch.delenv("ENABLE_REQUEST_LOGGING", raising=False)
        
        from app.config import Settings
        settings = Settings(_env_file=None)
        
        assert settings.enable_request_logging is False
    
    def test_enable_request_logging_true(self, monkeypatch):
        """Test that request logging can be enabled via config."""
        monkeypatch.setenv("APP_ENV", "dev")
        monkeypatch.setenv("ENABLE_REQUEST_LOGGING", "true")
        
        from app.config import Settings
        settings = Settings(_env_file=None)
        
        assert settings.enable_request_logging is True
    
    def test_enable_metrics_default(self, monkeypatch):
        """Test that metrics are disabled by default."""
        monkeypatch.setenv("APP_ENV", "dev")
        monkeypatch.delenv("ENABLE_METRICS", raising=False)
        
        from app.config import Settings
        settings = Settings(_env_file=None)
        
        assert settings.enable_metrics is False
    
    def test_enable_metrics_true(self, monkeypatch):
        """Test that metrics can be enabled via config."""
        monkeypatch.setenv("APP_ENV", "dev")
        monkeypatch.setenv("ENABLE_METRICS", "true")
        
        from app.config import Settings
        settings = Settings(_env_file=None)
        
        assert settings.enable_metrics is True
