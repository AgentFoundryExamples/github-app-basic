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
"""FastAPI application factory and initialization.

This module provides the main FastAPI application with:
- Configuration management
- Structured logging
- Request logging middleware (optional, config-gated)
- Prometheus metrics (optional, config-gated)
- Health check endpoints
- OpenAPI documentation
- Optional CORS middleware (disabled by default)
"""

from contextlib import asynccontextmanager
from typing import AsyncIterator
import logging
import time

from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import PlainTextResponse

from app.config import get_settings, Settings
from app.utils.logging import setup_logging, request_id_var, get_logger, log_structured_event
from app.utils.metrics import (
    init_metrics,
    get_metrics,
    is_metrics_enabled,
    increment_counter,
    METRIC_HTTP_REQUESTS_TOTAL
)
from app.routes import health, oauth, admin, token


@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncIterator[None]:
    """Lifespan context manager for application startup and shutdown.
    
    Args:
        app: The FastAPI application instance.
        
    Yields:
        Control during application runtime.
    """
    logger = get_logger(__name__)
    settings: Settings = app.state.settings
    
    # Startup
    log_structured_event(
        logger,
        "info",
        "application_startup",
        "Application starting",
        app_env=settings.app_env,
        region=settings.region,
        port=settings.port,
        request_logging_enabled=settings.enable_request_logging,
        metrics_enabled=settings.enable_metrics
    )
    
    # Initialize metrics if enabled
    init_metrics(enabled=settings.enable_metrics)
    if settings.enable_metrics:
        logger.info("Metrics collection enabled - /metrics endpoint available")
    
    yield
    
    # Shutdown
    log_structured_event(
        logger,
        "info",
        "application_shutdown",
        "Application shutting down"
    )


def create_app() -> FastAPI:
    """Factory function to create and configure the FastAPI application.
    
    Returns:
        Configured FastAPI application instance.
        
    Raises:
        ValueError: If production configuration validation fails.
    """
    # Load and validate settings
    settings = get_settings()
    
    # Setup logging
    setup_logging(settings.log_level)
    logger = get_logger(__name__)
    
    # Create FastAPI app
    app = FastAPI(
        title="GitHub App Token Minting Service",
        description="""
Service for minting GitHub App tokens with GCP integration.

## Authentication

**Cloud Run IAM Authentication:**
- All API endpoints (except health check) are protected by Cloud Run IAM authentication at the infrastructure level
- No application-level authentication is performed
- Deploy with: `gcloud run deploy --no-allow-unauthenticated`
- Callers must have the `roles/run.invoker` IAM role
- Requests must include a valid GCP identity token in the Authorization header: `Bearer <identity-token>`

**Obtaining Identity Tokens:**
- **User accounts:** `gcloud auth print-identity-token`
- **Service accounts (Python):** Use `google.oauth2.id_token.fetch_id_token(auth_req, service_url)`
- **Service accounts (Node.js):** Use `GoogleAuth.getIdTokenClient(serviceUrl)`
- **Cloud Scheduler:** Configure OIDC authentication with service account

**Identity Token Audience:**
- Must match the Cloud Run service URL
- Use regional URLs (e.g., `https://service-xxxxx-uc.a.run.app`)
- Do not use custom domains

**Security Model:**
The OpenAPI specification below defines a "CloudRunIAM" security scheme to document
the authentication requirements for client generators. However, the actual authentication
is enforced by Cloud Run's IAM layer at the infrastructure level, not by this application.
The bearer token referenced is a GCP identity token, not the GitHub access token.
        """,
        version="0.1.0",
        lifespan=lifespan,
        docs_url="/docs",
        openapi_url="/openapi.json",
    )
    
    # Add security scheme to OpenAPI spec
    def custom_openapi():
        if app.openapi_schema:
            return app.openapi_schema
        
        from fastapi.openapi.utils import get_openapi
        openapi_schema = get_openapi(
            title=app.title,
            version=app.version,
            description=app.description,
            routes=app.routes,
        )
        
        # Define the Cloud Run IAM security scheme
        openapi_schema["components"]["securitySchemes"] = {
            "CloudRunIAM": {
                "type": "http",
                "scheme": "bearer",
                "bearerFormat": "GCP Identity Token",
                "description": (
                    "Cloud Run IAM authentication using GCP identity tokens. "
                    "Obtain an identity token via `gcloud auth print-identity-token` (for users) "
                    "or `google.oauth2.id_token.fetch_id_token()` (for service accounts). "
                    "The token audience must match the Cloud Run service URL. "
                    "Callers must have the `roles/run.invoker` IAM role."
                )
            }
        }
        
        # Apply security scheme to all endpoints except health check
        for path, path_item in openapi_schema.get("paths", {}).items():
            if path == "/healthz":
                continue  # Health check is publicly accessible
            for operation in path_item.values():
                if isinstance(operation, dict) and "operationId" in operation:
                    operation["security"] = [{"CloudRunIAM": []}]
        
        app.openapi_schema = openapi_schema
        return app.openapi_schema
    
    app.openapi = custom_openapi
    
    # Store settings in app state
    app.state.settings = settings
    
    # Add middleware for request ID extraction
    @app.middleware("http")
    async def add_request_id_to_logs(request: Request, call_next):
        """Middleware to extract and log request IDs from headers.
        
        Extracts request ID from x-cloud-trace-context header (Cloud Run)
        or x-request-id header.
        """
        request_id = None
        
        # Try Cloud Run trace context first
        trace_context = request.headers.get("x-cloud-trace-context")
        if trace_context:
            # Format: TRACE_ID/SPAN_ID;o=TRACE_TRUE
            request_id = trace_context.split("/")[0] if "/" in trace_context else trace_context
        
        # Fallback to x-request-id
        if not request_id:
            request_id = request.headers.get("x-request-id")
        
        # Add to request state for downstream use
        request.state.request_id = request_id
        
        # Set the context variable for logging
        token = request_id_var.set(request_id)
        
        try:
            response = await call_next(request)
        finally:
            # Reset the context variable to its previous state
            request_id_var.reset(token)
        
        return response
    
    # Add optional request logging middleware
    if settings.enable_request_logging:
        logger.info("Request logging middleware enabled")
        
        @app.middleware("http")
        async def log_requests(request: Request, call_next):
            """Middleware to log HTTP requests with timing information.
            
            Logs method, path, status code, duration, and correlation IDs.
            Only active when ENABLE_REQUEST_LOGGING=true.
            """
            start_time = time.time()
            
            # Process request
            response = await call_next(request)
            
            # Calculate duration
            duration_ms = (time.time() - start_time) * 1000
            
            # Get request ID from state
            request_id = getattr(request.state, "request_id", None)
            
            # Get route template to avoid high cardinality in metrics
            # Use the route pattern instead of actual path to prevent unique paths
            route = request.scope.get("route")
            path_template = route.path if route else request.url.path
            
            # Log structured request event (use actual path for logging)
            log_structured_event(
                logger,
                "info",
                "http_request",
                f"{request.method} {request.url.path}",
                method=request.method,
                path=request.url.path,
                status_code=response.status_code,
                duration_ms=round(duration_ms, 2),
                request_id=request_id
            )
            
            # Increment metrics counter if enabled (use path template for low cardinality)
            increment_counter(
                METRIC_HTTP_REQUESTS_TOTAL,
                labels={
                    "method": request.method,
                    "path": path_template,
                    "status": str(response.status_code)
                }
            )
            
            return response
    else:
        logger.info("Request logging middleware disabled (default)")
    
    # Optional CORS middleware (disabled by default)
    if settings.enable_cors:
        logger.warning(
            "CORS is enabled - ensure this is intended for your environment. "
            "IMPORTANT: Using wildcard (*) origins is a security risk in production. "
            "Configure specific allowed origins before deploying to production."
        )
        # TODO: Add CORS_ALLOWED_ORIGINS config and replace ["*"] with specific origins for production
        app.add_middleware(
            CORSMiddleware,
            allow_origins=["*"],  # SECURITY: Wildcard allows all origins - configure specific origins for production
            allow_credentials=False,  # Disabled with wildcard origins to prevent security vulnerability
            allow_methods=["*"],
            allow_headers=["*"],
        )
    else:
        logger.info("CORS middleware is disabled (default)")
    
    # Register routers
    app.include_router(health.router, tags=["health"])
    app.include_router(oauth.router, tags=["oauth"])
    app.include_router(admin.router, tags=["admin"])
    app.include_router(token.router, tags=["token"])
    
    # Add metrics endpoint if enabled
    if settings.enable_metrics:
        @app.get(
            "/metrics",
            summary="Prometheus Metrics",
            description="""
Export Prometheus-compatible metrics for monitoring.

**Metrics Provided:**
- `github_token_refresh_attempts_total`: Total token refresh attempts
- `github_token_refresh_successes_total`: Successful token refreshes
- `github_token_refresh_failures_total`: Failed token refreshes
- `github_token_refresh_cooldowns_total`: Refresh attempts blocked by cooldown
- `github_oauth_flows_started_total`: OAuth flows initiated
- `github_oauth_flows_completed_total`: OAuth flows completed successfully
- `github_oauth_flows_failed_total`: OAuth flows that failed
- `http_requests_total`: HTTP requests by method/path/status (if request logging enabled)

**⚠️ Security Warning:**
This endpoint is **NOT** protected by Cloud Run IAM authentication by default.
It will be publicly accessible when metrics are enabled.

**Production Deployment:**
For production deployments, you should either:
1. Keep `ENABLE_METRICS=false` (recommended default) and use Cloud Monitoring instead
2. Add authentication middleware to protect this endpoint
3. Use a separate metrics scraper with proper authentication
4. Deploy with network-level access controls

**Data Exposure:**
This endpoint exposes aggregated counters and does not contain:
- Tokens or credentials
- PII or user data
- Internal configuration details

However, request patterns and error rates may provide information about system behavior.
            """,
            response_class=PlainTextResponse,
            tags=["observability"]
        )
        async def metrics_endpoint():
            """Export Prometheus metrics."""
            metrics = get_metrics()
            if metrics:
                return metrics.export_prometheus()
            return "# Metrics not initialized\n"
        
        logger.info("Metrics endpoint registered at /metrics")
    
    logger.info("FastAPI application created successfully")
    
    return app


# Create the application instance
app = create_app()


if __name__ == "__main__":
    import uvicorn
    import os
    
    port = int(os.getenv("PORT", "8000"))
    uvicorn.run(
        "app.main:app",
        host="0.0.0.0",
        port=port,
        reload=True,
        log_config=None,  # Use our custom logging
    )
