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
- Health check endpoints
- OpenAPI documentation
- Optional CORS middleware (disabled by default)
"""

from contextlib import asynccontextmanager
from typing import AsyncIterator
import logging

from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware

from app.config import get_settings, Settings
from app.utils.logging import setup_logging, request_id_var, get_logger
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
    logger.info(
        "Application starting",
        extra={"extra_fields": {
            "app_env": settings.app_env,
            "region": settings.region,
            "port": settings.port
        }}
    )
    
    yield
    
    # Shutdown
    logger.info("Application shutting down")


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
        description="Service for minting GitHub App tokens with GCP integration",
        version="0.1.0",
        lifespan=lifespan,
        docs_url="/docs",
        openapi_url="/openapi.json",
    )
    
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
