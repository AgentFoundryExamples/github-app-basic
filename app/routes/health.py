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
"""Health check and readiness endpoints for the service."""

from fastapi import APIRouter, Depends, Request, Response, status
from typing import Dict, Any, Optional
import asyncio
from datetime import datetime, timezone, timedelta

from app.config import Settings
from app.dependencies.firestore import get_settings
from app.services.firestore import get_firestore_client
from app.services.readiness import get_readiness_state
from app.utils.logging import get_logger, log_structured_event
from app.utils.metrics import (
    increment_counter,
    METRIC_HEALTH_CHECK_SUCCESSES,
    METRIC_HEALTH_CHECK_FAILURES,
    METRIC_READINESS_CHECK_SUCCESSES,
    METRIC_READINESS_CHECK_FAILURES
)
from app.utils.security import sanitize_exception_message

logger = get_logger(__name__)

router = APIRouter()

# Cache for health check results to avoid hammering Firestore
# Protected by Python GIL for simple dictionary operations
_health_cache: Dict[str, Any] = {}
_health_cache_timestamp: Optional[datetime] = None
_health_cache_lock = asyncio.Lock()


async def check_firestore_health(settings: Settings) -> Dict[str, Any]:
    """Check Firestore connectivity with timeout.
    
    Performs a lightweight check by attempting to access Firestore client
    and optionally performing a simple query.
    
    Args:
        settings: Application settings.
        
    Returns:
        Dictionary with status and optional error details.
    """
    try:
        # Try to get Firestore client with timeout
        client = get_firestore_client(settings)
        
        # Perform a simple operation to verify connectivity
        # Use a very lightweight operation - just list collections (limited to 1)
        async def test_connection():
            collections = client.collections()
            # Just check if we can iterate (don't consume the whole iterator)
            async for _ in collections:
                break
            return True
        
        # Execute with timeout
        await asyncio.wait_for(
            test_connection(),
            timeout=settings.health_check_timeout_seconds
        )
        
        return {
            "status": "healthy",
            "service": "firestore"
        }
        
    except asyncio.TimeoutError:
        error_msg = f"Firestore health check timed out after {settings.health_check_timeout_seconds}s"
        logger.warning(error_msg)
        return {
            "status": "unhealthy",
            "service": "firestore",
            "error": "timeout"
        }
    except ValueError as e:
        # Configuration error
        error_msg = sanitize_exception_message(e)
        logger.error(f"Firestore configuration error: {error_msg}")
        return {
            "status": "unhealthy",
            "service": "firestore",
            "error": "configuration_error"
        }
    except Exception as e:
        # Other errors
        error_msg = sanitize_exception_message(e)
        logger.error(f"Firestore health check failed: {error_msg}", exc_info=True)
        return {
            "status": "unhealthy",
            "service": "firestore",
            "error": "connection_failed"
        }


def check_github_config(settings: Settings) -> Dict[str, Any]:
    """Check GitHub App configuration validity.
    
    Validates that essential configuration is present without exposing values.
    
    Args:
        settings: Application settings.
        
    Returns:
        Dictionary with status and optional error details.
    """
    try:
        # Check essential GitHub App configuration
        required_config = {
            "github_app_id": settings.github_app_id,
            "github_app_private_key_pem": settings.github_app_private_key_pem,
        }
        
        missing = [key for key, value in required_config.items() if not value]
        
        if missing:
            return {
                "status": "unhealthy",
                "service": "github_config",
                "error": "missing_configuration"
            }
        
        # Basic format validation for private key
        if not settings.github_app_private_key_pem.startswith('-----BEGIN'):
            return {
                "status": "unhealthy",
                "service": "github_config",
                "error": "invalid_key_format"
            }
        
        return {
            "status": "healthy",
            "service": "github_config"
        }
        
    except Exception as e:
        error_msg = sanitize_exception_message(e)
        logger.error(f"GitHub config check failed: {error_msg}", exc_info=True)
        return {
            "status": "unhealthy",
            "service": "github_config",
            "error": "validation_failed"
        }


@router.get("/healthz")
async def health_check(
    response: Response,
    settings: Settings = Depends(get_settings)
) -> Dict[str, Any]:
    """Health check endpoint with Firestore connectivity and config validation.
    
    Performs checks on:
    - Firestore connectivity (with timeout and caching)
    - GitHub App configuration presence and basic validity
    
    Returns 200 if all checks pass, 503 if any check fails.
    Results are cached to avoid excessive Firestore queries.
    
    Returns:
        Dictionary with overall status and component statuses.
    """
    global _health_cache, _health_cache_timestamp
    
    log_structured_event(
        logger,
        "info",
        "health_check_called",
        "Health check endpoint called"
    )
    
    # Check if cache is valid (thread-safe with async lock)
    async with _health_cache_lock:
        cache_valid = False
        if _health_cache_timestamp and settings.health_check_cache_ttl_seconds > 0:
            cache_age = (datetime.now(timezone.utc) - _health_cache_timestamp).total_seconds()
            cache_valid = cache_age < settings.health_check_cache_ttl_seconds
        
        if cache_valid and _health_cache:
            log_structured_event(
                logger,
                "debug",
                "health_check_cache_hit",
                "Using cached health check results"
            )
            result = _health_cache
        else:
            # Perform health checks
            firestore_health = await check_firestore_health(settings)
            github_config_health = check_github_config(settings)
            
            # Determine overall status
            all_healthy = all([
                firestore_health["status"] == "healthy",
                github_config_health["status"] == "healthy"
            ])
            
            result = {
                "status": "healthy" if all_healthy else "unhealthy",
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "checks": {
                    "firestore": firestore_health,
                    "github_config": github_config_health
                }
            }
            
            # Update cache
            _health_cache = result
            _health_cache_timestamp = datetime.now(timezone.utc)
            
            log_structured_event(
                logger,
                "info",
                "health_check_completed",
                f"Health check completed: {result['status']}",
                status=result['status'],
                firestore_status=firestore_health["status"],
                github_config_status=github_config_health["status"]
            )
    
    # Update readiness state based on health check
    readiness_state = get_readiness_state()
    if result["checks"]["firestore"]["status"] == "healthy":
        readiness_state.mark_component_ready("firestore")
    else:
        readiness_state.mark_component_not_ready("firestore")
    
    if result["checks"]["github_config"]["status"] == "healthy":
        readiness_state.mark_component_ready("github_config")
    else:
        readiness_state.mark_component_not_ready("github_config")
    
    # Set HTTP status code
    if result["status"] != "healthy":
        response.status_code = status.HTTP_503_SERVICE_UNAVAILABLE
        increment_counter(METRIC_HEALTH_CHECK_FAILURES)
    else:
        increment_counter(METRIC_HEALTH_CHECK_SUCCESSES)
    
    return result


@router.get("/readyz")
async def readiness_check(response: Response) -> Dict[str, Any]:
    """Readiness check endpoint.
    
    Indicates whether the application is ready to serve traffic.
    Returns 200 if ready, 503 if not ready.
    
    Readiness is determined by whether critical components
    (Firestore, GitHub config) have been successfully initialized.
    
    Returns:
        Dictionary with readiness status and component details.
    """
    readiness_state = get_readiness_state()
    status_info = readiness_state.get_status()
    
    log_structured_event(
        logger,
        "info",
        "readiness_check_called",
        f"Readiness check: {'ready' if status_info['ready'] else 'not ready'}",
        ready=status_info['ready']
    )
    
    if not status_info["ready"]:
        response.status_code = status.HTTP_503_SERVICE_UNAVAILABLE
        increment_counter(METRIC_READINESS_CHECK_FAILURES)
    else:
        increment_counter(METRIC_READINESS_CHECK_SUCCESSES)
    
    return {
        "ready": status_info["ready"],
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "initialized_at": status_info["initialized_at"],
        "components": status_info["components"]
    }
