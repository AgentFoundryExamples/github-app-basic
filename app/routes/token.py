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
"""Token endpoint for retrieving and refreshing GitHub user access tokens.

Provides:
- POST /api/token - Get or refresh GitHub user access token
"""

from typing import Optional
from datetime import datetime, timezone, timedelta

from fastapi import APIRouter, HTTPException, Depends, Query, Body
from pydantic import BaseModel, Field

from app.config import Settings
from app.dao.firestore_dao import FirestoreDAO
from app.dependencies.firestore import get_firestore_dao, get_settings
from app.services.github import (
    GitHubAppJWT,
    GitHubTokenRefreshManager,
    GitHubTokenRefreshError,
    GitHubTokenRefreshCooldownError
)
from app.utils.logging import get_logger

logger = get_logger(__name__)

router = APIRouter()


class TokenRequest(BaseModel):
    """Request body for token endpoint (optional)."""
    
    force_refresh: Optional[bool] = Field(
        default=False,
        description="Force token refresh even if not near expiry"
    )


class TokenResponse(BaseModel):
    """Response model for token endpoint."""
    
    access_token: str = Field(
        description="GitHub user access token"
    )
    token_type: str = Field(
        description="Token type (typically 'bearer')"
    )
    expires_at: Optional[str] = Field(
        default=None,
        description="Token expiration time in ISO-8601 format, or null for non-expiring tokens"
    )


@router.post(
    "/api/token",
    summary="Get GitHub User Access Token",
    description="""
Get the stored GitHub user access token, refreshing if necessary.

**Authentication:**
- This endpoint is protected by Cloud Run IAM authentication at the infrastructure level
- No application-level authentication is performed
- Configure Cloud Run to require authentication: `gcloud run deploy --no-allow-unauthenticated`
- Callers must have appropriate IAM permissions to invoke the Cloud Run service

**Behavior:**
1. Retrieves the stored GitHub user token from Firestore
2. Checks if the token is near expiry (within configured threshold) or if force_refresh is requested
3. If refresh is needed, calls GitHub's refresh API to obtain a new token
4. Respects cooldown period after failed refresh attempts to prevent excessive API calls
5. Returns the token (current or refreshed) with metadata

**Token Refresh:**
- Tokens are refreshed when:
  - `force_refresh=true` is provided (query parameter or request body)
  - Token expiration is within the configured threshold (default: 30 minutes)
- Tokens without expiration dates are only refreshed when `force_refresh=true`
- After a failed refresh, a cooldown period prevents immediate retries (default: 300 seconds)

**Request Parameters:**
- `force_refresh` (optional): Can be provided as query parameter or in JSON request body
  - Query parameter: `/api/token?force_refresh=true`
  - Request body: `{"force_refresh": true}`
  - Default: `false`

**Response:**
Returns JSON with:
- `access_token`: The GitHub user access token (string)
- `token_type`: Token type, typically "bearer" (string)
- `expires_at`: ISO-8601 timestamp or null for non-expiring tokens (string or null)

**Error Responses:**
- 404: User has not completed authorization - no token stored
- 500: Token refresh failed due to GitHub API error
- 503: Firestore service unavailable

**Important:** This endpoint does NOT expose:
- Internal metadata (last_refresh_attempt, last_refresh_status, etc.)
- Firestore document structure
- Encryption details

**Use Cases:**
- Internal services retrieving tokens for GitHub API calls
- Automated workflows requiring fresh access tokens
- Token management and rotation
    """,
    response_model=TokenResponse,
    responses={
        200: {
            "description": "Token retrieved successfully (may have been refreshed)",
            "content": {
                "application/json": {
                    "examples": {
                        "non_expiring_token": {
                            "summary": "Non-expiring GitHub token",
                            "description": "Most GitHub user-to-server tokens do not expire",
                            "value": {
                                "access_token": "gho_ExampleToken123...",
                                "token_type": "bearer",
                                "expires_at": None
                            }
                        },
                        "expiring_token": {
                            "summary": "Expiring GitHub token",
                            "description": "Some tokens may have expiration dates",
                            "value": {
                                "access_token": "gho_ExampleToken456...",
                                "token_type": "bearer",
                                "expires_at": "2025-12-31T23:59:59+00:00"
                            }
                        }
                    }
                }
            }
        },
        404: {
            "description": "User has not completed authorization",
            "content": {
                "application/json": {
                    "example": {
                        "detail": "User has not completed authorization"
                    }
                }
            }
        },
        500: {
            "description": "Token refresh failed",
            "content": {
                "application/json": {
                    "example": {
                        "detail": "Failed to refresh GitHub token"
                    }
                }
            }
        },
        503: {
            "description": "Firestore service unavailable",
            "content": {
                "application/json": {
                    "example": {
                        "detail": "Firestore service is temporarily unavailable"
                    }
                }
            }
        }
    },
    tags=["token"]
)
async def get_token(
    force_refresh_query: Optional[bool] = Query(
        default=None,
        description="Force token refresh (query parameter)",
        alias="force_refresh"
    ),
    request_body: Optional[TokenRequest] = Body(default=None),
    settings: Settings = Depends(get_settings),
    dao: FirestoreDAO = Depends(get_firestore_dao)
) -> TokenResponse:
    """Get or refresh GitHub user access token.
    
    Args:
        force_refresh_query: Force refresh flag from query parameter
        request_body: Optional request body with force_refresh flag
        settings: Application settings (injected)
        dao: Firestore DAO instance (injected)
    
    Returns:
        TokenResponse with access_token, token_type, and expires_at
        
    Raises:
        HTTPException: 404 if token not found, 500 on refresh failures
    """
    # Determine force_refresh from query param or request body
    # Query parameter takes precedence over request body
    force_refresh = False
    if force_refresh_query is not None:
        force_refresh = force_refresh_query
    elif request_body is not None and request_body.force_refresh is not None:
        force_refresh = request_body.force_refresh
    
    logger.info(
        "Token retrieval requested",
        extra={"extra_fields": {
            "force_refresh": force_refresh,
            "collection": settings.github_tokens_collection,
            "doc_id": settings.github_tokens_doc_id
        }}
    )
    
    try:
        # Retrieve stored token from Firestore
        token_data = await dao.get_github_token(
            collection=settings.github_tokens_collection,
            doc_id=settings.github_tokens_doc_id,
            decrypt=True
        )
        
        if token_data is None:
            logger.warning(
                "Token document not found",
                extra={"extra_fields": {
                    "collection": settings.github_tokens_collection,
                    "doc_id": settings.github_tokens_doc_id
                }}
            )
            raise HTTPException(
                status_code=404,
                detail="User has not completed authorization"
            )
        
        # Parse expiration date
        expires_at = dao.parse_iso_datetime(token_data.get("expires_at"))
        
        # Determine if refresh is needed
        needs_refresh = force_refresh
        if not needs_refresh and expires_at is not None:
            needs_refresh = dao.is_token_near_expiry(
                expires_at=expires_at,
                threshold_minutes=settings.token_refresh_threshold_minutes
            )
        
        # Log refresh decision
        logger.info(
            "Token refresh decision",
            extra={"extra_fields": {
                "needs_refresh": needs_refresh,
                "force_refresh": force_refresh,
                "has_expiry": expires_at is not None,
                "is_near_expiry": dao.is_token_near_expiry(
                    expires_at=expires_at,
                    threshold_minutes=settings.token_refresh_threshold_minutes
                ) if expires_at else False
            }}
        )
        
        # Refresh token if needed
        if needs_refresh:
            try:
                # Initialize GitHub App JWT
                if not settings.github_app_id or not settings.github_app_private_key_pem:
                    logger.error(
                        "GitHub App credentials not configured for token refresh",
                        extra={"extra_fields": {
                            "has_app_id": settings.github_app_id is not None,
                            "has_private_key": settings.github_app_private_key_pem is not None
                        }}
                    )
                    raise HTTPException(
                        status_code=500,
                        detail="Failed to refresh GitHub token"
                    )
                
                github_app_jwt = GitHubAppJWT(
                    app_id=settings.github_app_id,
                    private_key_pem=settings.github_app_private_key_pem
                )
                
                # Refresh the token
                logger.info("Refreshing GitHub token")
                refreshed_token_data = await GitHubTokenRefreshManager.refresh_user_token(
                    current_token_data=token_data,
                    github_app_jwt=github_app_jwt,
                    client_id=settings.github_client_id,
                    client_secret=settings.github_client_secret,
                    cooldown_seconds=settings.token_refresh_cooldown_seconds,
                    force_refresh=force_refresh
                )
                
                # Parse new expiration
                new_expires_at = None
                if "expires_in" in refreshed_token_data:
                    new_expires_at = datetime.now(timezone.utc)
                    new_expires_at += timedelta(seconds=refreshed_token_data["expires_in"])
                
                # Persist refreshed token
                await dao.save_github_token(
                    collection=settings.github_tokens_collection,
                    doc_id=settings.github_tokens_doc_id,
                    access_token=refreshed_token_data["access_token"],
                    token_type=refreshed_token_data.get("token_type", "bearer"),
                    scope=refreshed_token_data.get("scope", token_data.get("scope")),
                    expires_at=new_expires_at,
                    refresh_token=refreshed_token_data.get("refresh_token"),
                    last_refresh_attempt=datetime.now(timezone.utc),
                    last_refresh_status="success",
                    last_refresh_error=None
                )
                
                logger.info(
                    "Token refreshed successfully",
                    extra={"extra_fields": {
                        "refresh_method": refreshed_token_data.get("refresh_method"),
                        "has_new_expiry": new_expires_at is not None
                    }}
                )
                
                # Use refreshed token data for response
                return TokenResponse(
                    access_token=refreshed_token_data["access_token"],
                    token_type=refreshed_token_data.get("token_type", "bearer"),
                    expires_at=new_expires_at.isoformat() if new_expires_at else None
                )
                
            except GitHubTokenRefreshCooldownError as e:
                # Cooldown error - return current token with logged warning
                logger.warning(
                    "Token refresh blocked by cooldown, returning current token",
                    extra={"extra_fields": {
                        "seconds_until_retry": e.seconds_until_retry,
                        "error_message": str(e)
                    }}
                )
                # Fall through to return current token
                
            except GitHubTokenRefreshError as e:
                # Token refresh failed - log error and persist failure
                logger.error(
                    "GitHub token refresh failed",
                    extra={"extra_fields": {
                        "error": str(e),
                        "error_type": type(e).__name__
                    }},
                    exc_info=True
                )
                
                # Persist failure metadata
                try:
                    await dao.save_github_token(
                        collection=settings.github_tokens_collection,
                        doc_id=settings.github_tokens_doc_id,
                        access_token=token_data["access_token"],
                        token_type=token_data.get("token_type", "bearer"),
                        scope=token_data.get("scope"),
                        expires_at=expires_at,
                        refresh_token=token_data.get("refresh_token"),
                        last_refresh_attempt=datetime.now(timezone.utc),
                        last_refresh_status="failed",
                        last_refresh_error=str(e)
                    )
                except Exception as persist_error:
                    logger.error(
                        "Failed to persist refresh failure metadata",
                        extra={"extra_fields": {"error": str(persist_error)}}
                    )
                
                # Return 500 with sanitized error
                raise HTTPException(
                    status_code=500,
                    detail="Failed to refresh GitHub token"
                )
            
            except Exception as e:
                # Unexpected error during refresh
                logger.error(
                    "Unexpected error during token refresh",
                    extra={"extra_fields": {
                        "error": str(e),
                        "error_type": type(e).__name__
                    }},
                    exc_info=True
                )
                raise HTTPException(
                    status_code=500,
                    detail="Failed to refresh GitHub token"
                )
        
        # Return current token (not refreshed or refresh failed with cooldown)
        return TokenResponse(
            access_token=token_data["access_token"],
            token_type=token_data.get("token_type", "bearer"),
            expires_at=expires_at.isoformat() if expires_at else None
        )
        
    except HTTPException:
        # Re-raise HTTP exceptions (404, 500, 503)
        raise
        
    except PermissionError as e:
        # Firestore permission error - return 503
        logger.error(
            "Permission denied accessing Firestore",
            extra={"extra_fields": {
                "error": str(e),
                "error_type": type(e).__name__
            }},
            exc_info=True
        )
        raise HTTPException(
            status_code=503,
            detail="Firestore service is temporarily unavailable"
        )
        
    except Exception as e:
        # Check if it's a Firestore connectivity/API error
        error_type = type(e).__name__
        error_str = str(e).lower()
        
        # Firestore-related errors should return 503
        if any(keyword in error_str for keyword in ["firestore", "connection", "unavailable", "timeout"]):
            logger.error(
                "Firestore service error",
                extra={"extra_fields": {
                    "error": str(e),
                    "error_type": error_type
                }},
                exc_info=True
            )
            raise HTTPException(
                status_code=503,
                detail="Firestore service is temporarily unavailable"
            )
        
        # Other unexpected errors return 500
        logger.error(
            "Failed to retrieve token",
            extra={"extra_fields": {
                "error": str(e),
                "error_type": error_type
            }},
            exc_info=True
        )
        raise HTTPException(
            status_code=500,
            detail="Failed to retrieve token"
        )
