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
"""Admin endpoints for operational monitoring and management.

Provides secured admin endpoints for:
- Token metadata inspection (without exposing sensitive data)
"""

from typing import Optional
from fastapi import APIRouter, Request, HTTPException, Depends

from app.config import Settings
from app.dao.firestore_dao import FirestoreDAO
from app.dependencies.firestore import get_firestore_dao, get_settings
from app.utils.logging import get_logger

logger = get_logger(__name__)

router = APIRouter()


@router.get(
    "/admin/token-metadata",
    summary="Get GitHub Token Metadata",
    description="""
Get non-sensitive metadata about the stored GitHub OAuth token.

**Security:**
- This endpoint is IAM-restricted via Cloud Run authentication
- Never returns the actual access token or encrypted ciphertext
- Only returns metadata: scope, token_type, expires_at, updated_at

**Storage:**
- Tokens are stored encrypted in Firestore using AES-256-GCM
- The encryption key is managed via environment variables
- Only metadata fields are returned by this endpoint

**Use Cases:**
- Operators verifying when the token was last updated
- Confirming token scopes without exposing sensitive data
- Health checks to ensure token exists

**Response:**
- 200: Metadata found and returned
- 404: Token document not found in Firestore
- 500: Firestore access error or other internal error
- 503: Firestore service unavailable

**Note:** This endpoint relies on Cloud Run IAM for authentication.
Requests without valid credentials will be rejected at the Cloud Run level.
    """,
    responses={
        200: {
            "description": "Token metadata retrieved successfully",
            "content": {
                "application/json": {
                    "example": {
                        "token_type": "bearer",
                        "scope": "repo,user:email,read:org",
                        "expires_at": "2025-12-31T23:59:59+00:00",
                        "has_refresh_token": True,
                        "updated_at": "2025-12-30T12:00:00+00:00"
                    }
                }
            }
        },
        404: {
            "description": "Token document not found",
            "content": {
                "application/json": {
                    "example": {
                        "detail": "Token document not found in Firestore"
                    }
                }
            }
        },
        500: {
            "description": "Internal server error",
            "content": {
                "application/json": {
                    "example": {
                        "detail": "Failed to retrieve token metadata"
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
    tags=["admin"]
)
async def get_token_metadata(
    settings: Settings = Depends(get_settings),
    dao: FirestoreDAO = Depends(get_firestore_dao)
) -> dict:
    """Get non-sensitive metadata about the stored GitHub token.
    
    Returns metadata fields only (scope, token_type, expires_at, updated_at).
    Never returns the actual access token or encrypted data.
    
    Args:
        settings: Application settings (injected)
        dao: Firestore DAO instance (injected)
    
    Returns:
        Dictionary containing token metadata
        
    Raises:
        HTTPException: 404 if token not found, 500 on other errors
    """
    try:
        logger.info(
            "Retrieving token metadata",
            extra={"extra_fields": {
                "collection": settings.github_tokens_collection,
                "doc_id": settings.github_tokens_doc_id
            }}
        )
        
        metadata = await dao.get_github_token_metadata(
            collection=settings.github_tokens_collection,
            doc_id=settings.github_tokens_doc_id
        )
        
        if metadata is None:
            logger.warning(
                "Token document not found",
                extra={"extra_fields": {
                    "collection": settings.github_tokens_collection,
                    "doc_id": settings.github_tokens_doc_id
                }}
            )
            raise HTTPException(
                status_code=404,
                detail="Token document not found in Firestore"
            )
        
        logger.info(
            "Token metadata retrieved successfully",
            extra={"extra_fields": {
                "token_type": metadata.get("token_type"),
                "has_scope": metadata.get("scope") is not None,
                "has_expiry": metadata.get("expires_at") is not None,
                "has_refresh_token": metadata.get("has_refresh_token", False)
            }}
        )
        
        return metadata
        
    except HTTPException:
        # Re-raise HTTP exceptions (like 404)
        raise
        
    except PermissionError as e:
        logger.error(
            "Permission denied accessing Firestore",
            extra={"extra_fields": {"error": str(e)}},
            exc_info=True
        )
        raise HTTPException(
            status_code=500,
            detail="Permission denied accessing token storage. Check IAM roles."
        )
        
    except Exception as e:
        logger.error(
            "Failed to retrieve token metadata",
            extra={"extra_fields": {
                "error": str(e),
                "error_type": type(e).__name__
            }},
            exc_info=True
        )
        raise HTTPException(
            status_code=500,
            detail="Failed to retrieve token metadata"
        )
