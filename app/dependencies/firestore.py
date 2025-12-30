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
"""Firestore dependency injection for FastAPI routes.

This module provides dependency injection functions that make Firestore DAO
accessible to FastAPI routes with proper error handling and HTTP status codes.
"""

from fastapi import Depends, HTTPException, status, Request

from app.config import Settings
from app.dao.firestore_dao import FirestoreDAO
from app.services.firestore import get_firestore_client
from app.utils.logging import get_logger

logger = get_logger(__name__)


def get_settings(request: Request) -> Settings:
    """Get application settings from FastAPI app state.
    
    Args:
        request: FastAPI request object.
        
    Returns:
        Application settings.
    """
    return request.app.state.settings


def get_firestore_dao(settings: Settings = Depends(get_settings)) -> FirestoreDAO:
    """Get Firestore DAO instance for dependency injection.
    
    This function is used as a FastAPI dependency to inject FirestoreDAO
    into route handlers. It handles initialization errors gracefully and
    converts them to appropriate HTTP errors.
    
    Args:
        settings: Application settings (injected).
        
    Returns:
        Initialized FirestoreDAO instance.
        
    Raises:
        HTTPException: 503 if Firestore client cannot be initialized,
                      500 for other unexpected errors.
    """
    try:
        client = get_firestore_client(settings)
        return FirestoreDAO(client)
        
    except ValueError as e:
        # Configuration error (missing GCP_PROJECT_ID, etc.)
        error_msg = f"Firestore configuration error: {str(e)}"
        logger.error(error_msg)
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail=error_msg
        )
        
    except Exception as e:
        # Unexpected error during client initialization
        error_msg = f"Failed to initialize Firestore: {str(e)}"
        logger.error(error_msg, exc_info=True)
        
        # Expose detailed error in non-production environments for easier debugging
        detail_msg = "Firestore service is temporarily unavailable"
        if settings.app_env != "prod":
            detail_msg = error_msg
        
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail=detail_msg
        )
