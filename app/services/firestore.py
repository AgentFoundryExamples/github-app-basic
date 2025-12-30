"""Firestore client initialization and management.

This module provides lazy initialization of Google Cloud Firestore client
using GCP_PROJECT_ID and default credentials (compatible with GOOGLE_APPLICATION_CREDENTIALS).
"""

from typing import Optional
from google.cloud import firestore
from google.api_core import exceptions as gcp_exceptions

from app.config import Settings
from app.utils.logging import get_logger

logger = get_logger(__name__)

# Global client instance (initialized lazily)
_firestore_client: Optional[firestore.AsyncClient] = None


def get_firestore_client(settings: Settings) -> firestore.AsyncClient:
    """Get or create a Firestore async client instance.
    
    Lazily initializes the Firestore async client using the provided settings.
    Subsequent calls return the same client instance.
    
    Args:
        settings: Application settings containing GCP configuration.
        
    Returns:
        Initialized Firestore async client instance.
        
    Raises:
        ValueError: If GCP_PROJECT_ID is not configured.
        Exception: If Firestore client initialization fails.
    """
    global _firestore_client
    
    if _firestore_client is not None:
        return _firestore_client
    
    if not settings.gcp_project_id:
        error_msg = (
            "GCP_PROJECT_ID is not configured. Set it in environment variables or .env file. "
            "For local development, also set GOOGLE_APPLICATION_CREDENTIALS to point to your "
            "service account key JSON file."
        )
        logger.error(error_msg)
        raise ValueError(error_msg)
    
    try:
        logger.info(
            "Initializing Firestore async client",
            extra={"extra_fields": {
                "project_id": settings.gcp_project_id,
                "region": settings.region
            }}
        )
        
        # Initialize Firestore async client with project ID
        # Credentials are automatically discovered from:
        # 1. GOOGLE_APPLICATION_CREDENTIALS environment variable
        # 2. Cloud Run default service account (in production)
        # 3. gcloud auth application-default login (local development)
        _firestore_client = firestore.AsyncClient(project=settings.gcp_project_id)
        
        logger.info("Firestore async client initialized successfully")
        return _firestore_client
        
    except gcp_exceptions.GoogleAPICallError as e:
        error_msg = f"Failed to initialize Firestore client: {str(e)}"
        logger.error(error_msg, exc_info=True)
        raise Exception(error_msg) from e
    except Exception as e:
        error_msg = f"Unexpected error initializing Firestore client: {str(e)}"
        logger.error(error_msg, exc_info=True)
        raise


def reset_firestore_client() -> None:
    """Reset the global Firestore client instance.
    
    Primarily used for testing purposes to allow re-initialization
    with different settings or to clean up resources.
    """
    global _firestore_client
    if _firestore_client is not None:
        logger.info("Resetting Firestore client instance")
        _firestore_client = None
