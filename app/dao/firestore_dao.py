"""Firestore DAO providing async-friendly wrappers for Firestore operations.

This module provides a Data Access Object (DAO) for Firestore operations,
exposing methods like get_document and set_document with typed responses
and structured error handling.
"""

from typing import Optional, Dict, Any
from google.cloud import firestore
from google.api_core import exceptions as gcp_exceptions

from app.utils.logging import get_logger

logger = get_logger(__name__)


class FirestoreDAO:
    """Data Access Object for Firestore operations.
    
    Provides async-friendly wrappers for common Firestore operations
    with proper error handling and logging.
    """
    
    def __init__(self, client: firestore.Client):
        """Initialize FirestoreDAO with a Firestore client.
        
        Args:
            client: Initialized Firestore client instance.
        """
        self.client = client
    
    async def get_document(
        self, 
        collection: str, 
        doc_id: str
    ) -> Optional[Dict[str, Any]]:
        """Retrieve a document from Firestore.
        
        Args:
            collection: Name of the Firestore collection.
            doc_id: Document ID to retrieve.
            
        Returns:
            Dictionary containing document data if found, None otherwise.
            
        Raises:
            PermissionError: If access is denied due to IAM permissions.
            Exception: For other Firestore errors.
        """
        try:
            logger.info(
                f"Retrieving document from Firestore",
                extra={"extra_fields": {
                    "collection": collection,
                    "doc_id": doc_id
                }}
            )
            
            doc_ref = self.client.collection(collection).document(doc_id)
            doc = doc_ref.get()
            
            if doc.exists:
                logger.info(
                    f"Document retrieved successfully",
                    extra={"extra_fields": {
                        "collection": collection,
                        "doc_id": doc_id
                    }}
                )
                return doc.to_dict()
            else:
                logger.info(
                    f"Document not found",
                    extra={"extra_fields": {
                        "collection": collection,
                        "doc_id": doc_id
                    }}
                )
                return None
                
        except gcp_exceptions.PermissionDenied as e:
            error_msg = (
                f"Permission denied accessing Firestore collection '{collection}'. "
                f"Ensure the service account has proper IAM roles "
                f"(roles/datastore.user or roles/datastore.owner)."
            )
            logger.error(error_msg, exc_info=True)
            raise PermissionError(error_msg) from e
            
        except gcp_exceptions.GoogleAPICallError as e:
            error_msg = (
                f"Firestore API error retrieving document '{doc_id}' "
                f"from collection '{collection}': {str(e)}"
            )
            logger.error(error_msg, exc_info=True)
            raise Exception(error_msg) from e
            
        except Exception as e:
            error_msg = (
                f"Unexpected error retrieving document '{doc_id}' "
                f"from collection '{collection}': {str(e)}"
            )
            logger.error(error_msg, exc_info=True)
            raise
    
    async def set_document(
        self,
        collection: str,
        doc_id: str,
        data: Dict[str, Any],
        merge: bool = False
    ) -> Dict[str, Any]:
        """Set or update a document in Firestore.
        
        Args:
            collection: Name of the Firestore collection.
            doc_id: Document ID to set/update.
            data: Dictionary containing document data to persist.
            merge: If True, merge with existing document. If False, overwrite.
            
        Returns:
            Dictionary containing the persisted data.
            
        Raises:
            ValueError: If data is empty or invalid.
            PermissionError: If access is denied due to IAM permissions.
            Exception: For other Firestore errors.
        """
        if not data:
            raise ValueError("Cannot set document with empty data")
        
        try:
            logger.info(
                f"Setting document in Firestore",
                extra={"extra_fields": {
                    "collection": collection,
                    "doc_id": doc_id,
                    "merge": merge,
                    "data_keys": list(data.keys())
                }}
            )
            
            doc_ref = self.client.collection(collection).document(doc_id)
            doc_ref.set(data, merge=merge)
            
            logger.info(
                f"Document set successfully",
                extra={"extra_fields": {
                    "collection": collection,
                    "doc_id": doc_id
                }}
            )
            
            return data
            
        except gcp_exceptions.PermissionDenied as e:
            error_msg = (
                f"Permission denied writing to Firestore collection '{collection}'. "
                f"Ensure the service account has proper IAM roles "
                f"(roles/datastore.user or roles/datastore.owner)."
            )
            logger.error(error_msg, exc_info=True)
            raise PermissionError(error_msg) from e
            
        except gcp_exceptions.GoogleAPICallError as e:
            error_msg = (
                f"Firestore API error setting document '{doc_id}' "
                f"in collection '{collection}': {str(e)}"
            )
            logger.error(error_msg, exc_info=True)
            raise Exception(error_msg) from e
            
        except Exception as e:
            error_msg = (
                f"Unexpected error setting document '{doc_id}' "
                f"in collection '{collection}': {str(e)}"
            )
            logger.error(error_msg, exc_info=True)
            raise
