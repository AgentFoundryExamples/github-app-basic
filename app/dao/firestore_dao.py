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
"""Firestore DAO providing async-friendly wrappers for Firestore operations.

This module provides a Data Access Object (DAO) for Firestore operations,
exposing methods like get_document and set_document with typed responses
and structured error handling. It also provides encrypted token storage
for GitHub OAuth tokens.
"""

import base64
from datetime import datetime, timezone
from typing import Optional, Dict, Any
from google.cloud import firestore
from google.api_core import exceptions as gcp_exceptions
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import padding
import secrets

from app.utils.logging import get_logger, mask_sensitive_data

logger = get_logger(__name__)


class FirestoreDAO:
    """Data Access Object for Firestore operations.
    
    Provides async-friendly wrappers for common Firestore operations
    with proper error handling and logging. Includes support for
    encrypted GitHub token storage.
    """
    
    def __init__(self, client: firestore.AsyncClient, encryption_key: Optional[str] = None):
        """Initialize FirestoreDAO with a Firestore async client.
        
        Args:
            client: Initialized Firestore async client instance.
            encryption_key: Optional hex-encoded encryption key for token encryption (32 bytes).
        """
        self.client = client
        self._encryption_key_bytes: Optional[bytes] = None
        
        if encryption_key:
            try:
                self._encryption_key_bytes = bytes.fromhex(encryption_key)
                if len(self._encryption_key_bytes) != 32:
                    raise ValueError(f"Encryption key must be 32 bytes, got {len(self._encryption_key_bytes)}")
                logger.info("Encryption key configured for token storage")
            except ValueError as e:
                error_msg = f"Invalid encryption key format: {str(e)}"
                logger.error(error_msg)
                raise ValueError(error_msg) from e
    
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
            doc = await doc_ref.get()
            
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
            await doc_ref.set(data, merge=merge)
            
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
    
    def _encrypt_token(self, token: str) -> str:
        """Encrypt a token using AES-256-CBC.
        
        Args:
            token: The plaintext token to encrypt.
            
        Returns:
            Base64-encoded encrypted token with IV prepended.
            
        Raises:
            ValueError: If encryption key is not configured.
        """
        if not self._encryption_key_bytes:
            raise ValueError(
                "Encryption key not configured. Set GITHUB_TOKEN_ENCRYPTION_KEY environment variable."
            )
        
        # Generate random IV (16 bytes for AES)
        iv = secrets.token_bytes(16)
        
        # Create cipher
        cipher = Cipher(
            algorithms.AES(self._encryption_key_bytes),
            modes.CBC(iv),
            backend=default_backend()
        )
        encryptor = cipher.encryptor()
        
        # Apply PKCS7 padding
        padder = padding.PKCS7(128).padder()
        padded_data = padder.update(token.encode('utf-8')) + padder.finalize()
        
        # Encrypt
        encrypted = encryptor.update(padded_data) + encryptor.finalize()
        
        # Prepend IV to encrypted data and base64 encode
        combined = iv + encrypted
        return base64.b64encode(combined).decode('utf-8')
    
    def _decrypt_token(self, encrypted_token: str) -> str:
        """Decrypt a token using AES-256-CBC.
        
        Args:
            encrypted_token: Base64-encoded encrypted token with IV prepended.
            
        Returns:
            Decrypted plaintext token.
            
        Raises:
            ValueError: If encryption key is not configured or decryption fails.
        """
        if not self._encryption_key_bytes:
            raise ValueError(
                "Encryption key not configured. Set GITHUB_TOKEN_ENCRYPTION_KEY environment variable."
            )
        
        try:
            # Decode from base64
            combined = base64.b64decode(encrypted_token)
            
            # Extract IV (first 16 bytes) and encrypted data
            iv = combined[:16]
            encrypted = combined[16:]
            
            # Create cipher
            cipher = Cipher(
                algorithms.AES(self._encryption_key_bytes),
                modes.CBC(iv),
                backend=default_backend()
            )
            decryptor = cipher.decryptor()
            
            # Decrypt
            padded_data = decryptor.update(encrypted) + decryptor.finalize()
            
            # Remove PKCS7 padding
            unpadder = padding.PKCS7(128).unpadder()
            data = unpadder.update(padded_data) + unpadder.finalize()
            
            return data.decode('utf-8')
        except Exception as e:
            error_msg = f"Failed to decrypt token: {str(e)}"
            logger.error(error_msg)
            raise ValueError(error_msg) from e
    
    async def save_github_token(
        self,
        collection: str,
        doc_id: str,
        access_token: str,
        token_type: str = "bearer",
        scope: Optional[str] = None,
        expires_at: Optional[datetime] = None,
        refresh_token: Optional[str] = None
    ) -> Dict[str, Any]:
        """Save GitHub OAuth token with encryption.
        
        Args:
            collection: Firestore collection name.
            doc_id: Document ID for the token.
            access_token: GitHub access token to encrypt and store.
            token_type: Token type (typically "bearer").
            scope: OAuth scopes granted.
            expires_at: Token expiration time (timezone-aware).
            refresh_token: Optional refresh token (also encrypted).
            
        Returns:
            Dictionary containing the persisted metadata (without decrypted tokens).
            
        Raises:
            ValueError: If encryption key is not configured or data is invalid.
            PermissionError: If Firestore access is denied.
            Exception: For other Firestore errors.
        """
        if not access_token:
            raise ValueError("access_token is required")
        
        # Encrypt the access token
        encrypted_access_token = self._encrypt_token(access_token)
        
        # Encrypt refresh token if provided
        encrypted_refresh_token = None
        if refresh_token:
            encrypted_refresh_token = self._encrypt_token(refresh_token)
        
        # Build document data
        now_utc = datetime.now(timezone.utc)
        data = {
            "access_token": encrypted_access_token,
            "token_type": token_type,
            "scope": scope,
            "expires_at": expires_at.isoformat() if expires_at else None,
            "refresh_token": encrypted_refresh_token,
            "updated_at": now_utc.isoformat()
        }
        
        logger.info(
            "Saving GitHub token to Firestore",
            extra={"extra_fields": {
                "collection": collection,
                "doc_id": doc_id,
                "token_type": token_type,
                "scope": scope,
                "has_refresh_token": refresh_token is not None,
                "access_token_preview": mask_sensitive_data(access_token, 4)
            }}
        )
        
        # Save to Firestore
        await self.set_document(collection, doc_id, data, merge=False)
        
        # Return metadata without decrypted tokens
        return {
            "token_type": token_type,
            "scope": scope,
            "expires_at": data["expires_at"],
            "has_refresh_token": refresh_token is not None,
            "updated_at": data["updated_at"]
        }
    
    async def get_github_token(
        self,
        collection: str,
        doc_id: str,
        decrypt: bool = True
    ) -> Optional[Dict[str, Any]]:
        """Retrieve GitHub OAuth token with optional decryption.
        
        Args:
            collection: Firestore collection name.
            doc_id: Document ID for the token.
            decrypt: If True, decrypt the access_token and refresh_token.
            
        Returns:
            Dictionary containing token data, or None if not found.
            If decrypt=True, includes decrypted "access_token" and "refresh_token".
            If decrypt=False, includes encrypted values as-is.
            
        Raises:
            ValueError: If decryption fails.
            PermissionError: If Firestore access is denied.
            Exception: For other Firestore errors.
        """
        logger.info(
            "Retrieving GitHub token from Firestore",
            extra={"extra_fields": {
                "collection": collection,
                "doc_id": doc_id,
                "decrypt": decrypt
            }}
        )
        
        data = await self.get_document(collection, doc_id)
        
        if not data:
            return None
        
        if decrypt:
            # Decrypt access token
            encrypted_access_token = data.get("access_token")
            if encrypted_access_token:
                data["access_token"] = self._decrypt_token(encrypted_access_token)
            
            # Decrypt refresh token if present
            encrypted_refresh_token = data.get("refresh_token")
            if encrypted_refresh_token:
                data["refresh_token"] = self._decrypt_token(encrypted_refresh_token)
        
        return data
    
    async def get_github_token_metadata(
        self,
        collection: str,
        doc_id: str
    ) -> Optional[Dict[str, Any]]:
        """Retrieve GitHub token metadata without decryption.
        
        Useful for admin endpoints or health checks that need to verify
        token existence without exposing sensitive data.
        
        Args:
            collection: Firestore collection name.
            doc_id: Document ID for the token.
            
        Returns:
            Dictionary containing metadata (token_type, scope, expires_at, updated_at),
            or None if not found. Does not include decrypted tokens.
            
        Raises:
            PermissionError: If Firestore access is denied.
            Exception: For other Firestore errors.
        """
        data = await self.get_github_token(collection, doc_id, decrypt=False)
        
        if not data:
            return None
        
        # Return only metadata fields, excluding encrypted tokens
        return {
            "token_type": data.get("token_type"),
            "scope": data.get("scope"),
            "expires_at": data.get("expires_at"),
            "has_refresh_token": data.get("refresh_token") is not None,
            "updated_at": data.get("updated_at")
        }
