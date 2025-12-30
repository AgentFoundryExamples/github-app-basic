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
from cryptography.exceptions import InvalidTag
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
        """Encrypt a token using AES-256-GCM.
        
        Args:
            token: The plaintext token to encrypt.
            
        Returns:
            Base64-encoded string containing nonce, ciphertext, and tag.
            
        Raises:
            ValueError: If encryption key is not configured.
        """
        if not self._encryption_key_bytes:
            raise ValueError(
                "Encryption key not configured. Set GITHUB_TOKEN_ENCRYPTION_KEY environment variable."
            )
        
        # Generate a random 96-bit nonce as recommended for GCM
        nonce = secrets.token_bytes(12)
        
        # Create cipher
        cipher = Cipher(
            algorithms.AES(self._encryption_key_bytes),
            modes.GCM(nonce),
            backend=default_backend()
        )
        encryptor = cipher.encryptor()
        
        # Encrypt
        encrypted = encryptor.update(token.encode('utf-8')) + encryptor.finalize()
        
        # Prepend nonce and append tag, then base64 encode
        combined = nonce + encrypted + encryptor.tag
        return base64.b64encode(combined).decode('utf-8')
    
    def _decrypt_token(self, encrypted_token: str) -> str:
        """Decrypt a token using AES-256-GCM.
        
        Args:
            encrypted_token: Base64-encoded string containing nonce, ciphertext, and tag.
            
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
            
            # Validate minimum length (12 bytes nonce + 16 bytes tag)
            if len(combined) < 28:
                raise ValueError(
                    f"Encrypted data too short: expected at least 28 bytes, got {len(combined)}"
                )
            
            # Extract nonce, ciphertext, and tag
            nonce = combined[:12]
            tag = combined[-16:]
            encrypted = combined[12:-16]
            
            # Create cipher
            cipher = Cipher(
                algorithms.AES(self._encryption_key_bytes),
                modes.GCM(nonce, tag),
                backend=default_backend()
            )
            decryptor = cipher.decryptor()
            
            # Decrypt
            data = decryptor.update(encrypted) + decryptor.finalize()
            
            return data.decode('utf-8')
        except (ValueError, InvalidTag, TypeError) as e:
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
        refresh_token: Optional[str] = None,
        last_refresh_attempt: Optional[datetime] = None,
        last_refresh_status: Optional[str] = None,
        last_refresh_error: Optional[str] = None
    ) -> Dict[str, Any]:
        """Save GitHub OAuth token with encryption and refresh metadata.
        
        Args:
            collection: Firestore collection name.
            doc_id: Document ID for the token.
            access_token: GitHub access token to encrypt and store.
            token_type: Token type (typically "bearer").
            scope: OAuth scopes granted.
            expires_at: Token expiration time (must be timezone-aware).
            refresh_token: Optional refresh token (also encrypted).
            last_refresh_attempt: Timestamp of last refresh attempt (must be timezone-aware if provided).
            last_refresh_status: Status of last refresh attempt (e.g., "success", "failed", "pending").
            last_refresh_error: Error message from last refresh attempt if it failed.
            
        Returns:
            Dictionary containing the persisted metadata (without decrypted tokens).
            
        Raises:
            ValueError: If encryption key is not configured or data is invalid.
            PermissionError: If Firestore access is denied.
            Exception: For other Firestore errors.
        """
        if not access_token:
            raise ValueError("access_token is required")
        
        # Validate expires_at is timezone-aware if provided
        if expires_at is not None and expires_at.tzinfo is None:
            raise ValueError(
                "expires_at must be timezone-aware. Use datetime.now(timezone.utc) or "
                "ensure your datetime object has tzinfo set."
            )
        
        # Validate last_refresh_attempt is timezone-aware if provided
        if last_refresh_attempt is not None and last_refresh_attempt.tzinfo is None:
            raise ValueError(
                "last_refresh_attempt must be timezone-aware. Use datetime.now(timezone.utc) or "
                "ensure your datetime object has tzinfo set."
            )
        
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
            "last_refresh_attempt": last_refresh_attempt.isoformat() if last_refresh_attempt else None,
            "last_refresh_status": last_refresh_status,
            "last_refresh_error": last_refresh_error,
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
                "last_refresh_status": last_refresh_status,
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
            "last_refresh_attempt": data["last_refresh_attempt"],
            "last_refresh_status": last_refresh_status,
            "last_refresh_error": last_refresh_error,
            "updated_at": data["updated_at"]
        }
    
    async def get_github_token(
        self,
        collection: str,
        doc_id: str,
        decrypt: bool = True
    ) -> Optional[Dict[str, Any]]:
        """Retrieve GitHub OAuth token with optional decryption.
        
        Handles legacy documents missing new metadata fields by providing safe defaults.
        
        Args:
            collection: Firestore collection name.
            doc_id: Document ID for the token.
            decrypt: If True, decrypt the access_token and refresh_token.
            
        Returns:
            Dictionary containing token data, or None if not found.
            If decrypt=True, includes decrypted "access_token" and "refresh_token".
            If decrypt=False, includes encrypted values as-is.
            Legacy documents without refresh metadata will have None for those fields.
            
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
        
        # Provide safe defaults for legacy documents missing new fields
        data.setdefault("last_refresh_attempt", None)
        data.setdefault("last_refresh_status", None)
        data.setdefault("last_refresh_error", None)
        
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
            Dictionary containing metadata (token_type, scope, expires_at, updated_at,
            last_refresh_attempt, last_refresh_status, last_refresh_error),
            or None if not found. Does not include decrypted tokens.
            Legacy documents will have None for missing refresh metadata fields.
            
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
            "last_refresh_attempt": data.get("last_refresh_attempt"),
            "last_refresh_status": data.get("last_refresh_status"),
            "last_refresh_error": data.get("last_refresh_error"),
            "updated_at": data.get("updated_at")
        }
    
    @staticmethod
    def parse_iso_datetime(iso_string: Optional[str]) -> Optional[datetime]:
        """Parse ISO 8601 datetime string to timezone-aware datetime.
        
        Args:
            iso_string: ISO 8601 formatted datetime string (e.g., "2025-12-31T23:59:59+00:00").
            
        Returns:
            Timezone-aware datetime object, or None if input is None or invalid.
        """
        if not iso_string:
            return None
        
        try:
            # Parse ISO format - fromisoformat handles timezone info
            dt = datetime.fromisoformat(iso_string)
            
            # Ensure timezone-aware - if naive, assume UTC
            if dt.tzinfo is None:
                dt = dt.replace(tzinfo=timezone.utc)
            
            return dt
        except (ValueError, TypeError) as e:
            logger.warning(
                f"Failed to parse datetime string: {iso_string}",
                extra={"extra_fields": {"error": str(e)}}
            )
            return None
    
    @staticmethod
    def is_token_near_expiry(
        expires_at: Optional[datetime],
        threshold_minutes: int,
        current_time: Optional[datetime] = None
    ) -> bool:
        """Check if a token is near expiry based on configured threshold.
        
        A token is considered near-expiry if:
        - It has an expires_at datetime AND
        - The time until expiry is less than or equal to threshold_minutes
        
        Tokens without expires_at are considered non-expiring and return False.
        
        Args:
            expires_at: Token expiration datetime (must be timezone-aware if provided).
            threshold_minutes: Minutes before expiry to consider token near-expiry.
            current_time: Optional current time for testing. Defaults to datetime.now(timezone.utc).
            
        Returns:
            True if token is near expiry, False if not near expiry or non-expiring.
            
        Raises:
            ValueError: If expires_at is provided but not timezone-aware.
        """
        # Non-expiring tokens (missing expires_at) are never near expiry
        if expires_at is None:
            return False
        
        # Validate timezone-aware
        if expires_at.tzinfo is None:
            raise ValueError("expires_at must be timezone-aware")
        
        # Get current time
        now = current_time if current_time is not None else datetime.now(timezone.utc)
        
        # Validate current_time is timezone-aware
        if now.tzinfo is None:
            raise ValueError("current_time must be timezone-aware")
        
        # Calculate time until expiry
        time_until_expiry = expires_at - now
        
        # Convert threshold to timedelta
        from datetime import timedelta
        threshold = timedelta(minutes=threshold_minutes)
        
        # Token is near expiry if time remaining <= threshold
        return time_until_expiry <= threshold
    
    @staticmethod
    def is_token_expired(
        expires_at: Optional[datetime],
        current_time: Optional[datetime] = None
    ) -> bool:
        """Check if a token has already expired.
        
        Args:
            expires_at: Token expiration datetime (must be timezone-aware if provided).
            current_time: Optional current time for testing. Defaults to datetime.now(timezone.utc).
            
        Returns:
            True if token is expired, False if not expired or non-expiring.
            
        Raises:
            ValueError: If expires_at is provided but not timezone-aware.
        """
        # Non-expiring tokens (missing expires_at) never expire
        if expires_at is None:
            return False
        
        # Validate timezone-aware
        if expires_at.tzinfo is None:
            raise ValueError("expires_at must be timezone-aware")
        
        # Get current time
        now = current_time if current_time is not None else datetime.now(timezone.utc)
        
        # Validate current_time is timezone-aware
        if now.tzinfo is None:
            raise ValueError("current_time must be timezone-aware")
        
        # Token is expired if current time >= expiry time
        return now >= expires_at
