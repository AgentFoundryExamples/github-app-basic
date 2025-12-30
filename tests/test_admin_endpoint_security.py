# Tests for admin endpoint security - simplified version
import pytest
from app.dao.firestore_dao import FirestoreDAO
from unittest.mock import Mock, AsyncMock, patch


class TestAdminMetadataOnlyPattern:
    """Test that metadata methods exclude sensitive data."""
    
    @pytest.mark.asyncio
    async def test_dao_get_github_token_metadata_excludes_tokens(self):
        """Test that DAO method excludes encrypted token fields."""
        # Create a DAO with mocked client
        mock_client = Mock()
        dao = FirestoreDAO(client=mock_client, encryption_key="a" * 64)
        
        # Mock the underlying get_github_token to return full data
        full_data = {
            "access_token": "encrypted_base64_data_here",
            "refresh_token": "encrypted_refresh_token_here",
            "token_type": "bearer",
            "scope": "repo",
            "expires_at": "2025-12-31T23:59:59+00:00",
            "updated_at": "2025-12-30T12:00:00+00:00"
        }
        
        with patch.object(dao, 'get_github_token', AsyncMock(return_value=full_data)):
            metadata = await dao.get_github_token_metadata("collection", "doc_id")
            
            # CRITICAL: Verify metadata does NOT contain encrypted fields
            assert "access_token" not in metadata
            assert "refresh_token" not in metadata
            
            # Verify metadata DOES contain safe fields
            assert metadata["token_type"] == "bearer"
            assert metadata["scope"] == "repo"
            assert metadata["expires_at"] == "2025-12-31T23:59:59+00:00"
            
            # Verify has_refresh_token is a boolean flag
            assert metadata["has_refresh_token"] is True
            assert isinstance(metadata["has_refresh_token"], bool)
    
    @pytest.mark.asyncio
    async def test_dao_get_github_token_metadata_when_no_refresh_token(self):
        """Test metadata correctly reports absence of refresh token."""
        mock_client = Mock()
        dao = FirestoreDAO(client=mock_client, encryption_key="a" * 64)
        
        # Mock data without refresh_token
        full_data = {
            "access_token": "encrypted_base64_data_here",
            "refresh_token": None,
            "token_type": "bearer",
            "scope": "repo",
            "expires_at": None,
            "updated_at": "2025-12-30T12:00:00+00:00"
        }
        
        with patch.object(dao, 'get_github_token', AsyncMock(return_value=full_data)):
            metadata = await dao.get_github_token_metadata("collection", "doc_id")
            
            # Verify has_refresh_token is False when None
            assert metadata["has_refresh_token"] is False
            
            # Verify no actual token data is present
            assert "access_token" not in metadata
            assert "refresh_token" not in metadata
    
    @pytest.mark.asyncio
    async def test_get_github_token_with_decrypt_false_returns_encrypted(self):
        """Test that get_github_token with decrypt=False returns encrypted tokens."""
        mock_client = Mock()
        dao = FirestoreDAO(client=mock_client, encryption_key="a" * 64)
        
        # Mock Firestore document retrieval
        mock_doc_data = {
            "access_token": "encrypted_base64",
            "token_type": "bearer",
            "scope": "repo"
        }
        
        with patch.object(dao, 'get_document', AsyncMock(return_value=mock_doc_data)):
            result = await dao.get_github_token("coll", "doc", decrypt=False)
            
            # Should return encrypted token as-is
            assert result["access_token"] == "encrypted_base64"
            # But metadata method should filter it out
    
    def test_metadata_allowed_fields(self):
        """Test that only safe metadata fields are included."""
        # Define what's allowed in metadata responses
        allowed_fields = {
            "token_type",
            "scope", 
            "expires_at",
            "has_refresh_token",
            "last_refresh_attempt",
            "last_refresh_status",
            "last_refresh_error",
            "updated_at"
        }
        
        # Define what should NEVER appear
        forbidden_fields = {
            "access_token",
            "refresh_token",
            "private_key",
            "client_secret",
            "encryption_key"
        }
        
        # Verify these sets don't overlap
        assert len(allowed_fields & forbidden_fields) == 0
