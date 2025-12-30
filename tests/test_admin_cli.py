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
"""Tests for show_token_metadata CLI script."""

import sys
import os
import pytest
from unittest.mock import Mock, patch, AsyncMock
import json

# Import script module
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent.parent))
from scripts import show_token_metadata


class TestShowTokenMetadataCLI:
    """Test suite for show_token_metadata CLI script."""
    
    @pytest.mark.asyncio
    async def test_get_token_metadata_success(self):
        """Test successful metadata retrieval."""
        mock_client = Mock()
        mock_doc = Mock()
        mock_doc.exists = True
        mock_doc.to_dict.return_value = {
            "access_token": "encrypted_token",
            "token_type": "bearer",
            "scope": "repo,user",
            "expires_at": "2025-12-31T23:59:59+00:00",
            "refresh_token": "encrypted_refresh",
            "updated_at": "2025-12-30T12:00:00+00:00"
        }
        
        mock_doc_ref = Mock()
        mock_doc_ref.get = AsyncMock(return_value=mock_doc)
        mock_collection = Mock()
        mock_collection.document.return_value = mock_doc_ref
        mock_client.collection.return_value = mock_collection
        
        result = await show_token_metadata.get_token_metadata(
            mock_client, "github_tokens", "primary_user"
        )
        
        assert result is not None
        assert result["token_type"] == "bearer"
        assert result["scope"] == "repo,user"
        assert result["expires_at"] == "2025-12-31T23:59:59+00:00"
        assert result["has_refresh_token"] is True
        assert result["updated_at"] == "2025-12-30T12:00:00+00:00"
        
        # Verify sensitive fields are NOT included
        assert "access_token" not in result
        assert "refresh_token" not in result
    
    @pytest.mark.asyncio
    async def test_get_token_metadata_not_found(self):
        """Test metadata retrieval when document doesn't exist."""
        mock_client = Mock()
        mock_doc = Mock()
        mock_doc.exists = False
        
        mock_doc_ref = Mock()
        mock_doc_ref.get = AsyncMock(return_value=mock_doc)
        mock_collection = Mock()
        mock_collection.document.return_value = mock_doc_ref
        mock_client.collection.return_value = mock_collection
        
        result = await show_token_metadata.get_token_metadata(
            mock_client, "github_tokens", "primary_user"
        )
        
        assert result is None
    
    def test_format_metadata_human(self):
        """Test human-readable formatting."""
        metadata = {
            "token_type": "bearer",
            "scope": "repo,user:email",
            "expires_at": "2025-12-31T23:59:59+00:00",
            "has_refresh_token": True,
            "updated_at": "2025-12-30T12:00:00+00:00"
        }
        
        result = show_token_metadata.format_metadata_human(metadata)
        
        assert "GitHub Token Metadata" in result
        assert "bearer" in result
        assert "repo,user:email" in result
        assert "2025-12-31T23:59:59+00:00" in result
        assert "True" in result
    
    def test_format_metadata_with_none_values(self):
        """Test formatting handles None values gracefully."""
        metadata = {
            "token_type": "bearer",
            "scope": None,
            "expires_at": None,
            "has_refresh_token": False,
            "updated_at": "2025-12-30T12:00:00+00:00"
        }
        
        result = show_token_metadata.format_metadata_human(metadata)
        
        assert "bearer" in result
        assert "none" in result.lower() or "None" in result
        assert "False" in result
    
    @pytest.mark.asyncio
    async def test_main_success(self, monkeypatch, capsys):
        """Test main function with successful metadata retrieval."""
        monkeypatch.setenv("GCP_PROJECT_ID", "test-project")
        
        # Mock parse_args
        mock_args = Mock()
        mock_args.collection = "github_tokens"
        mock_args.doc_id = "primary_user"
        mock_args.json = False
        mock_args.quiet = False
        
        with patch.object(show_token_metadata, 'parse_args', return_value=mock_args), \
             patch('google.cloud.firestore.AsyncClient') as mock_client_class:
            
            # Setup mock Firestore client
            mock_client = Mock()
            mock_doc = Mock()
            mock_doc.exists = True
            mock_doc.to_dict.return_value = {
                "token_type": "bearer",
                "scope": "repo",
                "expires_at": None,
                "refresh_token": None,
                "updated_at": "2025-12-30T12:00:00+00:00"
            }
            
            mock_doc_ref = Mock()
            mock_doc_ref.get = AsyncMock(return_value=mock_doc)
            mock_collection = Mock()
            mock_collection.document.return_value = mock_doc_ref
            mock_client.collection.return_value = mock_collection
            
            # Setup async context manager
            mock_client_instance = Mock()
            mock_client_instance.__aenter__ = AsyncMock(return_value=mock_client)
            mock_client_instance.__aexit__ = AsyncMock(return_value=None)
            mock_client_class.return_value = mock_client_instance
            
            exit_code = await show_token_metadata.main()
            
            assert exit_code == 0
            captured = capsys.readouterr()
            assert "GitHub Token Metadata" in captured.out
            assert "bearer" in captured.out
    
    @pytest.mark.asyncio
    async def test_main_json_output(self, monkeypatch, capsys):
        """Test main function with JSON output."""
        monkeypatch.setenv("GCP_PROJECT_ID", "test-project")
        
        mock_args = Mock()
        mock_args.collection = "github_tokens"
        mock_args.doc_id = "primary_user"
        mock_args.json = True
        mock_args.quiet = False
        
        with patch.object(show_token_metadata, 'parse_args', return_value=mock_args), \
             patch('google.cloud.firestore.AsyncClient') as mock_client_class:
            
            mock_client = Mock()
            mock_doc = Mock()
            mock_doc.exists = True
            mock_doc.to_dict.return_value = {
                "token_type": "bearer",
                "scope": "repo,user",
                "expires_at": "2025-12-31T23:59:59+00:00",
                "refresh_token": "encrypted",
                "updated_at": "2025-12-30T12:00:00+00:00"
            }
            
            mock_doc_ref = Mock()
            mock_doc_ref.get = AsyncMock(return_value=mock_doc)
            mock_collection = Mock()
            mock_collection.document.return_value = mock_doc_ref
            mock_client.collection.return_value = mock_collection
            
            mock_client_instance = Mock()
            mock_client_instance.__aenter__ = AsyncMock(return_value=mock_client)
            mock_client_instance.__aexit__ = AsyncMock(return_value=None)
            mock_client_class.return_value = mock_client_instance
            
            exit_code = await show_token_metadata.main()
            
            assert exit_code == 0
            captured = capsys.readouterr()
            
            # Should be valid JSON
            output_data = json.loads(captured.out)
            assert output_data["token_type"] == "bearer"
            assert output_data["scope"] == "repo,user"
            
            # Verify tokens not in output
            assert "access_token" not in output_data
            assert "refresh_token" not in output_data
    
    @pytest.mark.asyncio
    async def test_main_document_not_found(self, monkeypatch, capsys):
        """Test main function when document doesn't exist."""
        monkeypatch.setenv("GCP_PROJECT_ID", "test-project")
        
        mock_args = Mock()
        mock_args.collection = "github_tokens"
        mock_args.doc_id = "primary_user"
        mock_args.json = False
        mock_args.quiet = False
        
        with patch.object(show_token_metadata, 'parse_args', return_value=mock_args), \
             patch('google.cloud.firestore.AsyncClient') as mock_client_class:
            
            mock_client = Mock()
            mock_doc = Mock()
            mock_doc.exists = False
            
            mock_doc_ref = Mock()
            mock_doc_ref.get = AsyncMock(return_value=mock_doc)
            mock_collection = Mock()
            mock_collection.document.return_value = mock_doc_ref
            mock_client.collection.return_value = mock_collection
            
            mock_client_instance = Mock()
            mock_client_instance.__aenter__ = AsyncMock(return_value=mock_client)
            mock_client_instance.__aexit__ = AsyncMock(return_value=None)
            mock_client_class.return_value = mock_client_instance
            
            exit_code = await show_token_metadata.main()
            
            assert exit_code == 1
            captured = capsys.readouterr()
            assert "not found" in captured.err.lower()
    
    @pytest.mark.asyncio
    async def test_main_missing_project_id(self, monkeypatch, capsys):
        """Test main function without GCP_PROJECT_ID."""
        monkeypatch.delenv("GCP_PROJECT_ID", raising=False)
        
        mock_args = Mock()
        mock_args.collection = "github_tokens"
        mock_args.doc_id = "primary_user"
        mock_args.json = False
        mock_args.quiet = False
        
        with patch.object(show_token_metadata, 'parse_args', return_value=mock_args):
            exit_code = await show_token_metadata.main()
            
            assert exit_code == 1
            captured = capsys.readouterr()
            assert "GCP_PROJECT_ID" in captured.err
            assert "required" in captured.err.lower()
    
    @pytest.mark.asyncio
    async def test_main_permission_denied(self, monkeypatch, capsys):
        """Test main function with permission denied error."""
        from google.api_core import exceptions as gcp_exceptions
        
        monkeypatch.setenv("GCP_PROJECT_ID", "test-project")
        
        mock_args = Mock()
        mock_args.collection = "github_tokens"
        mock_args.doc_id = "primary_user"
        mock_args.json = False
        mock_args.quiet = False
        
        with patch.object(show_token_metadata, 'parse_args', return_value=mock_args), \
             patch('google.cloud.firestore.AsyncClient') as mock_client_class:
            
            mock_client = Mock()
            mock_collection = Mock()
            mock_collection.document.side_effect = gcp_exceptions.PermissionDenied("Access denied")
            mock_client.collection.return_value = mock_collection
            
            mock_client_instance = Mock()
            mock_client_instance.__aenter__ = AsyncMock(return_value=mock_client)
            mock_client_instance.__aexit__ = AsyncMock(return_value=None)
            mock_client_class.return_value = mock_client_instance
            
            exit_code = await show_token_metadata.main()
            
            assert exit_code == 1
            captured = capsys.readouterr()
            assert "permission" in captured.err.lower()
            assert "iam" in captured.err.lower() or "roles" in captured.err.lower()
    
    @pytest.mark.asyncio
    async def test_main_authentication_error(self, monkeypatch, capsys):
        """Test main function with authentication error."""
        monkeypatch.setenv("GCP_PROJECT_ID", "test-project")
        
        mock_args = Mock()
        mock_args.collection = "github_tokens"
        mock_args.doc_id = "primary_user"
        mock_args.json = False
        mock_args.quiet = False
        
        with patch.object(show_token_metadata, 'parse_args', return_value=mock_args), \
             patch('google.cloud.firestore.AsyncClient') as mock_client_class:
            
            mock_client_class.side_effect = Exception("Could not find default credentials")
            
            exit_code = await show_token_metadata.main()
            
            assert exit_code == 1
            captured = capsys.readouterr()
            assert "authentication" in captured.err.lower() or "credentials" in captured.err.lower()
    
    def test_parse_args_defaults(self):
        """Test parse_args with default values."""
        with patch('sys.argv', ['show_token_metadata.py']):
            args = show_token_metadata.parse_args()
            
            assert args.collection == "github_tokens"
            assert args.doc_id == "primary_user"
            assert args.json is False
            assert args.quiet is False
    
    def test_parse_args_custom_values(self):
        """Test parse_args with custom values."""
        with patch('sys.argv', [
            'show_token_metadata.py',
            '--collection', 'my_tokens',
            '--doc-id', 'user123',
            '--json',
            '--quiet'
        ]):
            args = show_token_metadata.parse_args()
            
            assert args.collection == "my_tokens"
            assert args.doc_id == "user123"
            assert args.json is True
            assert args.quiet is True
