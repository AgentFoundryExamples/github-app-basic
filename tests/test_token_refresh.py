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
"""Tests for GitHub token refresh workflows."""

import pytest
from unittest.mock import Mock, patch, AsyncMock
from datetime import datetime, timezone, timedelta

from app.services.github import (
    GitHubAppJWT,
    GitHubTokenRefreshManager,
    GitHubTokenRefreshError,
    GitHubTokenRefreshCooldownError
)


def generate_test_private_key() -> str:
    """Generate a test RSA private key for testing."""
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.backends import default_backend
    
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )
    
    private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    ).decode('utf-8')
    
    return private_pem


class TestTokenRefreshWithRefreshToken:
    """Test suite for token refresh using refresh_token grant."""
    
    @pytest.fixture
    def github_app_jwt(self):
        """Create a GitHubAppJWT instance for testing."""
        private_key = generate_test_private_key()
        return GitHubAppJWT(app_id="12345", private_key_pem=private_key)
    
    @pytest.fixture
    def current_token_data(self):
        """Create sample current token data."""
        return {
            "access_token": "gho_old_token_123",
            "token_type": "bearer",
            "scope": "repo,user",
            "expires_at": (datetime.now(timezone.utc) + timedelta(minutes=5)).isoformat(),
            "refresh_token": "ghr_refresh_token_xyz",
            "last_refresh_attempt": None,
            "last_refresh_status": None,
            "last_refresh_error": None
        }
    
    @pytest.mark.asyncio
    async def test_refresh_with_valid_refresh_token_success(self, github_app_jwt, current_token_data):
        """Test successful token refresh using refresh_token grant."""
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.json.return_value = {
            "access_token": "gho_new_token_456",
            "token_type": "bearer",
            "scope": "repo,user",
            "expires_in": 28800,
            "refresh_token": "ghr_new_refresh_token_abc"
        }
        
        with patch('httpx.AsyncClient') as mock_client:
            mock_client.return_value.__aenter__.return_value.post = AsyncMock(
                return_value=mock_response
            )
            
            result = await GitHubTokenRefreshManager.refresh_user_token(
                current_token_data=current_token_data,
                github_app_jwt=github_app_jwt,
                client_id="test_client_id",
                client_secret="test_client_secret",
                cooldown_seconds=300
            )
        
        assert result["access_token"] == "gho_new_token_456"
        assert result["token_type"] == "bearer"
        assert result["refresh_token"] == "ghr_new_refresh_token_abc"
        assert result["refresh_status"] == "success"
        assert result["refresh_method"] == "refresh_grant"
    
    @pytest.mark.asyncio
    async def test_refresh_without_new_refresh_token(self, github_app_jwt, current_token_data):
        """Test refresh when GitHub doesn't return new refresh_token."""
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.json.return_value = {
            "access_token": "gho_new_token_456",
            "token_type": "bearer",
            "scope": "repo,user",
            "expires_in": 28800
            # No refresh_token in response
        }
        
        with patch('httpx.AsyncClient') as mock_client:
            mock_client.return_value.__aenter__.return_value.post = AsyncMock(
                return_value=mock_response
            )
            
            result = await GitHubTokenRefreshManager.refresh_user_token(
                current_token_data=current_token_data,
                github_app_jwt=github_app_jwt,
                client_id="test_client_id",
                client_secret="test_client_secret"
            )
        
        assert result["access_token"] == "gho_new_token_456"
        assert "refresh_token" not in result
        assert result["refresh_status"] == "success"
    
    @pytest.mark.asyncio
    async def test_refresh_with_401_raises_error(self, github_app_jwt, current_token_data):
        """Test that 401 response raises error without fallback."""
        mock_response = Mock()
        mock_response.status_code = 401
        mock_response.text = "Unauthorized"
        
        with patch('httpx.AsyncClient') as mock_client:
            mock_client.return_value.__aenter__.return_value.post = AsyncMock(
                return_value=mock_response
            )
            
            # 401 should raise immediately without attempting fallback
            with pytest.raises(GitHubTokenRefreshError, match="status 401"):
                await GitHubTokenRefreshManager.refresh_user_token(
                    current_token_data=current_token_data,
                    github_app_jwt=github_app_jwt,
                    client_id="test_client_id",
                    client_secret="test_client_secret"
                )
    
    @pytest.mark.asyncio
    async def test_refresh_with_422_raises_error(self, github_app_jwt, current_token_data):
        """Test that 422 response raises error without fallback."""
        mock_response = Mock()
        mock_response.status_code = 422
        mock_response.text = "Unprocessable Entity"
        
        with patch('httpx.AsyncClient') as mock_client:
            mock_client.return_value.__aenter__.return_value.post = AsyncMock(
                return_value=mock_response
            )
            
            # 422 should raise immediately without attempting fallback
            with pytest.raises(GitHubTokenRefreshError, match="status 422"):
                await GitHubTokenRefreshManager.refresh_user_token(
                    current_token_data=current_token_data,
                    github_app_jwt=github_app_jwt,
                    client_id="test_client_id",
                    client_secret="test_client_secret"
                )
    
    @pytest.mark.asyncio
    async def test_refresh_with_missing_access_token_raises_error(self, github_app_jwt, current_token_data):
        """Test that missing access_token in response raises error."""
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.json.return_value = {
            "token_type": "bearer",
            "scope": "repo"
            # Missing access_token
        }
        
        with patch('httpx.AsyncClient') as mock_client:
            mock_client.return_value.__aenter__.return_value.post = AsyncMock(
                return_value=mock_response
            )
            
            with pytest.raises(GitHubTokenRefreshError, match="missing access_token"):
                await GitHubTokenRefreshManager.refresh_user_token(
                    current_token_data=current_token_data,
                    github_app_jwt=github_app_jwt,
                    client_id="test_client_id",
                    client_secret="test_client_secret"
                )
    
    @pytest.mark.asyncio
    async def test_refresh_with_github_error_response(self, github_app_jwt, current_token_data):
        """Test refresh handles GitHub error responses with fallback to reissue."""
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.json.return_value = {
            "error": "invalid_grant",
            "error_description": "The refresh token is invalid or expired"
        }
        
        with patch('httpx.AsyncClient') as mock_client:
            mock_client.return_value.__aenter__.return_value.post = AsyncMock(
                return_value=mock_response
            )
            
            # Since refresh_token is invalid, should attempt reissue
            # Reissue is not implemented, so should wrap in GitHubTokenRefreshError
            with pytest.raises(GitHubTokenRefreshError, match="Token reissue failed"):
                await GitHubTokenRefreshManager.refresh_user_token(
                    current_token_data=current_token_data,
                    github_app_jwt=github_app_jwt,
                    client_id="test_client_id",
                    client_secret="test_client_secret"
                )


class TestTokenRefreshFallbackToReissue:
    """Test suite for token refresh fallback to reissue method."""
    
    @pytest.fixture
    def github_app_jwt(self):
        """Create a GitHubAppJWT instance for testing."""
        private_key = generate_test_private_key()
        return GitHubAppJWT(app_id="12345", private_key_pem=private_key)
    
    @pytest.fixture
    def token_data_without_refresh_token(self):
        """Create token data without refresh_token."""
        return {
            "access_token": "gho_old_token_123",
            "token_type": "bearer",
            "scope": "repo,user",
            "expires_at": (datetime.now(timezone.utc) + timedelta(minutes=5)).isoformat(),
            "refresh_token": None,
            "last_refresh_attempt": None,
            "last_refresh_status": None,
            "last_refresh_error": None
        }
    
    @pytest.mark.asyncio
    async def test_refresh_without_refresh_token_attempts_reissue(
        self, github_app_jwt, token_data_without_refresh_token
    ):
        """Test that missing refresh_token triggers reissue attempt."""
        # Reissue is not fully implemented, so should wrap NotImplementedError
        with pytest.raises(GitHubTokenRefreshError, match="Token reissue failed"):
            await GitHubTokenRefreshManager.refresh_user_token(
                current_token_data=token_data_without_refresh_token,
                github_app_jwt=github_app_jwt,
                client_id="test_client_id",
                client_secret="test_client_secret"
            )
    
    @pytest.mark.asyncio
    async def test_refresh_with_revoked_token_falls_back_to_reissue(self, github_app_jwt):
        """Test that revoked refresh_token falls back to reissue."""
        token_data = {
            "access_token": "gho_old_token_123",
            "token_type": "bearer",
            "refresh_token": "ghr_revoked_token",
            "last_refresh_attempt": None,
            "last_refresh_status": None,
            "last_refresh_error": None
        }
        
        # Mock refresh_token call returning revoked error
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.json.return_value = {
            "error": "invalid_grant",
            "error_description": "The refresh token has been revoked"
        }
        
        with patch('httpx.AsyncClient') as mock_client:
            mock_client.return_value.__aenter__.return_value.post = AsyncMock(
                return_value=mock_response
            )
            
            # Should fall back to reissue, which wraps NotImplementedError
            with pytest.raises(GitHubTokenRefreshError, match="Token reissue failed"):
                await GitHubTokenRefreshManager.refresh_user_token(
                    current_token_data=token_data,
                    github_app_jwt=github_app_jwt,
                    client_id="test_client_id",
                    client_secret="test_client_secret"
                )


class TestTokenRefreshCooldown:
    """Test suite for token refresh cooldown enforcement."""
    
    @pytest.fixture
    def github_app_jwt(self):
        """Create a GitHubAppJWT instance for testing."""
        private_key = generate_test_private_key()
        return GitHubAppJWT(app_id="12345", private_key_pem=private_key)
    
    @pytest.fixture
    def token_data_recent_failure(self):
        """Create token data with recent refresh failure."""
        last_attempt = datetime.now(timezone.utc) - timedelta(seconds=60)  # 60 seconds ago
        return {
            "access_token": "gho_old_token_123",
            "token_type": "bearer",
            "refresh_token": "ghr_refresh_token_xyz",
            "last_refresh_attempt": last_attempt.isoformat(),
            "last_refresh_status": "failed",
            "last_refresh_error": "GitHub API error"
        }
    
    @pytest.mark.asyncio
    async def test_cooldown_blocks_refresh_after_recent_failure(
        self, github_app_jwt, token_data_recent_failure
    ):
        """Test that cooldown blocks refresh within cooldown period."""
        with pytest.raises(GitHubTokenRefreshCooldownError) as exc_info:
            await GitHubTokenRefreshManager.refresh_user_token(
                current_token_data=token_data_recent_failure,
                github_app_jwt=github_app_jwt,
                client_id="test_client_id",
                client_secret="test_client_secret",
                cooldown_seconds=300  # 5 minutes
            )
        
        assert "too soon" in str(exc_info.value).lower()
        assert hasattr(exc_info.value, "seconds_until_retry")
        assert exc_info.value.seconds_until_retry > 0
    
    @pytest.mark.asyncio
    async def test_force_refresh_bypasses_cooldown(self, github_app_jwt, token_data_recent_failure):
        """Test that force_refresh bypasses cooldown check."""
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.json.return_value = {
            "access_token": "gho_new_token_456",
            "token_type": "bearer",
            "scope": "repo,user",
            "expires_in": 28800,
            "refresh_token": "ghr_new_refresh_token_abc"
        }
        
        with patch('httpx.AsyncClient') as mock_client:
            mock_client.return_value.__aenter__.return_value.post = AsyncMock(
                return_value=mock_response
            )
            
            # Should succeed despite recent failure because force_refresh=True
            result = await GitHubTokenRefreshManager.refresh_user_token(
                current_token_data=token_data_recent_failure,
                github_app_jwt=github_app_jwt,
                client_id="test_client_id",
                client_secret="test_client_secret",
                cooldown_seconds=300,
                force_refresh=True
            )
        
        assert result["access_token"] == "gho_new_token_456"
        assert result["refresh_status"] == "success"
    
    @pytest.mark.asyncio
    async def test_cooldown_not_enforced_after_success(self, github_app_jwt):
        """Test that cooldown is not enforced after successful refresh."""
        last_attempt = datetime.now(timezone.utc) - timedelta(seconds=60)
        token_data = {
            "access_token": "gho_old_token_123",
            "token_type": "bearer",
            "refresh_token": "ghr_refresh_token_xyz",
            "last_refresh_attempt": last_attempt.isoformat(),
            "last_refresh_status": "success",  # Last attempt was successful
            "last_refresh_error": None
        }
        
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.json.return_value = {
            "access_token": "gho_new_token_456",
            "token_type": "bearer",
            "scope": "repo,user",
            "expires_in": 28800
        }
        
        with patch('httpx.AsyncClient') as mock_client:
            mock_client.return_value.__aenter__.return_value.post = AsyncMock(
                return_value=mock_response
            )
            
            # Should succeed because last attempt was successful (no cooldown)
            result = await GitHubTokenRefreshManager.refresh_user_token(
                current_token_data=token_data,
                github_app_jwt=github_app_jwt,
                client_id="test_client_id",
                client_secret="test_client_secret",
                cooldown_seconds=300
            )
        
        assert result["access_token"] == "gho_new_token_456"
    
    @pytest.mark.asyncio
    async def test_cooldown_allows_refresh_after_period_elapsed(self, github_app_jwt):
        """Test that cooldown allows refresh after cooldown period."""
        # Last attempt was 400 seconds ago (outside 300 second cooldown)
        last_attempt = datetime.now(timezone.utc) - timedelta(seconds=400)
        token_data = {
            "access_token": "gho_old_token_123",
            "token_type": "bearer",
            "refresh_token": "ghr_refresh_token_xyz",
            "last_refresh_attempt": last_attempt.isoformat(),
            "last_refresh_status": "failed",
            "last_refresh_error": "Previous error"
        }
        
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.json.return_value = {
            "access_token": "gho_new_token_456",
            "token_type": "bearer",
            "scope": "repo,user",
            "expires_in": 28800
        }
        
        with patch('httpx.AsyncClient') as mock_client:
            mock_client.return_value.__aenter__.return_value.post = AsyncMock(
                return_value=mock_response
            )
            
            # Should succeed because cooldown period has elapsed
            result = await GitHubTokenRefreshManager.refresh_user_token(
                current_token_data=token_data,
                github_app_jwt=github_app_jwt,
                client_id="test_client_id",
                client_secret="test_client_secret",
                cooldown_seconds=300
            )
        
        assert result["access_token"] == "gho_new_token_456"


class TestTokenRefreshRetryLogic:
    """Test suite for token refresh retry and backoff logic."""
    
    @pytest.fixture
    def github_app_jwt(self):
        """Create a GitHubAppJWT instance for testing."""
        private_key = generate_test_private_key()
        return GitHubAppJWT(app_id="12345", private_key_pem=private_key)
    
    @pytest.fixture
    def token_data(self):
        """Create sample token data."""
        return {
            "access_token": "gho_old_token_123",
            "token_type": "bearer",
            "refresh_token": "ghr_refresh_token_xyz",
            "last_refresh_attempt": None,
            "last_refresh_status": None,
            "last_refresh_error": None
        }
    
    @pytest.mark.asyncio
    async def test_refresh_retries_on_500_error(self, github_app_jwt, token_data):
        """Test that 500 errors trigger retry with backoff."""
        # First two attempts fail with 500, third succeeds
        mock_response_fail = Mock()
        mock_response_fail.status_code = 500
        mock_response_fail.text = "Internal Server Error"
        
        mock_response_success = Mock()
        mock_response_success.status_code = 200
        mock_response_success.json.return_value = {
            "access_token": "gho_new_token_456",
            "token_type": "bearer",
            "scope": "repo,user",
            "expires_in": 28800
        }
        
        call_count = 0
        
        async def mock_post(*args, **kwargs):
            nonlocal call_count
            call_count += 1
            if call_count < 3:
                return mock_response_fail
            return mock_response_success
        
        with patch('httpx.AsyncClient') as mock_client, \
             patch('asyncio.sleep', new_callable=AsyncMock):  # Skip actual sleep
            mock_client.return_value.__aenter__.return_value.post = mock_post
            
            result = await GitHubTokenRefreshManager.refresh_user_token(
                current_token_data=token_data,
                github_app_jwt=github_app_jwt,
                client_id="test_client_id",
                client_secret="test_client_secret",
                max_retries=3
            )
        
        assert result["access_token"] == "gho_new_token_456"
        assert call_count == 3  # Verified 2 failures + 1 success
    
    @pytest.mark.asyncio
    async def test_refresh_exhausts_retries_on_persistent_500(self, github_app_jwt, token_data):
        """Test that persistent 500 errors exhaust retries."""
        mock_response = Mock()
        mock_response.status_code = 500
        mock_response.text = "Internal Server Error"
        
        with patch('httpx.AsyncClient') as mock_client, \
             patch('asyncio.sleep', new_callable=AsyncMock):
            mock_client.return_value.__aenter__.return_value.post = AsyncMock(
                return_value=mock_response
            )
            
            with pytest.raises(GitHubTokenRefreshError, match="status 500"):
                await GitHubTokenRefreshManager.refresh_user_token(
                    current_token_data=token_data,
                    github_app_jwt=github_app_jwt,
                    client_id="test_client_id",
                    client_secret="test_client_secret",
                    max_retries=3
                )
    
    @pytest.mark.asyncio
    async def test_refresh_retries_on_network_error(self, github_app_jwt, token_data):
        """Test that network errors trigger retry."""
        import httpx
        
        # First attempt fails with network error, second succeeds
        mock_response_success = Mock()
        mock_response_success.status_code = 200
        mock_response_success.json.return_value = {
            "access_token": "gho_new_token_456",
            "token_type": "bearer",
            "scope": "repo"
        }
        
        call_count = 0
        
        async def mock_post(*args, **kwargs):
            nonlocal call_count
            call_count += 1
            if call_count == 1:
                raise httpx.ConnectError("Connection failed")
            return mock_response_success
        
        with patch('httpx.AsyncClient') as mock_client, \
             patch('asyncio.sleep', new_callable=AsyncMock):
            mock_client.return_value.__aenter__.return_value.post = mock_post
            
            result = await GitHubTokenRefreshManager.refresh_user_token(
                current_token_data=token_data,
                github_app_jwt=github_app_jwt,
                client_id="test_client_id",
                client_secret="test_client_secret",
                max_retries=3
            )
        
        assert result["access_token"] == "gho_new_token_456"
        assert call_count == 2


class TestTokenRefreshEdgeCases:
    """Test suite for edge cases in token refresh."""
    
    @pytest.fixture
    def github_app_jwt(self):
        """Create a GitHubAppJWT instance for testing."""
        private_key = generate_test_private_key()
        return GitHubAppJWT(app_id="12345", private_key_pem=private_key)
    
    @pytest.mark.asyncio
    async def test_refresh_with_empty_refresh_token_attempts_reissue(self, github_app_jwt):
        """Test that empty string refresh_token attempts reissue."""
        token_data = {
            "access_token": "gho_old_token_123",
            "token_type": "bearer",
            "refresh_token": "",  # Empty string
            "last_refresh_attempt": None,
            "last_refresh_status": None,
            "last_refresh_error": None
        }
        
        # Empty string is falsy, so should attempt reissue, which wraps NotImplementedError
        with pytest.raises(GitHubTokenRefreshError, match="Token reissue failed"):
            await GitHubTokenRefreshManager.refresh_user_token(
                current_token_data=token_data,
                github_app_jwt=github_app_jwt,
                client_id="test_client_id",
                client_secret="test_client_secret"
            )
    
    @pytest.mark.asyncio
    async def test_refresh_with_no_last_attempt_skips_cooldown(self, github_app_jwt):
        """Test that missing last_refresh_attempt skips cooldown check."""
        token_data = {
            "access_token": "gho_old_token_123",
            "token_type": "bearer",
            "refresh_token": "ghr_refresh_token_xyz",
            "last_refresh_attempt": None,  # No previous attempt
            "last_refresh_status": "failed",  # Status doesn't matter without attempt time
            "last_refresh_error": "Previous error"
        }
        
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.json.return_value = {
            "access_token": "gho_new_token_456",
            "token_type": "bearer"
        }
        
        with patch('httpx.AsyncClient') as mock_client:
            mock_client.return_value.__aenter__.return_value.post = AsyncMock(
                return_value=mock_response
            )
            
            # Should succeed without cooldown check
            result = await GitHubTokenRefreshManager.refresh_user_token(
                current_token_data=token_data,
                github_app_jwt=github_app_jwt,
                client_id="test_client_id",
                client_secret="test_client_secret",
                cooldown_seconds=300
            )
        
        assert result["access_token"] == "gho_new_token_456"
    
    @pytest.mark.asyncio
    async def test_refresh_with_invalid_datetime_skips_cooldown(self, github_app_jwt):
        """Test that invalid last_refresh_attempt datetime skips cooldown."""
        token_data = {
            "access_token": "gho_old_token_123",
            "token_type": "bearer",
            "refresh_token": "ghr_refresh_token_xyz",
            "last_refresh_attempt": "not-a-datetime",  # Invalid format
            "last_refresh_status": "failed",
            "last_refresh_error": "Previous error"
        }
        
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.json.return_value = {
            "access_token": "gho_new_token_456",
            "token_type": "bearer"
        }
        
        with patch('httpx.AsyncClient') as mock_client:
            mock_client.return_value.__aenter__.return_value.post = AsyncMock(
                return_value=mock_response
            )
            
            # Should succeed without cooldown check (parse returns None)
            result = await GitHubTokenRefreshManager.refresh_user_token(
                current_token_data=token_data,
                github_app_jwt=github_app_jwt,
                client_id="test_client_id",
                client_secret="test_client_secret",
                cooldown_seconds=300
            )
        
        assert result["access_token"] == "gho_new_token_456"
