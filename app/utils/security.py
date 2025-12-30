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
"""Security utilities for redacting sensitive data in logs and API responses.

This module provides centralized helpers for:
- Token masking (showing only prefix/suffix)
- Secret detection and redaction in strings, dicts, and lists
- Safe exception sanitization
"""

import re
from typing import Any, Dict, List, Union, Optional


# Patterns that indicate sensitive data
SENSITIVE_PATTERNS = [
    r'gh[pousr]_[A-Za-z0-9_-]{4,}',  # GitHub tokens (ghp_, gho_, ghs_, ghu_) - at least 4 chars after prefix
    r'[A-Za-z0-9]{40}',  # Generic 40-character tokens (like GitHub classic tokens)
    r'-----BEGIN\s+(?:RSA\s+)?PRIVATE\s+KEY-----',  # PEM keys
    r'(?:password|passwd|pwd|secret|api[_-]?key|token|auth)["\s:=]+[A-Za-z0-9+/=]{8,}',  # Key-value pairs
]

# Fields that should be redacted (case-insensitive)
SENSITIVE_FIELD_NAMES = {
    'password', 'passwd', 'pwd', 'secret', 'api_key', 'apikey', 'token',
    'access_token', 'refresh_token', 'private_key', 'client_secret',
    'authorization', 'auth', 'bearer', 'credentials', 'credential',
    'encryption_key', 'github_app_private_key_pem', 'github_client_secret',
    'github_token_encryption_key', 'github_webhook_secret'
}


def redact_token(
    token: Optional[str],
    prefix_len: int = 8,
    suffix_len: int = 4,
    mask_char: str = "*"
) -> str:
    """Redact a token showing only prefix and suffix.
    
    This is the primary helper for masking tokens in logs. It shows enough
    context to identify which token is being used while hiding the secret.
    
    Args:
        token: The token to redact (can be None, str, or bytes-like)
        prefix_len: Number of characters to show at the start (default: 8)
        suffix_len: Number of characters to show at the end (default: 4)
        mask_char: Character to use for masking (default: "*")
        
    Returns:
        Redacted string in format "prefix...suffix" or appropriate placeholder
        
    Examples:
        >>> redact_token("ghp_1234567890abcdefghijklmnopqrstuvwxyz")
        "ghp_1234...wxyz"
        >>> redact_token("short")
        "shor*"
        >>> redact_token(None)
        "[REDACTED]"
        >>> redact_token("")
        "[EMPTY]"
    """
    if token is None:
        return "[REDACTED]"
    
    # Handle bytes-like objects
    if isinstance(token, bytes):
        try:
            token = token.decode('utf-8')
        except (UnicodeDecodeError, AttributeError):
            return "[BINARY_DATA]"
    
    # Convert to string if not already
    token_str = str(token).strip()
    
    if not token_str:
        return "[EMPTY]"
    
    token_len = len(token_str)
    
    # For very short strings, just show first few chars
    if token_len <= max(prefix_len, suffix_len):
        visible = min(token_len - 1, 4) if token_len > 1 else 0
        return token_str[:visible] + mask_char
    
    # If suffix_len is 0, don't show suffix
    if suffix_len == 0:
        if token_len <= prefix_len:
            return token_str[:prefix_len] + (mask_char * 3)
        masked_len = token_len - prefix_len
        middle = "." * 3 if masked_len < 10 else f".{masked_len}."
        return f"{token_str[:prefix_len]}{middle}"
    
    # Standard case: show prefix and suffix
    if token_len <= prefix_len + suffix_len:
        # Not enough chars for both prefix and suffix
        return token_str[:prefix_len] + (mask_char * 3)
    
    # Show prefix and suffix with ellipsis
    masked_len = token_len - prefix_len - suffix_len
    middle = "." * 3 if masked_len < 10 else f".{masked_len}."
    return f"{token_str[:prefix_len]}{middle}{token_str[-suffix_len:]}"


def detect_sensitive_string(value: str) -> bool:
    """Check if a string appears to contain sensitive data.
    
    Uses pattern matching to detect common token formats.
    
    Args:
        value: String to check
        
    Returns:
        True if the string appears sensitive, False otherwise
        
    Examples:
        >>> detect_sensitive_string("ghp_1234567890abcdefghijklmnopqrstuvwxyz")
        True
        >>> detect_sensitive_string("hello world")
        False
    """
    if not isinstance(value, str):
        return False
    
    for pattern in SENSITIVE_PATTERNS:
        if re.search(pattern, value, re.IGNORECASE):
            return True
    
    return False


def redact_dict(
    data: Dict[str, Any],
    recursive: bool = True,
    redact_func: Optional[callable] = None
) -> Dict[str, Any]:
    """Redact sensitive fields in a dictionary.
    
    This helper sanitizes dictionary data structures by:
    1. Redacting fields with sensitive names (access_token, password, etc.)
    2. Optionally recursing into nested dicts and lists
    3. Applying pattern-based detection for token-like values
    
    Args:
        data: Dictionary to sanitize
        recursive: Whether to recurse into nested structures (default: True)
        redact_func: Custom redaction function (default: redact_token)
        
    Returns:
        Sanitized dictionary with sensitive values redacted
        
    Examples:
        >>> redact_dict({"access_token": "secret123", "user": "john"})
        {"access_token": "[REDACTED]", "user": "john"}
        >>> redact_dict({"data": {"password": "pass123"}})
        {"data": {"password": "[REDACTED]"}}
    """
    if redact_func is None:
        redact_func = lambda x: redact_token(x, prefix_len=4, suffix_len=0)
    
    result = {}
    
    for key, value in data.items():
        # Check if field name indicates sensitive data
        if key.lower().replace('_', '').replace('-', '') in {
            name.replace('_', '').replace('-', '') for name in SENSITIVE_FIELD_NAMES
        }:
            result[key] = "[REDACTED]"
            continue
        
        # Skip None values - they're not sensitive
        if value is None:
            result[key] = None
            continue
        
        # Recursively handle nested structures
        if recursive:
            if isinstance(value, dict):
                result[key] = redact_dict(value, recursive=True, redact_func=redact_func)
                continue
            elif isinstance(value, (list, tuple)):
                result[key] = redact_list(value, recursive=True, redact_func=redact_func)
                continue
        
        # Check string values for sensitive patterns
        if isinstance(value, str) and detect_sensitive_string(value):
            result[key] = redact_func(value)
        else:
            result[key] = value
    
    return result


def redact_list(
    data: Union[List[Any], tuple],
    recursive: bool = True,
    redact_func: Optional[callable] = None
) -> List[Any]:
    """Redact sensitive values in a list or tuple.
    
    Args:
        data: List or tuple to sanitize
        recursive: Whether to recurse into nested structures (default: True)
        redact_func: Custom redaction function (default: redact_token)
        
    Returns:
        Sanitized list with sensitive values redacted
        
    Examples:
        >>> redact_list(["normal", "ghp_1234567890abcdefghijklmnopqrstuvwxyz"])
        ["normal", "ghp_..."]
    """
    if redact_func is None:
        redact_func = lambda x: redact_token(x, prefix_len=4, suffix_len=0)
    
    result = []
    
    for item in data:
        if recursive:
            if isinstance(item, dict):
                result.append(redact_dict(item, recursive=True, redact_func=redact_func))
                continue
            elif isinstance(item, (list, tuple)):
                result.append(redact_list(item, recursive=True, redact_func=redact_func))
                continue
        
        # Check string values for sensitive patterns
        if isinstance(item, str) and detect_sensitive_string(item):
            result.append(redact_func(item))
        else:
            result.append(item)
    
    return result


def sanitize_exception_message(exception: Exception) -> str:
    """Sanitize exception message to remove any embedded tokens or secrets.
    
    This helper ensures that when exceptions are logged or returned in API
    responses, they don't leak sensitive data that might have been embedded
    in the error message.
    
    Args:
        exception: The exception to sanitize
        
    Returns:
        Sanitized error message string
        
    Examples:
        >>> sanitize_exception_message(ValueError("Failed with token ghp_abc123..."))
        "Failed with token [REDACTED]"
    """
    message = str(exception)
    
    # Apply pattern-based redaction to the message
    for pattern in SENSITIVE_PATTERNS:
        message = re.sub(pattern, "[REDACTED]", message, flags=re.IGNORECASE)
    
    return message


def sanitize_log_extra(extra_fields: Dict[str, Any]) -> Dict[str, Any]:
    """Sanitize extra fields dict before logging.
    
    This is a convenience wrapper around redact_dict specifically for
    log extra_fields dictionaries.
    
    Args:
        extra_fields: Dictionary of extra fields to log
        
    Returns:
        Sanitized dictionary safe for logging
        
    Examples:
        >>> sanitize_log_extra({"user": "john", "token": "secret"})
        {"user": "john", "token": "[REDACTED]"}
    """
    return redact_dict(extra_fields, recursive=True)


def extract_metadata_only(data: Dict[str, Any], allowed_fields: List[str]) -> Dict[str, Any]:
    """Extract only allowed metadata fields from a data structure.
    
    This is useful for admin endpoints that should return metadata but never
    the actual sensitive values.
    
    Args:
        data: Source data dictionary
        allowed_fields: List of field names that are safe to return
        
    Returns:
        Dictionary containing only allowed fields
        
    Examples:
        >>> extract_metadata_only(
        ...     {"token": "secret", "expires_at": "2025-12-31", "scope": "repo"},
        ...     ["expires_at", "scope"]
        ... )
        {"expires_at": "2025-12-31", "scope": "repo"}
    """
    return {
        key: data[key]
        for key in allowed_fields
        if key in data
    }


def is_field_sensitive(field_name: str) -> bool:
    """Check if a field name indicates sensitive data.
    
    Args:
        field_name: Name of the field to check
        
    Returns:
        True if field name suggests sensitive data, False otherwise
        
    Examples:
        >>> is_field_sensitive("access_token")
        True
        >>> is_field_sensitive("user_id")
        False
    """
    normalized = field_name.lower().replace('_', '').replace('-', '')
    normalized_sensitive = {
        name.replace('_', '').replace('-', '') for name in SENSITIVE_FIELD_NAMES
    }
    return normalized in normalized_sensitive
