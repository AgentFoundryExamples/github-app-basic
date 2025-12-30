# Security Notes

This document describes the security measures and best practices implemented in the GitHub App Token Minting Service to protect sensitive data.

## Overview

The service handles sensitive data including:
- GitHub OAuth tokens (access tokens, refresh tokens)
- GitHub App private keys
- Client secrets and API keys
- User authentication data

To prevent data leakage, the service implements **defense-in-depth** security measures across all layers:
- Centralized redaction utilities
- Automatic logging sanitization
- Encrypted storage with AES-256-GCM
- Metadata-only API responses
- Exception message sanitization

## Security Utilities

### Redaction Helpers (`app/utils/security.py`)

The service provides centralized security utilities for redacting sensitive data before logging or returning it in API responses.

#### Token Redaction

**Function**: `redact_token(token, prefix_len=8, suffix_len=4)`

Masks tokens showing only a prefix and optional suffix to aid debugging while protecting the actual secret.

```python
from app.utils.security import redact_token

# Example usage
token = "ghp_1234567890abcdefghijklmnopqrstuvwxyz"
masked = redact_token(token)
# Result: "ghp_1234...wxyz"

# Only show prefix (for high-security scenarios)
masked = redact_token(token, prefix_len=4, suffix_len=0)
# Result: "ghp_.32."
```

**When to use:**
- Before logging any token value
- When displaying token metadata to users
- In error messages that might contain tokens

#### Dictionary Redaction

**Function**: `redact_dict(data, recursive=True)`

Recursively sanitizes dictionaries by:
1. Redacting fields with sensitive names (password, api_key, access_token, etc.)
2. Detecting and redacting token-like patterns in values
3. Processing nested structures (dicts and lists)

```python
from app.utils.security import redact_dict

# Example usage
data = {
    "access_token": "ghp_secret123",
    "user": "john",
    "metadata": {
        "password": "secret",
        "email": "john@example.com"
    }
}

sanitized = redact_dict(data)
# Result: {
#     "access_token": "[REDACTED]",
#     "user": "john",
#     "metadata": {
#         "password": "[REDACTED]",
#         "email": "john@example.com"
#     }
# }
```

**When to use:**
- Before logging request/response bodies
- Before returning error details to clients
- When serializing audit log entries

#### Exception Sanitization

**Function**: `sanitize_exception_message(exception)`

Removes embedded tokens and secrets from exception messages using pattern matching.

```python
from app.utils.security import sanitize_exception_message

# Example usage
try:
    authenticate("ghp_1234567890abcdefghijklmnopqrstuvwxyz")
except ValueError as e:
    # e.message might contain the token
    safe_message = sanitize_exception_message(e)
    logger.error(f"Authentication failed: {safe_message}")
```

**When to use:**
- Before logging any exception
- Before including exception details in HTTP responses
- When persisting error information to databases

## Logging Security

### Structured Logging with Automatic Redaction

All logging uses the structured JSON logger configured in `app/utils/logging.py`. The logger automatically includes correlation IDs and request IDs for tracing.

**Best Practices:**
1. **Never log raw tokens directly** - Always use `redact_token()` first
2. **Use extra_fields for context** - Sensitive data in extra_fields should be redacted
3. **Sanitize exceptions** - Use `sanitize_exception_message()` before logging errors

**Example:**
```python
from app.utils.logging import get_logger
from app.utils.security import redact_token, sanitize_exception_message

logger = get_logger(__name__)

# ✅ CORRECT: Token is redacted
access_token = "ghp_secret123..."
logger.info(
    "Token retrieved",
    extra={"extra_fields": {
        "token_preview": redact_token(access_token, prefix_len=4, suffix_len=0),
        "user_id": 42
    }}
)

# ❌ INCORRECT: Raw token in logs
logger.info(f"Token: {access_token}")  # DON'T DO THIS!

# ✅ CORRECT: Exception is sanitized
try:
    process_token(access_token)
except Exception as e:
    logger.error(
        "Token processing failed",
        extra={"extra_fields": {
            "error": sanitize_exception_message(e)
        }},
        exc_info=True
    )
```

### Debug Logging

Even in debug mode, **never bypass redaction helpers**. Debug logs should use the same security utilities to prevent accidental leakage.

## API Endpoint Security

### Admin Endpoints

Admin endpoints (e.g., `/admin/token-metadata`) return **metadata only**, never the actual secrets.

**What's returned:**
- ✅ Token type (e.g., "bearer")
- ✅ Scopes (e.g., "repo,user:email")
- ✅ Expiration timestamps
- ✅ Boolean flags (e.g., `has_refresh_token`)
- ✅ Status information

**What's NEVER returned:**
- ❌ Decrypted access tokens
- ❌ Decrypted refresh tokens
- ❌ Encrypted ciphertext
- ❌ Private keys
- ❌ Client secrets

**Implementation:**
```python
# ✅ CORRECT: Return only metadata
metadata = await dao.get_github_token_metadata(
    collection=settings.github_tokens_collection,
    doc_id=settings.github_tokens_doc_id
)
return metadata  # Contains no decrypted tokens

# ❌ INCORRECT: Return full token data
token_data = await dao.get_github_token(
    collection=settings.github_tokens_collection,
    doc_id=settings.github_tokens_doc_id,
    decrypt=True
)
return token_data  # Contains decrypted access_token!
```

### Error Responses

HTTP error responses use generic error messages and **never include**:
- Raw tokens or secrets
- Full exception stack traces (in production)
- Sensitive configuration values
- Database query details

**Example:**
```python
# ✅ CORRECT: Generic error message
raise HTTPException(
    status_code=500,
    detail="Failed to refresh GitHub token"
)

# ❌ INCORRECT: Detailed error with potential secrets
raise HTTPException(
    status_code=500,
    detail=f"Failed with token {access_token}: {str(e)}"
)
```

## Sensitive Field Detection

The security utilities automatically detect sensitive field names:

```python
SENSITIVE_FIELD_NAMES = {
    'password', 'passwd', 'pwd', 'secret', 'api_key', 'apikey', 'token',
    'access_token', 'refresh_token', 'private_key', 'client_secret',
    'authorization', 'auth', 'bearer', 'credentials', 'credential',
    'encryption_key', 'github_app_private_key_pem', 'github_client_secret',
    'github_token_encryption_key', 'github_webhook_secret'
}
```

Detection is **case-insensitive** and handles **underscores/hyphens** (e.g., `access_token`, `Access-Token`, `ACCESSTOKEN` all match).

## Pattern-Based Redaction

The security utilities use regex patterns to detect tokens embedded in strings:

```python
SENSITIVE_PATTERNS = [
    r'gh[pousr]_[A-Za-z0-9_-]{4,}',  # GitHub tokens (ghp_, gho_, etc.)
    r'[A-Za-z0-9]{40}',  # Generic 40-character tokens
    r'-----BEGIN\s+(?:RSA\s+)?PRIVATE\s+KEY-----',  # PEM keys
    r'(?:password|passwd|secret)["\s:=]+[A-Za-z0-9+/=]{8,}',  # Key-value pairs
]
```

These patterns automatically redact tokens even when they appear in:
- Log messages
- Exception text
- API request/response bodies
- Configuration dump outputs

## Token Storage Security

### Encryption at Rest

All tokens are encrypted before storage in Firestore using **AES-256-GCM**:

```python
# Encryption configuration
ALGORITHM = "AES-256-GCM"
KEY_SIZE = 32 bytes (256 bits)
NONCE_SIZE = 12 bytes (96 bits) - randomly generated per encryption
TAG_SIZE = 16 bytes (128 bits) - authentication tag
```

**Key management:**
- Keys stored in environment variable `GITHUB_TOKEN_ENCRYPTION_KEY`
- **Production**: Use Google Secret Manager (never env vars)
- Key rotation requires re-authentication and re-encryption

### Defense in Depth

Tokens are protected by multiple security layers:

1. **GCP-managed encryption at rest** (automatic)
2. **Application-level encryption** (AES-256-GCM, required)
3. **IAM-based access control** (Firestore permissions)
4. **Network encryption** (HTTPS/TLS in transit)

## Edge Cases and Special Scenarios

### Firestore Exceptions

When Firestore operations fail, exception messages are sanitized before logging:

```python
try:
    await dao.get_document(collection, doc_id)
except Exception as e:
    logger.error(
        "Firestore operation failed",
        extra={"extra_fields": {
            "error": sanitize_exception_message(e)  # Removes any embedded secrets
        }},
        exc_info=True
    )
```

### GitHub API Exceptions

GitHub API errors might echo credential material. The service sanitizes these before logging:

```python
# ✅ CORRECT: Never log raw GitHub API response
logger.error(
    "GitHub API request failed",
    extra={"extra_fields": {
        "status_code": response.status_code,
        "response_preview": "[REDACTED]"  # Don't include response body
    }}
)
```

### Debug Mode

Debug logging still uses redaction helpers. There is **no configuration option** to disable redaction.

```python
# Even in debug mode, tokens are redacted
if settings.log_level == "DEBUG":
    logger.debug(
        "Token details",
        extra={"extra_fields": {
            "token_preview": redact_token(token)  # Still redacted!
        }}
    )
```

### Unicode and Byte Inputs

The redaction helpers handle:
- Unicode strings (UTF-8)
- Byte strings (decoded to UTF-8)
- Extremely short secrets (< 4 characters)
- Empty or None values

```python
# All these are handled safely
redact_token(None)  # Returns "[REDACTED]"
redact_token("")  # Returns "[EMPTY]"
redact_token(b"token")  # Decoded and redacted
redact_token("αβγδ")  # Unicode handled
```

## Testing Security Measures

### Unit Tests

Comprehensive unit tests verify redaction behavior:
- `tests/test_security_utils.py` - 52 tests covering:
  - Token redaction (various lengths, formats)
  - Sensitive string detection
  - Dictionary/list sanitization
  - Exception message sanitization
  - Edge cases (unicode, bytes, None, empty)

**Run tests:**
```bash
pytest tests/test_security_utils.py -v
```

### Integration Tests

Integration tests verify end-to-end security:
- Admin endpoints return only metadata
- Error responses never contain secrets
- Logs are properly sanitized
- Token refresh failures are handled securely

## Common Pitfalls and How to Avoid Them

### ❌ Logging Raw Tokens

```python
# WRONG
logger.info(f"Got token: {access_token}")

# CORRECT
from app.utils.security import redact_token
logger.info(
    "Got token",
    extra={"extra_fields": {"token_preview": redact_token(access_token)}}
)
```

### ❌ Returning Tokens in API Responses

```python
# WRONG
return {"token": access_token, "user": "john"}

# CORRECT (return only metadata)
return {"token_type": "bearer", "expires_at": expires_at, "user": "john"}
```

### ❌ Unsan itized Exceptions in HTTP Responses

```python
# WRONG
except ValueError as e:
    raise HTTPException(status_code=400, detail=str(e))

# CORRECT
except ValueError as e:
    logger.error("Validation failed", extra={"extra_fields": {"error": sanitize_exception_message(e)}})
    raise HTTPException(status_code=400, detail="Validation failed")
```

### ❌ Debug Output with Secrets

```python
# WRONG
print(f"DEBUG: Token = {access_token}")

# CORRECT
logger.debug(
    "Token retrieved",
    extra={"extra_fields": {"token_preview": redact_token(access_token)}}
)
```

### ❌ Bypassing Redaction in Tests

```python
# WRONG (even in tests)
def test_token_retrieval():
    token = "ghp_secret123"
    logger.info(f"Test token: {token}")  # Don't do this!

# CORRECT
def test_token_retrieval():
    token = "ghp_secret123"
    logger.info(
        "Test token",
        extra={"extra_fields": {"token_preview": redact_token(token)}}
    )
```

## Audit Checklist

Use this checklist when reviewing code for security issues:

- [ ] All token logging uses `redact_token()`
- [ ] Exception logging uses `sanitize_exception_message()`
- [ ] Admin endpoints return metadata only (no decrypted tokens)
- [ ] HTTP error responses use generic messages
- [ ] Request/response logging redacts sensitive fields
- [ ] Firestore operations handle PermissionError properly
- [ ] GitHub API errors don't leak credentials
- [ ] Debug logs still use redaction helpers
- [ ] Tests don't log raw secrets
- [ ] New sensitive field names are added to `SENSITIVE_FIELD_NAMES`

## Future Contributors

**When adding new features:**

1. **Add new sensitive fields** to `SENSITIVE_FIELD_NAMES` in `app/utils/security.py`
2. **Use redaction helpers** for all logging of user input or API responses
3. **Sanitize exceptions** before logging or returning to clients
4. **Write tests** that verify secrets are not leaked
5. **Review existing patterns** to ensure they cover your use case
6. **Never bypass security utilities** even for debugging or testing
7. **Document new security considerations** in this file

## Security Contact

For security issues or questions:
- Review this document first
- Check existing tests for examples
- Consult the implementation in `app/utils/security.py`
- Follow the patterns used in routes, services, and DAOs

## References

- [OWASP Logging Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Logging_Cheat_Sheet.html)
- [GitHub Token Security Best Practices](https://docs.github.com/en/authentication/keeping-your-account-and-data-secure/about-authentication-to-github)
- [NIST Cryptographic Standards](https://csrc.nist.gov/projects/cryptographic-standards-and-guidelines)
