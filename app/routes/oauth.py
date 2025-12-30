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
"""OAuth and GitHub App installation endpoints.

Provides:
- /github/install - Redirect to GitHub App installation page with CSRF protection
- /oauth/callback - Handle OAuth callback, exchange code for token
"""

import secrets
import re
from typing import Optional
from urllib.parse import urlencode
from datetime import datetime, timezone, timedelta

from fastapi import APIRouter, Request, Response, HTTPException, Query, Depends
from fastapi.responses import RedirectResponse, HTMLResponse

from app.config import Settings
from app.services.github import GitHubOAuthManager, GitHubOAuthError
from app.utils.logging import get_logger, correlation_id_var
from app.dao.firestore_dao import FirestoreDAO
from app.dependencies.firestore import get_firestore_dao

logger = get_logger(__name__)

router = APIRouter()


@router.get(
    "/github/install",
    summary="Initiate GitHub App OAuth Authorization",
    description="""
Initiates the OAuth user authorization flow for a GitHub App by redirecting to GitHub's authorization page.

**Note on Terminology:** This endpoint name uses "install" for historical reasons, but it initiates 
an OAuth user authorization flow, not a GitHub App installation. The flow grants the app permission 
to act on behalf of the authenticated user. For actual app installation to organizations/repos, 
see GitHub's installation endpoints (not implemented in this service).

**⚠️ Interactive Use Only:** This endpoint is designed for interactive browser use only. 
It initiates an OAuth flow that requires user interaction in a web browser. 
Do not call this endpoint from automated scripts or API clients.

**Process:**
1. Generates a cryptographically strong CSRF state token
2. Stores the state token server-side with 5-minute expiration
3. Sets an `oauth_state` cookie in the browser for additional verification
4. Redirects browser to GitHub's OAuth authorization page
5. User authorizes the app on GitHub
6. GitHub redirects back to `/oauth/callback` with authorization code

**Security Features:**
- CSRF protection via state token
- Cookie-based state verification
- State tokens expire after 5 minutes
- State tokens are single-use only

**Cookies Set:**
- `oauth_state`: Secure, HttpOnly cookie for state verification (expires in 5 minutes)
  - `secure=true` in production (HTTPS only)
  - `samesite=lax` to prevent CSRF attacks
    """,
    responses={
        302: {
            "description": "Redirect to GitHub OAuth authorization page",
            "headers": {
                "Location": {
                    "description": "GitHub OAuth authorization URL with client_id, state, and scopes",
                    "schema": {"type": "string"}
                },
                "Set-Cookie": {
                    "description": "oauth_state cookie for CSRF verification (HttpOnly, 5-minute expiration)",
                    "schema": {"type": "string"}
                }
            }
        },
        500: {
            "description": "Server configuration error",
            "content": {
                "application/json": {
                    "example": {
                        "detail": "GitHub OAuth is not properly configured"
                    }
                }
            }
        }
    },
    tags=["oauth"]
)
async def github_install(
    request: Request,
    scopes: str = Query(
        default="user:email,read:org",
        description="Comma-separated list of OAuth scopes to request. Common scopes: repo, user, read:org, write:org",
        examples=["repo,user:email,read:org", "user,read:org", "repo,user"]
    )
) -> RedirectResponse:
    """Redirect to GitHub App installation page with CSRF protection.
    
    Generates a state token for CSRF protection and redirects to GitHub's
    OAuth authorization page.
    
    Query Parameters:
        scopes: Optional comma-separated list of OAuth scopes (default: user:email,read:org)
    
    Returns:
        RedirectResponse to GitHub authorization page
        
    Raises:
        HTTPException: If required configuration is missing
    """
    settings: Settings = request.app.state.settings
    
    # Generate correlation ID for tracking this OAuth flow
    correlation_id = secrets.token_urlsafe(16)
    token = correlation_id_var.set(correlation_id)
    
    try:
        # Validate required configuration
        if not settings.github_client_id:
            logger.error(
                "GitHub client ID not configured",
                extra={"extra_fields": {"correlation_id": correlation_id}}
            )
            raise HTTPException(
                status_code=500,
                detail="GitHub OAuth is not properly configured"
            )
        
        if not settings.github_oauth_redirect_uri:
            logger.error(
                "GitHub OAuth redirect URI not configured",
                extra={"extra_fields": {"correlation_id": correlation_id}}
            )
            raise HTTPException(
                status_code=500,
                detail="GitHub OAuth redirect URI is not configured"
            )
        
        # Generate CSRF state token
        state = GitHubOAuthManager.generate_state_token()
        
        # Validate and sanitize scopes parameter
        # Only allow alphanumeric, comma, colon, underscore, and hyphen
        scopes_param = scopes.strip()
        if not re.match(r'^[a-zA-Z0-9_:,-]+$', scopes_param):
            logger.warning(
                "Invalid scope format provided",
                extra={"extra_fields": {
                    "correlation_id": correlation_id,
                    "provided_scopes": scopes_param[:50]  # Truncate for security
                }}
            )
            # Use safe default if invalid
            scopes_param = "user:email,read:org"
        
        # Build GitHub OAuth authorization URL
        params = {
            "client_id": settings.github_client_id,
            "redirect_uri": settings.github_oauth_redirect_uri,
            "state": state,
            "scope": scopes_param
        }
        
        # Add app_id if available for app installation flow
        if settings.github_app_id:
            params["app_id"] = settings.github_app_id
        
        github_url = f"https://github.com/login/oauth/authorize?{urlencode(params)}"
        
        logger.info(
            "Redirecting to GitHub OAuth authorization",
            extra={"extra_fields": {
                "correlation_id": correlation_id,
                "state_prefix": state[:8] + "...",
                "scopes": scopes_param,
                "redirect_uri": settings.github_oauth_redirect_uri
            }}
        )
        
        # Create response with state cookie for additional verification
        response = RedirectResponse(url=github_url, status_code=302)
        response.set_cookie(
            key="oauth_state",
            value=state,
            max_age=300,  # 5 minutes
            httponly=True,
            secure=settings.app_env == "prod",
            samesite="lax"
        )
        
        return response
        
    finally:
        correlation_id_var.reset(token)


@router.get(
    "/oauth/callback",
    summary="GitHub OAuth Callback Handler",
    description="""
Handles the OAuth callback from GitHub after user authorization.

**⚠️ Do Not Call Directly:** This endpoint should only be accessed via GitHub's OAuth redirect.
Browser clients should not call this endpoint manually; it's invoked automatically by GitHub
after the user completes the authorization flow on GitHub's website.

**Process:**
1. Receives authorization code and state from GitHub redirect
2. Validates CSRF state token (checks cookie and server-side store)
3. Exchanges authorization code for GitHub access token
4. Logs token details (with masking for security)
5. Returns user-friendly HTML success or error page
6. Clears the oauth_state cookie

**Security Features:**
- Validates state token matches the cookie value
- Verifies state token hasn't expired (5-minute lifetime)
- Ensures state token is used only once (consumed on verification)
- Masks tokens in logs (shows only first 8 and last 4 characters)

**⚠️ Token Handling:**
Access tokens are logged for development/debugging but **NOT persisted** to any database.
This implementation is designed for **single-user interactive scenarios** only.
For multi-user production deployments, implement secure token storage.

**Common Errors:**
- `400 Bad Request`: Missing parameters, state mismatch, expired state
- `500 Internal Server Error`: Token exchange failure, GitHub API error
    """,
    responses={
        200: {
            "description": "OAuth flow completed successfully",
            "content": {
                "text/html": {
                    "example": """
<!DOCTYPE html>
<html>
<head><title>OAuth Success</title></head>
<body>
    <h1>Authorization Successful</h1>
    <p>Token Type: bearer</p>
    <p>Granted Scopes: repo,user:email</p>
    <p>Expiration: Token does not expire.</p>
</body>
</html>
                    """
                }
            }
        },
        400: {
            "description": "Bad request - missing parameters, invalid state, or authorization denied",
            "content": {
                "text/html": {
                    "examples": {
                        "missing_params": {
                            "summary": "Missing required parameters",
                            "value": "HTML error page: Missing required parameters (code or state)"
                        },
                        "state_mismatch": {
                            "summary": "State token mismatch",
                            "value": "HTML error page: State token does not match (CSRF protection)"
                        },
                        "expired_state": {
                            "summary": "Expired state token",
                            "value": "HTML error page: State token expired or already used"
                        },
                        "user_denied": {
                            "summary": "User denied authorization",
                            "value": "HTML error page: GitHub authorization failed (user denied)"
                        }
                    }
                }
            }
        },
        500: {
            "description": "Server error - token exchange failed or GitHub API error",
            "content": {
                "text/html": {
                    "example": "HTML error page: Failed to exchange authorization code for access token"
                }
            }
        }
    },
    tags=["oauth"]
)
async def oauth_callback(
    request: Request,
    dao: FirestoreDAO = Depends(get_firestore_dao),
    code: Optional[str] = Query(
        default=None,
        description="Authorization code from GitHub (provided by GitHub redirect)",
        examples=["abc123def456"]
    ),
    state: Optional[str] = Query(
        default=None,
        description="CSRF state token (must match the cookie value)",
        examples=["Hk9u7yXZ4bQrPm8L..."]
    ),
    error: Optional[str] = Query(
        default=None,
        description="Error code if authorization failed (e.g., 'access_denied')",
        examples=["access_denied"]
    ),
    error_description: Optional[str] = Query(
        default=None,
        description="Human-readable error description from GitHub",
        examples=["The user denied the authorization request"]
    )
) -> HTMLResponse:
    """Handle OAuth callback from GitHub.
    
    Validates state token, exchanges authorization code for access token,
    logs token details (masked), and returns confirmation page.
    
    Query Parameters:
        code: Authorization code from GitHub
        state: CSRF state token
        error: Error code if authorization failed
        error_description: Human-readable error description
    
    Returns:
        HTMLResponse with success or error page
    """
    settings: Settings = request.app.state.settings
    
    # Generate correlation ID for tracking
    correlation_id = secrets.token_urlsafe(16)
    token = correlation_id_var.set(correlation_id)
    
    try:
        # Check for OAuth errors from GitHub
        if error:
            logger.warning(
                "GitHub OAuth authorization failed",
                extra={"extra_fields": {
                    "correlation_id": correlation_id,
                    "error": error,
                    "description": error_description or "No description provided"
                }}
            )
            
            return HTMLResponse(
                content=_render_error_page(
                    title="Authorization Failed",
                    message=f"GitHub authorization failed: {error}",
                    details=error_description or "The authorization request was denied or failed."
                ),
                status_code=400
            )
        
        # Validate required parameters
        if not code or not state:
            logger.warning(
                "OAuth callback missing required parameters",
                extra={"extra_fields": {
                    "correlation_id": correlation_id,
                    "has_code": bool(code),
                    "has_state": bool(state)
                }}
            )
            
            return HTMLResponse(
                content=_render_error_page(
                    title="Invalid Request",
                    message="Missing required parameters",
                    details="The callback request is missing the authorization code or state parameter."
                ),
                status_code=400
            )
        
        # Verify state token (CSRF protection)
        cookie_state = request.cookies.get("oauth_state")
        
        # First, check if the state from the query parameter matches the cookie
        if not cookie_state or cookie_state != state:
            logger.warning(
                "OAuth state cookie mismatch or missing",
                extra={"extra_fields": {
                    "correlation_id": correlation_id,
                    "state_prefix": state[:8] + "...",
                    "cookie_prefix": cookie_state[:8] + "..." if cookie_state else "None"
                }}
            )
            
            return HTMLResponse(
                content=_render_error_page(
                    title="Security Verification Failed",
                    message="State token mismatch",
                    details="The state token does not match the expected value. Please try again."
                ),
                status_code=400
            )
        
        # If they match, verify the token against the server-side store (consumes it)
        if not GitHubOAuthManager.verify_state_token(state):
            logger.warning(
                "OAuth state verification failed - invalid or expired state",
                extra={"extra_fields": {
                    "correlation_id": correlation_id,
                    "state_prefix": state[:8] + "...",
                    "has_cookie_state": bool(cookie_state)
                }}
            )
            
            return HTMLResponse(
                content=_render_error_page(
                    title="Security Verification Failed",
                    message="Invalid or expired state token",
                    details="The state token is invalid, expired, or has already been used. "
                           "Please try again from the beginning."
                ),
                status_code=400
            )
        
        # Exchange code for access token
        try:
            token_data = await GitHubOAuthManager.exchange_code_for_token(
                code=code,
                client_id=settings.github_client_id,
                client_secret=settings.github_client_secret,
                redirect_uri=settings.github_oauth_redirect_uri
            )
        except GitHubOAuthError as e:
            logger.error(
                "OAuth token exchange failed",
                extra={"extra_fields": {
                    "correlation_id": correlation_id,
                    "error": str(e)
                }}
            )
            
            return HTMLResponse(
                content=_render_error_page(
                    title="Token Exchange Failed",
                    message="Failed to exchange authorization code for access token",
                    details=str(e)
                ),
                status_code=500
            )
        
        # Validate token data
        access_token = token_data.get("access_token")
        if not access_token:
            logger.error(
                "OAuth response missing access_token",
                extra={"extra_fields": {
                    "correlation_id": correlation_id,
                    "response_keys": list(token_data.keys())
                }}
            )
            
            return HTMLResponse(
                content=_render_error_page(
                    title="Invalid Response",
                    message="GitHub response is missing access token",
                    details="The OAuth response did not include an access token."
                ),
                status_code=500
            )
        
        # Check for scope field (optional but expected)
        scope = token_data.get("scope")
        if not scope:
            logger.warning(
                "OAuth response missing scope field",
                extra={"extra_fields": {"correlation_id": correlation_id}}
            )
        
        # Calculate expires_at from expires_in if provided
        expires_at = None
        expires_in = token_data.get("expires_in")
        if expires_in is not None:
            try:
                expires_at = datetime.now(timezone.utc) + timedelta(seconds=int(expires_in))
            except (ValueError, TypeError) as e:
                logger.warning(
                    "Failed to parse expires_in, token will be saved without expiration",
                    extra={"extra_fields": {
                        "correlation_id": correlation_id,
                        "expires_in": expires_in,
                        "error": str(e)
                    }}
                )
        
        # Persist token to Firestore
        try:
            token_type = token_data.get("token_type", "bearer")
            refresh_token = token_data.get("refresh_token")
            
            await dao.save_github_token(
                collection=settings.github_tokens_collection,
                doc_id=settings.github_tokens_doc_id,
                access_token=access_token,
                token_type=token_type,
                scope=scope,
                expires_at=expires_at,
                refresh_token=refresh_token
            )
            
            logger.info(
                "GitHub token persisted to Firestore successfully",
                extra={"extra_fields": {
                    "correlation_id": correlation_id,
                    "collection": settings.github_tokens_collection,
                    "doc_id": settings.github_tokens_doc_id
                }}
            )
        except PermissionError as e:
            # Firestore permission denied - IAM configuration issue
            logger.error(
                "Permission denied writing to Firestore",
                extra={"extra_fields": {
                    "correlation_id": correlation_id,
                    "error": str(e)
                }},
                exc_info=True
            )
            
            return HTMLResponse(
                content=_render_error_page(
                    title="Token Storage Failed",
                    message="Permission denied accessing token storage",
                    details="The service does not have permission to store tokens. "
                           "Please contact an administrator to check IAM roles."
                ),
                status_code=503
            )
        except ValueError as e:
            # Invalid data or missing encryption key
            logger.error(
                "Invalid data for token persistence",
                extra={"extra_fields": {
                    "correlation_id": correlation_id,
                    "error": str(e)
                }},
                exc_info=True
            )
            
            return HTMLResponse(
                content=_render_error_page(
                    title="Token Storage Failed",
                    message="Failed to persist GitHub token",
                    details="Token storage is not properly configured. "
                           "Please contact an administrator."
                ),
                status_code=503
            )
        except Exception as e:
            # Other Firestore errors (network, quota, etc.)
            logger.error(
                "Failed to persist GitHub token to Firestore",
                extra={"extra_fields": {
                    "correlation_id": correlation_id,
                    "error": str(e),
                    "error_type": type(e).__name__
                }},
                exc_info=True
            )
            
            return HTMLResponse(
                content=_render_error_page(
                    title="Token Storage Failed",
                    message="Failed to persist GitHub token",
                    details="The token was obtained successfully but could not be saved. "
                           "Please contact an administrator or try again later."
                ),
                status_code=503
            )
        
        # Log successful token exchange (token already masked in service layer)
        logger.info(
            "OAuth flow completed successfully",
            extra={"extra_fields": {
                "correlation_id": correlation_id,
                "token_type": token_type,
                "scope": scope or "unknown",
                "expires_in_seconds": expires_in,
                "has_expiry": expires_in is not None
            }}
        )
        
        # Render success page
        response = HTMLResponse(
            content=_render_success_page(
                token_type=token_type,
                scope=scope or "unknown",
                expires_in=expires_in
            ),
            status_code=200
        )
        
        # Clear the state cookie
        response.delete_cookie("oauth_state")
        
        return response
        
    finally:
        correlation_id_var.reset(token)


def _render_success_page(
    token_type: str,
    scope: str,
    expires_in: Optional[int]
) -> str:
    """Render OAuth success confirmation page.
    
    Args:
        token_type: Type of token received
        scope: Granted scopes
        expires_in: Token expiration in seconds (if applicable)
    
    Returns:
        HTML content for success page
    """
    expiry_text = (
        f"Token expires in {expires_in} seconds ({expires_in // 60} minutes)."
        if expires_in
        else "Token does not expire."
    )
    
    return f"""
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>OAuth Success</title>
    <style>
        body {{
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Oxygen, Ubuntu, sans-serif;
            max-width: 600px;
            margin: 50px auto;
            padding: 20px;
            background-color: #f5f5f5;
        }}
        .container {{
            background: white;
            border-radius: 8px;
            padding: 30px;
            box-shadow: 0 2px 10px rgba(0,0,0,0.1);
        }}
        .success-icon {{
            text-align: center;
            font-size: 48px;
            color: #28a745;
            margin-bottom: 20px;
        }}
        h1 {{
            color: #28a745;
            margin: 0 0 10px 0;
            font-size: 24px;
        }}
        p {{
            color: #666;
            line-height: 1.6;
            margin: 10px 0;
        }}
        .details {{
            background: #f8f9fa;
            border-left: 4px solid #28a745;
            padding: 15px;
            margin: 20px 0;
            border-radius: 4px;
        }}
        .details strong {{
            color: #333;
        }}
        .note {{
            font-size: 14px;
            color: #6c757d;
            margin-top: 20px;
            padding-top: 20px;
            border-top: 1px solid #dee2e6;
        }}
    </style>
</head>
<body>
    <div class="container">
        <div class="success-icon">✓</div>
        <h1>Authorization Successful</h1>
        <p>You have successfully authorized the GitHub App.</p>
        
        <div class="details">
            <p><strong>Token Type:</strong> {token_type}</p>
            <p><strong>Granted Scopes:</strong> {scope}</p>
            <p><strong>Expiration:</strong> {expiry_text}</p>
        </div>
        
        <p class="note">
            <strong>Note:</strong> The access token has been logged (partially masked) for development purposes.
            In production, tokens are not persisted and should be handled securely.
            You may now close this window.
        </p>
    </div>
</body>
</html>
"""


def _render_error_page(title: str, message: str, details: str) -> str:
    """Render OAuth error page.
    
    Args:
        title: Error title
        message: Short error message
        details: Detailed error description
    
    Returns:
        HTML content for error page
    """
    return f"""
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>{title}</title>
    <style>
        body {{
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Oxygen, Ubuntu, sans-serif;
            max-width: 600px;
            margin: 50px auto;
            padding: 20px;
            background-color: #f5f5f5;
        }}
        .container {{
            background: white;
            border-radius: 8px;
            padding: 30px;
            box-shadow: 0 2px 10px rgba(0,0,0,0.1);
        }}
        .error-icon {{
            text-align: center;
            font-size: 48px;
            color: #dc3545;
            margin-bottom: 20px;
        }}
        h1 {{
            color: #dc3545;
            margin: 0 0 10px 0;
            font-size: 24px;
        }}
        p {{
            color: #666;
            line-height: 1.6;
            margin: 10px 0;
        }}
        .details {{
            background: #f8f9fa;
            border-left: 4px solid #dc3545;
            padding: 15px;
            margin: 20px 0;
            border-radius: 4px;
        }}
        .action {{
            margin-top: 20px;
            padding-top: 20px;
            border-top: 1px solid #dee2e6;
        }}
        a {{
            display: inline-block;
            background: #007bff;
            color: white;
            padding: 10px 20px;
            text-decoration: none;
            border-radius: 4px;
            margin-top: 10px;
        }}
        a:hover {{
            background: #0056b3;
        }}
    </style>
</head>
<body>
    <div class="container">
        <div class="error-icon">✗</div>
        <h1>{title}</h1>
        <p>{message}</p>
        
        <div class="details">
            <p><strong>Details:</strong> {details}</p>
        </div>
        
        <div class="action">
            <p>Please try again or contact support if the problem persists.</p>
            <a href="/github/install">Try Again</a>
        </div>
    </div>
</body>
</html>
"""
