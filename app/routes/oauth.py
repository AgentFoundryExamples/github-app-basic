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
from typing import Optional
from urllib.parse import urlencode

from fastapi import APIRouter, Request, Response, HTTPException
from fastapi.responses import RedirectResponse, HTMLResponse

from app.config import Settings
from app.services.github import GitHubOAuthManager, GitHubOAuthError
from app.utils.logging import get_logger, correlation_id_var

logger = get_logger(__name__)

router = APIRouter()


@router.get("/github/install")
async def github_install(request: Request) -> RedirectResponse:
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
        
        # Get scopes from query parameter or use defaults
        scopes = request.query_params.get("scopes", "user:email,read:org")
        
        # Build GitHub OAuth authorization URL
        params = {
            "client_id": settings.github_client_id,
            "redirect_uri": settings.github_oauth_redirect_uri,
            "state": state,
            "scope": scopes
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
                "scopes": scopes,
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


@router.get("/oauth/callback")
async def oauth_callback(
    request: Request,
    code: Optional[str] = None,
    state: Optional[str] = None,
    error: Optional[str] = None,
    error_description: Optional[str] = None
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
        
        # Log successful token exchange (token already masked in service layer)
        token_type = token_data.get("token_type", "unknown")
        expires_in = token_data.get("expires_in")
        
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
