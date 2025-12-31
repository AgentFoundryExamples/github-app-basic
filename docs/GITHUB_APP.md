# GitHub App Configuration Guide

This guide walks you through creating and configuring a GitHub App for use with the Token Minting Service.

## Prerequisites

- A GitHub account (personal or organization)
- Admin access to create GitHub Apps
- Cloud Run service URL from [SELF_HOSTING.md](SELF_HOSTING.md) deployment
- Understanding of OAuth 2.0 and GitHub App permissions

## Overview

The Token Minting Service uses GitHub App OAuth for user authorization. This guide covers:
1. Creating a GitHub App
2. Configuring OAuth settings and callback URLs
3. Setting repository and organization permissions
4. Generating and storing credentials
5. Testing the OAuth flow

## Step 1: Create a GitHub App

### Navigate to GitHub App Settings

```bash
# For personal account
https://github.com/settings/apps

# For organization (replace ORG_NAME)
https://github.com/organizations/ORG_NAME/settings/apps
```

Click **"New GitHub App"** to begin.

### Basic Information

**Required Fields:**

| Field | Value | Notes |
|-------|-------|-------|
| **GitHub App name** | `My Token Minting Service` | Must be unique across GitHub |
| **Homepage URL** | `https://your-service.run.app` | Your Cloud Run service URL |
| **Description** | `OAuth token service for GitHub API` | Optional but recommended |

**Webhook Configuration:**

| Field | Value | Notes |
|-------|-------|-------|
| **Webhook URL** | `https://your-service.run.app/webhooks/github` | Required by GitHub, even if not used |
| **Webhook secret** | Generate secure token | `openssl rand -hex 32` |

⚠️ **Note**: Webhook handling is not yet implemented in this service, but GitHub requires a webhook URL to create the app. The service includes webhook secret configuration for future use.

### OAuth Configuration (CRITICAL)

This section configures user authorization flow. **Incorrect settings will break OAuth.**

**Callback URL (Required):**

The callback URL must **exactly match** your Cloud Run service's OAuth callback endpoint:

```
# Format
https://<your-cloud-run-service-url>/oauth/callback

# Example
https://github-app-token-service-abc123-uc.a.run.app/oauth/callback
```

**⚠️ Common Mistakes to Avoid:**

- ❌ Wrong path: `/auth/callback` instead of `/oauth/callback`
- ❌ Trailing slash: `/oauth/callback/` (GitHub treats this as different)
- ❌ Wrong protocol: `http://` instead of `https://` (Cloud Run uses HTTPS)
- ❌ Localhost in production: `http://localhost:8000` (only valid for local development)
- ❌ Port numbers in Cloud Run URL: Cloud Run doesn't expose port numbers

**OAuth Settings:**

| Setting | Value | Purpose |
|---------|-------|---------|
| **Request user authorization (OAuth) during installation** | ✅ **ENABLED** | Required for OAuth flow |
| **Enable Device Flow** | Optional | Not used by this service |
| **Expire user authorization tokens** | Recommended: Disabled | Tokens typically don't expire for user-to-server |

### Setup URL (Optional)

| Field | Value | Notes |
|-------|-------|-------|
| **Setup URL** | Leave blank or use `https://your-service.run.app/github/install` | Post-installation redirect |
| **Redirect on update** | Optional | Redirect users after updating app permissions |

## Step 2: Configure Permissions

GitHub Apps require explicit permissions for API operations. Configure based on your use case.

### Repository Permissions

**Recommended Minimum Permissions:**

| Permission | Access Level | Purpose |
|------------|--------------|---------|
| **Contents** | Read | Read repository files and commits |
| **Metadata** | Read | Read repository metadata (always required) |

**Additional Permissions (as needed):**

| Permission | Access Level | Use Case |
|------------|--------------|----------|
| **Issues** | Read & Write | Manage issues |
| **Pull requests** | Read & Write | Manage pull requests |
| **Actions** | Read & Write | Manage GitHub Actions workflows |
| **Packages** | Read | Access GitHub Packages |
| **Deployments** | Read & Write | Manage deployments |

### Organization Permissions

| Permission | Access Level | Use Case |
|------------|--------------|----------|
| **Members** | Read | Read organization membership |
| **Administration** | Read | Read organization settings |

### Account Permissions

| Permission | Access Level | Use Case |
|------------|--------------|----------|
| **Email addresses** | Read | Access user email (included in `user:email` scope) |
| **Profile** | Read | Access user profile information |

**⚠️ Principle of Least Privilege:**
- Only request permissions you actually need
- Users see all requested permissions during OAuth
- Over-requesting permissions reduces user trust
- You can always add permissions later (requires user re-authorization)

### Subscribe to Events (Optional)

If you plan to implement webhook handlers in the future:

| Event | Purpose |
|-------|---------|
| **Push** | Notified when code is pushed |
| **Pull request** | Notified when PRs are created/updated |
| **Issues** | Notified when issues are created/updated |
| **Repository** | Notified when repositories are created/deleted |

⚠️ **Note**: The current service does not process webhook events. This is for future extensibility.

## Step 3: Generate Credentials

### App ID

After creating the app, note the **App ID** (numeric identifier):

```
App ID: 123456
```

**Location**: Top of GitHub App settings page

**Store as**: `GITHUB_APP_ID` environment variable or Secret Manager secret

### Client ID

Find the **Client ID** in the "OAuth credentials" section:

```
Client ID: Iv1.abc123def456
```

**Format**: Always starts with `Iv1.` or `Iv23.`

**Store as**: `GITHUB_CLIENT_ID` environment variable or Secret Manager secret

### Client Secret

**⚠️ CRITICAL: This is shown only once!**

1. Scroll to **"Client secrets"** section
2. Click **"Generate a new client secret"**
3. **Copy the secret immediately** - GitHub will never show it again
4. Store securely (Secret Manager or password manager)

```
Client Secret: 1a2b3c4d5e6f7g8h9i0j1k2l3m4n5o6p7q8r9s0
```

**Store as**: `GITHUB_CLIENT_SECRET` environment variable or Secret Manager secret

### Private Key

**⚠️ CRITICAL: Download and store securely!**

1. Scroll to **"Private keys"** section
2. Click **"Generate a private key"**
3. GitHub downloads a `.pem` file (e.g., `your-app-name.2023-12-30.private-key.pem`)
4. Store in a secure location - GitHub will never show it again

**File Contents:**
```
-----BEGIN RSA PRIVATE KEY-----
MIIEpAIBAAKCAQEA...
...many lines of base64...
-----END RSA PRIVATE KEY-----
```

**Store as**: `GITHUB_APP_PRIVATE_KEY_PEM` environment variable or Secret Manager secret

**Format for Environment Variables:**

Option 1 (Escaped newlines):
```bash
export GITHUB_APP_PRIVATE_KEY_PEM="-----BEGIN RSA PRIVATE KEY-----\nMIIEpAIBAAKCAQEA...\n-----END RSA PRIVATE KEY-----"
```

Option 2 (Literal newlines in .env file):
```bash
GITHUB_APP_PRIVATE_KEY_PEM="-----BEGIN RSA PRIVATE KEY-----
MIIEpAIBAAKCAQEA...
-----END RSA PRIVATE KEY-----"
```

### Webhook Secret (Optional)

Generate a secure random token for webhook signature verification:

```bash
openssl rand -hex 32
```

**Store as**: `GITHUB_WEBHOOK_SECRET` environment variable or Secret Manager secret

**Note**: This is optional for the current implementation but recommended for future webhook support.

## Step 4: Store Credentials in Secret Manager

After generating all credentials, store them in Google Secret Manager:

```bash
# Set variables with your actual values
export GITHUB_APP_ID="123456"
export GITHUB_CLIENT_ID="Iv1.abc123def456"
export GITHUB_CLIENT_SECRET="1a2b3c4d5e6f7g8h9i0j1k2l3m4n5o6p7q8r9s0"
export GITHUB_WEBHOOK_SECRET="your_webhook_secret_here"
export PROJECT_ID="your-gcp-project-id"

# Store App ID
echo -n "$GITHUB_APP_ID" | \
  gcloud secrets create github-app-id \
  --data-file=- \
  --project=$PROJECT_ID

# Store Private Key (from file)
gcloud secrets create github-app-private-key-pem \
  --data-file=/path/to/your-app-name.private-key.pem \
  --project=$PROJECT_ID

# Store Client ID
echo -n "$GITHUB_CLIENT_ID" | \
  gcloud secrets create github-client-id \
  --data-file=- \
  --project=$PROJECT_ID

# Store Client Secret
echo -n "$GITHUB_CLIENT_SECRET" | \
  gcloud secrets create github-client-secret \
  --data-file=- \
  --project=$PROJECT_ID

# Store Webhook Secret
echo -n "$GITHUB_WEBHOOK_SECRET" | \
  gcloud secrets create github-webhook-secret \
  --data-file=- \
  --project=$PROJECT_ID
```

## Step 5: Update Cloud Run Service

Redeploy Cloud Run with the GitHub credentials:

```bash
export SERVICE_URL=$(gcloud run services describe github-app-token-service \
  --region us-central1 \
  --format 'value(status.url)' \
  --project=$PROJECT_ID)

gcloud run deploy github-app-token-service \
  --region us-central1 \
  --set-env-vars "GITHUB_OAUTH_REDIRECT_URI=${SERVICE_URL}/oauth/callback" \
  --set-secrets "GITHUB_APP_ID=github-app-id:latest" \
  --set-secrets "GITHUB_APP_PRIVATE_KEY_PEM=github-app-private-key-pem:latest" \
  --set-secrets "GITHUB_CLIENT_ID=github-client-id:latest" \
  --set-secrets "GITHUB_CLIENT_SECRET=github-client-secret:latest" \
  --set-secrets "GITHUB_WEBHOOK_SECRET=github-webhook-secret:latest" \
  --project=$PROJECT_ID
```

## Step 6: Test OAuth Flow

### Grant Yourself Access

```bash
gcloud run services add-iam-policy-binding github-app-token-service \
  --region us-central1 \
  --member="user:your-email@example.com" \
  --role="roles/run.invoker" \
  --project=$PROJECT_ID
```

### Complete OAuth Authorization

```bash
# Start authenticated proxy
gcloud run services proxy github-app-token-service \
  --region us-central1 \
  --project=$PROJECT_ID

# In your browser, navigate to:
http://localhost:8080/github/install
```

**What Happens:**
1. Service redirects you to GitHub authorization page
2. You review and approve requested permissions
3. GitHub redirects back to `/oauth/callback`
4. Service exchanges authorization code for access token
5. Token is encrypted and stored in Firestore
6. Success page displays token metadata (not the actual token)

**Success Indicators:**
- ✅ Browser shows "Authorization Successful" page
- ✅ Token type displayed (typically "bearer")
- ✅ Scopes listed (e.g., "repo, user:email")
- ✅ Service logs show successful token storage (masked)

## Callback URL Reference

The following table shows correct callback URLs for different environments:

| Environment | Callback URL | Example |
|-------------|--------------|---------|
| **Cloud Run Production** | `https://<service>-<hash>-<region>.a.run.app/oauth/callback` | `https://github-app-token-service-abc123-uc.a.run.app/oauth/callback` |
| **Local Development** | `http://localhost:<port>/oauth/callback` | `http://localhost:8000/oauth/callback` |
| **ngrok Tunnel** | `https://<subdomain>.ngrok.io/oauth/callback` | `https://abc123.ngrok.io/oauth/callback` |
| **Custom Domain** | `https://your-domain.com/oauth/callback` | `https://tokens.example.com/oauth/callback` |

**⚠️ Critical Rules:**
- Protocol must match (HTTP vs HTTPS)
- No trailing slashes
- Path must be exactly `/oauth/callback`
- Port numbers only for local development
- GitHub treats `localhost` and `127.0.0.1` as different hosts

## OAuth Scopes

The service requests OAuth scopes via the `/github/install` endpoint. Default scopes can be customized via query parameter.

**Default Scopes:**
```
user:email,read:org
```

**Custom Scopes Example:**
```bash
# Request additional scopes
http://localhost:8080/github/install?scopes=repo,user,read:org,admin:repo_hook
```

**Common Scopes:**

| Scope | Access | Use Case |
|-------|--------|----------|
| `repo` | Full repository access | Read/write code, issues, PRs |
| `repo:status` | Read repository commit statuses | CI/CD integration |
| `repo:invite` | Manage repository invitations | Add collaborators |
| `user` | Read/write user profile | Update user information |
| `user:email` | Read user email addresses | Contact user |
| `user:follow` | Follow/unfollow users | Social features |
| `read:org` | Read organization membership | Verify organization access |
| `write:org` | Manage organization | Admin operations |
| `admin:repo_hook` | Manage repository webhooks | Webhook automation |
| `admin:org_hook` | Manage organization webhooks | Organization-level webhooks |
| `gist` | Create/update gists | Snippet sharing |
| `notifications` | Access notifications | Notification management |
| `workflow` | Manage GitHub Actions workflows | CI/CD automation |

**Scope Best Practices:**
- Request minimum scopes needed for your use case
- Users can review scopes before authorizing
- Over-requesting reduces user trust and authorization rate
- Scopes can be changed later (requires user re-authorization)

## GitHub App vs OAuth App

This service uses **GitHub App OAuth**, not classic OAuth Apps. Key differences:

| Feature | GitHub App (This Service) | OAuth App |
|---------|---------------------------|-----------|
| **Authentication** | OAuth + App JWT | OAuth only |
| **Granular Permissions** | ✅ Repository-level | ❌ User-level only |
| **Installation** | Installed per org/repo | User-level authorization |
| **API Rate Limits** | 5,000 requests/hour per installation | 5,000 requests/hour per user |
| **Token Type** | User-to-server tokens | OAuth tokens |
| **Webhooks** | ✅ Built-in | ✅ Available |
| **Future-Proof** | ✅ Modern approach | ⚠️ Legacy |

## Troubleshooting

### "redirect_uri_mismatch" Error

**Error:**
```
The redirect_uri MUST match the registered callback URL for this application.
```

**Cause:** Callback URL in GitHub App settings doesn't match `GITHUB_OAUTH_REDIRECT_URI` environment variable.

**Solution:**
1. Check GitHub App settings → Callback URL
2. Get Cloud Run URL: `gcloud run services describe github-app-token-service --format 'value(status.url)'`
3. Ensure exact match: `<cloud-run-url>/oauth/callback`
4. Check for trailing slashes, protocol (http vs https), port numbers

### "Invalid client_secret" Error

**Cause:** `GITHUB_CLIENT_SECRET` environment variable doesn't match GitHub App client secret.

**Solution:**
1. Verify secret in Secret Manager: `gcloud secrets versions access latest --secret github-client-secret`
2. Regenerate client secret in GitHub App settings if needed
3. Update Secret Manager with new secret
4. Redeploy Cloud Run service

### "Invalid private_key" Error

**Cause:** `GITHUB_APP_PRIVATE_KEY_PEM` is malformed or missing BEGIN/END markers.

**Solution:**
1. Verify PEM format includes `-----BEGIN RSA PRIVATE KEY-----` and `-----END RSA PRIVATE KEY-----`
2. Check for escaped newlines (`\n`) vs literal newlines
3. Regenerate private key in GitHub App settings if needed
4. Re-upload to Secret Manager

### Permissions Not Applied

**Cause:** Updated permissions require user re-authorization.

**Solution:**
1. Users must visit `/github/install` again to authorize new permissions
2. Existing tokens don't automatically gain new permissions
3. Consider revoking old tokens and requiring re-authorization

### Webhook Delivery Failing

**Cause:** Webhook URL is not reachable or webhook secret is incorrect.

**Solution:**
1. Verify webhook URL is publicly accessible (Cloud Run URL)
2. Check webhook secret matches `GITHUB_WEBHOOK_SECRET`
3. Review webhook delivery logs in GitHub App settings
4. **Note**: Webhook handling not yet implemented, so failures are expected

## Security Considerations

### Credential Storage

- ✅ **DO**: Store credentials in Google Secret Manager
- ✅ **DO**: Use IAM to control access to secrets
- ✅ **DO**: Rotate credentials regularly (every 90 days minimum)
- ❌ **DON'T**: Commit credentials to version control
- ❌ **DON'T**: Share credentials via email or Slack
- ❌ **DON'T**: Log credentials in application logs

### OAuth Callback Security

- ✅ **DO**: Use HTTPS for callback URLs in production
- ✅ **DO**: Validate state tokens to prevent CSRF attacks (handled by service)
- ✅ **DO**: Verify callback originates from GitHub (IP allowlisting recommended)
- ❌ **DON'T**: Disable state token validation
- ❌ **DON'T**: Use HTTP callbacks in production

### Permission Minimization

- ✅ **DO**: Request minimum permissions needed
- ✅ **DO**: Document why each permission is needed
- ✅ **DO**: Review permissions periodically
- ❌ **DON'T**: Request admin permissions unless absolutely necessary
- ❌ **DON'T**: Request organization access for personal projects

## Next Steps

1. **Complete OAuth Flow**: See [OPERATIONS.md](OPERATIONS.md) for initial OAuth setup
2. **Configure Monitoring**: Set up alerts for OAuth failures
3. **Review Security**: Read [SECURITY.md](SECURITY.md) for threat model
4. **Plan Credential Rotation**: Schedule regular credential updates

## Reference Links

- [GitHub Apps Documentation](https://docs.github.com/en/apps)
- [GitHub App Permissions](https://docs.github.com/en/rest/overview/permissions-required-for-github-apps)
- [OAuth Scopes for GitHub Apps](https://docs.github.com/en/apps/oauth-apps/building-oauth-apps/scopes-for-oauth-apps)
- [Creating a GitHub App](https://docs.github.com/en/apps/creating-github-apps)
