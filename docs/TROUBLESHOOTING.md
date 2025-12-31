# Troubleshooting Guide

This guide provides solutions to common issues when deploying and operating the GitHub App Token Minting Service.

## Quick Diagnostic Commands

```bash
# Check service status
gcloud run services describe github-app-token-service \
  --region us-central1 \
  --format 'value(status.conditions)'

# View recent logs
gcloud logging tail \
  "resource.type=cloud_run_revision AND resource.labels.service_name=github-app-token-service" \
  --project your-gcp-project-id

# Test health endpoint
curl -H "Authorization: Bearer $(gcloud auth print-identity-token)" \
  $(gcloud run services describe github-app-token-service --region us-central1 --format 'value(status.url)')/healthz

# Check Firestore connectivity
python scripts/show_token_metadata.py
```

## OAuth and Callback Issues

### Error: "redirect_uri_mismatch"

**Symptoms:**
```
The redirect_uri MUST match the registered callback URL for this application.
```

**Cause:** Callback URL in GitHub App settings doesn't match the redirect URI configured in the service.

**Diagnosis:**

```bash
# Get Cloud Run service URL
gcloud run services describe github-app-token-service \
  --region us-central1 \
  --format 'value(status.url)'

# Check GITHUB_OAUTH_REDIRECT_URI environment variable
gcloud run services describe github-app-token-service \
  --region us-central1 \
  --format 'value(spec.template.spec.containers[0].env)'
```

**Solution:**

1. Get exact Cloud Run URL
2. Ensure GitHub App callback URL is: `<cloud-run-url>/oauth/callback`
3. Update GitHub App settings:
   - Go to https://github.com/settings/apps
   - Select your app → General → Callback URL
   - Set to: `https://your-service-abc123.run.app/oauth/callback`
4. Update environment variable:

```bash
export SERVICE_URL=$(gcloud run services describe github-app-token-service \
  --region us-central1 --format 'value(status.url)')

gcloud run services update github-app-token-service \
  --region us-central1 \
  --update-env-vars "GITHUB_OAUTH_REDIRECT_URI=${SERVICE_URL}/oauth/callback"
```

**Common Mistakes:**
- ❌ Trailing slash: `/oauth/callback/`
- ❌ Wrong path: `/auth/callback` instead of `/oauth/callback`
- ❌ Wrong protocol: `http://` instead of `https://`
- ❌ Port numbers in Cloud Run URL (Cloud Run doesn't expose ports)

### Error: "State token mismatch"

**Symptoms:**
```
400 Bad Request: State token mismatch
```

**Cause:** 
- Cookies disabled in browser
- OAuth flow took longer than 5 minutes (state expired)
- Server restarted between `/github/install` and callback

**Solution:**

1. **Enable cookies in browser:**
   - Check browser privacy settings
   - Allow cookies for the Cloud Run domain
   - Try in incognito/private window

2. **Complete flow within 5 minutes:**
   - Don't let GitHub authorization page sit idle
   - Click "Authorize" promptly after reviewing

3. **For multi-instance deployments**, use Redis/Memcache for state storage (not implemented in single-user version)

4. **Test with curl (bypasses cookie issues):**

```bash
# Start fresh OAuth flow
curl -i -H "Authorization: Bearer $(gcloud auth print-identity-token)" \
  "$(gcloud run services describe github-app-token-service --region us-central1 --format 'value(status.url)')/github/install"
```

### Error: "Invalid or expired state token"

**Symptoms:**
```
400 Bad Request: State token is invalid, expired, or has already been used
```

**Cause:**
- OAuth state token expired (>5 minutes since `/github/install`)
- Refreshed callback page (state token already consumed)
- Server restarted (in-memory state store cleared)

**Solution:**

1. **Start over from beginning:**
   - Navigate to `/github/install` again
   - Complete authorization within 5 minutes
   - Don't refresh the callback page

2. **For production with multiple instances**, implement distributed state storage (future enhancement)

### Error: "Failed to exchange authorization code"

**Symptoms:**
```
500 Internal Server Error: Failed to exchange authorization code for access token
```

**Cause:**
- Authorization code already used (can only be used once)
- Authorization code expired (10-minute GitHub limit)
- Incorrect `GITHUB_CLIENT_SECRET`
- Network error communicating with GitHub API

**Diagnosis:**

```bash
# Check client secret in Secret Manager
gcloud secrets versions access latest --secret github-client-secret

# View detailed error in logs
gcloud logging read \
  "resource.type=cloud_run_revision
   AND resource.labels.service_name=github-app-token-service
   AND jsonPayload.message=~\"Failed to exchange\"" \
  --limit 10 --format json
```

**Solution:**

1. **Don't refresh callback page** - authorization codes are single-use
2. **Complete flow within 10 minutes** - GitHub expires authorization codes
3. **Verify client secret is correct:**

```bash
# Regenerate client secret in GitHub App settings
# Store in Secret Manager
echo -n "NEW_CLIENT_SECRET" | \
  gcloud secrets versions add github-client-secret --data-file=-

# Redeploy to pick up new secret
gcloud run deploy github-app-token-service --region us-central1
```

4. **Check GitHub API status:** https://www.githubstatus.com

### Error: "User denied authorization"

**Symptoms:**
```
User canceled the authorization request
```

**Cause:** User clicked "Cancel" instead of "Authorize" on GitHub authorization page.

**Solution:**
- Restart OAuth flow from `/github/install`
- User must click "Authorize" to complete flow

## IAM and Permission Issues

### Error: 403 Forbidden (Cloud Run)

**Symptoms:**
```
Error: Forbidden
Your client does not have permission to get URL / from this server.
```

**Cause:** Calling service/user lacks `roles/run.invoker` permission on Cloud Run service.

**Diagnosis:**

```bash
# Check who has access
gcloud run services get-iam-policy github-app-token-service \
  --region us-central1

# Test with your current credentials
gcloud auth print-identity-token
curl -H "Authorization: Bearer $(gcloud auth print-identity-token)" \
  "$(gcloud run services describe github-app-token-service --region us-central1 --format 'value(status.url)')/healthz"
```

**Solution:**

```bash
# Grant access to a user
gcloud run services add-iam-policy-binding github-app-token-service \
  --region us-central1 \
  --member='user:alice@example.com' \
  --role='roles/run.invoker'

# Grant access to a service account
gcloud run services add-iam-policy-binding github-app-token-service \
  --region us-central1 \
  --member='serviceAccount:my-service@project.iam.gserviceaccount.com' \
  --role='roles/run.invoker'

# Verify IAM policy
gcloud run services get-iam-policy github-app-token-service --region us-central1
```

**Wait 1-2 minutes for IAM changes to propagate.**

### Error: 403 Firestore Permission Denied

**Symptoms:**
```
PermissionError: Permission denied accessing Firestore collection 'github_tokens'
```

**Cause:** Cloud Run service account lacks Firestore IAM permissions.

**Diagnosis:**

```bash
# Get Cloud Run service account
SERVICE_ACCOUNT=$(gcloud run services describe github-app-token-service \
  --region us-central1 \
  --format 'value(spec.template.spec.serviceAccountName)')

# If empty, using default compute service account
if [ -z "$SERVICE_ACCOUNT" ]; then
  PROJECT_NUMBER=$(gcloud projects describe $(gcloud config get-value project) --format='value(projectNumber)')
  SERVICE_ACCOUNT="${PROJECT_NUMBER}-compute@developer.gserviceaccount.com"
  echo "Using default compute service account: $SERVICE_ACCOUNT"
fi

# Check Firestore permissions
gcloud projects get-iam-policy $(gcloud config get-value project) \
  --flatten="bindings[].members" \
  --filter="bindings.members:serviceAccount:${SERVICE_ACCOUNT} AND bindings.role:roles/datastore.user"
```

**Solution:**

```bash
# Grant Firestore access
gcloud projects add-iam-policy-binding $(gcloud config get-value project) \
  --member="serviceAccount:${SERVICE_ACCOUNT}" \
  --role="roles/datastore.user"

# Wait 1-2 minutes for IAM changes to propagate

# Test Firestore access
python scripts/show_token_metadata.py
```

### Error: 403 Secret Manager Access Denied

**Symptoms:**
```
Failed to access secret version: Permission denied
```

**Cause:** Cloud Run service account lacks Secret Manager access.

**Solution:**

```bash
# Get service account
SERVICE_ACCOUNT=$(gcloud run services describe github-app-token-service \
  --region us-central1 \
  --format 'value(spec.template.spec.serviceAccountName)')

# Grant access to all GitHub secrets
for SECRET in github-app-id github-app-private-key-pem github-client-id github-client-secret github-webhook-secret github-token-encryption-key; do
  gcloud secrets add-iam-policy-binding $SECRET \
    --member="serviceAccount:${SERVICE_ACCOUNT}" \
    --role="roles/secretmanager.secretAccessor"
done

# Redeploy to pick up permissions
gcloud run deploy github-app-token-service --region us-central1
```

## Configuration and Environment Variable Issues

### Error: "Missing required configuration"

**Symptoms:**
```
ValueError: Production environment requires the following settings: GITHUB_APP_ID, GITHUB_CLIENT_ID, GITHUB_CLIENT_SECRET
```

**Cause:** Required environment variables or secrets not configured for production (`APP_ENV=prod`).

**Diagnosis:**

```bash
# Check environment variables
gcloud run services describe github-app-token-service \
  --region us-central1 \
  --format 'yaml(spec.template.spec.containers[0].env)'

# Check secrets
gcloud run services describe github-app-token-service \
  --region us-central1 \
  --format 'yaml(spec.template.spec.containers[0].env[].valueFrom.secretKeyRef)'
```

**Solution:**

```bash
# Update secrets (if using Secret Manager)
gcloud run services update github-app-token-service \
  --region us-central1 \
  --set-secrets "GITHUB_APP_ID=github-app-id:latest" \
  --set-secrets "GITHUB_CLIENT_ID=github-client-id:latest" \
  --set-secrets "GITHUB_CLIENT_SECRET=github-client-secret:latest"

# Or update environment variables (not recommended for secrets)
gcloud run services update github-app-token-service \
  --region us-central1 \
  --update-env-vars "GITHUB_APP_ID=123456,GITHUB_CLIENT_ID=Iv1.abc123"
```

### Error: "Invalid encryption key format"

**Symptoms:**
```
ValueError: GITHUB_TOKEN_ENCRYPTION_KEY must be exactly 64 hex characters
```

**Cause:** Encryption key is not 64 hexadecimal characters (32 bytes).

**Solution:**

```bash
# Generate new valid key
NEW_KEY=$(python3 -c 'import secrets; print(secrets.token_hex(32))')
echo "Generated key: $NEW_KEY"

# Update Secret Manager
echo -n "$NEW_KEY" | \
  gcloud secrets versions add github-token-encryption-key --data-file=-

# Redeploy service
gcloud run deploy github-app-token-service --region us-central1

# Note: Existing tokens encrypted with old key cannot be decrypted
# You must delete old token and re-run OAuth flow
python scripts/reset_github_token.py
# Then visit: https://your-service.run.app/github/install
```

### Error: "Invalid PEM key format"

**Symptoms:**
```
ValueError: GITHUB_APP_PRIVATE_KEY_PEM must start with a PEM header
```

**Cause:** Private key is malformed, missing BEGIN/END markers, or has incorrect newlines.

**Diagnosis:**

```bash
# View current key from Secret Manager (first 100 chars)
gcloud secrets versions access latest --secret github-app-private-key-pem | head -c 100

# Should start with: -----BEGIN RSA PRIVATE KEY-----
```

**Solution:**

```bash
# Download new private key from GitHub App settings
# Store in Secret Manager (preserves newlines)
gcloud secrets versions add github-app-private-key-pem \
  --data-file=/path/to/your-app.private-key.pem

# Redeploy
gcloud run deploy github-app-token-service --region us-central1
```

## Firestore Issues

### Error: "Token document not found"

**Symptoms:**
```
404 Not Found: Token document not found in Firestore
```

**Cause:** OAuth flow has not been completed yet, or token was manually deleted.

**Solution:**

```bash
# Complete OAuth flow
# Visit: https://your-service.run.app/github/install

# Verify token exists in Firestore
python scripts/show_token_metadata.py

# Or check Firestore console:
# https://console.cloud.google.com/firestore/data
# → github_tokens collection → primary_user document
```

### Error: "Decryption failed"

**Symptoms:**
```
ValueError: Failed to decrypt token: Invalid authentication tag
```

**Cause:**
- Encryption key was rotated but old token still exists
- Encrypted data corrupted in Firestore
- Wrong encryption key configured

**Solution:**

```bash
# Delete old token and re-authenticate
python scripts/reset_github_token.py

# Verify encryption key is correct (64 hex chars)
gcloud secrets versions access latest --secret github-token-encryption-key | wc -c
# Should output: 64

# Re-run OAuth flow to create new token with current key
# Visit: https://your-service.run.app/github/install
```

### Error: "Firestore database not found"

**Symptoms:**
```
Firestore database does not exist in project
```

**Cause:** Firestore not configured in Native mode.

**Solution:**

```bash
# Create Firestore database in Native mode
gcloud firestore databases create \
  --location=us-central1 \
  --project=$(gcloud config get-value project)

# Wait 2-5 minutes for database provisioning

# Verify database exists
gcloud firestore databases describe
```

## Service Startup and Health Issues

### Service Won't Start

**Symptoms:**
```
Cloud Run error: The user-provided container failed to start and listen on the port defined by the PORT environment variable
```

**Diagnosis:**

```bash
# View startup logs
gcloud logging read \
  "resource.type=cloud_run_revision
   AND resource.labels.service_name=github-app-token-service
   AND timestamp>=\"$(date -u -d '10 minutes ago' --iso-8601=seconds)\"" \
  --limit 50 --format json
```

**Common Causes:**

1. **Missing required environment variables:**
   - Check for `ValueError: Production environment requires...` in logs
   - Add missing secrets/env vars

2. **Invalid credentials:**
   - Check for `ValueError: GITHUB_APP_PRIVATE_KEY_PEM must start with...`
   - Regenerate and update credentials

3. **Container image build failure:**
   - Rebuild image: `gcloud builds submit --tag gcr.io/PROJECT_ID/github-app-token-service:latest`

### Health Check Fails

**Symptoms:**
```
{
  "status": "degraded",
  "firestore": "error"
}
```

**Cause:** Firestore connectivity issues.

**Solution:**

```bash
# Check Firestore IAM permissions (see Firestore Permission Denied section above)

# Test Firestore connectivity
python scripts/show_token_metadata.py

# Check Firestore status
gcloud firestore databases describe
```

## GitHub API and Token Issues

### Error: "Token refresh failed"

**Symptoms:**
```
500 Internal Server Error: Failed to refresh GitHub token
```

**Cause:**
- GitHub API rate limit exceeded
- Refresh token invalid or expired
- Network connectivity issues
- Cooldown period active

**Diagnosis:**

```bash
# Check recent refresh attempts in logs
gcloud logging read \
  "resource.type=cloud_run_revision
   AND resource.labels.service_name=github-app-token-service
   AND jsonPayload.message=~\"refresh\"" \
  --limit 20 --format json

# Check token metadata for cooldown status
curl -H "Authorization: Bearer $(gcloud auth print-identity-token)" \
  "$(gcloud run services describe github-app-token-service --region us-central1 --format 'value(status.url)')/admin/token-metadata"
```

**Solution:**

1. **Wait for cooldown to expire** (default: 5 minutes after failed refresh)
2. **Check GitHub API status:** https://www.githubstatus.com
3. **Force refresh (bypasses cooldown):**

```bash
curl -X POST \
  -H "Authorization: Bearer $(gcloud auth print-identity-token)" \
  -H "Content-Type: application/json" \
  -d '{"force_refresh": true}' \
  "$(gcloud run services describe github-app-token-service --region us-central1 --format 'value(status.url)')/api/token"
```

4. **If refresh consistently fails, re-run OAuth flow:**

```bash
python scripts/reset_github_token.py
# Visit: https://your-service.run.app/github/install
```

### Error: "GitHub API rate limit exceeded"

**Symptoms:**
```
GitHub API rate limit exceeded: 5000 requests/hour
```

**Cause:** Exceeded GitHub's API rate limit (5000 requests/hour for authenticated requests).

**Solution:**

1. **Check rate limit status:**

```bash
# Using GitHub token from service
GITHUB_TOKEN=$(curl -s -X POST \
  -H "Authorization: Bearer $(gcloud auth print-identity-token)" \
  "$(gcloud run services describe github-app-token-service --region us-central1 --format 'value(status.url)')/api/token" | jq -r '.access_token')

curl -H "Authorization: Bearer $GITHUB_TOKEN" \
  https://api.github.com/rate_limit
```

2. **Wait for rate limit reset** (shown in `X-RateLimit-Reset` header)

3. **Reduce API call frequency** in calling services

4. **Consider using GitHub App installation tokens** instead of user tokens (higher rate limits, future enhancement)

## Log Analysis and Debugging

### Structured Log Search

```bash
# View all errors
gcloud logging read \
  "resource.type=cloud_run_revision
   AND resource.labels.service_name=github-app-token-service
   AND severity>=ERROR" \
  --limit 50 --format json

# OAuth flow errors
gcloud logging read \
  "resource.type=cloud_run_revision
   AND resource.labels.service_name=github-app-token-service
   AND jsonPayload.correlation_id:*
   AND severity>=WARNING" \
  --limit 50

# Token refresh events
gcloud logging read \
  "resource.type=cloud_run_revision
   AND resource.labels.service_name=github-app-token-service
   AND jsonPayload.message=~\"token refresh\"" \
  --limit 50 --format json
```

### Request Tracing

Enable request logging for detailed request/response inspection:

```bash
# Enable request logging (increases log volume)
gcloud run services update github-app-token-service \
  --region us-central1 \
  --update-env-vars "ENABLE_REQUEST_LOGGING=true"

# View request logs
gcloud logging read \
  "resource.type=cloud_run_revision
   AND resource.labels.service_name=github-app-token-service
   AND jsonPayload.method:*" \
  --limit 50 --format json
```

### Correlation IDs

All OAuth flows have correlation IDs for tracking:

```bash
# Find all logs for a specific OAuth flow
gcloud logging read \
  "resource.type=cloud_run_revision
   AND resource.labels.service_name=github-app-token-service
   AND jsonPayload.correlation_id=\"abc123-def456-ghi789\"" \
  --format json
```

## Network and Connectivity Issues

### Service Unreachable

**Symptoms:**
```
Connection timeout or refused
```

**Diagnosis:**

```bash
# Check service is running
gcloud run services describe github-app-token-service \
  --region us-central1 \
  --format 'value(status.conditions[0].status)'

# Check recent deployments
gcloud run revisions list \
  --service github-app-token-service \
  --region us-central1

# Test with authenticated request
curl -v -H "Authorization: Bearer $(gcloud auth print-identity-token)" \
  "$(gcloud run services describe github-app-token-service --region us-central1 --format 'value(status.url)')/healthz"
```

**Solution:**

1. **Service is scaling to zero** - make any request to wake it up
2. **IAM authentication required** - include valid identity token in `Authorization` header
3. **Check for recent failed deployments** - roll back if necessary

### Corporate Firewall Blocking OAuth

**Symptoms:**
- GitHub authorization page loads but callback fails
- Timeout when GitHub redirects to Cloud Run callback URL
- Works at home but not at office

**Cause:** Corporate firewall blocks outbound connections to Cloud Run domains or GitHub's redirect targets.

**Solutions:**

1. **Use VPN or personal network** for initial OAuth setup
2. **Request firewall exception** for:
   - `*.run.app` (Cloud Run domains)
   - `github.com` (GitHub OAuth endpoints)
   - `api.github.com` (GitHub API)

3. **Use ngrok tunnel** for local development (temporary workaround):

```bash
# Start ngrok tunnel
ngrok http 8000

# Update GitHub App callback URL to:
# https://abc123.ngrok.io/oauth/callback

# Run service locally with ngrok URL
export GITHUB_OAUTH_REDIRECT_URI="https://abc123.ngrok.io/oauth/callback"
uvicorn app.main:app --host 0.0.0.0 --port 8000
```

## Metrics and Monitoring Issues

### Metrics Endpoint Not Available

**Symptoms:**
```
404 Not Found on /metrics endpoint
```

**Cause:** Metrics endpoint is disabled by default.

**Solution:**

```bash
# Enable metrics
gcloud run services update github-app-token-service \
  --region us-central1 \
  --update-env-vars "ENABLE_METRICS=true"

# Access metrics (requires authentication)
curl -H "Authorization: Bearer $(gcloud auth print-identity-token)" \
  "$(gcloud run services describe github-app-token-service --region us-central1 --format 'value(status.url)')/metrics"
```

## Escalation and Support

When troubleshooting doesn't resolve your issue:

1. **Collect diagnostic information:**
   ```bash
   # Service configuration
   gcloud run services describe github-app-token-service --region us-central1 > service-config.yaml
   
   # Recent logs
   gcloud logging read "resource.type=cloud_run_revision AND resource.labels.service_name=github-app-token-service" \
     --limit 100 --format json > recent-logs.json
   
   # IAM policies
   gcloud run services get-iam-policy github-app-token-service --region us-central1 > iam-policy.yaml
   ```

2. **Check GitHub App configuration:**
   - Verify all credentials are correct
   - Check callback URL matches exactly
   - Review requested permissions

3. **Verify GCP project setup:**
   - All required APIs enabled
   - Firestore database exists in Native mode
   - Service account has necessary permissions

4. **Review documentation:**
   - [SELF_HOSTING.md](SELF_HOSTING.md) for setup steps
   - [GITHUB_APP.md](GITHUB_APP.md) for GitHub configuration
   - [OPERATIONS.md](OPERATIONS.md) for operational procedures
   - [SECURITY.md](SECURITY.md) for security considerations

## Common Error Patterns and Solutions

| Error Pattern | Component | Solution |
|---------------|-----------|----------|
| `redirect_uri_mismatch` | OAuth | Fix callback URL in GitHub App settings |
| `403 Forbidden` | IAM | Grant `roles/run.invoker` or `roles/datastore.user` |
| `404 Not Found` (token) | OAuth | Complete OAuth flow at `/github/install` |
| `500 Internal Server Error` | Various | Check logs for detailed error message |
| `State token mismatch` | OAuth | Enable cookies, complete flow within 5 minutes |
| `Decryption failed` | Firestore | Encryption key mismatch - delete token and re-authenticate |
| `Permission denied` | Firestore/Secrets | Grant IAM permissions to service account |

## Prevention Best Practices

- ✅ Use Secret Manager for all secrets
- ✅ Test OAuth flow after any configuration change
- ✅ Monitor logs regularly for errors
- ✅ Set up alerts for critical failures
- ✅ Document all manual configuration steps
- ✅ Keep credentials backed up securely
- ✅ Test disaster recovery procedures
- ✅ Maintain runbook for common issues

## Reference

- [Cloud Run Troubleshooting](https://cloud.google.com/run/docs/troubleshooting)
- [Firestore Troubleshooting](https://cloud.google.com/firestore/docs/troubleshooting)
- [GitHub OAuth Troubleshooting](https://docs.github.com/en/apps/oauth-apps/maintaining-oauth-apps/troubleshooting-oauth-apps)
