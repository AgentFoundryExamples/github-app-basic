# Operations Guide

This guide covers day-to-day operations including deployment, OAuth flow completion, token verification, and service-to-service integration.

## Prerequisites

- Completed [SELF_HOSTING.md](SELF_HOSTING.md) GCP setup
- Completed [GITHUB_APP.md](GITHUB_APP.md) GitHub App configuration
- Cloud Run service deployed and running
- IAM access to Cloud Run service (`roles/run.invoker`)

## Deployment Operations

### Initial Deployment

Follow the deployment steps in [SELF_HOSTING.md](SELF_HOSTING.md) for initial setup.

### Updating the Service

When code changes or configuration updates are needed:

```bash
export PROJECT_ID="your-gcp-project-id"
export REGION="us-central1"

# 1. Build new container image
gcloud builds submit \
  --tag gcr.io/$PROJECT_ID/github-app-token-service:latest \
  --project=$PROJECT_ID

# 2. Deploy updated image (preserves existing environment variables and secrets)
gcloud run deploy github-app-token-service \
  --image gcr.io/$PROJECT_ID/github-app-token-service:latest \
  --region $REGION \
  --project=$PROJECT_ID

# 3. Verify deployment
gcloud run services describe github-app-token-service \
  --region $REGION \
  --format 'value(status.url)' \
  --project=$PROJECT_ID
```

**Deployment creates a new revision** with zero downtime:
- Traffic gradually shifts to new revision
- Old revision remains available during migration
- Automatic rollback if new revision fails health checks

### Updating Environment Variables

```bash
# Update a single environment variable
gcloud run services update github-app-token-service \
  --region $REGION \
  --update-env-vars "LOG_LEVEL=DEBUG" \
  --project=$PROJECT_ID

# Update multiple environment variables
gcloud run services update github-app-token-service \
  --region $REGION \
  --update-env-vars "LOG_LEVEL=DEBUG,ENABLE_CORS=true" \
  --project=$PROJECT_ID

# Remove an environment variable
gcloud run services update github-app-token-service \
  --region $REGION \
  --remove-env-vars "ENABLE_CORS" \
  --project=$PROJECT_ID
```

### Updating Secrets

```bash
# Update a secret value in Secret Manager
echo -n "new_secret_value" | \
  gcloud secrets versions add github-client-secret \
  --data-file=- \
  --project=$PROJECT_ID

# Redeploy to pick up new secret version
gcloud run deploy github-app-token-service \
  --region $REGION \
  --project=$PROJECT_ID
```

**Note**: Secrets are read at container startup. You must redeploy for changes to take effect.

### Rolling Back

If a deployment causes issues, roll back to a previous revision:

```bash
# List revisions
gcloud run revisions list \
  --service github-app-token-service \
  --region $REGION \
  --project=$PROJECT_ID

# Roll back to specific revision
gcloud run services update-traffic github-app-token-service \
  --region $REGION \
  --to-revisions REVISION_NAME=100 \
  --project=$PROJECT_ID
```

## Installing the GitHub App

### Step 1: Grant Yourself Access

Ensure you have permission to invoke the Cloud Run service:

```bash
export PROJECT_ID="your-gcp-project-id"
export REGION="us-central1"

gcloud run services add-iam-policy-binding github-app-token-service \
  --region $REGION \
  --member="user:your-email@example.com" \
  --role="roles/run.invoker" \
  --project=$PROJECT_ID
```

### Step 2: Start OAuth Flow

Access the service using `gcloud` proxy for authentication:

```bash
# Start authenticated proxy (runs in foreground)
gcloud run services proxy github-app-token-service \
  --region $REGION \
  --project=$PROJECT_ID
```

**In your web browser, navigate to:**
```
http://localhost:8080/github/install
```

**Optional: Request Custom Scopes:**
```
http://localhost:8080/github/install?scopes=repo,user,read:org
```

### Step 3: Authorize on GitHub

You'll be redirected to GitHub's authorization page. Review and approve the requested permissions.

**What You'll See:**
- GitHub App name
- Requested OAuth scopes (permissions)
- Repository selection (if app requires repository access)
- "Authorize [App Name]" button

Click **"Authorize"** to proceed.

### Step 4: Callback and Token Storage

GitHub redirects back to the service's callback URL:

```
https://your-service.run.app/oauth/callback?code=...&state=...
```

**The Service Will:**
1. Validate the state token (CSRF protection)
2. Exchange authorization code for access token
3. Encrypt the token using AES-256-GCM
4. Store encrypted token in Firestore
5. Display success page with token metadata

**Success Page Shows:**
- ✅ "Authorization Successful" message
- Token type (e.g., "bearer")
- Granted scopes (e.g., "repo, user:email, read:org")
- Token expiration (typically "Token does not expire")

### Step 5: Verify Token Storage

Verify the token was stored correctly in Firestore.

**Option 1: Admin API Endpoint**

```bash
# Using gcloud proxy (if still running)
curl http://localhost:8080/admin/token-metadata

# Or with identity token
IDENTITY_TOKEN=$(gcloud auth print-identity-token)
SERVICE_URL=$(gcloud run services describe github-app-token-service \
  --region $REGION \
  --format 'value(status.url)' \
  --project=$PROJECT_ID)

curl -H "Authorization: Bearer $IDENTITY_TOKEN" \
  ${SERVICE_URL}/admin/token-metadata
```

**Expected Response:**
```json
{
  "token_type": "bearer",
  "scope": "repo,user:email,read:org",
  "expires_at": null,
  "has_refresh_token": false,
  "updated_at": "2025-12-30T19:00:00.000000+00:00"
}
```

**Option 2: CLI Script**

```bash
# Set required environment variables
export GCP_PROJECT_ID="your-gcp-project-id"
gcloud auth application-default login

# Run metadata script
cd /path/to/github-app-basic
python scripts/show_token_metadata.py

# Expected output:
# GitHub Token Metadata
# ==================================================
# Token Type:       bearer
# Scope:            repo,user:email,read:org
# Expires At:       never
# Has Refresh:      False
# Updated At:       2025-12-30T19:00:00.000000+00:00
# ==================================================
```

**Option 3: Firestore Console**

1. Navigate to [Cloud Console → Firestore](https://console.cloud.google.com/firestore/data)
2. Select `github_tokens` collection
3. Click `primary_user` document
4. Verify fields:
   - `access_token`: Base64-encoded encrypted string
   - `token_type`: "bearer"
   - `scope`: Requested scopes
   - `expires_at`: null or ISO 8601 timestamp
   - `updated_at`: ISO 8601 timestamp

⚠️ **Never copy the encrypted `access_token` field** - it's encrypted but should still be treated as sensitive.

## Invoking POST /api/token from Platform Services

The `/api/token` endpoint retrieves the stored GitHub token with automatic refresh logic.

### From Cloud Run Service (Python)

```python
import google.auth.transport.requests
import google.oauth2.id_token
import requests

SERVICE_URL = "https://your-service.run.app"

def get_github_token():
    """Get GitHub access token from token service."""
    # Get identity token for service-to-service auth
    auth_req = google.auth.transport.requests.Request()
    id_token = google.oauth2.id_token.fetch_id_token(auth_req, SERVICE_URL)
    
    # Call token endpoint
    response = requests.post(
        f"{SERVICE_URL}/api/token",
        headers={"Authorization": f"Bearer {id_token}"},
        json={"force_refresh": False},
        timeout=30
    )
    response.raise_for_status()
    return response.json()

# Usage
token_data = get_github_token()
github_token = token_data["access_token"]

# Use token for GitHub API calls
github_response = requests.get(
    "https://api.github.com/user",
    headers={
        "Authorization": f"Bearer {github_token}",
        "Accept": "application/vnd.github+json"
    }
)
print(f"Authenticated as: {github_response.json()['login']}")
```

### From Cloud Functions

```python
import functions_framework
import google.auth.transport.requests
import google.oauth2.id_token
import requests

SERVICE_URL = "https://your-service.run.app"

@functions_framework.http
def process_github_data(request):
    """Cloud Function that uses GitHub token."""
    try:
        # Get identity token
        auth_req = google.auth.transport.requests.Request()
        id_token = google.oauth2.id_token.fetch_id_token(auth_req, SERVICE_URL)
        
        # Get GitHub token
        token_response = requests.post(
            f"{SERVICE_URL}/api/token",
            headers={"Authorization": f"Bearer {id_token}"},
            timeout=30
        )
        token_response.raise_for_status()
        github_token = token_response.json()["access_token"]
        
        # Use GitHub token
        repos = requests.get(
            "https://api.github.com/user/repos",
            headers={"Authorization": f"Bearer {github_token}"},
            timeout=30
        ).json()
        
        return {"repos": [r["full_name"] for r in repos]}, 200
        
    except Exception as e:
        return {"error": str(e)}, 500
```

**Deploy Function with IAM Permission:**

```bash
# Deploy function
gcloud functions deploy process-github-data \
  --runtime python311 \
  --trigger-http \
  --region $REGION \
  --project=$PROJECT_ID

# Grant function's service account access to token service
FUNCTION_SA=$(gcloud functions describe process-github-data \
  --region $REGION \
  --format='value(serviceAccountEmail)' \
  --project=$PROJECT_ID)

gcloud run services add-iam-policy-binding github-app-token-service \
  --region $REGION \
  --member="serviceAccount:${FUNCTION_SA}" \
  --role='roles/run.invoker' \
  --project=$PROJECT_ID
```

### From Cloud Scheduler

Schedule regular token refresh or automated tasks:

```bash
# Create service account for scheduler
gcloud iam service-accounts create scheduler-github-token \
  --display-name="Cloud Scheduler for GitHub Token Service" \
  --project=$PROJECT_ID

export SCHEDULER_SA="scheduler-github-token@${PROJECT_ID}.iam.gserviceaccount.com"

# Grant scheduler service account access to token service
gcloud run services add-iam-policy-binding github-app-token-service \
  --region $REGION \
  --member="serviceAccount:${SCHEDULER_SA}" \
  --role='roles/run.invoker' \
  --project=$PROJECT_ID

# Create scheduled job (runs every hour)
SERVICE_URL=$(gcloud run services describe github-app-token-service \
  --region $REGION \
  --format 'value(status.url)' \
  --project=$PROJECT_ID)

gcloud scheduler jobs create http github-token-refresh \
  --schedule="0 * * * *" \
  --uri="${SERVICE_URL}/api/token" \
  --http-method=POST \
  --oidc-service-account-email="$SCHEDULER_SA" \
  --oidc-token-audience="$SERVICE_URL" \
  --headers="Content-Type=application/json" \
  --message-body='{"force_refresh": false}' \
  --location=$REGION \
  --project=$PROJECT_ID
```

### From Local Development

```bash
# Get identity token for your user account
IDENTITY_TOKEN=$(gcloud auth print-identity-token)

# Get service URL
SERVICE_URL=$(gcloud run services describe github-app-token-service \
  --region $REGION \
  --format 'value(status.url)' \
  --project=$PROJECT_ID)

# Call token endpoint
curl -X POST "${SERVICE_URL}/api/token" \
  -H "Authorization: Bearer ${IDENTITY_TOKEN}" \
  -H "Content-Type: application/json" \
  -d '{"force_refresh": false}'

# Expected response:
# {
#   "access_token": "gho_ExampleToken123...",
#   "token_type": "bearer",
#   "expires_at": null
# }
```

## Token Refresh Operations

The service automatically refreshes tokens when they approach expiration.

### Manual Token Refresh

Force a token refresh for testing or after permission changes:

```bash
# Using gcloud proxy
curl -X POST http://localhost:8080/api/token \
  -H "Content-Type: application/json" \
  -d '{"force_refresh": true}'

# Or with identity token
curl -X POST "${SERVICE_URL}/api/token?force_refresh=true" \
  -H "Authorization: Bearer $(gcloud auth print-identity-token)"
```

### Token Refresh Configuration

Configure refresh behavior via environment variables:

```bash
# Set refresh threshold (minutes before expiry)
gcloud run services update github-app-token-service \
  --region $REGION \
  --update-env-vars "TOKEN_REFRESH_THRESHOLD_MINUTES=60" \
  --project=$PROJECT_ID

# Set cooldown period (seconds between refresh attempts)
gcloud run services update github-app-token-service \
  --region $REGION \
  --update-env-vars "TOKEN_REFRESH_COOLDOWN_SECONDS=600" \
  --project=$PROJECT_ID
```

**Default Values:**
- `TOKEN_REFRESH_THRESHOLD_MINUTES=30` (refresh 30 minutes before expiry)
- `TOKEN_REFRESH_COOLDOWN_SECONDS=300` (5-minute cooldown after failed refresh)

### Monitoring Token Refresh

View token refresh activity in logs:

```bash
# View recent refresh attempts
gcloud logging read \
  "resource.type=cloud_run_revision
   AND resource.labels.service_name=github-app-token-service
   AND jsonPayload.message=~\"token refresh\"" \
  --limit 50 \
  --format json \
  --project=$PROJECT_ID
```

**Key Log Fields:**
- `refresh_status`: "success", "skipped", "failed"
- `refresh_reason`: "near_expiry", "force_refresh", "cooldown_active"
- `expires_at`: Token expiration timestamp
- `next_refresh_allowed`: Cooldown expiration timestamp

## Encryption Key Rotation

Regular key rotation improves security but requires service disruption.

### Pre-Rotation Checklist

- [ ] Schedule maintenance window with stakeholders
- [ ] Notify all users who depend on the token service
- [ ] Backup current token metadata (optional)
- [ ] Generate new encryption key
- [ ] Test key format is valid

### Rotation Procedure

```bash
# 1. Generate new encryption key
NEW_KEY=$(python3 -c 'import secrets; print(secrets.token_hex(32))')
echo "New key generated: $NEW_KEY"

# 2. (Optional) Backup current token metadata
python scripts/show_token_metadata.py --json > token_backup_$(date +%Y%m%d).json

# 3. Delete existing token (forces re-authentication)
python scripts/reset_github_token.py

# 4. Update Secret Manager with new key
echo -n "$NEW_KEY" | \
  gcloud secrets versions add github-token-encryption-key \
  --data-file=- \
  --project=$PROJECT_ID

# 5. Redeploy service to pick up new key
gcloud run deploy github-app-token-service \
  --region $REGION \
  --project=$PROJECT_ID

# 6. Re-run OAuth flow to store new token
# Navigate to: https://your-service.run.app/github/install
# (Use gcloud proxy if service is authenticated)

# 7. Verify new token is stored
python scripts/show_token_metadata.py
```

**Estimated Downtime:**
- Token deletion to OAuth completion: 5-15 minutes
- Services cannot make GitHub API calls during this window

**Rotation Frequency:**
- Minimum: Every 90 days
- Recommended: Every 30 days for high-security environments
- Emergency: Immediately if key compromise is suspected

## Monitoring and Observability

### Health Check Endpoint

```bash
# Check service health
curl http://localhost:8080/healthz

# Expected response:
# {
#   "status": "ok",
#   "firestore": "connected"
# }
```

**Health Check Components:**
- `status`: Overall service status ("ok", "degraded", "down")
- `firestore`: Firestore connectivity ("connected", "error")

### View Logs

```bash
# Stream real-time logs
gcloud logging tail \
  "resource.type=cloud_run_revision
   AND resource.labels.service_name=github-app-token-service" \
  --project=$PROJECT_ID

# View recent errors
gcloud logging read \
  "resource.type=cloud_run_revision
   AND resource.labels.service_name=github-app-token-service
   AND severity>=ERROR" \
  --limit 50 \
  --format json \
  --project=$PROJECT_ID

# View OAuth flow logs
gcloud logging read \
  "resource.type=cloud_run_revision
   AND resource.labels.service_name=github-app-token-service
   AND jsonPayload.correlation_id:*" \
  --limit 50 \
  --format json \
  --project=$PROJECT_ID
```

### Metrics and Alerting

Enable Prometheus metrics (optional):

```bash
# Enable metrics endpoint
gcloud run services update github-app-token-service \
  --region $REGION \
  --update-env-vars "ENABLE_METRICS=true" \
  --project=$PROJECT_ID

# Access metrics
curl http://localhost:8080/metrics
```

**Available Metrics:**
- `github_token_refresh_total`: Total token refresh attempts
- `github_token_refresh_success`: Successful refreshes
- `github_token_refresh_failures`: Failed refreshes
- `github_events_webhook_total`: Webhook events received (future)

**Set Up Alerts:**

```bash
# Create alert for token refresh failures
gcloud alpha monitoring policies create \
  --notification-channels=CHANNEL_ID \
  --display-name="GitHub Token Refresh Failures" \
  --condition-display-name="High refresh failure rate" \
  --condition-threshold-value=5 \
  --condition-threshold-duration=300s \
  --aggregation-alignment-period=60s \
  --project=$PROJECT_ID
```

### Request Logging

Enable detailed request logging (increases log volume):

```bash
# Enable request logging middleware
gcloud run services update github-app-token-service \
  --region $REGION \
  --update-env-vars "ENABLE_REQUEST_LOGGING=true" \
  --project=$PROJECT_ID
```

**Request Log Fields:**
- `method`: HTTP method (GET, POST, etc.)
- `path`: Request path
- `status_code`: HTTP status code
- `duration_ms`: Request duration in milliseconds
- `user_agent`: Client user agent string

**⚠️ Note**: Request logging is disabled by default to reduce log volume and costs.

## Backup and Disaster Recovery

### Token Metadata Backup

```bash
# Export token metadata (does NOT export actual tokens)
python scripts/show_token_metadata.py --json > backup_$(date +%Y%m%d).json

# Backup contains:
# - Token type
# - Scopes
# - Expiration timestamp
# - Last update timestamp
```

**What's NOT Backed Up:**
- Decrypted access tokens (intentional - not recoverable)
- Refresh tokens
- Encryption keys

### Firestore Backup

```bash
# Export entire Firestore database
gcloud firestore export gs://your-backup-bucket/firestore-backup-$(date +%Y%m%d) \
  --project=$PROJECT_ID

# Export specific collection
gcloud firestore export gs://your-backup-bucket/github-tokens-backup-$(date +%Y%m%d) \
  --collection-ids=github_tokens \
  --project=$PROJECT_ID
```

### Disaster Recovery

In case of total data loss:

1. **Redeploy Service**: Follow [SELF_HOSTING.md](SELF_HOSTING.md) deployment steps
2. **Generate New Encryption Key**: Old key cannot decrypt lost data anyway
3. **Re-Run OAuth Flow**: User must re-authorize to generate new token
4. **Update Dependent Services**: Notify services that token was regenerated

**Recovery Time Objective (RTO):**
- Service redeployment: 10-15 minutes
- OAuth re-authorization: 5 minutes
- **Total**: ~20 minutes

**Recovery Point Objective (RPO):**
- Token data is not recoverable from backups (encrypted with lost key)
- Must re-authorize to generate new token

## Troubleshooting Common Issues

See [TROUBLESHOOTING.md](TROUBLESHOOTING.md) for detailed troubleshooting steps.

**Quick Reference:**

| Issue | Likely Cause | Quick Fix |
|-------|--------------|-----------|
| 404 on `/api/token` | OAuth not completed | Visit `/github/install` to authorize |
| 403 Permission Denied | Missing IAM permission | Grant `roles/run.invoker` to caller |
| 500 Token Refresh Failed | GitHub API error or rate limit | Check logs, wait for cooldown to expire |
| Callback redirect fails | Incorrect callback URL | Verify callback URL matches exactly |

## Next Steps

1. **Review Security**: Read [SECURITY.md](SECURITY.md) for threat model and best practices
2. **Plan Monitoring**: Set up Cloud Monitoring alerts for errors
3. **Test Integration**: Verify service-to-service calls work correctly
4. **Schedule Maintenance**: Plan regular key rotation and dependency updates

## Reference

- [Cloud Run Documentation](https://cloud.google.com/run/docs)
- [Firestore Documentation](https://cloud.google.com/firestore/docs)
- [Secret Manager Documentation](https://cloud.google.com/secret-manager/docs)
- [GitHub API Documentation](https://docs.github.com/en/rest)
