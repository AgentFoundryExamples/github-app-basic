# GitHub App Token Minting Service

FastAPI-based service for minting GitHub App tokens with GCP integration, designed for Cloud Run deployment.

## Features

- 🚀 FastAPI framework with async support
- ⚙️ Pydantic Settings-based configuration management
- 📝 Structured JSON logging with request ID tracing
- 🏥 Health check endpoint
- 📚 Auto-generated OpenAPI documentation (Swagger UI)
- 🔒 Production environment validation
- 🌐 Optional CORS middleware (disabled by default)
- 🔐 OAuth token persistence with AES-256-GCM encryption in Firestore
- 🛡️ Secure token storage with automated timestamp normalization (UTC ISO-8601)
- 🔄 Token refresh workflows with cooldown enforcement and retry logic

## Prerequisites

- Python 3.11 or higher
- pip package manager

## Installation

1. Clone the repository:
```bash
git clone <repository-url>
cd github-app-basic
```

2. Create a virtual environment (recommended):
```bash
python3 -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate
```

3. Install dependencies:
```bash
pip install -r requirements.txt
```

4. For development, also install dev dependencies:
```bash
pip install -r requirements-dev.txt
```

## Configuration

The service is configured via environment variables. Create a `.env` file in the project root or export the variables:

### GitHub App Setup

Before configuring the service, you need to create and configure a GitHub App. Follow these steps carefully to ensure proper OAuth integration.

1. **Create a GitHub App**:
   - Go to [GitHub Settings → Developer settings → GitHub Apps](https://github.com/settings/apps)
   - Click "New GitHub App"
   - Fill in the required information:
     - **GitHub App name**: Choose a unique name (e.g., "My Token Minting Service")
     - **Homepage URL**: Your application URL or repository URL
     - **Webhook URL**: `https://your-service.run.app/webhooks/github` (or your local testing URL)
       - *Note: Webhook functionality is not yet implemented but required by GitHub*
     - **Webhook secret**: Generate a secure random token (e.g., `openssl rand -hex 32`)

2. **Configure Permissions** (as needed for your use case):
   - Set repository or organization permissions based on your requirements
   - Common permissions for token minting:
     - **Repository permissions:** Contents (read), Metadata (read)
     - **Organization permissions:** Members (read)
   - Subscribe to relevant webhook events (for future webhook handling)

3. **Generate OAuth Credentials**:
   - In your GitHub App settings, note the **App ID** (numeric, e.g., `123456`)
   - Under "Client secrets" section:
     - Click "Generate a new client secret"
     - **Copy the secret immediately** - GitHub shows it only once
     - This is your `GITHUB_CLIENT_SECRET`
   - Note the **Client ID** at the top (starts with `Iv1.` or `Iv23.`)
     - This is your `GITHUB_CLIENT_ID`

4. **Generate a Private Key**:
   - Scroll to "Private keys" section
   - Click "Generate a private key"
   - Download the `.pem` file - this is your `GITHUB_APP_PRIVATE_KEY_PEM`
   - **IMPORTANT**: Store this file securely. GitHub will not show it again.
   - For production, consider using Google Secret Manager or similar

5. **Configure OAuth Callback URL**:
   - ⚠️ **CRITICAL:** The callback URL must exactly match your service's redirect URI
   - In GitHub App settings, under "Identifying and authorizing users":
     - **Callback URL** (required for OAuth):
       - Local development: `http://localhost:8000/oauth/callback`
       - Cloud Run: `https://your-service-name-xxxxx-uc.a.run.app/oauth/callback`
     - **Request user authorization (OAuth) during installation:** ✅ Enable this
     - **Enable Device Flow:** Optional (not used by this service)
   
   ⚠️ **Common Mistakes to Avoid:**
   - Using `/auth/callback` instead of `/oauth/callback` (incorrect path)
   - Missing or incorrect protocol (HTTP vs HTTPS)
   - Including trailing slashes (e.g., `/oauth/callback/`)
   - Using `localhost` vs `127.0.0.1` (GitHub treats these as different)
   - Wrong port number

6. **Save the GitHub App**:
   - Click "Create GitHub App" at the bottom
   - You'll be redirected to your app's settings page
   - Keep this page open for copying credentials

**After Creating the App:**
- Copy all credentials immediately (especially the client secret, shown only once)
- Store credentials securely (never commit to git)
- Test the OAuth flow using the [OAuth Flow Manual Verification](#oauth-flow-manual-browser-verification) guide

### Required for Production (APP_ENV=prod)

```bash
# Application
APP_ENV=prod

# GitHub App Configuration
GITHUB_APP_ID=<your-app-id>                    # Numeric App ID from GitHub App settings
GITHUB_APP_PRIVATE_KEY_PEM=<your-private-key>  # Contents of downloaded .pem file
GITHUB_CLIENT_ID=<your-client-id>              # OAuth Client ID (starts with Iv1.)
GITHUB_CLIENT_SECRET=<your-client-secret>      # Generated OAuth client secret
GITHUB_OAUTH_REDIRECT_URI=<your-redirect-uri>  # OAuth callback URL
# GITHUB_WEBHOOK_SECRET is optional but recommended for webhook validation

# GCP Configuration (required for Firestore)
GCP_PROJECT_ID=<your-project-id>
GOOGLE_APPLICATION_CREDENTIALS=<path-to-credentials-json>

# Token Storage Encryption (required for production)
GITHUB_TOKEN_ENCRYPTION_KEY=<64-char-hex-key>  # Generate with: python -c 'import secrets; print(secrets.token_hex(32))'
```

### PEM Key Format

The `GITHUB_APP_PRIVATE_KEY_PEM` must be in PEM format with proper BEGIN/END markers. You have two options:

**Option 1: Escaped newlines (recommended for environment variables)**
```bash
export GITHUB_APP_PRIVATE_KEY_PEM="-----BEGIN RSA PRIVATE KEY-----\nMIIEpAIBAAKCAQEA...\n-----END RSA PRIVATE KEY-----"
```

**Option 2: Literal newlines (for .env files)**
```bash
GITHUB_APP_PRIVATE_KEY_PEM="-----BEGIN RSA PRIVATE KEY-----
MIIEpAIBAAKCAQEA...
-----END RSA PRIVATE KEY-----"
```

The service automatically handles both formats and provides clear error messages for invalid PEM keys.

### Optional Configuration

```bash
# Application
PORT=8000              # Server port (default: 8000)
LOG_LEVEL=INFO         # Logging level (default: INFO)

# GCP
REGION=us-central     # GCP region (default: us-central)

# CORS
ENABLE_CORS=false      # Enable CORS middleware (default: false)

# GitHub Webhook Secret (optional, but recommended for production)
GITHUB_WEBHOOK_SECRET=<your-webhook-secret>  # For webhook signature verification

# Token Storage (optional, defaults provided)
GITHUB_TOKENS_COLLECTION=github_tokens  # Firestore collection name for tokens
GITHUB_TOKENS_DOC_ID=primary_user       # Document ID for the primary token

# Token Refresh Configuration (optional, defaults provided)
TOKEN_REFRESH_THRESHOLD_MINUTES=30      # Minutes before expiry to refresh token (default: 30)
TOKEN_REFRESH_COOLDOWN_SECONDS=300      # Cooldown between refresh attempts (default: 300 = 5 min)
```

### Token Refresh Workflows

The service includes automatic token refresh capabilities with intelligent cooldown enforcement:

- **Refresh Method**: Uses OAuth `refresh_token` grant when available, falls back to reissue via GitHub App
- **Cooldown Enforcement**: Prevents excessive API calls by enforcing a configurable cooldown period between failed refresh attempts
- **Retry Logic**: Automatically retries transient errors (500, network issues) with exponential backoff
- **Error Handling**: Properly handles permanent failures (401, 422) without retry
- **Metadata Persistence**: Tracks refresh attempts, status, and errors in Firestore for observability

**Configuration Options:**
- `TOKEN_REFRESH_THRESHOLD_MINUTES`: How many minutes before token expiry to consider it "near-expiry" (default: 30)
- `TOKEN_REFRESH_COOLDOWN_SECONDS`: Minimum seconds between refresh attempts after failures (default: 300)

**Force Refresh:**
Token refresh can bypass cooldown when explicitly requested with `force_refresh=True`, useful for administrative operations.
```

### Development Defaults

For local development, only `APP_ENV=dev` is needed. All other fields are optional and will use sensible defaults.

### Firestore Configuration

The service includes Firestore integration for data persistence:

#### Local Development Setup

1. **Install Google Cloud SDK** (if not already installed):
   ```bash
   # Follow instructions at: https://cloud.google.com/sdk/docs/install
   ```

2. **Authenticate with your Google Cloud account**:
   ```bash
   gcloud auth application-default login
   ```

3. **Or use a service account key** (alternative to step 2):
   ```bash
   # Download service account key from GCP Console
   export GOOGLE_APPLICATION_CREDENTIALS=/path/to/your/service-account-key.json
   ```

4. **Set your GCP project ID**:
   ```bash
   export GCP_PROJECT_ID=your-gcp-project-id
   ```

#### Cloud Run Deployment

In Cloud Run, Firestore authentication uses the default service account automatically. Ensure:
- The Cloud Run service account has the `roles/datastore.user` or `roles/datastore.owner` IAM role
- `GCP_PROJECT_ID` environment variable is set in Cloud Run configuration

#### Firestore Usage

The Firestore DAO is available via FastAPI dependency injection:

```python
from fastapi import APIRouter, Depends
from app.dao.firestore_dao import FirestoreDAO
from app.dependencies.firestore import get_firestore_dao

router = APIRouter()

@router.get("/example")
async def example_endpoint(dao: FirestoreDAO = Depends(get_firestore_dao)):
    # Get a document
    doc = await dao.get_document("collection_name", "doc_id")
    
    # Set a document
    await dao.set_document("collection_name", "doc_id", {"key": "value"})
    
    return {"status": "ok"}
```

#### GitHub Token Storage in Firestore

The service stores GitHub OAuth tokens securely in Firestore with encryption. This section describes the storage schema, encryption strategy, and operational procedures.

##### Firestore Schema

**Collection:** `github_tokens` (configurable via `GITHUB_TOKENS_COLLECTION`)

**Document ID:** `primary_user` (configurable via `GITHUB_TOKENS_DOC_ID`)

**Document Structure:**

| Field | Type | Description | Encrypted |
|-------|------|-------------|-----------|
| `access_token` | String | GitHub OAuth access token | ✅ Yes (AES-256-GCM) |
| `token_type` | String | Token type (typically "bearer") | ❌ No |
| `scope` | String | OAuth scopes granted (e.g., "repo,user:email,read:org") | ❌ No |
| `expires_at` | String | ISO 8601 UTC timestamp of token expiration (null if no expiry) | ❌ No |
| `refresh_token` | String | Optional refresh token for token renewal | ✅ Yes (AES-256-GCM) |
| `updated_at` | String | ISO 8601 UTC timestamp when token was last saved | ❌ No |

**Encryption Format:**
- Encrypted fields are stored as Base64-encoded strings
- Format: `base64(nonce || ciphertext || auth_tag)`
  - `nonce`: 12 bytes (96 bits) - randomly generated per encryption
  - `ciphertext`: Variable length - encrypted token data
  - `auth_tag`: 16 bytes (128 bits) - GCM authentication tag

**Example Document (in Firestore):**
```json
{
  "access_token": "WyRQmxK7pNjM3kL2pHqR8vS9wT0uA1bC2dE3fF4gG5hH6iI7jJ8kK9lL0mM1nN2oO3pP4qQ5rR6sS7tT8uU9vV0wW1xX2yY3zZ4aA5bB6cC7dD8eE9fF0gG1hH2iI3jJ4kK5lL==",
  "token_type": "bearer",
  "scope": "repo,user:email,read:org",
  "expires_at": null,
  "refresh_token": null,
  "updated_at": "2025-12-30T19:00:00.000000+00:00"
}
```

⚠️ **IMPORTANT:** Never copy the `access_token` or `refresh_token` fields from Firestore into logs, issue trackers, or documentation. These encrypted values cannot be decrypted without the encryption key, but exposing them is still a security risk.

##### Encryption Strategy

The service uses a **defense-in-depth** encryption strategy with multiple layers:

**1. GCP-Managed Encryption at Rest (Default)**
- All Firestore data is automatically encrypted at rest by Google Cloud Platform
- Uses Google-managed encryption keys (GMEK)
- Transparent to applications - no configuration required
- Provides baseline security for all stored data

**2. Application-Level Encryption (Required)**
- Additional encryption layer using AES-256 in GCM mode
- Protects tokens even if Firestore data is compromised
- Requires explicit configuration via environment variable

**Encryption Algorithm:** AES-256-GCM
- **AES-256**: Advanced Encryption Standard with 256-bit keys
- **GCM**: Galois/Counter Mode - provides both confidentiality and authenticity
- **Key Size:** 32 bytes (256 bits)
- **Nonce Size:** 12 bytes (96 bits, randomly generated per encryption)
- **Authentication Tag:** 16 bytes (128 bits)

**Required Environment Variable:**
```bash
# Generate a new encryption key (32 bytes = 64 hex characters)
export GITHUB_TOKEN_ENCRYPTION_KEY=$(python -c 'import secrets; print(secrets.token_hex(32))')

# Example output: c4f9a8b2e7d6f1a3c9b8e7f6a5d4c3b2a1f9e8d7c6b5a4f3e2d1c0b9a8f7e6d5
```

**Production Configuration:**
```bash
# For Cloud Run deployment - set as environment variable
gcloud run services update github-app-token-service \
  --region us-central1 \
  --update-env-vars GITHUB_TOKEN_ENCRYPTION_KEY=your_64_char_hex_key \
  --project your-gcp-project-id
```

⚠️ **CRITICAL:** For production, use Google Secret Manager instead of environment variables:
```bash
# Store encryption key in Secret Manager
echo -n "your_64_char_hex_key" | gcloud secrets create github-token-encryption-key --data-file=-

# Deploy Cloud Run with secret reference
gcloud run deploy github-app-token-service \
  --set-secrets="GITHUB_TOKEN_ENCRYPTION_KEY=github-token-encryption-key:latest" \
  --project your-gcp-project-id
```

##### Key Rotation

To rotate the encryption key, you must re-encrypt all stored tokens with the new key. This service does not currently support automatic key rotation, so manual intervention is required:

**Key Rotation Steps:**

1. **Generate a new encryption key:**
   ```bash
   python -c 'import secrets; print(secrets.token_hex(32))'
   ```

2. **Backup existing tokens** (optional, for rollback):
   - Use the Firestore console or `gcloud firestore export` to backup data
   - Or use `show_token_metadata.py` to record metadata

3. **Delete the old token** (forces re-authentication):
   ```bash
   python scripts/reset_github_token.py
   ```

4. **Update the encryption key** in your deployment:
   ```bash
   # For Cloud Run
   gcloud run services update github-app-token-service \
     --update-env-vars GITHUB_TOKEN_ENCRYPTION_KEY=new_64_char_hex_key \
     --project your-gcp-project-id
   
   # Or update Secret Manager
   echo -n "new_64_char_hex_key" | gcloud secrets versions add github-token-encryption-key --data-file=-
   ```

5. **Re-run the OAuth flow** to store a new token encrypted with the new key:
   - Navigate to `https://<your-service-name>.run.app/github/install`
   - Complete the GitHub authorization flow
   - New token will be encrypted with the new key

**Rotation Frequency:**
- **Recommended:** Every 90 days minimum
- **Best Practice:** Every 30 days for high-security environments
- **Emergency:** Immediately if key compromise is suspected

**Service Availability During Rotation:**
- ⚠️ **Downtime Required:** The token rotation process requires deleting the existing token, which will cause service disruption for any processes or services using the token.
- **Impact:** Between steps 3 (delete token) and 5 (complete OAuth), the service cannot make authenticated GitHub API calls.
- **Recommended Approach:**
  - Schedule rotation during a maintenance window with minimal traffic
  - Notify all stakeholders before beginning the rotation
  - For critical services, consider having a backup authentication method ready
  - If multiple services share the same token, coordinate rotation to minimize total downtime
  - Test the OAuth flow in advance to ensure quick re-authentication
- **Estimated Downtime:** 5-15 minutes depending on OAuth flow completion time

**Limitations:**
- Manual process - no automatic key rotation yet
- Requires re-authentication after rotation
- Cannot decrypt old tokens with the new key (by design)
- Single-user design means all services share the same token

##### IAM Setup Requirements

To access Firestore, the Cloud Run service account must have appropriate IAM roles.

**Required IAM Role:**
- `roles/datastore.user` (read/write access to Firestore)
- OR `roles/datastore.owner` (full access, includes delete)

**Recommended:** Use `roles/datastore.user` for least privilege.

**Grant IAM Permissions:**

1. **Identify the Cloud Run service account:**
   ```bash
   # Get the service account used by Cloud Run
   SERVICE_ACCOUNT=$(gcloud run services describe github-app-token-service \
     --region us-central1 \
     --format 'value(spec.template.spec.serviceAccountName)' \
     --project $PROJECT_ID)
   
   # If empty, Cloud Run uses the default compute service account
   if [ -z "$SERVICE_ACCOUNT" ]; then
     PROJECT_NUMBER=$(gcloud projects describe $PROJECT_ID --format='value(projectNumber)')
     SERVICE_ACCOUNT="${PROJECT_NUMBER}-compute@developer.gserviceaccount.com"
     echo "Using default compute service account: $SERVICE_ACCOUNT"
   fi
   ```

2. **Grant Firestore access:**
   ```bash
   gcloud projects add-iam-policy-binding $PROJECT_ID \
     --member="serviceAccount:${SERVICE_ACCOUNT}" \
     --role="roles/datastore.user"
   ```

3. **Verify IAM permissions:**
   ```bash
   gcloud projects get-iam-policy $PROJECT_ID \
     --flatten="bindings[].members" \
     --format="table(bindings.role)" \
     --filter="bindings.members:serviceAccount:${SERVICE_ACCOUNT}"
   ```

**Best Practices:**
- **Dedicated Service Account:** Create a dedicated service account for Cloud Run instead of using the default compute account:
  ```bash
  # Create dedicated service account
  gcloud iam service-accounts create github-app-token-service \
    --display-name="GitHub App Token Service" \
    --project your-gcp-project-id
  
  # Grant Firestore access
  gcloud projects add-iam-policy-binding your-gcp-project-id \
    --member="serviceAccount:github-app-token-service@your-gcp-project-id.iam.gserviceaccount.com" \
    --role="roles/datastore.user"
  
  # Deploy Cloud Run with dedicated service account
  gcloud run deploy github-app-token-service \
    --service-account github-app-token-service@your-gcp-project-id.iam.gserviceaccount.com \
    --project your-gcp-project-id
  ```

- **Enable Audit Logging:** Monitor Firestore access via Cloud Audit Logs:
  - Navigate to Cloud Console → IAM & Admin → Audit Logs
  - Enable Data Read and Data Write logging for Cloud Datastore API
  - Review logs regularly for unauthorized access attempts
  - **Suspicious Patterns to Monitor:**
    - Multiple failed authentication attempts from the same service account
    - Firestore access from unexpected IP addresses or regions
    - Unusual read volume on the `github_tokens` collection
    - Access attempts outside normal service hours
    - Changes to IAM policies for Firestore or service accounts
  - **Recommended Alerts:**
    - Set up Cloud Monitoring alerts for Firestore permission denied errors (403)
    - Alert on unexpected service account usage
    - Monitor for encryption/decryption failures
    - Track changes to the encryption key environment variable

- **Principle of Least Privilege:** Grant only `roles/datastore.user`, not `roles/datastore.owner`, unless delete operations are required

##### Inspecting Token Metadata

Operators can inspect token metadata (without exposing the actual token) using three methods:

**Method 1: Cloud Console (Firestore UI)**

1. Navigate to Cloud Console → Firestore → Data
2. Select the `github_tokens` collection
3. Click the `primary_user` document
4. View metadata fields:
   - `token_type`, `scope`, `expires_at`, `updated_at`
   - `access_token` and `refresh_token` show encrypted Base64 strings
5. ⚠️ **DO NOT** copy or share the encrypted `access_token` field

**Method 2: `/admin/token-metadata` API Endpoint**

The service provides a secure admin endpoint that returns metadata only (never the actual token):

```bash
# Access via gcloud proxy (requires IAM authentication)
gcloud beta run proxy github-app-token-service --region us-central1

# In another terminal, call the endpoint
curl http://localhost:8080/admin/token-metadata

# Example response:
{
  "token_type": "bearer",
  "scope": "repo,user:email,read:org",
  "expires_at": null,
  "has_refresh_token": true,
  "updated_at": "2025-12-30T19:00:00.000000+00:00"
}
```

**Security:** This endpoint relies on Cloud Run IAM authentication. Ensure Cloud Run is deployed with `--no-allow-unauthenticated` and grant `roles/run.invoker` only to authorized users.

**Method 3: `show_token_metadata.py` CLI Script**

For local or automated inspection, use the provided CLI script:

```bash
# Set up authentication
export GCP_PROJECT_ID=your-gcp-project-id
gcloud auth application-default login

# Show token metadata (default location)
python scripts/show_token_metadata.py

# Output:
# GitHub Token Metadata
# ==================================================
# Token Type:       bearer
# Scope:            repo,user:email,read:org
# Expires At:       never
# Has Refresh:      False
# Updated At:       2025-12-30T19:00:00.000000+00:00
# ==================================================

# JSON output for automation
python scripts/show_token_metadata.py --json

# Custom collection/document
python scripts/show_token_metadata.py --collection my_tokens --doc-id user123
```

**What Metadata is Exposed:**
- ✅ `token_type` - Token type (e.g., "bearer")
- ✅ `scope` - OAuth scopes granted
- ✅ `expires_at` - Expiration timestamp (if applicable)
- ✅ `has_refresh_token` - Boolean indicating if refresh token exists
- ✅ `updated_at` - Last update timestamp

**What is NEVER Exposed:**
- ❌ `access_token` - The decrypted GitHub access token
- ❌ `refresh_token` - The decrypted refresh token
- ❌ Encrypted ciphertext values

##### Security Considerations

**No Endpoint Returns the Raw Token:**
- The `/oauth/callback` endpoint stores the token but never displays it
- The `/admin/token-metadata` endpoint returns only metadata
- Logs mask tokens showing only first 8 and last 4 characters
- No API endpoint exists to retrieve the decrypted token

**Logging Best Practices:**
- All token values are masked in logs using `mask_sensitive_data()`
- Example: `ghp_abc12...xyz9` instead of full token
- Correlation IDs track OAuth flows without exposing tokens
- Never log decrypted tokens or encryption keys

**Encrypted Data Handling:**
- ⚠️ Never copy encrypted `access_token` or `refresh_token` fields from Firestore
- ⚠️ Never paste encrypted blobs into issue trackers, logs, or documentation
- ⚠️ Never commit encryption keys to version control
- ⚠️ Never share encryption keys via email, Slack, or other communication channels

**Encryption Key Management Security:**
- ⚠️ **Shell History Exposure:** When setting `GITHUB_TOKEN_ENCRYPTION_KEY` via `export`, the key will be saved in shell history
  - Mitigation: Use `set +o history` before setting the variable, then `set -o history` after
  - Better: Use Secret Manager to avoid environment variables entirely
  - Alternative: Prefix the command with a space (in bash with `HISTCONTROL=ignorespace`)
- ⚠️ **Plaintext Key Storage:** Environment variables are visible to processes and may appear in logs
  - **Production:** Always use Google Secret Manager to inject keys securely
  - **Never** set encryption keys directly via `--update-env-vars` in production
  - Use `--set-secrets` with Secret Manager references instead
- ⚠️ **Potential Token Exposure:** During local development, tokens may be exposed through:
  - Browser developer tools when viewing OAuth callbacks
  - Application logs if debug logging is enabled
  - Process environment inspection tools
  - Always use `APP_ENV=prod` settings in production to enforce security validations

**Authentication and Authorization:**
- ⚠️ **Insufficient Auth Guidance:** The `/admin/token-metadata` endpoint relies entirely on Cloud Run IAM
  - **CRITICAL:** Always deploy with `--no-allow-unauthenticated`
  - Verify IAM policies with `gcloud run services get-iam-policy`
  - Grant `roles/run.invoker` only to specific users/service accounts
  - Regularly audit who has access to the Cloud Run service
  - Do not rely on obscurity - IAM authentication is your only protection

**Token Lifecycle:**
- Tokens are encrypted immediately upon receipt from GitHub
- Tokens remain encrypted in Firestore at rest
- Tokens are only decrypted in memory when needed for API calls
- No caching of decrypted tokens in application memory

**Incident Response:**
- If encryption key is compromised, rotate immediately following key rotation steps
- If Firestore access is compromised, revoke IAM permissions and rotate key
- If token is leaked, revoke it in GitHub App settings and re-authenticate

##### Local Development Setup

For local development, you have two options for Firestore access:

**Option 1: Firestore Emulator (No GCP Project Required)**

```bash
# Install Firebase tools
npm install -g firebase-tools

# Start Firestore emulator
firebase emulators:start --only firestore

# Set emulator environment variable (in another terminal)
export FIRESTORE_EMULATOR_HOST=localhost:8080
export GCP_PROJECT_ID=demo-project  # Any value works with emulator
export GOOGLE_APPLICATION_CREDENTIALS=""  # Prevents ADC lookup
export GITHUB_TOKEN_ENCRYPTION_KEY=$(python -c 'import secrets; print(secrets.token_hex(32))')

# Run the service
uvicorn app.main:app --reload
```

**Emulator Characteristics:**
- No GCP credentials needed
- Data is ephemeral (cleared on restart)
- No IAM authentication required
- Perfect for local testing and development

**Option 2: Application Default Credentials (ADC) with GCP Project**

```bash
# Authenticate with your GCP account
gcloud auth application-default login

# Set project ID and encryption key
export GCP_PROJECT_ID=your-gcp-project-id
export GITHUB_TOKEN_ENCRYPTION_KEY=$(python -c 'import secrets; print(secrets.token_hex(32))')

# Run the service
uvicorn app.main:app --reload
```

**ADC Characteristics:**
- Uses real GCP Firestore database
- Requires valid GCP project and permissions
- Data persists across runs
- Subject to IAM authentication
- Useful for testing against production-like environment

**Key Differences from Production:**

| Aspect | Local (Emulator) | Local (ADC) | Production (Cloud Run) |
|--------|-----------------|-------------|------------------------|
| **Credentials** | None required | User credentials (ADC) | Service account |
| **IAM Roles** | Not enforced | User's IAM roles | Service account IAM roles |
| **Data Persistence** | Ephemeral | Persistent | Persistent |
| **Encryption** | Required (same as prod) | Required (same as prod) | Required |
| **Firestore** | Emulated locally | Real GCP Firestore | Real GCP Firestore |

##### Troubleshooting

**Firestore Permission Denied (403)**

**Error:**
```
PermissionError: Permission denied accessing Firestore collection 'github_tokens'.
Ensure the service account has proper IAM roles (roles/datastore.user or roles/datastore.owner).
```

**Cause:**
- Cloud Run service account lacks Firestore IAM permissions

**Fix:**
```bash
# Identify service account
SERVICE_ACCOUNT=$(gcloud run services describe github-app-token-service \
  --region us-central1 \
  --format 'value(spec.template.spec.serviceAccountName)' \
  --project your-gcp-project-id)

# Grant Firestore access
gcloud projects add-iam-policy-binding your-gcp-project-id \
  --member="serviceAccount:${SERVICE_ACCOUNT}" \
  --role="roles/datastore.user"

# Wait 1-2 minutes for IAM changes to propagate
```

**Missing Encryption Key**

**Error:**
```
ValueError: Encryption key not configured. Set GITHUB_TOKEN_ENCRYPTION_KEY environment variable.
```

**Cause:**
- `GITHUB_TOKEN_ENCRYPTION_KEY` environment variable not set

**Fix:**
```bash
# Local development
export GITHUB_TOKEN_ENCRYPTION_KEY=$(python -c 'import secrets; print(secrets.token_hex(32))')

# Cloud Run
gcloud run services update github-app-token-service \
  --update-env-vars GITHUB_TOKEN_ENCRYPTION_KEY=your_64_char_hex_key \
  --project your-gcp-project-id
```

**Decryption Failed**

**Error:**
```
ValueError: Failed to decrypt token: Invalid authentication tag
```

**Possible Causes:**
1. Encryption key was rotated but old token still exists
2. Encrypted data was corrupted in Firestore
3. Wrong encryption key is configured

**Fix:**
```bash
# Delete the old token and re-authenticate
python scripts/reset_github_token.py

# Navigate to the OAuth flow to create a new token
# https://your-service.run.app/github/install
```

**Token Document Not Found**

**Error:**
```
404 Not Found: Token document not found in Firestore
```

**Cause:**
- OAuth flow has not been completed yet
- Document was deleted manually

**Fix:**
```bash
# Complete the OAuth flow to create a token
# Navigate to: https://your-service.run.app/github/install
# Or locally: http://localhost:8000/github/install
```

##### Limitations and Future Work

**Current Limitations:**

1. **Single-User Design:**
   - Only one token is stored per deployment (document ID: `primary_user`)
   - No support for multiple users or multi-tenant scenarios
   - No user authentication or session management

2. **No Automatic Token Refresh:**
   - GitHub user-to-server tokens typically don't expire
   - If tokens do expire, manual re-authentication is required
   - No background job to refresh tokens proactively

3. **Manual Key Rotation:**
   - Key rotation requires manual intervention and re-authentication
   - No automatic re-encryption of existing tokens with new keys

4. **In-Memory State:**
   - OAuth state tokens are stored in memory (lost on restart)
   - Not suitable for multi-instance deployments without external state store

**Future Enhancements (Out of Scope for Current Implementation):**

- Multi-user support with per-user token storage
- Automatic token refresh before expiration
- Key rotation with automatic re-encryption
- Redis/Memcache for distributed OAuth state storage
- Token usage analytics and monitoring
- Automatic token revocation on inactivity
- Support for GitHub App installation tokens (in addition to OAuth tokens)

**These enhancements are explicitly out of scope** to maintain focus on the core single-user token storage functionality. Implementing multi-user support or token refresh workflows requires significant architectural changes and is not part of the current design.

#### Firestore Emulator (Optional)

For local testing without GCP credentials:

```bash
# Install Firebase tools
npm install -g firebase-tools

# Start Firestore emulator
firebase emulators:start --only firestore

# Set emulator environment variable
export FIRESTORE_EMULATOR_HOST=localhost:8080
export GOOGLE_APPLICATION_CREDENTIALS=""  # Prevents ADC lookup
```

## Running Locally

### Standard Run

```bash
uvicorn app.main:app --reload --host 0.0.0.0 --port 8000
```

### With Custom Port (from environment)

```bash
PORT=3000 uvicorn app.main:app --reload --host 0.0.0.0 --port 3000
```

### Using Python directly

```bash
python -m app.main
```

The service will be available at `http://localhost:8000` (or your configured PORT).

## API Endpoints

### Health Check
```
GET /healthz
```
Returns: `{"status": "ok"}`

Used by load balancers and monitoring tools to verify service health.

### GitHub App OAuth Authorization (Initiation)
```
GET /github/install
```
Initiates the OAuth user authorization flow for a GitHub App by redirecting to GitHub's authorization page.

**Note on Terminology:** This endpoint uses "install" in its path for historical reasons, but it actually 
initiates an OAuth user authorization flow (not a GitHub App installation to an org/repo). The flow 
grants the app permission to act on behalf of the authenticated user with the requested scopes.

**⚠️ Interactive Use Only:** This endpoint must be opened in a web browser, not called via API clients.

**Query Parameters:**
- `scopes` (optional): Comma-separated list of OAuth scopes. Default: `user:email,read:org`
  - Common scopes: `repo`, `user`, `read:org`, `write:org`, `admin:repo_hook`

**Response:**
- **302 Redirect** to GitHub authorization page at `https://github.com/login/oauth/authorize`
- **Sets Cookie:** `oauth_state` (HttpOnly, secure in production, 5-minute expiration)

**Example:**
```bash
# Open in browser (do not use curl for OAuth flow)
http://localhost:8000/github/install

# With custom scopes
http://localhost:8000/github/install?scopes=repo,user,read:org
```

**Security:**
- CSRF protection via cryptographically strong state token
- State token stored server-side and in cookie (dual verification)
- 5-minute expiration window

**See:** [OAuth Flow: Manual Browser Verification](#oauth-flow-manual-browser-verification) for detailed step-by-step instructions.

### OAuth Callback Handler
```
GET /oauth/callback
```
Handles the OAuth callback from GitHub after user authorization. **Do not call directly.**

**⚠️ GitHub Redirect Only:** This endpoint is automatically invoked by GitHub's OAuth redirect. 
Browser clients should never call this endpoint directly.

**Query Parameters (provided by GitHub):**
- `code` (required): Authorization code from GitHub (single-use, 10-minute expiration)
- `state` (required): CSRF state token (must match server-side token and cookie)
- `error` (optional): Error code if authorization failed (e.g., `access_denied`)
- `error_description` (optional): Human-readable error description

**Response:**
- **200 OK:** HTML success page with token information (token type, scopes, expiration)
- **400 Bad Request:** HTML error page for:
  - Missing parameters (code or state)
  - State token mismatch (CSRF protection failure)
  - Expired or already-used state token
  - User denied authorization
- **500 Internal Server Error:** HTML error page for:
  - Token exchange failure with GitHub API
  - Invalid authorization code
  - Network errors

**Security Features:**
- Dual state verification (cookie and server-side store)
- One-time use state tokens (consumed on verification)
- 5-minute state token expiration
- Token masking in logs (shows only first 8 and last 4 characters)
- Correlation IDs for request tracing

**Token Handling:**
- ✅ Tokens are logged (masked) with correlation IDs for debugging
- ✅ Tokens are **securely persisted** to Firestore with AES-256-GCM encryption
- ✅ OAuth flow stores token immediately after successful authorization
- ⚠️ Single-user design: one token per deployment (document ID: `primary_user`)
- ⚠️ Multi-user token management requires additional architecture (out of scope)

**Example Success Flow:**
1. User navigates to `/github/install` in browser
2. User authorizes the app on GitHub's website
3. GitHub redirects to `/oauth/callback?code=abc123...&state=xyz789...`
4. Service validates state and exchanges code for access token
5. Token is encrypted and stored in Firestore
6. User sees HTML success page: "Authorization Successful"
7. Logs show masked token: `ghp_abc12...xyz9`

**Example Error Flow (State Mismatch):**
1. User opens `/github/install` with cookies disabled
2. Authorizes on GitHub
3. Callback receives `state` but no cookie
4. Service returns 400 error page: "State token mismatch"
5. User must enable cookies and retry from beginning

**See:** [Troubleshooting OAuth Issues](#troubleshooting-oauth-issues) for common error scenarios and solutions.

### Token Retrieval Endpoint
```
POST /api/token
```
Retrieves the stored GitHub user access token, automatically refreshing if near expiration or when explicitly requested.

**⚠️ IAM Authentication Required:** This endpoint is protected by Cloud Run IAM authentication. Callers must have the `roles/run.invoker` permission and provide a valid identity token.

**Authentication:**
- Requires Cloud Run IAM authentication at infrastructure level
- No application-level authentication is performed
- Deploy with: `gcloud run deploy --no-allow-unauthenticated`
- Callers must obtain identity tokens via `gcloud auth print-identity-token` or GCP client libraries

**Request:**
- **Method:** POST
- **Content-Type:** application/json (optional)
- **Headers:**
  - `Authorization: Bearer <identity-token>` (required for Cloud Run IAM)
  - `Content-Type: application/json` (optional, only if sending request body)

**Request Body (Optional):**
```json
{
  "force_refresh": false
}
```

**Query Parameters (Optional):**
- `force_refresh` (boolean): Force token refresh even if not near expiry. Default: `false`

**Response (200 OK):**
```json
{
  "access_token": "gho_ExampleToken123...",
  "token_type": "bearer",
  "expires_at": "2025-12-31T23:59:59+00:00"
}
```

**Response Fields:**
- `access_token` (string): GitHub user access token for API calls
- `token_type` (string): Token type, typically "bearer"
- `expires_at` (string or null): ISO-8601 timestamp of expiration, or `null` for non-expiring tokens

**Error Responses:**

| Status Code | Condition | Response Body |
|-------------|-----------|---------------|
| 404 Not Found | User has not completed OAuth authorization | `{"detail": "User has not completed authorization"}` |
| 500 Internal Server Error | Token refresh failed due to GitHub API error | `{"detail": "Failed to refresh GitHub token"}` |
| 503 Service Unavailable | Firestore service temporarily unavailable | `{"detail": "Firestore service is temporarily unavailable"}` |

**Token Refresh Behavior:**

The endpoint automatically refreshes tokens when:
1. **Near Expiration:** Token expiration is within configured threshold (default: 30 minutes)
2. **Force Refresh:** `force_refresh=true` is explicitly requested
3. **Non-Expiring Tokens:** Tokens with `expires_at=null` are only refreshed when `force_refresh=true`

**Cooldown Protection:**
- After a failed refresh attempt, a cooldown period prevents excessive API calls (default: 300 seconds)
- During cooldown, refresh attempts are blocked and the current token is returned
- `force_refresh=true` bypasses cooldown for administrative operations
- Cooldown is tracked in Firestore via `last_refresh_attempt` timestamp

**⚠️ Security Considerations:**
- Never log or print the `access_token` to stdout, logs, or error messages
- Use the token only for authorized GitHub API calls
- Store identity tokens securely when calling from external services
- Avoid unnecessary `force_refresh` requests to prevent cooldown activation

**Usage Examples:**

See [Calling POST /api/token from Platform Services](#calling-post-apitoken-from-platform-services) for detailed examples including:
- Cloud Run service-to-service calls
- Cloud Functions invocation
- Cloud Scheduler job configuration
- Python helper code for identity token acquisition

### OpenAPI Documentation
```
GET /docs
```
Interactive Swagger UI documentation with detailed endpoint specifications.

**Features:**
- Try out endpoints directly (except OAuth which requires browser flow)
- View request/response schemas
- See example values and descriptions
- Download OpenAPI JSON spec

**Note:** In Cloud Run deployments with IAM authentication, access requires authentication via `gcloud proxy`.

### OpenAPI JSON Schema
```
GET /openapi.json
```
OpenAPI 3.0 specification in JSON format

## OAuth Flow: Manual Browser Verification

This section provides step-by-step instructions for testing the OAuth flow manually using a web browser. This is essential for verifying your GitHub App configuration and understanding the interactive authentication process.

### Prerequisites

Before testing the OAuth flow, ensure you have:

1. **Created a GitHub App** (see [GitHub App Setup](#github-app-setup) section above)
2. **Configured environment variables** with your GitHub App credentials
3. **Set the correct OAuth callback URL** in your GitHub App settings
4. **Started the FastAPI service** locally or deployed to Cloud Run

### Step-by-Step OAuth Flow Verification

#### 1. Configure Callback URL

**Critical:** The callback URL in your GitHub App settings **must exactly match** the redirect URI in your configuration.

**For Local Development:**
```bash
# In GitHub App settings, set:
Callback URL: http://localhost:8000/oauth/callback

# In your environment or .env file:
export GITHUB_OAUTH_REDIRECT_URI="http://localhost:8000/oauth/callback"
```

**For Cloud Run Deployment:**
```bash
# In GitHub App settings, set:
Callback URL: https://your-service-name-xxxxx-uc.a.run.app/oauth/callback

# In Cloud Run environment variables:
GITHUB_OAUTH_REDIRECT_URI=https://your-service-name-xxxxx-uc.a.run.app/oauth/callback
```

**⚠️ Common Pitfalls:**
- **HTTP vs HTTPS:** Mismatched protocols will cause OAuth to fail
- **Trailing slashes:** `http://localhost:8000/oauth/callback/` ≠ `http://localhost:8000/oauth/callback`
- **Port numbers:** Must match exactly if specified
- **Localhost vs 127.0.0.1:** GitHub treats these as different hosts

#### 2. Start the Service

**Local Development:**
```bash
# Ensure environment variables are set
export GITHUB_CLIENT_ID=Iv1.your_client_id
export GITHUB_CLIENT_SECRET=your_client_secret
export GITHUB_APP_ID=your_app_id
export GITHUB_OAUTH_REDIRECT_URI=http://localhost:8000/oauth/callback

# Start the service
uvicorn app.main:app --reload --host 0.0.0.0 --port 8000
```

**Cloud Run (with gcloud proxy):**
```bash
# Start authenticated proxy
gcloud beta run proxy github-app-token-service --region us-central1

# The service will be available at http://localhost:8080
```

#### 3. Initiate OAuth Flow

Open your web browser and navigate to the installation endpoint:

```bash
# Local
http://localhost:8000/github/install

# Or with custom scopes
http://localhost:8000/github/install?scopes=repo,user,read:org

# Cloud Run (via proxy)
http://localhost:8080/github/install
```

**What Happens:**
1. The service generates a CSRF state token
2. Sets an `oauth_state` cookie in your browser (HttpOnly, 5-minute expiration)
3. Redirects you to GitHub's authorization page: `https://github.com/login/oauth/authorize`

#### 4. Authorize on GitHub

You will see the GitHub authorization page with:
- The name of your GitHub App
- Requested OAuth scopes (permissions)
- Options to grant access to specific repositories or all repositories
- "Authorize [App Name]" button

**Actions:**
- Review the requested permissions
- Select repository access (if applicable)
- Click "Authorize [App Name]" to approve
- Or click "Cancel" to deny authorization

#### 5. Handle Callback

After authorization, GitHub redirects your browser back to:
```
http://localhost:8000/oauth/callback?code=abc123...&state=xyz789...
```

**The service will:**
1. Validate the state token matches the cookie (CSRF protection)
2. Verify the state token hasn't expired (5-minute limit)
3. Exchange the authorization code for an access token via GitHub API
4. Display an HTML success or error page

#### 6. Verify Success

**Success Page Shows:**
- ✓ Checkmark icon and "Authorization Successful" heading
- Token type (typically "bearer")
- Granted scopes (the permissions you approved)
- Token expiration (usually "Token does not expire" for user tokens)

**Check Logs:**
```bash
# Service logs will show (with masked tokens):
{
  "level": "INFO",
  "message": "OAuth flow completed successfully",
  "extra_fields": {
    "correlation_id": "...",
    "token_type": "bearer",
    "scope": "repo,user:email,read:org",
    "has_expiry": false
  }
}
```

**⚠️ Important Note:** Access tokens are encrypted and securely stored in Firestore. Tokens are masked in logs showing only first 8 and last 4 characters (e.g., `ghp_abc12...xyz9`). The service uses AES-256-GCM encryption with a required encryption key set via `GITHUB_TOKEN_ENCRYPTION_KEY` environment variable.

### Troubleshooting OAuth Issues

#### State Mismatch Error

**Error Message:** "State token mismatch" or "State token does not match the expected value"

**Causes:**
- Cookies are disabled in your browser
- Cookie domain/path mismatch
- HTTP vs HTTPS configuration mismatch
- Browser privacy settings blocking third-party cookies

**Solutions:**
1. Enable cookies in your browser
2. Use the same protocol (HTTP/HTTPS) throughout
3. Check browser console for cookie errors
4. Try in an incognito/private window

#### State Expired Error

**Error Message:** "Invalid or expired state token" or "State token is invalid, expired, or has already been used"

**Causes:**
- More than 5 minutes elapsed between `/github/install` and callback
- State token was already used (refreshed callback page)
- Server restarted between install and callback (in-memory state lost)

**Solutions:**
1. Complete the OAuth flow within 5 minutes
2. Don't refresh the callback page after success
3. Restart from `/github/install` to generate a new state token
4. For production with multiple instances, use Redis for state storage

#### Invalid Code Error

**Error Message:** "Failed to exchange authorization code for access token"

**Causes:**
- Authorization code already used (can only be exchanged once)
- Authorization code expired (10-minute GitHub limit)
- Incorrect `CLIENT_SECRET` in configuration
- Network error communicating with GitHub API

**Solutions:**
1. Don't refresh the callback page (codes are single-use)
2. Restart OAuth flow from beginning
3. Verify `GITHUB_CLIENT_SECRET` is correct
4. Check service logs for detailed GitHub API error response

#### Redirect URI Mismatch

**Error Message (from GitHub):** "The redirect_uri MUST match the registered callback URL"

**Causes:**
- Callback URL in GitHub App settings doesn't match `GITHUB_OAUTH_REDIRECT_URI`
- Protocol mismatch (HTTP vs HTTPS)
- Port number mismatch
- Trailing slash difference

**Solutions:**
1. Copy exact URL from GitHub App settings → "Callback URL"
2. Paste into `GITHUB_OAUTH_REDIRECT_URI` environment variable
3. Ensure exact match including protocol, domain, port, and path
4. Restart the service after updating configuration

#### Missing Configuration Error

**Error Message:** "GitHub OAuth is not properly configured"

**Causes:**
- `GITHUB_CLIENT_ID` not set or empty
- `GITHUB_OAUTH_REDIRECT_URI` not set or empty
- Environment variables not loaded

**Solutions:**
1. Verify environment variables are set: `echo $GITHUB_CLIENT_ID`
2. Check `.env` file exists and is in the correct location
3. Restart the service after setting variables
4. In production, verify Cloud Run environment variables

### Rotating OAuth Credentials

You may need to regenerate OAuth credentials if they're compromised or as part of regular security maintenance.

#### Regenerate Client Secret

1. **In GitHub App Settings:**
   - Go to Settings → Developer settings → GitHub Apps → [Your App]
   - Scroll to "Client secrets"
   - Click "Generate a new client secret"
   - **Copy the new secret immediately** (shown only once)
   - Optionally delete old secret after updating configuration

2. **Update Configuration:**
   ```bash
   # Local: Update .env file
   GITHUB_CLIENT_SECRET=your_new_client_secret
   
   # Cloud Run: Update environment variable
   gcloud run services update github-app-token-service \
     --region us-central1 \
     --update-env-vars GITHUB_CLIENT_SECRET=your_new_client_secret \
     --project your-gcp-project-id
   ```

3. **Restart Service:**
   - Local: Restart uvicorn
   - Cloud Run: New revision deployed automatically

4. **Test OAuth Flow:** Verify authentication still works

#### Regenerate Private Key

1. **In GitHub App Settings:**
   - Go to Settings → Developer settings → GitHub Apps → [Your App]
   - Scroll to "Private keys"
   - Click "Generate a private key"
   - Download the `.pem` file
   - **Store securely** - GitHub won't show it again

2. **Update Configuration:**
   ```bash
   # Local: Update .env file with PEM contents
   GITHUB_APP_PRIVATE_KEY_PEM="-----BEGIN RSA PRIVATE KEY-----
   MIIEpAIBAAKCAQEA...
   -----END RSA PRIVATE KEY-----"
   
   # Or use escaped newlines
   GITHUB_APP_PRIVATE_KEY_PEM="-----BEGIN RSA PRIVATE KEY-----\nMIIEpAIBAAKCAQEA...\n-----END RSA PRIVATE KEY-----"
   
   # Cloud Run: Update environment variable
   # For production, it is STRONGLY recommended to use Google Secret Manager.
   # The following command is for non-production environments only.
   
   # 1. Read the key into a variable
   PEM_CONTENT=$(cat path/to/your-private-key.pem)
   
   # 2. Update the service, ensuring the variable is quoted
   gcloud run services update github-app-token-service \
     --region us-central1 \
     --set-env-vars="GITHUB_APP_PRIVATE_KEY_PEM=$PEM_CONTENT" \
     --project your-gcp-project-id
   ```

3. **Restart Service and Test**

4. **Delete Old Key:** In GitHub App settings, you can revoke the old private key once the new one is verified working

#### Best Practices for Credential Rotation

- **Schedule Regular Rotations:** Every 90 days minimum
- **Use Secret Manager:** For Cloud Run, store secrets in Google Secret Manager instead of environment variables
- **Test Before Deleting:** Verify new credentials work before revoking old ones
- **Document Rotation:** Keep a log of when credentials were last rotated
- **Monitor After Rotation:** Watch logs for authentication failures
- **Rotate All Credentials:** If one is compromised, rotate all related credentials

### OAuth API Limitations

**⚠️ This OAuth implementation is designed for interactive, single-user scenarios:**

- **Single-User Token Storage:** Tokens are encrypted and stored in Firestore but limited to one user per deployment
- **No Multi-User Support:** No user session management or per-user token isolation
- **No Automatic Token Refresh:** User must re-authenticate when tokens expire (though GitHub user tokens typically don't expire)
- **In-Memory OAuth State:** CSRF state tokens stored in memory (lost on restart)
- **Single Instance State:** OAuth state tokens not shared across multiple service instances

**For Production Multi-User Applications, Consider:**
- Implementing per-user token storage with user authentication
- Using Redis/Memcache for distributed OAuth state token storage
- Adding user session management with secure cookies
- Implementing automatic token refresh logic for tokens with expiration
- Setting up proper CORS policies for frontend applications
- Using OAuth state parameter for deep linking after authentication

## Calling POST /api/token from Platform Services

This section explains how to call the `POST /api/token` endpoint from various GCP platform services using Cloud Run IAM authentication with identity tokens.

### Prerequisites

Before calling the token endpoint, ensure:

1. **IAM Permissions:** The calling service or user has `roles/run.invoker` on the Cloud Run service
2. **Service URL:** You have the full Cloud Run service URL (e.g., `https://github-app-token-service-xxxxx-uc.a.run.app`)
3. **Regional URL:** For proper identity token audience, use the regional service URL (not custom domains)

### IAM Setup: Granting roles/run.invoker

The `roles/run.invoker` role allows a service account or user to invoke a Cloud Run service.

#### Grant Access to a User

```bash
# Grant access to a specific user
gcloud run services add-iam-policy-binding github-app-token-service \
  --region us-central1 \
  --member='user:alice@example.com' \
  --role='roles/run.invoker' \
  --project your-gcp-project-id
```

#### Grant Access to a Service Account

```bash
# Grant access to a service account (for Cloud Run, Cloud Functions, Cloud Scheduler)
gcloud run services add-iam-policy-binding github-app-token-service \
  --region us-central1 \
  --member='serviceAccount:my-service@project-id.iam.gserviceaccount.com' \
  --role='roles/run.invoker' \
  --project your-gcp-project-id
```

#### Verify IAM Permissions

```bash
# List all members with run.invoker role
gcloud run services get-iam-policy github-app-token-service \
  --region us-central1 \
  --project your-gcp-project-id
```

### Cloud Run to Cloud Run Invocation

When calling from one Cloud Run service to another, use Google's authentication libraries to obtain an identity token.

#### Python Example

```python
import google.auth
import google.auth.transport.requests
import google.oauth2.id_token
import requests
import json

# Service URL - use the regional Cloud Run URL
SERVICE_URL = "https://github-app-token-service-xxxxx-uc.a.run.app"

def get_github_token(force_refresh: bool = False) -> dict:
    """
    Get GitHub access token from the token service.
    
    Args:
        force_refresh: Force token refresh even if not near expiry
        
    Returns:
        dict with 'access_token', 'token_type', 'expires_at'
        
    Raises:
        requests.HTTPError: If request fails (404, 500, 503)
    """
    # Obtain identity token for service-to-service auth
    # This works for both service accounts on GCP and user credentials
    # via Application Default Credentials (ADC).
    import google.auth.transport.requests
    import google.oauth2.id_token
    
    try:
        auth_req = google.auth.transport.requests.Request()
        
        # fetch_id_token will use the credentials from google.auth.default()
        # to generate an identity token with the target service URL as audience.
        id_token = google.oauth2.id_token.fetch_id_token(auth_req, SERVICE_URL)
        
    except google.auth.exceptions.DefaultCredentialsError as e:
        raise Exception(
            "Could not find default credentials. "
            "Please run 'gcloud auth application-default login' or "
            "set up service account credentials."
        ) from e
    
    # Make authenticated request to token endpoint
    headers = {
        "Authorization": f"Bearer {id_token}",
        "Content-Type": "application/json"
    }
    
    # Optional: Include force_refresh in request body or query param
    data = {"force_refresh": force_refresh}
    
    response = requests.post(
        f"{SERVICE_URL}/api/token",
        headers=headers,
        json=data,
        timeout=30
    )
    
    # Raise exception for error responses
    response.raise_for_status()
    
    # Parse response
    token_data = response.json()
    
    # SECURITY: Never log or print the access_token
    # Only log metadata for debugging
    print(f"Token retrieved: type={token_data['token_type']}, "
          f"expires_at={token_data.get('expires_at', 'never')}")
    
    return token_data

# Usage example
try:
    token_response = get_github_token(force_refresh=False)
    github_token = token_response["access_token"]
    
    # Use the GitHub token for API calls
    github_headers = {
        "Authorization": f"Bearer {github_token}",
        "Accept": "application/vnd.github+json",
        "X-GitHub-Api-Version": "2022-11-28"
    }
    
    # Example: Get authenticated user
    github_response = requests.get(
        "https://api.github.com/user",
        headers=github_headers
    )
    github_response.raise_for_status()
    print(f"Authenticated as: {github_response.json()['login']}")
    
except requests.HTTPError as e:
    if e.response.status_code == 404:
        print("ERROR: OAuth authorization not completed")
    elif e.response.status_code == 500:
        print("ERROR: Token refresh failed")
    elif e.response.status_code == 503:
        print("ERROR: Firestore service unavailable")
    else:
        print(f"ERROR: Unexpected error: {e}")
```

#### Node.js Example

```javascript
const { GoogleAuth } = require('google-auth-library');
const axios = require('axios');

const SERVICE_URL = 'https://github-app-token-service-xxxxx-uc.a.run.app';

async function getGitHubToken(forceRefresh = false) {
  // Create GoogleAuth client
  const auth = new GoogleAuth();
  
  // Get identity token client for the target service
  // The client is automatically configured with SERVICE_URL as the audience
  const client = await auth.getIdTokenClient(SERVICE_URL);
  
  // Get the identity token from the configured client
  const idToken = await client.idTokenProvider.fetchIdToken(SERVICE_URL);
  
  // Alternative simpler approach (recommended):
  // const headers = await client.getRequestHeaders();
  // const idToken = headers['Authorization'].replace('Bearer ', '');
  
  // Call token endpoint
  const response = await axios.post(
    `${SERVICE_URL}/api/token`,
    { force_refresh: forceRefresh },
    {
      headers: {
        'Authorization': `Bearer ${idToken}`,
        'Content-Type': 'application/json'
      },
      timeout: 30000
    }
  );
  
  // SECURITY: Never log the access_token
  console.log(`Token retrieved: type=${response.data.token_type}, expires_at=${response.data.expires_at || 'never'}`);
  
  return response.data;
}

// Usage
(async () => {
  try {
    const tokenData = await getGitHubToken(false);
    const githubToken = tokenData.access_token;
    
    // Use the GitHub token for API calls
    const githubResponse = await axios.get('https://api.github.com/user', {
      headers: {
        'Authorization': `Bearer ${githubToken}`,
        'Accept': 'application/vnd.github+json',
        'X-GitHub-Api-Version': '2022-11-28'
      }
    });
    
    console.log(`Authenticated as: ${githubResponse.data.login}`);
  } catch (error) {
    if (error.response?.status === 404) {
      console.error('ERROR: OAuth authorization not completed');
    } else if (error.response?.status === 500) {
      console.error('ERROR: Token refresh failed');
    } else if (error.response?.status === 503) {
      console.error('ERROR: Firestore service unavailable');
    } else {
      console.error(`ERROR: ${error.message}`);
    }
  }
})();
```

### Cloud Functions Invocation

Cloud Functions can call the token endpoint using the same approach as Cloud Run services.

#### Python Cloud Function Example

```python
import functions_framework
import google.auth.transport.requests
import google.oauth2.id_token
import requests

SERVICE_URL = "https://github-app-token-service-xxxxx-uc.a.run.app"

@functions_framework.http
def get_github_repos(request):
    """
    Cloud Function that retrieves GitHub repositories for the authenticated user.
    """
    try:
        # Get identity token with the correct audience for the target service
        auth_req = google.auth.transport.requests.Request()
        id_token = google.oauth2.id_token.fetch_id_token(auth_req, SERVICE_URL)
        
        # Call token endpoint
        token_response = requests.post(
            f"{SERVICE_URL}/api/token",
            headers={"Authorization": f"Bearer {id_token}"},
            json={"force_refresh": False},
            timeout=30
        )
        token_response.raise_for_status()
        token_data = token_response.json()
        
        # Use GitHub token to fetch repositories
        github_response = requests.get(
            "https://api.github.com/user/repos",
            headers={
                "Authorization": f"Bearer {token_data['access_token']}",
                "Accept": "application/vnd.github+json"
            },
            timeout=30
        )
        github_response.raise_for_status()
        repos = github_response.json()
        
        return {"repos": [r["full_name"] for r in repos]}, 200
        
    except requests.HTTPError as e:
        return {"error": f"HTTP error: {e.response.status_code}"}, 500
    except Exception as e:
        return {"error": str(e)}, 500
```

**Deployment:**

```bash
# Deploy Cloud Function with necessary IAM permissions
gcloud functions deploy get-github-repos \
  --runtime python311 \
  --trigger-http \
  --entry-point get_github_repos \
  --region us-central1 \
  --project your-gcp-project-id

# Grant the function's service account access to the token service
FUNCTION_SA=$(gcloud functions describe get-github-repos \
  --region us-central1 \
  --format='value(serviceAccountEmail)' \
  --project your-gcp-project-id)

gcloud run services add-iam-policy-binding github-app-token-service \
  --region us-central1 \
  --member="serviceAccount:${FUNCTION_SA}" \
  --role='roles/run.invoker' \
  --project your-gcp-project-id
```

### Cloud Scheduler Job Configuration

Cloud Scheduler can invoke the token endpoint on a schedule using HTTP targets.

#### Creating a Scheduler Job

```bash
# Create a scheduler job that calls the token endpoint every hour
gcloud scheduler jobs create http github-token-refresh \
  --schedule="0 * * * *" \
  --uri="https://github-app-token-service-xxxxx-uc.a.run.app/api/token" \
  --http-method=POST \
  --oidc-service-account-email=scheduler-sa@your-gcp-project-id.iam.gserviceaccount.com \
  --oidc-token-audience="https://github-app-token-service-xxxxx-uc.a.run.app" \
  --headers="Content-Type=application/json" \
  --message-body='{"force_refresh": false}' \
  --location=us-central1 \
  --project your-gcp-project-id

# Grant the scheduler service account access to the token service
gcloud run services add-iam-policy-binding github-app-token-service \
  --region us-central1 \
  --member="serviceAccount:scheduler-sa@your-gcp-project-id.iam.gserviceaccount.com" \
  --role='roles/run.invoker' \
  --project your-gcp-project-id
```

**Important Notes:**
- `--oidc-service-account-email`: Service account that Cloud Scheduler uses for authentication
- `--oidc-token-audience`: Must match the Cloud Run service URL for proper identity token validation
- `--message-body`: JSON body with optional `force_refresh` parameter

#### Viewing Scheduler Job Logs

```bash
# View logs for the scheduler job
gcloud logging read "resource.type=cloud_scheduler_job AND resource.labels.job_id=github-token-refresh" \
  --limit 50 \
  --format json \
  --project your-gcp-project-id
```

### Using curl with Identity Tokens

For manual testing or scripts, use `gcloud auth print-identity-token` to obtain an identity token.

#### Basic curl Request

```bash
# Get identity token for your user account
IDENTITY_TOKEN=$(gcloud auth print-identity-token)

# Get service URL
SERVICE_URL="https://github-app-token-service-xxxxx-uc.a.run.app"

# Call the token endpoint
curl -X POST "${SERVICE_URL}/api/token" \
  -H "Authorization: Bearer ${IDENTITY_TOKEN}" \
  -H "Content-Type: application/json" \
  -d '{"force_refresh": false}'
```

#### With Query Parameter

```bash
# Using query parameter instead of request body
curl -X POST "${SERVICE_URL}/api/token?force_refresh=true" \
  -H "Authorization: Bearer ${IDENTITY_TOKEN}"
```

#### Parsing Response with jq

```bash
# Extract access_token from response (for use in scripts)
GITHUB_TOKEN=$(curl -s -X POST "${SERVICE_URL}/api/token" \
  -H "Authorization: Bearer ${IDENTITY_TOKEN}" \
  -H "Content-Type: application/json" \
  -d '{"force_refresh": false}' | jq -r '.access_token')

# SECURITY WARNING: Never echo or log the token value
# Use it directly for GitHub API calls

# Example: Use the token to call GitHub API
curl -s "https://api.github.com/user" \
  -H "Authorization: Bearer ${GITHUB_TOKEN}" \
  -H "Accept: application/vnd.github+json" | jq '.login'
```

### Error Handling and Response Codes

When calling POST /api/token, handle the following HTTP status codes:

| Status Code | Meaning | Action |
|-------------|---------|--------|
| 200 OK | Token retrieved successfully (may have been refreshed) | Use `access_token` from response |
| 404 Not Found | User has not completed OAuth authorization | Direct user to complete OAuth flow via `/github/install` |
| 500 Internal Server Error | Token refresh failed due to GitHub API error | Retry after cooldown period (default: 300 seconds) |
| 503 Service Unavailable | Firestore service temporarily unavailable | Retry with exponential backoff |

#### Python Error Handling Example

```python
import time
import requests

def get_github_token_with_retry(
    service_url: str,
    identity_token: str,
    force_refresh: bool = False,
    max_retries: int = 3
) -> dict:
    """
    Get GitHub token with retry logic for transient errors.
    
    Args:
        service_url: Cloud Run service URL
        identity_token: GCP identity token
        force_refresh: Force token refresh
        max_retries: Maximum number of retry attempts
        
    Returns:
        Token data dict
        
    Raises:
        Exception: If all retries exhausted or non-retryable error
    """
    retry_delay = 1  # Start with 1 second
    
    for attempt in range(max_retries):
        try:
            response = requests.post(
                f"{service_url}/api/token",
                headers={
                    "Authorization": f"Bearer {identity_token}",
                    "Content-Type": "application/json"
                },
                json={"force_refresh": force_refresh},
                timeout=30
            )
            
            if response.status_code == 200:
                return response.json()
            elif response.status_code == 404:
                # Non-retryable: User needs to complete OAuth
                raise Exception("OAuth authorization not completed. Visit /github/install")
            elif response.status_code == 500:
                # Retryable: Token refresh failed, may be in cooldown
                if attempt < max_retries - 1:
                    print(f"Token refresh failed, retrying in {retry_delay}s...")
                    time.sleep(retry_delay)
                    retry_delay *= 2  # Exponential backoff
                    continue
                else:
                    raise Exception("Token refresh failed after max retries")
            elif response.status_code == 503:
                # Retryable: Firestore unavailable
                if attempt < max_retries - 1:
                    print(f"Service unavailable, retrying in {retry_delay}s...")
                    time.sleep(retry_delay)
                    retry_delay *= 2
                    continue
                else:
                    raise Exception("Service unavailable after max retries")
            else:
                raise Exception(f"Unexpected status code: {response.status_code}")
                
        except requests.RequestException as e:
            if attempt < max_retries - 1:
                print(f"Request failed: {e}, retrying in {retry_delay}s...")
                time.sleep(retry_delay)
                retry_delay *= 2
                continue
            else:
                raise Exception(f"Request failed after max retries: {e}")
```

### Understanding Token Expiration and force_refresh

#### Non-Expiring Tokens

GitHub user-to-server tokens typically do not expire (`expires_at: null`). For these tokens:

- **Automatic Refresh:** Never triggered automatically (since no expiration date)
- **Manual Refresh:** Only via `force_refresh=true`
- **Use Case:** Administrative operations, manual token rotation, or testing

#### Tokens with Expiration

For tokens with an expiration date:

- **Automatic Refresh:** Triggered when expiration is within threshold (default: 30 minutes)
- **Threshold:** Configurable via `TOKEN_REFRESH_THRESHOLD_MINUTES` environment variable
- **Manual Refresh:** Can be forced with `force_refresh=true` even if not near expiry

#### When to Use force_refresh

| Scenario | Use force_refresh | Reason |
|----------|-------------------|--------|
| Regular API calls | ❌ No | Let automatic refresh handle it |
| Token near expiry | ❌ No | Automatically refreshed |
| Manual token rotation | ✅ Yes | Proactive security measure |
| Testing refresh logic | ✅ Yes | Verify refresh workflow |
| After IAM changes | ✅ Yes | Ensure token is current |
| Debugging auth issues | ✅ Yes | Get fresh token |

#### Cooldown Behavior

After a failed refresh attempt, a cooldown period prevents excessive GitHub API calls:

- **Default Cooldown:** 300 seconds (5 minutes)
- **Configuration:** Set via `TOKEN_REFRESH_COOLDOWN_SECONDS` environment variable
- **Bypass:** `force_refresh=true` bypasses cooldown for administrative operations
- **Tracking:** Last refresh attempt timestamp stored in Firestore

**Cooldown Example:**
```
12:00:00 - Token refresh fails (GitHub API error)
12:00:01 - Cooldown activated (300 seconds)
12:02:00 - Regular refresh blocked (still in cooldown)
12:02:00 - Returns current token with warning log
12:05:01 - Cooldown expires
12:05:02 - Regular refresh allowed again
```

**Force Refresh Bypass:**
```
12:00:00 - Token refresh fails (GitHub API error)
12:00:01 - Cooldown activated (300 seconds)
12:02:00 - force_refresh=true request
12:02:00 - Cooldown bypassed, refresh attempted
12:02:01 - New token returned (if successful)
```

### Best Practices

1. **Use Regional URLs:** Always use the regional Cloud Run URL (not custom domains) as the identity token audience
2. **Never Log Tokens:** The `access_token` should never be printed to logs, stdout, or error messages
3. **Handle All Status Codes:** Implement proper error handling for 404, 500, and 503 responses
4. **Retry with Backoff:** Use exponential backoff for 500 and 503 errors
5. **Respect Cooldown:** Don't use `force_refresh=true` unnecessarily to avoid cooldown activation
6. **Cache Tokens:** Cache the GitHub token in your service to avoid unnecessary calls to the token endpoint
7. **Token Expiration:** Check `expires_at` field and proactively refresh before expiration
8. **Monitor Failures:** Set up alerts for repeated 500 errors indicating refresh failures
9. **IAM Auditing:** Regularly review who has `roles/run.invoker` on the token service
10. **Secure Transport:** All calls use HTTPS; never transmit tokens over unencrypted connections

### Troubleshooting

#### Identity Token Invalid

**Error:** 401 Unauthorized or 403 Forbidden

**Causes:**
- Identity token expired (tokens have short lifetime, typically 1 hour)
- Wrong audience specified in identity token
- Missing `roles/run.invoker` permission

**Solutions:**
```bash
# Verify IAM permissions
gcloud run services get-iam-policy github-app-token-service \
  --region us-central1 \
  --project your-gcp-project-id

# Regenerate identity token
IDENTITY_TOKEN=$(gcloud auth print-identity-token)

# For service accounts, ensure correct audience is used
# Python: Use google.oauth2.id_token.fetch_id_token(auth_req, service_url)
# Node.js: Use GoogleAuth.getIdTokenClient(serviceUrl)
```

#### Token Refresh Cooldown

**Error:** Token refresh blocked, current token returned

**Cause:** Recent failed refresh attempt triggered cooldown period

**Solutions:**
- Wait for cooldown period to expire (default: 300 seconds)
- Use `force_refresh=true` to bypass cooldown (for admin operations only)
- Check logs for root cause of refresh failure

#### Firestore Permission Denied

**Error:** 503 Service Unavailable with "Firestore service is temporarily unavailable"

**Cause:** Cloud Run service account lacks Firestore IAM permissions

**Solution:**
```bash
# Grant Firestore access to Cloud Run service account
SERVICE_ACCOUNT=$(gcloud run services describe github-app-token-service \
  --region us-central1 \
  --format 'value(spec.template.spec.serviceAccountName)' \
  --project your-gcp-project-id)

gcloud projects add-iam-policy-binding your-gcp-project-id \
  --member="serviceAccount:${SERVICE_ACCOUNT}" \
  --role="roles/datastore.user"
```

## Testing

Run all tests:
```bash
pytest
```

Run with coverage:
```bash
pytest --cov=app --cov-report=html
```

Run specific test file:
```bash
pytest tests/test_health.py
```

Run with verbose output:
```bash
pytest -v
```

## Project Structure

```
github-app-basic/
├── app/
│   ├── __init__.py
│   ├── main.py              # FastAPI application factory
│   ├── config.py            # Configuration management
│   ├── routes/
│   │   ├── __init__.py
│   │   ├── health.py        # Health check endpoint
│   │   └── oauth.py         # GitHub OAuth endpoints (/github/install, /oauth/callback)
│   ├── services/
│   │   ├── __init__.py
│   │   ├── firestore.py     # Firestore client initialization
│   │   └── github.py        # GitHub App JWT & OAuth manager
│   ├── dao/
│   │   ├── __init__.py
│   │   └── firestore_dao.py # Firestore data access layer
│   ├── dependencies/
│   │   ├── __init__.py
│   │   └── firestore.py     # FastAPI dependency injection
│   └── utils/
│       ├── __init__.py
│       └── logging.py       # Structured logging with correlation IDs
├── tests/
│   ├── __init__.py
│   ├── test_config.py       # Configuration tests
│   ├── test_health.py       # Health endpoint tests
│   ├── test_firestore_dao.py # Firestore DAO tests
│   └── test_oauth_flow.py   # OAuth & JWT tests (33 tests)
├── requirements.txt         # Production dependencies
├── requirements-dev.txt     # Development dependencies
├── pyproject.toml           # pytest configuration
├── .gitignore              # Git ignore rules
└── README.md               # This file
```

## Logging

The service uses structured JSON logging with the following fields:
- `timestamp`: ISO 8601 formatted timestamp
- `level`: Log level (INFO, WARNING, ERROR, etc.)
- `logger`: Logger name (module path)
- `message`: Log message
- `request_id`: Request ID from headers (when available)
- `correlation_id`: Correlation ID for OAuth flows and multi-step operations (when available)

Request IDs are extracted from:
1. `x-cloud-trace-context` header (Cloud Run)
2. `x-request-id` header (fallback)

Correlation IDs are automatically generated for:
- OAuth authorization flows
- GitHub App JWT operations
- Multi-step transactions

This enables complete traceability of requests and OAuth flows across log entries.

## Cloud Run Deployment

The service is designed to work seamlessly with Google Cloud Run:

1. The `PORT` environment variable is automatically used when provided
2. Request tracing integrates with Cloud Run's `x-cloud-trace-context` header
3. Structured JSON logs are compatible with Cloud Logging
4. Health checks work with Cloud Run health check probes

## Development

### Adding New Routes

1. Create a new file in `app/routes/`
2. Define your router:
```python
from fastapi import APIRouter

router = APIRouter()

@router.get("/my-endpoint")
async def my_endpoint():
    return {"message": "Hello"}
```

3. Register the router in `app/main.py`:
```python
from app.routes import my_route

app.include_router(my_route.router, tags=["my-tag"])
```

### Enabling CORS

Set `ENABLE_CORS=true` in your environment. Note: This enables CORS for all origins. For production, modify `app/main.py` to specify allowed origins.

### Management Scripts

#### Reset GitHub Token

The `scripts/reset_github_token.py` utility allows you to delete or reset OAuth tokens stored in Firestore during development and testing.

**Usage:**

```bash
# Delete token using default collection/doc_id
python scripts/reset_github_token.py

# Delete token from custom location
python scripts/reset_github_token.py --collection my_tokens --doc-id user123

# Check if token exists without deleting (dry-run)
python scripts/reset_github_token.py --dry-run

# Quiet mode (suppress non-error output)
python scripts/reset_github_token.py --quiet
```

**Environment Variables:**
- `GCP_PROJECT_ID`: Required. Your GCP project ID
- `GITHUB_TOKENS_COLLECTION`: Optional. Collection name (default: `github_tokens`)
- `GITHUB_TOKENS_DOC_ID`: Optional. Document ID (default: `primary_user`)

**Exit Codes:**
- `0`: Success (token deleted or already non-existent)
- `1`: Error (configuration or Firestore error)

**Security:** The script never exposes token data in logs or output, only metadata about document existence.

## Troubleshooting

### Production Startup Failures

If the service fails to start in production (`APP_ENV=prod`), ensure all required GitHub environment variables are set and non-empty.

### Port Conflicts

If you see "Address already in use" errors, change the `PORT` environment variable or stop the conflicting service.

### Import Errors

Ensure you've activated your virtual environment and installed all dependencies.

## Docker Containerization

The service includes a production-ready Dockerfile based on `python:3.11-slim` with gunicorn and uvicorn workers.

### Building the Docker Image

#### Local Build

```bash
# Using Makefile
make docker-build

# Or directly with docker
docker build -t github-app-token-service:latest .
```

#### Build for Google Container Registry (GCR)

```bash
# Set your project ID
export PROJECT_ID=your-gcp-project-id

# Build and tag for GCR
make docker-build-gcr PROJECT_ID=$PROJECT_ID

# Push to GCR
make docker-push PROJECT_ID=$PROJECT_ID
```

#### Build Using Cloud Build

```bash
# Builds directly in GCP without local Docker
make build-cloud PROJECT_ID=$PROJECT_ID
```

### Running the Docker Container Locally

```bash
# Using Makefile (runs on port 8080)
make docker-run

# Or directly with docker
docker run -p 8080:8080 \
  -e APP_ENV=dev \
  -e PORT=8080 \
  github-app-token-service:latest
```

Test the containerized service:
```bash
curl http://localhost:8080/healthz
```

### Docker Image Features

- **Minimal Base**: Uses `python:3.11-slim` for small image size
- **Multi-stage Build**: Separates build and runtime for optimization
- **Non-root User**: Runs as `appuser` (UID 1000) for security
- **Production Server**: Uses gunicorn with uvicorn workers
- **Health Check**: Built-in Docker health check for `/healthz`
- **PORT Handling**: Respects Cloud Run's `PORT` environment variable (defaults to 8080)

## Cloud Run Deployment

The service is designed for Google Cloud Run with IAM-based authentication.

### Prerequisites

1. **Google Cloud SDK**: Install from https://cloud.google.com/sdk/docs/install

2. **Enable Required APIs**:
```bash
# Set your project
gcloud config set project your-gcp-project-id

# Enable APIs
gcloud services enable run.googleapis.com
gcloud services enable cloudbuild.googleapis.com
gcloud services enable firestore.googleapis.com
```

3. **Configure Firestore Native Mode**:
   - Go to [Google Cloud Console → Firestore](https://console.cloud.google.com/firestore)
   - Create a Native mode database (not Datastore mode)
   - Select region: **us-central1** (recommended) or your preferred region
   - Wait for provisioning to complete

### Deployment Steps

#### 1. Build the Container Image

Choose one of the following methods:

**Option A: Cloud Build (Recommended)**
```bash
# Builds in GCP, no local Docker required
make build-cloud PROJECT_ID=your-gcp-project-id
```

**Option B: Local Build + Push**
```bash
# Build locally and push to GCR
make docker-build-gcr PROJECT_ID=your-gcp-project-id
make docker-push PROJECT_ID=your-gcp-project-id
```

#### 2. Deploy to Cloud Run

**With Placeholder Values (for testing)**:
```bash
make deploy PROJECT_ID=your-gcp-project-id REGION=us-central1
```

This deploys with placeholder GitHub credentials. The service will start but GitHub integration won't work until you update the environment variables.

**With Real Secrets (production)**:
```bash
# Set environment variables
export GITHUB_APP_ID=123456
export GITHUB_APP_PRIVATE_KEY_PEM="-----BEGIN RSA PRIVATE KEY-----\n..."
export GITHUB_CLIENT_ID=Iv1.abc123
export GITHUB_CLIENT_SECRET=ghp_abc123
export GITHUB_WEBHOOK_SECRET=your_webhook_secret
export GITHUB_OAUTH_REDIRECT_URI=https://your-service.run.app/auth/callback

# Deploy with secrets
make deploy-with-secrets PROJECT_ID=your-gcp-project-id REGION=us-central1
```

**Manual Deployment**:
```bash
gcloud run deploy github-app-token-service \
  --image gcr.io/your-gcp-project-id/github-app-token-service:latest \
  --platform managed \
  --region us-central1 \
  --no-allow-unauthenticated \
  --set-env-vars APP_ENV=prod,GCP_PROJECT_ID=your-gcp-project-id,REGION=us-central1 \
  --set-env-vars GITHUB_APP_ID=123456,GITHUB_APP_PRIVATE_KEY_PEM="..." \
  --set-env-vars GITHUB_CLIENT_ID=...,GITHUB_CLIENT_SECRET=... \
  --set-env-vars GITHUB_WEBHOOK_SECRET=...,GITHUB_OAUTH_REDIRECT_URI=... \
  --project your-gcp-project-id
```

#### 3. Update Environment Variables

When GitHub credentials change, redeploy with updated values:

```bash
# Update specific environment variables
gcloud run services update github-app-token-service \
  --region us-central1 \
  --update-env-vars GITHUB_APP_ID=new_value,GITHUB_APP_PRIVATE_KEY_PEM="new_key" \
  --project your-gcp-project-id
```

### IAM Configuration

Cloud Run is deployed with `--no-allow-unauthenticated`, requiring IAM-based access control.

#### Grant Access to Users

```bash
# Allow a specific user to invoke the service
gcloud run services add-iam-policy-binding github-app-token-service \
  --region us-central1 \
  --member='user:alice@example.com' \
  --role='roles/run.invoker' \
  --project your-gcp-project-id
```

#### Grant Access to Service Accounts

```bash
# Allow a service account to invoke the service
gcloud run services add-iam-policy-binding github-app-token-service \
  --region us-central1 \
  --member='serviceAccount:my-service@project-id.iam.gserviceaccount.com' \
  --role='roles/run.invoker' \
  --project your-gcp-project-id
```

#### Service-to-Service Authentication

For Cloud Functions, Cloud Run, or other GCP services calling this service:

```python
import google.auth.transport.requests
import google.oauth2.id_token
import requests

# Get the service URL
SERVICE_URL = "https://github-app-token-service-xxxxx-uc.a.run.app"

# Obtain ID token with proper audience
auth_req = google.auth.transport.requests.Request()
id_token = google.oauth2.id_token.fetch_id_token(auth_req, SERVICE_URL)

# Make authenticated request
response = requests.get(
    f"{SERVICE_URL}/healthz",
    headers={"Authorization": f"Bearer {id_token}"}
)
```

#### Revoke Access

```bash
# Remove user access
gcloud run services remove-iam-policy-binding github-app-token-service \
  --region us-central1 \
  --member='user:alice@example.com' \
  --role='roles/run.invoker' \
  --project your-gcp-project-id
```

### Testing the Deployment

#### Using gcloud (Recommended)

```bash
# Proxy requests with automatic authentication
gcloud beta run proxy github-app-token-service \
  --region us-central1 \
  --project your-gcp-project-id

# In another terminal, make requests to localhost:8080
curl http://localhost:8080/healthz
curl http://localhost:8080/docs
```

Alternatively:
```bash
# One-time authenticated request
gcloud run services describe github-app-token-service \
  --region us-central1 \
  --format 'value(status.url)' \
  --project your-gcp-project-id

# Get URL, then:
curl -H "Authorization: Bearer $(gcloud auth print-identity-token)" \
  https://github-app-token-service-xxxxx-uc.a.run.app/healthz
```

#### Using Makefile

```bash
# Start authenticated proxy
make invoke PROJECT_ID=your-gcp-project-id REGION=us-central1
```

### Accessing Documentation Endpoints

The `/docs` (Swagger UI) and `/openapi.json` endpoints are **protected by IAM** and require authentication:

```bash
# Access Swagger UI through authenticated proxy
gcloud beta run proxy github-app-token-service --region us-central1
# Then navigate to http://localhost:8080/docs in your browser
```

**Important**: These endpoints are NOT publicly accessible. All access requires:
- IAM `roles/run.invoker` permission
- Valid identity token in request headers

### Firestore IAM Permissions

Ensure the Cloud Run service account has Firestore access:

```bash
# Get the service account email
# Note: If not explicitly set, Cloud Run uses the default compute service account:
# PROJECT_NUMBER-compute@developer.gserviceaccount.com
SERVICE_ACCOUNT=$(gcloud run services describe github-app-token-service \
  --region us-central1 \
  --format 'value(spec.template.spec.serviceAccountName)' \
  --project your-gcp-project-id)

# If the command returns empty, use the default compute service account
if [ -z "$SERVICE_ACCOUNT" ]; then
  PROJECT_NUMBER=$(gcloud projects describe your-gcp-project-id --format='value(projectNumber)')
  SERVICE_ACCOUNT="${PROJECT_NUMBER}-compute@developer.gserviceaccount.com"
  echo "Using default compute service account: $SERVICE_ACCOUNT"
fi

# Grant Firestore access
gcloud projects add-iam-policy-binding your-gcp-project-id \
  --member="serviceAccount:${SERVICE_ACCOUNT}" \
  --role="roles/datastore.user"
```

**Note**: The default compute service account format is `PROJECT_NUMBER-compute@developer.gserviceaccount.com`. For better security, consider creating a dedicated service account with minimal permissions for your Cloud Run service.

### Viewing Logs

#### Using gcloud

```bash
# View recent logs
gcloud logging read "resource.type=cloud_run_revision AND resource.labels.service_name=github-app-token-service" \
  --limit 50 \
  --format json \
  --project your-gcp-project-id
```

#### Using Makefile

```bash
make logs PROJECT_ID=your-gcp-project-id
```

#### In Cloud Console

Navigate to: **Cloud Run → github-app-token-service → LOGS**

### Logging Details

The service uses structured JSON logging compatible with Cloud Logging:

- **Request Tracing**: Extracts trace IDs from `x-cloud-trace-context` header
- **Structured Fields**: All logs include timestamp, level, logger, message
- **Automatic Integration**: Cloud Run automatically ingests stdout/stderr
- **Log Levels**: INFO (default), WARNING, ERROR, DEBUG

Example log entry:
```json
{
  "timestamp": "2025-12-30T06:00:00.000Z",
  "level": "INFO",
  "logger": "app.main",
  "message": "Application starting",
  "extra_fields": {
    "app_env": "prod",
    "region": "us-central1",
    "port": 8080
  }
}
```

### PORT Environment Variable

Cloud Run automatically sets the `PORT` environment variable. The application:
- **Respects `$PORT`**: Binds to the Cloud Run-provided port
- **Defaults to 8080**: Falls back when `PORT` is not set
- **Dockerfile Default**: Sets `PORT=8080` for local consistency

You typically don't need to set `PORT` manually in Cloud Run configuration.

### Resource Configuration

Adjust Cloud Run resources as needed:

```bash
gcloud run services update github-app-token-service \
  --region us-central1 \
  --memory 512Mi \
  --cpu 1 \
  --concurrency 80 \
  --min-instances 0 \
  --max-instances 10 \
  --project your-gcp-project-id
```

### Common Deployment Issues

#### Image Not Found
```
ERROR: (gcloud.run.deploy) Image 'gcr.io/...' not found
```
**Solution**: Run `make build-cloud` or verify the image was pushed to GCR.

#### Permission Denied
```
ERROR: (gcloud.run.deploy) PERMISSION_DENIED: Permission denied on resource
```
**Solution**: Ensure you have `roles/run.admin` role in the GCP project.

#### Service Won't Start
```
ERROR: The user-provided container failed to start and listen on the port defined by the PORT environment variable.
```
**Solution**: Check logs for startup errors. Verify required environment variables are set correctly.

#### Firestore Access Denied
**Solution**: Grant the service account `roles/datastore.user` as shown above.

### Security Best Practices

1. **Never Use `--allow-unauthenticated`**: Always deploy with `--no-allow-unauthenticated`
2. **Principle of Least Privilege**: Grant `roles/run.invoker` only to specific users/service accounts
3. **Use Secret Manager for Production**: Instead of environment variables, use Google Secret Manager to store sensitive credentials:
   ```bash
   # Create secrets in Secret Manager
   echo -n "your-app-id" | gcloud secrets create github-app-id --data-file=-
   cat your-private-key.pem | gcloud secrets create github-app-private-key-pem --data-file=-
   
   # Deploy with secrets mounted from Secret Manager
   gcloud run deploy github-app-token-service \
     --set-secrets="GITHUB_APP_ID=github-app-id:latest" \
     --set-secrets="GITHUB_APP_PRIVATE_KEY_PEM=github-app-private-key-pem:latest" \
     --set-secrets="GITHUB_CLIENT_ID=github-client-id:latest" \
     --set-secrets="GITHUB_CLIENT_SECRET=github-client-secret:latest" \
     --set-secrets="GITHUB_WEBHOOK_SECRET=github-webhook-secret:latest" \
     --set-env-vars="GITHUB_OAUTH_REDIRECT_URI=https://your-service.run.app/auth/callback" \
     # ... other flags
   ```
   This prevents secrets from appearing in deployment history and audit logs.
4. **Rotate Secrets**: Regularly update GitHub credentials and create new secret versions
5. **Monitor Access**: Review IAM policies and Cloud Audit Logs periodically
6. **Avoid Command-Line Secrets**: Never pass secrets as command-line arguments where they may be logged
7. **Secure Logging**: Ensure logs don't contain sensitive data. The application uses structured logging that excludes credentials.
8. **Enable VPC**: For additional security, deploy Cloud Run in a VPC Service Controls perimeter

## Makefile Commands

The project includes a Makefile for common workflows:

```bash
make help              # Show all available commands
make install           # Install dependencies
make run               # Run locally with uvicorn
make test              # Run pytest tests
make docker-build      # Build Docker image
make docker-run        # Run Docker container locally
make build-cloud       # Build image using Cloud Build
make deploy            # Deploy to Cloud Run
make invoke            # Access deployed service via proxy
make logs              # View Cloud Run logs
make clean             # Clean up local artifacts
```

All commands support overriding variables:
```bash
make deploy PROJECT_ID=my-project REGION=us-east1
```

## Next Steps

This service now includes:

### ✅ Implemented Features
- **GitHub App JWT Generation**: Create signed JWTs for GitHub App API authentication
  - Uses RS256 algorithm with configured private key
  - Automatic clock skew handling (60 seconds)
  - Respects GitHub's 600-second maximum expiration
  - Comprehensive error handling for malformed PEM keys
  
- **OAuth Installation Flow**: `/github/install` endpoint
  - Redirects to GitHub with proper OAuth parameters
  - CSRF protection via cryptographically strong state tokens
  - Configurable OAuth scopes
  - Secure cookie handling (HttpOnly, SameSite)
  
- **OAuth Callback Handler**: `/oauth/callback` endpoint
  - State token validation (one-time use, 5-minute expiration)
  - Authorization code exchange for access tokens
  - Comprehensive error handling and user-friendly HTML responses
  - Token logging with masking for security
  - Correlation ID tracking for debugging
  - Encrypted token persistence to Firestore
  
- **Encrypted Token Storage**: Firestore-based persistence
  - AES-256-GCM encryption for access and refresh tokens
  - Configurable collection name and document ID
  - Automatic timestamp normalization (UTC ISO-8601)
  - Metadata-only inspection endpoints
  - IAM-based access control
  
- **Admin Tools**:
  - `/admin/token-metadata` endpoint for metadata inspection
  - `show_token_metadata.py` CLI script for operational queries
  - `reset_github_token.py` CLI script for token deletion
  
- **Security Features**:
  - CSRF protection via state tokens
  - State token expiration and cleanup
  - Token masking in logs
  - Correlation IDs for OAuth flow tracking
  - Defense-in-depth encryption (GCP + application-level)
  - IAM-based Firestore access control

### 🔧 Usage Examples

#### GitHub App JWT Generation
```python
from app.services.github import GitHubAppJWT
from app.config import get_settings

settings = get_settings()
jwt_generator = GitHubAppJWT(
    app_id=settings.github_app_id,
    private_key_pem=settings.github_app_private_key_pem
)

# Generate JWT for GitHub API calls
token = jwt_generator.generate_jwt(expiration_seconds=300)

# Use token in API requests
headers = {
    "Authorization": f"Bearer {token}",
    "Accept": "application/vnd.github+json"
}
```

#### Testing OAuth Flow Locally
```bash
# Start the service with required environment variables
export GITHUB_CLIENT_ID=Iv1.your_client_id
export GITHUB_CLIENT_SECRET=your_client_secret
export GITHUB_APP_ID=your_app_id
export GITHUB_OAUTH_REDIRECT_URI=http://localhost:8000/oauth/callback
export GITHUB_TOKEN_ENCRYPTION_KEY=$(python -c 'import secrets; print(secrets.token_hex(32))')
export GCP_PROJECT_ID=your-gcp-project-id

# Authenticate with GCP (for Firestore)
gcloud auth application-default login

# Run the service
uvicorn app.main:app --reload

# Visit in browser
open http://localhost:8000/github/install

# Or with custom scopes
open http://localhost:8000/github/install?scopes=repo,user

# Check token metadata after OAuth flow
python scripts/show_token_metadata.py
```

### 📝 Future Enhancements
- Add GitHub API integration logic for repositories and installations
- Implement token minting endpoints for installation access tokens
- Add webhook handlers for GitHub App events
- Multi-user support with per-user token storage
- Automatic token refresh before expiration
- Key rotation with automatic re-encryption
- Redis/Memcache for distributed OAuth state token storage
- Rate limiting for OAuth endpoints
- User session management with authentication
- Set up CI/CD pipelines



# Permanents (License, Contributing, Author)

Do not change any of the below sections

## License

This Agent Foundry Project is licensed under the Apache 2.0 License - see the LICENSE file for details.

## Contributing

Feel free to submit issues and enhancement requests!

## Author

Created by Agent Foundry and John Brosnihan
