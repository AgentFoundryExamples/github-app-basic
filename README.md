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

Before configuring the service, you need to create and configure a GitHub App:

1. **Create a GitHub App**:
   - Go to [GitHub Settings → Developer settings → GitHub Apps](https://github.com/settings/apps)
   - Click "New GitHub App"
   - Fill in the required information:
     - **GitHub App name**: Choose a unique name
     - **Homepage URL**: Your application URL or repository URL
     - **Webhook URL**: `https://your-service.run.app/webhooks/github` (or your local testing URL)
     - **Webhook secret**: Generate a secure random token (e.g., `openssl rand -hex 32`)

2. **Configure Permissions** (as needed for your use case):
   - Set repository or organization permissions based on your requirements
   - Subscribe to relevant webhook events

3. **Generate OAuth Credentials**:
   - In your GitHub App settings, note the **App ID** (numeric)
   - Generate a **Client Secret** under "Client secrets"
   - Note the **Client ID** (starts with `Iv1.` or `Iv23.`)

4. **Generate a Private Key**:
   - Scroll to "Private keys" section
   - Click "Generate a private key"
   - Download the `.pem` file - this is your `GITHUB_APP_PRIVATE_KEY_PEM`
   - **IMPORTANT**: Store this file securely. GitHub will not show it again.

5. **Configure OAuth Callback URL**:
   - Set the callback URL to match your redirect URI:
     - Local: `http://localhost:8000/auth/callback`
     - Cloud Run: `https://your-service-name.run.app/auth/callback`

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

#### Important Security Notes

⚠️ **DO NOT store real secrets or sensitive user data in Firestore yet**
- Use placeholder collections only for testing (e.g., `test_collection`, `placeholder_data`)
- Real token/user data persistence requires additional security measures
- Always validate and sanitize data before persisting

#### Firestore Emulator (Optional)

For local testing without GCP credentials:

```bash
# Install Firebase tools
npm install -g firebase-tools

# Start Firestore emulator
firebase emulators:start --only firestore

# Set emulator environment variable
export FIRESTORE_EMULATOR_HOST=localhost:8080
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

### OpenAPI Documentation
```
GET /docs
```
Interactive Swagger UI documentation

### OpenAPI JSON Schema
```
GET /openapi.json
```
OpenAPI 3.0 specification in JSON format

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
│   │   └── health.py        # Health check endpoint
│   ├── services/
│   │   ├── __init__.py
│   │   └── firestore.py     # Firestore client initialization
│   ├── dao/
│   │   ├── __init__.py
│   │   └── firestore_dao.py # Firestore data access layer
│   ├── dependencies/
│   │   ├── __init__.py
│   │   └── firestore.py     # FastAPI dependency injection
│   └── utils/
│       ├── __init__.py
│       └── logging.py       # Structured logging setup
├── tests/
│   ├── __init__.py
│   ├── test_config.py       # Configuration tests
│   ├── test_health.py       # Health endpoint tests
│   └── test_firestore_dao.py # Firestore DAO tests
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

Request IDs are extracted from:
1. `x-cloud-trace-context` header (Cloud Run)
2. `x-request-id` header (fallback)

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
import google.auth
import google.auth.transport.requests
import requests

# Get the service URL
SERVICE_URL = "https://github-app-token-service-xxxxx-uc.a.run.app"

# Obtain ID token
auth_req = google.auth.transport.requests.Request()
credentials, project = google.auth.default()
credentials.refresh(auth_req)
id_token = credentials.id_token

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
gcloud run services proxy github-app-token-service \
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
gcloud run services proxy github-app-token-service --region us-central1
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

- Add GitHub API integration logic
- Implement token minting endpoints
- Add database persistence
- Set up CI/CD pipelines



# Permanents (License, Contributing, Author)

Do not change any of the below sections

## License

This Agent Foundry Project is licensed under the Apache 2.0 License - see the LICENSE file for details.

## Contributing

Feel free to submit issues and enhancement requests!

## Author

Created by Agent Foundry and John Brosnihan
