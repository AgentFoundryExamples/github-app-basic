# Local Development Guide

This guide covers running the GitHub App Token Minting Service locally for development, testing, and debugging.

## Prerequisites

- Python 3.11 or higher
- pip package manager
- Git
- A GitHub account for creating a test GitHub App
- (Optional) Docker for containerized local testing
- (Optional) ngrok for tunneling OAuth callbacks

## Quick Start

```bash
# Clone repository
git clone https://github.com/AgentFoundryExamples/github-app-basic.git
cd github-app-basic

# Create virtual environment
python3 -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate

# Install dependencies
pip install -r requirements.txt
pip install -r requirements-dev.txt

# Set up minimal configuration
export APP_ENV=dev
export GITHUB_TOKEN_ENCRYPTION_KEY=$(python3 -c 'import secrets; print(secrets.token_hex(32))')

# Run the service
uvicorn app.main:app --reload --host 0.0.0.0 --port 8000
```

**Service will be available at:** `http://localhost:8000`

## Configuration for Local Development

### Minimal Configuration (No GitHub Integration)

For basic service development without GitHub:

```bash
# Required
export APP_ENV=dev

# Optional (service will use defaults)
export PORT=8000
export LOG_LEVEL=INFO
```

**What Works:**
- ✅ Health check endpoint (`/healthz`)
- ✅ OpenAPI documentation (`/docs`)
- ✅ Service startup and shutdown

**What Doesn't Work:**
- ❌ GitHub App OAuth flow
- ❌ Token storage and retrieval
- ❌ GitHub API integration

### Full Configuration (GitHub Integration)

For testing OAuth flows and GitHub integration:

**⚠️ SECURITY WARNING:**
- **Never store sensitive credentials in environment variables for production** - they can be exposed through process listings, logs, and environment dumps
- **Use Secret Manager for all production secrets** - environment variables shown here are for local development only
- **Protect your shell history** - use `set +o history` before setting secrets, or use `.env` files instead
- **Never commit secrets** to version control, including in configuration files or documentation

```bash
# Application
export APP_ENV=dev
export PORT=8000
export LOG_LEVEL=DEBUG

# GitHub App (see GitHub App Setup section below)
# ⚠️ WARNING: Sensitive credentials - for development only
export GITHUB_APP_ID=123456
export GITHUB_APP_PRIVATE_KEY_PEM="-----BEGIN RSA PRIVATE KEY-----
MIIEpAIBAAKCAQEA...
-----END RSA PRIVATE KEY-----"
export GITHUB_CLIENT_ID=Iv1.abc123def456
export GITHUB_CLIENT_SECRET=your_client_secret_here
export GITHUB_WEBHOOK_SECRET=your_webhook_secret_here
export GITHUB_OAUTH_REDIRECT_URI=http://localhost:8000/oauth/callback

# Encryption
export GITHUB_TOKEN_ENCRYPTION_KEY=$(python3 -c 'import secrets; print(secrets.token_hex(32))')

# GCP (for Firestore integration)
export GCP_PROJECT_ID=your-gcp-project-id
# Option 1: Application Default Credentials
gcloud auth application-default login
# Option 2: Service Account
export GOOGLE_APPLICATION_CREDENTIALS=/path/to/service-account-key.json
```

### Using .env File

Create a `.env` file in the project root:

```bash
# Copy example configuration
cp .env.example .env

# Edit .env file with your values
nano .env  # or your preferred editor
```

**⚠️ SECURITY WARNING:**
- **Never commit `.env` files to version control** - they contain sensitive credentials
- Add `.env` to `.gitignore` (already done in this project)
- For production, use Secret Manager instead of environment variables
- For local development with sensitive data, consider using Secret Manager even locally
- Limit access to your development machine and `.env` files

**Example `.env` for local development:**

```bash
APP_ENV=dev
PORT=8000
LOG_LEVEL=DEBUG

# GitHub App Configuration
# ⚠️ WARNING: These are sensitive credentials - never commit to version control
GITHUB_APP_ID=123456
GITHUB_APP_PRIVATE_KEY_PEM="-----BEGIN RSA PRIVATE KEY-----
MIIEpAIBAAKCAQEA...
-----END RSA PRIVATE KEY-----"
GITHUB_CLIENT_ID=Iv1.abc123def456
GITHUB_CLIENT_SECRET=your_client_secret_here
GITHUB_OAUTH_REDIRECT_URI=http://localhost:8000/oauth/callback

# Encryption
GITHUB_TOKEN_ENCRYPTION_KEY=your_64_char_hex_key_here

# GCP
GCP_PROJECT_ID=your-dev-project-id
GOOGLE_APPLICATION_CREDENTIALS=/path/to/credentials.json

# Feature Flags
ENABLE_REQUEST_LOGGING=true
ENABLE_METRICS=true
```

**Note:** The service automatically loads `.env` files using Pydantic settings.

## Firestore Setup for Local Development

### Option 1: Firestore Emulator (No GCP Project)

Run Firestore locally without GCP credentials:

```bash
# Install Firebase CLI
npm install -g firebase-tools

# Initialize Firebase emulator
firebase init emulators
# Select "Firestore" when prompted
# Accept default port (8080) or choose custom port

# Create firebase.json configuration
cat > firebase.json <<EOF
{
  "emulators": {
    "firestore": {
      "port": 8080
    }
  }
}
EOF

# Start Firestore emulator
firebase emulators:start --only firestore

# In another terminal, configure service
export FIRESTORE_EMULATOR_HOST=localhost:8080
export GCP_PROJECT_ID=demo-project  # Any value works
export GOOGLE_APPLICATION_CREDENTIALS=""  # Prevents ADC lookup
export GITHUB_TOKEN_ENCRYPTION_KEY=$(python3 -c 'import secrets; print(secrets.token_hex(32))')

# Run service
uvicorn app.main:app --reload
```

**Emulator Characteristics:**
- ✅ No GCP credentials required
- ✅ Fast startup and teardown
- ✅ No cost
- ❌ Data is ephemeral (cleared on restart)
- ❌ No IAM enforcement

**Use Case:** Unit testing, rapid iteration, offline development

### Option 2: Real Firestore Database (With GCP Project)

Use a real GCP Firestore database for development:

```bash
# Authenticate with GCP
gcloud auth application-default login

# Set project
export GCP_PROJECT_ID=your-dev-project-id

# Generate encryption key
export GITHUB_TOKEN_ENCRYPTION_KEY=$(python3 -c 'import secrets; print(secrets.token_hex(32))')

# Run service
uvicorn app.main:app --reload
```

**Real Firestore Characteristics:**
- ✅ Data persists across runs
- ✅ IAM authentication enforced
- ✅ Matches production behavior
- ❌ Requires GCP project and credentials
- ❌ Incurs costs (minimal for development)

**Use Case:** Integration testing, debugging production issues, testing IAM

**Best Practice:** Use separate dev/staging/prod GCP projects to isolate data.

## GitHub App Setup for Local Development

### Create a Test GitHub App

1. **Navigate to GitHub App Settings:**
   ```
   https://github.com/settings/apps
   ```

2. **Click "New GitHub App"**

3. **Fill in Basic Information:**
   - **GitHub App name**: `My Dev Token Service` (must be unique)
   - **Homepage URL**: `http://localhost:8000`
   - **Callback URL**: `http://localhost:8000/oauth/callback`
   - **Webhook URL**: `http://localhost:8000/webhooks/github` (not used but required)
   - **Webhook secret**: `dev_webhook_secret_123`

4. **Set Permissions:**
   - **Repository permissions**: Contents (Read), Metadata (Read)
   - **Account permissions**: Email addresses (Read)

5. **Create the App**

6. **Copy Credentials:**
   - **App ID**: Displayed at top of settings page
   - **Client ID**: In "OAuth credentials" section
   - **Client Secret**: Generate and copy immediately
   - **Private Key**: Generate and download `.pem` file

**⚠️ Important Notes:**
- Localhost callback URLs work for local development
- GitHub treats `localhost` and `127.0.0.1` as different hosts
- Ports must match exactly in callback URL
- You can create separate GitHub Apps for dev/staging/prod

## Handling OAuth Callbacks Locally

### Option 1: Direct Localhost (Simplest)

**GitHub App Configuration:**
```
Callback URL: http://localhost:8000/oauth/callback
```

**Service Configuration:**
```bash
export GITHUB_OAUTH_REDIRECT_URI=http://localhost:8000/oauth/callback
```

**Test OAuth Flow:**
```bash
# Start service
uvicorn app.main:app --reload

# Open in browser
open http://localhost:8000/github/install

# Complete authorization on GitHub
# GitHub redirects back to localhost:8000/oauth/callback
```

**Limitations:**
- Only works on your local machine
- Cannot test from mobile devices or remote machines
- Corporate firewalls may block GitHub callbacks to localhost

### Option 2: ngrok Tunnel (For Remote Testing)

Use ngrok to expose your local service to the internet:

```bash
# Install ngrok
# macOS: brew install ngrok
# Linux: Download from https://ngrok.com/download

# Start ngrok tunnel
ngrok http 8000

# ngrok will display:
# Forwarding: https://abc123.ngrok.io -> http://localhost:8000
```

**GitHub App Configuration:**
```
Callback URL: https://abc123.ngrok.io/oauth/callback
```

**Service Configuration:**
```bash
export GITHUB_OAUTH_REDIRECT_URI=https://abc123.ngrok.io/oauth/callback

# Start service
uvicorn app.main:app --reload
```

**Test OAuth Flow:**
```bash
# Open ngrok URL in browser
open https://abc123.ngrok.io/github/install

# Or use ngrok's inspection interface
open http://localhost:4040
```

**ngrok Advantages:**
- ✅ Works from any device/network
- ✅ Inspect requests via web interface
- ✅ HTTPS support
- ✅ Test webhooks (future)

**ngrok Limitations:**
- ⚠️ Free tier has URL that changes on restart
- ⚠️ Requires updating GitHub App callback URL when tunnel restarts
- ⚠️ Public URL may be accessed by anyone (use ngrok auth for protection)

### Option 3: Tailscale/Other VPN (For Team Access)

Use Tailscale or similar VPN for secure team access:

```bash
# Install Tailscale
# Follow: https://tailscale.com/download

# Get your Tailscale IP
ip addr show tailscale0

# Example: 100.100.100.100
```

**GitHub App Configuration:**
```
Callback URL: http://100.100.100.100:8000/oauth/callback
```

**Service Configuration:**
```bash
export GITHUB_OAUTH_REDIRECT_URI=http://100.100.100.100:8000/oauth/callback
uvicorn app.main:app --reload --host 0.0.0.0
```

**Advantages:**
- ✅ Secure team collaboration
- ✅ Stable IP across sessions
- ✅ No public exposure

**Limitations:**
- ⚠️ Requires VPN setup for all team members

## Running the Service

### Standard Local Run

```bash
# Using uvicorn directly (recommended for development)
uvicorn app.main:app --reload --host 0.0.0.0 --port 8000

# Using Python module
python -m app.main

# Using Makefile
make run
```

**Development Server Options:**

| Flag | Description |
|------|-------------|
| `--reload` | Auto-reload on code changes |
| `--host 0.0.0.0` | Listen on all interfaces (allows external access) |
| `--port 8000` | Port to listen on |
| `--log-level debug` | Enable debug logging |
| `--workers 1` | Number of worker processes (default: 1 for development) |

### Running with Docker

```bash
# Build image
docker build -t github-app-token-service:dev .

# Run container
docker run -p 8000:8000 \
  -e APP_ENV=dev \
  -e PORT=8000 \
  -e GITHUB_TOKEN_ENCRYPTION_KEY=$(python3 -c 'import secrets; print(secrets.token_hex(32))') \
  -v ~/.config/gcloud/application_default_credentials.json:/root/.config/gcloud/application_default_credentials.json:ro \
  github-app-token-service:dev

# Or using Makefile
make docker-build
make docker-run
```

**Mounting Credentials:**
```bash
# Mount Application Default Credentials (specific file, not entire directory)
-v ~/.config/gcloud/application_default_credentials.json:/root/.config/gcloud/application_default_credentials.json:ro

# Mount service account key
-v /path/to/key.json:/app/credentials.json:ro
-e GOOGLE_APPLICATION_CREDENTIALS=/app/credentials.json

# Mount .env file
-v $(pwd)/.env:/app/.env:ro
```

### Running Tests

```bash
# Run all tests
pytest

# Run with coverage
pytest --cov=app --cov-report=html

# Run specific test file
pytest tests/test_oauth_flow.py

# Run with verbose output
pytest -v

# Run tests matching pattern
pytest -k "test_oauth"

# Using Makefile
make test
```

## Request Logging Behavior

The service supports optional request logging middleware for debugging.

### Enable Request Logging

```bash
# Via environment variable
export ENABLE_REQUEST_LOGGING=true
uvicorn app.main:app --reload

# Via .env file
echo "ENABLE_REQUEST_LOGGING=true" >> .env
```

**What Gets Logged:**

```json
{
  "level": "INFO",
  "message": "HTTP request completed",
  "extra_fields": {
    "method": "POST",
    "path": "/api/token",
    "status_code": 200,
    "duration_ms": 156.23,
    "user_agent": "python-requests/2.31.0"
  }
}
```

**Logged for Every Request:**
- HTTP method (GET, POST, etc.)
- Request path (e.g., `/api/token`)
- Status code (200, 404, 500, etc.)
- Duration in milliseconds
- User agent string

**⚠️ Not Logged (Security):**
- Request body contents
- Response body contents
- Authorization headers
- Tokens or secrets

### Disable Request Logging

```bash
# Default behavior (disabled)
export ENABLE_REQUEST_LOGGING=false

# Or remove the environment variable
unset ENABLE_REQUEST_LOGGING
```

**Why Disabled by Default:**
- Reduces log volume in production
- Lower Cloud Logging costs
- Minimizes noise in logs

**When to Enable:**
- Local development and debugging
- Investigating performance issues
- Tracking request patterns
- Development/staging environments

## Metrics Endpoint

The service supports optional Prometheus metrics for monitoring.

### Enable Metrics

```bash
# Via environment variable
export ENABLE_METRICS=true
uvicorn app.main:app --reload

# Access metrics endpoint
curl http://localhost:8000/metrics
```

**Available Metrics:**

```
# Token refresh events
github_token_refresh_total{status="success"} 45
github_token_refresh_total{status="failed"} 2

# Webhook events (future)
github_events_webhook_total{event="push"} 123
```

**Metrics Format:** Prometheus text exposition format

**Integration:** Compatible with Prometheus, Grafana, Cloud Monitoring

### Disable Metrics

```bash
# Default behavior (disabled)
export ENABLE_METRICS=false
```

**Why Disabled by Default:**
- Reduces overhead
- Not needed for single-user deployments
- Avoid exposing internal metrics

**When to Enable:**
- Performance monitoring
- Integration with Prometheus/Grafana
- Debugging refresh failures
- Staging/production observability

## Debugging OAuth Flows

### Debug OAuth State Tokens

```python
# Enable debug logging
export LOG_LEVEL=DEBUG

# Check logs for state token generation and validation
# Logs will show:
# - State token created (correlation_id)
# - State token stored in memory
# - State token validation (match/mismatch)
# - State token expiration
```

### Test OAuth Flow Step-by-Step

```bash
# 1. Start service with debug logging
export LOG_LEVEL=DEBUG
uvicorn app.main:app --reload

# 2. Open /github/install in browser
open http://localhost:8000/github/install

# 3. Check logs for:
# - State token generation
# - Redirect URL construction
# - Cookie setting

# 4. Authorize on GitHub

# 5. Check logs for callback processing:
# - State validation
# - Code exchange
# - Token encryption
# - Firestore storage
```

### Common Local Development Issues

**Issue: "State token mismatch"**

**Cause:** Cookies disabled in browser or using different hostname.

**Solution:**
```bash
# Ensure consistent hostname
# If GitHub redirects to 127.0.0.1 but service is on localhost, state will mismatch

# Update GitHub App callback URL to match exactly
# Either:
# http://localhost:8000/oauth/callback
# OR
# http://127.0.0.1:8000/oauth/callback

# Update service config to match
export GITHUB_OAUTH_REDIRECT_URI=http://localhost:8000/oauth/callback
```

**Issue: "Connection refused" after GitHub authorization**

**Cause:** Service not running or port mismatch.

**Solution:**
```bash
# Verify service is running
lsof -i :8000

# Check logs for startup errors
# Verify PORT environment variable matches

# Restart service
uvicorn app.main:app --reload --port 8000
```

**Issue: "Firestore permission denied" locally**

**Cause:** Not authenticated with GCP or using emulator without FIRESTORE_EMULATOR_HOST set.

**Solution:**
```bash
# Option 1: Use Firestore emulator
export FIRESTORE_EMULATOR_HOST=localhost:8080
firebase emulators:start --only firestore

# Option 2: Authenticate with GCP
gcloud auth application-default login
export GCP_PROJECT_ID=your-dev-project-id
```

## Development Workflow

### Recommended Development Cycle

1. **Make code changes**
2. **Auto-reload picks up changes** (if using `--reload`)
3. **Run tests**: `pytest tests/test_your_change.py`
4. **Test manually via `/docs` or curl**
5. **Check logs for errors**
6. **Commit changes**

### Hot Reloading

```bash
# Enable hot reload (watches for file changes)
uvicorn app.main:app --reload

# Customize watched paths
uvicorn app.main:app --reload --reload-dir app

# Exclude paths from watching
uvicorn app.main:app --reload --reload-exclude '*.pyc'
```

**What Triggers Reload:**
- Changes to `.py` files in `app/` directory
- Changes to imported modules
- Configuration file changes

**What Doesn't Trigger Reload:**
- Environment variable changes (restart required)
- `.env` file changes (restart required)
- Dependency changes (reinstall required)

### Testing GitHub Integration Locally

```python
# test_local_github.py
import requests

# Get token from local service
response = requests.post("http://localhost:8000/api/token")
token_data = response.json()
github_token = token_data["access_token"]

# Test GitHub API
github_response = requests.get(
    "https://api.github.com/user",
    headers={"Authorization": f"Bearer {github_token}"}
)
print(f"Authenticated as: {github_response.json()['login']}")
```

### Debugging with VS Code

Create `.vscode/launch.json`:

```json
{
  "version": "0.2.0",
  "configurations": [
    {
      "name": "FastAPI",
      "type": "python",
      "request": "launch",
      "module": "uvicorn",
      "args": [
        "app.main:app",
        "--reload",
        "--host",
        "0.0.0.0",
        "--port",
        "8000"
      ],
      "jinja": true,
      "justMyCode": false,
      "envFile": "${workspaceFolder}/.env"
    }
  ]
}
```

**Debugging Features:**
- Set breakpoints in code
- Inspect variables
- Step through OAuth flow
- View call stack

## IDE Setup

### VS Code

Recommended extensions:

```json
{
  "recommendations": [
    "ms-python.python",
    "ms-python.vscode-pylance",
    "ms-python.black-formatter",
    "ms-python.isort",
    "ms-toolsai.jupyter",
    "redhat.vscode-yaml"
  ]
}
```

Settings (`.vscode/settings.json`):

```json
{
  "python.linting.enabled": true,
  "python.linting.pylintEnabled": false,
  "python.linting.flake8Enabled": true,
  "python.formatting.provider": "black",
  "python.testing.pytestEnabled": true,
  "python.testing.unittestEnabled": false,
  "editor.formatOnSave": true
}
```

### PyCharm

1. **Configure Python Interpreter:**
   - File → Settings → Project → Python Interpreter
   - Add interpreter from `venv/` directory

2. **Configure pytest:**
   - File → Settings → Tools → Python Integrated Tools
   - Default test runner: pytest

3. **Configure environment variables:**
   - Run → Edit Configurations
   - Add configuration for FastAPI
   - Set environment variables or point to `.env` file

## Differences from Production

| Aspect | Local Development | Production (Cloud Run) |
|--------|-------------------|------------------------|
| **Environment** | `APP_ENV=dev` | `APP_ENV=prod` |
| **Firestore** | Emulator or dev database | Production database |
| **Secrets** | `.env` file | Google Secret Manager |
| **Authentication** | Optional (can run unauthenticated) | Required (`--no-allow-unauthenticated`) |
| **HTTPS** | HTTP (localhost) | HTTPS (Cloud Run) |
| **Logging** | Console output | Cloud Logging |
| **Metrics** | Optional, disabled by default | Optional, disabled by default |
| **Request Logging** | Can enable for debugging | Disabled (cost optimization) |
| **OAuth Callback** | `http://localhost:8000/oauth/callback` | `https://service.run.app/oauth/callback` |
| **IAM Enforcement** | None | Firestore, Secret Manager IAM |
| **Data Persistence** | Emulator: ephemeral<br>Dev DB: persistent | Persistent |

## Cleaning Up

```bash
# Stop Firebase emulator
# Press Ctrl+C in emulator terminal

# Deactivate virtual environment
deactivate

# Clean Python cache files
make clean
# Or manually:
find . -type d -name "__pycache__" -exec rm -rf {} +
find . -type f -name "*.pyc" -delete
```

## Next Steps

1. **Complete OAuth Flow**: Test with your GitHub App
2. **Explore API Endpoints**: Use `/docs` for interactive testing
3. **Review Logs**: Understand structured logging format
4. **Write Tests**: Add tests for new features
5. **Deploy to Staging**: Follow [SELF_HOSTING.md](SELF_HOSTING.md) for GCP deployment

## Troubleshooting Local Development

See [TROUBLESHOOTING.md](TROUBLESHOOTING.md) for common issues and solutions.

**Quick Fixes:**
- **ImportError**: `pip install -r requirements.txt`
- **Port already in use**: Change PORT or kill process: `lsof -ti :8000 | xargs kill`
- **Firestore errors**: Check emulator is running or GCP auth is valid
- **OAuth fails**: Verify callback URL matches in both GitHub App and service config

## Reference

- [FastAPI Documentation](https://fastapi.tiangolo.com/)
- [Uvicorn Documentation](https://www.uvicorn.org/)
- [Firebase Emulator Suite](https://firebase.google.com/docs/emulator-suite)
- [ngrok Documentation](https://ngrok.com/docs)
