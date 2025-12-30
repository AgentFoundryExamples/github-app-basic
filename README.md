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

### Required for Production (APP_ENV=prod)

```bash
# Application
APP_ENV=prod

# GitHub App Configuration
GITHUB_APP_ID=<your-app-id>
GITHUB_PRIVATE_KEY=<your-private-key>
GITHUB_CLIENT_ID=<your-client-id>
GITHUB_CLIENT_SECRET=<your-client-secret>
GITHUB_WEBHOOK_SECRET=<your-webhook-secret>

# GCP Configuration (optional for dev)
GCP_PROJECT_ID=<your-project-id>
GOOGLE_APPLICATION_CREDENTIALS=<path-to-credentials-json>
```

### Optional Configuration

```bash
# Application
PORT=8000              # Server port (default: 8000)
LOG_LEVEL=INFO         # Logging level (default: INFO)

# GCP
REGION=us-central1     # GCP region (default: us-central1)

# CORS
ENABLE_CORS=false      # Enable CORS middleware (default: false)
```

### Development Defaults

For local development, only `APP_ENV=dev` is needed. All other fields are optional and will use sensible defaults.

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
│   └── utils/
│       ├── __init__.py
│       └── logging.py       # Structured logging setup
├── tests/
│   ├── __init__.py
│   ├── test_config.py       # Configuration tests
│   └── test_health.py       # Health endpoint tests
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

## Next Steps

- Add GitHub API integration logic
- Implement token minting endpoints
- Add database persistence
- Set up CI/CD pipelines
- Configure Cloud Run deployment



# Permanents (License, Contributing, Author)

Do not change any of the below sections

## License

This Agent Foundry Project is licensed under the Apache 2.0 License - see the LICENSE file for details.

## Contributing

Feel free to submit issues and enhancement requests!

## Author

Created by Agent Foundry and John Brosnihan
