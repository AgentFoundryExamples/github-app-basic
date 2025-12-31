# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [v0.1.0] - 2025-12-31

### Summary

Initial open-source release of the GitHub App Token Minting Service, a FastAPI-based solution for secure OAuth token management with GCP integration designed for self-hosted Cloud Run deployment.

### Added

#### Security Hardening
- **Defense-in-Depth Encryption**: AES-256-GCM encryption for OAuth tokens at rest in Firestore, providing application-level protection in addition to GCP-managed encryption
- **IAM-Based Access Control**: Cloud Run IAM authentication for all API endpoints with `--no-allow-unauthenticated` enforcement
- **Token Redaction**: Automatic masking of sensitive tokens in logs (shows first 8 and last 4 characters only)
- **CSRF Protection**: Cryptographically strong state tokens for OAuth flows with 5-minute expiration and one-time use
- **Secure Token Storage**: Firestore-based persistence with configurable encryption keys via environment variables or Secret Manager
- **Security Documentation**: Comprehensive threat model, IAM configuration requirements, and incident response procedures

#### Structured Logging and Observability
- **JSON Structured Logging**: Cloud Logging-compatible structured logs with consistent schema across all components
- **Correlation IDs**: Automatic correlation ID generation and propagation for OAuth flows and multi-step operations
- **Request Tracing**: Integration with Cloud Run's `x-cloud-trace-context` header for distributed tracing
- **Token Refresh Tracking**: Detailed logging of refresh attempts, cooldown enforcement, and error conditions
- **Configurable Log Levels**: Support for INFO, WARNING, ERROR, and DEBUG levels via `LOG_LEVEL` environment variable

#### Health and Readiness Probes
- **Health Check Endpoint** (`/healthz`): Validates service health including Firestore connectivity with configurable TTL caching
- **Readiness Endpoint** (`/readyz`): Indicates whether the service is ready to accept requests based on recent health check status
- **Health Check Caching**: Configurable cache TTL (default: 30 seconds) to reduce Firestore load via `HEALTH_CHECK_CACHE_TTL_SECONDS`
- **Graceful Degradation**: Services return appropriate HTTP status codes (200 OK, 503 Service Unavailable) based on dependency health

#### GitHub OAuth Integration
- **OAuth Authorization Flow**: Complete implementation with `/github/install` initiation and `/oauth/callback` handler
- **Token Exchange**: Secure authorization code exchange for access tokens with comprehensive error handling
- **Token Refresh**: Automatic token refresh with cooldown enforcement and retry logic for near-expiry tokens
- **Configurable Scopes**: Support for custom OAuth scopes via query parameters (default: `user:email,read:org`)
- **State Management**: In-memory OAuth state token storage with automatic cleanup and expiration

#### Token Management
- **Token Retrieval API** (`POST /api/token`): IAM-authenticated endpoint for retrieving GitHub access tokens
- **Automatic Refresh**: Configurable threshold for near-expiry token refresh (default: 30 minutes before expiration)
- **Cooldown Protection**: Prevents excessive GitHub API calls with configurable cooldown period (default: 300 seconds)
- **Force Refresh**: Administrative bypass option for explicit token refresh operations
- **Token Metadata Inspection**: Admin endpoint (`/admin/token-metadata`) for viewing token metadata without exposing sensitive values

#### Documentation
- **[Self-Hosting Guide](docs/SELF_HOSTING.md)**: Complete GCP setup instructions, Firestore configuration, and Cloud Run deployment procedures
- **[GitHub App Configuration](docs/GITHUB_APP.md)**: Step-by-step GitHub App creation and OAuth setup with callback URL examples
- **[Operations Guide](docs/OPERATIONS.md)**: Day-to-day operations including token rotation, monitoring, and troubleshooting
- **[Security Documentation](docs/SECURITY.md)**: Detailed threat model, encryption strategy, IAM requirements, and security best practices
- **[Troubleshooting Guide](docs/TROUBLESHOOTING.md)**: Common issues and solutions for OAuth failures, Firestore errors, and deployment problems
- **[Local Development Guide](docs/LOCAL_DEV.md)**: Instructions for running locally with Firestore emulator or Application Default Credentials

#### DevOps and Deployment
- **Docker Support**: Production-ready Dockerfile with multi-stage builds, non-root user, and health checks
- **Cloud Run Deployment**: Makefile targets for Cloud Build, GCR push, and Cloud Run deployment with IAM configuration
- **Environment Configuration**: Comprehensive environment variable support for all service settings
- **Secret Management**: Integration with Google Secret Manager for production credential storage
- **Makefile Automation**: Common tasks including build, test, deploy, and log viewing

#### Testing
- **Comprehensive Test Suite**: 306+ passing tests covering OAuth flows, token management, health checks, and security
- **Unit Tests**: Component-level testing for config, DAO, services, and utilities
- **Integration Tests**: End-to-end testing of OAuth flows and token refresh workflows
- **Security Tests**: Validation of token redaction, encryption, and IAM authentication
- **Mock Firestore**: Test fixtures using mock Firestore clients for isolated testing

#### Experimental Features (Opt-In)
- **Request Logging Middleware**: Detailed HTTP request/response logging (disabled by default, enable via `ENABLE_REQUEST_LOGGING=true`)
- **Prometheus Metrics**: Token refresh and webhook event counters (disabled by default, enable via `ENABLE_METRICS=true` and access at `/metrics`)

### Configuration

New environment variables for service configuration:

| Variable | Default | Description |
|----------|---------|-------------|
| `APP_ENV` | `dev` | Application environment (`dev` or `prod`) |
| `PORT` | `8000` | Server port (automatically set by Cloud Run) |
| `LOG_LEVEL` | `INFO` | Logging level (INFO, WARNING, ERROR, DEBUG) |
| `ENABLE_REQUEST_LOGGING` | `false` | Enable detailed HTTP request logging |
| `ENABLE_METRICS` | `false` | Enable Prometheus metrics endpoint |
| `ENABLE_CORS` | `false` | Enable CORS middleware |
| `TOKEN_REFRESH_THRESHOLD_MINUTES` | `30` | Minutes before expiry to trigger refresh |
| `TOKEN_REFRESH_COOLDOWN_SECONDS` | `300` | Cooldown between failed refresh attempts |
| `HEALTH_CHECK_CACHE_TTL_SECONDS` | `30` | Cache TTL for health check results |
| `GITHUB_TOKEN_ENCRYPTION_KEY` | (required) | 64-character hex key for token encryption |
| `GITHUB_TOKENS_COLLECTION` | `github_tokens` | Firestore collection name |
| `GITHUB_TOKENS_DOC_ID` | `primary_user` | Firestore document ID |

### Security

- **Encryption Key Management**: Application-level AES-256-GCM encryption requires explicit key configuration
- **IAM Authentication**: All API endpoints protected by Cloud Run IAM (except OAuth callback which validates state tokens)
- **Token Masking**: All logs mask sensitive tokens to prevent accidental exposure
- **CSRF Protection**: OAuth state tokens use cryptographically strong random generation with time-based expiration
- **No Token Exposure**: No API endpoint returns decrypted tokens in responses (tokens only used internally for GitHub API calls)

### Upgrade Notes

This is the initial release (v0.1.0). For self-hosting:

1. **Review Documentation**: Start with the [Self-Hosting Guide](docs/SELF_HOSTING.md) for complete setup instructions
2. **Configure GitHub App**: Follow [GitHub App Configuration](docs/GITHUB_APP.md) to create and configure your GitHub App
3. **Set Up Encryption**: Generate a 64-character hex encryption key: `python -c 'import secrets; print(secrets.token_hex(32))'`
4. **Deploy to Cloud Run**: Use provided Makefile targets or manual `gcloud` commands from the README
5. **Complete OAuth Flow**: Navigate to `/github/install` in your browser to authorize and store tokens
6. **Verify Health**: Check `/healthz` endpoint to ensure Firestore connectivity

### Known Limitations

- **Single-User Design**: Only one token stored per deployment (document ID: `primary_user`)
- **In-Memory OAuth State**: State tokens not shared across multiple service instances (use single instance or external state store)
- **Manual Key Rotation**: Encryption key rotation requires deleting existing tokens and re-authenticating
- **No Multi-Tenancy**: No support for multiple users or per-user token isolation

### Dependencies

- **Runtime**: Python 3.11+
- **Framework**: FastAPI 0.115.6, Uvicorn 0.34.0
- **GCP**: google-cloud-firestore 2.20.1
- **Cryptography**: cryptography 44.0.0
- **GitHub**: PyJWT 2.10.1, requests 2.32.3

### Future Roadmap

- Multi-user support with per-user token storage
- Automatic key rotation with re-encryption
- Redis/Memcache for distributed OAuth state
- Automatic token refresh background jobs
- Enhanced monitoring and alerting integration
- GitHub App installation token support

---

**Release Date**: December 31, 2025  
**Git Tag**: v0.1.0  
**Compatibility**: First stable release

For questions, issues, or contributions, please refer to [CONTRIBUTING.md](CONTRIBUTING.md).
