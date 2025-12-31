# Contributing to GitHub App Token Minting Service

Thank you for your interest in contributing to the GitHub App Token Minting Service! This document provides guidelines for contributing to this project.

## Table of Contents

- [Code of Conduct](#code-of-conduct)
- [Getting Started](#getting-started)
- [Development Environment](#development-environment)
- [Coding Standards](#coding-standards)
- [Testing Requirements](#testing-requirements)
- [Security Considerations](#security-considerations)
- [Pull Request Process](#pull-request-process)
- [External Contributor Limitations](#external-contributor-limitations)
- [Release Process](#release-process)

## Code of Conduct

This project follows a professional code of conduct. All contributors are expected to:

- Be respectful and inclusive in all communications
- Focus on constructive feedback and collaboration
- Respect differing viewpoints and experiences
- Accept responsibility for mistakes and learn from them
- Prioritize the best interests of the community and project

## Getting Started

### Prerequisites

- **Python**: 3.11 or higher
- **pip**: Package manager (comes with Python)
- **Git**: Version control system
- **GCP Account**: For testing Firestore integration (optional - see emulator below)
- **GitHub Account**: For OAuth flow testing

### Fork and Clone

1. Fork the repository on GitHub
2. Clone your fork locally:
   ```bash
   git clone https://github.com/YOUR-USERNAME/github-app-basic.git
   cd github-app-basic
   ```

3. Add the upstream repository:
   ```bash
   git remote add upstream https://github.com/AgentFoundryExamples/github-app-basic.git
   ```

4. Create a feature branch:
   ```bash
   git checkout -b feature/your-feature-name
   ```

## Development Environment

### Local Setup

1. **Create a virtual environment**:
   ```bash
   python3 -m venv venv
   source venv/bin/activate  # On Windows: venv\Scripts\activate
   ```

2. **Install dependencies**:
   ```bash
   pip install -r requirements.txt
   pip install -r requirements-dev.txt
   ```

3. **Set up environment variables**:
   ```bash
   cp .env.example .env
   # Edit .env with your configuration
   ```

### Firestore Setup Options

#### Option 1: Firestore Emulator (Recommended for Contributors)

The Firestore emulator allows you to develop and test without a GCP project:

```bash
# Install Firebase tools
npm install -g firebase-tools

# Start Firestore emulator
firebase emulators:start --only firestore

# In another terminal, set environment variables
export FIRESTORE_EMULATOR_HOST=localhost:8080
export GCP_PROJECT_ID=demo-project  # Any value works with emulator
export GOOGLE_APPLICATION_CREDENTIALS=""  # Prevents ADC lookup
export GITHUB_TOKEN_ENCRYPTION_KEY=$(python -c 'import secrets; print(secrets.token_hex(32))')
export APP_ENV=dev

# Run the service
uvicorn app.main:app --reload
```

**Benefits**:
- No GCP account or credentials required
- No costs or quotas
- Ephemeral data (cleared on restart)
- Perfect for unit and integration testing

#### Option 2: Application Default Credentials (for GCP users)

If you have a GCP account and want to test against a real Firestore instance:

```bash
# Authenticate with your GCP account
gcloud auth application-default login

# Set environment variables
export GCP_PROJECT_ID=your-test-project-id
export GITHUB_TOKEN_ENCRYPTION_KEY=$(python -c 'import secrets; print(secrets.token_hex(32))')
export APP_ENV=dev

# Run the service
uvicorn app.main:app --reload
```

### Running the Service

```bash
# Standard run with auto-reload
uvicorn app.main:app --reload --host 0.0.0.0 --port 8000

# Or use the Makefile
make run
```

The service will be available at `http://localhost:8000`.

### Accessing Documentation

- **Swagger UI**: http://localhost:8000/docs
- **OpenAPI JSON**: http://localhost:8000/openapi.json

## Coding Standards

### Python Style Guide

We follow [PEP 8](https://peps.python.org/pep-0008/) with some specific conventions:

1. **Type Hints**: Use Python type hints for all function signatures
   ```python
   def get_token(force_refresh: bool = False) -> dict[str, Any]:
       ...
   ```

2. **Docstrings**: Follow [Google Style Python Docstrings](https://google.github.io/styleguide/pyguide.html#38-comments-and-docstrings)
   ```python
   def encrypt_token(token: str) -> str:
       """Encrypts a token using AES-256-GCM.
       
       Args:
           token: The plaintext token to encrypt.
           
       Returns:
           Base64-encoded encrypted token with nonce and auth tag.
           
       Raises:
           ValueError: If encryption key is not configured.
       """
       ...
   ```

3. **Line Length**: Maximum 100 characters (can extend to 120 for complex expressions)

4. **Imports**: Group imports in the following order (separated by blank lines):
   - Standard library imports
   - Third-party library imports
   - Local application imports

5. **Error Handling**: Use specific exception types and provide meaningful error messages
   ```python
   # ✅ Good
   if not encryption_key:
       raise ValueError("Encryption key not configured. Set GITHUB_TOKEN_ENCRYPTION_KEY environment variable.")
   
   # ❌ Bad
   if not encryption_key:
       raise Exception("Missing key")
   ```

### Code Organization

- **Keep functions small**: Aim for functions under 50 lines
- **Single Responsibility**: Each function/class should have one clear purpose
- **DRY Principle**: Don't Repeat Yourself - extract common logic into utilities
- **Separation of Concerns**: Follow existing architecture (routes → services → DAO)

### FastAPI Conventions

- **Dependency Injection**: Use FastAPI's `Depends()` for shared dependencies
- **Pydantic Models**: Define request/response models using Pydantic
- **HTTP Status Codes**: Use appropriate status codes (200, 404, 500, 503)
- **Error Responses**: Return consistent error response format with `detail` field

### Logging Standards

- **Structured Logging**: Use the logging utility from `app.utils.logging`
- **Log Levels**: 
  - `DEBUG`: Detailed diagnostic information
  - `INFO`: General operational information
  - `WARNING`: Unexpected but handled situations
  - `ERROR`: Error conditions that need attention
- **No Sensitive Data**: Never log tokens, secrets, or PII
- **Token Masking**: Use `mask_sensitive_data()` when logging token-related information

## Testing Requirements

### Running Tests

```bash
# Run all tests
pytest

# Run with verbose output
pytest -v

# Run specific test file
pytest tests/test_oauth_flow.py

# Run with coverage report
pytest --cov=app --cov-report=html

# Run specific test markers
pytest -m unit           # Unit tests only
pytest -m integration    # Integration tests only
```

### Test Coverage Requirements

- **New code**: Minimum 80% test coverage
- **Critical paths**: 100% coverage for security-related code (encryption, authentication, token handling)
- **Edge cases**: Test error conditions, boundary cases, and failure scenarios

### Writing Tests

1. **Test Structure**: Follow the Arrange-Act-Assert pattern
   ```python
   def test_token_encryption():
       # Arrange
       service = TokenService(encryption_key="test_key")
       token = "ghp_test_token"
       
       # Act
       encrypted = service.encrypt_token(token)
       
       # Assert
       assert encrypted != token
       assert len(encrypted) > 0
   ```

2. **Test Naming**: Use descriptive names that explain what is being tested
   - ✅ `test_oauth_callback_validates_state_token`
   - ❌ `test_callback`

3. **Fixtures**: Use pytest fixtures for common setup (see `tests/conftest.py`)

4. **Mocking**: Use `unittest.mock` or `pytest-mock` for external dependencies
   ```python
   from unittest.mock import Mock, patch
   
   @patch('app.services.github.requests.post')
   def test_token_exchange(mock_post):
       mock_post.return_value.json.return_value = {"access_token": "test"}
       # ... test implementation
   ```

5. **Async Tests**: Mark async tests with `@pytest.mark.asyncio`
   ```python
   @pytest.mark.asyncio
   async def test_async_endpoint():
       async with AsyncClient(app=app) as client:
           response = await client.get("/healthz")
           assert response.status_code == 200
   ```

### Test Categories

- **Unit Tests** (`@pytest.mark.unit`): Test individual functions/classes in isolation
- **Integration Tests** (`@pytest.mark.integration`): Test multiple components working together
- **Security Tests**: Validate security features (encryption, authentication, authorization)

### Continuous Integration

Tests run automatically on all pull requests. Ensure all tests pass before requesting review:

```bash
# Verify tests pass locally
pytest -v

# Check for common issues
python -m pytest --tb=short
```

## Security Considerations

### Handling Secrets

**❌ NEVER commit secrets to the repository:**
- No real GitHub tokens in test files or examples
- No encryption keys in code or config files
- No GCP service account keys in the repository
- No API credentials or passwords

**✅ Use appropriate secret storage:**
- Use `.env` files for local development (already in `.gitignore`)
- Use environment variables for CI/CD
- Use Google Secret Manager for production deployments
- Use Firestore emulator for testing (no real credentials needed)

### Testing OAuth Flows

External contributors cannot complete full OAuth flows with real GitHub Apps because:
- OAuth requires registered callback URLs (can't use localhost from forks)
- Integration tests require GCP credentials
- Real tokens can't be shared in PRs for security reasons

**Solutions for Contributors:**

1. **Use Mock Data**: Test OAuth logic with mocked GitHub API responses
   ```python
   @patch('app.services.github.requests.post')
   def test_oauth_exchange(mock_post):
       mock_post.return_value.json.return_value = {
           "access_token": "gho_test_token",
           "token_type": "bearer",
           "scope": "user:email"
       }
       # Test the exchange logic
   ```

2. **Use Firestore Emulator**: Test token storage without GCP credentials
   ```bash
   firebase emulators:start --only firestore
   export FIRESTORE_EMULATOR_HOST=localhost:8080
   pytest tests/test_firestore_dao.py
   ```

3. **Focus on Unit Tests**: Contribute unit tests that don't require integration with external services

4. **Documentation**: Update docs, add examples, improve error messages (no secrets needed!)

### Security Review

All security-related changes undergo additional review:
- Changes to encryption logic
- Authentication/authorization modifications
- Token handling and storage
- IAM configuration changes
- Credential management

## Pull Request Process

### Before Submitting

1. **Update your branch** with the latest upstream changes:
   ```bash
   git fetch upstream
   git rebase upstream/main
   ```

2. **Run tests** and ensure they pass:
   ```bash
   pytest -v
   ```

3. **Check code style** (if linter is configured):
   ```bash
   # We don't currently have a linter configured, but follow PEP 8
   ```

4. **Update documentation** if your changes affect:
   - API endpoints or behavior
   - Configuration options
   - Deployment procedures
   - Setup instructions

5. **Add to CHANGELOG** (for significant changes):
   - Follow the existing format
   - Add entry under `[Unreleased]` section
   - Include category: Added/Changed/Deprecated/Removed/Fixed/Security

### Commit Messages

Use clear, descriptive commit messages:

```
feat: Add automatic token refresh with cooldown enforcement

- Implement configurable refresh threshold (default: 30 minutes)
- Add cooldown period to prevent excessive API calls
- Include force_refresh option for admin operations
- Update token metadata schema with last_refresh_attempt

Closes #123
```

**Format**:
- **Type**: `feat`, `fix`, `docs`, `test`, `refactor`, `chore`, `security`
- **Subject**: Short summary (50 chars or less)
- **Body**: Detailed explanation (wrap at 72 chars)
- **Footer**: Issue references, breaking changes

### PR Description Template

```markdown
## Description
Brief description of what this PR does and why.

## Type of Change
- [ ] Bug fix (non-breaking change which fixes an issue)
- [ ] New feature (non-breaking change which adds functionality)
- [ ] Breaking change (fix or feature that would cause existing functionality to not work as expected)
- [ ] Documentation update
- [ ] Security fix

## Testing
- [ ] Unit tests added/updated
- [ ] Integration tests added/updated (if applicable)
- [ ] Manual testing completed
- [ ] All tests pass locally

## Checklist
- [ ] Code follows the project's style guidelines
- [ ] Self-reviewed the code
- [ ] Commented code in hard-to-understand areas
- [ ] Updated documentation (README, docs/, inline comments)
- [ ] No new warnings generated
- [ ] Added tests that prove the fix/feature works
- [ ] No secrets or credentials committed

## Security Considerations
List any security implications or considerations for this change.
```

### Review Process

1. **Automated Checks**: CI runs tests automatically on PR creation
2. **Code Review**: At least one maintainer review required
3. **Security Review**: Required for security-related changes
4. **Documentation Review**: Required if docs are updated
5. **Approval**: PR must be approved before merging
6. **Merge**: Maintainers will merge approved PRs

### Feedback and Iteration

- Respond to review comments constructively
- Push additional commits to address feedback
- Don't force-push after review has started (breaks review context)
- Request re-review after addressing comments

## External Contributor Limitations

### What External Contributors Can Do

✅ **Encouraged Contributions:**
- Bug fixes in application logic
- Unit test additions and improvements
- Documentation improvements (README, guides, examples)
- Code refactoring and optimization
- Error message improvements
- Mock-based integration tests
- Feature enhancements (with discussion first)

✅ **Testing Without Credentials:**
- Use Firestore emulator for DAO testing
- Mock GitHub API responses for OAuth testing
- Write unit tests with in-memory state
- Test with dummy encryption keys for local dev

### What External Contributors Cannot Do

❌ **Limitations:**
- Cannot run full integration tests requiring real GCP credentials
- Cannot test OAuth flows with production GitHub Apps
- Cannot access production or staging environments
- Cannot modify CI/CD pipeline secrets
- Cannot approve/merge PRs (maintainer-only)

### Getting Help

If you need help testing your contribution:
1. Open an issue describing what you want to contribute
2. Maintainers can provide test results or mock data
3. Focus on unit tests that maintainers can validate with integration tests
4. Ask questions in the issue/PR - we're here to help!

## Release Process

For maintainers and contributors interested in the release workflow:

### Versioning

We follow [Semantic Versioning](https://semver.org/):
- **MAJOR** (X.0.0): Breaking changes
- **MINOR** (x.X.0): New features, backward-compatible
- **PATCH** (x.x.X): Bug fixes, backward-compatible

### Release Steps

1. **Update CHANGELOG.md**:
   - Move `[Unreleased]` changes to new version section
   - Add release date
   - Create new `[Unreleased]` section

2. **Update README.md** (if needed):
   - Update version references
   - Update compatibility notes
   - Refresh feature lists if significant changes

3. **Create Git Tag**:
   ```bash
   git tag -a v0.2.0 -m "Release v0.2.0"
   git push origin v0.2.0
   ```

4. **Create GitHub Release**:
   - Go to repository → Releases → New Release
   - Select the tag
   - Copy CHANGELOG entry as release notes
   - ⚠️ **Never include secrets or credentials in release notes**

5. **Update Deployment**:
   - Deploy to staging for validation
   - Deploy to production after testing
   - Monitor logs for issues

6. **Announce Release**:
   - Update any external documentation
   - Notify users of breaking changes (if any)

### Pre-release Testing

Before tagging a release:
- All tests must pass
- Manual testing of critical paths
- Security review for sensitive changes
- Documentation review for accuracy
- Upgrade testing from previous version

## Questions?

- **General Questions**: Open a GitHub issue with the `question` label
- **Security Concerns**: See [SECURITY.md](SECURITY.md) for responsible disclosure
- **Feature Requests**: Open an issue with the `enhancement` label
- **Bug Reports**: Open an issue with the `bug` label

## License

By contributing, you agree that your contributions will be licensed under the Apache License 2.0. See [LICENSE](LICENSE) for details.

### Attribution for Derivative Works

If you create derivative works:
1. Retain the original Apache 2.0 license
2. Include a NOTICE file with attribution to original authors
3. Clearly mark your modifications
4. Follow Apache 2.0 license requirements for redistribution

---

Thank you for contributing to the GitHub App Token Minting Service! 🎉
