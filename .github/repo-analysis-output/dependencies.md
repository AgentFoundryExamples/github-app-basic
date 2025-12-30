# Dependency Graph

Multi-language intra-repository dependency analysis.

Supports Python, JavaScript/TypeScript, C/C++, Rust, Go, Java, C#, Swift, HTML/CSS, and SQL.

Includes classification of external dependencies as stdlib vs third-party.

## Statistics

- **Total files**: 10
- **Intra-repo dependencies**: 6
- **External stdlib dependencies**: 9
- **External third-party dependencies**: 13

## External Dependencies

### Standard Library / Core Modules

Total: 9 unique modules

- `contextlib.asynccontextmanager`
- `contextvars.ContextVar`
- `logging`
- `os`
- `sys`
- `typing.Any`
- `typing.AsyncIterator`
- `typing.Dict`
- `typing.Optional`

### Third-Party Packages

Total: 13 unique packages

- `fastapi.APIRouter`
- `fastapi.FastAPI`
- `fastapi.Request`
- `fastapi.middleware.cors.CORSMiddleware`
- `fastapi.testclient.TestClient`
- `pydantic.Field`
- `pydantic.ValidationError`
- `pydantic.field_validator`
- `pydantic_settings.BaseSettings`
- `pydantic_settings.SettingsConfigDict`
- `pytest`
- `pythonjsonlogger.jsonlogger`
- `uvicorn`

## Most Depended Upon Files (Intra-Repo)

- `app/config.py` (3 dependents)
- `app/utils/logging.py` (1 dependents)
- `app/routes/health.py` (1 dependents)
- `app/main.py` (1 dependents)

## Files with Most Dependencies (Intra-Repo)

- `app/main.py` (3 dependencies)
- `tests/test_health.py` (2 dependencies)
- `tests/test_config.py` (1 dependencies)
