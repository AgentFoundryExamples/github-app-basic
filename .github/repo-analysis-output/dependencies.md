# Dependency Graph

Multi-language intra-repository dependency analysis.

Supports Python, JavaScript/TypeScript, C/C++, Rust, Go, Java, C#, Swift, HTML/CSS, and SQL.

Includes classification of external dependencies as stdlib vs third-party.

## Statistics

- **Total files**: 17
- **Intra-repo dependencies**: 18
- **External stdlib dependencies**: 15
- **External third-party dependencies**: 18

## External Dependencies

### Standard Library / Core Modules

Total: 15 unique modules

- `contextlib.asynccontextmanager`
- `contextvars.ContextVar`
- `logging`
- `os`
- `sys`
- `threading`
- `threading.Lock`
- `typing.Any`
- `typing.AsyncIterator`
- `typing.Dict`
- `typing.Optional`
- `unittest.mock.AsyncMock`
- `unittest.mock.MagicMock`
- `unittest.mock.Mock`
- `unittest.mock.patch`

### Third-Party Packages

Total: 18 unique packages

- `fastapi.APIRouter`
- `fastapi.Depends`
- `fastapi.FastAPI`
- `fastapi.HTTPException`
- `fastapi.Request`
- `fastapi.middleware.cors.CORSMiddleware`
- `fastapi.status`
- `fastapi.testclient.TestClient`
- `google.api_core.exceptions`
- `google.cloud.firestore`
- `pydantic.Field`
- `pydantic.ValidationError`
- `pydantic.field_validator`
- `pydantic_settings.BaseSettings`
- `pydantic_settings.SettingsConfigDict`
- `pytest`
- `pythonjsonlogger.jsonlogger`
- `uvicorn`

## Most Depended Upon Files (Intra-Repo)

- `app/config.py` (6 dependents)
- `app/utils/logging.py` (4 dependents)
- `app/dao/firestore_dao.py` (2 dependents)
- `app/services/firestore.py` (2 dependents)
- `app/main.py` (2 dependents)
- `app/routes/health.py` (1 dependents)
- `app/dependencies/firestore.py` (1 dependents)

## Files with Most Dependencies (Intra-Repo)

- `tests/test_firestore_dao.py` (5 dependencies)
- `app/dependencies/firestore.py` (4 dependencies)
- `app/main.py` (3 dependencies)
- `app/services/firestore.py` (2 dependencies)
- `tests/test_health.py` (2 dependencies)
- `app/dao/firestore_dao.py` (1 dependencies)
- `tests/test_config.py` (1 dependencies)
