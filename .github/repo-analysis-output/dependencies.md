# Dependency Graph

Multi-language intra-repository dependency analysis.

Supports Python, JavaScript/TypeScript, C/C++, Rust, Go, Java, C#, Swift, HTML/CSS, and SQL.

Includes classification of external dependencies as stdlib vs third-party.

## Statistics

- **Total files**: 21
- **Intra-repo dependencies**: 26
- **External stdlib dependencies**: 22
- **External third-party dependencies**: 28

## External Dependencies

### Standard Library / Core Modules

Total: 22 unique modules

- `contextlib.asynccontextmanager`
- `contextvars.ContextVar`
- `datetime.datetime`
- `datetime.timedelta`
- `http.client`
- `logging`
- `os`
- `re`
- `secrets`
- `sys`
- `threading`
- `threading.Lock`
- `time`
- `typing.Any`
- `typing.AsyncIterator`
- `typing.Dict`
- `typing.Optional`
- `unittest.mock.AsyncMock`
- `unittest.mock.MagicMock`
- `unittest.mock.Mock`
- ... and 2 more (see JSON for full list)

### Third-Party Packages

Total: 28 unique packages

- `cryptography.hazmat.backends.default_backend`
- `cryptography.hazmat.primitives.asymmetric.rsa`
- `cryptography.hazmat.primitives.serialization`
- `fastapi.APIRouter`
- `fastapi.Depends`
- `fastapi.FastAPI`
- `fastapi.HTTPException`
- `fastapi.Query`
- `fastapi.Request`
- `fastapi.Response`
- `fastapi.middleware.cors.CORSMiddleware`
- `fastapi.responses.HTMLResponse`
- `fastapi.responses.RedirectResponse`
- `fastapi.status`
- `fastapi.testclient.TestClient`
- `google.api_core.exceptions`
- `google.cloud.firestore`
- `httpx`
- `jwt`
- `pydantic.Field`
- ... and 8 more (see JSON for full list)

## Most Depended Upon Files (Intra-Repo)

- `app/config.py` (8 dependents)
- `app/utils/logging.py` (6 dependents)
- `app/main.py` (3 dependents)
- `app/dao/firestore_dao.py` (2 dependents)
- `app/services/firestore.py` (2 dependents)
- `app/services/github.py` (2 dependents)
- `app/routes/health.py` (1 dependents)
- `app/routes/oauth.py` (1 dependents)
- `app/dependencies/firestore.py` (1 dependents)

## Files with Most Dependencies (Intra-Repo)

- `tests/test_firestore_dao.py` (5 dependencies)
- `app/dependencies/firestore.py` (4 dependencies)
- `app/main.py` (4 dependencies)
- `app/routes/oauth.py` (3 dependencies)
- `tests/test_oauth_flow.py` (3 dependencies)
- `app/services/firestore.py` (2 dependencies)
- `tests/test_health.py` (2 dependencies)
- `app/dao/firestore_dao.py` (1 dependencies)
- `app/services/github.py` (1 dependencies)
- `tests/test_config.py` (1 dependencies)
