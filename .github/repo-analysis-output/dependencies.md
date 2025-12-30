# Dependency Graph

Multi-language intra-repository dependency analysis.

Supports Python, JavaScript/TypeScript, C/C++, Rust, Go, Java, C#, Swift, HTML/CSS, and SQL.

Includes classification of external dependencies as stdlib vs third-party.

## Statistics

- **Total files**: 22
- **Intra-repo dependencies**: 30
- **External stdlib dependencies**: 27
- **External third-party dependencies**: 32

## External Dependencies

### Standard Library / Core Modules

Total: 27 unique modules

- `argparse`
- `asyncio`
- `base64`
- `contextlib.asynccontextmanager`
- `contextvars.ContextVar`
- `datetime.datetime`
- `datetime.timedelta`
- `datetime.timezone`
- `http.client`
- `logging`
- `os`
- `re`
- `secrets`
- `sys`
- `threading`
- `threading.Lock`
- `time`
- `traceback`
- `typing.Any`
- `typing.AsyncIterator`
- ... and 7 more (see JSON for full list)

### Third-Party Packages

Total: 32 unique packages

- `cryptography.exceptions.InvalidTag`
- `cryptography.hazmat.backends.default_backend`
- `cryptography.hazmat.primitives.asymmetric.rsa`
- `cryptography.hazmat.primitives.ciphers.Cipher`
- `cryptography.hazmat.primitives.ciphers.algorithms`
- `cryptography.hazmat.primitives.ciphers.modes`
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
- ... and 12 more (see JSON for full list)

## Most Depended Upon Files (Intra-Repo)

- `app/config.py` (8 dependents)
- `app/utils/logging.py` (7 dependents)
- `app/dao/firestore_dao.py` (3 dependents)
- `app/dependencies/firestore.py` (3 dependents)
- `app/main.py` (3 dependents)
- `app/services/firestore.py` (2 dependents)
- `app/services/github.py` (2 dependents)
- `app/routes/health.py` (1 dependents)
- `app/routes/oauth.py` (1 dependents)

## Files with Most Dependencies (Intra-Repo)

- `tests/test_firestore_dao.py` (6 dependencies)
- `app/routes/oauth.py` (5 dependencies)
- `app/dependencies/firestore.py` (4 dependencies)
- `app/main.py` (4 dependencies)
- `tests/test_oauth_flow.py` (4 dependencies)
- `app/services/firestore.py` (2 dependencies)
- `tests/test_health.py` (2 dependencies)
- `app/dao/firestore_dao.py` (1 dependencies)
- `app/services/github.py` (1 dependencies)
- `tests/test_config.py` (1 dependencies)
