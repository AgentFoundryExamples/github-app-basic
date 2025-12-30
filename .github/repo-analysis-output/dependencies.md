# Dependency Graph

Multi-language intra-repository dependency analysis.

Supports Python, JavaScript/TypeScript, C/C++, Rust, Go, Java, C#, Swift, HTML/CSS, and SQL.

Includes classification of external dependencies as stdlib vs third-party.

## Statistics

- **Total files**: 29
- **Intra-repo dependencies**: 49
- **External stdlib dependencies**: 29
- **External third-party dependencies**: 34

## External Dependencies

### Standard Library / Core Modules

Total: 29 unique modules

- `argparse`
- `asyncio`
- `base64`
- `contextlib.asynccontextmanager`
- `contextvars.ContextVar`
- `datetime.datetime`
- `datetime.timedelta`
- `datetime.timezone`
- `http.client`
- `json`
- `logging`
- `os`
- `pathlib.Path`
- `re`
- `secrets`
- `sys`
- `threading`
- `threading.Lock`
- `time`
- `traceback`
- ... and 9 more (see JSON for full list)

### Third-Party Packages

Total: 34 unique packages

- `cryptography.exceptions.InvalidTag`
- `cryptography.hazmat.backends.default_backend`
- `cryptography.hazmat.primitives.asymmetric.rsa`
- `cryptography.hazmat.primitives.ciphers.Cipher`
- `cryptography.hazmat.primitives.ciphers.algorithms`
- `cryptography.hazmat.primitives.ciphers.modes`
- `cryptography.hazmat.primitives.serialization`
- `fastapi.APIRouter`
- `fastapi.Body`
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
- ... and 14 more (see JSON for full list)

## Most Depended Upon Files (Intra-Repo)

- `app/config.py` (11 dependents)
- `app/utils/logging.py` (9 dependents)
- `app/dao/firestore_dao.py` (7 dependents)
- `app/services/github.py` (6 dependents)
- `app/dependencies/firestore.py` (5 dependents)
- `app/main.py` (4 dependents)
- `app/services/firestore.py` (2 dependents)
- `app/routes/health.py` (1 dependents)
- `app/routes/oauth.py` (1 dependents)
- `app/routes/admin.py` (1 dependents)

## Files with Most Dependencies (Intra-Repo)

- `app/main.py` (6 dependencies)
- `tests/test_firestore_dao.py` (6 dependencies)
- `app/routes/oauth.py` (5 dependencies)
- `app/routes/token.py` (5 dependencies)
- `app/dependencies/firestore.py` (4 dependencies)
- `app/routes/admin.py` (4 dependencies)
- `tests/test_oauth_flow.py` (4 dependencies)
- `tests/test_token_endpoint.py` (4 dependencies)
- `app/services/firestore.py` (2 dependencies)
- `tests/test_health.py` (2 dependencies)
