# Dependency Graph

Multi-language intra-repository dependency analysis.

Supports Python, JavaScript/TypeScript, C/C++, Rust, Go, Java, C#, Swift, HTML/CSS, and SQL.

Includes classification of external dependencies as stdlib vs third-party.

## Statistics

- **Total files**: 35
- **Intra-repo dependencies**: 78
- **External stdlib dependencies**: 33
- **External third-party dependencies**: 36

## External Dependencies

### Standard Library / Core Modules

Total: 33 unique modules

- `argparse`
- `asyncio`
- `base64`
- `collections.defaultdict`
- `contextlib.asynccontextmanager`
- `contextvars.ContextVar`
- `datetime.datetime`
- `datetime.timedelta`
- `datetime.timezone`
- `http.client`
- `io.StringIO`
- `json`
- `logging`
- `os`
- `pathlib.Path`
- `re`
- `secrets`
- `sys`
- `threading`
- `threading.Lock`
- ... and 13 more (see JSON for full list)

### Third-Party Packages

Total: 36 unique packages

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
- `fastapi.openapi.utils.get_openapi`
- `fastapi.responses.HTMLResponse`
- `fastapi.responses.PlainTextResponse`
- `fastapi.responses.RedirectResponse`
- ... and 16 more (see JSON for full list)

## Most Depended Upon Files (Intra-Repo)

- `app/config.py` (13 dependents)
- `app/utils/logging.py` (12 dependents)
- `app/utils/security.py` (9 dependents)
- `app/dao/firestore_dao.py` (8 dependents)
- `app/dependencies/firestore.py` (6 dependents)
- `app/services/github.py` (6 dependents)
- `app/services/firestore.py` (5 dependents)
- `app/utils/metrics.py` (5 dependents)
- `app/main.py` (5 dependents)
- `app/services/readiness.py` (3 dependents)

## Files with Most Dependencies (Intra-Repo)

- `app/main.py` (9 dependencies)
- `app/routes/health.py` (7 dependencies)
- `app/routes/oauth.py` (7 dependencies)
- `app/routes/token.py` (7 dependencies)
- `tests/test_firestore_dao.py` (6 dependencies)
- `app/routes/admin.py` (5 dependencies)
- `tests/test_health.py` (5 dependencies)
- `app/dependencies/firestore.py` (4 dependencies)
- `tests/test_logging_and_metrics.py` (4 dependencies)
- `tests/test_oauth_flow.py` (4 dependencies)
