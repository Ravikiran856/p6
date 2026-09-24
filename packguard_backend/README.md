# PackGuard Backend

FastAPI REST API for PyPI package risk scanning (static analysis + Random Forest + typosquat detection).

## Quick start

```bash
cd packguard_backend
pip install -r requirements.txt
python ml/train_model.py --n-rows 50
copy .env.example .env
uvicorn main:app --reload --port 8000
```

Open `http://127.0.0.1:8000/docs` for interactive API docs.

## Auth

Production: mobile app signs in with Firebase Auth; send `Authorization: Bearer <Firebase ID token>` on protected routes.

Local dev (no Firebase credentials): set `ALLOW_DEV_AUTH_BYPASS=true` and use:

```http
Authorization: Bearer dev:<uid>:<email>
```

Signup/login endpoints accept `{ "idToken": "<firebase-or-dev-token>" }` and verify via Firebase Admin SDK.

## Endpoints (prefix `/api/v1`)

| Method | Path | Description |
|--------|------|-------------|
| GET | `/health` | Liveness + model version |
| POST | `/auth/signup` | Verify token, create user profile |
| POST | `/auth/login` | Verify token, return profile |
| POST | `/scan/package` | JSON `{ "packageName": "..." }` or multipart `requirements_file` |
| GET | `/scan/dependency-graph/{package_name}` | Graph nodes/edges with risk colors (depth ≤ 3) |
| GET | `/scan/history` | Paginated scan history (`cursor`, `limit`, `riskLevel`) |
| GET | `/scan/report/{scan_id}/pdf` | PDF report download |
| POST | `/scan/rescan-check` | Background re-scan for version/risk drift (`?run_sync=true` for tests) |

## Rate limiting (slowapi)

Configured in `app/core/rate_limit.py` and applied on scan/auth/report routes. Global middleware in `main.py` (`SlowAPIMiddleware`). For production, back the limiter with Redis storage and stricter per-user keys (IEEE paper: document limits on `/scan/package` and PyPI-heavy graph walks).

## Tests

```bash
pytest tests/ -v
```

## Docker

```bash
docker build -t packguard-api .
docker run -p 8000:8000 -e ALLOW_DEV_AUTH_BYPASS=true packguard-api
```
