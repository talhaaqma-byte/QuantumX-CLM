# Backend API (FastAPI)

## Status

The repository now includes a working FastAPI foundation in `backend/`.

## Running the API

1. Install dependencies:

```bash
python -m venv .venv
source .venv/bin/activate
pip install -r backend/requirements.txt
```

2. Configure environment variables:

```bash
cp .env.example .env
```

3. Run the server:

```bash
uvicorn backend.app.main:app --reload --host 0.0.0.0 --port 8000
```

4. Health check:

```bash
curl http://localhost:8000/health
```

## Configuration

Configuration is loaded via environment variables (Pydantic Settings v2):

- `CLM_ENVIRONMENT` (default: `development`)
- `CLM_LOG_LEVEL` (default: `INFO`)
- `CLM_CORE_DB_DSN` (optional)
- `CLM_SECURE_DB_DSN` (optional)
- `CLM_DB_SSL_REQUIRED` + optional cert fields

## Dual Database Handling

The application maintains separate SQLAlchemy async engines/sessionmakers for:

- `clm_core_db` (application data)
- `clm_secure_db` (sensitive crypto material)

No cross-database joins are performed; cross-database references should be validated at the application layer via UUIDs.

## Alembic

Alembic is scaffolded for both databases:

```bash
alembic -c backend/alembic_core.ini upgrade head
alembic -c backend/alembic_secure.ini upgrade head
```

The initial schema currently lives in the raw SQL migrations under `migrations/`.
