# QuantumX-CLM Backend (FastAPI)

## Overview

This directory contains the FastAPI backend foundation:

- Async FastAPI application
- Modular service routers (`auth`, `certificates`, `workflows`, `policies`, `integrations`)
- Shared utilities in `backend/common/` (config, logging, DB)
- Pydantic v2 models
- Alembic scaffolding for migrations (core + secure DB)

## Setup

Create a virtual environment and install dependencies:

```bash
python -m venv .venv
source .venv/bin/activate
pip install -r backend/requirements.txt
```

Copy environment variables:

```bash
cp .env.example .env
```

Update `.env` with your database DSNs as needed.

## Run the API

From the repository root:

```bash
uvicorn backend.app.main:app --reload --host 0.0.0.0 --port 8000
```

Health check:

```bash
curl http://localhost:8000/health
```

## Dual-DB Configuration

The app supports two Postgres databases:

- `CLM_CORE_DB_DSN` (application data)
- `CLM_SECURE_DB_DSN` (sensitive crypto material)

Both are optional for boot; the API can start without DBs configured.

If you want `/health` to actively test DB connectivity, set:

```bash
CLM_HEALTHCHECK_DB=true
```

## Alembic Migrations

Alembic is scaffolded as two independent environments:

- Core DB: `backend/alembic_core.ini`
- Secure DB: `backend/alembic_secure.ini`

Examples:

```bash
alembic -c backend/alembic_core.ini upgrade head
alembic -c backend/alembic_secure.ini upgrade head
```

These environments are currently set up for future migrations; the initial schema is defined in `migrations/`.
