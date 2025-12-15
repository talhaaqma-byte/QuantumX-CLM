from __future__ import annotations

import os

import uvicorn


def main() -> None:
    host = os.getenv("CLM_HOST", "0.0.0.0")
    port = int(os.getenv("CLM_PORT", "8000"))
    reload = os.getenv("CLM_RELOAD", "false").lower() in {"1", "true", "yes"}

    uvicorn.run("backend.app.main:app", host=host, port=port, reload=reload)


if __name__ == "__main__":
    main()
