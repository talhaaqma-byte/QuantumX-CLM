from __future__ import annotations

from typing import AsyncIterator

from fastapi import Depends, HTTPException, Request
from sqlalchemy.ext.asyncio import AsyncSession

from backend.common.db import Database


def get_database(request: Request) -> Database:
    return request.app.state.db


async def get_core_session(
    db: Database = Depends(get_database),
) -> AsyncIterator[AsyncSession]:
    if db.core_sessionmaker is None:
        raise HTTPException(status_code=503, detail="Core database is not configured")

    async with db.core_sessionmaker() as session:
        yield session


async def get_secure_session(
    db: Database = Depends(get_database),
) -> AsyncIterator[AsyncSession]:
    if db.secure_sessionmaker is None:
        raise HTTPException(status_code=503, detail="Secure database is not configured")

    async with db.secure_sessionmaker() as session:
        yield session
