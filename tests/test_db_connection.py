"""
Phase 1 — Connection test.
Run with:  python tests/test_db_connection.py
Verifies that Python can connect to PostgreSQL and that the scans table exists.
"""

import asyncio
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "backend"))

from dotenv import load_dotenv

load_dotenv()

from sqlalchemy import text
from db.session import engine, AsyncSessionLocal
from db.models import Scan


async def main():
    print("Testing PostgreSQL connection...")

    async with engine.connect() as conn:
        result = await conn.execute(text("SELECT version()"))
        version = result.scalar()
        print(f"  Connected! PostgreSQL version: {version}")

    print("Inserting a test scan record...")
    async with AsyncSessionLocal() as session:
        scan = Scan(
            target_ip="127.0.0.1",
            target_hostname="localhost",
            scan_type="port",
            status="queued",
            options={"ports": "1-1000"},
        )
        session.add(scan)
        await session.commit()
        await session.refresh(scan)
        print(f"  Inserted scan: {scan}")

    print("Reading it back...")
    async with AsyncSessionLocal() as session:
        result = await session.execute(text("SELECT id, target_ip, status FROM scans LIMIT 5"))
        rows = result.fetchall()
        for row in rows:
            print(f"  Row: {dict(row._mapping)}")

    print("\nAll checks passed!")

    await engine.dispose()


if __name__ == "__main__":
    asyncio.run(main())
