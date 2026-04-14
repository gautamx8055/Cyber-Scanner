# CyberScanner — Claude Context

## What this project is
A professional-grade, open-source cybersecurity scanner inspired by Nmap.
Built as a solo learning project (~3 hrs/day) to learn Python, Networking, Docker, and Full-Stack Dev.

Full plan: `docs/PROJECT_PLAN.md`
Architecture diagram: `docs/workflow/WORKFLOW.md`
Task tracker: `TODO.md` — update checkboxes as tasks are completed.

---

## Tech Stack

- **Backend**: Python 3.12, FastAPI, SQLAlchemy (async), asyncpg, Alembic, Rich, httpx, scapy
- **Database**: PostgreSQL 16 (runs in Docker)
- **Frontend**: Next.js 14 + shadcn/ui + TailwindCSS (Phase 8 — not started yet)
- **Packaging**: Docker Compose (dev), PyInstaller + multi-stage Docker (Phase 10)

---

## Project Structure

```
cyber-scanner/
├── CLAUDE.md                  ← you are here
├── TODO.md                    ← task tracker, update as work completes
├── docker-compose.yml         ← PostgreSQL + backend containers
├── .env                       ← local secrets (never commit)
├── .env.example               ← template for .env
├── docker/
│   └── backend.Dockerfile
├── backend/
│   ├── main.py                ← FastAPI entry point
│   ├── requirements.txt       ← all Python deps
│   ├── alembic.ini
│   ├── alembic/
│   │   └── versions/          ← migration files
│   ├── db/
│   │   ├── session.py         ← async engine + get_db() dependency
│   │   └── models.py          ← SQLAlchemy ORM models
│   ├── scanner/               ← port_scanner, vuln_scanner, web_scanner, reporter
│   ├── api/                   ← FastAPI route handlers
│   └── c_extensions/          ← C port scanner (Phase 9)
├── frontend/                  ← Next.js app (Phase 8)
├── tests/
│   └── test_db_connection.py  ← verify PostgreSQL connection
└── docs/
    ├── PROJECT_PLAN.md
    ├── workflow/WORKFLOW.md
    └── tasks/                 ← one doc file per completed task
```

---

## Current Progress

- **Phase 1 — DONE**: Docker + PostgreSQL, Python skeleton, SQLAlchemy + Alembic wired up.
- **Phase 2 — NEXT**: Synchronous TCP port scanner.

See `TODO.md` for the full per-task breakdown.

---

## Dev Workflow

```bash
# Start services
docker-compose up -d

# Run migrations (first time, or after adding a new migration)
cd backend && alembic upgrade head

# Run FastAPI locally (outside Docker, for faster dev)
cd backend && source ../venv/bin/activate && uvicorn main:app --reload

# Test DB connection
python tests/test_db_connection.py
```

---

## Rules for Claude

- Always update `TODO.md` checkboxes when a task is completed.
- Never commit `.env` — use `.env.example` as the template.
- **Never read, edit, or access `.env` or any `.env.*` files (e.g. `.env.local`, `.env.production`, `.env.staging`). These contain real secrets. Only `.env.example` may be read and edited — it holds no real credentials, only placeholder values.**
- When adding a new Python package: add it to `backend/requirements.txt`.
- When changing the DB schema: create an Alembic migration, don't edit tables by hand.
- Keep scanner modules in `backend/scanner/`, API routes in `backend/api/`.
- Don't add features or abstractions beyond what the current phase requires.
- **After completing any task, create a documentation file in `docs/tasks/` named after the task (e.g. `task-1.1-docker-postgresql.md`, `task-2.1-tcp-scanner.md`). Document: what was built, what files were created/modified, key concepts learned, and how to run/test it.**
