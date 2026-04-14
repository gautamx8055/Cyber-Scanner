# Task 1.2 — Python Project Skeleton

## What was built
Created the full folder structure for the project, installed all core Python dependencies, and wrote the FastAPI entry point.

## Files created
| File | Purpose |
|---|---|
| `backend/main.py` | FastAPI app instance with `/` and `/health` routes |
| `backend/requirements.txt` | All pinned Python dependencies |
| `backend/scanner/__init__.py` | Marks `scanner/` as a Python package |
| `backend/api/__init__.py` | Marks `api/` as a Python package |
| `backend/db/__init__.py` | Marks `db/` as a Python package |

## Folders created
```
backend/
  scanner/       ← port_scanner, vuln_scanner, web_scanner, reporter (Phases 2-5)
  api/           ← FastAPI route handlers (Phase 6)
  db/            ← SQLAlchemy models and session factory
  alembic/       ← Alembic migration files
  c_extensions/  ← C port scanner shared library (Phase 9)
frontend/        ← Next.js app (Phase 8)
tests/           ← test and verification scripts
```

## `backend/main.py` — what's in it

```python
app = FastAPI(
    title="CyberScanner",
    description="Professional-grade cybersecurity scanner API",
    version="0.1.0",
)

GET /          → {"status": "ok", "message": "CyberScanner is running"}
GET /health    → {"status": "healthy"}
```

- `console = Console()` is created at module level — ready to use anywhere in the file for colored terminal output.
- FastAPI auto-generates Swagger UI at `/docs` and ReDoc at `/redoc` — free, no extra setup needed.
- The `if __name__ == "__main__"` block at the bottom lets you run the file directly with `python main.py`. It prints a green startup message via Rich, then launches uvicorn with `host="0.0.0.0"` (accessible from any network interface) and `reload=True` (auto-restarts on code changes). This block is skipped when uvicorn imports `main.py` as a module.

## Dependencies installed (`backend/requirements.txt`)
| Package | Version | Why |
|---|---|---|
| `fastapi` | 0.115.0 | Web framework for the REST API |
| `uvicorn[standard]` | 0.30.6 | ASGI server that runs FastAPI; `[standard]` adds uvloop + websockets |
| `sqlalchemy[asyncio]` | 2.0.36 | ORM — maps Python classes to DB tables; `[asyncio]` adds async support |
| `asyncpg` | 0.29.0 | Async PostgreSQL driver used by SQLAlchemy at runtime |
| `alembic` | 1.13.3 | Database migration tool — versioned schema changes |
| `httpx` | 0.27.2 | Async HTTP client for web scanner (Phase 5) |
| `rich` | 13.9.2 | Beautiful terminal output — tables, colors, progress bars |
| `scapy` | 2.6.0 | Low-level packet crafting — ICMP ping, SYN scans (Phase 3, 9) |
| `jinja2` | 3.1.4 | HTML templating for scan reports (Phase 7) |
| `weasyprint` | 62.3 | Converts HTML reports to PDF (Phase 7) |
| `python-dotenv` | 1.0.1 | Loads `.env` file into `os.environ` at startup |
| `pydantic-settings` | 2.5.2 | Typed settings class built from env vars |

## Key concept — Virtual Environment
A virtual environment (`venv/`) is an isolated Python installation scoped to this project.
- Keeps this project's packages separate from your system Python and other projects.
- Any `pip install` goes into `venv/lib/`, not globally.
- Always activate before running Python commands:
  ```bash
  source venv/bin/activate       # Mac/Linux
  venv\Scripts\activate          # Windows
  ```
- When activated, your terminal prompt shows `(venv)` at the start.
- The `venv/` folder is in `.gitignore` — each developer creates their own with `pip install -r requirements.txt`.

## How to run
```bash
# Activate venv
source venv/bin/activate

# Install / re-install all dependencies
pip install -r backend/requirements.txt

# Run the FastAPI server locally (outside Docker, faster for dev)
cd backend && uvicorn main:app --reload

# Visit in browser:
# http://localhost:8000        → {"status": "ok", "message": "CyberScanner is running"}
# http://localhost:8000/docs   → Swagger UI (interactive API docs, auto-generated)
# http://localhost:8000/health → {"status": "healthy"}
```
