# Task 1.3 — Connect Python to PostgreSQL

## What was built
Wired SQLAlchemy (async) to the Docker PostgreSQL container. Configured Alembic for migrations. Created the `scans` table via the first migration. Wrote a connection test script.

## Files created / modified
| File | Action | Purpose |
|---|---|---|
| `backend/db/session.py` | Created | Async SQLAlchemy engine, session factory, `get_db()` FastAPI dependency |
| `backend/db/models.py` | Created | `Scan` ORM model with `ScanType` and `ScanStatus` enums |
| `backend/alembic/env.py` | Modified | Reads `DATABASE_URL` from env, swaps driver for sync migrations, wires models |
| `backend/alembic.ini` | Modified | Changed `sqlalchemy.url` from placeholder to real PostgreSQL URL |
| `backend/alembic/versions/1dce0a522bd6_initial_scans_table.py` | Created | First migration — creates `scans` table with two indexes |
| `tests/test_db_connection.py` | Created | Inserts a scan row and reads it back to verify the full stack works |

## Extra package installed
`psycopg2-binary` was installed alongside the existing deps. Alembic uses a **synchronous** database driver to run migrations (it can't use asyncpg). `psycopg2-binary` is the sync PostgreSQL driver for this purpose only.

## Why the migration was created manually
When we ran `alembic revision --autogenerate`, Alembic tried to connect to PostgreSQL to compare the current schema — but Docker wasn't running yet, so it got "connection refused". Instead of requiring Docker just to generate a migration, we wrote the migration file by hand. This is a normal practice and gives you full control over what SQL runs.

## `backend/alembic/env.py` — key changes from the default
The default Alembic `env.py` knows nothing about our project. We rewrote it to:

1. **Import our models** — `import db.models` registers all ORM classes on `Base.metadata` so Alembic knows what tables to manage.
2. **Read `DATABASE_URL` from environment** — instead of hardcoding credentials.
3. **Swap the async driver for a sync one** — Alembic's migration runner is synchronous. It cannot use `asyncpg`. So we replace `postgresql+asyncpg://` with `postgresql://` (which uses `psycopg2`) before passing the URL to the engine.

```python
sync_url = db_url.replace("postgresql+asyncpg://", "postgresql://")
config.set_main_option("sqlalchemy.url", sync_url)
```

## `backend/alembic.ini` — what changed
One line was changed from the default:
```ini
# Before (placeholder):
sqlalchemy.url = driver://user:pass@localhost/dbname

# After (our dev DB):
sqlalchemy.url = postgresql://cyberscanner:cyberscanner123@localhost:5432/cyberscanner
```
This is the fallback URL used when `DATABASE_URL` env var is not set.

## `backend/db/session.py` — key details

```python
engine = create_async_engine(DATABASE_URL, echo=False, pool_pre_ping=True)
AsyncSessionLocal = async_sessionmaker(engine, class_=AsyncSession, expire_on_commit=False)
```

- `echo=False` — SQLAlchemy won't log every SQL query to the terminal. Set to `True` temporarily when debugging to see exact queries being run.
- `pool_pre_ping=True` — before handing out a connection from the pool, SQLAlchemy sends a lightweight `SELECT 1` to check it's still alive. If the DB restarted, the dead connection is discarded and a fresh one is created automatically.
- `expire_on_commit=False` — by default, SQLAlchemy expires all loaded objects after `session.commit()`, forcing a re-fetch from the DB on next access. Setting this to `False` means objects remain accessible in memory after commit without an extra query — important for async code where re-fetching requires an `await`.
- `DeclarativeBase` — the base class all ORM models inherit from. It registers each subclass in `Base.metadata`, which is what Alembic reads to know what tables exist.

## `backend/db/models.py` — key details

**SQLAlchemy 2.0 style columns**
```python
id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
target_hostname: Mapped[str | None] = mapped_column(String(255), nullable=True)
```
- `Mapped[str]` — type annotation that tells SQLAlchemy (and your IDE) the Python type of this column.
- `Mapped[str | None]` — means the column can be `None` (nullable). The `| None` part is Python 3.10+ union syntax.
- This is the new SQLAlchemy 2.0 style — older code used `Column(String(36), ...)` without type annotations.

**UUID auto-generation**
```python
default=lambda: str(uuid.uuid4())
```
The `id` is generated in Python (not by PostgreSQL) when you do `Scan(...)`. This means you can know the ID before the row is even inserted into the database.

**Python `default` vs `server_default`**
- `default=lambda: str(uuid.uuid4())` — runs in Python when the ORM creates the object. Alembic migration uses `server_default` (runs at the DB level as a SQL expression) for the same columns to ensure they have defaults even when inserted via raw SQL.
- `default=datetime.utcnow` — same idea for `started_at`. The Python ORM sets it; the migration uses `server_default=sa.func.now()`.

**`str, enum.Enum` dual inheritance**
```python
class ScanType(str, enum.Enum):
    port = "port"
```
Inheriting from both `str` and `enum.Enum` means each value is both a string and an enum member. Benefit: it serializes to JSON as a plain string (`"port"`) without extra conversion, and FastAPI's Pydantic models handle it automatically.

**`__repr__`**
```python
def __repr__(self) -> str:
    return f"<Scan id={self.id} target={self.target_ip} status={self.status}>"
```
Defines what prints when you do `print(scan)` or inspect it in a debugger — makes logs and test output readable.

## `backend/alembic/env.py` — key details

**`sys.path.insert` trick**
```python
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
```
Alembic runs from `backend/alembic/` but our modules are in `backend/`. This adds `backend/` to Python's search path so `from db.session import Base` works without installing the package.

**`pool.NullPool` for migrations**
```python
connectable = create_engine(url, poolclass=pool.NullPool)
```
`NullPool` disables connection pooling entirely for migrations. Each migration opens a connection, runs its SQL, and closes it immediately. This avoids leftover connections hanging around after migrations finish.

**Offline vs online migration mode**
- *Online mode* (normal): Alembic connects to the real DB, compares live schema vs your models, runs SQL directly.
- *Offline mode*: Alembic generates the SQL statements as text without connecting to the DB — useful for reviewing what would run, or for DBAs who want to apply SQL manually. Triggered with `alembic upgrade head --sql`.

**`do_run_migrations()` helper**
Extracted so the same migration logic works whether Alembic connects itself (`connectable is None`) or receives an existing connection passed in programmatically (`context.config.attributes.get("connection")`).

## Migration file — key details

**`down_revision = None`**
Means this is the very first migration — it has no parent. Every subsequent migration will set `down_revision` to the ID of the migration it builds on top of. This forms a linked chain Alembic follows in order.

**`branch_labels` and `depends_on`**
Both `None` for now. Used in advanced multi-branch migration setups (e.g. two features adding different tables independently). Not needed for a linear project like this.

**PostgreSQL ENUM types**
```python
scan_type_enum = sa.Enum("port", "vuln", "web", "full", name="scan_type_enum")
```
PostgreSQL stores ENUMs as a named type in the database, not just a column constraint. This is why `downgrade()` must explicitly drop the ENUM types after dropping the table — they exist independently in the DB and won't be cleaned up automatically.

**`server_default` in the migration**
```python
sa.Column("scan_type", scan_type_enum, nullable=False, server_default="port"),
sa.Column("started_at", sa.DateTime(), nullable=False, server_default=sa.func.now()),
```
`server_default` runs at the PostgreSQL level — the DB itself fills in the value if no value is provided. This matters for rows inserted via raw SQL (e.g. `psql`) that bypass the Python ORM.

## `tests/test_db_connection.py` — key details

**`sys.path.insert` + `load_dotenv()`**
```python
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "backend"))
load_dotenv()
```
The test lives in `tests/` but needs to import from `backend/`. The `sys.path.insert` adds `backend/` to the path. `load_dotenv()` reads `.env` into `os.environ` before the DB modules are imported (they read `DATABASE_URL` at import time).

**`await session.refresh(scan)`**
After `session.commit()`, the session expires the object. `refresh()` re-fetches the row from the DB so we can read the auto-generated `id` and `started_at` that PostgreSQL filled in.

**`await engine.dispose()`**
Closes all connections in the async connection pool cleanly. Without this, the script would hang after finishing because asyncpg keeps background connections open.

**`row._mapping`**
SQLAlchemy 2.0 result rows aren't plain dicts. `row._mapping` converts a row to a dict-like view so `dict(row._mapping)` gives a readable `{column: value}` output.

## Key concepts learned

**ORM (SQLAlchemy)**
- ORM = Object Relational Mapper. You define Python classes; SQLAlchemy generates SQL.
- `class Scan(Base)` → becomes the `scans` table in PostgreSQL.
- `session.add(scan)` → `INSERT INTO scans ...`
- `session.execute(text("SELECT ..."))` → raw SQL when needed.

**Async engine vs sync engine**
- Runtime (FastAPI routes): uses `create_async_engine` + `asyncpg` — non-blocking, fits the async server.
- Migrations (Alembic): uses a sync `create_engine` + `psycopg2` — Alembic's internals are synchronous, so we need the sync driver here only.

**`get_db()` dependency**
- A FastAPI dependency that opens a DB session per request, commits on success, rolls back on exception, and closes automatically.
- Usage in a route: `db: AsyncSession = Depends(get_db)` — FastAPI injects it automatically.

**Alembic migrations**
- A migration is a versioned Python script that changes the DB schema.
- `alembic upgrade head` — applies all pending migrations in order.
- `alembic downgrade -1` — rolls back the last migration.
- Alembic stores applied migration IDs in the `alembic_version` table in your DB — it never applies the same migration twice.
- Each migration has `upgrade()` (apply) and `downgrade()` (undo).

**`DATABASE_URL` format**
| Context | URL format |
|---|---|
| Python runtime (asyncpg) | `postgresql+asyncpg://user:pass@host:port/db` |
| Alembic migrations (psycopg2) | `postgresql://user:pass@host:port/db` |
| Host machine → Docker | host = `localhost` |
| Container → Container | host = `db` (Docker service name) |

## Scans table schema (migration `1dce0a522bd6`)
```
scans
├── id              VARCHAR(36)    UUID, primary key
├── target_ip       VARCHAR(255)   required — IP address being scanned
├── target_hostname VARCHAR(255)   optional — resolved hostname
├── scan_type       ENUM           port | vuln | web | full
├── status          ENUM           queued | running | completed | failed
├── started_at      TIMESTAMP      auto-set to now() on insert
├── completed_at    TIMESTAMP      null until scan finishes
└── options         JSON           flexible config — port range, flags, etc.

Indexes:
  ix_scans_target_ip   — fast lookup by IP
  ix_scans_started_at  — fast sorting/filtering by date
```

## How to run
```bash
# 1. Start PostgreSQL in Docker
docker-compose up -d db

# 2. Activate venv
source venv/bin/activate

# 3. Run the migration — creates the scans table
cd backend
alembic upgrade head

# 4. Confirm the table was created
docker exec -it cyberscanner_db psql -U cyberscanner -d cyberscanner -c "\dt"
# Should show: scans

# 5. Run the connection test
cd ..
python tests/test_db_connection.py

# Expected output:
# Testing PostgreSQL connection...
#   Connected! PostgreSQL version: PostgreSQL 16.x ...
# Inserting a test scan record...
#   Inserted scan: <Scan id=... target=127.0.0.1 status=queued>
# Reading it back...
#   Row: {'id': '...', 'target_ip': '127.0.0.1', 'status': 'queued'}
# All checks passed!
```
