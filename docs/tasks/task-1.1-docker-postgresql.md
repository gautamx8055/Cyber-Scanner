# Task 1.1 — Docker + PostgreSQL Setup

## What was built
Set up the full Docker development environment with a PostgreSQL 16 database container and a backend container skeleton.

## Files created / modified
| File | Purpose |
|---|---|
| `docker-compose.yml` | Defines the `db` (PostgreSQL) and `backend` (FastAPI) services |
| `docker/backend.Dockerfile` | Builds the Python 3.12 backend image, installs all requirements |
| `.env` | Local secrets — DB credentials, DATABASE_URL, SECRET_KEY (never commit) |
| `.env.example` | Template showing all required env vars (safe to commit) |
| `.gitignore` | Prevents `.env`, `venv/`, `__pycache__/`, etc. from being committed |

## Env vars defined (in `.env`)
| Variable | Value | Used by |
|---|---|---|
| `POSTGRES_USER` | `cyberscanner` | PostgreSQL container, SQLAlchemy |
| `POSTGRES_PASSWORD` | `cyberscanner123` | PostgreSQL container, SQLAlchemy |
| `POSTGRES_DB` | `cyberscanner` | PostgreSQL container, SQLAlchemy |
| `DATABASE_URL` | `postgresql+asyncpg://cyberscanner:cyberscanner123@localhost:5432/cyberscanner` | Python backend |
| `SECRET_KEY` | `dev-secret-key-replace-in-prod` | FastAPI (future auth) |
| `DEBUG` | `true` | FastAPI |

## docker-compose.yml — service breakdown

### `db` service (PostgreSQL 16)
- `image: postgres:16` — pulls the official PostgreSQL 16 image from Docker Hub
- `ports: 5432:5432` — exposes PostgreSQL on your machine at port 5432
- `volumes: postgres_data:/var/lib/postgresql/data` — persists DB data across restarts
- `healthcheck` — runs `pg_isready` every 5s, up to 10 retries before giving up
- `restart: unless-stopped` — auto-restarts if it crashes, but not if you manually stop it

### `backend` service (FastAPI)
- `build: docker/backend.Dockerfile` — builds the image from our Dockerfile
- `ports: 8000:8000` — exposes FastAPI on your machine at port 8000
- `volumes: ./backend:/app` — mounts your local `backend/` folder inside the container (live reload in dev — code changes take effect without rebuilding)
- `depends_on: db: condition: service_healthy` — waits for PostgreSQL health check to pass before starting
- `environment: DATABASE_URL` — overrides the `.env` value to use `@db:5432` (Docker internal hostname) instead of `@localhost:5432`

## Key concepts learned

**Image vs Container**
- An *image* is the blueprint (e.g. `postgres:16` downloaded from Docker Hub).
- A *container* is a running instance of that image — like a process spawned from that blueprint.

**`docker-compose up`**
- Reads `docker-compose.yml`, pulls/builds images, starts all defined services together.
- `docker-compose up -d` runs them in the background (detached mode).

**Health check**
- The `db` container runs `pg_isready -U cyberscanner -d cyberscanner` every 5 seconds.
- The backend only starts after this command returns success — prevents "connection refused" errors on startup.

**Named volumes**
- `postgres_data` is a named Docker volume managed by Docker (not a folder on your disk).
- Data persists even if the container is stopped or removed. Only `docker volume rm` deletes it.

**Container networking**
- Containers in the same `docker-compose.yml` can reach each other by **service name**.
- The backend connects to PostgreSQL at `db:5432` — `db` resolves to the container's internal IP automatically.
- `localhost:5432` only works from your machine (host), not from inside another container.

**`restart: unless-stopped`**
- Container restarts automatically if it crashes or the machine reboots.
- Does NOT restart if you manually run `docker-compose stop` or `docker stop`.

## How to run
```bash
# Start all services in background
docker-compose up -d

# Check containers are running
docker ps

# Check PostgreSQL logs
docker logs cyberscanner_db

# Connect to PostgreSQL manually (psql shell inside the container)
docker exec -it cyberscanner_db psql -U cyberscanner -d cyberscanner

# Stop all services (keeps data)
docker-compose stop

# Stop and delete containers (keeps volume data)
docker-compose down

# Stop and delete everything including DB data
docker-compose down -v
```
