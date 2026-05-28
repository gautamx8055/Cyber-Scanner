# Task 6.4 — Docker Compose: Backend Health Check + Service Networking

## What was built
Phase 6.4 finishes the multi-container story: the `backend` service that ran
since Task 6.3 now has its own **health check**, and container networking is
explicit — both services share a named bridge, and the backend talks to
PostgreSQL by service name (`db`).

### Compose diagram
```
            ┌─────────────────── cyberscanner_net ───────────────────┐
            │                                                          │
host:8000 ──┼──► backend (FastAPI) ──── DATABASE_URL=…@db:5432/… ──►   │
            │   healthcheck: GET /health (urllib)                       │
            │                                                          │
host:5432 ──┼──► db (postgres:16)                                       │
            │   healthcheck: pg_isready                                 │
            └──────────────────────────────────────────────────────────┘
```

### Files modified
- **`docker-compose.yml`**
  - Added a `healthcheck` to the `backend` service. The test runs
    `python -c "import urllib.request,sys; sys.exit(0 if urllib.request.urlopen('http://localhost:8000/health', timeout=2).status == 200 else 1)"`.
    `urllib` ships with `python:3.12-slim`, so no extra `apt` package is
    needed (avoids bloating the image with `curl` or `wget`).
  - Tuned: `interval: 10s`, `timeout: 5s`, `retries: 5`, `start_period: 15s` —
    `start_period` is the grace window during which failures don't count, so
    uvicorn's startup doesn't look like a flaky service.
  - Added a top-level `networks: default: { name: cyberscanner_net }` so the
    bridge has a stable, scoped name instead of `<projectdir>_default`.
  - Documented why `DATABASE_URL` uses host `db:5432` (not `localhost`): Docker
    Compose's built-in DNS resolves the service name on the user-defined
    bridge network. The `5432:5432` host mapping is for the host machine; the
    backend reaches the DB **inside** the network, where mapped ports don't
    apply.
## Key concepts
- **`depends_on: condition: service_healthy`**: makes the backend wait until
  the db's `pg_isready` check passes before starting — already in place from
  Phase 1, just called out here.
- **Container DNS**: in Docker Compose, every service on the same network is
  reachable by its service name. Hard-coding `db:5432` is correct for
  in-network traffic; the host port mapping is a separate plane for traffic
  originating outside the network.
- **Health check vs liveness vs readiness**: Compose's health check is a
  single boolean per service. It feeds two things: (a) `docker ps` status,
  and (b) downstream services using `depends_on: condition: service_healthy`.
  Kubernetes splits these into liveness and readiness probes; here we have
  the one check.
- **`start_period`**: protects long startups (DB connection pool warm-up,
  Alembic-style migrations). Failures during this window don't count toward
  `retries` — without it, a slow first boot could mark the service unhealthy
  and trigger restarts.

## How to run / test
```bash
docker compose up -d --build
docker compose ps                # both services should show "healthy"
docker inspect cyberscanner_backend --format '{{.State.Health.Status}}'
# trigger from inside the network
docker compose exec backend python -c \
  "import urllib.request; print(urllib.request.urlopen('http://localhost:8000/health').read())"
```

## Testing status
- `docker compose config` validates cleanly with the new health check and
  network block.
- Host has Docker Desktop installed but the daemon wasn't running during this
  session — runtime verification of the live health check should be done the
  next time the user starts Docker; the check itself is standard urllib and
  has no project-specific assumptions.

Remaining: Phase 7 (Report Engine — JSON/CSV/HTML/PDF export) lands in the
same commit as this task.
