# Task 2.3 — argparse CLI, Port Spec Parsing, Baseline Timing

## What was built
A CLI entry point for the scanner, a flexible port-specification parser,
and a timing harness that records how long the synchronous scan takes —
the baseline we'll beat in Phase 3 with `asyncio`.

## Files created / modified
- **new** `backend/cli.py`
  - `parse_ports(spec)` — single / range / list / mixed → `list[int]`
  - `cmd_ports(args)` — runs the scan, renders, persists
  - `build_parser()` — argparse setup with `ports` subcommand
  - `main(argv)` — entrypoint

## Key concepts

### argparse in one minute
`argparse` turns a positional/optional spec into a parser that validates
user input, auto-generates `--help`, and returns a `Namespace` object.
The pattern used here:

```python
parser = argparse.ArgumentParser(prog="cyberscan")
sub = parser.add_subparsers(required=True)
ports = sub.add_parser("ports")
ports.add_argument("target")              # positional
ports.add_argument("-p", "--ports", ...)  # optional
ports.add_argument("--timeout", type=float, ...)
ports.set_defaults(func=cmd_ports)        # dispatch
```

### Port spec grammar
| Form | Example | Expanded |
|---|---|---|
| single | `80` | `[80]` |
| range | `1-1000` | `[1, 2, ..., 1000]` |
| list | `80,443,8080` | `[80, 443, 8080]` |
| mixed | `22,80,8000-8100` | `[22, 80, 8000, ..., 8100]` |

Implementation: split on `,`, expand each chunk, union into a `set`,
return sorted. Out-of-range values (e.g. `0`, `70000`, reversed ranges)
raise `ValueError`, which the CLI translates into a clean error message.

### Timing measurement
Wall-clock timing comes from `time.perf_counter()` — the highest
resolution monotonic clock Python exposes. Sampled **once** before and
once after the scan. A first measurement run on localhost (7 ports, 2
open, 0.5s timeout) took ~4.0s — the open-port banner-grab timeout
dominates. Scale that to 1,000 ports on a real host and you get the
motivation for Phase 3.

## How to run

```bash
cd backend

# single port
python -m cli ports 127.0.0.1 -p 5432

# range
python -m cli ports 127.0.0.1 -p 1-1000 --timeout 0.5

# list
python -m cli ports 127.0.0.1 -p 22,80,443,5432,8000,8080

# mixed; show closed ports too; skip DB save
python -m cli ports 127.0.0.1 -p 22,80,8000-8100 --show-closed --no-save

# help
python -m cli ports -h
```

## CLI flags

| Flag | Default | Purpose |
|---|---|---|
| `target` (positional) | — | IP or hostname |
| `-p`, `--ports` | `1-1000` | ports to scan (see grammar above) |
| `--timeout` | `1.0` | per-port connect timeout (seconds) |
| `--show-closed` | off | include closed/filtered rows in the table |
| `--no-save` | off | skip the PostgreSQL insert |
