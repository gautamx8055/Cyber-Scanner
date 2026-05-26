# Task 4.2 — Live NVD API, CVSS Scoring, Rich Output

## What was built
The online half of the vulnerability engine plus the presentation layer:
- **Live NVD lookups** against the NIST NVD 2.0 REST API (opt-in via `--nvd`).
- **CVSS severity scoring** — map a base score to Critical / High / Medium /
  Low / None.
- **Colored Rich table** rendering of findings, sorted worst-first.

## Files created / modified
- **modified** `backend/scanner/vuln_scanner.py`:
  - `severity_from_score(score)` — CVSS band from base score
  - `query_nvd(product, version)` — one keyword query to NVD 2.0
  - `_keyword_version()` — clean a banner version for NVD's keyword index
  - `_nvd_score(metrics)` — pull base score + severity (v3.1 → v3.0 → v2)
  - `scan_nvd(port_results)` — query NVD per distinct service, rate-limited
  - `render_vuln_table(target, findings)` — colored, severity-sorted output

## Key concepts

### CVSS severity bands (CVSS v3)
| Score | Severity |
|------:|----------|
| 9.0–10.0 | Critical |
| 7.0–8.9  | High |
| 4.0–6.9  | Medium |
| 0.1–3.9  | Low |
| 0.0 / unknown | None / Unknown |

### Querying NVD
`GET https://services.nvd.nist.gov/rest/json/cves/2.0?keywordSearch=<product version>`.
The response's `metrics` block can carry CVSS v3.1, v3.0, and/or v2 — we prefer
the newest available and derive the band ourselves for v2 (which predates
qualitative ratings).

Two gotchas handled:
- **Patch suffixes**: NVD's keyword index doesn't recognise `7.6p1`/`1.0.1f`,
  so `_keyword_version()` reduces the version to its leading numeric form
  (`7.6`, `1.0.1`) for the search. The full detected version is still what we
  display and store.
- **Rate limits**: anonymous callers get ~5 requests / 30s. `scan_nvd` queries
  one distinct `(product, version)` at a time and sleeps ~6s between them. Set
  `NVD_API_KEY` in the environment to raise the limit. NVD keyword search is
  fuzzy, so its hits are *candidates*, not confirmed matches (a finding's
  `Src` column shows `local` vs `nvd`).

### Rendering
`render_vuln_table` sorts by severity (worst first), then score, then port, and
colors the severity column (Critical = bold red … Low = cyan). A one-line
summary tallies counts per severity.

## How to test
```bash
# scoring + a live query
docker-compose exec backend python -c "
import asyncio
from scanner.vuln_scanner import severity_from_score, query_nvd
print([severity_from_score(s) for s in (9.8, 7.5, 5.3, 2.0, None)])
print(asyncio.run(query_nvd('OpenSSH', '7.6', results_per_page=3))[0])
"
```
