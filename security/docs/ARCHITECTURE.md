# Project ARGUS (Cyber Trace) — architecture reference

This is a working reference implementation of all 9 layers from the
project README, split into the folders the repo already declares. It's
built to be extended, not shipped as-is — see "Before production" below.

## Layer → file map

| # | Layer                  | File(s) |
|---|-------------------------|---------|
| 1 | Data collection         | `collectors/collector.py`, `collectors/sample_agent.py` |
| 2 | Processing              | `detection_engine/processing.py` |
| 3 | Detection engine        | `detection_engine/detection.py` |
| 4 | Threat intelligence     | `detection_engine/threat_intel.py` |
| 5 | Correlation engine      | `detection_engine/correlation.py` |
| 6 | Risk assessment         | `detection_engine/risk.py` |
| 7 | Backend API             | `backend/app.py`, `backend/config.py`, `backend/auth.py` |
| 8 | Database                | `database/db.py` |
| 9 | Frontend dashboard      | not included — consumes this API |

`detection_engine/pipeline.py` orchestrates layers 2–6 for a single
incoming event; `backend/app.py` calls it once per request to `/api/events`.

## Data flow

1. A collector (or `curl`, for testing) `POST`s a raw JSON event to `/api/events`.
2. `collectors/collector.py` stores the untouched raw payload.
3. `detection_engine/processing.py` normalizes it into a common schema.
4. `detection_engine/threat_intel.py` checks it against known-bad indicators.
5. `detection_engine/detection.py` runs rule checks (brute force, IOC match, etc).
6. If any rule fired, `detection_engine/correlation.py` groups it with related
   recent events from the same user/IP.
7. `detection_engine/risk.py` scores the resulting incident 0–100 and saves it.
8. The frontend (not included) reads `/api/incidents` to display results.

## Running it

```bash
pip install -r requirements.txt
cp .env.example .env   # already has the variables this code reads
python -m backend.app
```

## Testing it

```bash
curl http://localhost:5000/api/health

# Normal event, no alert expected
curl -X POST http://localhost:5000/api/events \
  -H "Content-Type: application/json" -H "X-API-Key: dev-api-key" \
  -d '{"type":"login","user":"alice","src_ip":"10.0.0.5","severity":"low"}'

# Known-malicious-IP rule (demo IOC list in threat_intel.py)
curl -X POST http://localhost:5000/api/events \
  -H "Content-Type: application/json" -H "X-API-Key: dev-api-key" \
  -d '{"type":"connection","user":"carol","src_ip":"45.83.64.1","severity":"high"}'

curl http://localhost:5000/api/incidents -H "X-API-Key: dev-api-key"
```

## Auth model

Two separate models, because collectors and humans have different needs:

- **Collectors** (`POST /api/events`) use the shared `X-API-Key` header —
  machines don't have passwords.
- **Analysts/admins** (dashboard-facing GET/DELETE routes) use real
  accounts: `POST /api/auth/register` then `POST /api/auth/login` to get
  a JWT, sent as `Authorization: Bearer <token>` on every request.
  `require_auth` checks the token is valid; `require_role("admin")`
  additionally checks the role claim — see `delete_incident()` in
  `backend/app.py` for the pattern to copy for new protected routes.

Registration is open only while the `users` table is empty (the first
account created becomes the bootstrap admin). Every registration after
that requires an existing admin's token.

## Before production

These are flagged inline with `TODO` comments in the relevant files too:

- **Threat intel** (`detection_engine/threat_intel.py`): static demo IP
  list. Needs a real feed integration using `THREAT_INTELLIGENCE_API_KEY`,
  plus caching so it's not hit on every event.
- **Database** (`database/db.py`): SQLite is fine for development and
  testing. For production event volume, split high-volume raw/normalized
  events into something built for it (Elasticsearch, TimescaleDB) and
  keep only incidents/users/config in a relational store.
- **Secrets**: `.env` works for local dev. Production should pull
  `SECRET_KEY`, `API_KEY`, and `THREAT_INTELLIGENCE_API_KEY` from a
  secrets manager, not a committed file.
- **No rate limiting, no HTTPS termination** — both expected to be
  handled at the deployment layer (reverse proxy / API gateway), not
  in this code.
- **Correlation window and risk weights** (`correlation.py`,
  `risk.py`) are starting values — tune against real incident data.
- **Folder naming**: this code uses `detection_engine` (underscore).
  Python can't import a package named `detection-engine` (hyphen) — if
  the repo's existing folder uses a hyphen, rename it with
  `git mv detection-engine detection_engine` (not a plain `mv`, so the
  history is preserved as a rename) before merging.
- **JWT secret rotation**: tokens are signed with `SECRET_KEY`. Rotating
  it invalidates every issued token immediately — fine for dev, needs a
  planned rollout for production (e.g. rotate during a maintenance
  window, or support two active keys briefly).
