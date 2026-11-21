# Changelog

All notable changes to ProfilePulse will be documented in this file.

## [0.5.0] - 2026-11-18

### Counting
- **Rolling dedupe period**: A visitor is counted once per `PROFILEPULSE_DEDUPE_DAYS` (default 30), not once per day. Repeat visits no longer add to the count.
- **Stable keyed visitor hash**: Visitors are identified by HMAC-SHA256 of the viewer IP. The hash no longer changes daily. Raw IPs are never stored.
- **Burst collapse**: Double loads of the same profile by the same client type within `PROFILEPULSE_BURST_SECONDS` (default 60) count as one visit.
- **IPv6 grouping**: IPv6 viewer addresses are grouped by /64 prefix, so one connection keeps one visitor key.
- **Honest labels**: Default badge labels are "Visitors (est.)", "Visitors Today (est.)", and "Unique Visitors (est.)". `?label=` still overrides them.

### Reporting & Diagnostics
- `/report` shows `dedupe_days`, `trust_proxy`, `viewer_identity`, `today_definition`, and `burst_collapses`.
- `hits` records `xff_count` and `ip_version` (counts and IP version only, never the IP).
- Startup warning when `PROFILEPULSE_TRUST_PROXY` is off, since viewers cannot be told apart and counts are undercounted.

### Database
- New `visitor_seen` table. Migrations are non-destructive (`ADD COLUMN IF NOT EXISTS`); existing rows are kept.
- `daily_uniques` is no longer written. It is kept for history and planned for removal.

### Docs
- Calibration protocol in `docs/CALIBRATION.md`.
- `ARCHITECTURE.md` updated for PostgreSQL and the new dedupe design.

## [0.4.0] - 2026-11-18

### Time Zone (IST)
- **IST daily reset**: Daily counters and visitor keys roll over at 00:00 IST (+05:30), not UTC midnight.
- **IST timestamps**: Added `ts_ist`, `first_seen_ist`, and `updated_at_ist` columns (backfilled from existing rows). `/report` shows `timezone` and `last_updated_ist`.

## [0.3.0] - 2026-11-08

### Database Migration & Production Deployment
- **PostgreSQL Migration (`psycopg` v3)**: Replaced SQLite with PostgreSQL using `psycopg` (v3). Schema updated to use `BIGSERIAL`, PostgreSQL parameter placeholders (`%s`), `INSERT ... ON CONFLICT DO NOTHING`, and atomic upserts with `EXCLUDED.` syntax.
- **Connection Masking**: Added credential masking for database URLs in logs and `/health` degradation messages to prevent credential leakage.
- **Render & PostgreSQL/Supabase Support**: Added `render.yaml` Blueprint specification for deploying the Docker container on Render with environment variable configurations (`DATABASE_URL`, auto-generated `PROFILEPULSE_SECRET`, `PROFILEPULSE_TRUST_PROXY`).
- **Proxy Client IP Detection**: Configured `get_client_ip` to inspect the trailing IP in `X-Forwarded-For` when `PROFILEPULSE_TRUST_PROXY=true`, correctly identifying client IPs behind Render's reverse proxy while protecting against client header spoofing.
- **Test Isolation**: Updated test suite to strictly require `TEST_DATABASE_URL` (dropping and recreating tables before each test), preventing test execution against production `DATABASE_URL` and skipping database tests cleanly when `TEST_DATABASE_URL` is omitted.
- **Local Dev Compose**: Added a `postgres:16-alpine` service to `docker-compose.yml` with persistent volume `postgres_data`.

## [0.2.1] - 2026-11-08

### Security & Privacy
- **Privacy fix (Zero PII Guarantee)**: Stopped storing raw `User-Agent` strings in the `hits` table. Stored only coarse client categories (`github-camo`, `browser`, `script`, `other`). Removed `top_user_agents` raw strings from `/report/{username}` and updated `/privacy` endpoint to accurately reflect stored telemetry.
- **Strict Username Validation**: Updated `USERNAME_RE` with `\A...\Z` string boundary anchors. Added explicit rejection of leading/trailing hyphens, newlines, and consecutive hyphens (`--`), strictly enforcing GitHub's 1-39 character naming constraints.
- **Client-Keyed Anti-Griefing Rate Limiter**: Refactored `rate_limited` to key by client identity (IP address) rather than target profile username, preventing badge denial-of-service/griefing attacks against victims. Applied rate limiting to `preview=true` requests to prevent spam. Added `PROFILEPULSE_TRUST_PROXY` configuration to prevent `X-Forwarded-For` spoofing.
- **Production Secret Validation**: Extracted secret validation into `validate_secret(env, secret)` called at startup. Explicitly blacklisted both `"dev-secret-change-me"` and the docker-compose default `"local-dev-secret-key-32chars"`, enforcing a minimum of 16 characters in production mode.
- **SVG Injection Hardening**: Confirmed `sanitize_color` and `render_svg` safely reject tag/quote breakout vectors (`red"/><script>`, `blue" onload="..."`) and escape custom labels into valid XML.

### Reliability & Resilience
- **GitHub Verification Resilience & Caching**: Validated `check_github_user_exists` cache TTLs (24h for valid, 1h for 404) and confirmed fail-open behavior on GitHub API 403 rate limits, 5xx server errors, and network timeouts.
- **Retention Pruning Boundary Integrity**: Verified that `prune_old_records` deletes records older than 30 days across `hits`, `daily_uniques`, and `active_windows`, preserves records within the 30-day window (e.g. 25 days old), and never alters `user_totals` or `daily_stats` aggregate tables.
- **Degraded Health Probe**: Verified `/health` reports `status: "degraded"` when database connectivity fails.
- **Atomic Concurrency Deduplication**: Configured SQLite connection timeout and verified under multi-threaded concurrency (20 simultaneous requests) that exactly one unique visitor is recorded without deadlocks.

