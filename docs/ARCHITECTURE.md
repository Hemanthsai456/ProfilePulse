# ProfilePulse Architecture

ProfilePulse is a privacy-first microservice providing verifiable badge analytics for GitHub README embeds.

## 1. Request Flow

```
Visitor Browser
      │
      ▼
GitHub README (camo.githubusercontent.com)
      │ (or direct HTTP/curl)
      ▼
ProfilePulse (/badge/{username})
      │
      ├── 1. Validate Username (strict alphanumeric + single hyphens, 1-39 chars)
      ├── 2. Extract Client IP (honoring X-Forwarded-For ONLY if TRUST_PROXY=true)
      ├── 3. In-Memory Sliding Window Rate Limiting (per-client IP, 60 req/min)
      ├── 4. GitHub User Verification (cached 24h for 200, 1h for 404, fail-open on errors)
      ├── 5. Generate Visitor Key (keyed HMAC-SHA256 of the normalized viewer IP; stable, not daily)
      ├── 6. Categorize Client (github-camo, browser, script, other — no raw UA stored)
      ├── 7. Deduplication (PostgreSQL, atomic statements)
      │         ├── burst check: a counted load of the same profile and client type within
      │         │   PROFILEPULSE_BURST_SECONDS (default 60) is one page load, not a new visitor
      │         ├── visitor_seen (username, visitor_key, via_camo): counted again only after
      │         │   PROFILEPULSE_DEDUPE_DAYS (default 30) since last_counted
      │         └── active_windows (username, window_id, via_camo)
      ├── 8. Update O(1) Pre-Aggregated Totals (user_totals, daily_stats)
      └── 9. Render Sanitized SVG Badge (strict CSP & cache-control headers)
```

## 2. Camo Proxy Verification

GitHub README images are fetched through GitHub's Camo proxy (`camo.githubusercontent.com`).
- ProfilePulse classifies requests by client category:
  - **`github-camo`**: User-Agent contains `github-camo`. Primary badge metrics count these views.
  - **`browser` / `script` / `other`**: Direct requests from browsers or tools like curl. Counted separately and excluded from default production badges to prevent trivial count inflation.
- **Privacy Guard**: Raw User-Agent strings are never stored. Only the coarse category string is persisted in PostgreSQL.

## 3. Database Tables (PostgreSQL with psycopg v3)

- **`user_totals`**: Fast $O(1)$ read table storing cumulative camo and direct unique/load/window counters per username.
- **`daily_stats`**: Aggregate daily counters per `(username, day)`. Retained indefinitely.
- **`visitor_seen`**: Visitor dedupe table with primary key `(username, visitor_key, via_camo)` and `last_counted`. A visitor is counted again only after `PROFILEPULSE_DEDUPE_DAYS`. Rows older than that are deleted, so visitor hashes are not kept longer than needed.
- **`daily_uniques`**: Legacy table from the daily-key design. No longer written. Existing rows are kept and pruned after 30 days. Planned for removal once no one needs the history.
- **`active_windows`**: Deduplication table for 30-minute time blocks `(username, window_id, via_camo)`. Pruned after 30 days.
- **`hits`**: Telemetry log storing timestamp (`DOUBLE PRECISION`), IST timestamp (`ts_ist`), day, username, visitor hash, coarse client category, camo flag, conditional flag, unique flag, burst-collapse flag, X-Forwarded-For entry count (`xff_count`), and IP version (`ip_version`). Never stores raw IPs. Pruned after 30 days.

## 4. Rate Limiting & Griefing Defense

- **Client-Keyed**: Rate limits are enforced per client IP, never per victim username. An attacker flooding `/badge/victim` exhausts only their own quota without blocking genuine visitors.
- **Preview Enforced**: Requests with `preview=true` are tracked by the rate limiter to prevent uncounted endpoint flooding.
- **Proxy Spoofing Defense**: `X-Forwarded-For` is ignored unless `PROFILEPULSE_TRUST_PROXY=true` is explicitly set behind a trusted reverse proxy.

