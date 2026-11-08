# ProfilePulse

ProfilePulse provides honest, privacy-first analytics badges for GitHub profile README embeds by tracking GitHub Camo proxy requests and direct requests. Because static image badges cannot verify actual profile page visits, all counts represent estimated proxy loads and unique request fingerprints rather than guaranteed human views.

---

## 🚀 Quick Start

### With Docker (Recommended)
```bash
docker compose up -d
```
Starts PostgreSQL and the ProfilePulse application service at `http://localhost:8000`.

### Without Docker
```bash
python -m venv .venv
source .venv/bin/activate  # On Windows: .venv\Scripts\activate
pip install -r requirements.txt
export DATABASE_URL="postgresql://postgres:password@localhost:5432/profilepulse"
uvicorn app.main:app --host 0.0.0.0 --port 8000
```

---

## 🏷️ Using the Badge

Embed the badge in your GitHub README using your deployed host:

**Markdown:**
```markdown
[![Profile Views](https://YOUR-HOST/badge/YOUR_GITHUB_USERNAME)](https://YOUR-HOST/report/YOUR_GITHUB_USERNAME)
```

**HTML:**
```html
<img src="https://YOUR-HOST/badge/YOUR_GITHUB_USERNAME" alt="Profile Views" />
```

### Query Parameters

| Parameter | Options / Format | Description |
|---|---|---|
| `metric` | `unique` (default), `today`, `loads`, `windows` | Metric to display: total uniques, today's uniques, badge loads, or active 30-min windows. |
| `view` | `split`, standard (default) | `split` displays both today and total counts (`X today · Y total`). |
| `label` | String (e.g. `Views`) | Custom label on the left side of the badge. |
| `color` | Hex (`4c1`, `#0969da`) or name (`blue`, `green`, `orange`) | Custom color for the right side of the badge. |
| `source` | `camo` (default), `all`, `direct` | Traffic source filter. In production, default `camo` counts only GitHub proxy hits. |
| `preview` | `true`, `false` (default) | Renders the badge without incrementing or recording hits (alias: `ignore_owner`). |

---

## ⚙️ Configuration

Configure via environment variables or a `.env` file:

| Variable | Default | Description |
|---|---|---|
| `DATABASE_URL` | *Required* | PostgreSQL connection string (production Neon or local container). |
| `TEST_DATABASE_URL` | *None* | Dedicated PostgreSQL test database URL used strictly by the test suite. |
| `PROFILEPULSE_ENV` | `development` | Mode: `development` or `production`. In production, secure secret checks are enforced. |
| `PROFILEPULSE_SECRET` | `dev-secret-change-me` | Secret for HMAC hashing visitor fingerprints. Must be a secure 16+ char key in production. |
| `PROFILEPULSE_RATE_LIMIT` | `60` | Maximum requests per minute per client IP before rate limiting. |
| `PROFILEPULSE_WINDOW_SECONDS` | `1800` | Duration in seconds for an active window block (default: 30 minutes). |
| `PROFILEPULSE_RETENTION_DAYS` | `30` | Retention period in days for raw hit logs before automatic pruning. |
| `PROFILEPULSE_TRUST_PROXY` | `false` | When `true`, honors `X-Forwarded-For`. Set `true` only behind trusted reverse proxies (e.g. Render). |
| `PROFILEPULSE_VALIDATE_GITHUB_USER` | `true` | Validates GitHub username existence before tracking hits. |
| `GITHUB_TOKEN` | `""` | Optional token to raise GitHub user check API limits from 60 to 5,000 req/hr. |

---

## 🔒 Privacy

ProfilePulse adheres to strict privacy guarantees matching `/privacy`:
- **Zero Raw PII**: Neither raw IP addresses nor raw User-Agent strings are stored. Only coarse categories (`github-camo`, `browser`, `script`, `other`) are saved.
- **Daily Key Rotation**: Visitor fingerprints use HMAC-SHA256 salted with the UTC date string (`HMAC(SECRET, day|ip|ua)`), rotating every 24 hours to prevent cross-day tracking.
- **Strict 30-Day Retention**: Raw telemetry and visitor keys are purged after 30 days. Only aggregate counters are kept.
- **Zero Cookies**: Sets no tracking cookies and makes no cross-site calls.

---

## ⚠️ Limitations

- **Estimates Only**: Static image embeds cannot observe viewport visibility or tab focus; counts reflect observed requests.
- **Camo Caching**: GitHub's Camo proxy caches images for variable intervals, which may coalesce rapid visits into fewer requests.
- **In-Memory Rate Limiting**: The sliding-window rate limiter is stored in-memory per process; it resets on restarts and does not coordinate across multi-worker deployments.
- **Free Tier Cold Starts & Database Pauses**: Render's free tier sleeps after 15 minutes of inactivity, and Neon's free compute pauses when idle. Keep-warm pinging (e.g. via UptimeRobot every 5 minutes on `/health`) prevents cold starts.
- **Reverse Proxy Headers**: `PROFILEPULSE_TRUST_PROXY` must be set to `true` when deployed behind Render or other reverse proxies so that client IPs are extracted safely.

---

## 🛠️ Development

Run test suite:
```bash
pytest
```

Run linter:
```bash
ruff check .
```

---

## 📄 License

This project is licensed under the terms of the [MIT License](LICENSE).
