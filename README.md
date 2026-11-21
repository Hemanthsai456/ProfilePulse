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
| `metric` | `both` (default), `unique`, `today`, `loads`, `windows` | Metric to display: both (unique views on left & total visits on right), unique (all-time), today, badge loads, or active windows. |
| `view` | `split`, standard (default) | `split` displays both today and total counts (`X today · Y total`). |
| `label` | String (e.g. `Views`) | Custom label on the left side of the badge. |
| `color` | Hex (`4c1`, `#0969da`) or name (`blue`, `green`, `orange`) | Custom color for the main/left counter (default: green `#2ea043`). |
| `label_color` | Hex (`2ea043`, `#555`) or name (`green`, `blue`) | Custom color for the left label (default: grey `#555555`, alias: `labelColor`). |
| `label2_color`| Hex or name | Custom color for the right label in dual and split badges (defaults to `label_color`). |
| `color2`      | Hex or name | Custom color for the right counter in dual and split badges (defaults to `color`). |
| `source` | `camo` (default), `all`, `direct` | Traffic source filter. In production, default `camo` counts only GitHub proxy hits. |
| `preview` | `true`, `false` (default) | Renders the badge without incrementing or recording hits (alias: `ignore_owner`). |

### 🎨 Badge Variations & Examples

Select and copy any variation below directly into your GitHub profile `README.md` (replace `YOUR-HOST` and `YOUR_GITHUB_USERNAME`):

#### 1. Unique Views & Total Visits (Default)
Displays unique views on the left and total visits on the right (`X unique views | Y total visits`):
```markdown
[![Profile Views](https://YOUR-HOST/badge/YOUR_GITHUB_USERNAME)](https://YOUR-HOST/report/YOUR_GITHUB_USERNAME)
```

#### 2. Standalone Unique Visitors
Displays estimated all-time unique visitors on the right (`Unique Visitors (est.) | X`):
```markdown
[![Unique Visitors](https://YOUR-HOST/badge/YOUR_GITHUB_USERNAME/unique)](https://YOUR-HOST/report/YOUR_GITHUB_USERNAME)
```
*(Also available via query parameter: `https://YOUR-HOST/badge/YOUR_GITHUB_USERNAME?metric=unique`)*

#### 3. Today's Visitors
Displays unique visitors for the current day (resets at 00:00 IST):
```markdown
[![Visitors Today](https://YOUR-HOST/badge/YOUR_GITHUB_USERNAME?metric=today)](https://YOUR-HOST/report/YOUR_GITHUB_USERNAME)
```

#### 4. Split View (Today · Total)
Displays both today's visitors and all-time total within a single badge (`X today · Y total`):
```markdown
[![Profile Views](https://YOUR-HOST/badge/YOUR_GITHUB_USERNAME?view=split)](https://YOUR-HOST/report/YOUR_GITHUB_USERNAME)
```

#### 5. Total Badge Loads (Raw Impressions)
Displays total times the badge has been fetched and rendered, including repeated loads:
```markdown
[![Badge Loads](https://YOUR-HOST/badge/YOUR_GITHUB_USERNAME?metric=loads)](https://YOUR-HOST/report/YOUR_GITHUB_USERNAME)
```

#### 6. Active Windows (30-Minute Blocks)
Displays the count of distinct 30-minute visitor activity blocks:
```markdown
[![Active Windows](https://YOUR-HOST/badge/YOUR_GITHUB_USERNAME?metric=windows)](https://YOUR-HOST/report/YOUR_GITHUB_USERNAME)
```

#### 7. Custom Label & Color
Customizes the badge text and right-side color (e.g., `blue`, `green`, `brightgreen`, `orange`, `red`, `yellow`, `gray`, or hex code `#0969da`):
```markdown
[![Profile Views](https://YOUR-HOST/badge/YOUR_GITHUB_USERNAME?label=Profile+Views&color=blue)](https://YOUR-HOST/report/YOUR_GITHUB_USERNAME)
```

#### 8. Four-Part Dual Badge with Custom Colors
Independently style each segment of the default badge (e.g., green on the left, blue `#2C81F5` on the right):
```markdown
[![Profile Views](https://YOUR-HOST/badge/YOUR_GITHUB_USERNAME?label_color=2ea043&color=2ea043&label2_color=2C81F5&color2=2C81F5)](https://YOUR-HOST/report/YOUR_GITHUB_USERNAME)
```

#### 9. Side-by-Side Badges (Two Badges on One Line)
Render any two independent metrics side-by-side on GitHub by placing them without a blank line break:
```markdown
[![Total Loads](https://YOUR-HOST/badge/YOUR_GITHUB_USERNAME?metric=loads&color=2C81F5)](https://YOUR-HOST/report/YOUR_GITHUB_USERNAME) [![Today](https://YOUR-HOST/badge/YOUR_GITHUB_USERNAME?metric=today&color=2ea043)](https://YOUR-HOST/report/YOUR_GITHUB_USERNAME)
```

#### 10. Split View with Custom Styling
Combines split metrics (`Today | X | Total | Y`) with custom label and branding color:
```markdown
[![Visitors](https://YOUR-HOST/badge/YOUR_GITHUB_USERNAME?view=split&label=Visitors&color=2ea043)](https://YOUR-HOST/report/YOUR_GITHUB_USERNAME)
```

#### 11. Preview Mode (Non-Incrementing)
Renders the badge live without incrementing counters or logging hits — ideal for testing layouts:
```markdown
[![Preview](https://YOUR-HOST/badge/YOUR_GITHUB_USERNAME?preview=true)](https://YOUR-HOST/report/YOUR_GITHUB_USERNAME)
```

---

## ⚙️ Configuration

Configure via environment variables or a `.env` file:

| Variable | Default | Description |
|---|---|---|
| `DATABASE_URL` | *Required* | PostgreSQL connection string (production Supabase or local container). |
| `TEST_DATABASE_URL` | *None* | Dedicated PostgreSQL test database URL used strictly by the test suite. |
| `PROFILEPULSE_ENV` | `development` | Mode: `development` or `production`. In production, secure secret checks are enforced. |
| `PROFILEPULSE_SECRET` | `dev-secret-change-me` | Secret for HMAC hashing visitor fingerprints. Must be a secure 16+ char key in production. |
| `PROFILEPULSE_RATE_LIMIT` | `60` | Maximum requests per minute per client IP before rate limiting. |
| `PROFILEPULSE_OWNER_VISITOR_KEYS` | _(empty)_ | Optional comma-separated visitor keys to exclude from counts (your own visits). Find your key with the `hits` query in `docs/CALIBRATION.md`. Only excludes loads from that same key, so visits from another network still count. |
| `PROFILEPULSE_DEDUPE_DAYS` | `30` | A visitor is counted once, then not again until this many days have passed since their last counted visit. |
| `PROFILEPULSE_WINDOW_SECONDS` | `1800` | Duration in seconds for an active window block (default: 30 minutes). |
| `PROFILEPULSE_RETENTION_DAYS` | `30` | Retention period in days for raw hit logs before automatic pruning. |
| `PROFILEPULSE_TRUST_PROXY` | `false` | When `true`, honors `X-Forwarded-For` so each viewer is identified. Set `true` only behind trusted reverse proxies (e.g. Render). While `false`, counts are badly undercounted (the server logs a warning and `/report` shows the setting). |
| `PROFILEPULSE_VALIDATE_GITHUB_USER` | `true` | Validates GitHub username existence before tracking hits. |
| `GITHUB_TOKEN` | `""` | Optional token to raise GitHub user check API limits from 60 to 5,000 req/hr. |

---

## 🔒 Privacy

ProfilePulse adheres to strict privacy guarantees matching `/privacy`:
- **Zero Raw PII**: Neither raw IP addresses nor raw User-Agent strings are stored. Only coarse categories (`github-camo`, `browser`, `script`, `other`) are saved.
- **Keyed Visitor Hashes**: Viewer IPs are hashed with HMAC-SHA256 and a server secret. The hash is stable, so a repeat visitor is not counted again until `PROFILEPULSE_DEDUPE_DAYS` (default 30) have passed since they were last counted. Hashes are deleted after that period, and raw IPs are never stored.
- **Strict 30-Day Retention**: Raw telemetry and visitor keys are purged after 30 days. Only aggregate counters are kept.
- **Zero Cookies**: Sets no tracking cookies and makes no cross-site calls.

---

## ⚠️ Limitations

- **Estimates Only**: Static image embeds cannot observe viewport visibility or tab focus; counts reflect observed requests.
- **Camo Caching**: GitHub's Camo proxy caches images for variable intervals, which may coalesce rapid visits into fewer requests.
- **In-Memory Rate Limiting**: The sliding-window rate limiter is stored in-memory per process; it resets on restarts and does not coordinate across multi-worker deployments.
- **Free Tier Cold Starts & Database Pauses**: Render's free tier sleeps after 15 minutes of inactivity, and Supabase free projects pause after a week of inactivity. Keep-warm pinging (e.g. via UptimeRobot every 5 minutes on `/health`) prevents cold starts and keeps the database active.
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
