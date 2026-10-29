<div align="center">

# ProfilePulse

**Honest, privacy-first GitHub README badge visitor analytics.**

[![CI](https://github.com/Hemanthsai456/ProfilePulse/actions/workflows/ci.yml/badge.svg)](https://github.com/Hemanthsai456/ProfilePulse/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Python 3.10 | 3.11 | 3.12](https://img.shields.io/badge/Python-3.10%20%7C%203.11%20%7C%203.12-brightgreen.svg)](pyproject.toml)
[![FastAPI](https://img.shields.io/badge/Framework-FastAPI-009688.svg)](https://fastapi.tiangolo.com)
[![Docker Ready](https://img.shields.io/badge/Docker-Ready-2496ED.svg)](Dockerfile)

</div>

---

## 📌 Overview

Many GitHub profile visitor counters inflate numbers by counting every image reload or script execution as a unique human visit. Furthermore, because GitHub proxies images through [Camo](https://github.com/atmos/camo) (`camo.githubusercontent.com`), external servers observe GitHub's proxy rather than direct visitor IPs.

**ProfilePulse** is an open-source, hardened microservice designed to provide **truthful, transparent README badge analytics**. It reports what it can actually observe, clearly distinguishes between raw requests and estimated visitors, and never claims to measure things an image tag cannot observe.

---

## 🛡️ Anti-Inflation & Hardening (v0.2.0)

- **Camo Proxy Verification:** Only requests originating from GitHub's Camo image proxy (`User-Agent: github-camo ...`) count toward primary badge metrics. Direct curl/browser hits cannot trivially inflate profile counts.
- **Atomic Deduplication:** Eliminates check-then-insert race conditions using database unique constraints (`INSERT OR IGNORE`).
- **Daily Key Rotation:** Visitor fingerprints incorporate the UTC day in the HMAC payload (`HMAC(SECRET, day|ip|ua)`). Hashes rotate daily so visitors cannot be cross-correlated across dates.
- **Fast $O(1)$ Reads:** Aggregated counters are maintained in dedicated summary tables. Badge queries execute in sub-millisecond time, preventing GitHub Camo timeouts.
- **Automatic 30-Day Retention:** Raw request telemetry is automatically purged after 30 days while preserving cumulative daily and total statistics.
- **GitHub Account Verification:** Checks that requested usernames exist on GitHub before storing telemetry to prevent junk spamming.
- **SVG Security:** Strict `Content-Security-Policy: default-src 'none'; style-src 'unsafe-inline'` and `X-Content-Type-Options: nosniff`.
- **Non-Root Docker:** Runs as a non-privileged system user (`appuser`, UID 10001) with reverse-proxy header support.

---

## 📊 Metrics Explained

| Metric | Query Parameter | What It Actually Measures | Resilience to Refreshes |
|---|---|---|---|
| **Total Uniques (est.)** | `?metric=unique` *(default)* | Sum of each day's unique visitors via GitHub Camo | High (deduplicated per day) |
| **Today's Uniques** | `?metric=today` | Today's unique visitors via GitHub Camo | High (resets at 00:00 UTC) |
| **Active Windows** | `?metric=windows` | Distinct 30-minute time intervals with observed badge activity | **Maximum** (resists refresh spam without tracking people) |
| **Badge Loads** | `?metric=loads` | Every uncached HTTP request reaching the server | Low (counts every uncached reload) |
| **Verified Profile Visits** | *None* | Stays `null`. A static image badge cannot prove a page visit. | N/A — Never fabricated |

---

## 🚀 Quick Usage in GitHub README

Embed the badge directly into your GitHub profile `README.md`:

```markdown
<!-- Default: Total Uniques (est.) -->
![Profile Views](https://your-profilepulse-instance.com/badge/YOUR_GITHUB_USERNAME)

<!-- Split View: Today's Count alongside All-Time Total -->
![Profile Views](https://your-profilepulse-instance.com/badge/YOUR_GITHUB_USERNAME?view=split)

<!-- Today's Unique Visitors Only -->
![Today's Visitors](https://your-profilepulse-instance.com/badge/YOUR_GITHUB_USERNAME?metric=today)

<!-- Metric: Active 30-min Windows (Spam-Resistant) -->
![Active Windows](https://your-profilepulse-instance.com/badge/YOUR_GITHUB_USERNAME?metric=windows)

<!-- Metric: Raw Badge Loads -->
![Badge Loads](https://your-profilepulse-instance.com/badge/YOUR_GITHUB_USERNAME?metric=loads)

<!-- Custom Label and Color -->
![Visits](https://your-profilepulse-instance.com/badge/YOUR_GITHUB_USERNAME?label=Profile+Visits&color=0969da)
```

> [!NOTE]
> GitHub Camo only fetches images over **HTTPS**. Ensure your public ProfilePulse instance is deployed behind HTTPS (e.g., Render, Fly.io, Railway, or Cloudflare).

### Badge Customization Options

| Parameter | Type | Default | Description |
|---|---|---|---|
| `metric` | `string` | `unique` | One of `unique` (all-time), `today`, `windows`, or `loads`. |
| `view` | `string` | `""` | Set to `split` to display `today · total` (e.g. `12 today · 1.2k total`). |
| `label` | `string` | Automatic | Left badge label (e.g. `Views`, `Visitors`). |
| `color` | `string` | `#2ea043` | Hex code (e.g. `0969da`) or name (`blue`, `orange`, `green`, `red`, etc.). |
| `source` | `string` | `camo` | `camo` (GitHub proxy views only), `all`, or `direct`. |
| `preview` | `bool` | `false` | When `true` (or `1`), returns the current badge without incrementing or logging the visit. Useful for README previews. |

---

## 🔍 Public Transparency Report (`/report/{username}`)

ProfilePulse provides a public transparency endpoint for any user at `/report/{username}`. Unlike opaque counter services, ProfilePulse shows exactly how many requests were observed, proxy indicators, and daily trends:

```json
{
  "username": "hemanthsai456",
  "metrics": {
    "camo_proxied": {
      "total_uniques_est": 42,
      "badge_loads": 128,
      "active_windows": 36
    },
    "direct_requests": {
      "total_uniques_est": 2,
      "badge_loads": 5
    },
    "combined": {
      "total_loads": 133,
      "distinct_visitor_keys_retained": 7,
      "camo_percentage": 96.2,
      "conditional_requests": 14
    },
    "verified_profile_visits": null
  },
  "per_day": [
    {
      "day": "2026-10-29",
      "camo_uniques": 15,
      "camo_loads": 45,
      "camo_windows": 12,
      "direct_uniques": 1,
      "direct_loads": 2
    }
  ]
}
```

---

## 🛠️ Local Development

### Prerequisites
- Python 3.10+
- `pip`

### Setup
```bash
# Clone the repository
git clone https://github.com/Hemanthsai456/ProfilePulse.git
cd ProfilePulse

# Install dependencies
pip install -r requirements-dev.txt

# Run development server
uvicorn app.main:app --reload --port 8000
```

### Running Tests & Linting
```bash
# Run automated test suite
pytest

# Run linter
ruff check .
```

---

## 🐳 Docker Deployment

### Run with Docker Compose
```bash
docker compose up -d --build
```

### Run with Docker CLI
```bash
# Build Docker image
docker build -t profilepulse .

# Run container with persistent data volume and proxy headers
docker run -d \
  -p 8000:8000 \
  -v profilepulse_data:/data \
  -e PROFILEPULSE_ENV="production" \
  -e PROFILEPULSE_SECRET="generate-a-secure-random-secret-key-min-16-chars" \
  --name profilepulse \
  profilepulse
```

---

## 🔒 Privacy & Security

Visit `/privacy` on your deployment to view the automated public privacy policy:
- **Zero PII:** Raw IP addresses and user agents are never stored in plain text.
- **Daily Key Rotation:** Visitor fingerprints (`visitor_key`) use HMAC-SHA256 salted with the UTC date string (`day`). Hashes rotate every 24 hours, preventing cross-day tracking.
- **Strict 30-Day Retention:** Raw request telemetry is purged after 30 days. Only anonymous aggregated totals are retained.
- **Production Guardrail:** In production (`PROFILEPULSE_ENV=production`), the application refuses to start if `PROFILEPULSE_SECRET` is unset, default, or less than 16 characters.

---

## 📄 License

This project is licensed under the terms of the [MIT License](LICENSE).
