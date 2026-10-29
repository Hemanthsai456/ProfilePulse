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

Many GitHub profile visitor counters inflate numbers by counting every image reload as a unique human visit. Furthermore, because GitHub proxies images through [Camo](https://github.com/atmos/camo) (`camo.githubusercontent.com`), external servers observe GitHub's proxy rather than direct visitor IPs.

**ProfilePulse** is an open-source, lightweight microservice designed to provide **truthful, transparent README badge analytics**. It reports what it can actually observe, clearly distinguishes between raw requests and estimated visitors, and never claims to measure things an image tag cannot observe.

---

## 📊 Metrics Explained

| Metric | Query Parameter | What It Actually Measures | Resilience to Refreshes |
|---|---|---|---|
| **Daily Uniques (est.)** | `?metric=unique` *(default)* | At most one hit per visitor fingerprint (HMAC) per UTC day | Medium (bounded by Camo proxy behavior) |
| **Badge Loads** | `?metric=loads` | Every raw HTTP request that reached the server | Low (counts every uncached reload) |
| **Active Windows** | `?metric=windows` | Distinct 30-minute time intervals with observed badge activity | **High** (defuses refresh spam without tracking people) |
| **Verified Profile Visits** | *None* | Stays `null`. A static image badge cannot prove a page visit. | N/A — Never fabricated |

---

## 🚀 Quick Usage in GitHub README

Embed the badge directly into your GitHub profile `README.md`:

```markdown
<!-- Default: Daily Uniques (est.) -->
![Profile Views](https://your-profilepulse-instance.com/badge/YOUR_GITHUB_USERNAME)

<!-- Metric: Badge Loads -->
![Badge Loads](https://your-profilepulse-instance.com/badge/YOUR_GITHUB_USERNAME?metric=loads)

<!-- Metric: Active 30-min Windows (Spam-Resistant) -->
![Active Windows](https://your-profilepulse-instance.com/badge/YOUR_GITHUB_USERNAME?metric=windows)

<!-- Custom Label and Color -->
![Visits](https://your-profilepulse-instance.com/badge/YOUR_GITHUB_USERNAME?metric=unique&label=Profile+Visits&color=0969da)
```

> [!NOTE]
> GitHub Camo only fetches images over **HTTPS**. Ensure your public ProfilePulse instance is deployed behind HTTPS (e.g., Render, Fly.io, Railway, or Cloudflare).

### Badge Customization Options

| Parameter | Type | Default | Description |
|---|---|---|---|
| `metric` | `string` | `unique` | One of `unique`, `loads`, or `windows`. |
| `label` | `string` | Automatic | Left badge label (e.g. `Views`, `Visitors`). |
| `color` | `string` | `#2ea043` | Hex code (e.g. `0969da`) or name (`blue`, `orange`, `green`, `red`, etc.). |
| `ignore_owner` | `bool` | `false` | When `true` (or `1`), returns the current badge without incrementing or logging the visit. Useful for README previews. |

---

## 🔍 Public Transparency Report (`/report/{username}`)

ProfilePulse provides a public transparency endpoint for any user at `/report/{username}`. Unlike opaque counter services, ProfilePulse shows exactly how many requests were observed, proxy indicators, and daily trends:

```json
{
  "username": "hemanthsai456",
  "badge_loads": 128,
  "daily_uniques_est": 42,
  "active_windows": 36,
  "distinct_visitor_keys": 7,
  "via_camo": 121,
  "conditional_requests": 14,
  "with_x_forwarded_for": 121,
  "per_day": [
    {
      "day": "2026-10-29",
      "loads": 45,
      "distinct_keys": 4,
      "active_windows": 12,
      "daily_uniques_est": 15
    }
  ],
  "verified_profile_visits": null,
  "proxy_analysis": {
    "camo_request_percentage": 94.5,
    "signal": "Distinct visitor keys observed across requests."
  }
}
```

---

## 🧪 Feasibility Experiment Protocol

ProfilePulse is built to investigate whether embedded badges can distinguish visitors behind GitHub's image proxy. 

Follow the structured experiment protocol in [docs/EXPERIMENT.md](docs/EXPERIMENT.md):
1. **Direct Request:** Baseline direct request.
2. **Profile Embed:** Embed badge and visit once.
3. **Repeated Refreshes:** Inspect caching absorption.
4. **Multi-Device / Network:** Measure `distinct_visitor_keys`.
5. **Decision Gate:** Evaluate if Camo masks visitor entropy.

For design rationale and the decision roadmap, see [docs/IDEA.md](docs/IDEA.md) and [docs/IDEA_v2.md](docs/IDEA_v2.md).

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

### Running Tests
ProfilePulse includes an automated test suite verifying badge generation, rate-limiting, metrics calculation, and security protections:

```bash
pytest
```

---

## 🐳 Docker Deployment

### Run with Docker
```bash
# Build Docker image
docker build -t profilepulse .

# Run container with persistent data volume
docker run -d \
  -p 8000:8000 \
  -v profilepulse_data:/data \
  -e PROFILEPULSE_SECRET="replace-with-a-secure-secret-key" \
  --name profilepulse \
  profilepulse
```

### Run with Docker Compose
```bash
docker compose up -d
```

---

## 🔒 Privacy & Security

- **No Raw IP Storage:** Visitor fingerprints (`visitor_key`) are generated using an HMAC SHA-256 digest of request attributes with a server-side secret (`PROFILEPULSE_SECRET`). Raw IP addresses and user agents are never stored in plain text.
- **XSS & Injection Protection:** Badge labels, colors, and values are strictly validated, sanitized, and XML-escaped prior to SVG assembly.
- **Abuse Prevention & Rate Limiting:** Includes per-user rate limiting (default 60 requests/minute). Requests exceeding the threshold degrade gracefully by returning the current badge without failing or crashing.
- **Cache-Control:** Emits strict `no-cache, no-store, must-revalidate` directives to ensure GitHub Camo refreshes badges as expected.

---

## 📄 License

This project is licensed under the terms of the [MIT License](LICENSE).
