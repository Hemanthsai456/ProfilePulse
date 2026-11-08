# Deployment Guide (Render + Neon)

This guide covers deploying ProfilePulse using **Neon** (Serverless PostgreSQL) and **Render** (Container Web Service via Blueprint).

> **Note on Free Tiers & Cold Starts:**
> - Render free web services spin down (sleep) after 15 minutes of inactivity. The first incoming request after sleep takes 30–50 seconds to respond as the container boots up.
> - Neon free databases compute-pause when idle and resume automatically upon connection (typically 500ms–1s).
> - Setting up a free external monitoring ping (such as UptimeRobot) every 5 minutes against `/health` helps keep the service warm and responsive.

---

## 1. Create the Neon Database

1. Go to [Neon Console](https://console.neon.tech/) and create a free project (e.g. `profilepulse`).
2. Copy the **Connection Details** (PostgreSQL connection string).
3. Ensure `sslmode=require` is present at the end of the connection string:
   ```text
   postgresql://neondb_owner:YOUR_PASSWORD@ep-xyz-pooler.us-east-2.aws.neon.tech/neondb?sslmode=require
   ```

---

## 2. Deploy on Render via Blueprint

ProfilePulse includes a `render.yaml` Blueprint file at the repository root.

1. Fork or push your ProfilePulse repository to GitHub.
2. Sign in to the [Render Dashboard](https://dashboard.render.com/).
3. Click **New +** → **Blueprint**.
4. Connect your `ProfilePulse` repository. Render automatically reads `render.yaml`.
5. Under Environment Variables:
   - `PROFILEPULSE_ENV` is pre-set to `production`.
   - `PROFILEPULSE_SECRET` is automatically generated with a secure random string.
   - `PROFILEPULSE_TRUST_PROXY` is set to `true` (enabling Render reverse proxy IP extraction).
   - `DATABASE_URL`: Set this manually by pasting your Neon PostgreSQL connection string.
6. Click **Apply**. Render will build the Docker container, run database schema initialization at startup, and start the service.

---

## 3. Set Up Uptime Monitoring (Keep-Warm)

To reduce cold starts from Render sleeping:
1. Create a free account at [UptimeRobot](https://uptimerobot.com/) (or any HTTP monitor).
2. Add a new monitor:
   - **Monitor Type**: `HTTP(s)`
   - **Friendly Name**: `ProfilePulse Health`
   - **URL (or IP)**: `https://your-service.onrender.com/health`
   - **Monitoring Interval**: Every `5 minutes`
3. Save the monitor. This continuously checks service health and keeps the container active.

---

## 4. Test the Deployed Badge

1. Verify the health check:
   ```bash
   curl -I https://your-service.onrender.com/health
   # Returns HTTP 200 {"status": "ok", "database": "connected", ...}
   ```
2. Request a test badge:
   ```bash
   curl -I https://your-service.onrender.com/badge/octocat
   # Returns HTTP 200 image/svg+xml
   ```
3. Embed in your README:
   ```markdown
   [![Profile Views](https://your-service.onrender.com/badge/YOUR_USERNAME)](https://your-service.onrender.com/report/YOUR_USERNAME)
   ```

---

## 5. Reverse Proxy & X-Forwarded-For Architecture

### Single-Proxy Architecture Assumption
When `PROFILEPULSE_TRUST_PROXY=true`, ProfilePulse reads the **trailing IP** in the `X-Forwarded-For` header (`parts[-1].strip()`).
- **Prerequisite:** This design relies on having **exactly one trusted reverse proxy** (e.g. Render's incoming proxy) directly in front of the application container.
- **Why this works:** Standard reverse proxies append the client's direct socket connection IP to the end of any incoming `X-Forwarded-For` header. If a malicious client sends `X-Forwarded-For: 198.51.100.1`, Render appends the client's actual connecting IP (`203.0.113.50`), delivering `198.51.100.1, 203.0.113.50`. By taking `parts[-1]`, ProfilePulse uses the authentic client IP rather than the spoofed prefix.
- **Multi-proxy warning:** If multiple layers of reverse proxies sit between the client and the application (e.g. Cloudflare -> AWS ALB -> Render), ensure the intermediate layers strip or normalize untrusted upstream headers, or that only the trusted ingress IP is accepted.

### Manual Verification Check
To verify that your deployment is correctly extracting the real client IP and ignoring spoofed headers:

1. Send repeated preview requests with a spoofed `X-Forwarded-For` header until the per-client rate limit is reached (60 requests per minute):
   ```bash
   for i in {1..65}; do
     curl -s -o /dev/null -D - \
       -H "X-Forwarded-For: 198.51.100.1" \
       "https://your-service.onrender.com/badge/octocat?preview=true" | grep -i "x-ratelimit"
   done
   ```
   You will observe `X-RateLimit-Exceeded: true` once the limit is hit.

2. Immediately send another request from the **same client machine**, but switch to a completely different fake IP in the header:
   ```bash
   curl -s -D - \
     -H "X-Forwarded-For: 203.0.113.99" \
     "https://your-service.onrender.com/badge/octocat?preview=true" | grep -i "x-ratelimit"
   ```

3. **Verify:** You should still receive `X-RateLimit-Exceeded: true`. This confirms that the service ignores the spoofed `X-Forwarded-For` prefix and applies rate limiting based on your machine's authentic client IP appended by Render.

---

## Other Container Hosts

ProfilePulse is packaged as a standard Docker container. Any host running Docker with a valid `DATABASE_URL` (PostgreSQL 14+) and `PROFILEPULSE_SECRET` will run ProfilePulse without modification.
