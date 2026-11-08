"""ProfilePulse — Honest, privacy-first GitHub README badge visitor analytics.

Core Research & Engineering Design:
  * Camo Verification: Distinguishes between requests from GitHub's Camo image proxy
    (camo.githubusercontent.com) and direct HTTP/curl hits.
  * Race-Condition Free: Uses atomic PostgreSQL unique constraints with ON CONFLICT DO NOTHING.
  * Ephemeral Daily Keys: Incorporates UTC date in HMAC hashing so visitor keys rotate daily.
  * Totals Table: O(1) reads for fast badge rendering without slow full-table scans.
  * 30-Day Retention: Automatically prunes raw hit logs while preserving daily and total aggregates.
  * GitHub Account Validation: Validates GitHub username existence to prevent junk spamming.
  * SVG Security: Serves badges with strict CSP and nosniff headers.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import logging
import os
import re
import sys
import time
import urllib.parse
from contextlib import asynccontextmanager, closing
from datetime import datetime, timezone
from typing import Any

import httpx
import psycopg
from fastapi import FastAPI, HTTPException, Query, Request, Response
from psycopg.rows import dict_row

__version__ = "0.3.0"

# --- Environment & Configuration ---
ENV = os.environ.get("PROFILEPULSE_ENV", os.environ.get("ENVIRONMENT", "development")).lower()
SECRET_STR = os.environ.get("PROFILEPULSE_SECRET", "")
DATABASE_URL = os.environ.get("DATABASE_URL", "").strip()
TRUST_PROXY = os.environ.get("PROFILEPULSE_TRUST_PROXY", "false").lower() in ("true", "1")

INSECURE_SECRETS = {
    "dev-secret-change-me",
    "local-dev-secret-key-32chars",
}


def validate_secret(env: str, secret: str) -> None:
    """Validate that the secret meets production security requirements."""
    if env.lower() == "production" and (not secret or secret in INSECURE_SECRETS or len(secret) < 16):
        raise RuntimeError(
            "FATAL: In production mode, PROFILEPULSE_SECRET must be set to a secure, random string (min 16 chars) and cannot use default dev keys."
        )


validate_secret(ENV, SECRET_STR)

SECRET = (SECRET_STR or "dev-secret-change-me").encode("utf-8")
RATE_LIMIT_PER_MIN = int(os.environ.get("PROFILEPULSE_RATE_LIMIT", "60"))
WINDOW_SECONDS = int(os.environ.get("PROFILEPULSE_WINDOW_SECONDS", "1800"))  # 30 minutes
RAW_RETENTION_DAYS = int(os.environ.get("PROFILEPULSE_RETENTION_DAYS", "30"))
GITHUB_VALIDATE_USER = os.environ.get("PROFILEPULSE_VALIDATE_GITHUB_USER", "true").lower() in ("true", "1")
GITHUB_TOKEN = os.environ.get("GITHUB_TOKEN", os.environ.get("PROFILEPULSE_GITHUB_TOKEN", "")).strip()

USERNAME_RE = re.compile(r"\A[A-Za-z0-9](?:[A-Za-z0-9]|-(?=[A-Za-z0-9])){0,38}\Z")
HEX_COLOR_RE = re.compile(r"^#?([0-9a-fA-F]{3}|[0-9a-fA-F]{6})$")

SAFE_COLORS = {
    "brightgreen": "#4c1",
    "green": "#2ea043",
    "yellowgreen": "#a4a61d",
    "yellow": "#dfb317",
    "orange": "#fe7d37",
    "red": "#e05d44",
    "blue": "#0969da",
    "lightgrey": "#9f9f9f",
    "gray": "#555555",
    "grey": "#555555",
    "black": "#24292f",
    "informational": "#0969da",
    "success": "#2ea043",
    "critical": "#e05d44",
}


# --- Structured JSON Logging ---
class JsonFormatter(logging.Formatter):
    def format(self, record: logging.LogRecord) -> str:
        log_obj = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "level": record.levelname,
            "message": record.getMessage(),
            "logger": record.name,
        }
        if hasattr(record, "props"):
            log_obj.update(record.props)  # type: ignore
        return json.dumps(log_obj)


logger = logging.getLogger("profilepulse")
handler = logging.StreamHandler(sys.stdout)
handler.setFormatter(JsonFormatter())
logger.addHandler(handler)
logger.setLevel(logging.INFO)
logger.propagate = False


# --- GitHub User Existence Cache ---
# Cache maps username -> (exists: bool, expires_at: float)
_USER_CACHE: dict[str, tuple[bool, float]] = {}
CACHE_TTL_VALID = 86400.0  # 24 hours
CACHE_TTL_INVALID = 3600.0  # 1 hour


async def check_github_user_exists(username: str) -> bool:
    """Check if the GitHub account exists, using an in-memory TTL cache."""
    now = time.time()
    cached = _USER_CACHE.get(username)
    if cached and cached[1] > now:
        return cached[0]

    url = f"https://api.github.com/users/{username}"
    headers = {"User-Agent": "ProfilePulse-Verifier/0.3"}
    if GITHUB_TOKEN:
        headers["Authorization"] = f"Bearer {GITHUB_TOKEN}"

    try:
        async with httpx.AsyncClient(timeout=3.0) as client:
            resp = await client.get(url, headers=headers)
            if resp.status_code == 200:
                _USER_CACHE[username] = (True, now + CACHE_TTL_VALID)
                return True
            elif resp.status_code == 404:
                _USER_CACHE[username] = (False, now + CACHE_TTL_INVALID)
                return False
            else:
                # If GitHub API returns 403 (rate limited) or server error, fail open
                logger.warning(
                    "GitHub API verification degraded",
                    extra={"props": {"status": resp.status_code, "username": username}},
                )
                return True
    except (httpx.HTTPError, OSError) as exc:
        # On network error or timeout, fail open to avoid service disruption
        logger.warning(
            "GitHub API verification error, failing open",
            extra={"props": {"error": str(exc), "username": username}},
        )
        return True


# --- Database Initialization & Schema ---
def mask_db_url(url: str) -> str:
    """Mask credentials in database URL for safe logging and error reporting."""
    if not url:
        return ""
    try:
        parsed = urllib.parse.urlsplit(url)
        if parsed.password:
            netloc = f"{parsed.username}:***@{parsed.hostname}"
            if parsed.port:
                netloc += f":{parsed.port}"
            return urllib.parse.urlunsplit(
                (parsed.scheme, netloc, parsed.path, parsed.query, parsed.fragment)
            )
        return url
    except (ValueError, AttributeError):
        return "postgresql://***:***@masked/db"


def init_db(conn: psycopg.Connection) -> None:
    """Initialize PostgreSQL database schema with all required tables and indexes."""
    with conn.cursor() as cur:
        # 1. Total aggregate stats per user (O(1) read for badges)
        cur.execute(
            """CREATE TABLE IF NOT EXISTS user_totals (
                username TEXT PRIMARY KEY,
                camo_uniques BIGINT DEFAULT 0,
                camo_loads BIGINT DEFAULT 0,
                camo_windows BIGINT DEFAULT 0,
                direct_uniques BIGINT DEFAULT 0,
                direct_loads BIGINT DEFAULT 0,
                updated_at DOUBLE PRECISION NOT NULL
            )"""
        )

        # 2. Daily aggregate stats per user
        cur.execute(
            """CREATE TABLE IF NOT EXISTS daily_stats (
                username TEXT NOT NULL,
                day TEXT NOT NULL,
                camo_uniques BIGINT DEFAULT 0,
                camo_loads BIGINT DEFAULT 0,
                camo_windows BIGINT DEFAULT 0,
                direct_uniques BIGINT DEFAULT 0,
                direct_loads BIGINT DEFAULT 0,
                PRIMARY KEY (username, day)
            )"""
        )

        # 3. Unique visitor deduplication table (Atomic unique constraint)
        cur.execute(
            """CREATE TABLE IF NOT EXISTS daily_uniques (
                username TEXT NOT NULL,
                day TEXT NOT NULL,
                visitor_key TEXT NOT NULL,
                via_camo INTEGER NOT NULL,
                ts DOUBLE PRECISION NOT NULL,
                PRIMARY KEY (username, day, visitor_key)
            )"""
        )
        cur.execute("CREATE INDEX IF NOT EXISTS idx_uniques_ts ON daily_uniques(ts)")

        # 4. Active 30-minute windows deduplication table
        cur.execute(
            """CREATE TABLE IF NOT EXISTS active_windows (
                username TEXT NOT NULL,
                window_id BIGINT NOT NULL,
                via_camo INTEGER NOT NULL,
                ts DOUBLE PRECISION NOT NULL,
                PRIMARY KEY (username, window_id, via_camo)
            )"""
        )
        cur.execute("CREATE INDEX IF NOT EXISTS idx_windows_ts ON active_windows(ts)")

        # 5. Raw hit telemetry log (Pruned after 30 days, zero raw UA/IP)
        cur.execute(
            """CREATE TABLE IF NOT EXISTS hits (
                id BIGSERIAL PRIMARY KEY,
                ts DOUBLE PRECISION NOT NULL,
                day TEXT NOT NULL,
                username TEXT NOT NULL,
                visitor_key TEXT NOT NULL,
                client_type TEXT NOT NULL DEFAULT 'other',
                via_camo INTEGER NOT NULL,
                conditional INTEGER NOT NULL,
                counted_unique INTEGER NOT NULL
            )"""
        )
        cur.execute("CREATE INDEX IF NOT EXISTS idx_hits_user_day ON hits(username, day)")
        cur.execute("CREATE INDEX IF NOT EXISTS idx_hits_ts ON hits(ts)")
    conn.commit()


def get_db(db_url: str | None = None) -> psycopg.Connection:
    """Initialize and return a connection to PostgreSQL with dict_row factory."""
    target_url = db_url or DATABASE_URL
    if not target_url:
        raise psycopg.OperationalError("DATABASE_URL is not set.")
    try:
        conn = psycopg.connect(target_url, row_factory=dict_row)
        return conn
    except psycopg.Error as exc:
        masked_exc = str(exc)
        if target_url:
            masked_exc = masked_exc.replace(target_url, mask_db_url(target_url))
        logger.error("Database connection failure", extra={"props": {"error": masked_exc}})
        raise psycopg.OperationalError(masked_exc) from None


def prune_old_records(conn: psycopg.Connection, retention_days: int = RAW_RETENTION_DAYS) -> int:
    """Prune raw logs older than retention period while preserving user_totals and daily_stats."""
    cutoff = time.time() - (retention_days * 86400.0)
    with conn.cursor() as cur:
        cur.execute("DELETE FROM hits WHERE ts < %s", (cutoff,))
        deleted = cur.rowcount
        cur.execute("DELETE FROM daily_uniques WHERE ts < %s", (cutoff,))
        cur.execute("DELETE FROM active_windows WHERE ts < %s", (cutoff,))
    conn.commit()
    return deleted


# --- Core Helper Functions ---
def get_client_ip(request: Request) -> str:
    """Extract client IP, only honoring X-Forwarded-For if TRUST_PROXY is enabled.

    When running behind a trusted reverse proxy (like Render), the proxy appends
    the connecting client IP to the end of the X-Forwarded-For chain. We take the
    last entry to ensure we read the proxy-verified IP, preventing client spoofing.
    """
    if TRUST_PROXY:
        xff = request.headers.get("x-forwarded-for")
        if xff:
            parts = [p.strip() for p in xff.split(",") if p.strip()]
            if parts:
                return parts[-1]
    if request.client and request.client.host:
        return request.client.host
    return "unknown"


def visitor_key(day: str, request: Request) -> str:
    """Generate an ephemeral, daily-rotated HMAC visitor fingerprint.

    Incorporates the UTC day into the HMAC salt so visitor keys rotate daily.
    Uses get_client_ip(request).
    """
    ip = get_client_ip(request)
    ua = request.headers.get("user-agent", "")
    raw = f"{day}|{ip}|{ua}".encode()
    return hmac.new(SECRET, raw, hashlib.sha256).hexdigest()[:16]


def categorize_ua(ua: str) -> str:
    """Classify user agent into a coarse category without storing raw string."""
    ua_lower = ua.lower()
    if "github-camo" in ua_lower:
        return "github-camo"
    if any(bot in ua_lower for bot in ("curl", "wget", "python", "http", "bot", "crawl", "spider", "scanner")):
        return "script"
    if any(b in ua_lower for b in ("mozilla", "chrome", "safari", "firefox", "edge", "opera")):
        return "browser"
    return "other"


def sanitize_color(color_input: str | None) -> str:
    """Validate and sanitize the badge color to prevent SVG markup injection."""
    if not color_input:
        return "#2ea043"

    color_lower = color_input.strip().lower()
    if color_lower in SAFE_COLORS:
        return SAFE_COLORS[color_lower]

    match = HEX_COLOR_RE.match(color_lower)
    if match:
        return f"#{match.group(1)}"

    return "#2ea043"


def escape_xml(s: str) -> str:
    """Strict XML escaping for SVG contents."""
    return (
        s.replace("&", "&amp;")
        .replace("<", "&lt;")
        .replace(">", "&gt;")
        .replace('"', "&quot;")
        .replace("'", "&#39;")
    )


def format_number(n: int) -> str:
    """Format large numbers cleanly (e.g. 1.2k for badges)."""
    if n >= 1_000_000:
        return f"{n / 1_000_000:.1f}M".replace(".0M", "M")
    if n >= 10_000:
        return f"{n / 1_000:.1f}k".replace(".0k", "k")
    return f"{n:,}"


def render_svg(label: str, value: str, color: str = "#2ea043") -> str:
    """Generate an accessible, Shields-style SVG badge."""
    label_esc = escape_xml(label)
    value_esc = escape_xml(value)

    lw = max(40, int(7.2 * len(label) + 16))
    vw = max(30, int(7.2 * len(value) + 16))
    total_w = lw + vw

    lx = lw / 2.0
    vx = lw + (vw / 2.0)
    safe_color = sanitize_color(color)

    return (
        f'<svg xmlns="http://www.w3.org/2000/svg" width="{total_w}" height="20" '
        f'role="img" aria-label="{label_esc}: {value_esc}">'
        f'<title>{label_esc}: {value_esc}</title>'
        f'<linearGradient id="s" x2="0" y2="100%">'
        f'<stop offset="0" stop-color="#bbb" stop-opacity=".1"/>'
        f'<stop offset="100%" stop-opacity=".1"/>'
        f'</linearGradient>'
        f'<clipPath id="r">'
        f'<rect width="{total_w}" height="20" rx="3" fill="#fff"/>'
        f'</clipPath>'
        f'<g clip-path="url(#r)">'
        f'<rect width="{lw}" height="20" fill="#555"/>'
        f'<rect x="{lw}" width="{vw}" height="20" fill="{safe_color}"/>'
        f'<rect width="{total_w}" height="20" fill="url(#s)"/>'
        f'</g>'
        f'<g fill="#fff" text-anchor="middle" '
        f'font-family="Verdana,Geneva,DejaVu Sans,sans-serif" text-rendering="geometricPrecision" font-size="11">'
        f'<text aria-hidden="true" x="{lx}" y="15" fill="#010101" fill-opacity=".3">{label_esc}</text>'
        f'<text x="{lx}" y="14">{label_esc}</text>'
        f'<text aria-hidden="true" x="{vx}" y="15" fill="#010101" fill-opacity=".3">{value_esc}</text>'
        f'<text x="{vx}" y="14">{value_esc}</text>'
        f'</g>'
        f'</svg>'
    )


def valid_user(username: str) -> str:
    """Validate GitHub username according to GitHub naming rules."""
    if (
        not username
        or len(username) > 39
        or username.startswith("-")
        or username.endswith("-")
        or "--" in username
        or "\n" in username
        or "\r" in username
        or not USERNAME_RE.match(username)
    ):
        raise HTTPException(
            status_code=400,
            detail="Invalid GitHub username format. Allowed: alphanumeric, single hyphens, max 39 characters, no leading or trailing hyphen.",
        )
    return username.lower()


_CLIENT_RATE_LIMITS: dict[str, list[float]] = {}


def rate_limited(client_id: str, limit: int = RATE_LIMIT_PER_MIN) -> bool:
    """Check if the rate limit of requests per minute has been exceeded for this client."""
    now = time.time()
    cutoff = now - 60.0
    timestamps = _CLIENT_RATE_LIMITS.get(client_id, [])
    timestamps = [ts for ts in timestamps if ts > cutoff]
    if len(timestamps) >= limit:
        _CLIENT_RATE_LIMITS[client_id] = timestamps
        return True
    timestamps.append(now)
    _CLIENT_RATE_LIMITS[client_id] = timestamps
    return False


def normalize_metric(metric: str) -> str:
    """Normalize metric aliases to standard keys."""
    m = metric.strip().lower()
    if m in ("unique", "uniques", "total", "total_unique"):
        return "unique"
    if m in ("today", "daily", "today_unique"):
        return "today"
    if m in ("loads", "load", "badge_loads"):
        return "loads"
    if m in ("windows", "window", "active", "active_windows"):
        return "windows"
    raise HTTPException(
        status_code=400,
        detail="Metric must be one of: 'unique' (Total Uniques), 'today' (Today's Uniques), 'loads' (Badge Loads), or 'windows' (Active Windows).",
    )


@asynccontextmanager
async def lifespan(app: FastAPI):
    if DATABASE_URL:
        try:
            with closing(get_db()) as conn:
                init_db(conn)
                pruned = prune_old_records(conn)
                if pruned > 0:
                    logger.info("Startup raw records pruned", extra={"props": {"pruned": pruned}})
        except (psycopg.Error, OSError) as exc:
            logger.warning(
                "Startup database check failed, continuing in degraded state",
                extra={"props": {"error": str(exc)}},
            )
    yield


app = FastAPI(
    title="ProfilePulse",
    description="Honest, privacy-preserving GitHub README visitor analytics.",
    version=__version__,
    lifespan=lifespan,
)


@app.get("/badge/{username}")
@app.get("/badge/{username}.svg")
async def badge(
    username: str,
    request: Request,
    metric: str = Query("unique", description="Metric: 'unique' (all-time), 'today', 'loads', or 'windows'"),
    view: str = Query("", description="Badge style view: 'split' (shows today · total) or standard"),
    label: str = Query("", description="Custom label for the badge"),
    color: str = Query("", description="Custom badge color (hex code or name)"),
    source: str = Query(
        "camo",
        description="Traffic source to count: 'camo' (GitHub proxy views only), 'all', or 'direct'",
    ),
    preview: bool = Query(
        False,
        description="If true, do not increment or record hit (useful for previewing without counting)",
    ),
    ignore_owner: bool | None = Query(None, description="Deprecated alias for preview"),
):
    """Serve an SVG badge for a GitHub username.

    Only requests proxied by GitHub Camo count toward the primary badge metrics by default,
    preventing direct curl/browser hits from inflating profile counters.
    """
    user = valid_user(username)
    metric_type = normalize_metric(metric)
    is_preview = preview or (ignore_owner is True)

    now = time.time()
    day = datetime.fromtimestamp(now, timezone.utc).strftime("%Y-%m-%d")
    window_id = int(now // WINDOW_SECONDS)
    key = visitor_key(day, request)

    ua = request.headers.get("user-agent", "") or ""
    client_cat = categorize_ua(ua)
    is_camo = 1 if client_cat == "github-camo" else 0
    is_conditional = 1 if ("if-none-match" in request.headers or "if-modified-since" in request.headers) else 0

    client_ip = get_client_ip(request)
    rate_limit_exceeded = rate_limited(client_ip, limit=RATE_LIMIT_PER_MIN)

    # Validate that GitHub account exists to prevent storage junk (cached)
    if GITHUB_VALIDATE_USER and not is_preview:
        exists = await check_github_user_exists(user)
        if not exists:
            raise HTTPException(status_code=404, detail=f"GitHub user '{user}' does not exist.")

    with closing(get_db()) as conn, conn.cursor() as cur:
        if not is_preview and not rate_limit_exceeded:
            # 1. Atomic daily unique insertion (avoids check-then-insert race condition)
            cur.execute(
                """INSERT INTO daily_uniques (username, day, visitor_key, via_camo, ts)
                VALUES (%s, %s, %s, %s, %s)
                ON CONFLICT DO NOTHING""",
                (user, day, key, is_camo, now),
            )
            counted_unique = 1 if cur.rowcount > 0 else 0

            # 2. Atomic active window insertion
            cur.execute(
                """INSERT INTO active_windows (username, window_id, via_camo, ts)
                VALUES (%s, %s, %s, %s)
                ON CONFLICT DO NOTHING""",
                (user, window_id, is_camo, now),
            )
            counted_window = 1 if cur.rowcount > 0 else 0

            # 3. Update aggregate totals table (O(1) updates)
            cur.execute(
                """INSERT INTO user_totals (
                    username, camo_uniques, camo_loads, camo_windows,
                    direct_uniques, direct_loads, updated_at
                ) VALUES (%s, %s, %s, %s, %s, %s, %s)
                ON CONFLICT (username) DO UPDATE SET
                    camo_uniques = user_totals.camo_uniques + EXCLUDED.camo_uniques,
                    camo_loads = user_totals.camo_loads + EXCLUDED.camo_loads,
                    camo_windows = user_totals.camo_windows + EXCLUDED.camo_windows,
                    direct_uniques = user_totals.direct_uniques + EXCLUDED.direct_uniques,
                    direct_loads = user_totals.direct_loads + EXCLUDED.direct_loads,
                    updated_at = EXCLUDED.updated_at""",
                (
                    user,
                    counted_unique if is_camo else 0,
                    1 if is_camo else 0,
                    counted_window if is_camo else 0,
                    counted_unique if not is_camo else 0,
                    1 if not is_camo else 0,
                    now,
                ),
            )

            # 4. Update daily stats table
            cur.execute(
                """INSERT INTO daily_stats (
                    username, day, camo_uniques, camo_loads, camo_windows,
                    direct_uniques, direct_loads
                ) VALUES (%s, %s, %s, %s, %s, %s, %s)
                ON CONFLICT (username, day) DO UPDATE SET
                    camo_uniques = daily_stats.camo_uniques + EXCLUDED.camo_uniques,
                    camo_loads = daily_stats.camo_loads + EXCLUDED.camo_loads,
                    camo_windows = daily_stats.camo_windows + EXCLUDED.camo_windows,
                    direct_uniques = daily_stats.direct_uniques + EXCLUDED.direct_uniques,
                    direct_loads = daily_stats.direct_loads + EXCLUDED.direct_loads""",
                (
                    user,
                    day,
                    counted_unique if is_camo else 0,
                    1 if is_camo else 0,
                    counted_window if is_camo else 0,
                    counted_unique if not is_camo else 0,
                    1 if not is_camo else 0,
                ),
            )

            # 5. Raw hit telemetry (zero raw UA/IP)
            cur.execute(
                """INSERT INTO hits (
                    ts, day, username, visitor_key, client_type,
                    via_camo, conditional, counted_unique
                ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s)""",
                (now, day, user, key, client_cat, is_camo, is_conditional, counted_unique),
            )
            conn.commit()

        # Fast O(1) reads for badge rendering
        cur.execute(
            "SELECT camo_uniques, camo_loads, camo_windows, direct_uniques, direct_loads FROM user_totals WHERE username=%s",
            (user,),
        )
        tot_row = cur.fetchone()

        cur.execute(
            "SELECT camo_uniques, camo_loads, direct_uniques, direct_loads FROM daily_stats WHERE username=%s AND day=%s",
            (user, day),
        )
        day_row = cur.fetchone()

    # Fallback to zero if user has no rows yet
    tot = tot_row if tot_row else {
        "camo_uniques": 0, "camo_loads": 0, "camo_windows": 0,
        "direct_uniques": 0, "direct_loads": 0,
    }
    today_stats = day_row if day_row else {
        "camo_uniques": 0, "camo_loads": 0,
        "direct_uniques": 0, "direct_loads": 0,
    }

    # Filter by source: 'camo' (default), 'all', or 'direct'
    # In development mode, if no Camo traffic exists yet, automatically include direct counts so local testing displays numbers
    use_source = source.lower()
    if use_source == "camo" and ENV == "development" and tot["camo_loads"] == 0 and tot["direct_loads"] > 0:
        use_source = "all"

    if use_source == "direct":
        total_unique = tot["direct_uniques"]
        today_unique = today_stats["direct_uniques"]
        total_loads = tot["direct_loads"]
        total_windows = tot["camo_windows"]
    elif use_source == "all":
        total_unique = tot["camo_uniques"] + tot["direct_uniques"]
        today_unique = today_stats["camo_uniques"] + today_stats["direct_uniques"]
        total_loads = tot["camo_loads"] + tot["direct_loads"]
        total_windows = tot["camo_windows"]
    else:  # 'camo' (production default)
        total_unique = tot["camo_uniques"]
        today_unique = today_stats["camo_uniques"]
        total_loads = tot["camo_loads"]
        total_windows = tot["camo_windows"]

    # Compute label and display value
    if view == "split":
        display_label = label[:32] if label else "Profile Views"
        display_value = f"{format_number(today_unique)} today · {format_number(total_unique)} total"
    elif metric_type == "today":
        display_label = label[:32] if label else "Today's Uniques"
        display_value = format_number(today_unique)
    elif metric_type == "windows":
        display_label = label[:32] if label else "Active Windows"
        display_value = format_number(total_windows)
    elif metric_type == "loads":
        display_label = label[:32] if label else "Badge Loads"
        display_value = format_number(total_loads)
    else:  # 'unique' (default)
        display_label = label[:32] if label else "Total Uniques (est.)"
        display_value = format_number(total_unique)

    svg_content = render_svg(display_label, display_value, color)

    headers = {
        "Content-Type": "image/svg+xml",
        "Cache-Control": "max-age=0, no-cache, no-store, must-revalidate, private",
        "Pragma": "no-cache",
        "Expires": "0",
        "X-Content-Type-Options": "nosniff",
        "Content-Security-Policy": "default-src 'none'; style-src 'unsafe-inline'",
    }
    if rate_limit_exceeded:
        headers["X-RateLimit-Exceeded"] = "true"

    return Response(content=svg_content, media_type="image/svg+xml", headers=headers)


@app.get("/report/{username}")
def report(username: str) -> dict[str, Any]:
    """Transparency report: Detailed breakdown of what was actually observed."""
    user = valid_user(username)

    with closing(get_db()) as conn, conn.cursor() as cur:
        cur.execute(
            "SELECT camo_uniques, camo_loads, camo_windows, direct_uniques, direct_loads FROM user_totals WHERE username=%s",
            (user,),
        )
        tot_row = cur.fetchone()
        tot = tot_row if tot_row else {
            "camo_uniques": 0, "camo_loads": 0, "camo_windows": 0,
            "direct_uniques": 0, "direct_loads": 0,
        }

        cur.execute(
            "SELECT COUNT(DISTINCT visitor_key) FROM hits WHERE username=%s", (user,)
        )
        distinct_res = cur.fetchone()
        distinct_keys = next(iter(distinct_res.values())) if distinct_res else 0

        cur.execute(
            "SELECT COALESCE(SUM(conditional), 0) FROM hits WHERE username=%s", (user,)
        )
        cond_res = cur.fetchone()
        conditional = next(iter(cond_res.values())) if cond_res else 0

        cur.execute(
            """SELECT
                day,
                camo_uniques,
                camo_loads,
                camo_windows,
                direct_uniques,
                direct_loads
            FROM daily_stats
            WHERE username=%s
            ORDER BY day DESC
            LIMIT 30""",
            (user,),
        )
        daily_rows = cur.fetchall()
        per_day = list(daily_rows)

        cur.execute(
            """SELECT
                COALESCE(client_type, 'other') AS client_type,
                COUNT(*) AS count
            FROM hits
            WHERE username=%s
            GROUP BY client_type
            ORDER BY count DESC""",
            (user,),
        )
        type_rows = cur.fetchall()
        client_types = list(type_rows)

    total_loads = tot["camo_loads"] + tot["direct_loads"]
    camo_pct = round((tot["camo_loads"] / total_loads * 100), 1) if total_loads > 0 else 0.0

    return {
        "username": user,
        "metrics": {
            "camo_proxied": {
                "total_uniques_est": tot["camo_uniques"],
                "badge_loads": tot["camo_loads"],
                "active_windows": tot["camo_windows"],
            },
            "direct_requests": {
                "total_uniques_est": tot["direct_uniques"],
                "badge_loads": tot["direct_loads"],
            },
            "combined": {
                "total_loads": total_loads,
                "distinct_visitor_keys_retained": distinct_keys,
                "camo_percentage": camo_pct,
                "conditional_requests": conditional,
            },
            "verified_profile_visits": None,
        },
        "per_day": per_day,
        "client_types": client_types,
        "methodology": {
            "camo_proxied": "Requests routed through GitHub's image proxy (camo.githubusercontent.com) from README embeds.",
            "direct_requests": "Direct HTTP/curl requests made directly to this server.",
            "verified_profile_visits": "Always null. A static image badge cannot verify an actual GitHub profile page visit.",
        },
    }


@app.get("/privacy")
def privacy() -> dict[str, Any]:
    """Public privacy specification outlining data handling and retention guarantees."""
    return {
        "service": "ProfilePulse",
        "version": __version__,
        "guarantees": [
            "Zero PII: IP addresses and user agents are never stored in raw form. Only coarse client categories (e.g. github-camo, browser, script) and ephemeral daily HMAC hashes are kept.",
            "Ephemeral Daily Hashing: Visitor keys are generated using HMAC-SHA256 with the UTC date salted in, ensuring hashes rotate daily and cannot be linked across days.",
            "Strict 30-Day Retention: Raw telemetry and visitor hashes are purged after 30 days. Only aggregated counters are preserved.",
            "No Cookies: ProfilePulse sets zero cookies and performs no cross-site user tracking.",
        ],
        "retention_policy": {
            "raw_hits_days": RAW_RETENTION_DAYS,
            "aggregate_totals": "Indefinite counters per username",
        },
    }


@app.get("/health")
def health() -> dict[str, Any]:
    """Container health check for orchestrator probes."""
    try:
        with closing(get_db()) as conn, conn.cursor() as cur:
            cur.execute("SELECT 1")
        db_status = "connected"
    except (psycopg.Error, OSError) as exc:
        masked_err = str(exc)
        if DATABASE_URL:
            masked_err = masked_err.replace(DATABASE_URL, mask_db_url(DATABASE_URL))
        db_status = f"unhealthy: {masked_err}"

    return {
        "status": "ok" if db_status == "connected" else "degraded",
        "version": __version__,
        "database": db_status,
        "environment": ENV,
    }
