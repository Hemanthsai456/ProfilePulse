"""ProfilePulse — Honest, privacy-first GitHub README badge visitor analytics.

Core Research & Engineering Design:
  * Camo Verification: Distinguishes between requests from GitHub's Camo image proxy
    (camo.githubusercontent.com) and direct HTTP/curl hits.
  * Race-Condition Free: Uses atomic PostgreSQL unique constraints with ON CONFLICT DO NOTHING.
  * Keyed Visitor Hashes: Viewer IPs are HMAC-hashed with a server secret so repeat visits can be recognized
    for PROFILEPULSE_DEDUPE_DAYS without storing the IP.
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
from datetime import datetime, timedelta, timezone
from typing import Any

import httpx
import psycopg
from fastapi import FastAPI, HTTPException, Query, Request, Response
from psycopg.rows import dict_row

__version__ = "0.5.0"

# Indian Standard Time (UTC+05:30). Daily counters roll over at IST midnight,
# and human-readable timestamp columns are stored in IST.
IST = timezone(timedelta(hours=5, minutes=30), name="IST")
IST_LABEL = "Asia/Kolkata (UTC+05:30)"


def ist_day(ts: float) -> str:
    """Return the IST calendar date (YYYY-MM-DD) for a Unix timestamp."""
    return datetime.fromtimestamp(ts, IST).strftime("%Y-%m-%d")


def ist_stamp(ts: float) -> str:
    """Return a human-readable IST timestamp, e.g. '2026-11-12 21:07:03 IST'."""
    return datetime.fromtimestamp(ts, IST).strftime("%Y-%m-%d %H:%M:%S") + " IST"

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
# A visitor is counted once, then not again until this many days have passed since they were last counted.
DEDUPE_DAYS = int(os.environ.get("PROFILEPULSE_DEDUPE_DAYS", "30"))
# Loads of the same profile by the same client type within this many seconds are one visit
# (a double fetch in one page load), even if they arrive with different viewer keys.
BURST_SECONDS = int(os.environ.get("PROFILEPULSE_BURST_SECONDS", "60"))
# Owner exclusion (opt-in): comma-separated visitor keys (from the hits table) whose loads are not counted.
OWNER_VISITOR_KEYS = frozenset(
    k.strip() for k in os.environ.get("PROFILEPULSE_OWNER_VISITOR_KEYS", "").split(",") if k.strip()
)
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


# Every table the app owns. Each gets Row Level Security at startup.
APP_TABLES = ("user_totals", "daily_stats", "daily_uniques", "active_windows", "hits", "visitor_seen")


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
        cur.execute("CREATE INDEX IF NOT EXISTS idx_hits_burst ON hits(username, via_camo, ts)")
        # Privacy-safe dedupe diagnostics (counts and IP version only, never the IP itself).
        cur.execute("ALTER TABLE hits ADD COLUMN IF NOT EXISTS xff_count INTEGER")
        cur.execute("ALTER TABLE hits ADD COLUMN IF NOT EXISTS ip_version TEXT")
        cur.execute("ALTER TABLE hits ADD COLUMN IF NOT EXISTS burst_collapsed INTEGER NOT NULL DEFAULT 0")

        # 6. Stable visitor dedupe: one row per visitor, stamped when they were last counted.
        #    A visitor is counted again only after DEDUPE_DAYS have passed since last_counted.
        cur.execute(
            """CREATE TABLE IF NOT EXISTS visitor_seen (
                username TEXT NOT NULL,
                visitor_key TEXT NOT NULL,
                via_camo INTEGER NOT NULL,
                last_counted DOUBLE PRECISION NOT NULL,
                last_counted_ist TEXT,
                PRIMARY KEY (username, visitor_key, via_camo)
            )"""
        )
        cur.execute("CREATE INDEX IF NOT EXISTS idx_visitor_seen_last ON visitor_seen(last_counted)")

        # 7. IST timestamp columns (migration, non-destructive). Existing rows are kept;
        #    new columns are added with IF NOT EXISTS and backfilled from the epoch `ts`.
        ist_expr = "to_char(to_timestamp({col}) AT TIME ZONE 'Asia/Kolkata', 'YYYY-MM-DD HH24:MI:SS') || ' IST'"
        migrations = [
            ("hits", "ts_ist", "ts"),
            ("daily_uniques", "first_seen_ist", "ts"),
            ("active_windows", "first_seen_ist", "ts"),
            ("user_totals", "updated_at_ist", "updated_at"),
        ]
        for table, column, src in migrations:
            cur.execute(f"ALTER TABLE {table} ADD COLUMN IF NOT EXISTS {column} TEXT")
            cur.execute(
                f"UPDATE {table} SET {column} = {ist_expr.format(col=src)} WHERE {column} IS NULL"
            )

        # 8. Row Level Security on every app table. Supabase's Data API exposes the public
        #    schema, so without RLS anyone with the project URL and anon key could read hits and
        #    visitor hashes. With RLS enabled and no policies, anon/authenticated access is denied.
        #    The table owner and the postgres role bypass RLS, so the app's own connection is unaffected.
        for table in APP_TABLES:
            cur.execute(f"ALTER TABLE {table} ENABLE ROW LEVEL SECURITY")
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
        # Visitor hashes are only needed while they can still block a repeat count.
        cur.execute(
            "DELETE FROM visitor_seen WHERE last_counted < %s",
            (time.time() - (DEDUPE_DAYS * 86400.0),),
        )
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


def viewer_ip(request: Request) -> str:
    """Best-effort IP of the person viewing the badge.

    Camo forwards the viewer's IP as the first X-Forwarded-For entry. That entry is only
    trusted when PROFILEPULSE_TRUST_PROXY is enabled. Without it, the connecting host
    (GitHub's proxy) is used, which collapses all viewers into one visitor.
    """
    if TRUST_PROXY:
        xff = request.headers.get("x-forwarded-for")
        if xff:
            parts = [p.strip() for p in xff.split(",") if p.strip()]
            if parts and _is_valid_ip(parts[0]):
                return parts[0]
    return get_client_ip(request)


def _is_valid_ip(value: str) -> bool:
    """True only for a syntactically valid IP address. Rejects junk, which would otherwise become a visitor key."""
    import ipaddress

    try:
        ipaddress.ip_address(value)
    except ValueError:
        return False
    return True


def normalize_ip(ip: str) -> str:
    """Collapse an IPv6 address to its /64 prefix, so one connection keeps one visitor key
    even when the address changes within the prefix. IPv4 addresses are returned unchanged."""
    import ipaddress

    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return ip
    if addr.version == 6:
        return str(ipaddress.ip_network(f"{ip}/64", strict=False))
    return str(addr)


def viewer_diagnostics(request: Request) -> tuple[int, str]:
    """Privacy-safe diagnostics for dedupe debugging: the number of X-Forwarded-For entries
    and the IP version ('v4', 'v6' or 'none'). Never returns the raw IP."""
    xff = request.headers.get("x-forwarded-for", "") if TRUST_PROXY else ""
    count = len([p for p in xff.split(",") if p.strip()])
    ip = viewer_ip(request)
    if not ip or ip == "unknown":
        return count, "none"
    return count, ("v6" if ":" in ip else "v4")


def visitor_key(request: Request) -> str:
    """Stable keyed visitor fingerprint: HMAC-SHA256 of the normalized viewer IP with the server secret.

    Not rotated daily, so repeat visits can be recognized for DEDUPE_DAYS.
    The raw IP is never stored.
    """
    ip = normalize_ip(viewer_ip(request))
    return hmac.new(SECRET, f"visitor|{ip}".encode(), hashlib.sha256).hexdigest()[:16]


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
    if not TRUST_PROXY:
        message = (
            "PROFILEPULSE_TRUST_PROXY is off: every viewer appears as GitHub's proxy address, "
            "so repeat visitors cannot be told apart and counts will be badly undercounted. "
            "Enable it behind Render or another trusted reverse proxy."
        )
        if ENV == "production":
            logger.warning(message, extra={"props": {"trust_proxy": False, "env": ENV}})
        else:
            logger.info(message, extra={"props": {"trust_proxy": False, "env": ENV}})
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
    day = ist_day(now)  # daily counters reset at IST midnight (00:00 +05:30)
    stamp = ist_stamp(now)
    window_id = int(now // WINDOW_SECONDS)
    key = visitor_key(request)
    is_owner = key in OWNER_VISITOR_KEYS
    xff_count, ip_version = viewer_diagnostics(request)

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
        if not is_preview and not rate_limit_exceeded and not is_owner:
            # 1a. Burst collapse: a second counted load of this profile by the same client
            #     type within BURST_SECONDS is the same page load, not a new visitor.
            cur.execute(
                """SELECT 1 FROM hits
                WHERE username = %s AND via_camo = %s AND counted_unique = 1 AND ts > %s
                LIMIT 1""",
                (user, is_camo, now - BURST_SECONDS),
            )
            in_burst = cur.fetchone() is not None

            # 1b. Atomic unique check: count a visitor only if they are new, or their last
            #     counted visit is older than DEDUPE_DAYS. A single statement avoids races.
            burst_collapsed = 1 if in_burst else 0
            if in_burst:
                counted_unique = 0
            else:
                cutoff = now - (DEDUPE_DAYS * 86400.0)
                cur.execute(
                    """INSERT INTO visitor_seen (username, visitor_key, via_camo, last_counted, last_counted_ist)
                    VALUES (%s, %s, %s, %s, %s)
                    ON CONFLICT (username, visitor_key, via_camo) DO UPDATE SET
                        last_counted = EXCLUDED.last_counted,
                        last_counted_ist = EXCLUDED.last_counted_ist
                    WHERE visitor_seen.last_counted < %s
                    RETURNING 1""",
                    (user, key, is_camo, now, stamp, cutoff),
                )
                counted_unique = 1 if cur.fetchone() else 0

            # 2. Atomic active window insertion
            cur.execute(
                """INSERT INTO active_windows (username, window_id, via_camo, ts, first_seen_ist)
                VALUES (%s, %s, %s, %s, %s)
                ON CONFLICT DO NOTHING""",
                (user, window_id, is_camo, now, stamp),
            )
            counted_window = 1 if cur.rowcount > 0 else 0

            # 3. Update aggregate totals table (O(1) updates)
            cur.execute(
                """INSERT INTO user_totals (
                    username, camo_uniques, camo_loads, camo_windows,
                    direct_uniques, direct_loads, updated_at, updated_at_ist
                ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s)
                ON CONFLICT (username) DO UPDATE SET
                    camo_uniques = user_totals.camo_uniques + EXCLUDED.camo_uniques,
                    camo_loads = user_totals.camo_loads + EXCLUDED.camo_loads,
                    camo_windows = user_totals.camo_windows + EXCLUDED.camo_windows,
                    direct_uniques = user_totals.direct_uniques + EXCLUDED.direct_uniques,
                    direct_loads = user_totals.direct_loads + EXCLUDED.direct_loads,
                    updated_at = EXCLUDED.updated_at,
                    updated_at_ist = EXCLUDED.updated_at_ist""",
                (
                    user,
                    counted_unique if is_camo else 0,
                    1 if is_camo else 0,
                    counted_window if is_camo else 0,
                    counted_unique if not is_camo else 0,
                    1 if not is_camo else 0,
                    now,
                    stamp,
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
                    via_camo, conditional, counted_unique, ts_ist, xff_count, ip_version, burst_collapsed
                ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)""",
                (now, day, user, key, client_cat, is_camo, is_conditional, counted_unique, stamp,
                 xff_count, ip_version, burst_collapsed),
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
        display_label = label[:32] if label else "Visitors (est.)"
        display_value = f"{format_number(today_unique)} today · {format_number(total_unique)} total"
    elif metric_type == "today":
        display_label = label[:32] if label else "Visitors Today (est.)"
        display_value = format_number(today_unique)
    elif metric_type == "windows":
        display_label = label[:32] if label else "Active Windows"
        display_value = format_number(total_windows)
    elif metric_type == "loads":
        display_label = label[:32] if label else "Badge Loads"
        display_value = format_number(total_loads)
    else:  # 'unique' (default)
        display_label = label[:32] if label else "Unique Visitors (est.)"
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
            "SELECT camo_uniques, camo_loads, camo_windows, direct_uniques, direct_loads, updated_at_ist "
            "FROM user_totals WHERE username=%s",
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

    with closing(get_db()) as conn, conn.cursor() as cur:
        cur.execute("SELECT COUNT(*) AS n FROM hits WHERE username = %s AND burst_collapsed = 1", (user,))
        burst_row = cur.fetchone()
    burst_collapses = burst_row["n"] if burst_row else 0

    return {
        "username": user,
        "dedupe_days": DEDUPE_DAYS,
        "trust_proxy": TRUST_PROXY,
        "owner_exclusion_keys_configured": len(OWNER_VISITOR_KEYS),
        "viewer_identity": (
            "First X-Forwarded-For entry (viewer IP), hashed"
            if TRUST_PROXY
            else "Connecting host only (GitHub proxy). Repeat visitors cannot be told apart; counts are undercounted."
        ),
        "today_definition": "Visitors first counted today, IST (+05:30). Repeat visits within the dedupe period are not counted again.",
        "burst_collapses": burst_collapses,
        "burst_collapses_note": (
            f"Double loads of the same profile within {BURST_SECONDS} seconds, counted as one visit. "
            f"Covers the raw-log retention window ({RAW_RETENTION_DAYS} days)."
        ),
        "timezone": IST_LABEL,
        "day_boundary": "Daily counters reset at 00:00 IST (+05:30).",
        "last_updated_ist": tot_row.get("updated_at_ist") if tot_row else None,
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
            "Zero PII: IP addresses and user agents are never stored in raw form. Only coarse client categories (e.g. github-camo, browser, script) and keyed visitor hashes are kept.",
            "Keyed Visitor Hashing: Visitors are identified by HMAC-SHA256 of their IP with a server-side secret. The hash is stable so repeat visits are not counted again, and it cannot be reversed to an IP without the secret.",
            "Bounded Hash Lifetime: A visitor hash is deleted once that visitor has not been counted for PROFILEPULSE_DEDUPE_DAYS (default 30 days). Raw telemetry is purged after RAW_RETENTION_DAYS.",
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
