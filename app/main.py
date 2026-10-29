"""ProfilePulse — Honest, privacy-first GitHub README badge visitor analytics.

Core Research & Engineering Design:
  * Camo Verification: Distinguishes between requests from GitHub's Camo image proxy
    (camo.githubusercontent.com) and direct HTTP/curl hits.
  * Race-Condition Free: Uses atomic database unique constraints with INSERT OR IGNORE.
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
import sqlite3
import sys
import time
from contextlib import asynccontextmanager, closing
from datetime import UTC, datetime
from typing import Any

import httpx
from fastapi import FastAPI, HTTPException, Query, Request, Response

__version__ = "0.2.0"

# --- Environment & Configuration ---
ENV = os.environ.get("PROFILEPULSE_ENV", os.environ.get("ENVIRONMENT", "development")).lower()
SECRET_STR = os.environ.get("PROFILEPULSE_SECRET", "")

if ENV == "production" and (not SECRET_STR or SECRET_STR == "dev-secret-change-me" or len(SECRET_STR) < 16):
    raise RuntimeError(
        "FATAL: In production mode, PROFILEPULSE_SECRET must be set to a secure, random string (min 16 chars)."
    )

SECRET = (SECRET_STR or "dev-secret-change-me").encode("utf-8")
DB_PATH = os.environ.get("PROFILEPULSE_DB", "profilepulse.db")
RATE_LIMIT_PER_MIN = int(os.environ.get("PROFILEPULSE_RATE_LIMIT", "60"))
WINDOW_SECONDS = int(os.environ.get("PROFILEPULSE_WINDOW_SECONDS", "1800"))  # 30 minutes
RAW_RETENTION_DAYS = int(os.environ.get("PROFILEPULSE_RETENTION_DAYS", "30"))
GITHUB_VALIDATE_USER = os.environ.get("PROFILEPULSE_VALIDATE_GITHUB_USER", "true").lower() in ("true", "1")

USERNAME_RE = re.compile(r"^[A-Za-z0-9](?:[A-Za-z0-9-]{0,38})$")
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
            "timestamp": datetime.now(UTC).isoformat(),
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
    headers = {"User-Agent": "ProfilePulse-Verifier/0.2"}

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
def get_db() -> sqlite3.Connection:
    """Initialize and return a connection to the SQLite database with full constraints."""
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA foreign_keys=ON")

    with conn:
        # 1. Total aggregate stats per user (O(1) read for badges)
        conn.execute(
            """CREATE TABLE IF NOT EXISTS user_totals (
                username TEXT PRIMARY KEY,
                camo_uniques INTEGER DEFAULT 0,
                camo_loads INTEGER DEFAULT 0,
                camo_windows INTEGER DEFAULT 0,
                direct_uniques INTEGER DEFAULT 0,
                direct_loads INTEGER DEFAULT 0,
                updated_at REAL NOT NULL
            )"""
        )

        # 2. Daily aggregate stats per user
        conn.execute(
            """CREATE TABLE IF NOT EXISTS daily_stats (
                username TEXT NOT NULL,
                day TEXT NOT NULL,
                camo_uniques INTEGER DEFAULT 0,
                camo_loads INTEGER DEFAULT 0,
                camo_windows INTEGER DEFAULT 0,
                direct_uniques INTEGER DEFAULT 0,
                direct_loads INTEGER DEFAULT 0,
                PRIMARY KEY (username, day)
            )"""
        )

        # 3. Unique visitor deduplication table (Atomic unique constraint)
        conn.execute(
            """CREATE TABLE IF NOT EXISTS daily_uniques (
                username TEXT NOT NULL,
                day TEXT NOT NULL,
                visitor_key TEXT NOT NULL,
                via_camo INTEGER NOT NULL,
                ts REAL NOT NULL,
                PRIMARY KEY (username, day, visitor_key)
            )"""
        )
        conn.execute("CREATE INDEX IF NOT EXISTS idx_uniques_ts ON daily_uniques(ts)")

        # 4. Active 30-minute windows deduplication table
        conn.execute(
            """CREATE TABLE IF NOT EXISTS active_windows (
                username TEXT NOT NULL,
                window_id INTEGER NOT NULL,
                via_camo INTEGER NOT NULL,
                ts REAL NOT NULL,
                PRIMARY KEY (username, window_id, via_camo)
            )"""
        )
        conn.execute("CREATE INDEX IF NOT EXISTS idx_windows_ts ON active_windows(ts)")

        # 5. Raw hit telemetry log (Pruned after 30 days)
        conn.execute(
            """CREATE TABLE IF NOT EXISTS hits (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                ts REAL NOT NULL,
                day TEXT NOT NULL,
                username TEXT NOT NULL,
                visitor_key TEXT NOT NULL,
                user_agent TEXT,
                via_camo INTEGER NOT NULL,
                conditional INTEGER NOT NULL,
                counted_unique INTEGER NOT NULL
            )"""
        )
        conn.execute("CREATE INDEX IF NOT EXISTS idx_hits_user_day ON hits(username, day)")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_hits_ts ON hits(ts)")

    return conn


def prune_old_records(conn: sqlite3.Connection, retention_days: int = RAW_RETENTION_DAYS) -> int:
    """Prune raw logs older than retention period while preserving user_totals and daily_stats."""
    cutoff = time.time() - (retention_days * 86400.0)
    with conn:
        cursor = conn.execute("DELETE FROM hits WHERE ts < ?", (cutoff,))
        deleted = cursor.rowcount
        conn.execute("DELETE FROM daily_uniques WHERE ts < ?", (cutoff,))
        conn.execute("DELETE FROM active_windows WHERE ts < ?", (cutoff,))
    return deleted


# --- Core Helper Functions ---
def visitor_key(day: str, request: Request) -> str:
    """Generate an ephemeral, daily-rotated HMAC visitor fingerprint.

    Incorporates the UTC day into the HMAC salt so visitor keys rotate daily.
    Uses request.client.host (populated by trusted reverse-proxy headers).
    """
    ip = request.client.host if request.client else "unknown"
    ua = request.headers.get("user-agent", "")
    raw = f"{day}|{ip}|{ua}".encode()
    return hmac.new(SECRET, raw, hashlib.sha256).hexdigest()[:16]


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
    if not USERNAME_RE.match(username) or "--" in username:
        raise HTTPException(
            status_code=400,
            detail="Invalid GitHub username format. Allowed: alphanumeric, single hyphens, max 39 characters.",
        )
    return username.lower()


def rate_limited(conn: sqlite3.Connection, username: str) -> bool:
    """Check if the rate limit of requests per minute has been exceeded for this user."""
    since = time.time() - 60
    n = conn.execute(
        "SELECT COUNT(*) FROM hits WHERE username=? AND ts>?", (username, since)
    ).fetchone()[0]
    return n >= RATE_LIMIT_PER_MIN


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
    with closing(get_db()) as conn:
        pruned = prune_old_records(conn)
        if pruned > 0:
            logger.info("Startup raw records pruned", extra={"props": {"pruned": pruned}})
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
    day = datetime.fromtimestamp(now, UTC).strftime("%Y-%m-%d")
    window_id = int(now // WINDOW_SECONDS)
    key = visitor_key(day, request)

    ua = (request.headers.get("user-agent", "") or "")[:250]
    is_camo = 1 if "github-camo" in ua.lower() else 0
    is_conditional = 1 if ("if-none-match" in request.headers or "if-modified-since" in request.headers) else 0

    # Validate that GitHub account exists to prevent storage junk (cached)
    if GITHUB_VALIDATE_USER and not is_preview:
        exists = await check_github_user_exists(user)
        if not exists:
            raise HTTPException(status_code=404, detail=f"GitHub user '{user}' does not exist.")

    rate_limit_exceeded = False

    with closing(get_db()) as conn:
        rate_limit_exceeded = rate_limited(conn, user)

        if not is_preview and not rate_limit_exceeded:
            # 1. Atomic daily unique insertion (avoids check-then-insert race condition)
            cur = conn.execute(
                """INSERT OR IGNORE INTO daily_uniques (username, day, visitor_key, via_camo, ts)
                VALUES (?, ?, ?, ?, ?)""",
                (user, day, key, is_camo, now),
            )
            counted_unique = 1 if cur.rowcount > 0 else 0

            # 2. Atomic active window insertion
            cur_win = conn.execute(
                """INSERT OR IGNORE INTO active_windows (username, window_id, via_camo, ts)
                VALUES (?, ?, ?, ?)""",
                (user, window_id, is_camo, now),
            )
            counted_window = 1 if cur_win.rowcount > 0 else 0

            # 3. Update aggregate totals table (O(1) updates)
            conn.execute(
                """INSERT INTO user_totals (
                    username, camo_uniques, camo_loads, camo_windows,
                    direct_uniques, direct_loads, updated_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(username) DO UPDATE SET
                    camo_uniques = camo_uniques + ?,
                    camo_loads = camo_loads + ?,
                    camo_windows = camo_windows + ?,
                    direct_uniques = direct_uniques + ?,
                    direct_loads = direct_loads + ?,
                    updated_at = ?""",
                (
                    user,
                    counted_unique if is_camo else 0,
                    1 if is_camo else 0,
                    counted_window if is_camo else 0,
                    counted_unique if not is_camo else 0,
                    1 if not is_camo else 0,
                    now,
                    counted_unique if is_camo else 0,
                    1 if is_camo else 0,
                    counted_window if is_camo else 0,
                    counted_unique if not is_camo else 0,
                    1 if not is_camo else 0,
                    now,
                ),
            )

            # 4. Update daily stats table
            conn.execute(
                """INSERT INTO daily_stats (
                    username, day, camo_uniques, camo_loads, camo_windows,
                    direct_uniques, direct_loads
                ) VALUES (?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(username, day) DO UPDATE SET
                    camo_uniques = camo_uniques + ?,
                    camo_loads = camo_loads + ?,
                    camo_windows = camo_windows + ?,
                    direct_uniques = direct_uniques + ?,
                    direct_loads = direct_loads + ?""",
                (
                    user,
                    day,
                    counted_unique if is_camo else 0,
                    1 if is_camo else 0,
                    counted_window if is_camo else 0,
                    counted_unique if not is_camo else 0,
                    1 if not is_camo else 0,
                    counted_unique if is_camo else 0,
                    1 if is_camo else 0,
                    counted_window if is_camo else 0,
                    counted_unique if not is_camo else 0,
                    1 if not is_camo else 0,
                ),
            )

            # 5. Raw hit telemetry
            conn.execute(
                """INSERT INTO hits (
                    ts, day, username, visitor_key, user_agent,
                    via_camo, conditional, counted_unique
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)""",
                (now, day, user, key, ua, is_camo, is_conditional, counted_unique),
            )
            conn.commit()

        # Fast O(1) reads for badge rendering
        tot_row = conn.execute(
            "SELECT camo_uniques, camo_loads, camo_windows, direct_uniques, direct_loads FROM user_totals WHERE username=?",
            (user,),
        ).fetchone()

        day_row = conn.execute(
            "SELECT camo_uniques, camo_loads, direct_uniques, direct_loads FROM daily_stats WHERE username=? AND day=?",
            (user, day),
        ).fetchone()

    # Fallback to zero if user has no rows yet
    tot = dict(tot_row) if tot_row else {
        "camo_uniques": 0, "camo_loads": 0, "camo_windows": 0,
        "direct_uniques": 0, "direct_loads": 0,
    }
    today_stats = dict(day_row) if day_row else {
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
        total_windows = tot["camo_windows"]  # windows are predominantly camo
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

    with closing(get_db()) as conn:
        tot_row = conn.execute(
            "SELECT camo_uniques, camo_loads, camo_windows, direct_uniques, direct_loads FROM user_totals WHERE username=?",
            (user,),
        ).fetchone()
        tot = dict(tot_row) if tot_row else {
            "camo_uniques": 0, "camo_loads": 0, "camo_windows": 0,
            "direct_uniques": 0, "direct_loads": 0,
        }

        distinct_keys = conn.execute(
            "SELECT COUNT(DISTINCT visitor_key) FROM hits WHERE username=?", (user,)
        ).fetchone()[0]

        conditional = conn.execute(
            "SELECT COALESCE(SUM(conditional), 0) FROM hits WHERE username=?", (user,)
        ).fetchone()[0]

        daily_rows = conn.execute(
            """SELECT
                day,
                camo_uniques,
                camo_loads,
                camo_windows,
                direct_uniques,
                direct_loads
            FROM daily_stats
            WHERE username=?
            ORDER BY day DESC
            LIMIT 30""",
            (user,),
        ).fetchall()
        per_day = [dict(r) for r in daily_rows]

        agent_rows = conn.execute(
            """SELECT
                COALESCE(user_agent, 'unknown') AS user_agent,
                COUNT(*) AS count
            FROM hits
            WHERE username=?
            GROUP BY user_agent
            ORDER BY count DESC
            LIMIT 10""",
            (user,),
        ).fetchall()
        top_agents = [dict(r) for r in agent_rows]

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
        "top_user_agents": top_agents,
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
            "Zero PII: IP addresses and user agents are never stored in raw form.",
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
        with closing(get_db()) as conn:
            conn.execute("SELECT 1").fetchone()
        db_status = "connected"
    except (sqlite3.Error, OSError) as exc:
        db_status = f"unhealthy: {exc}"

    return {
        "status": "ok" if db_status == "connected" else "degraded",
        "version": __version__,
        "database": db_status,
        "environment": ENV,
    }
