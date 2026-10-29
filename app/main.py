"""ProfilePulse — Honest, privacy-first GitHub README badge visitor analytics.

Core Research Objective:
Measure what can actually be observed when embedding an image badge in a GitHub profile.
Distinguishes between:
  * Badge Loads: every HTTP request received by this server.
  * Daily Uniques (est.): at most one count per (username, UTC day, visitor_key).
  * Active Windows: count of distinct time windows (e.g., 30 mins) with observed activity.
  * Verified Profile Visits: null (unobservable from a README image; never fabricated).
"""

from __future__ import annotations

import hashlib
import hmac
import os
import re
import sqlite3
import time
from contextlib import closing
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from fastapi import FastAPI, HTTPException, Query, Request, Response

__version__ = "0.1.0"

# Configuration
DB_PATH = os.environ.get("PROFILEPULSE_DB", "profilepulse.db")
SECRET = os.environ.get("PROFILEPULSE_SECRET", "dev-secret-change-me").encode("utf-8")
USERNAME_RE = re.compile(r"^[A-Za-z0-9](?:[A-Za-z0-9-]{0,38})$")
RATE_LIMIT_PER_MIN = int(os.environ.get("PROFILEPULSE_RATE_LIMIT", "60"))
WINDOW_SECONDS = int(os.environ.get("PROFILEPULSE_WINDOW_SECONDS", "1800"))  # 30 minutes

# Named colors mapping for badge customization
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
    "informational": "#007ec6",
    "success": "#2ea043",
    "critical": "#e05d44",
}
HEX_COLOR_RE = re.compile(r"^#?([0-9a-fA-F]{3}|[0-9a-fA-F]{6})$")

app = FastAPI(
    title="ProfilePulse",
    description="Honest GitHub README badge counter with privacy-preserving analytics.",
    version=__version__,
)


def get_db() -> sqlite3.Connection:
    """Initialize and return a connection to the SQLite database."""
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    conn.execute(
        """CREATE TABLE IF NOT EXISTS hits (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            ts REAL NOT NULL,
            day TEXT NOT NULL,
            window_id INTEGER NOT NULL,
            username TEXT NOT NULL,
            visitor_key TEXT NOT NULL,
            user_agent TEXT,
            via_camo INTEGER NOT NULL,
            conditional INTEGER NOT NULL,
            forwarded_for INTEGER NOT NULL,
            counted_unique INTEGER NOT NULL
        )"""
    )
    conn.execute("CREATE INDEX IF NOT EXISTS idx_hits_user_day ON hits(username, day)")
    conn.execute("CREATE INDEX IF NOT EXISTS idx_hits_user_ts ON hits(username, ts)")
    conn.execute("CREATE INDEX IF NOT EXISTS idx_hits_user_window ON hits(username, window_id)")
    return conn


def visitor_key(request: Request) -> str:
    """Generate a privacy-preserving HMAC fingerprint for deduplication.

    Does not store or reveal raw IP addresses.
    """
    ip = request.client.host if request.client else "unknown"
    xff = request.headers.get("x-forwarded-for", "")
    ua = request.headers.get("user-agent", "")
    raw = f"{ip}|{xff}|{ua}".encode("utf-8")
    return hmac.new(SECRET, raw, hashlib.sha256).hexdigest()[:16]


def sanitize_color(color_input: Optional[str]) -> str:
    """Validate and sanitize the badge color to prevent SVG injection."""
    if not color_input:
        return "#2ea043"

    color_lower = color_input.strip().lower()
    if color_lower in SAFE_COLORS:
        return SAFE_COLORS[color_lower]

    match = HEX_COLOR_RE.match(color_lower)
    if match:
        hex_val = match.group(1)
        return f"#{hex_val}"

    return "#2ea043"


def escape_xml(s: str) -> str:
    """Escape special characters for safe inclusion in SVG markup."""
    return (
        s.replace("&", "&amp;")
        .replace("<", "&lt;")
        .replace(">", "&gt;")
        .replace('"', "&quot;")
        .replace("'", "&#39;")
    )


def render_svg(label: str, value: str, color: str = "#2ea043") -> str:
    """Generate an accessible, Shields-style SVG badge."""
    label_esc = escape_xml(label)
    value_esc = escape_xml(value)

    # Approximate width based on character count
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
    """Check if the rate limit of requests per minute has been exceeded for this username."""
    since = time.time() - 60
    n = conn.execute(
        "SELECT COUNT(*) FROM hits WHERE username=? AND ts>?", (username, since)
    ).fetchone()[0]
    return n >= RATE_LIMIT_PER_MIN


def normalize_metric(metric: str) -> str:
    """Normalize metric aliases to standard metric keys."""
    m = metric.strip().lower()
    if m in ("unique", "uniques", "daily_unique", "daily_uniques"):
        return "unique"
    if m in ("loads", "load", "badge_loads"):
        return "loads"
    if m in ("windows", "window", "active", "active_windows"):
        return "windows"
    raise HTTPException(
        status_code=400,
        detail="Metric must be one of: 'unique' (Daily Uniques est.), 'loads' (Badge Loads), or 'windows' (Active Windows).",
    )


@app.get("/badge/{username}")
@app.get("/badge/{username}.svg")
def badge(
    username: str,
    request: Request,
    metric: str = Query("unique", description="Metric type: 'unique', 'loads', or 'windows'"),
    label: str = Query("", description="Custom label for the badge"),
    color: str = Query("", description="Custom badge color (hex code or name)"),
    ignore_owner: bool = Query(
        False,
        description="If true, do not increment or record hit (useful for previewing without self-counting)",
    ),
):
    """Serve an SVG counter badge for a GitHub username.

    Records the request and computes the requested metric:
    - 'unique': Daily Uniques (est.) — at most 1 count per visitor key per UTC day.
    - 'loads': Badge Loads — total requests reaching the server.
    - 'windows': Active Windows — distinct 30-minute activity blocks (resists refresh spam).
    """
    user = valid_user(username)
    metric_type = normalize_metric(metric)

    # Determine default label based on metric
    if not label:
        if metric_type == "unique":
            display_label = "Daily Uniques (est.)"
        elif metric_type == "windows":
            display_label = "Active Windows"
        else:
            display_label = "Badge Loads"
    else:
        display_label = label[:32]

    now = time.time()
    day = datetime.fromtimestamp(now, timezone.utc).strftime("%Y-%m-%d")
    window_id = int(now // WINDOW_SECONDS)
    key = visitor_key(request)
    ua = (request.headers.get("user-agent", "") or "")[:250]

    rate_limit_exceeded = False

    with closing(get_db()) as conn:
        rate_limit_exceeded = rate_limited(conn, user)

        # Record hit if not ignored and not rate-limited
        if not ignore_owner and not rate_limit_exceeded:
            seen_today = conn.execute(
                "SELECT 1 FROM hits WHERE username=? AND day=? AND visitor_key=? AND counted_unique=1",
                (user, day, key),
            ).fetchone()
            counted_unique = 0 if seen_today else 1

            conn.execute(
                """INSERT INTO hits(
                    ts, day, window_id, username, visitor_key, user_agent,
                    via_camo, conditional, forwarded_for, counted_unique
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                (
                    now,
                    day,
                    window_id,
                    user,
                    key,
                    ua,
                    int("camo" in ua.lower()),
                    int("if-none-match" in request.headers or "if-modified-since" in request.headers),
                    int("x-forwarded-for" in request.headers),
                    counted_unique,
                ),
            )
            conn.commit()

        # Query the metric value
        if metric_type == "unique":
            val = conn.execute(
                "SELECT COALESCE(SUM(counted_unique), 0) FROM hits WHERE username=?", (user,)
            ).fetchone()[0]
        elif metric_type == "windows":
            val = conn.execute(
                "SELECT COUNT(DISTINCT window_id) FROM hits WHERE username=?", (user,)
            ).fetchone()[0]
        else:
            val = conn.execute(
                "SELECT COUNT(*) FROM hits WHERE username=?", (user,)
            ).fetchone()[0]

    svg_content = render_svg(display_label, f"{val:,}", color)

    headers = {
        "Content-Type": "image/svg+xml",
        "Cache-Control": "max-age=0, no-cache, no-store, must-revalidate, private",
        "Pragma": "no-cache",
        "Expires": "0",
    }
    if rate_limit_exceeded:
        headers["X-RateLimit-Exceeded"] = "true"

    return Response(
        content=svg_content,
        media_type="image/svg+xml",
        headers=headers,
    )


@app.get("/report/{username}")
def report(username: str) -> Dict[str, Any]:
    """Experiment report: What did ProfilePulse actually observe for this username?

    Includes telemetry on GitHub Camo proxying, conditional requests, user agents,
    and distinct visitor keys to help evaluate measurement feasibility.
    """
    user = valid_user(username)

    with closing(get_db()) as conn:
        def scalar(sql: str, *args: Any) -> int:
            row = conn.execute(sql, args).fetchone()
            return row[0] if row else 0

        total_loads = scalar("SELECT COUNT(*) FROM hits WHERE username=?", user)
        distinct_keys = scalar("SELECT COUNT(DISTINCT visitor_key) FROM hits WHERE username=?", user)
        daily_uniques_est = scalar("SELECT COALESCE(SUM(counted_unique), 0) FROM hits WHERE username=?", user)
        active_windows = scalar("SELECT COUNT(DISTINCT window_id) FROM hits WHERE username=?", user)
        via_camo = scalar("SELECT COALESCE(SUM(via_camo), 0) FROM hits WHERE username=?", user)
        conditional = scalar("SELECT COALESCE(SUM(conditional), 0) FROM hits WHERE username=?", user)
        forwarded_for = scalar("SELECT COALESCE(SUM(forwarded_for), 0) FROM hits WHERE username=?", user)

        per_day_rows = conn.execute(
            """SELECT
                day,
                COUNT(*) AS loads,
                COUNT(DISTINCT visitor_key) AS distinct_keys,
                COUNT(DISTINCT window_id) AS active_windows,
                COALESCE(SUM(counted_unique), 0) AS daily_uniques_est
            FROM hits
            WHERE username=?
            GROUP BY day
            ORDER BY day DESC""",
            (user,),
        ).fetchall()
        per_day = [dict(r) for r in per_day_rows]

        agent_rows = conn.execute(
            """SELECT
                COALESCE(user_agent, 'unknown') AS user_agent,
                COUNT(*) AS n
            FROM hits
            WHERE username=?
            GROUP BY user_agent
            ORDER BY n DESC
            LIMIT 10""",
            (user,),
        ).fetchall()
        top_agents = [dict(r) for r in agent_rows]

    # Evaluate decision gate signal
    if distinct_keys <= 1 and total_loads > 5:
        camo_status = "Visitors appear hidden behind GitHub's Camo proxy (distinct_visitor_keys remains ~1). Daily uniques may be undercounted."
    elif distinct_keys > 1:
        camo_status = "Distinct visitor keys observed across requests. Distinct clients reach the server."
    else:
        camo_status = "Awaiting sufficient traffic data to evaluate proxy transparency."

    return {
        "username": user,
        "badge_loads": total_loads,
        "daily_uniques_est": daily_uniques_est,
        "active_windows": active_windows,
        "distinct_visitor_keys": distinct_keys,
        "via_camo": via_camo,
        "conditional_requests": conditional,
        "with_x_forwarded_for": forwarded_for,
        "per_day": per_day,
        "top_user_agents": top_agents,
        "verified_profile_visits": None,  # Intentionally null: unobservable from an image request
        "proxy_analysis": {
            "camo_request_percentage": round((via_camo / total_loads * 100), 1) if total_loads > 0 else 0.0,
            "signal": camo_status,
        },
        "methodology": {
            "badge_loads": "Total HTTP requests that reached this server.",
            "daily_uniques_est": "Counts at most one hit per (day, visitor_key). Note: If GitHub Camo proxies requests, multiple visitors may share a key.",
            "active_windows": "Count of distinct 30-minute intervals with observed hits. Resists refresh spam without needing visitor identification.",
            "verified_profile_visits": "Always null. A README image cannot verify an actual GitHub profile page visit.",
        },
    }


@app.get("/health")
def health() -> Dict[str, Any]:
    """Health check endpoint for container uptime and orchestrator probes."""
    try:
        with closing(get_db()) as conn:
            conn.execute("SELECT 1").fetchone()
        db_status = "connected"
    except Exception as exc:
        db_status = f"unhealthy: {exc}"

    return {
        "status": "ok" if db_status == "connected" else "degraded",
        "version": __version__,
        "database": db_status,
    }
