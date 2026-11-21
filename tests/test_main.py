"""Unit and integration tests for ProfilePulse (PostgreSQL / Supabase)."""

import concurrent.futures
import os
import time
import urllib.parse
import xml.etree.ElementTree as ET
from contextlib import closing
from unittest.mock import AsyncMock, patch

import httpx
import psycopg
import pytest
from fastapi import HTTPException
from fastapi.testclient import TestClient

import app.main as app_module
from app.main import app, prune_old_records, render_svg

TEST_DB_URL = os.environ.get("TEST_DATABASE_URL", "").strip()
PROD_DB_URL = os.environ.get("DATABASE_URL", "").strip()


def normalize_host(host: str | None) -> str:
    """Normalize hostname, treating local loopback aliases identically."""
    h = (host or "").lower()
    if h in ("localhost", "127.0.0.1", "::1"):
        return "localhost"
    return h


def parse_db_target(url: str) -> tuple[str, str]:
    """Extract normalized (host, database_name) from a PostgreSQL connection URL."""
    if not url:
        return "", ""
    parsed = urllib.parse.urlsplit(url)
    db_name = parsed.path.strip("/").split("/")[0] if parsed.path else ""
    return normalize_host(parsed.hostname), db_name


def validate_test_db_safety(test_db_url: str, prod_db_url: str) -> None:
    """Enforce test database naming conventions and prevent running tests against production."""
    if not test_db_url:
        return
    test_host, test_db = parse_db_target(test_db_url)
    if not test_db.endswith("_test"):
        raise ValueError(
            f"FATAL: Refusing to run tests because TEST_DATABASE_URL database name '{test_db}' "
            "does not end with '_test'."
        )
    if prod_db_url:
        prod_host, prod_db = parse_db_target(prod_db_url)
        if test_host == prod_host and test_db == prod_db:
            raise ValueError(
                "FATAL: Refusing to run tests because TEST_DATABASE_URL and DATABASE_URL "
                f"target the same host ('{test_host}') and database ('{test_db}')."
            )


@pytest.fixture(autouse=True)
def setup_test_db(monkeypatch):
    """Ensure tests only use TEST_DATABASE_URL and have a clean database schema."""
    test_db_url = os.environ.get("TEST_DATABASE_URL", "").strip()
    prod_db_url = os.environ.get("DATABASE_URL", "").strip()

    # Safety check: compare host and database name, and refuse unless test db ends with _test
    try:
        validate_test_db_safety(test_db_url, prod_db_url)
    except ValueError as exc:
        pytest.fail(str(exc))

    # Never allow DATABASE_URL in tests; only TEST_DATABASE_URL
    monkeypatch.setattr(app_module, "DATABASE_URL", test_db_url)
    monkeypatch.setattr(app_module, "ENV", "development")
    # Bypass external network calls to GitHub API during default tests
    monkeypatch.setattr(app_module, "GITHUB_VALIDATE_USER", False)
    monkeypatch.setattr(app_module, "TRUST_PROXY", False, raising=False)

    # Clear in-memory caches
    if hasattr(app_module, "_USER_CACHE"):
        app_module._USER_CACHE.clear()
    if hasattr(app_module, "_CLIENT_RATE_LIMITS"):
        app_module._CLIENT_RATE_LIMITS.clear()

    # If test_db_url is set, reset tables to a clean state
    if test_db_url:
        with closing(app_module.get_db(test_db_url)) as conn:
            with conn.cursor() as cur:
                cur.execute("""
                    DROP TABLE IF EXISTS hits CASCADE;
                    DROP TABLE IF EXISTS active_windows CASCADE;
                    DROP TABLE IF EXISTS daily_uniques CASCADE;
                    DROP TABLE IF EXISTS daily_stats CASCADE;
                    DROP TABLE IF EXISTS user_totals CASCADE;
                    DROP TABLE IF EXISTS visitor_seen CASCADE;
                """)
            conn.commit()
            app_module.init_db(conn)

    yield


@pytest.fixture
def client():
    return TestClient(app)


def require_test_db():
    test_db_url = os.environ.get("TEST_DATABASE_URL", "").strip()
    if not test_db_url:
        pytest.skip("TEST_DATABASE_URL is unset. Skipping database test.")


def test_health(client):
    require_test_db()
    response = client.get("/health")
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "ok"
    assert data["database"] == "connected"
    assert data["version"] == app_module.__version__


def test_privacy_endpoint(client):
    response = client.get("/privacy")
    assert response.status_code == 200
    data = response.json()
    assert "Zero PII" in data["guarantees"][0]
    assert data["retention_policy"]["raw_hits_days"] == 30


def test_badge_security_and_cache_headers(client):
    require_test_db()
    for endpoint in ("/badge/testuser", "/badge/testuser/unique", "/badge/testuser/both"):
        response = client.get(endpoint, headers={"User-Agent": "github-camo (abc)"})
        assert response.status_code == 200
        assert response.headers["content-type"] == "image/svg+xml"
        assert response.headers["x-content-type-options"] == "nosniff"
        assert "default-src 'none'" in response.headers["content-security-policy"]
        assert "no-cache" in response.headers["cache-control"]
        assert response.headers["expires"] == "0"


def test_camo_vs_direct_counting(client):
    require_test_db()
    # Direct hit
    client.get("/badge/camouser", headers={"User-Agent": "Mozilla/5.0 direct"})
    # Camo hit
    client.get("/badge/camouser", headers={"User-Agent": "github-camo (12345)"})

    rep = client.get("/report/camouser").json()
    assert rep["metrics"]["camo_proxied"]["badge_loads"] == 1
    assert rep["metrics"]["direct_requests"]["badge_loads"] == 1
    assert rep["metrics"]["camo_proxied"]["total_uniques_est"] == 1
    assert rep["metrics"]["direct_requests"]["total_uniques_est"] == 1


def test_atomic_unique_deduplication(client, monkeypatch):
    require_test_db()
    monkeypatch.setattr(app_module, "TRUST_PROXY", True)
    monkeypatch.setattr(app_module, "BURST_SECONDS", 0)
    # Two camo requests from the same viewer IP count once
    camo_headers = {"User-Agent": "github-camo (123)", "X-Forwarded-For": "198.51.100.10"}
    client.get("/badge/uniquetest", headers=camo_headers)
    resp = client.get("/badge/uniquetest/unique", headers=camo_headers)

    assert resp.status_code == 200
    assert ">1<" in resp.text

    # A different viewer IP is a second unique visitor
    other_headers = {"User-Agent": "github-camo (456)", "X-Forwarded-For": "198.51.100.11"}
    client.get("/badge/uniquetest", headers=other_headers)
    resp3 = client.get("/badge/uniquetest/unique", headers=other_headers)
    assert ">2<" in resp3.text


def test_double_fetch_in_one_page_load_counts_once(client, monkeypatch):
    require_test_db()
    monkeypatch.setattr(app_module, "TRUST_PROXY", True)
    monkeypatch.setattr(app_module, "BURST_SECONDS", 60)
    # Same page load, two requests whose viewer IPs differ (the owner's double open)
    client.get("/badge/burstuser", headers={"User-Agent": "github-camo (1)", "X-Forwarded-For": "198.51.100.61"})
    client.get("/badge/burstuser", headers={"User-Agent": "github-camo (2)", "X-Forwarded-For": "198.51.100.62"})

    rep = client.get("/report/burstuser").json()
    assert rep["metrics"]["camo_proxied"]["badge_loads"] == 2
    assert rep["metrics"]["camo_proxied"]["total_uniques_est"] == 1
    assert rep["burst_collapses"] == 1

    # After the burst window has passed, a new visitor counts again
    conn = app_module.get_db()
    with conn.cursor() as cur:
        cur.execute("UPDATE hits SET ts = ts - 120 WHERE username = %s", ("burstuser",))
    conn.commit()
    conn.close()
    client.get("/badge/burstuser", headers={"User-Agent": "github-camo (3)", "X-Forwarded-For": "198.51.100.63"})
    rep = client.get("/report/burstuser").json()
    assert rep["metrics"]["camo_proxied"]["total_uniques_est"] == 2


def test_owner_visitor_keys_are_not_counted(client, monkeypatch):
    require_test_db()
    monkeypatch.setattr(app_module, "TRUST_PROXY", True)
    monkeypatch.setattr(app_module, "BURST_SECONDS", 0)
    owner_headers = {"User-Agent": "github-camo (own)", "X-Forwarded-For": "198.51.100.90"}
    client.get("/badge/owneruser", headers=owner_headers)
    rep = client.get("/report/owneruser").json()
    assert rep["metrics"]["camo_proxied"]["total_uniques_est"] == 1

    # Read the owner's key from the hit log, then exclude it
    conn = app_module.get_db()
    with conn.cursor() as cur:
        cur.execute("SELECT visitor_key FROM hits WHERE username = %s", ("owneruser",))
        owner_key = cur.fetchone()["visitor_key"]
    conn.close()
    monkeypatch.setattr(app_module, "OWNER_VISITOR_KEYS", frozenset({owner_key}))

    # The owner's loads no longer count
    client.get("/badge/owneruser", headers=owner_headers)
    client.get("/badge/owneruser", headers=owner_headers)
    rep = client.get("/report/owneruser").json()
    assert rep["metrics"]["camo_proxied"]["total_uniques_est"] == 1
    assert rep["owner_exclusion_keys_configured"] == 1

    # Another viewer still counts
    client.get("/badge/owneruser", headers={"User-Agent": "github-camo (x)", "X-Forwarded-For": "198.51.100.91"})
    rep = client.get("/report/owneruser").json()
    assert rep["metrics"]["camo_proxied"]["total_uniques_est"] == 2


def test_malformed_forwarded_address_is_ignored():
    from starlette.requests import Request

    scope = {
        "type": "http",
        "headers": [(b"x-forwarded-for", b"not-an-ip, 203.0.113.9")],
        "client": ("10.1.1.1", 1234),
    }
    monkeypatch_value = app_module.TRUST_PROXY
    app_module.TRUST_PROXY = True
    try:
        ip = app_module.viewer_ip(Request(scope))
    finally:
        app_module.TRUST_PROXY = monkeypatch_value
    # First entry is junk, so the viewer is not taken from it
    assert ip != "not-an-ip"
    assert ip == "203.0.113.9"


def test_ordinary_startup_does_not_rescan_timestamps(client):
    require_test_db()
    client.get("/badge/backfilluser", headers={"User-Agent": "github-camo (bf)"})
    conn = app_module.get_db()
    with conn.cursor() as cur:
        cur.execute("UPDATE hits SET ts_ist = NULL WHERE username = %s", ("backfilluser",))
    conn.commit()
    # Column already exists, so startup must not backfill it again
    app_module.init_db(conn)
    with conn.cursor() as cur:
        cur.execute("SELECT ts_ist FROM hits WHERE username = %s", ("backfilluser",))
        row = cur.fetchone()
    conn.close()
    assert row["ts_ist"] is None


def test_row_level_security_enabled_on_all_app_tables():
    require_test_db()
    conn = app_module.get_db()
    app_module.init_db(conn)
    with conn.cursor() as cur:
        cur.execute(
            "SELECT relname, relrowsecurity FROM pg_class WHERE relname = ANY(%s)",
            (list(app_module.APP_TABLES),),
        )
        rows = cur.fetchall()
    conn.close()
    assert len(rows) == len(app_module.APP_TABLES)
    assert all(row["relrowsecurity"] for row in rows)


def test_report_states_viewer_identity_and_trust(client, monkeypatch):
    require_test_db()
    monkeypatch.setattr(app_module, "TRUST_PROXY", False)
    client.get("/badge/trustuser", headers={"User-Agent": "github-camo (5)"})
    rep = client.get("/report/trustuser").json()
    assert rep["trust_proxy"] is False
    assert "undercounted" in rep["viewer_identity"]
    assert rep["today_definition"].startswith("Visitors first counted today")
    assert rep["burst_collapses"] == 0


def test_diagnostics_store_counts_not_ips(client, monkeypatch):
    require_test_db()
    monkeypatch.setattr(app_module, "TRUST_PROXY", True)
    client.get(
        "/badge/diaguser",
        headers={"User-Agent": "github-camo (9)", "X-Forwarded-For": "2001:db8:1:2::7, 10.0.0.1"},
    )
    conn = app_module.get_db()
    with conn.cursor() as cur:
        cur.execute("SELECT xff_count, ip_version FROM hits WHERE username = %s", ("diaguser",))
        row = cur.fetchone()
    conn.close()
    assert row["xff_count"] == 2
    assert row["ip_version"] == "v6"


def test_normalize_ip_collapses_ipv6_slash64():
    same_a = app_module.normalize_ip("2001:db8:1:2:aaaa::1")
    same_b = app_module.normalize_ip("2001:db8:1:2:bbbb::9")
    assert same_a == same_b
    assert app_module.normalize_ip("203.0.113.5") == "203.0.113.5"


def test_repeat_visitor_counted_once_per_dedupe_period(client, monkeypatch):
    require_test_db()
    monkeypatch.setattr(app_module, "TRUST_PROXY", True)
    monkeypatch.setattr(app_module, "DEDUPE_DAYS", 30)
    monkeypatch.setattr(app_module, "BURST_SECONDS", 0)
    headers = {"User-Agent": "github-camo (789)", "X-Forwarded-For": "198.51.100.50"}

    # Repeated visits within the period count once
    for _ in range(3):
        client.get("/badge/dedupeuser", headers=headers)
    rep = client.get("/report/dedupeuser").json()
    assert rep["metrics"]["camo_proxied"]["total_uniques_est"] == 1
    assert rep["metrics"]["camo_proxied"]["badge_loads"] == 3

    # Push the last counted visit 31 days back: the same visitor counts again
    conn = app_module.get_db()
    with conn.cursor() as cur:
        cur.execute(
            "UPDATE visitor_seen SET last_counted = last_counted - %s WHERE username = %s",
            (31 * 86400.0, "dedupeuser"),
        )
    conn.commit()
    conn.close()

    client.get("/badge/dedupeuser", headers=headers)
    rep = client.get("/report/dedupeuser").json()
    assert rep["metrics"]["camo_proxied"]["total_uniques_est"] == 2


def test_badge_views_split_and_today(client):
    require_test_db()
    camo_headers = {"User-Agent": "github-camo (abc)"}
    default_resp = client.get("/badge/splituser", headers=camo_headers)
    assert default_resp.status_code == 200
    assert "Unique views" in default_resp.text
    assert "Total visits" in default_resp.text

    # Dedicated /unique endpoint
    unique_resp = client.get("/badge/splituser/unique", headers=camo_headers)
    assert unique_resp.status_code == 200
    assert "Unique Visitors (est.)" in unique_resp.text

    # Split view (today · total)
    split_resp = client.get("/badge/splituser?view=split", headers=camo_headers)
    assert split_resp.status_code == 200
    assert "Today" in split_resp.text
    assert "Total" in split_resp.text

    # Today metric
    today_resp = client.get("/badge/splituser?metric=today", headers=camo_headers)
    assert today_resp.status_code == 200
    assert "Visitors Today (est.)" in today_resp.text


def test_dual_badge_colors_each_part_separately(client):
    require_test_db()
    camo_headers = {"User-Agent": "github-camo (four)"}
    params = {
        "label_color": "#2ea043",  # left label
        "color": "#2c81f5",  # left counter
        "label2_color": "#ff0000",  # right label
        "color2": "#000000",  # right counter
    }
    resp = client.get("/badge/fourpart", headers=camo_headers, params=params)
    assert resp.status_code == 200
    svg = resp.text
    # Each of the four parts is painted with its own color, in order
    order = [svg.index(f'fill="{c}"') for c in ("#2ea043", "#2c81f5", "#ff0000", "#000000")]
    assert order == sorted(order)
    assert svg.count("<rect x=") == 4


def test_preview_mode(client):
    require_test_db()
    camo_headers = {"User-Agent": "github-camo (abc)"}
    client.get("/badge/previewuser", headers=camo_headers)

    # Hit with preview=true
    resp_prev = client.get("/badge/previewuser?preview=true&metric=loads", headers=camo_headers)
    assert ">1<" in resp_prev.text

    # Hit with deprecated ignore_owner alias
    resp_alias = client.get("/badge/previewuser?ignore_owner=true&metric=loads", headers=camo_headers)
    assert ">1<" in resp_alias.text

    # Loads should still be 1 in report
    rep = client.get("/report/previewuser").json()
    assert rep["metrics"]["camo_proxied"]["badge_loads"] == 1


def test_rate_limiting_graceful_degradation(client, monkeypatch):
    require_test_db()
    monkeypatch.setattr(app_module, "RATE_LIMIT_PER_MIN", 3)
    camo_headers = {"User-Agent": "github-camo (abc)"}

    for _ in range(3):
        client.get("/badge/ratelimituser?metric=loads", headers=camo_headers)

    # 4th request exceeds rate limit
    resp = client.get("/badge/ratelimituser?metric=loads", headers=camo_headers)
    assert resp.status_code == 200
    assert resp.headers.get("x-ratelimit-exceeded") == "true"
    assert ">3<" in resp.text


def test_svg_sanitization():
    rendered = render_svg("<script>alert(1)</script>", "10", color="blue", label_color="green")
    assert "<script>" not in rendered
    assert "&lt;script&gt;" in rendered
    assert "#2ea043" in rendered  # label_color="green"
    assert "#0969da" in rendered  # color="blue"


# -------------------------------------------------------------------------
# Bug 1: Privacy guarantee & no raw user agent / IP storage
# -------------------------------------------------------------------------
def test_no_raw_user_agent_or_ip_stored(client):
    require_test_db()
    secret_ua = "Mozilla/5.0 SecretScanner/1.0"
    resp = client.get(
        "/badge/privacyuser",
        headers={"User-Agent": secret_ua},
    )
    assert resp.status_code == 200

    # Query all user tables in PostgreSQL public schema
    conn = app_module.get_db()
    with conn.cursor() as cursor:
        cursor.execute("""
            SELECT table_name FROM information_schema.tables 
            WHERE table_schema = 'public'
        """)
        tables = [row["table_name"] for row in cursor.fetchall()]

        for table in tables:
            cursor.execute(f"SELECT * FROM {table}")
            rows = cursor.fetchall()
            for row in rows:
                for val in row.values():
                    if isinstance(val, str):
                        assert secret_ua not in val, f"Found raw User-Agent in table {table}"
                        assert "testclient" not in val, f"Found raw client IP in table {table}"
    conn.close()

    # Assert /report contains no raw user agent string
    rep = client.get("/report/privacyuser")
    assert rep.status_code == 200
    rep_text = rep.text
    assert secret_ua not in rep_text
    rep_data = rep.json()
    assert "top_user_agents" not in rep_data

    # Assert /privacy text matches accurate storage policy
    priv = client.get("/privacy").json()
    assert any("user agents are never stored in raw form" in g for g in priv["guarantees"])


# -------------------------------------------------------------------------
# Bug 2: Username validation accepts bad input
# -------------------------------------------------------------------------
@pytest.mark.parametrize(
    "username,expected_status",
    [
        ("octocat", 200),
        ("user-123", 200),
        ("a", 200),
        ("a" * 39, 200),
        ("abc\n", 400),
        ("abc-", 400),
        ("-abc", 400),
        ("abc--def", 400),
        ("", 400),
        ("a" * 40, 400),
        ("user@domain", 400),
        ("user name", 400),
        ("user\r\n", 400),
    ],
)
def test_username_validation(client, username, expected_status):
    if expected_status == 200:
        require_test_db()

    if not username:
        with pytest.raises(HTTPException) as exc_info:
            app_module.valid_user(username)
        assert exc_info.value.status_code == 400
    else:
        # Check valid_user function directly
        if expected_status == 400:
            with pytest.raises(HTTPException) as exc_info:
                app_module.valid_user(username)
            assert exc_info.value.status_code == 400
        else:
            assert app_module.valid_user(username) == username.lower()

        # Check endpoint behavior with properly percent-encoded path
        encoded = urllib.parse.quote(username, safe="")
        resp = client.get(f"/badge/{encoded}")
        assert resp.status_code == expected_status


# -------------------------------------------------------------------------
# Bug 3: Rate limit is keyed by client identity, not target username
# -------------------------------------------------------------------------
def test_rate_limit_anti_griefing(monkeypatch):
    require_test_db()
    monkeypatch.setattr(app_module, "RATE_LIMIT_PER_MIN", 2)
    monkeypatch.setattr(app_module, "TRUST_PROXY", True)

    client1 = TestClient(app)
    client2 = TestClient(app)

    # Client 1 exhausts rate limit on /badge/victim
    r1 = client1.get("/badge/victim", headers={"X-Forwarded-For": "198.51.100.1"})
    assert r1.status_code == 200
    assert r1.headers.get("x-ratelimit-exceeded") is None

    r2 = client1.get("/badge/victim", headers={"X-Forwarded-For": "198.51.100.1"})
    assert r2.status_code == 200
    assert r2.headers.get("x-ratelimit-exceeded") is None

    r3 = client1.get("/badge/victim", headers={"X-Forwarded-For": "198.51.100.1"})
    assert r3.status_code == 200
    assert r3.headers.get("x-ratelimit-exceeded") == "true"

    # Client 2 (different IP) requests /badge/victim and succeeds without rate limit
    r_client2 = client2.get("/badge/victim", headers={"X-Forwarded-For": "198.51.100.2"})
    assert r_client2.status_code == 200
    assert r_client2.headers.get("x-ratelimit-exceeded") is None


def test_preview_mode_rate_limited(monkeypatch):
    require_test_db()
    monkeypatch.setattr(app_module, "RATE_LIMIT_PER_MIN", 2)
    monkeypatch.setattr(app_module, "TRUST_PROXY", True)
    c = TestClient(app)

    headers = {"X-Forwarded-For": "203.0.113.5"}
    c.get("/badge/previewvictim?preview=true", headers=headers)
    c.get("/badge/previewvictim?preview=true", headers=headers)
    r3 = c.get("/badge/previewvictim?preview=true", headers=headers)
    assert r3.status_code == 200
    assert r3.headers.get("x-ratelimit-exceeded") == "true"


def test_trust_proxy_disables_spoofing(monkeypatch):
    require_test_db()
    # When TRUST_PROXY is False (default), X-Forwarded-For is ignored
    monkeypatch.setattr(app_module, "TRUST_PROXY", False)
    monkeypatch.setattr(app_module, "RATE_LIMIT_PER_MIN", 2)
    c = TestClient(app)

    # Client tries to spoof IP via X-Forwarded-For
    c.get("/badge/spooftest", headers={"X-Forwarded-For": "1.1.1.1"})
    c.get("/badge/spooftest", headers={"X-Forwarded-For": "2.2.2.2"})
    r3 = c.get("/badge/spooftest", headers={"X-Forwarded-For": "3.3.3.3"})
    # Both previous requests actually came from testclient, so 3rd request is rate limited!
    assert r3.headers.get("x-ratelimit-exceeded") == "true"


# -------------------------------------------------------------------------
# Bug 4: Production secret blacklist & validation function
# -------------------------------------------------------------------------
def test_production_secret_enforcement():
    # Empty secret in production
    with pytest.raises(RuntimeError, match="FATAL"):
        app_module.validate_secret("production", "")

    # dev-secret-change-me in production
    with pytest.raises(RuntimeError, match="FATAL"):
        app_module.validate_secret("production", "dev-secret-change-me")

    # compose fallback local-dev-secret-key-32chars in production
    with pytest.raises(RuntimeError, match="FATAL"):
        app_module.validate_secret("production", "local-dev-secret-key-32chars")

    # Under 16 characters in production
    with pytest.raises(RuntimeError, match="FATAL"):
        app_module.validate_secret("production", "short-secret")

    # Valid secret in production
    app_module.validate_secret("production", "super-secret-random-production-key-64b")

    # Dev allows dev defaults
    app_module.validate_secret("development", "dev-secret-change-me")
    app_module.validate_secret("development", "local-dev-secret-key-32chars")


# -------------------------------------------------------------------------
# Bug 5: GitHub user existence check and resilient caching
# -------------------------------------------------------------------------
@pytest.mark.asyncio
async def test_github_user_existence_and_caching(monkeypatch):
    # 1. 200 OK -> cached True for 24h
    mock_resp_200 = AsyncMock()
    mock_resp_200.status_code = 200

    with patch("httpx.AsyncClient.get", new_callable=AsyncMock) as mock_get:
        mock_get.return_value = mock_resp_200
        exists = await app_module.check_github_user_exists("gooduser")
        assert exists is True
        assert "gooduser" in app_module._USER_CACHE
        assert app_module._USER_CACHE["gooduser"][0] is True
        # Second call should use cache, not call mock_get again
        exists_cached = await app_module.check_github_user_exists("gooduser")
        assert exists_cached is True
        assert mock_get.call_count == 1

    # 2. 404 Not Found -> cached False for 1h
    mock_resp_404 = AsyncMock()
    mock_resp_404.status_code = 404

    with patch("httpx.AsyncClient.get", new_callable=AsyncMock) as mock_get:
        mock_get.return_value = mock_resp_404
        exists = await app_module.check_github_user_exists("baduser")
        assert exists is False
        assert "baduser" in app_module._USER_CACHE
        assert app_module._USER_CACHE["baduser"][0] is False

    # 3. 403 Rate Limited -> Fail open (returns True)
    mock_resp_403 = AsyncMock()
    mock_resp_403.status_code = 403

    with patch("httpx.AsyncClient.get", new_callable=AsyncMock) as mock_get:
        mock_get.return_value = mock_resp_403
        exists = await app_module.check_github_user_exists("ratelimiteduser")
        assert exists is True

    # 4. 500 Server Error -> Fail open (returns True)
    mock_resp_500 = AsyncMock()
    mock_resp_500.status_code = 500

    with patch("httpx.AsyncClient.get", new_callable=AsyncMock) as mock_get:
        mock_get.return_value = mock_resp_500
        exists = await app_module.check_github_user_exists("erroruser")
        assert exists is True

    # 5. Network Timeout / Connection Error -> Fail open (returns True)
    with patch("httpx.AsyncClient.get", new_callable=AsyncMock) as mock_get:
        mock_get.side_effect = httpx.TimeoutException("Timed out")
        exists = await app_module.check_github_user_exists("timeoutuser")
        assert exists is True


# -------------------------------------------------------------------------
# Bug 6: SVG injection & sanitization
# -------------------------------------------------------------------------
def test_svg_injection_vectors():
    # Test malicious colors and labels
    color1 = 'red"/><script>alert(1)</script>'
    color2 = 'blue" onload="alert(1)'
    label = 'Test "Quote" <tag> & More'

    rendered = render_svg(label, "10", color=color1)
    # Parse as valid XML
    root = ET.fromstring(rendered)
    assert root.tag.endswith("svg")
    assert "<script>" not in rendered
    assert "alert(1)" not in rendered
    # Color falls back to default safe color #2ea043
    assert 'fill="#2ea043"' in rendered

    rendered2 = render_svg(label, "20", color=color2)
    root2 = ET.fromstring(rendered2)
    assert root2.tag.endswith("svg")
    assert 'onload="alert(1)' not in rendered2

    # Assert label is XML escaped
    assert '&quot;Quote&quot;' in rendered
    assert '&lt;tag&gt;' in rendered
    assert '&amp; More' in rendered


# -------------------------------------------------------------------------
# Bug 7: Retention pruning boundary & table integrity
# -------------------------------------------------------------------------
def test_pruning_old_records():
    require_test_db()
    conn = app_module.get_db()
    now = time.time()
    old_ts = now - (35 * 86400)      # 35 days ago (should be deleted)
    recent_ts = now - (25 * 86400)   # 25 days ago (should be retained)

    with conn.cursor() as cur:
        # Insert into hits
        cur.execute(
            "INSERT INTO hits (ts, day, username, visitor_key, client_type, via_camo, conditional, counted_unique) "
            "VALUES (%s, '2020-01-01', 'olduser', 'key1', 'github-camo', 1, 0, 1)",
            (old_ts,),
        )
        cur.execute(
            "INSERT INTO hits (ts, day, username, visitor_key, client_type, via_camo, conditional, counted_unique) "
            "VALUES (%s, '2020-01-11', 'recentuser', 'key2', 'github-camo', 1, 0, 1)",
            (recent_ts,),
        )

        # Insert into daily_uniques
        cur.execute(
            "INSERT INTO daily_uniques (username, day, visitor_key, via_camo, ts) VALUES ('olduser', '2020-01-01', 'k1', 1, %s)",
            (old_ts,),
        )
        cur.execute(
            "INSERT INTO daily_uniques (username, day, visitor_key, via_camo, ts) VALUES ('recentuser', '2020-01-11', 'k2', 1, %s)",
            (recent_ts,),
        )

        # Insert into active_windows
        cur.execute(
            "INSERT INTO active_windows (username, window_id, via_camo, ts) VALUES ('olduser', 100, 1, %s)",
            (old_ts,),
        )
        cur.execute(
            "INSERT INTO active_windows (username, window_id, via_camo, ts) VALUES ('recentuser', 200, 1, %s)",
            (recent_ts,),
        )

        # Insert aggregates into user_totals and daily_stats (must NEVER be pruned)
        cur.execute(
            "INSERT INTO user_totals (username, camo_uniques, camo_loads, camo_windows, direct_uniques, direct_loads, updated_at) "
            "VALUES ('olduser', 10, 20, 5, 0, 0, %s)",
            (old_ts,),
        )
        cur.execute(
            "INSERT INTO daily_stats (username, day, camo_uniques, camo_loads, camo_windows, direct_uniques, direct_loads) "
            "VALUES ('olduser', '2020-01-01', 10, 20, 5, 0, 0)",
        )
        conn.commit()

        deleted = prune_old_records(conn, retention_days=30)
        assert deleted >= 1

        # Verify hits table: old removed, recent kept
        cur.execute("SELECT COUNT(*) AS c FROM hits WHERE ts = %s", (old_ts,))
        assert cur.fetchone()["c"] == 0
        cur.execute("SELECT COUNT(*) AS c FROM hits WHERE ts = %s", (recent_ts,))
        assert cur.fetchone()["c"] == 1

        # Verify daily_uniques: old removed, recent kept
        cur.execute("SELECT COUNT(*) AS c FROM daily_uniques WHERE ts = %s", (old_ts,))
        assert cur.fetchone()["c"] == 0
        cur.execute("SELECT COUNT(*) AS c FROM daily_uniques WHERE ts = %s", (recent_ts,))
        assert cur.fetchone()["c"] == 1

        # Verify active_windows: old removed, recent kept
        cur.execute("SELECT COUNT(*) AS c FROM active_windows WHERE ts = %s", (old_ts,))
        assert cur.fetchone()["c"] == 0
        cur.execute("SELECT COUNT(*) AS c FROM active_windows WHERE ts = %s", (recent_ts,))
        assert cur.fetchone()["c"] == 1

        # Verify user_totals & daily_stats: preserved!
        cur.execute("SELECT COUNT(*) AS c FROM user_totals WHERE username = 'olduser'")
        assert cur.fetchone()["c"] == 1
        cur.execute("SELECT COUNT(*) AS c FROM daily_stats WHERE username = 'olduser'")
        assert cur.fetchone()["c"] == 1

    conn.close()


# -------------------------------------------------------------------------
# Bug 8: Health check returns degraded when database is unavailable
# -------------------------------------------------------------------------
def test_health_degraded_when_db_down(client, monkeypatch):
    def mock_get_db_failure(db_url=None):
        raise psycopg.OperationalError("connection failed: server closed the connection unexpectedly")

    monkeypatch.setattr(app_module, "get_db", mock_get_db_failure)

    response = client.get("/health")
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "degraded"
    assert "unhealthy" in data["database"]


# -------------------------------------------------------------------------
# Bug 9: Concurrency deduplication under PostgreSQL
# -------------------------------------------------------------------------
def test_concurrent_identical_requests():
    require_test_db()
    test_client = TestClient(app)
    camo_headers = {"User-Agent": "github-camo (concurrent-client-1)"}

    def make_request():
        return test_client.get("/badge/concurrentuser", headers=camo_headers)

    # Send 20 concurrent identical requests
    with concurrent.futures.ThreadPoolExecutor(max_workers=8) as executor:
        futures = [executor.submit(make_request) for _ in range(20)]
        results = [f.result() for f in futures]

    for resp in results:
        assert resp.status_code == 200

    # Query report to verify deduplication
    rep = test_client.get("/report/concurrentuser").json()
    assert rep["metrics"]["camo_proxied"]["total_uniques_est"] == 1
    assert rep["metrics"]["camo_proxied"]["badge_loads"] == 20


# -------------------------------------------------------------------------
# Test Database Safety Guard
# -------------------------------------------------------------------------
def test_safety_guard_rejects_non_test_db():
    with pytest.raises(ValueError, match="does not end with '_test'"):
        validate_test_db_safety("postgresql://postgres@localhost:5432/profilepulse_prod", "")


def test_safety_guard_rejects_matching_host_and_db():
    with pytest.raises(ValueError, match="target the same host"):
        validate_test_db_safety(
            "postgresql://user1:secret1@127.0.0.1:5432/profilepulse_test",
            "postgresql://user2:secret2@localhost:5432/profilepulse_test?sslmode=require",
        )


def test_safety_guard_accepts_valid_test_db():
    # Should not raise
    validate_test_db_safety(
        "postgresql://postgres@localhost:5432/my_app_test",
        "postgresql://postgres@localhost:5432/my_app_prod",
    )
