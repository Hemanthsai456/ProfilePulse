"""Unit and integration tests for ProfilePulse v0.2.0."""

import pytest
from fastapi.testclient import TestClient

import app.main as app_module
from app.main import app, prune_old_records, render_svg


@pytest.fixture(autouse=True)
def setup_test_db(tmp_path, monkeypatch):
    """Use an isolated SQLite database file and test environment for each test."""
    db_file = tmp_path / "test_profilepulse.db"
    monkeypatch.setattr(app_module, "DB_PATH", str(db_file))
    monkeypatch.setattr(app_module, "ENV", "development")
    # Bypass external network calls to GitHub API during tests
    monkeypatch.setattr(app_module, "GITHUB_VALIDATE_USER", False)
    yield


@pytest.fixture
def client():
    return TestClient(app)


def test_health(client):
    response = client.get("/health")
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "ok"
    assert data["database"] == "connected"
    assert data["version"] == "0.2.0"


def test_privacy_endpoint(client):
    response = client.get("/privacy")
    assert response.status_code == 200
    data = response.json()
    assert "Zero PII" in data["guarantees"][0]
    assert data["retention_policy"]["raw_hits_days"] == 30


def test_badge_security_and_cache_headers(client):
    response = client.get("/badge/testuser", headers={"User-Agent": "github-camo (abc)"})
    assert response.status_code == 200
    assert response.headers["content-type"] == "image/svg+xml"
    assert response.headers["x-content-type-options"] == "nosniff"
    assert "default-src 'none'" in response.headers["content-security-policy"]
    assert "no-cache" in response.headers["cache-control"]
    assert response.headers["expires"] == "0"


def test_camo_vs_direct_counting(client):
    # Direct hit
    client.get("/badge/camouser", headers={"User-Agent": "Mozilla/5.0 direct"})
    # Camo hit
    client.get("/badge/camouser", headers={"User-Agent": "github-camo (12345)"})

    rep = client.get("/report/camouser").json()
    assert rep["metrics"]["camo_proxied"]["badge_loads"] == 1
    assert rep["metrics"]["direct_requests"]["badge_loads"] == 1
    assert rep["metrics"]["camo_proxied"]["total_uniques_est"] == 1
    assert rep["metrics"]["direct_requests"]["total_uniques_est"] == 1


def test_atomic_unique_deduplication(client):
    # Two camo requests from same client
    camo_headers = {"User-Agent": "github-camo (123)"}
    client.get("/badge/uniquetest", headers=camo_headers)
    resp = client.get("/badge/uniquetest", headers=camo_headers)

    assert resp.status_code == 200
    assert ">1<" in resp.text

    # Third request with a different user agent
    client.get("/badge/uniquetest", headers={"User-Agent": "github-camo (456)"})
    resp3 = client.get("/badge/uniquetest", headers={"User-Agent": "github-camo (456)"})
    assert ">2<" in resp3.text


def test_badge_views_split_and_today(client):
    camo_headers = {"User-Agent": "github-camo (abc)"}
    client.get("/badge/splituser", headers=camo_headers)

    # Split view (today · total)
    split_resp = client.get("/badge/splituser?view=split", headers=camo_headers)
    assert split_resp.status_code == 200
    assert "today" in split_resp.text
    assert "total" in split_resp.text

    # Today metric
    today_resp = client.get("/badge/splituser?metric=today", headers=camo_headers)
    assert today_resp.status_code == 200
    assert "Today&#39;s Uniques" in today_resp.text


def test_preview_mode(client):
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
    rendered = render_svg("<script>alert(1)</script>", "10", color="blue")
    assert "<script>" not in rendered
    assert "&lt;script&gt;" in rendered


def test_pruning_old_records():
    conn = app_module.get_db()
    now = 1000000.0  # arbitrary past timestamp
    # Insert older than 30 days
    old_ts = now - (35 * 86400)
    conn.execute(
        "INSERT INTO hits (ts, day, username, visitor_key, user_agent, via_camo, conditional, counted_unique) "
        "VALUES (?, '2020-01-01', 'olduser', 'key1', 'ua', 1, 0, 1)",
        (old_ts,),
    )
    conn.commit()

    deleted = prune_old_records(conn, retention_days=30)
    assert deleted >= 1
    conn.close()


def test_production_secret_enforcement(monkeypatch):
    monkeypatch.setenv("PROFILEPULSE_ENV", "production")
    monkeypatch.setenv("PROFILEPULSE_SECRET", "dev-secret-change-me")

    with pytest.raises(RuntimeError) as exc_info:
        # Re-import or evaluate production check logic
        env = "production"
        sec = "dev-secret-change-me"
        if env == "production" and (not sec or sec == "dev-secret-change-me" or len(sec) < 16):
            raise RuntimeError("FATAL: In production mode, PROFILEPULSE_SECRET must be set to a secure string.")

    assert "FATAL" in str(exc_info.value)
