"""Unit and integration tests for ProfilePulse."""

import os
import pytest
from fastapi.testclient import TestClient

from app.main import app, get_db, sanitize_color, escape_xml, render_svg


@pytest.fixture(autouse=True)
def setup_test_db(tmp_path, monkeypatch):
    """Use an isolated SQLite database file for each test run."""
    db_file = tmp_path / "test_profilepulse.db"
    monkeypatch.setattr("app.main.DB_PATH", str(db_file))
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
    assert "version" in data


def test_badge_default_unique(client):
    response = client.get("/badge/testuser")
    assert response.status_code == 200
    assert response.headers["content-type"] == "image/svg+xml"
    assert "no-cache" in response.headers["cache-control"]
    assert "Daily Uniques (est.)" in response.text
    assert "<svg" in response.text

    # Second request from same client on same day shouldn't increment daily unique
    response2 = client.get("/badge/testuser")
    assert response2.status_code == 200
    # Both should show "1" for unique
    assert ">1<" in response2.text


def test_badge_svg_extension(client):
    response = client.get("/badge/testuser.svg")
    assert response.status_code == 200
    assert response.headers["content-type"] == "image/svg+xml"


def test_badge_loads_metric(client):
    client.get("/badge/loaduser?metric=loads")
    client.get("/badge/loaduser?metric=loads")
    response = client.get("/badge/loaduser?metric=loads")
    assert response.status_code == 200
    assert "Badge Loads" in response.text
    assert ">3<" in response.text


def test_badge_windows_metric(client):
    client.get("/badge/windowuser?metric=windows")
    client.get("/badge/windowuser?metric=windows")
    response = client.get("/badge/windowuser?metric=windows")
    assert response.status_code == 200
    assert "Active Windows" in response.text
    # All 3 requests were within the same 30m window, so count is 1
    assert ">1<" in response.text


def test_badge_custom_label_and_color(client):
    response = client.get("/badge/customuser?label=Visits&color=orange")
    assert response.status_code == 200
    assert "Visits" in response.text
    assert "#fe7d37" in response.text  # orange hex


def test_badge_custom_hex_color(client):
    response = client.get("/badge/customuser2?color=0969da")
    assert response.status_code == 200
    assert "#0969da" in response.text


def test_badge_ignore_owner(client):
    # Initial load: 1
    client.get("/badge/owneruser?metric=loads")

    # Request with ignore_owner should not increment loads count
    resp = client.get("/badge/owneruser?metric=loads&ignore_owner=true")
    assert resp.status_code == 200
    assert ">1<" in resp.text

    # Next regular request should be 2
    resp2 = client.get("/badge/owneruser?metric=loads")
    assert resp2.status_code == 200
    assert ">2<" in resp2.text


def test_invalid_username(client):
    # Double hyphens are not allowed by GitHub username rules
    res1 = client.get("/badge/invalid--name")
    assert res1.status_code == 400

    # Special characters
    res2 = client.get("/badge/user$name")
    assert res2.status_code == 400

    # Leading hyphen
    res3 = client.get("/badge/-username")
    assert res3.status_code == 400


def test_invalid_metric(client):
    res = client.get("/badge/validuser?metric=invalid_metric")
    assert res.status_code == 400
    assert "Metric must be one of" in res.json()["detail"]


def test_report_endpoint(client):
    # Perform some badge hits with specific headers
    client.get(
        "/badge/reportuser",
        headers={"User-Agent": "github-camo (726d482d)", "X-Forwarded-For": "192.168.1.1"},
    )
    client.get(
        "/badge/reportuser",
        headers={"User-Agent": "Mozilla/5.0", "If-None-Match": '"etag123"'},
    )

    res = client.get("/report/reportuser")
    assert res.status_code == 200
    data = res.json()

    assert data["username"] == "reportuser"
    assert data["badge_loads"] == 2
    assert data["via_camo"] == 1
    assert data["conditional_requests"] == 1
    assert data["with_x_forwarded_for"] == 1
    assert data["verified_profile_visits"] is None
    assert "proxy_analysis" in data
    assert "methodology" in data
    assert len(data["per_day"]) >= 1
    assert len(data["top_user_agents"]) >= 1


def test_svg_injection_protection():
    rendered = render_svg("<script>alert(1)</script>", "10", color="red; fill:blue")
    assert "<script>" not in rendered
    assert "&lt;script&gt;" in rendered
    # Color fallback or sanitized
    assert "red; fill:blue" not in rendered


def test_rate_limiting_graceful_degradation(client, monkeypatch):
    monkeypatch.setattr("app.main.RATE_LIMIT_PER_MIN", 3)

    # 3 hits under limit
    for _ in range(3):
        client.get("/badge/ratelimited?metric=loads")

    # 4th hit should still return 200 with SVG, but include rate limit header
    resp = client.get("/badge/ratelimited?metric=loads")
    assert resp.status_code == 200
    assert resp.headers["content-type"] == "image/svg+xml"
    assert resp.headers.get("x-ratelimit-exceeded") == "true"
    # The count should stay at 3 because 4th hit was not recorded
    assert ">3<" in resp.text
